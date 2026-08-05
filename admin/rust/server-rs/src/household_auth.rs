//! Soyeht proof-of-possession auth for household-scoped routes.

use axum::http::{HeaderMap, Method, header};
use household_rs::caveats::{self, Operation};
use household_rs::device_admission::{
    DeviceAdmissionError, DeviceStatus, HouseholdDeviceAdmissionAuthorityV1,
    owner_person_cert_digest,
};
use household_rs::pop::RequestSigningContext;
use household_rs::{
    DeviceId, HouseholdAuthState, HouseholdRecord, P256Signature, PersonId,
    household_lifecycle::{HouseholdLifecycleLock, LifecycleReadGuard},
};
use std::path::Path;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::household_state::HouseholdState;

const TIMESTAMP_TOLERANCE_SECS: u64 = 60;

/// Acquire lifecycle-shared and prove that disk still contains the exact
/// household record whose in-memory authority a blocking operation is about
/// to use.
///
/// This function blocks on a cross-process flock and must be called only from
/// `spawn_blocking` (or an already-synchronous worker). Retaining the returned
/// guard prevents teardown/replace from renaming `household/` until the caller
/// finishes all path-based I/O. Exact record equality prevents a stale daemon
/// from operating on a replacement household after it finally acquires the
/// lock.
/// Why an exact-household lifecycle acquisition refused.
///
/// [`Self::RecordChanged`] is a **cross-binding**: the durable record no longer
/// matches the identity the request was authorized against. On the delegated
/// device path that class must collapse into
/// [`RosterReadAuthError::DeviceUnauthenticated`] like every other device-side
/// refusal — it is a property of the request's binding, not of the server's
/// availability. The remaining three are genuine availability faults.
///
/// These are kept apart **in the type** rather than as reason strings so that a
/// caller cannot flatten a cross-binding into an availability answer with a
/// `map_err(|_| ...)`; doing so silently answers a question the collapse exists
/// to refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactLifecycleRefusal {
    OpenFailed,
    SharedFailed,
    RecordReadFailed,
    RecordChanged,
}

impl ExactLifecycleRefusal {
    /// Log-facing reason class. Never reaches the wire.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::OpenFailed => "lifecycle_open_failed",
            Self::SharedFailed => "lifecycle_shared_failed",
            Self::RecordReadFailed => "household_record_read_failed",
            Self::RecordChanged => "household_record_changed",
        }
    }
}

pub(crate) fn acquire_exact_household_lifecycle(
    state_dir: &Path,
    expected: &HouseholdRecord,
) -> Result<LifecycleReadGuard, ExactLifecycleRefusal> {
    let lifecycle = HouseholdLifecycleLock::open_verified(state_dir)
        .map_err(|_| ExactLifecycleRefusal::OpenFailed)?;
    let guard = lifecycle
        .lock_shared()
        .map_err(|_| ExactLifecycleRefusal::SharedFailed)?;
    let observed: Option<HouseholdRecord> = household_rs::storage::read_optional_cbor(
        &household_rs::storage::household_record_path(state_dir),
    )
    .map_err(|_| ExactLifecycleRefusal::RecordReadFailed)?;
    if observed.as_ref() != Some(expected) {
        return Err(ExactLifecycleRefusal::RecordChanged);
    }
    Ok(guard)
}

#[derive(Debug, Clone)]
pub struct SoyehtPoP {
    pub p_id: String,
    pub timestamp: u64,
    pub signature: P256Signature,
}

#[derive(Clone)]
pub struct AuthorizedRequest {
    pub owner_auth: Arc<HouseholdAuthState>,
    pub actor_person_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing proof")]
    Missing,
    #[error("malformed proof")]
    Malformed,
    #[error("timestamp outside replay window")]
    Timestamp,
    #[error("household identity is unavailable")]
    IdentityUnavailable,
    #[error("owner auth state is unavailable")]
    OwnerAuthUnavailable,
    #[error("signer is not a household member")]
    NotAMember,
    #[error("certificate rejected")]
    CertRejected,
    #[error("signature rejected")]
    SignatureRejected,
    #[error("operation not permitted")]
    CaveatRejected,
}

impl SoyehtPoP {
    pub fn parse(headers: &HeaderMap) -> Result<Self, AuthError> {
        let value = headers
            .get(header::AUTHORIZATION)
            .ok_or(AuthError::Missing)?
            .to_str()
            .map_err(|_| AuthError::Malformed)?;
        let rest = value
            .strip_prefix("Soyeht-PoP ")
            .ok_or(AuthError::Malformed)?;
        let mut parts = rest.split(':');
        let version = parts.next().ok_or(AuthError::Malformed)?;
        let p_id = parts.next().ok_or(AuthError::Malformed)?;
        let ts = parts.next().ok_or(AuthError::Malformed)?;
        let sig = parts.next().ok_or(AuthError::Malformed)?;
        if parts.next().is_some() || version != "v1" || !PersonId::is_well_formed(p_id) {
            return Err(AuthError::Malformed);
        }
        let timestamp = ts.parse::<u64>().map_err(|_| AuthError::Malformed)?;
        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, sig)
                .map_err(|_| AuthError::Malformed)?;
        let signature = P256Signature::from_bytes(&sig_bytes).map_err(|_| AuthError::Malformed)?;
        Ok(Self {
            p_id: p_id.to_string(),
            timestamp,
            signature,
        })
    }
}

pub async fn authorize_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    operation: Operation,
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_request_with_actor(state, headers, method, path_and_query, body, operation, now)
        .await
        .map(|authorized| authorized.owner_auth)
}

pub async fn authorize_request_with_actor(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    operation: Operation,
    now: u64,
) -> Result<AuthorizedRequest, AuthError> {
    let pop = SoyehtPoP::parse(headers).inspect_err(log_rejected)?;
    let skew = now.abs_diff(pop.timestamp);
    if skew > TIMESTAMP_TOLERANCE_SECS {
        log_rejected(&AuthError::Timestamp);
        return Err(AuthError::Timestamp);
    }
    let identity = state.current().await.ok_or_else(|| {
        log_rejected(&AuthError::IdentityUnavailable);
        AuthError::IdentityUnavailable
    })?;
    let owner_auth = state.current_owner_auth().await.ok_or_else(|| {
        log_rejected(&AuthError::OwnerAuthUnavailable);
        AuthError::OwnerAuthUnavailable
    })?;
    if !bool::from(
        owner_auth
            .owner_person_cert
            .p_id
            .0
            .as_bytes()
            .ct_eq(pop.p_id.as_bytes()),
    ) {
        log_rejected(&AuthError::NotAMember);
        return Err(AuthError::NotAMember);
    }
    owner_auth
        .owner_person_cert
        .verify(&identity.record.hh_id, &identity.record.hh_pub, now)
        .map_err(|_| {
            log_rejected(&AuthError::CertRejected);
            AuthError::CertRejected
        })?;
    let ctx = RequestSigningContext::new(method.as_str(), path_and_query, pop.timestamp, body);
    ctx.verify(&owner_auth.owner_person_cert.p_pub, &pop.signature)
        .map_err(|_| {
            log_rejected(&AuthError::SignatureRejected);
            AuthError::SignatureRejected
        })?;
    if !caveats::permits(&owner_auth.owner_person_cert.caveats, &operation) {
        log_rejected(&AuthError::CaveatRejected);
        return Err(AuthError::CaveatRejected);
    }
    tracing::info!(
        stage = "household_auth.pop.accepted",
        p_id = %pop.p_id,
        operation = %operation,
    );
    Ok(AuthorizedRequest {
        owner_auth,
        actor_person_id: pop.p_id,
    })
}

/// Authorize the first owner passkey enrollment surface.
///
/// This is intentionally not a generic helper and intentionally does not check
/// a delegable caveat. Before a passkey exists, "owner" is proven by the
/// current HH-root-verified owner `PersonCert` plus a fresh `Soyeht-PoP`
/// signature over method, path/query, timestamp, and exact request body.
pub async fn authorize_owner_auth_enroll_initial_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerAuthEnrollInitial",
    )
    .await
}

/// Authorize the owner passkey enrollment status surface.
///
/// Status is a read-only E1 helper, so it proves only owner identity and fresh
/// body-bound proof-of-possession. It intentionally does not check a delegable
/// caveat and does not reuse the enrollment operation label.
pub async fn authorize_owner_webauthn_registration_status_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerWebauthnRegistrationStatus",
    )
    .await
}

/// Authorize the owner passkey revoke start surface.
///
/// This proves only current owner identity and a fresh body-bound
/// proof-of-possession. The `WebAuthn` assertion generated by the returned
/// challenge is the step-up proof for the later finish slice.
pub async fn authorize_owner_webauthn_revoke_credential_start_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerWebauthnRevokeCredentialStart",
    )
    .await
}

/// Authorize the owner passkey revoke finish surface.
///
/// This proves current owner identity and fresh body-bound
/// proof-of-possession. The embedded `WebAuthn` assertion is still the
/// high-value step-up proof for the revoke mutation itself.
pub async fn authorize_owner_webauthn_revoke_credential_finish_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerWebauthnRevokeCredentialFinish",
    )
    .await
}

/// Authorize the owner `AddCredential` start surface.
///
/// This proves only current owner identity and fresh body-bound
/// proof-of-possession. The returned challenges require a live owner passkey
/// assertion and a bound registration ceremony before any future mutation.
pub async fn authorize_owner_webauthn_add_credential_start_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerWebauthnAddCredentialStart",
    )
    .await
}

/// Authorize the owner `AddCredential` finish surface.
///
/// This proves current owner identity and fresh body-bound proof-of-possession.
/// The live owner-passkey approval assertion and bound registration ceremony
/// are verified by the finish runtime before any mutation.
pub async fn authorize_owner_webauthn_add_credential_finish_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerWebauthnAddCredentialFinish",
    )
    .await
}

/// Authorize Secure/Upgrade App Attest challenge issuance.
///
/// This proves only the current owner identity plus a fresh body-bound
/// proof-of-possession. The App Attest proof and owner-key signature are bound
/// and verified by the Secure/Upgrade finish runtime.
pub async fn authorize_secure_upgrade_start_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "SecureUpgradeStart",
    )
    .await
}

/// Authorize Secure/Upgrade App Attest finish and strong owner minting.
///
/// The `PoP` only identifies the current owner submitting the ceremony; the
/// handler revalidates the stored challenge, App Attest proof, owner-key
/// signature, durable replay state, and verified provenance before minting.
pub async fn authorize_secure_upgrade_finish_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "SecureUpgradeFinish",
    )
    .await
}

/// Authorize the owner recovery-code readiness surface.
///
/// Readiness is owner-authenticated but does not grant owner auth by itself.
pub async fn authorize_owner_webauthn_recovery_status_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerWebauthnRecoveryStatus",
    )
    .await
}

/// Authorize the owner recovery-code provision start surface.
///
/// This proves only current owner identity and fresh body-bound
/// proof-of-possession. The returned `WebAuthn` challenge is the step-up proof
/// for provision/rotation.
pub async fn authorize_owner_webauthn_recovery_start_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerWebauthnRecoveryStart",
    )
    .await
}

/// Authorize the owner recovery-code provision finish surface.
///
/// The embedded `WebAuthn` assertion remains the high-value step-up proof for the
/// recovery verifier mutation.
pub async fn authorize_owner_webauthn_recovery_finish_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerWebauthnRecoveryFinish",
    )
    .await
}

/// Authorize the owner recovery-code consume start surface.
///
/// This proves only current owner identity and fresh body-bound
/// proof-of-possession. Recovery-code possession and registration binding are
/// verified by the recovery consume runtime path, not by a live passkey
/// assertion.
pub async fn authorize_owner_webauthn_recovery_consume_start_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerWebauthnRecoveryConsumeStart",
    )
    .await
}

/// Authorize the owner recovery-code consume finish surface.
///
/// Like start, this proves only current owner identity and fresh body-bound
/// proof-of-possession. The finish runtime re-proves recovery-code possession
/// and validates the registration binding before any mutation.
pub async fn authorize_owner_webauthn_recovery_consume_finish_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    authorize_owner_only_pop_request(
        state,
        headers,
        method,
        path_and_query,
        body,
        now,
        "OwnerWebauthnRecoveryConsumeFinish",
    )
    .await
}

async fn authorize_owner_only_pop_request(
    state: &HouseholdState,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    now: u64,
    operation_label: &'static str,
) -> Result<Arc<HouseholdAuthState>, AuthError> {
    let pop = SoyehtPoP::parse(headers).inspect_err(log_rejected)?;
    let skew = now.abs_diff(pop.timestamp);
    if skew > TIMESTAMP_TOLERANCE_SECS {
        log_rejected(&AuthError::Timestamp);
        return Err(AuthError::Timestamp);
    }
    let identity = state.current().await.ok_or_else(|| {
        log_rejected(&AuthError::IdentityUnavailable);
        AuthError::IdentityUnavailable
    })?;
    let owner_auth = state.current_owner_auth().await.ok_or_else(|| {
        log_rejected(&AuthError::OwnerAuthUnavailable);
        AuthError::OwnerAuthUnavailable
    })?;
    if !bool::from(
        owner_auth
            .owner_person_cert
            .p_id
            .0
            .as_bytes()
            .ct_eq(pop.p_id.as_bytes()),
    ) {
        log_rejected(&AuthError::NotAMember);
        return Err(AuthError::NotAMember);
    }
    owner_auth
        .owner_person_cert
        .verify(&identity.record.hh_id, &identity.record.hh_pub, now)
        .map_err(|_| {
            log_rejected(&AuthError::CertRejected);
            AuthError::CertRejected
        })?;
    let ctx = RequestSigningContext::new(method.as_str(), path_and_query, pop.timestamp, body);
    ctx.verify(&owner_auth.owner_person_cert.p_pub, &pop.signature)
        .map_err(|_| {
            log_rejected(&AuthError::SignatureRejected);
            AuthError::SignatureRejected
        })?;
    tracing::info!(
        stage = "household_auth.pop.accepted",
        p_id = %pop.p_id,
        operation = operation_label,
    );
    Ok(owner_auth)
}

fn log_rejected(err: &AuthError) {
    tracing::warn!(
        stage = "household_auth.pop.rejected",
        error.kind = ?err,
        "Soyeht-PoP request rejected"
    );
}

// ─── D2c-1a: device-delegated roster read ───────────────────────────────────

/// Explicit opt-in header for the delegated path. Its presence — not any
/// property of the proof — is what selects device-only dispatch.
pub const DEVICE_ID_HEADER: &str = "soyeht-device-id";

/// A `d_` identifier is `d_` plus exactly 52 lowercase RFC-4648 base32 chars
/// (BLAKE3-256 over the SEC1 key, unpadded). `DeviceId::is_well_formed` only
/// checks the prefix, which is too loose to route authority on.
const DEVICE_ID_BODY_LEN: usize = 52;

/// Who the request is authorized as. Both arms carry the same verified owner
/// auth state, so a caller reads one shape regardless of dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RosterReadActor {
    Owner {
        person_id: String,
    },
    Device {
        device_id: DeviceId,
        /// Non-zero admission generation the decision was taken against.
        generation: u64,
    },
}

/// The common authorized reader returned by [`authorize_roster_read`].
#[derive(Clone)]
pub struct AuthorizedRosterReader {
    pub owner_auth: Arc<HouseholdAuthState>,
    pub actor: RosterReadActor,
}

/// Wire-facing refusal classes.
///
/// Every device-side refusal — malformed id, unknown device, revoked device,
/// revoked person, cross-binding, wrong signature, caveat denial — collapses
/// into [`Self::DeviceUnauthenticated`] on purpose. Distinguishing them on the
/// wire would let an unauthenticated caller enumerate which `d_id`s exist and
/// what state they are in. The reason class stays in `tracing`.
#[derive(Debug, thiserror::Error)]
pub enum RosterReadAuthError {
    /// The header was absent, so the existing owner path ran and refused. Its
    /// semantics are passed through unchanged.
    #[error("owner authorization refused: {0}")]
    Owner(#[from] AuthError),
    /// The delegated path refused. Deliberately one class.
    #[error("unauthenticated")]
    DeviceUnauthenticated,
    /// The household identity, owner auth, or the durable device-admission
    /// authority is absent. Distinct from a refusal so the later handler can
    /// answer "not initialized / temporarily unavailable" rather than 401.
    #[error("device admission authority unavailable")]
    AuthorityUnavailable,
}

/// Authorize a roster-read sibling as **either** the owner **or** an admitted
/// device, chosen solely by the presence of `Soyeht-Device-Id`.
///
/// Header absent: delegates to [`authorize_request`] untouched — same `PoP`
/// bytes, same semantics, same caveat check.
///
/// Header present: device-only. There is **no** owner fallback on any device
/// failure. A malformed, unknown, revoked or wrongly-signed device id must not
/// silently succeed as the owner just because the owner's key also signed the
/// request; that would turn an explicit delegation into an escalation.
///
/// The `Soyeht-PoP` header itself is unchanged (`v1:<p_id>:<ts>:<sig>`): the
/// `p_id` slot still carries the *parent person*, and only the verifying key
/// changes — `entry.d_pub` instead of `p_pub`. iOS needs no signing change.
///
/// `live_snapshot` does blocking file I/O, so it runs inside `spawn_blocking`;
/// no lock is held across an await and none is held while a body is produced.
// Deliberately mirrors `authorize_request_with_actor`'s parameter list so the
// two dispatch arms read identically at the call site, plus the one datum the
// delegated path genuinely needs (`state_dir`, to rehydrate the authority).
// Bundling them into a struct would hide that parallel for no safety gain.
#[allow(clippy::too_many_arguments)]
pub async fn authorize_roster_read(
    state: &HouseholdState,
    state_dir: &std::path::Path,
    headers: &HeaderMap,
    method: &Method,
    path_and_query: &str,
    body: &[u8],
    operation: Operation,
    now: u64,
) -> Result<AuthorizedRosterReader, RosterReadAuthError> {
    let Some(raw_device_id) = headers.get(DEVICE_ID_HEADER) else {
        let authorized = authorize_request_with_actor(
            state,
            headers,
            method,
            path_and_query,
            body,
            operation,
            now,
        )
        .await?;
        return Ok(AuthorizedRosterReader {
            owner_auth: authorized.owner_auth,
            actor: RosterReadActor::Owner {
                person_id: authorized.actor_person_id,
            },
        });
    };

    // From here the request is device-only. Every failure below is terminal.
    let device_id = raw_device_id
        .to_str()
        .ok()
        .and_then(parse_strict_device_id)
        .ok_or_else(|| device_rejected("device_id_malformed"))?;

    let pop = SoyehtPoP::parse(headers).map_err(|_| device_rejected("pop_malformed"))?;
    if now.abs_diff(pop.timestamp) > TIMESTAMP_TOLERANCE_SECS {
        return Err(device_rejected("timestamp"));
    }

    let identity = state
        .current()
        .await
        .ok_or_else(|| authority_unavailable("identity_unavailable"))?;
    let owner_auth = state
        .current_owner_auth()
        .await
        .ok_or_else(|| authority_unavailable("owner_auth_unavailable"))?;
    let owner_cert = &owner_auth.owner_person_cert;

    // The owner cert must verify against the *live* root and clock before it is
    // allowed to stand as the device's parent.
    owner_cert
        .verify(&identity.record.hh_id, &identity.record.hh_pub, now)
        .map_err(|_| device_rejected("owner_cert_rejected"))?;

    let snapshot = {
        let state_dir = state_dir.to_path_buf();
        let record = identity.record.clone();
        let hh_id = identity.record.hh_id.clone();
        let hh_pub = identity.record.hh_pub.clone();
        match tokio::task::spawn_blocking(move || {
            let lifecycle = acquire_exact_household_lifecycle(&state_dir, &record)?;
            let snapshot =
                HouseholdDeviceAdmissionAuthorityV1::new(&state_dir, hh_id, hh_pub).live_snapshot();
            drop(lifecycle);
            Ok::<_, ExactLifecycleRefusal>(snapshot)
        })
        .await
        {
            Ok(Ok(Ok(snapshot))) => snapshot,
            Ok(Ok(Err(DeviceAdmissionError::Unavailable))) => {
                return Err(authority_unavailable("authority_absent"));
            }
            Ok(Ok(Err(_))) => return Err(device_rejected("authority_read_rejected")),
            // The durable record no longer matches the identity this request was
            // authorized against. That is a cross-binding — a property of the
            // request's binding — and the wire class above requires it to
            // collapse. Answering `AuthorityUnavailable` here would distinguish
            // it from the other fifteen device-side refusals.
            Ok(Err(ExactLifecycleRefusal::RecordChanged)) => {
                return Err(device_rejected("cross_binding"));
            }
            Ok(Err(refusal)) => return Err(authority_unavailable(refusal.reason())),
            Err(_) => return Err(authority_unavailable("authority_join_failed")),
        }
    };

    if snapshot.generation() == 0 {
        return Err(device_rejected("generation_zero"));
    }
    let entry = snapshot
        .entry(&device_id)
        .ok_or_else(|| device_rejected("device_not_listed"))?;

    // Authenticate under the device's own admitted key before acting on any
    // further field. Never `p_pub` — that is the escalation this path forbids.
    let ctx = RequestSigningContext::new(method.as_str(), path_and_query, pop.timestamp, body);
    ctx.verify(&entry.d_pub, &pop.signature)
        .map_err(|_| device_rejected("signature_rejected"))?;

    if entry.status != DeviceStatus::Active {
        return Err(device_rejected("device_not_active"));
    }
    if snapshot.is_person_revoked(&entry.p_id) {
        return Err(device_rejected("person_revoked"));
    }
    // The proof's person slot, the entry's parent, and the live owner cert must
    // all name one person, bound to the exact cert the authority admitted under.
    if !bool::from(entry.p_id.0.as_bytes().ct_eq(pop.p_id.as_bytes())) {
        return Err(device_rejected("pop_person_mismatch"));
    }
    if entry.p_id != owner_cert.p_id {
        return Err(device_rejected("owner_person_mismatch"));
    }
    let owner_digest = owner_person_cert_digest(owner_cert)
        .map_err(|_| device_rejected("owner_cert_digest_failed"))?;
    if entry.person_cert_digest.0 != owner_digest {
        return Err(device_rejected("owner_cert_digest_drift"));
    }
    if entry.person_not_after.is_some_and(|limit| now >= limit) {
        return Err(device_rejected("person_limit_expired"));
    }

    // Effective caveats: the device's own set when it declared one — including
    // `Some([])`, which grants nothing — otherwise the verified parent's set.
    let effective = entry
        .device_caveats
        .as_deref()
        .unwrap_or(&owner_cert.caveats);
    if !caveats::permits(effective, &operation) {
        return Err(device_rejected("caveat_rejected"));
    }

    tracing::info!(
        stage = "household_auth.device.accepted",
        operation = %operation,
    );
    Ok(AuthorizedRosterReader {
        owner_auth: Arc::clone(&owner_auth),
        actor: RosterReadActor::Device {
            device_id,
            generation: snapshot.generation(),
        },
    })
}

/// Strict `d_` + exactly 52 lowercase base32 characters. Anything else is not a
/// device identifier and must not reach the authority as a lookup key.
fn parse_strict_device_id(raw: &str) -> Option<DeviceId> {
    let body = raw.strip_prefix("d_")?;
    if body.len() != DEVICE_ID_BODY_LEN {
        return None;
    }
    if !body
        .bytes()
        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        return None;
    }
    Some(DeviceId(raw.to_string()))
}

/// Log the reason *class* only. No `d_id`, `p_id`, key, path, or body ever
/// reaches a log line from this path.
fn device_rejected(reason: &'static str) -> RosterReadAuthError {
    tracing::warn!(
        stage = "household_auth.device.rejected",
        reason,
        "delegated device request rejected"
    );
    RosterReadAuthError::DeviceUnauthenticated
}

fn authority_unavailable(reason: &'static str) -> RosterReadAuthError {
    tracing::warn!(
        stage = "household_auth.device.unavailable",
        reason,
        "device admission authority unavailable"
    );
    RosterReadAuthError::AuthorityUnavailable
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use household_rs::ids::{derive_household_id, derive_machine_id};
    use household_rs::keys::{IdentityKey, P256Keypair};
    use std::sync::mpsc;
    use std::time::Duration;

    fn record(name: &str) -> HouseholdRecord {
        let household = P256Keypair::generate();
        let machine = P256Keypair::generate();
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&household.public()),
            hh_pub: household.public(),
            name: name.into(),
            created_at: 1,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![derive_machine_id(&machine.public())],
            is_follower: false,
        }
    }

    #[test]
    fn exact_household_guard_blocks_replace_and_rejects_a_stale_record() {
        let temp = tempfile::tempdir().unwrap();
        let first = record("first");
        household_rs::storage::atomic_write_cbor(
            &household_rs::storage::household_record_path(temp.path()),
            &first,
        )
        .unwrap();

        let guard = acquire_exact_household_lifecycle(temp.path(), &first).unwrap();
        let contender_dir = temp.path().to_path_buf();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let contender = std::thread::spawn(move || {
            let lifecycle = HouseholdLifecycleLock::open_verified(&contender_dir).unwrap();
            let _write = lifecycle.lock_exclusive().unwrap();
            acquired_tx.send(()).unwrap();
        });
        assert!(
            acquired_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "teardown/replacement entered while a path-based authority read was live"
        );
        drop(guard);
        acquired_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        contender.join().unwrap();

        let second = record("second");
        household_rs::storage::atomic_write_cbor(
            &household_rs::storage::household_record_path(temp.path()),
            &second,
        )
        .unwrap();
        assert_eq!(
            acquire_exact_household_lifecycle(temp.path(), &first).unwrap_err(),
            ExactLifecycleRefusal::RecordChanged
        );
    }
}
