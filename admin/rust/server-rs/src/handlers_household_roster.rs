//! `GET /api/v1/household/roster/currency/{m_id}` — machine roster currency.
//!
//! Contract: Machine Roster Currency. This is the
//! B0a slice: a projection of the durable roster authority already in
//! [`household_rs::machine_roster_store`]. It admits no checkpoint and signs no
//! roster fact, but a successful query does durably advance the monotonic clock
//! floor used for temporal decisions.
//!
//! Wire is canonical CBOR (`application/cbor`), NOT the `application/json` used
//! by the household Claw Store routes — the iOS decoder for this endpoint is a
//! canonical-CBOR decoder that re-encodes the response and byte-compares, so any
//! non-canonical encoding is rejected by the client.
//!
//! Fail-closed posture:
//! - no/!valid `PoP` → 401 `unauthenticated`, never a roster fact;
//! - malformed machine id → 400 `invalid_machine_id`, no store read;
//! - any store/integrity failure → 5xx with a typed literal, never a fabricated
//!   `not_listed` (which would read as "this machine was never a member").
//!
//! The nine `outcome` literals are NOT spelled here: they come from
//! [`PublicCurrencyOutcome::wire_str`], which lives beside the enum so the
//! vocabulary has exactly one source.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    http::{HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;

use household_rs::HouseholdError;
use household_rs::ids::MachineId;
use household_rs::machine_roster_authority::{MachineRosterMemberV1, MachineRosterRevocationV1};
use household_rs::machine_roster_evidence::{
    RosterEvidenceSnapshotBody, SignedRosterEvidence, build_signed_evidence,
};
use household_rs::machine_roster_store::{
    ChainIntegrityError, MachineRosterCoordinator, PublicCurrencyOutcome, RosterStoreError,
};

use crate::household_auth;
use crate::household_state::HouseholdState;
use crate::time_util;

/// Axum path template. The `{m_id}` segment is validated with
/// [`MachineId::parse`] (`m_` + 52 base32 chars) before any store read.
pub const CURRENCY_PATH: &str = "/api/v1/household/roster/currency/{m_id}";

/// `application/cbor` — must match the iOS `RosterWire.contentType` exactly;
/// the client rejects any other media type before decoding.
pub const CONTENT_TYPE: &str = "application/cbor";

/// Combined router state: the in-memory household identity (for the `PoP` gate,
/// same as `handlers_household::machines`) plus the on-disk `state_dir` the
/// roster coordinator reads its chain/floor records from.
#[derive(Clone)]
pub struct RosterRouterState {
    pub household: HouseholdState,
    pub state_dir: PathBuf,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    v: u8,
    error: &'static str,
}

#[derive(Serialize)]
struct ActiveResponse<'a> {
    v: u8,
    outcome: &'static str,
    member: &'a MachineRosterMemberV1,
}

#[derive(Serialize)]
struct RevokedResponse<'a> {
    v: u8,
    outcome: &'static str,
    tombstone: &'a MachineRosterRevocationV1,
}

#[derive(Serialize)]
struct PlainResponse {
    v: u8,
    outcome: &'static str,
}

/// Encode a currency outcome into its canonical CBOR body.
///
/// Three closed key sets, one per outcome family:
/// - `active`  → `{v, outcome, member}`
/// - `revoked` → `{v, outcome, tombstone}` (the full 16-key canonical tombstone,
///   owner cert and signature included, so the client can verify it offline)
/// - everything else → `{v, outcome}`
///
/// `pub` so the wire shape is testable without standing up an HTTP stack.
pub fn encode_currency_body(outcome: &PublicCurrencyOutcome) -> Result<Vec<u8>, HouseholdError> {
    let literal = outcome.wire_str();
    match outcome {
        PublicCurrencyOutcome::Active { member } => {
            household_rs::cbor::to_canonical_vec(&ActiveResponse {
                v: 1,
                outcome: literal,
                member: member.as_ref(),
            })
        }
        PublicCurrencyOutcome::Revoked { tombstone } => {
            household_rs::cbor::to_canonical_vec(&RevokedResponse {
                v: 1,
                outcome: literal,
                tombstone: tombstone.as_ref(),
            })
        }
        _ => household_rs::cbor::to_canonical_vec(&PlainResponse {
            v: 1,
            outcome: literal,
        }),
    }
}

/// Typed store failure → (HTTP status, wire literal).
///
/// Exhaustive on purpose: a new `RosterStoreError` variant must be given a
/// literal here rather than collapsing into a generic 500, so the client keeps
/// getting a diagnosable code. `not_initialized` and `lock_timeout` are the two
/// "ask again later" conditions and are the only 503s.
fn store_error_wire(err: &RosterStoreError) -> (StatusCode, &'static str) {
    match err {
        RosterStoreError::NotInitialized => (StatusCode::SERVICE_UNAVAILABLE, "not_initialized"),
        RosterStoreError::LockTimeout => (StatusCode::SERVICE_UNAVAILABLE, "lock_timeout"),
        RosterStoreError::Io { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "store_io"),
        RosterStoreError::UnsafeFileType { .. } => {
            (StatusCode::INTERNAL_SERVER_ERROR, "unsafe_file_type")
        }
        RosterStoreError::TempAlreadyExists => {
            (StatusCode::INTERNAL_SERVER_ERROR, "temp_already_exists")
        }
        RosterStoreError::ModeMismatch => (StatusCode::INTERNAL_SERVER_ERROR, "mode_mismatch"),
        RosterStoreError::InvalidPath => (StatusCode::INTERNAL_SERVER_ERROR, "invalid_path"),
        RosterStoreError::AlreadyInitialized => (StatusCode::CONFLICT, "already_initialized"),
        RosterStoreError::InconsistentProvisioningState => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "inconsistent_provisioning_state",
        ),
        RosterStoreError::ReadbackMismatch => {
            (StatusCode::INTERNAL_SERVER_ERROR, "readback_mismatch")
        }
        RosterStoreError::LatchPoisoned => (StatusCode::INTERNAL_SERVER_ERROR, "latch_poisoned"),
        RosterStoreError::InvalidCurrentOwnerAuthority => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_current_owner_authority",
        ),
        RosterStoreError::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "storage"),
        RosterStoreError::Household(_) => (StatusCode::INTERNAL_SERVER_ERROR, "household"),
        RosterStoreError::OwnerAuth(_) => (StatusCode::INTERNAL_SERVER_ERROR, "owner_auth"),
        RosterStoreError::Integrity(inner) => {
            (StatusCode::INTERNAL_SERVER_ERROR, integrity_wire(*inner))
        }
    }
}

/// Chain integrity failure → `integrity_*` literal. One literal per variant.
fn integrity_wire(err: ChainIntegrityError) -> &'static str {
    match err {
        ChainIntegrityError::NonCanonicalRecord => "integrity_non_canonical",
        ChainIntegrityError::DuplicateKey => "integrity_duplicate_key",
        ChainIntegrityError::UnknownField => "integrity_unknown_field",
        ChainIntegrityError::NullField => "integrity_null_field",
        ChainIntegrityError::VersionMismatch => "integrity_version",
        ChainIntegrityError::HouseholdMismatch => "integrity_household",
        ChainIntegrityError::InvalidStateKeySet => "integrity_key_set",
        ChainIntegrityError::CheckpointDecode => "integrity_checkpoint_decode",
        ChainIntegrityError::CheckpointSignature => "integrity_checkpoint_signature",
        ChainIntegrityError::OwnerCertificate => "integrity_owner_certificate",
        ChainIntegrityError::OwnerContinuity => "integrity_owner_continuity",
        ChainIntegrityError::SequenceRelation => "integrity_sequence",
        ChainIntegrityError::HashRelation => "integrity_hash",
        ChainIntegrityError::Projection => "integrity_projection",
        ChainIntegrityError::ForkReapplyMismatch => "integrity_fork_reapply",
        ChainIntegrityError::Temporal => "integrity_temporal",
        ChainIntegrityError::EpochRelation => "integrity_epoch",
    }
}

fn cbor_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut resp = (status, body).into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Canonical `{v: 1, error: "<literal>"}` envelope — exactly two keys, which is
/// what the client's envelope decoder requires before it will surface a typed
/// error instead of a generic malformed-response.
fn error_response(status: StatusCode, code: &'static str) -> Response {
    match household_rs::cbor::to_canonical_vec(&ErrorEnvelope { v: 1, error: code }) {
        Ok(body) => cbor_response(status, body),
        // Encoding a two-key literal map cannot fail in practice; if it somehow
        // does, still fail closed with the status and uniform anti-cache/media
        // headers. The empty body remains deliberately undecodable as an error
        // envelope.
        Err(_) => cbor_response(status, Vec::new()),
    }
}

/// `GET /api/v1/household/roster/currency/{m_id}` — owner-authed, read-only
/// currency for one machine.
///
/// Gate order is deliberate: clock → `PoP` → body shape → machine id → store.
/// Authorization runs before any request-shape complaint so an unauthenticated
/// caller learns only "401", and the store is touched only after the id is
/// known well-formed.
pub async fn currency(
    State(state): State<RosterRouterState>,
    Path(m_id_raw): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let Some(now) = time_util::unix_now_secs_checked("household.roster.currency.clock") else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable");
    };
    // Owner **or** an admitted household device, selected solely by the presence
    // of `Soyeht-Device-Id`. This is a household read, and `ClawsList` is the
    // read capability every delegated household device already carries.
    //
    // Header absent: the owner `PoP` gate is exactly the one
    // `handlers_household::{snapshot, machines}` use, unchanged.
    //
    // Header present: device-only and terminal. A valid *owner* signature never
    // rescues a device-selected request — silently falling back would turn an
    // explicit delegation into an escalation. Every device-side refusal is one
    // collapsed `unauthenticated`, so an unauthenticated caller cannot use the
    // status to enumerate which devices exist or what state they are in; the
    // reason class stays in the helper's own tracing. Only a genuinely absent
    // admission authority is distinguishable, as `not_initialized`.
    let owner_auth = match household_auth::authorize_roster_read(
        &state.household,
        &state.state_dir,
        &headers,
        &method,
        &path_and_query,
        &body,
        household_rs::caveats::Operation::ClawsList,
        now,
    )
    .await
    {
        // The actor is deliberately dropped here: the coordinator is rehydrated
        // from the owner auth the helper verified, and no `d_id`/`p_id`/actor
        // ever reaches this handler's logging or its wire vocabulary.
        Ok(reader) => reader.owner_auth,
        Err(
            household_auth::RosterReadAuthError::Owner(_)
            | household_auth::RosterReadAuthError::DeviceUnauthenticated,
        ) => {
            return error_response(StatusCode::UNAUTHORIZED, "unauthenticated");
        }
        Err(household_auth::RosterReadAuthError::AuthorityUnavailable) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "not_initialized");
        }
    };

    // GET carries no body. The PoP signature covers the body, so a signed
    // non-empty body is authentic — it is still refused, because this endpoint
    // has no request payload and accepting one would leave an unread,
    // unvalidated field on an authenticated path.
    if !body.is_empty() {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "body_not_allowed");
    }

    let Ok(m_id) = MachineId::parse(m_id_raw) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_machine_id");
    };

    let Some(identity) = state.household.current().await else {
        // Authorization already proved a loaded household; losing it between
        // the two reads is a shutdown/reload race, not a client error.
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "not_initialized");
    };

    // The coordinator takes a cross-process file lock and does blocking file
    // I/O, so it must not run on the async executor.
    let state_dir = state.state_dir.clone();
    let record = identity.record.clone();
    let auth = owner_auth.clone();
    let queried = tokio::task::spawn_blocking(move || {
        let _lifecycle = household_auth::acquire_exact_household_lifecycle(&state_dir, &record)
            .map_err(|_| RosterStoreError::InvalidCurrentOwnerAuthority)?;
        let coordinator =
            MachineRosterCoordinator::from_validated_household(&state_dir, &record, &auth)?;
        coordinator.query_machine_currency(&m_id)
    })
    .await;

    let outcome = match queried {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(err)) => {
            let (status, code) = store_error_wire(&err);
            tracing::warn!(stage = "household.roster.currency.store_error", code,);
            return error_response(status, code);
        }
        Err(join_err) => {
            tracing::error!(
                stage = "household.roster.currency.join_error",
                error = %join_err,
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
        }
    };

    match encode_currency_body(&outcome) {
        Ok(body) => {
            tracing::debug!(
                stage = "household.roster.currency.served",
                outcome = outcome.wire_str(),
            );
            cbor_response(StatusCode::OK, body)
        }
        Err(err) => {
            tracing::error!(
                stage = "household.roster.currency.encode_failed",
                error = %err,
            );
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "encode_failed")
        }
    }
}

// ─── B0b: roster evidence ───────────────────────────────────────────────────

/// Axum path template. Unlike currency this route carries **no** `m_id`, which
/// is why `invalid_machine_id` and `query_not_allowed` never appear here.
pub const EVIDENCE_PATH: &str = "/api/v1/household/roster/evidence";

/// The request is a two-key map; anything larger is refused before decoding.
const MAX_EVIDENCE_REQUEST_BYTES: usize = 1024;

/// Exactly `{client_nonce: bstr[32], v: 1}`. `deny_unknown_fields` is the point:
/// an unrecognised key is a rejection, never something to ignore.
#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRequest {
    #[serde(with = "household_rs::machine_roster_evidence::request_bstr32")]
    client_nonce: [u8; 32],
    v: u8,
}

/// Served when the outcome is `available` — exactly ten keys.
#[derive(Serialize)]
struct EvidenceAvailableWire<'a> {
    client_nonce: &'a serde_bytes::Bytes,
    full_snapshot_digest: &'a serde_bytes::Bytes,
    outcome: &'a str,
    signature: &'a serde_bytes::Bytes,
    signer_m_id: &'a str,
    signer_machine_cert: &'a serde_bytes::Bytes,
    signer_machine_cert_fingerprint: &'a serde_bytes::Bytes,
    snapshot_body: &'a RosterEvidenceSnapshotBody,
    state_evidence_digest: &'a serde_bytes::Bytes,
    v: u8,
}

/// Served for every `unavailable_*` — exactly seven keys. `snapshot_body`,
/// `state_evidence_digest` and `full_snapshot_digest` are **absent**, not null:
/// the client treats their presence as a protocol violation.
#[derive(Serialize)]
struct EvidenceUnavailableWire<'a> {
    client_nonce: &'a serde_bytes::Bytes,
    outcome: &'a str,
    signature: &'a serde_bytes::Bytes,
    signer_m_id: &'a str,
    signer_machine_cert: &'a serde_bytes::Bytes,
    signer_machine_cert_fingerprint: &'a serde_bytes::Bytes,
    v: u8,
}

/// Encode a signed evidence result into its frozen available/unavailable wire.
///
/// Public so the closed key sets and nested-map body can be contract-tested
/// without duplicating the handler's serialization.
pub fn encode_evidence_body(evidence: &SignedRosterEvidence) -> Result<Vec<u8>, HouseholdError> {
    let nonce = serde_bytes::Bytes::new(&evidence.client_nonce);
    let signature = serde_bytes::Bytes::new(evidence.signature.as_bytes());
    let cert = serde_bytes::Bytes::new(&evidence.signer_machine_cert);
    let fingerprint = serde_bytes::Bytes::new(&evidence.signer_machine_cert_fingerprint);
    match (
        evidence.snapshot_body.as_ref(),
        evidence.state_evidence_digest.as_ref(),
        evidence.full_snapshot_digest.as_ref(),
    ) {
        (Some(snapshot_body), Some(state_digest), Some(full_digest)) => {
            // @kiana found this by reading the frozen iOS verifier; the
            // original server tests only asserted key presence and therefore
            // missed that a bstr containing CBOR is not the required nested map.
            household_rs::cbor::to_canonical_vec(&EvidenceAvailableWire {
                client_nonce: nonce,
                full_snapshot_digest: serde_bytes::Bytes::new(full_digest),
                outcome: evidence.outcome.wire_str(),
                signature,
                signer_m_id: &evidence.signer_m_id,
                signer_machine_cert: cert,
                signer_machine_cert_fingerprint: fingerprint,
                snapshot_body,
                state_evidence_digest: serde_bytes::Bytes::new(state_digest),
                v: 1,
            })
        }
        _ => household_rs::cbor::to_canonical_vec(&EvidenceUnavailableWire {
            client_nonce: nonce,
            outcome: evidence.outcome.wire_str(),
            signature,
            signer_m_id: &evidence.signer_m_id,
            signer_machine_cert: cert,
            signer_machine_cert_fingerprint: fingerprint,
            v: 1,
        }),
    }
}

/// The request media type must be exactly `application/cbor`; absent or
/// anything else is 415, never a lenient parse.
fn evidence_content_type_exact(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == CONTENT_TYPE)
}

/// `POST /api/v1/household/roster/evidence`.
///
/// Gate order matches currency: clock → auth → body → shape → identity → store.
///
/// Authorization is the shared `authorize_roster_read`, so the owner path is
/// byte-identical to currency's and a present `Soyeht-Device-Id` selects a
/// terminal device-only path with no fallback in either direction.
///
/// An `unavailable_*` is a **200** carrying a signed, signer-anchored statement
/// — not an error envelope. It therefore requires a usable signer: if the
/// machine identity or its key is missing the answer is 503 `not_initialized`,
/// and a signing failure is 500 `sign_failed`. Neither is an `unavailable_*`,
/// because those four literals describe the *roster*, and "this machine cannot
/// sign" is not a fact about the roster.
pub async fn evidence(
    State(state): State<RosterRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());

    let Some(now) = time_util::unix_now_secs_checked("household.roster.evidence.clock") else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "clock_unavailable");
    };

    let owner_auth = match household_auth::authorize_roster_read(
        &state.household,
        &state.state_dir,
        &headers,
        &method,
        &path_and_query,
        &body,
        household_rs::caveats::Operation::ClawsList,
        now,
    )
    .await
    {
        // The actor is dropped: no `d_id`/`p_id`/actor reaches this handler's
        // logging or wire vocabulary.
        Ok(reader) => reader.owner_auth,
        Err(
            household_auth::RosterReadAuthError::Owner(_)
            | household_auth::RosterReadAuthError::DeviceUnauthenticated,
        ) => return error_response(StatusCode::UNAUTHORIZED, "unauthenticated"),
        Err(household_auth::RosterReadAuthError::AuthorityUnavailable) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "not_initialized");
        }
    };

    if body.len() > MAX_EVIDENCE_REQUEST_BYTES {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
    }
    if !evidence_content_type_exact(&headers) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
    }

    let Ok(request) = household_rs::cbor::from_canonical_slice::<EvidenceRequest>(&body) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if request.v != 1 {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // Re-encode and byte-compare: a decodable but non-canonical request is
    // refused rather than normalized, so the nonce the client signed over and
    // the bytes we echo cannot diverge.
    match household_rs::cbor::to_canonical_vec(&EvidenceRequest {
        client_nonce: request.client_nonce,
        v: request.v,
    }) {
        Ok(canonical) if canonical == body.as_ref() => {}
        _ => return error_response(StatusCode::BAD_REQUEST, "invalid_request"),
    }
    let client_nonce = request.client_nonce;

    let Some(identity) = state.household.current().await else {
        // Authorization already proved a loaded household; losing it here is a
        // shutdown/reload race, not a client error.
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "not_initialized");
    };

    let state_dir = state.state_dir.clone();
    let record = identity.record.clone();
    let auth = owner_auth.clone();
    let signer = Arc::clone(&identity);
    let produced = tokio::task::spawn_blocking(move || {
        let _lifecycle = household_auth::acquire_exact_household_lifecycle(&state_dir, &record)
            .map_err(|_| RosterStoreError::InvalidCurrentOwnerAuthority)?;
        let coordinator =
            MachineRosterCoordinator::from_validated_household(&state_dir, &record, &auth)?;
        // The store lock is taken and released inside this call; the body is
        // built, digested and signed below with no lock held.
        let (outcome, snapshot) = coordinator.query_roster_evidence(&signer.cert.m_id)?;
        Ok::<_, RosterStoreError>(build_signed_evidence(
            outcome,
            client_nonce,
            &signer.cert,
            signer.m_priv.as_ref(),
            snapshot.as_ref(),
        ))
    })
    .await;

    let evidence = match produced {
        Ok(Ok(Ok(evidence))) => evidence,
        Ok(Ok(Err(err))) => {
            tracing::error!(stage = "household.roster.evidence.sign_failed", error = %err);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "sign_failed");
        }
        Ok(Err(err)) => {
            let (status, code) = store_error_wire(&err);
            tracing::warn!(stage = "household.roster.evidence.store_error", error = %err, code);
            return error_response(status, code);
        }
        Err(join_err) => {
            tracing::error!(stage = "household.roster.evidence.join_error", error = %join_err);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
        }
    };

    match encode_evidence_body(&evidence) {
        Ok(encoded) => {
            tracing::info!(
                stage = "household.roster.evidence.served",
                outcome = evidence.outcome.wire_str(),
            );
            cbor_response(StatusCode::OK, encoded)
        }
        Err(err) => {
            tracing::error!(stage = "household.roster.evidence.encode_failed", error = %err);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "encode_failed")
        }
    }
}

#[cfg(test)]
mod tests;
