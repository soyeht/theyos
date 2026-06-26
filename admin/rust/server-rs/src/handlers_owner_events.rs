//! Phase 3 owner-events long-poll, owner approve/decline, and push-token
//! registration endpoints (`contracts/owner-events.md`,
//! `contracts/push-token-register.md`).
//!
//! Module skeleton committed in T006 of the Phase 3 task list. Endpoint
//! implementations arrive in T047–T057.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use household_rs::caveats::Operation;
use household_rs::owner_approval_v2::{
    OwnerApprovalContextV2, OwnerApprovalV2, OwnerApprovalV2Error, OwnerOperation,
    PairMachineTrustedContextInput,
};
use household_rs::owner_events::{
    JoinCancelledPayload, MachineJoinedPayload, OwnerDevicePushToken, OwnerEvent, OwnerEventLog,
    OwnerEventPayload, OwnerEventType, OwnerEventsBroadcaster,
};
use household_rs::owner_webauthn::{OwnerWebauthnChallengeId, OwnerWebauthnRp};
use household_rs::owner_webauthn_anchor::{
    OwnerWebauthnAnchorMode, verify_or_update_owner_webauthn_authority_anchor,
};
use household_rs::pair_machine::{
    CeremonyError, CeremonyInputs, CeremonyTxn, FinalizeWithM2Options, FinalizeWithM2Outcome,
    JoinRequest, OwnerApproval, OwnerApprovalContext, PairMachineState, PairMachineWindow,
    PairMachineWindowSnapshot, join_request_hash,
};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_bytes::ByteBuf;
use tokio::sync::Mutex;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::watch;
use webauthn_rs::prelude::{
    CreationChallengeResponse, RegisterPublicKeyCredential, RequestChallengeResponse, Uuid,
};
use zeroize::Zeroizing;

use crate::apns_dispatcher;
use crate::handlers_device_pairing::DevicePairingStore;
use crate::household_auth;
use crate::household_state::HouseholdState;
use crate::time_util;

const CBOR_CONTENT_TYPE: &str = "application/cbor";
const OWNER_EVENTS_LONG_POLL_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Clone)]
pub struct OwnerEventsRouterState {
    pub household: HouseholdState,
    pub window: Arc<PairMachineWindow>,
    pub event_log: Arc<OwnerEventLog>,
    pub event_broadcaster: OwnerEventsBroadcaster,
    pub state_dir: PathBuf,
    pub long_poll_timeout: Duration,
    pub device_pairing_store: DevicePairingStore,
    /// Keystore policy under which `HH_priv` was originally persisted.
    /// `owner_approve_handler` forwards it into `CeremonyInputs` so
    /// `CeremonyTxn::commit` can destroy the right backend on Shamir
    /// transition.
    pub key_backing_policy: household_rs::KeyBackingPolicy,
    /// Owner-auth rollout policy. Defaults to legacy behavior for every
    /// operation so introducing S2 primitives cannot brick existing onboarding.
    pub owner_approval_policy: OwnerApprovalEnforcementPolicy,
    /// Tenant-scoped `WebAuthn` relying party for owner-approval ceremonies.
    ///
    /// `None` keeps the v2 owner-approval surface fail-closed. The production
    /// flip must inject a tenant RP; default router construction remains
    /// behavior-preserving.
    pub owner_webauthn_rp: Option<Arc<Mutex<OwnerWebauthnRp>>>,
    /// Keystore-backed rollback anchor verifier for owner passkey authority.
    ///
    /// Pair-machine v2 enforcement requires this before it can decide whether
    /// an owner has active credentials. This prevents a rolled-back credential
    /// log from re-enabling a revoked passkey or downgrading to legacy.
    pub owner_webauthn_anchor: Option<OwnerWebauthnAnchorVerifier>,
}

#[derive(Clone)]
pub struct OwnerWebauthnAnchorVerifier {
    pub keystore: Arc<dyn keystore_rs::KeystoreBackend>,
}

impl OwnerEventsRouterState {
    #[must_use]
    pub fn new(
        household: HouseholdState,
        window: Arc<PairMachineWindow>,
        event_log: Arc<OwnerEventLog>,
        event_broadcaster: OwnerEventsBroadcaster,
        state_dir: PathBuf,
        key_backing_policy: household_rs::KeyBackingPolicy,
    ) -> Self {
        Self::with_timeout(
            household,
            window,
            event_log,
            event_broadcaster,
            state_dir,
            key_backing_policy,
            OWNER_EVENTS_LONG_POLL_TIMEOUT,
        )
    }

    #[must_use]
    pub fn with_timeout(
        household: HouseholdState,
        window: Arc<PairMachineWindow>,
        event_log: Arc<OwnerEventLog>,
        event_broadcaster: OwnerEventsBroadcaster,
        state_dir: PathBuf,
        key_backing_policy: household_rs::KeyBackingPolicy,
        long_poll_timeout: Duration,
    ) -> Self {
        Self {
            household,
            window,
            event_log,
            event_broadcaster,
            state_dir,
            long_poll_timeout,
            device_pairing_store: DevicePairingStore::new(),
            key_backing_policy,
            owner_approval_policy: OwnerApprovalEnforcementPolicy::default(),
            owner_webauthn_rp: None,
            owner_webauthn_anchor: None,
        }
    }

    #[must_use]
    pub fn with_owner_approval_policy(
        mut self,
        owner_approval_policy: OwnerApprovalEnforcementPolicy,
    ) -> Self {
        self.owner_approval_policy = owner_approval_policy;
        self
    }

    #[must_use]
    pub fn with_owner_webauthn_rp(mut self, rp: OwnerWebauthnRp) -> Self {
        self.owner_webauthn_rp = Some(Arc::new(Mutex::new(rp)));
        self
    }

    #[must_use]
    pub fn with_owner_webauthn_anchor(
        mut self,
        keystore: Arc<dyn keystore_rs::KeystoreBackend>,
    ) -> Self {
        self.owner_webauthn_anchor = Some(OwnerWebauthnAnchorVerifier { keystore });
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerApprovalEnforcementPolicy {
    pub pair_machine_approve: OwnerOperationEnforcement,
    pub bootstrap_initialize: OwnerOperationEnforcement,
    pub bootstrap_teardown: OwnerOperationEnforcement,
    pub pair_device_confirm: OwnerOperationEnforcement,
    pub revoke_credential: OwnerOperationEnforcement,
}

impl Default for OwnerApprovalEnforcementPolicy {
    fn default() -> Self {
        Self {
            pair_machine_approve: OwnerOperationEnforcement::LegacyOnly,
            bootstrap_initialize: OwnerOperationEnforcement::LegacyOnly,
            bootstrap_teardown: OwnerOperationEnforcement::LegacyOnly,
            pair_device_confirm: OwnerOperationEnforcement::LegacyOnly,
            revoke_credential: OwnerOperationEnforcement::LegacyOnly,
        }
    }
}

impl OwnerApprovalEnforcementPolicy {
    #[must_use]
    pub fn with_pair_machine_approve(mut self, mode: OwnerOperationEnforcement) -> Self {
        self.pair_machine_approve = mode;
        self
    }

    #[must_use]
    pub fn pair_machine_approval_body_mode(
        &self,
        owner_has_active_webauthn_credential: bool,
    ) -> PairMachineApprovalBodyMode {
        self.pair_machine_approve
            .body_mode(owner_has_active_webauthn_credential)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerOperationEnforcement {
    /// Preserve the existing v1 owner-PoP approval path.
    LegacyOnly,
    /// Require v2 only after the owner has at least one active `WebAuthn`
    /// credential. Before enrollment exists, fall back to legacy so this flag
    /// cannot brick pair-machine onboarding during migration.
    V2WhenOwnerHasActiveCredential,
}

impl OwnerOperationEnforcement {
    #[must_use]
    fn body_mode(self, owner_has_active_webauthn_credential: bool) -> PairMachineApprovalBodyMode {
        match (self, owner_has_active_webauthn_credential) {
            (Self::LegacyOnly, _) | (Self::V2WhenOwnerHasActiveCredential, false) => {
                PairMachineApprovalBodyMode::LegacyV1
            }
            (Self::V2WhenOwnerHasActiveCredential, true) => PairMachineApprovalBodyMode::RequireV2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairMachineApprovalBodyMode {
    LegacyV1,
    RequireV2,
}

pub fn reassert_pair_machine_approval_context_against_live_window(
    approved_context: &OwnerApprovalContextV2,
    live_snapshot: &PairMachineWindowSnapshot,
) -> Result<(), OwnerApprovalV2Error> {
    if approved_context.op != OwnerOperation::PairMachineApprove {
        return Err(OwnerApprovalV2Error::TrustedState(
            "operation is not pair-machine approve",
        ));
    }
    let cursor = approved_context
        .cursor
        .ok_or(OwnerApprovalV2Error::MissingField("cursor"))?;
    if live_snapshot.state != PairMachineState::AwaitingOwner
        || live_snapshot.owner_event_cursor != Some(cursor)
    {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window cursor changed",
        ));
    }
    if live_snapshot.approval_claim.is_some() {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window already claimed",
        ));
    }
    if live_snapshot.expiry != approved_context.ttl_unix {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window ttl changed",
        ));
    }
    if live_snapshot.addr_hint.as_deref() != approved_context.addr.as_deref() {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window addr changed",
        ));
    }
    if live_snapshot.transport != approved_context.transport {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window transport changed",
        ));
    }
    if live_snapshot.nonce.as_ref().map(ByteBuf::as_ref)
        != approved_context.nonce.as_ref().map(ByteBuf::as_ref)
    {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live window nonce changed",
        ));
    }
    let cached_join_request =
        live_snapshot
            .cached_join_request
            .as_ref()
            .ok_or(OwnerApprovalV2Error::TrustedState(
                "missing live cached join request",
            ))?;
    let live_join_request_hash = join_request_hash(cached_join_request);
    if approved_context
        .join_request_hash
        .as_ref()
        .map(ByteBuf::as_ref)
        != Some(live_join_request_hash.as_slice())
    {
        return Err(OwnerApprovalV2Error::TrustedState(
            "live join request changed",
        ));
    }
    Ok(())
}

fn owner_approval_v2_capabilities() -> Vec<String> {
    vec!["machine-cert".to_string(), "shamir-2pc".to_string()]
}

fn pair_machine_window_data(
    cursor: u64,
    snapshot: PairMachineWindowSnapshot,
) -> Result<PairMachineWindowData, &'static str> {
    if snapshot.state != PairMachineState::AwaitingOwner
        || snapshot.owner_event_cursor != Some(cursor)
    {
        return Err("window_cursor_mismatch");
    }
    if snapshot.approval_claim.is_some() {
        return Err("window_already_claimed");
    }
    let active_m_pub = snapshot.m_pub.clone().ok_or("window_missing_m_pub")?;
    let cached_join_request = snapshot
        .cached_join_request
        .clone()
        .ok_or("missing_cached_join_request")?;
    let join_request = household_rs::cbor::from_canonical_slice(cached_join_request.as_ref())
        .map_err(|_| "cached_join_request_decode")?;
    Ok(PairMachineWindowData {
        snapshot,
        active_m_pub,
        cached_join_request,
        join_request,
    })
}

fn pair_machine_expected_context_from_snapshot(
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
    snapshot: &PairMachineWindowSnapshot,
    now: u64,
    challenge_ttl_secs: u64,
    replay_nonce: [u8; 32],
) -> Result<OwnerApprovalContextV2, OwnerApprovalV2Error> {
    OwnerApprovalContextV2::pair_machine_approve_from_trusted_state(
        PairMachineTrustedContextInput {
            hh_id: identity.record.hh_id.clone(),
            owner_p_id: owner_auth.owner_person_cert.p_id.clone(),
            snapshot,
            capabilities: owner_approval_v2_capabilities(),
            issued_at: now,
            challenge_ttl_secs,
            replay_nonce,
        },
    )
}

fn pair_machine_credentials_for_policy(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> Result<Option<household_rs::owner_webauthn::OwnerWebauthnCredentialStore>, String> {
    if state.owner_approval_policy.pair_machine_approve == OwnerOperationEnforcement::LegacyOnly {
        return Ok(None);
    }
    let verifier = state
        .owner_webauthn_anchor
        .as_ref()
        .ok_or_else(|| "owner webauthn anchor verifier unavailable".to_string())?;
    verify_or_update_owner_webauthn_authority_anchor(
        verifier.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .map_err(|e| e.to_string())?;
    owner_auth
        .owner_webauthn_credentials(&identity.record)
        .map(Some)
        .map_err(|e| e.to_string())
}

fn parse_pair_machine_approval_body(
    mode: PairMachineApprovalBodyMode,
    cursor: u64,
    body: &[u8],
) -> Result<PairMachineApprovalWireBody, &'static str> {
    match mode {
        PairMachineApprovalBodyMode::LegacyV1 => {
            let approval: OwnerApproval =
                household_rs::cbor::from_canonical_slice(body).map_err(|_| "cbor_decode")?;
            match approval.to_canonical_bytes() {
                Ok(canonical) if canonical == body => {}
                Ok(_) => return Err("non_canonical_cbor"),
                Err(_) => return Err("cbor_reencode"),
            }
            if approval.version != 1 || approval.cursor != cursor {
                return Err("body_cursor_mismatch");
            }
            Ok(PairMachineApprovalWireBody::LegacyV1(approval))
        }
        PairMachineApprovalBodyMode::RequireV2 => {
            let finish: OwnerApprovalV2Finish =
                household_rs::cbor::from_canonical_slice(body).map_err(|_| "cbor_decode")?;
            let canonical =
                household_rs::cbor::to_canonical_vec(&finish).map_err(|_| "cbor_reencode")?;
            if canonical != body {
                return Err("non_canonical_cbor");
            }
            if finish.version != 1 || finish.approval.context.cursor != Some(cursor) {
                return Err("body_cursor_mismatch");
            }
            finish
                .approval
                .validate_shape()
                .map_err(|_| "approval_v2_shape")?;
            Ok(PairMachineApprovalWireBody::V2(Box::new(finish)))
        }
    }
}

#[derive(Serialize)]
struct OwnerEventsResponse {
    #[serde(rename = "v")]
    version: u8,
    events: Vec<OwnerEvent>,
    next_cursor: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerApprovalV2StartRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Serialize)]
struct OwnerApprovalV2StartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    context: OwnerApprovalContextV2,
    options: RequestChallengeResponse,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationStartRequest {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Serialize)]
struct OwnerWebauthnRegistrationStartResponse {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    options: CreationChallengeResponse,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerWebauthnRegistrationFinishRequest {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    credential: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
struct OwnerWebauthnRegistrationFinishResponse {
    #[serde(rename = "v")]
    version: u8,
    credential_id: ByteBuf,
    active_credential_count: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerApprovalV2Finish {
    #[serde(rename = "v")]
    version: u8,
    challenge_id: String,
    approval: OwnerApprovalV2,
}

enum PairMachineApprovalWireBody {
    LegacyV1(OwnerApproval),
    V2(Box<OwnerApprovalV2Finish>),
}

struct PairMachineWindowData {
    snapshot: PairMachineWindowSnapshot,
    active_m_pub: ByteBuf,
    cached_join_request: ByteBuf,
    join_request: JoinRequest,
}

#[derive(Deserialize)]
struct PushTokenRegisterRequest {
    #[serde(rename = "v")]
    version: u8,
    platform: String,
    push_token: ByteBuf,
}

#[derive(Serialize)]
struct PushTokenRegisterResponse {
    #[serde(rename = "v")]
    version: u8,
    updated_at: u64,
}

#[derive(Serialize)]
struct OwnerDeclineAck {
    #[serde(rename = "v")]
    version: u8,
}

#[derive(Serialize)]
struct OwnerApprovalAck {
    #[serde(rename = "v")]
    version: u8,
    machine_cert_hash: ByteBuf,
}

#[derive(Serialize)]
struct GenericError<'a> {
    #[serde(rename = "v")]
    version: u8,
    error: &'a str,
}

enum FinalizeAttempt {
    Acked(Box<CeremonyTxn>, Box<FinalizeWithM2Outcome>),
    DefiniteFailure(CeremonyError),
    AmbiguousFailure(CeremonyError),
}

fn cbor_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    resp
}

fn generic_error_response(status: StatusCode, error: &'static str) -> Response {
    let bytes = household_rs::cbor::to_canonical_vec(&GenericError { version: 1, error })
        .unwrap_or_default();
    cbor_response(status, bytes)
}

fn unauthenticated_response() -> Response {
    generic_error_response(StatusCode::UNAUTHORIZED, "unauthenticated")
}

fn internal_error_response() -> Response {
    generic_error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal")
}

fn decode_canonical_cbor<T>(body: &[u8]) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = household_rs::cbor::from_canonical_slice(body).map_err(|e| e.to_string())?;
    let canonical = household_rs::cbor::to_canonical_vec(&value).map_err(|e| e.to_string())?;
    if canonical != body {
        return Err("non_canonical_cbor".into());
    }
    Ok(value)
}

/// `GET /api/v1/household/owner-events?since=<cursor>` long-poll endpoint.
///
/// The cursor is base64url-no-pad over a deterministic-CBOR unsigned integer.
/// Auth failures and malformed cursors collapse to the generic Phase 3
/// unauthenticated surface; operator-only detail is emitted via tracing.
pub async fn owner_events_long_poll(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.long_poll.clock") else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    if let Err(e) = household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdAddMachine,
        now,
    )
    .await
    {
        tracing::warn!(
            stage = "owner_events.long_poll.rejected",
            reason = "pop_auth_failed",
            error = %e,
        );
        return unauthenticated_response();
    }

    let Ok(since) = decode_since_cursor(&uri) else {
        tracing::warn!(
            stage = "owner_events.long_poll.rejected",
            reason = "cursor_decode",
        );
        return unauthenticated_response();
    };

    if state.event_log.cursor_head() > since {
        return owner_events_since_response(&state, since);
    }

    let mut subscription = state.event_broadcaster.subscribe();

    // Close the race where an append lands after the initial head check but
    // before this request subscribes to the broadcaster.
    if state.event_log.cursor_head() > since {
        return owner_events_since_response(&state, since);
    }

    let timeout = tokio::time::sleep(state.long_poll_timeout);
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            biased;

            () = &mut timeout => {
                // Positive observability gate (T093) — the long-poll
                // wait elapsed without any matching owner event. Distinct
                // from `long_poll.rejected` (auth/decode failure) so the
                // audit can distinguish "owner is idle / iPhone is
                // backgrounded" from "request was malformed".
                tracing::info!(
                    stage = "owner_events.long_poll.timeout",
                    since = since,
                );
                return StatusCode::NO_CONTENT.into_response();
            }
            received = subscription.receiver_mut().recv() => {
                match received {
                    Ok(event) if event.cursor > since => {
                        return owner_events_since_response(&state, since);
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        if state.event_log.cursor_head() > since {
                            return owner_events_since_response(&state, since);
                        }
                    }
                    Err(RecvError::Closed) => {
                        return StatusCode::NO_CONTENT.into_response();
                    }
                }
            }
        }
    }
}

fn decode_since_cursor(uri: &Uri) -> Result<u64, ()> {
    let query = uri.query().ok_or(())?;
    let raw = query
        .split('&')
        .find_map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            (key == "since").then_some(value)
        })
        .ok_or(())?;
    if raw.is_empty() {
        return Err(());
    }
    let bytes = B64URL.decode(raw).map_err(|_| ())?;
    household_rs::cbor::from_canonical_slice::<u64>(&bytes).map_err(|_| ())
}

fn owner_events_since_response(state: &OwnerEventsRouterState, since: u64) -> Response {
    let events = match state.event_log.read_since(since) {
        Ok(events) => events,
        Err(e) => {
            tracing::error!(
                stage = "owner_events.long_poll.read_failed",
                error = %e,
            );
            return internal_error_response();
        }
    };
    let next_cursor = events.last().map_or(since, |event| event.cursor);
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerEventsResponse {
        version: 1,
        events,
        next_cursor,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

fn owner_webauthn_user_uuid(owner_auth: &household_rs::HouseholdAuthState) -> Uuid {
    let mut input = b"soyeht-owner-webauthn-user-v1\0".to_vec();
    input.extend_from_slice(owner_auth.hh_id.to_string().as_bytes());
    input.push(0);
    input.extend_from_slice(owner_auth.owner_person_cert.p_id.0.as_bytes());
    let digest = blake3::hash(&input);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    // RFC 4122-compatible deterministic UUID shape: version 5, variant 1.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn reject_owner_webauthn_registration(reason: &'static str, error: Option<String>) -> Response {
    if let Some(error) = error {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_registration.rejected",
            reason,
            error = %error,
        );
    } else {
        tracing::warn!(
            stage = "owner_events.owner_webauthn_registration.rejected",
            reason,
        );
    }
    unauthenticated_response()
}

fn verify_or_migrate_owner_webauthn_credentials_for_enrollment(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    owner_auth: &household_rs::HouseholdAuthState,
) -> Result<household_rs::owner_webauthn::OwnerWebauthnCredentialStore, String> {
    let Some(anchor) = &state.owner_webauthn_anchor else {
        return Err("missing_anchor_verifier".into());
    };
    verify_or_update_owner_webauthn_authority_anchor(
        anchor.keystore.as_ref(),
        &owner_auth.owner_webauthn,
        &identity.record,
        &owner_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .map_err(|e| format!("anchor_verify_failed: {e}"))?;
    owner_auth
        .owner_webauthn_credentials(&identity.record)
        .map_err(|e| format!("credential_reconstruct_failed: {e}"))
}

/// `POST /api/v1/household/owner-webauthn/registration/start`.
///
/// Starts enrollment for the first owner passkey. This is an S3 backend
/// scaffold: the default router has no RP/anchor and therefore fails closed.
/// Additional credentials and revocation stay in later owner-gated slices.
pub async fn owner_webauthn_registration_start_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.owner_webauthn_start.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let owner_auth = match household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdAddMachine,
        now,
    )
    .await
    {
        Ok(owner_auth) => owner_auth,
        Err(e) => {
            return reject_owner_webauthn_registration("pop_auth_failed", Some(e.to_string()));
        }
    };

    let request: OwnerWebauthnRegistrationStartRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_registration("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_registration("bad_version", None);
    }

    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_registration("identity_unavailable", None);
    };
    let credentials = match verify_or_migrate_owner_webauthn_credentials_for_enrollment(
        &state,
        &identity,
        &owner_auth,
    ) {
        Ok(credentials) => credentials,
        Err(e) => return reject_owner_webauthn_registration("credential_load_failed", Some(e)),
    };
    if !owner_auth.owner_webauthn.is_empty() || credentials.active_count() > 0 {
        return reject_owner_webauthn_registration("credential_already_enrolled", None);
    }
    let Some(rp) = &state.owner_webauthn_rp else {
        return reject_owner_webauthn_registration("rp_unavailable", None);
    };

    let mut rng = OsRng;
    let user_id = owner_webauthn_user_uuid(&owner_auth);
    let owner_name = owner_auth.owner_person_cert.p_id.0.as_str();
    let owner_display_name = owner_auth.owner_person_cert.display_name.as_str();
    let (challenge_id, options) = match rp.lock().await.start_registration(
        &mut rng,
        now,
        user_id,
        owner_name,
        owner_display_name,
        credentials.credentials(),
    ) {
        Ok(result) => result,
        Err(e) => {
            return reject_owner_webauthn_registration(
                "registration_start_failed",
                Some(e.to_string()),
            );
        }
    };
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationStartResponse {
        version: 1,
        challenge_id: challenge_id.as_str().to_string(),
        options,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-webauthn/registration/finish`.
///
/// Commits the first owner passkey into the HH-root-signed authority log, then
/// advances the keystore-backed anchor. Enforcement remains off until a later,
/// explicitly approved flip.
pub async fn owner_webauthn_registration_finish_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.owner_webauthn_finish.clock")
    else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let authorized_owner_auth = match household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdAddMachine,
        now,
    )
    .await
    {
        Ok(owner_auth) => owner_auth,
        Err(e) => {
            return reject_owner_webauthn_registration("pop_auth_failed", Some(e.to_string()));
        }
    };

    let request: OwnerWebauthnRegistrationFinishRequest = match decode_canonical_cbor(&body) {
        Ok(request) => request,
        Err(e) => return reject_owner_webauthn_registration("cbor_decode", Some(e)),
    };
    if request.version != 1 {
        return reject_owner_webauthn_registration("bad_version", None);
    }
    let challenge_id = match OwnerWebauthnChallengeId::parse(request.challenge_id) {
        Ok(challenge_id) => challenge_id,
        Err(e) => {
            return reject_owner_webauthn_registration("bad_challenge_id", Some(e.to_string()));
        }
    };

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;
    let Some(identity) = state.household.current().await else {
        return reject_owner_webauthn_registration("identity_unavailable", None);
    };
    let Some(current_owner_auth) = state.household.current_owner_auth().await else {
        return reject_owner_webauthn_registration("owner_auth_unavailable", None);
    };
    if current_owner_auth.owner_person_cert.p_id != authorized_owner_auth.owner_person_cert.p_id {
        return reject_owner_webauthn_registration("owner_auth_changed", None);
    }
    let Some(hh_priv) = identity.hh_priv.as_deref() else {
        return reject_owner_webauthn_registration("household_root_unavailable", None);
    };
    let credentials = match verify_or_migrate_owner_webauthn_credentials_for_enrollment(
        &state,
        &identity,
        &current_owner_auth,
    ) {
        Ok(credentials) => credentials,
        Err(e) => return reject_owner_webauthn_registration("credential_load_failed", Some(e)),
    };
    if !current_owner_auth.owner_webauthn.is_empty() || credentials.active_count() > 0 {
        return reject_owner_webauthn_registration("credential_already_enrolled", None);
    }
    let Some(rp) = &state.owner_webauthn_rp else {
        return reject_owner_webauthn_registration("rp_unavailable", None);
    };
    let Some(anchor) = state.owner_webauthn_anchor.clone() else {
        return reject_owner_webauthn_registration("missing_anchor_verifier", None);
    };

    let credential =
        match rp
            .lock()
            .await
            .finish_registration(now, &challenge_id, &request.credential)
        {
            Ok(credential) => credential,
            Err(e) => {
                return reject_owner_webauthn_registration(
                    "registration_finish_failed",
                    Some(e.to_string()),
                );
            }
        };
    let credential_id = ByteBuf::from(credential.credential_id_bytes().to_vec());
    let genesis = match household_rs::owner_webauthn_authority::OwnerWebauthnAuthority::sign_genesis(
        hh_priv,
        &identity.record,
        &current_owner_auth.owner_person_cert,
        credential,
        now,
    ) {
        Ok(genesis) => genesis,
        Err(e) => {
            return reject_owner_webauthn_registration(
                "authority_sign_failed",
                Some(e.to_string()),
            );
        }
    };
    let mut next_auth = current_owner_auth.as_ref().clone();
    next_auth.owner_webauthn.push_signed(genesis);
    next_auth.updated_at = now;
    if let Err(e) = next_auth.verify(&identity.record, now) {
        return reject_owner_webauthn_registration("authority_verify_failed", Some(e.to_string()));
    }
    let active_credential_count = match next_auth.owner_webauthn_credentials(&identity.record) {
        Ok(credentials) => credentials.active_count() as u64,
        Err(e) => {
            return reject_owner_webauthn_registration(
                "credential_reconstruct_failed",
                Some(e.to_string()),
            );
        }
    };

    // `household_auth_state.cbor` is the durable log commit point. Advance the
    // rollback anchor only after this file is safely persisted, otherwise the
    // next boot could see an anchor ahead of the log and fail closed.
    if let Err(e) = next_auth.save(&state.state_dir) {
        return reject_owner_webauthn_registration("authority_save_failed", Some(e.to_string()));
    }
    // Keep in-memory owner auth aligned with the durable commit before any
    // post-save anchor failure can return. A retry must see the committed
    // credential and fail closed instead of re-enrolling against stale memory.
    state
        .household
        .set_owner_auth(Arc::new(next_auth.clone()))
        .await;
    if let Err(e) = verify_or_update_owner_webauthn_authority_anchor(
        anchor.keystore.as_ref(),
        &next_auth.owner_webauthn,
        &identity.record,
        &next_auth.owner_person_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    ) {
        return reject_owner_webauthn_registration("anchor_update_failed", Some(e.to_string()));
    }
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerWebauthnRegistrationFinishResponse {
        version: 1,
        credential_id,
        active_credential_count,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-device/push-token`.
///
/// Persists the current iOS APNS device token for future opaque tickles.
pub async fn push_token_register_handler(
    State(state): State<OwnerEventsRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("owner_events.push_token.clock") else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let owner_auth = match household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdAddMachine,
        now,
    )
    .await
    {
        Ok(owner_auth) => owner_auth,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.push_token.rejected",
                reason = "pop_auth_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };

    let request: PushTokenRegisterRequest = match household_rs::cbor::from_canonical_slice(&body) {
        Ok(request) => request,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.push_token.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    if request.version != 1 {
        tracing::warn!(
            stage = "owner_events.push_token.rejected",
            reason = "bad_version",
            version = request.version,
        );
        return unauthenticated_response();
    }

    let token = OwnerDevicePushToken {
        version: 1,
        p_id: owner_auth.owner_person_cert.p_id.0.clone(),
        platform: request.platform,
        push_token: request.push_token,
        updated_at: now,
    };
    if let Err(e) = household_rs::owner_events::put_owner_push_token(&state.state_dir, &token) {
        tracing::warn!(
            stage = "owner_events.push_token.rejected",
            reason = "persist_failed",
            error = %e,
        );
        return unauthenticated_response();
    }

    let bytes = household_rs::cbor::to_canonical_vec(&PushTokenRegisterResponse {
        version: 1,
        updated_at: now,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-events/<cursor>/approval-v2/start`.
pub async fn owner_approval_v2_start_handler(
    State(state): State<OwnerEventsRouterState>,
    Path(cursor_raw): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(cursor) = cursor_raw.parse::<u64>() else {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "bad_cursor_path",
        );
        return unauthenticated_response();
    };
    let Some(now) = time_util::unix_now_secs_checked("owner_events.approval_v2_start.clock") else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let owner_auth = match household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdAddMachine,
        now,
    )
    .await
    {
        Ok(owner_auth) => owner_auth,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "pop_auth_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    let request: OwnerApprovalV2StartRequest = match household_rs::cbor::from_canonical_slice(&body)
    {
        Ok(request) => request,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    if request.version != 1 {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "unsupported_version",
        );
        return unauthenticated_response();
    }
    match household_rs::cbor::to_canonical_vec(&request) {
        Ok(canonical) if canonical == body.as_ref() => {}
        Ok(_) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "non_canonical_cbor",
            );
            return unauthenticated_response();
        }
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "cbor_reencode",
                error = %e,
            );
            return unauthenticated_response();
        }
    }

    let Some(identity) = state.household.current().await else {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "identity_unavailable",
        );
        return unauthenticated_response();
    };
    let credentials =
        match pair_machine_credentials_for_policy(&state, &identity, owner_auth.as_ref()) {
            Ok(Some(credentials)) => credentials,
            Ok(None) => {
                tracing::warn!(
                    stage = "owner_events.approval_v2_start.rejected",
                    reason = "policy_legacy_only",
                );
                return unauthenticated_response();
            }
            Err(e) => {
                tracing::warn!(
                    stage = "owner_events.approval_v2_start.rejected",
                    reason = "owner_webauthn_authority_unavailable",
                    error = %e,
                );
                return unauthenticated_response();
            }
        };
    if state
        .owner_approval_policy
        .pair_machine_approval_body_mode(credentials.active_count() > 0)
        != PairMachineApprovalBodyMode::RequireV2
    {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "owner_has_no_active_webauthn_credential",
        );
        return unauthenticated_response();
    }
    let Some(rp) = state.owner_webauthn_rp.as_ref() else {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = "owner_webauthn_rp_unavailable",
        );
        return unauthenticated_response();
    };

    let snapshot = state.window.snapshot().await;
    if let Err(reason) = pair_machine_window_data(cursor, snapshot.clone()) {
        tracing::warn!(
            stage = "owner_events.approval_v2_start.rejected",
            reason = reason,
            cursor = cursor,
            window_cursor = ?snapshot.owner_event_cursor,
        );
        return unauthenticated_response();
    }

    let mut rng = rand::rngs::OsRng;
    let mut replay_nonce = [0_u8; 32];
    rng.fill_bytes(&mut replay_nonce);
    let mut rp = rp.lock().await;
    let expected_context = match pair_machine_expected_context_from_snapshot(
        &identity,
        owner_auth.as_ref(),
        &snapshot,
        now,
        rp.config().challenge_ttl().as_secs(),
        replay_nonce,
    ) {
        Ok(context) => context,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "trusted_context_build_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    let (challenge_id, options) = match rp.start_owner_approval_assertion(
        &mut rng,
        now,
        credentials.credentials(),
        &expected_context,
    ) {
        Ok(started) => started,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approval_v2_start.rejected",
                reason = "webauthn_start_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };

    let bytes = household_rs::cbor::to_canonical_vec(&OwnerApprovalV2StartResponse {
        version: 1,
        challenge_id: challenge_id.as_str().to_string(),
        context: expected_context,
        options,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-events/<cursor>/approve`.
pub async fn owner_approve_handler(
    State(state): State<OwnerEventsRouterState>,
    Path(cursor_raw): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(cursor) = cursor_raw.parse::<u64>() else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "bad_cursor_path",
        );
        return unauthenticated_response();
    };
    let Some(now) = time_util::unix_now_secs_checked("owner_events.approve.clock") else {
        return unauthenticated_response();
    };
    let pop = match household_auth::SoyehtPoP::parse(&headers) {
        Ok(pop) => pop,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "pop_parse_failed",
                error = ?e,
            );
            return unauthenticated_response();
        }
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let owner_auth = match household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdAddMachine,
        now,
    )
    .await
    {
        Ok(owner_auth) => owner_auth,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "pop_auth_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };

    let Some(identity) = state.household.current().await else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "identity_unavailable",
        );
        return unauthenticated_response();
    };
    let credentials_for_policy =
        match pair_machine_credentials_for_policy(&state, &identity, owner_auth.as_ref()) {
            Ok(credentials) => credentials,
            Err(e) => {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_authority_unavailable",
                    error = %e,
                );
                return unauthenticated_response();
            }
        };
    let body_mode = state.owner_approval_policy.pair_machine_approval_body_mode(
        credentials_for_policy
            .as_ref()
            .is_some_and(|credentials| credentials.active_count() > 0),
    );
    let approval_wire = match parse_pair_machine_approval_body(body_mode, cursor, &body) {
        Ok(approval) => approval,
        Err(reason) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = reason,
                path_cursor = cursor,
            );
            return unauthenticated_response();
        }
    };
    let mut window_data = match pair_machine_window_data(cursor, state.window.snapshot().await) {
        Ok(data) => data,
        Err(reason) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = reason,
                cursor = cursor,
            );
            return unauthenticated_response();
        }
    };
    let approved_v2_context = match &approval_wire {
        PairMachineApprovalWireBody::LegacyV1(approval) => {
            let approval_context = OwnerApprovalContext::build(
                identity.record.hh_id.clone(),
                owner_auth.owner_person_cert.p_id.clone(),
                cursor,
                window_data.join_request.challenge_sig.clone(),
                pop.timestamp,
            );
            if now.abs_diff(approval_context.timestamp) > 60 {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "approval_timestamp_skew",
                );
                return unauthenticated_response();
            }
            if let Err(e) =
                approval_context.verify(&owner_auth.owner_person_cert.p_pub, &approval.approval_sig)
            {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "approval_sig_invalid",
                    error = %e,
                );
                abort_with_cancel_event(
                    &state,
                    &identity,
                    window_data.active_m_pub.clone(),
                    "prepare_failed",
                )
                .await;
                return unauthenticated_response();
            }
            None
        }
        PairMachineApprovalWireBody::V2(finish) => {
            if let Err(e) = finish.approval.context.validate_at(now) {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "approval_v2_context_expired",
                    error = %e,
                );
                return unauthenticated_response();
            }
            let Some(credentials) = credentials_for_policy.as_ref() else {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_credentials_unavailable",
                );
                return unauthenticated_response();
            };
            let Some(mut credential) = credentials
                .credentials()
                .iter()
                .find(|credential| {
                    credential.credential_id_bytes() == finish.approval.credential_id.as_ref()
                })
                .cloned()
            else {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_credential_not_found",
                );
                return unauthenticated_response();
            };
            let Ok(challenge_id) = OwnerWebauthnChallengeId::parse(finish.challenge_id.clone())
            else {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_challenge_id_invalid",
                );
                return unauthenticated_response();
            };
            let assertion = match finish.approval.to_public_key_credential() {
                Ok(assertion) => assertion,
                Err(e) => {
                    tracing::warn!(
                        stage = "owner_events.approve.rejected",
                        reason = "approval_v2_assertion_invalid",
                        error = %e,
                    );
                    return unauthenticated_response();
                }
            };
            let Some(rp) = state.owner_webauthn_rp.as_ref() else {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_rp_unavailable",
                );
                return unauthenticated_response();
            };
            let Ok(replay_nonce) =
                <[u8; 32]>::try_from(finish.approval.context.replay_nonce.as_ref())
            else {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "approval_v2_replay_nonce_length",
                );
                return unauthenticated_response();
            };
            let mut rp = rp.lock().await;
            let expected_context = match pair_machine_expected_context_from_snapshot(
                &identity,
                owner_auth.as_ref(),
                &window_data.snapshot,
                finish.approval.context.issued_at,
                rp.config().challenge_ttl().as_secs(),
                replay_nonce,
            ) {
                Ok(context) => context,
                Err(e) => {
                    tracing::warn!(
                        stage = "owner_events.approve.rejected",
                        reason = "trusted_context_build_failed",
                        error = %e,
                    );
                    return unauthenticated_response();
                }
            };
            if let Err(e) = rp.finish_owner_approval_assertion(
                now,
                &challenge_id,
                &assertion,
                &mut credential,
                &finish.approval.context,
            ) {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "owner_webauthn_finish_failed",
                    error = %e,
                );
                return unauthenticated_response();
            }
            if let Err(e) = finish.approval.require_expected_context(&expected_context) {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "approval_v2_context_mismatch",
                    error = %e,
                );
                return unauthenticated_response();
            }
            Some(finish.approval.context.clone())
        }
    };
    let mutation_guard = if let Some(context) = approved_v2_context.as_ref() {
        let guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
            .lock()
            .await;
        let live_snapshot = state.window.snapshot().await;
        let live_window_data = match pair_machine_window_data(cursor, live_snapshot) {
            Ok(data) => data,
            Err(reason) => {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = reason,
                    cursor = cursor,
                );
                return unauthenticated_response();
            }
        };
        if let Err(e) = reassert_pair_machine_approval_context_against_live_window(
            context,
            &live_window_data.snapshot,
        ) {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "approval_v2_live_window_mismatch",
                error = %e,
            );
            return unauthenticated_response();
        }
        let mut claim_id = [0_u8; 32];
        OsRng.fill_bytes(&mut claim_id);
        if let Err(e) = state
            .window
            .claim_owner_approval(cursor, claim_id, now)
            .await
        {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "approval_v2_claim_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
        window_data = live_window_data;
        Some(guard)
    } else {
        None
    };

    let Some(hh_priv_handle) = identity.hh_priv.as_ref() else {
        // Post-Shamir household: the keystore custody of HH_priv has been
        // destroyed. There is no path here that can issue a new
        // MachineCert under the household root. The pre-prepare gate
        // (`shamir_n == 1` in `founder_stage_join_request`) should have
        // refused this ceremony already; this is defense-in-depth.
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "post_shamir_household",
        );
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    };
    // Phase 3 Shamir splitting requires the raw HH_priv scalar bytes
    // (`split_2_of_2` operates on the 32-byte EC scalar). Secure-Enclave
    // backed keys are non-exportable by design, so an SE-backed
    // `hh_priv` returns `None` here and the ceremony refuses. This is
    // a fundamental architectural limitation of Phase 3 (a key you
    // cannot read cannot be split); a Phase 6+ work item would
    // replace n-of-n Shamir with a threshold-signature primitive
    // that operates over the SE handle. For Phase 3, the founder
    // bootstrap path on macOS MUST run with
    // `THEYOS_FORCE_SOFTWARE_KEYS=1` if the household is intended to
    // grow beyond one machine. See `contracts/local-anchor.md`
    // §"Story 2 anchor mechanism" for the broader SE-backend
    // discussion. The wire response is the generic 401 per
    // FR-019a / R14; the WARN log surfaces the actionable reason
    // for the operator on M1.
    let Some(hh_priv) = hh_priv_handle.as_software_secret().copied() else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "hh_scalar_unavailable",
            hint = "SE-backed HH_priv is non-exportable; Phase 3 Shamir splitting requires THEYOS_FORCE_SOFTWARE_KEYS=1 at bootstrap",
        );
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    };
    let Some(m1_priv) = identity.m_priv.as_software_secret().copied() else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "m1_scalar_unavailable",
            hint = "SE-backed M_priv is non-exportable; Phase 3 ECDH for shard encryption requires THEYOS_FORCE_SOFTWARE_KEYS=1 at bootstrap",
        );
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    };
    let Ok(candidate_m_pub_sec1) = <[u8; 33]>::try_from(window_data.join_request.m_pub.as_ref())
    else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "candidate_m_pub_length",
        );
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    };
    let push_token_seed = match household_rs::owner_events::get_owner_push_token(&state.state_dir) {
        Ok(token) => token,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "push_token_seed_read_failed",
                error = %e,
            );
            abort_with_cancel_event(
                &state,
                &identity,
                window_data.active_m_pub.clone(),
                "prepare_failed",
            )
            .await;
            return unauthenticated_response();
        }
    };
    let txn = match CeremonyTxn::prepare(CeremonyInputs {
        hh_priv: Zeroizing::new(hh_priv),
        hh_id: identity.record.hh_id.clone(),
        hh_pub_sec1: *identity.record.hh_pub.as_bytes(),
        m1_priv_scalar: Zeroizing::new(m1_priv),
        m1_pub_sec1: *identity.cert.m_pub.as_bytes(),
        m1_id: identity.cert.m_id.to_string(),
        candidate_m_pub_sec1,
        candidate_hostname: window_data.join_request.hostname.clone(),
        candidate_platform: window_data.join_request.platform.clone(),
        joined_at: now,
        state_dir: state.state_dir.clone(),
        existing_record: identity.record.clone(),
        policy: state.key_backing_policy,
    }) {
        Ok(txn) => txn,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "ceremony_prepare_failed",
                error = %e,
            );
            abort_with_cancel_event(
                &state,
                &identity,
                window_data.active_m_pub.clone(),
                "prepare_failed",
            )
            .await;
            return unauthenticated_response();
        }
    };
    drop(mutation_guard);
    let addr = window_data
        .snapshot
        .addr_hint
        .clone()
        .unwrap_or_else(|| window_data.join_request.addr.clone());
    // T073: persist the JoinResponse bytes we are about to POST so
    // boot-time `recover_phase3_ceremony` can re-POST them after a
    // crash. `HH_priv` is destroyed during commit, so the
    // encrypted-shard-for-M2 inside `JoinResponse` cannot be
    // reconstructed post-crash. Build the response here using the same
    // options finalize_with_m2 will use.
    let cached_join_request_bytes = window_data.cached_join_request.to_vec();
    let pending_response_bytes = {
        let opts_for_build = FinalizeWithM2Options {
            addr: &addr,
            join_request_cbor: &cached_join_request_bytes,
            founder_cert: &identity.cert,
            founder_tailscale_addr: None,
            push_token_seed: push_token_seed.clone(),
            response_signer: identity.m_priv.as_ref(),
        };
        match txn.build_join_response(&opts_for_build) {
            Ok(jr) => match jr.to_canonical_bytes() {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        stage = "owner_events.approve.rejected",
                        reason = "join_response_canonical_encode_failed",
                        error = %e,
                    );
                    let _ =
                        household_rs::storage::clear_phase3_finalize_ack_marker(&state.state_dir);
                    txn.rollback();
                    abort_with_cancel_event(
                        &state,
                        &identity,
                        window_data.active_m_pub.clone(),
                        "prepare_failed",
                    )
                    .await;
                    return unauthenticated_response();
                }
            },
            Err(e) => {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "join_response_build_failed",
                    error = %e,
                );
                let _ = household_rs::storage::clear_phase3_finalize_ack_marker(&state.state_dir);
                txn.rollback();
                abort_with_cancel_event(
                    &state,
                    &identity,
                    window_data.active_m_pub.clone(),
                    "prepare_failed",
                )
                .await;
                return unauthenticated_response();
            }
        }
    };
    if let Err(e) = household_rs::storage::write_phase3_pending_join_response(
        &state.state_dir,
        &pending_response_bytes,
    ) {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "phase3_pending_join_response_write_failed",
            error = %e,
            hint = "refusing to launch finalize_with_m2 without durable JoinResponse copy",
        );
        txn.rollback();
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    }
    // R7.2/R7.3: write the recovery-driver intent pin BEFORE invoking
    // `finalize_with_m2`. The marker says "M1 has launched a join
    // ceremony with this candidate; if the boot path observes a
    // pre-Shamir record AND this marker is durable, recovery MUST
    // preserve `.staged` and dispatch T073/T074's two-state probe
    // instead of rolling back". Writing it AFTER `finalize_with_m2`
    // (the previous R6.1 placement) leaves two split-brain windows:
    //   (a) crash between `finalize_with_m2 Ok` and the marker
    //       fsync+rename becoming durable;
    //   (b) FinalizeAck network response lost in flight (M2's
    //       `staged.commit()` Ok'd, packet dropped) — the Err arm
    //       below would have returned 401 with no marker on disk.
    // Both leave M2 committed, M1 rolled back.
    //
    // The pending JoinResponse is durable before the marker, so a boot
    // that observes the marker also has the bytes needed to re-POST
    // finalize. A crash before this marker leaves only ordinary staged
    // files; boot-time recovery rolls them back and reload clears the
    // owner-approval claim as stale.
    let candidate_m_id_str = txn.candidate_cert().m_id.to_string();
    if let Err(e) = household_rs::storage::write_phase3_finalize_ack_marker(
        &state.state_dir,
        &candidate_m_id_str,
    ) {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "phase3_finalize_ack_marker_write_failed",
            error = %e,
            hint = "refusing to launch finalize_with_m2 without durable intent pin",
        );
        // The txn has not contacted M2 yet; explicit rollback unlinks
        // the staged set cleanly with no residue.
        let _ = household_rs::storage::clear_phase3_pending_join_response(&state.state_dir);
        txn.rollback();
        abort_with_cancel_event(
            &state,
            &identity,
            window_data.active_m_pub.clone(),
            "prepare_failed",
        )
        .await;
        return unauthenticated_response();
    }
    let identity_for_finalize = Arc::clone(&identity);
    let finalized = tokio::task::spawn_blocking(move || {
        let finalize_opts = FinalizeWithM2Options {
            addr: &addr,
            join_request_cbor: &cached_join_request_bytes,
            founder_cert: &identity_for_finalize.cert,
            founder_tailscale_addr: None,
            push_token_seed,
            response_signer: identity_for_finalize.m_priv.as_ref(),
        };
        match txn.finalize_with_m2(&finalize_opts) {
            Ok(outcome) => FinalizeAttempt::Acked(Box::new(txn), Box::new(outcome)),
            Err(e) if e.is_ambiguous_finalize_outcome() => {
                txn.preserve_staged_for_recovery();
                FinalizeAttempt::AmbiguousFailure(e)
            }
            Err(e) => {
                txn.rollback();
                FinalizeAttempt::DefiniteFailure(e)
            }
        }
    })
    .await;
    let (txn, finalize) = match finalized {
        Ok(FinalizeAttempt::Acked(txn, outcome)) => (*txn, *outcome),
        Ok(FinalizeAttempt::DefiniteFailure(e)) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "m2_finalize_failed",
                error = %e,
            );
            // The blocking task already rolled back the M1 staged set.
            // This arm is only for a definitive local/build error or a
            // generic 401-style reject from M2 before it returned an ack.
            if let Err(clear_err) =
                household_rs::storage::clear_phase3_finalize_ack_marker(&state.state_dir)
            {
                tracing::warn!(
                    stage = "owner_events.approve.finalize_ack_marker_clear_failed",
                    reason = "after_finalize_with_m2_err",
                    error = %clear_err,
                );
            }
            if let Err(clear_err) =
                household_rs::storage::clear_phase3_pending_join_response(&state.state_dir)
            {
                tracing::warn!(
                    stage = "owner_events.approve.pending_join_response_clear_failed",
                    reason = "after_finalize_with_m2_err",
                    error = %clear_err,
                );
            }
            abort_with_cancel_event(
                &state,
                &identity,
                window_data.active_m_pub.clone(),
                "candidate_unreachable",
            )
            .await;
            return unauthenticated_response();
        }
        Ok(FinalizeAttempt::AmbiguousFailure(e)) => {
            tracing::error!(
                stage = "owner_events.approve.partially_committed",
                reason = "m2_finalize_outcome_ambiguous",
                error = %e,
                hint = "finalize POST may have committed M2; M1 .staged files + finalize intent marker left for boot recovery",
            );
            return internal_error_response();
        }
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "m2_finalize_task_failed",
                error = %e,
            );
            // Unknown outcome: keep the marker. If the blocking task
            // panicked before preserving the staged set, recovery may
            // have less evidence than desired, but clearing the marker
            // here would make a possible M2 commit strictly worse.
            return internal_error_response();
        }
    };
    let candidate_cert = txn.candidate_cert().clone();
    // T064: failure-injection crash point — fires immediately after
    // `finalize_with_m2` returns Ok and BEFORE `commit_preserve_on_error`
    // promotes the staged set. A registered Panic models "M1 crash
    // between 2PC step 11 (FinalizeAck received) and step 12 (rename
    // staged files)". On reboot, M1 sees a pre-Shamir record + marker
    // + .staged files and recovery rolls forward via the post-commit
    // probe of M2 per `contracts/shamir-transition.md` §"Recovery on
    // M1 boot".
    #[cfg(any(test, feature = "failure-injection"))]
    {
        match crate::failure_injection::apply(crate::failure_injection::InjectionPoint::M1AfterAck)
            .await
        {
            crate::failure_injection::Outcome::EarlyReject(_) => {
                // Match the post-ack ambiguous-failure surface so the
                // marker + staged set survive for boot recovery.
                txn.preserve_staged_for_recovery();
                return internal_error_response();
            }
            crate::failure_injection::Outcome::Skip
            | crate::failure_injection::Outcome::Continue => {}
        }
    }
    // From this point forward, M2 has already returned `FinalizeAck` and
    // therefore committed cert+shard+record on its side. We must NOT
    // rollback or surface `unauthenticated` for failures past this line —
    // that would create a split-brain (M2 committed, M1 not). Instead we
    // log at ERROR + return `internal_error_response` (500) and rely on
    // three safeguards:
    //   1. `.staged` files left on disk by `CeremonyTxn::prepare` MUST
    //      survive the failure. R7.1: `commit_preserve_on_error()` is
    //      the variant that disarms `StagedCommit::Drop`'s automatic
    //      `.staged` cleanup on commit error. The plain `commit()`
    //      would have unlinked them via the destructor, defeating
    //      recovery.
    //   2. The `phase3_finalize_ack.marker` file written BEFORE
    //      `finalize_with_m2` (R7.2/R7.3) pins the "in-flight ceremony"
    //      state on disk. Boot-time `recover_partial_phase3_commit`
    //      checks for it and refuses to roll back the `.staged` set
    //      even when the on-disk record is still pre-Shamir.
    //   3. `commit_preserve_on_error`'s post-promote cleanup primitives
    //      (keystore destroy, sole-shard unlink) are idempotent, so
    //      retrying them on next boot is safe.
    // T073/T074 will add the explicit `recover_phase3_ceremony` boot path
    // that drives these to completion (see `contracts/shamir-transition.md`
    // §"Recovery on M1 boot"). Until then the marker + staged files remain
    // and an operator can hand-finish via the existing primitives. The 500
    // wire surface is contracted in `contracts/owner-events.md`.
    // T064: post-rename hook synchronously consults the
    // failure-injection registry between staged.commit (step 12) and
    // sole-shard unlink + keystore destroy (step 13). Production
    // builds compile this hook to a constant `Continue` (the
    // closure body is `cfg`-gated; the closure itself is always
    // passed but is a no-op when the feature is off).
    let post_rename_hook = || -> household_rs::pair_machine::PostRenameHookOutcome {
        #[cfg(any(test, feature = "failure-injection"))]
        {
            match crate::failure_injection::apply_sync(
                crate::failure_injection::InjectionPoint::M1AfterStagedRename,
            ) {
                crate::failure_injection::Outcome::EarlyReject(msg) => {
                    return household_rs::pair_machine::PostRenameHookOutcome::EarlyReject(msg);
                }
                crate::failure_injection::Outcome::Skip
                | crate::failure_injection::Outcome::Continue => {}
            }
        }
        household_rs::pair_machine::PostRenameHookOutcome::Continue
    };
    if let Err(e) = txn.commit_preserve_on_error_with_hook(post_rename_hook) {
        tracing::error!(
            stage = "owner_events.approve.partially_committed",
            reason = "m1_commit_failed_after_m2_ack",
            error = %e,
            hint = "M2 acked; sole-shard + .staged + finalize intent marker left for boot recovery",
        );
        return internal_error_response();
    }
    // T064: failure-injection crash point — fires after
    // `commit_preserve_on_error` returns Ok (staged renames + sole-shard
    // unlink + keystore destroy all done) and BEFORE the marker is
    // cleared / `OwnerEvent{type=machine-joined}` is appended. A
    // registered Panic models "M1 crash between 2PC step 13 (sole-shard
    // unlink) and step 14 (event-log append)". On reboot, M1 has a
    // post-Shamir record on disk; boot-time
    // `clear_stale_phase3_marker_if_post_shamir` removes the marker
    // and the household is fully committed. The missing
    // `machine-joined` event is reconciled by the iPhone's next
    // owner-events long-poll, which observes the post-commit state.
    #[cfg(any(test, feature = "failure-injection"))]
    {
        match crate::failure_injection::apply(
            crate::failure_injection::InjectionPoint::M1AfterStagedCommit,
        )
        .await
        {
            crate::failure_injection::Outcome::EarlyReject(_) => {
                return internal_error_response();
            }
            crate::failure_injection::Outcome::Skip
            | crate::failure_injection::Outcome::Continue => {}
        }
    }
    // R6.1: ceremony fully committed — the post-Shamir record is durable
    // on disk, so boot-time recovery would correctly roll forward any
    // residual `.staged`. The marker is no longer protective; clear it
    // best-effort. R7.NB2: failures here are also covered by
    // `recover_partial_phase3_commit`'s unconditional post-Shamir clear,
    // so the marker is guaranteed to be cleaned up on next boot.
    if let Err(e) = household_rs::storage::clear_phase3_finalize_ack_marker(&state.state_dir) {
        tracing::warn!(
            stage = "owner_events.approve.finalize_ack_marker_clear_failed",
            error = %e,
            hint = "post-Shamir record on disk; boot-time recovery clears the marker on next start",
        );
    }
    if let Err(e) = household_rs::storage::clear_phase3_pending_join_response(&state.state_dir) {
        tracing::warn!(
            stage = "owner_events.approve.pending_join_response_clear_failed",
            error = %e,
            hint = "post-Shamir record on disk; boot-time recovery clears the pending JoinResponse on next start",
        );
    }
    // Reload `LoadedIdentity` from disk: the on-disk record now has
    // `shamir_n=2` and the keystore custody of HH_priv has been
    // destroyed. `try_load_existing` will deliver `hh_priv: None`.
    // Swap it into the shared `HouseholdState` so subsequent requests
    // see the post-Shamir household and `founder_stage_join_request`'s
    // `shamir_n == 1` gate refuses any further add-machine attempts on
    // the now-stale single-machine path. (B6.)
    match household_rs::try_load_existing(&state.state_dir, state.key_backing_policy) {
        Ok(Some(reloaded)) => {
            state.household.set_loaded(Arc::new(reloaded)).await;
        }
        Ok(None) | Err(_) => {
            // The reload should never fail post-commit (we just wrote
            // those files). Log and continue — the next handler that
            // observes the stale `HouseholdState` will fail closed via
            // its own gates. We do NOT return an error here because the
            // ceremony itself succeeded.
            tracing::error!(
                stage = "owner_events.approve.identity_reload_failed",
                hint = "post-commit identity unavailable; next request will refresh from disk on the slow path",
            );
        }
    }
    if let Err(e) = state
        .window
        .enter_committed(finalize.join_response_bytes.clone())
        .await
    {
        // Same post-commit semantics as above — disk is authoritative.
        tracing::error!(
            stage = "owner_events.approve.window_commit_failed",
            reason = "in_memory_window_update_failed_after_disk_commit",
            error = %e,
        );
        return internal_error_response();
    }
    // Positive observability gate (T093): the household has just grown
    // from N=1 (sole-shard) to N=2 (Shamir 2-of-2). This is the
    // canonical "ceremony committed" + "Shamir transition committed"
    // checkpoint — a successful transition emits exactly one of these
    // events per ceremony, regardless of replay-after-commit re-entry.
    tracing::info!(
        stage = "pair_machine.shamir_transition_committed",
        cursor = cursor,
        candidate_m_id = %candidate_cert.m_id,
    );
    if let Err(e) = state.event_log.append(
        &identity.cert.m_id.to_string(),
        identity.m_priv.as_ref(),
        OwnerEventType::MachineJoined,
        OwnerEventPayload::MachineJoined(MachineJoinedPayload {
            m_pub: ByteBuf::from(candidate_cert.m_pub.as_bytes().to_vec()),
            m_id: candidate_cert.m_id.to_string(),
            hostname: candidate_cert.hostname.clone(),
            joined_at: candidate_cert.joined_at,
        }),
    ) {
        // The household is committed; only the audit-log append failed.
        // Return 500 so the iPhone knows the ceremony succeeded but the
        // event-log signal was lost — the next long-poll observes the
        // post-commit state (membership=2) and reconciles.
        tracing::error!(
            stage = "owner_events.approve.event_append_failed",
            reason = "machine_joined_event_append_failed_after_commit",
            error = %e,
        );
        return internal_error_response();
    }
    dispatch_owner_event_tickle_if_idle(state.state_dir.clone(), &state.event_broadcaster);

    tracing::info!(
        stage = "owner_events.approve.accepted",
        cursor = cursor,
        candidate_m_id = %candidate_cert.m_id,
    );
    let bytes = household_rs::cbor::to_canonical_vec(&OwnerApprovalAck {
        version: 1,
        machine_cert_hash: finalize.ack.machine_cert_hash,
    })
    .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /api/v1/household/owner-events/<cursor>/decline`.
pub async fn owner_decline_handler(
    State(state): State<OwnerEventsRouterState>,
    Path(cursor_raw): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(cursor) = cursor_raw.parse::<u64>() else {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "bad_cursor_path",
        );
        return unauthenticated_response();
    };
    let Some(now) = time_util::unix_now_secs_checked("owner_events.decline.clock") else {
        return unauthenticated_response();
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    if let Err(e) = household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdAddMachine,
        now,
    )
    .await
    {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "pop_auth_failed",
            error = %e,
        );
        return unauthenticated_response();
    }

    let Some(identity) = state.household.current().await else {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "identity_unavailable",
        );
        return unauthenticated_response();
    };
    let snap = state.window.snapshot().await;
    if snap.state != PairMachineState::AwaitingOwner || snap.owner_event_cursor != Some(cursor) {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "window_cursor_mismatch",
            cursor = cursor,
            window_cursor = ?snap.owner_event_cursor,
        );
        return unauthenticated_response();
    }
    let Some(m_pub) = snap.m_pub.as_ref() else {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "window_missing_m_pub",
        );
        return unauthenticated_response();
    };
    if let Err(e) = state.window.enter_aborted().await {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "window_abort_failed",
            error = %e,
        );
        return unauthenticated_response();
    }
    let event = state.event_log.append(
        &identity.cert.m_id.to_string(),
        identity.m_priv.as_ref(),
        OwnerEventType::JoinCancelled,
        OwnerEventPayload::JoinCancelled(JoinCancelledPayload {
            m_pub: m_pub.clone(),
            reason: "declined".into(),
        }),
    );
    if let Err(e) = event {
        tracing::warn!(
            stage = "owner_events.decline.rejected",
            reason = "cancel_event_append_failed",
            error = %e,
        );
        return unauthenticated_response();
    }
    dispatch_owner_event_tickle_if_idle(state.state_dir.clone(), &state.event_broadcaster);
    // Positive observability gate (T093) — the owner has affirmatively
    // declined the join. Distinguished from `decline.rejected` (any
    // failure) so audit consumers can count only successful declines.
    tracing::info!(stage = "owner_events.decline.accepted", cursor = cursor,);

    let bytes =
        household_rs::cbor::to_canonical_vec(&OwnerDeclineAck { version: 1 }).unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

async fn abort_with_cancel_event(
    state: &OwnerEventsRouterState,
    identity: &household_rs::LoadedIdentity,
    m_pub: ByteBuf,
    reason: &'static str,
) {
    if let Err(e) = state.window.enter_aborted().await {
        tracing::warn!(
            stage = "owner_events.cancel.abort_failed",
            reason = reason,
            error = %e,
        );
        return;
    }
    match state.event_log.append(
        &identity.cert.m_id.to_string(),
        identity.m_priv.as_ref(),
        OwnerEventType::JoinCancelled,
        OwnerEventPayload::JoinCancelled(JoinCancelledPayload {
            m_pub,
            reason: reason.into(),
        }),
    ) {
        Ok(_) => {
            dispatch_owner_event_tickle_if_idle(state.state_dir.clone(), &state.event_broadcaster);
            // Positive observability gate (T093) — the ceremony was
            // aborted from an internal path (2PC failure during
            // approve) rather than an explicit owner decline. The
            // `reason` carries the source: `2pc_failed`, `internal`,
            // etc. Production audit consumers count this against
            // `decline.accepted` to distinguish owner-initiated
            // declines from system-driven aborts.
            tracing::info!(stage = "pair_machine.ceremony_aborted", reason = reason,);
        }
        Err(e) => tracing::warn!(
            stage = "owner_events.cancel.append_failed",
            reason = reason,
            error = %e,
        ),
    }
}

/// Dispatch an opaque APNS tickle after an owner event was durably appended and
/// published, but only when no long-poll request is currently subscribed.
///
/// The APNS dispatcher accepts only the registered push token, never the event
/// itself, so no household metadata can reach Apple through this path.
pub fn dispatch_owner_event_tickle_if_idle(
    state_dir: PathBuf,
    event_broadcaster: &OwnerEventsBroadcaster,
) {
    if event_broadcaster.active_subscribers() > 0 {
        return;
    }
    tokio::spawn(async move {
        let token = match household_rs::owner_events::get_owner_push_token(&state_dir) {
            Ok(Some(token)) => token,
            Ok(None) => {
                tracing::info!(
                    stage = "owner_events.apns.skipped",
                    reason = "no_registered_token",
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    stage = "owner_events.apns.skipped",
                    reason = "token_read_failed",
                    error = %e,
                );
                return;
            }
        };
        match apns_dispatcher::dispatch_tickle(&token).await {
            Ok(()) => {
                // Positive observability gate (T093) — the dispatcher
                // returned successfully. Note: this fires AFTER the
                // dispatcher's own internal `apns.disabled_at_runtime`
                // short-circuit (which still returns Ok), so a build
                // running with `THEYOS_PUSH_DISABLED=1` produces a
                // pair of events: the disabled-at-runtime info plus
                // this dispatched info. Audit consumers cross-check
                // both layers.
                tracing::info!(stage = "owner_events.apns.dispatched");
            }
            Err(e) => tracing::warn!(
                stage = "owner_events.apns.dispatch_failed",
                error = %e,
            ),
        }
    });
}

/// Spawn a runtime watchdog that fires when the `PairMachineWindow`
/// reaches its TTL expiry without owner action. This is the active
/// half of FR-019's "owner timed out" requirement — the boot-time
/// recovery in `load_state_dir` only handles the case where the
/// daemon was DOWN during expiry; this watchdog handles the in-process
/// case where the daemon is up but the owner never approved or
/// declined.
///
/// On fire the watchdog:
///
///  1. Emits `pair_machine.owner_timed_out` (T093 / FR-019 stage).
///  2. Calls [`abort_with_cancel_event`] with `reason = "timeout"`,
///     which transitions the window `awaiting_owner → aborted`,
///     appends a `JoinCancelled{reason="timeout"}` owner event so any
///     iPhone long-poll wakes up with the cancellation, and tickles
///     the broadcaster (which fires APNS for backgrounded clients).
///
/// The watchdog re-arms on every state transition into `Staging` or
/// `AwaitingOwner` and cancels itself early if the window leaves
/// those states before expiry. Production callers MUST hold the
/// returned [`tokio::task::JoinHandle`] for the lifetime of the
/// owner-events router; dropping it does not abort the task.
///
/// # Shutdown
///
/// Pass a `watch::Receiver<bool>` whose channel sender is owned by
/// the caller. Callers wishing to stop the watchdog cleanly (test
/// teardown, in-process daemon restart) invoke
/// `cancel_tx.send(true)`. The watch primitive *latches*: every
/// subsequent `*cancel_rx.borrow()` returns `true`, so a regression
/// where the wake lands during a non-`select!` await (e.g.,
/// `state.window.snapshot().await`,
/// `state.household.current().await`,
/// `abort_with_cancel_event(...).await`) is still observed at the
/// next sticky check at the top of the loop. This closes the
/// lost-wakeup race that an edge-triggered primitive like
/// [`tokio::sync::Notify`] would have exposed.
///
/// The watchdog also exits if all senders drop (`changed()` returns
/// `Err`). In production the sender MUST be retained — see
/// `household_bootstrap.rs` for the canonical leak pattern — or the
/// watchdog will exit immediately on first `changed()` poll.
#[must_use]
pub fn spawn_owner_timeout_watchdog(
    state: OwnerEventsRouterState,
    mut cancel_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut state_rx = state.window.subscribe();
        loop {
            // Sticky cancel check — closes the lost-wakeup race that
            // an edge-triggered shutdown primitive would have. Any
            // prior `cancel_tx.send(true)` is observed here regardless
            // of whether the watchdog was suspended on a `select!`
            // arm, a non-`select!` await (snapshot, current, abort),
            // or between iterations. Subsequent `changed()` arms in
            // the body remain useful for waking from sleeps.
            if *cancel_rx.borrow() {
                return;
            }
            let snap = state.window.snapshot().await;
            let in_timed_state = matches!(
                snap.state,
                PairMachineState::Staging | PairMachineState::AwaitingOwner
            );
            if !in_timed_state {
                tokio::select! {
                    cancel = cancel_rx.changed() => {
                        // Either a true `send(true)` landed or all
                        // senders dropped — either way exit.
                        let _ = cancel;
                        return;
                    }
                    changed = state_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
                continue;
            }
            let Some(expiry) = snap.expiry else {
                tokio::select! {
                    cancel = cancel_rx.changed() => {
                        let _ = cancel;
                        return;
                    }
                    changed = state_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
                continue;
            };
            let Some(now) = time_util::unix_now_secs_checked("pair_machine.timeout_watchdog.clock")
            else {
                if backoff_or_cancel(&mut cancel_rx).await {
                    return;
                }
                continue;
            };
            let sleep_secs = expiry.saturating_sub(now);
            if sleep_secs > 0 {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(sleep_secs)) => {}
                    changed = state_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        continue;
                    }
                    cancel = cancel_rx.changed() => {
                        let _ = cancel;
                        return;
                    }
                }
            }
            // Re-snapshot. The state may have advanced during sleep
            // (approve/decline races the timeout); fire only if the
            // window is STILL in a timed state and the wall clock has
            // truly passed expiry. This avoids a spurious abort on a
            // clock skew or premature wake.
            let snap = state.window.snapshot().await;
            if !matches!(
                snap.state,
                PairMachineState::Staging | PairMachineState::AwaitingOwner
            ) {
                continue;
            }
            // The three "transient None" branches below all use
            // `backoff_or_cancel` so a stuck condition (clock
            // failure, household unloaded, missing m_pub) cannot
            // tight-loop the CPU — every retry waits 1s OR exits on
            // cancel. Without this, an elapsed-TTL window where any
            // of these returned None would spin the loop because
            // `sleep_secs == 0` skips the pre-sleep `select!` arm.
            let Some(now) = time_util::unix_now_secs_checked("pair_machine.timeout_watchdog.clock")
            else {
                if backoff_or_cancel(&mut cancel_rx).await {
                    return;
                }
                continue;
            };
            if let Some(expiry) = snap.expiry {
                if now < expiry {
                    continue;
                }
            }
            let Some(identity) = state.household.current().await else {
                if backoff_or_cancel(&mut cancel_rx).await {
                    return;
                }
                continue;
            };
            let Some(m_pub) = snap.m_pub.clone() else {
                if backoff_or_cancel(&mut cancel_rx).await {
                    return;
                }
                continue;
            };
            tracing::info!(
                stage = "pair_machine.owner_timed_out",
                cursor = ?snap.owner_event_cursor,
                expiry = ?snap.expiry,
            );
            abort_with_cancel_event(&state, &identity, m_pub, "timeout").await;
            // Loop and wait for the next state transition; the abort
            // moves the window to `Aborted`, so the next iteration
            // hits the !in_timed_state branch and waits. The sticky
            // cancel check at the top of the loop catches a cancel
            // that landed mid-`abort_with_cancel_event`.
        }
    })
}

/// 1-second back-pressure that races the cancel signal. Returns
/// `true` if the caller should exit because cancel was triggered.
/// Used by [`spawn_owner_timeout_watchdog`] in transient-`None`
/// branches (clock failure, household unloaded, missing `m_pub`) so a
/// stuck condition does not tight-loop the CPU after the TTL has
/// elapsed (the `sleep_secs > 0` pre-sleep arm is bypassed once
/// `expiry` is in the past).
async fn backoff_or_cancel(cancel_rx: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(1)) => false,
        cancel = cancel_rx.changed() => {
            let _ = cancel;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::ids::{HouseholdId, MachineId};
    use household_rs::machine_cert::PersonId;
    use household_rs::owner_approval_v2::PairMachineApprovalContextInput;
    use household_rs::pair_machine::{
        JoinTransport, PAIR_MACHINE_VERSION, PairMachineApprovalClaim,
    };

    fn household_id() -> HouseholdId {
        HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap()
    }

    fn machine_id() -> MachineId {
        MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()
    }

    fn owner_person_id() -> PersonId {
        PersonId("p_owner-alpha".to_string())
    }

    fn approval_context(join_request_bytes: &[u8]) -> OwnerApprovalContextV2 {
        OwnerApprovalContextV2::pair_machine_approve(PairMachineApprovalContextInput {
            hh_id: household_id(),
            owner_p_id: owner_person_id(),
            cursor: 7,
            m_id: machine_id(),
            addr: "192.0.2.10:8091".to_string(),
            transport: JoinTransport::Lan,
            ttl_unix: 1_800,
            nonce: [0x11; 32],
            join_request_hash: join_request_hash(join_request_bytes),
            capabilities: vec!["machine-cert".to_string(), "shamir-2pc".to_string()],
            issued_at: 1_000,
            expires_at: 1_120,
            replay_nonce: [0x22; 32],
        })
    }

    fn live_snapshot(join_request_bytes: &[u8]) -> PairMachineWindowSnapshot {
        PairMachineWindowSnapshot {
            version: PAIR_MACHINE_VERSION,
            state: PairMachineState::AwaitingOwner,
            m_pub: Some(ByteBuf::from(vec![0x03; 33])),
            nonce: Some(ByteBuf::from(vec![0x11; 32])),
            expiry: Some(1_800),
            transport: Some(JoinTransport::Lan),
            addr_hint: Some("192.0.2.10:8091".to_string()),
            fingerprint: Some("fp-neutral".to_string()),
            owner_event_cursor: Some(7),
            cached_join_request: Some(ByteBuf::from(join_request_bytes.to_vec())),
            cached_response: None,
            anchor_secret: None,
            pinned_hh_pub: None,
            pinned_hh_id: None,
            approval_claim: None,
        }
    }

    #[test]
    fn owner_approval_policy_is_per_operation_and_default_off() {
        let policy = OwnerApprovalEnforcementPolicy::default();
        assert_eq!(
            policy.pair_machine_approval_body_mode(false),
            PairMachineApprovalBodyMode::LegacyV1
        );
        assert_eq!(
            policy.pair_machine_approval_body_mode(true),
            PairMachineApprovalBodyMode::LegacyV1
        );
        assert_eq!(
            policy.bootstrap_initialize,
            OwnerOperationEnforcement::LegacyOnly
        );
        assert_eq!(
            policy.bootstrap_teardown,
            OwnerOperationEnforcement::LegacyOnly
        );
        assert_eq!(
            policy.pair_device_confirm,
            OwnerOperationEnforcement::LegacyOnly
        );
        assert_eq!(
            policy.revoke_credential,
            OwnerOperationEnforcement::LegacyOnly
        );
    }

    #[test]
    fn pair_machine_v2_policy_requires_active_owner_passkey_before_requiring_v2() {
        let policy = OwnerApprovalEnforcementPolicy::default()
            .with_pair_machine_approve(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);

        assert_eq!(
            policy.pair_machine_approval_body_mode(false),
            PairMachineApprovalBodyMode::LegacyV1,
            "owners without enrolled passkeys keep the legacy path during migration"
        );
        assert_eq!(
            policy.pair_machine_approval_body_mode(true),
            PairMachineApprovalBodyMode::RequireV2
        );
    }

    #[test]
    fn pair_machine_reassertion_accepts_unchanged_live_window() {
        let join_request_bytes = b"neutral canonical join request";
        let context = approval_context(join_request_bytes);
        let snapshot = live_snapshot(join_request_bytes);

        reassert_pair_machine_approval_context_against_live_window(&context, &snapshot).unwrap();
    }

    #[test]
    fn pair_machine_reassertion_rejects_window_changed_after_approval() {
        let join_request_bytes = b"neutral canonical join request";
        let context = approval_context(join_request_bytes);
        let mut snapshot = live_snapshot(join_request_bytes);
        snapshot.cached_join_request = Some(ByteBuf::from(b"mutated join request".to_vec()));

        let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
            .unwrap_err();
        assert!(matches!(
            err,
            OwnerApprovalV2Error::TrustedState("live join request changed")
        ));
    }

    #[test]
    fn pair_machine_reassertion_rejects_cursor_or_state_change_after_approval() {
        let join_request_bytes = b"neutral canonical join request";
        let context = approval_context(join_request_bytes);
        let mut snapshot = live_snapshot(join_request_bytes);
        snapshot.owner_event_cursor = Some(8);

        let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
            .unwrap_err();
        assert!(matches!(
            err,
            OwnerApprovalV2Error::TrustedState("live window cursor changed")
        ));

        let mut snapshot = live_snapshot(join_request_bytes);
        snapshot.state = PairMachineState::Committed;
        let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
            .unwrap_err();
        assert!(matches!(
            err,
            OwnerApprovalV2Error::TrustedState("live window cursor changed")
        ));
    }

    #[test]
    fn pair_machine_reassertion_rejects_claimed_window() {
        let join_request_bytes = b"neutral canonical join request";
        let context = approval_context(join_request_bytes);
        let mut snapshot = live_snapshot(join_request_bytes);
        snapshot.approval_claim = Some(PairMachineApprovalClaim {
            claim_id: ByteBuf::from(vec![0xA5; 32]),
            owner_event_cursor: 7,
            claimed_at: 1_700,
        });

        let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
            .unwrap_err();
        assert!(matches!(
            err,
            OwnerApprovalV2Error::TrustedState("live window already claimed")
        ));
    }
}
