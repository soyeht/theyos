//! Phase 3 founding-machine join-request endpoint, candidate's
//! pre-household listener (`/pair-machine/local/seed` and
//! `/pair-machine/local/finalize`), and the shared
//! `founder_stage_join_request` helper.
//!
//! Founder-side staging is transport-neutral: the remote QR endpoint and the
//! LAN Bonjour browser both call [`founder_stage_join_request`] after they have
//! obtained a signed [`JoinRequest`].

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use household_rs::caveats::Operation;
use household_rs::owner_events::{
    JoinRequestPayload, OwnerEventLog, OwnerEventPayload, OwnerEventType, OwnerEventsBroadcaster,
    owner_push_token_path,
};
use household_rs::pair_machine::{
    FinalizeAck, JoinRequest, JoinResponse, PairMachineState, PairMachineWindow,
    PairMachineWindowSnapshot, join_request_hash, pair_machine_window_path, shamir_self_shard_path,
    verify_join_request,
};
use serde::Serialize;
use serde_bytes::ByteBuf;

use crate::bonjour_trust::{DiscoverySource, classify_source};
use crate::handlers_owner_events;
use crate::household_auth;
use crate::household_state::HouseholdState;
use crate::time_util;

/// Application content type for every Phase 3 join-request response —
/// success, replay, and the generic-failure 401 alike.
const CBOR_CONTENT_TYPE: &str = "application/cbor";

pub const POST_COMMIT_REDUNDANCY_NOTICE: &str = "Household now has 2 machines. Until you add a 3rd machine, losing either machine means losing the household. Add another machine soon.";

/// State threaded into the `POST /api/v1/household/join-request`
/// handler and (later) the candidate's `local/seed` endpoint when
/// Story 2 lands. The router-side type carries `PairMachineState` (the
/// protocol-state enum imported above) only via the wrapped `PairMachineWindow`.
#[derive(Clone)]
pub struct PairMachineRouterState {
    pub window: Arc<PairMachineWindow>,
    pub household: HouseholdState,
    pub event_log: Arc<OwnerEventLog>,
    pub event_broadcaster: OwnerEventsBroadcaster,
    pub state_dir: PathBuf,
}

/// State for M2's pre-household listener. This process does not have a
/// household identity yet; it only has the candidate keypair and a staged
/// `PairMachineWindow` from `theyos install --pair-machine`.
#[derive(Clone)]
pub struct PreHouseholdRouterState {
    pub window: Arc<PairMachineWindow>,
    pub state_dir: PathBuf,
    pub key_policy: household_rs::KeyBackingPolicy,
    pub finalize_lock: Arc<tokio::sync::Mutex<()>>,
}

pub fn pre_household_router(state: PreHouseholdRouterState) -> Router {
    Router::new()
        .route("/pair-machine/anchor-handoff", get(anchor_handoff_handler))
        .route("/pair-machine/local/seed", get(local_seed_handler))
        .route("/pair-machine/local/anchor", post(local_anchor_handler))
        .route("/pair-machine/local/finalize", post(local_finalize_handler))
        .fallback(pre_household_reject)
        .with_state(state)
}

/// `JoinRequestAccepted = {v=1, owner_event_cursor: uint, expiry: uint}` —
/// success body for the join-request endpoint per `contracts/join-request.md`.
#[derive(Serialize)]
struct JoinRequestAccepted {
    #[serde(rename = "v")]
    version: u8,
    owner_event_cursor: u64,
    expiry: u64,
}

/// `LocalAnchor` — the iPhone-delivered trust anchor body per
/// `contracts/local-anchor.md` (B7).
///
/// The wire body carries only what the candidate uses to pin the
/// household identity: `anchor_secret` (the QR-only authenticator),
/// `hh_id`, and `hh_pub`. The owner's `PersonCert` is intentionally
/// omitted — it would be dead weight on the wire (the candidate has
/// no `hh_priv` to validate it against during anchor pinning, and the
/// `anchor_secret` itself is already the gate). Logging the
/// post-anchor identity uses the pinned `hh_id`/`hh_pub` directly.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LocalAnchor {
    #[serde(rename = "v")]
    version: u8,
    anchor_secret: serde_bytes::ByteBuf,
    hh_id: String,
    hh_pub: serde_bytes::ByteBuf,
}

impl LocalAnchor {
    fn to_canonical_bytes(&self) -> Result<Vec<u8>, household_rs::HouseholdError> {
        household_rs::cbor::to_canonical_vec(self)
    }
}

#[derive(serde::Serialize)]
struct LocalAnchorAck {
    #[serde(rename = "v")]
    version: u8,
}

/// Generic-failure body — deterministic CBOR `{v=1, error="unauthenticated"}`
/// per R14 / FR-019a. Returned for every join-request failure mode.
#[derive(Serialize)]
struct GenericUnauth<'a> {
    #[serde(rename = "v")]
    version: u8,
    error: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinSource {
    OwnerQr,
    Bonjour,
}

impl JoinSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OwnerQr => "owner_qr",
            Self::Bonjour => "bonjour",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FounderStageAccepted {
    pub owner_event_cursor: u64,
    pub expiry: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FounderStageOutcome {
    Accepted(FounderStageAccepted),
    Replay(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FounderStageError;

fn cbor_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    resp
}

fn unauthenticated_response() -> Response {
    let bytes = household_rs::cbor::to_canonical_vec(&GenericUnauth {
        version: 1,
        error: "unauthenticated",
    })
    .unwrap_or_default();
    cbor_response(StatusCode::UNAUTHORIZED, bytes)
}

async fn pre_household_reject() -> Response {
    unauthenticated_response()
}

/// `GET /pair-machine/anchor-handoff` — Tailnet-gated anchor secret delivery.
///
/// Eliminates QR scan when both candidate and owner-iPhone are on the same
/// Tailnet. Caller MUST originate from a Tailnet IP (`100.64.0.0/10` or
/// `fd00::/8` ULA); all other sources receive 403 with no probing oracle.
///
/// Contract: `specs/005-soyeht-onboarding/contracts/anchor-handoff.md`
pub async fn anchor_handoff_handler(
    State(state): State<PreHouseholdRouterState>,
    req: axum::extract::Request,
) -> Response {
    let t0 = Instant::now();
    // 1. Source IP check — Tailnet CGNAT or ULA only.
    // ConnectInfo is injected by `into_make_service_with_connect_info` in
    // production; in tests, inject it directly via `.extension(ConnectInfo(...))`.
    let is_tailnet = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ci| classify_source(ci.0.ip()) == DiscoverySource::Tailnet);
    if !is_tailnet {
        let bytes = anchor_cbor_error("tailnet_required");
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
            bytes,
        )
            .into_response();
    }

    // 2. Load window snapshot.
    let snap = state.window.snapshot().await;

    // 3. State gate.
    match snap.state {
        PairMachineState::Idle => {
            let bytes = anchor_cbor_error("no_active_pair_machine");
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
                bytes,
            )
                .into_response();
        }
        PairMachineState::Committed | PairMachineState::Aborted => {
            let bytes = anchor_cbor_error("window_terminated");
            return (
                StatusCode::GONE,
                [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
                bytes,
            )
                .into_response();
        }
        PairMachineState::Staging | PairMachineState::AwaitingOwner => {}
    }

    // 4. Expiry check.
    if let Some(expiry) = snap.expiry {
        let now = time_util::unix_now_secs_checked("anchor_handoff.clock").unwrap_or(u64::MAX);
        if now >= expiry {
            let bytes = anchor_cbor_error("window_terminated");
            return (
                StatusCode::GONE,
                [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
                bytes,
            )
                .into_response();
        }
    }

    // 5. Extract required fields (all populated when window is Staging/AwaitingOwner).
    let (Some(m_pub), Some(nonce), Some(anchor_secret)) = (
        snap.m_pub.as_ref(),
        snap.nonce.as_ref(),
        snap.anchor_secret.as_ref(),
    ) else {
        tracing::warn!(
            stage = "anchor_handoff.missing_fields",
            state = ?snap.state,
        );
        let bytes = anchor_cbor_error("no_active_pair_machine");
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
            bytes,
        )
            .into_response();
    };

    let fingerprint = snap.fingerprint.as_deref().unwrap_or("").to_string();
    let expires_at = snap.expiry.unwrap_or(0);

    // u128→u64 truncation impossible in practice (u64 covers ~585 millennia).
    #[allow(clippy::cast_possible_truncation)]
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    tracing::info!(stage = "anchor_handoff.served", expires_at, elapsed_ms,);

    let body = AnchorHandoffResponse {
        v: 1,
        m_pub: ByteBuf::from(m_pub.to_vec()),
        nonce: ByteBuf::from(nonce.to_vec()),
        anchor_secret: ByteBuf::from(anchor_secret.to_vec()),
        fingerprint,
        expires_at,
    };
    match household_rs::cbor::to_canonical_vec(&body) {
        Ok(bytes) => cbor_response(StatusCode::OK, bytes),
        Err(e) => {
            tracing::error!(stage = "anchor_handoff.encode_failed", error = %e);
            let bytes = anchor_cbor_error("internal_error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
                bytes,
            )
                .into_response()
        }
    }
}

#[derive(Serialize)]
struct AnchorHandoffResponse {
    v: u8,
    m_pub: ByteBuf,
    nonce: ByteBuf,
    anchor_secret: ByteBuf,
    fingerprint: String,
    expires_at: u64,
}

#[derive(Serialize)]
struct AnchorHandoffError {
    v: u8,
    error: &'static str,
}

fn anchor_cbor_error(error: &'static str) -> Vec<u8> {
    household_rs::cbor::to_canonical_vec(&AnchorHandoffError { v: 1, error }).unwrap_or_default()
}

/// `GET /pair-machine/local/seed?nonce=<base32-short>`.
///
/// Used by Story 2 discovery so M1 can fetch the exact signed `JoinRequest` bytes
/// cached by the candidate install path.
pub async fn local_seed_handler(
    State(state): State<PreHouseholdRouterState>,
    uri: Uri,
) -> Response {
    let Some(supplied_nonce) = query_param(&uri, "nonce") else {
        return unauthenticated_response();
    };
    let snap = state.window.snapshot().await;
    // Accept both `Staging` and `AwaitingOwner` per
    // `contracts/local-anchor.md` §"State gate". `AwaitingOwner` is the
    // protocol-correct state once the owner-event has been appended;
    // refusing it here would prevent M1's recovery probe (T073) from
    // re-fetching the cached `JoinRequest` after a daemon restart, and
    // would force the iPhone to race the owner-event append.
    if !matches!(
        snap.state,
        PairMachineState::Staging | PairMachineState::AwaitingOwner
    ) {
        return unauthenticated_response();
    }
    let Some(nonce) = snap.nonce.as_ref() else {
        return unauthenticated_response();
    };
    if nonce.len() < 8 {
        return unauthenticated_response();
    }
    let expected = household_rs::ids::base32_lower_nopad_encode(&nonce.as_ref()[..8]);
    if supplied_nonce != expected {
        return unauthenticated_response();
    }
    let Some(cached) = snap.cached_join_request.as_ref() else {
        return unauthenticated_response();
    };
    cbor_response(StatusCode::OK, cached.to_vec())
}

/// `POST /pair-machine/local/anchor`.
///
/// External trust anchor delivered by the owner iPhone after the human
/// owner has approved the join (B7 / `contracts/local-anchor.md`). The
/// iPhone authenticates by presenting `anchor_secret` from the QR;
/// constant-time comparison against `pair_machine_window.anchor_secret`
/// gates the pin. Idempotent on identical re-pinning; divergent
/// re-pinning is refused.
pub async fn local_anchor_handler(
    State(state): State<PreHouseholdRouterState>,
    body: Bytes,
) -> Response {
    use household_rs::cbor::from_canonical_slice;
    use subtle::ConstantTimeEq;
    let t0 = Instant::now();

    let snap = state.window.snapshot().await;
    if !matches!(
        snap.state,
        PairMachineState::Staging | PairMachineState::AwaitingOwner
    ) {
        return unauthenticated_response();
    }
    let anchor: LocalAnchor = match from_canonical_slice(&body) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_anchor.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    match anchor.to_canonical_bytes() {
        Ok(canonical) if canonical == body.as_ref() => {}
        _ => {
            tracing::warn!(
                stage = "pair_machine.local_anchor.rejected",
                reason = "non_canonical_cbor",
            );
            return unauthenticated_response();
        }
    }
    if anchor.version != 1 {
        return unauthenticated_response();
    }
    if anchor.anchor_secret.len() != 32 {
        return unauthenticated_response();
    }
    let Some(window_secret) = snap.anchor_secret.as_ref() else {
        // Window was opened by the founder-side staging path
        // (Story 2 fetched JoinRequest), which has no candidate
        // anchor secret to gate against. The candidate's own install
        // path always sets `Some` so this branch only applies to
        // founder-side windows that should never receive
        // `local/anchor`.
        return unauthenticated_response();
    };
    if window_secret.len() != 32 {
        return unauthenticated_response();
    }
    // Constant-time compare across the 32-byte secrets.
    if anchor
        .anchor_secret
        .ct_eq(window_secret.as_ref())
        .unwrap_u8()
        != 1
    {
        tracing::warn!(
            stage = "pair_machine.local_anchor.rejected",
            reason = "anchor_secret_mismatch",
        );
        return unauthenticated_response();
    }
    let Ok(hh_pub_arr) = <[u8; 33]>::try_from(anchor.hh_pub.as_ref()) else {
        return unauthenticated_response();
    };
    let Ok(hh_pub_key) = household_rs::keys::P256PublicKey::from_bytes(&hh_pub_arr) else {
        return unauthenticated_response();
    };
    let derived_hh_id = household_rs::derive_household_id(&hh_pub_key);
    if derived_hh_id.to_string() != anchor.hh_id {
        tracing::warn!(
            stage = "pair_machine.local_anchor.rejected",
            reason = "hh_id_derivation_mismatch",
        );
        return unauthenticated_response();
    }
    if let Err(e) = state
        .window
        .pin_household_anchor(anchor.hh_id.clone(), hh_pub_arr)
        .await
    {
        match e {
            household_rs::pair_machine::WindowError::MismatchedCeremony => {
                tracing::warn!(
                    stage = "pair_machine.local_anchor.rejected",
                    reason = "divergent_pin",
                );
            }
            other => {
                tracing::warn!(
                    stage = "pair_machine.local_anchor.rejected",
                    reason = "pin_failed",
                    error = %other,
                );
            }
        }
        return unauthenticated_response();
    }
    // u128→u64 truncation impossible in practice (u64 covers ~585 millennia).
    #[allow(clippy::cast_possible_truncation)]
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    tracing::info!(
        stage = "pair_machine.local_anchor.accepted",
        hh_id = %anchor.hh_id,
        elapsed_ms,
    );
    let bytes =
        household_rs::cbor::to_canonical_vec(&LocalAnchorAck { version: 1 }).unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

/// `POST /pair-machine/local/finalize`.
///
/// M2 validates the `JoinResponse`, unwraps the peer-delivered shard, rewraps
/// it for local at-rest storage, and atomically commits the post-join files.
pub async fn local_finalize_handler(
    State(state): State<PreHouseholdRouterState>,
    body: Bytes,
) -> Response {
    let t0 = Instant::now();
    let _finalize_guard = state.finalize_lock.lock().await;
    let snap = state.window.snapshot().await;
    if matches!(snap.state, PairMachineState::Committed) {
        if snap
            .cached_response
            .as_ref()
            .is_some_and(|cached| cached.as_ref() == body.as_ref())
        {
            let Ok(response) = household_rs::cbor::from_canonical_slice::<JoinResponse>(&body)
            else {
                return unauthenticated_response();
            };
            return finalize_ack_response(&response.machine_cert);
        }
        return unauthenticated_response();
    }
    if !matches!(
        snap.state,
        PairMachineState::Staging | PairMachineState::AwaitingOwner
    ) {
        return unauthenticated_response();
    }

    let response: JoinResponse = match household_rs::cbor::from_canonical_slice(&body) {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    match response.to_canonical_bytes() {
        Ok(canonical) if canonical == body.as_ref() => {}
        Ok(_) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "non_canonical_cbor",
            );
            return unauthenticated_response();
        }
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "cbor_reencode",
                error = %e,
            );
            return unauthenticated_response();
        }
    }
    if response.version != 1 {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "bad_version",
            version = response.version,
        );
        return unauthenticated_response();
    }
    // CBOR-shape check (`join_request_hash`) — bind this response to the
    // exact `JoinRequest` cached on the candidate, regardless of the
    // contents of the rest of the body. Per `contracts/local-anchor.md`,
    // this runs BEFORE the external-anchor gate so the anchor gate is
    // applied to a response that is already shape-checked.
    let Some(cached_join_request) = snap.cached_join_request.as_ref() else {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "missing_cached_join_request",
        );
        return unauthenticated_response();
    };
    let expected_join_request_hash = join_request_hash(cached_join_request.as_ref());
    if response.join_request_hash.as_ref() != expected_join_request_hash.as_slice() {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "join_request_hash_mismatch",
        );
        return unauthenticated_response();
    }
    // External-anchor gate (B7 / contracts/local-anchor.md). The
    // `JoinResponse` is otherwise self-contained: an attacker on the
    // network can mint their own household root, forge a founder
    // cert, encrypt a shard for the candidate's `m_pub` (publicly
    // known via `local/seed`), sign the response, and POST it — every
    // internal cross-check passes. The fix is to require the iPhone
    // to deliver `(hh_id, hh_pub)` ahead of finalize via
    // `POST /pair-machine/local/anchor`, authenticated by the
    // QR-only `anchor_secret`. The candidate refuses to accept any
    // `JoinResponse` whose household identity does not bit-equal
    // the pinned anchor. Runs AFTER `join_request_hash` and BEFORE
    // any cert-chain verification per the contract sequence.
    let Some(pinned_hh_pub) = snap.pinned_hh_pub.as_ref() else {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "trust_anchor_missing",
            hint = "iPhone has not delivered POST /pair-machine/local/anchor yet",
        );
        return unauthenticated_response();
    };
    if pinned_hh_pub.as_ref() != response.household_record.hh_pub.as_bytes() {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "trust_anchor_hh_pub_mismatch",
        );
        return unauthenticated_response();
    }
    if snap
        .pinned_hh_id
        .as_deref()
        .is_none_or(|id| id != response.household_record.hh_id.as_str())
    {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "trust_anchor_hh_id_mismatch",
        );
        return unauthenticated_response();
    }
    if let Err(e) = response.household_record.validate() {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "record_invalid",
            error = %e,
        );
        return unauthenticated_response();
    }
    let Ok(trust_hh_pub) = <&[u8; 33]>::try_from(pinned_hh_pub.as_ref()) else {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "trust_anchor_hh_pub_length",
        );
        return unauthenticated_response();
    };
    if let Err(e) = household_rs::machine_cert::verify_against_household_root(
        &response.machine_cert,
        trust_hh_pub,
    ) {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "candidate_cert_invalid",
            error = %e,
        );
        return unauthenticated_response();
    }

    let candidate_key =
        match household_rs::ensure_candidate_machine_keypair(&state.state_dir, state.key_policy) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "candidate_key_unavailable",
                    error = %e,
                );
                return unauthenticated_response();
            }
        };
    let candidate_pub = candidate_key.public();
    let candidate_m_id = household_rs::derive_machine_id(&candidate_pub);
    let candidate_m_id_str = candidate_m_id.to_string();
    if response.machine_cert.m_pub != candidate_pub || response.machine_cert.m_id != candidate_m_id
    {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "candidate_cert_mismatch",
        );
        return unauthenticated_response();
    }
    if !response
        .household_record
        .members
        .iter()
        .any(|member| member == &candidate_m_id)
    {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "candidate_missing_from_record",
        );
        return unauthenticated_response();
    }

    let Some((founder_cert, founder_entry_m_pub)) =
        verified_founder_cert_from_peer_list(&response, trust_hh_pub)
    else {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "founder_cert_missing",
        );
        return unauthenticated_response();
    };
    if let Err(e) = response.verify_response_sig(&founder_cert) {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "response_sig_invalid",
            error = %e,
        );
        return unauthenticated_response();
    }
    // Phase 3 candidate-side shard decryption uses ECDH with the
    // founder's m_pub (`shard_at_rest::decrypt_from_peer`), which
    // needs the candidate's M_priv as a raw 32-byte scalar. SE-backed
    // keys are non-exportable by design and return `None` here.
    // Same architectural limitation as `owner_approve_handler`:
    // Phase 3 candidates on macOS MUST run with
    // `THEYOS_FORCE_SOFTWARE_KEYS=1` at install time. The wire
    // response is the generic 401 per FR-019a / R14; the WARN log
    // surfaces the actionable reason for the operator on M2. See
    // `contracts/local-anchor.md` §"Story 2 anchor mechanism".
    let Some(candidate_scalar) = candidate_key.as_software_secret().copied() else {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "candidate_scalar_unavailable",
            hint = "SE-backed M_priv is non-exportable; Phase 3 shard decryption requires THEYOS_FORCE_SOFTWARE_KEYS=1 at install time",
        );
        return unauthenticated_response();
    };
    let plaintext_shard = match household_rs::shard_at_rest::decrypt_from_peer(
        &response.encrypted_shard,
        &candidate_scalar,
        &founder_entry_m_pub,
        &candidate_m_id_str,
    ) {
        Ok(shard) => shard,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "shard_decrypt_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    let self_shard = match household_rs::shard_at_rest::encrypt_for_self(
        &plaintext_shard,
        &candidate_scalar,
        &candidate_pub,
        &candidate_m_id_str,
        household_rs::shamir::SHARD_X_M2,
    ) {
        Ok(shard) => shard,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "shard_rewrap_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };

    let mut committed_snap = snap.clone();
    committed_snap.state = PairMachineState::Committed;
    committed_snap.cached_response = Some(ByteBuf::from(body.to_vec()));

    // R6.2: order matches the M1 `CeremonyTxn::prepare` invariant —
    // `household_record.cbor` rename is the canonical "candidate is
    // committed" marker and MUST be the LAST file promoted. A crash
    // between any of [cert, marker, self_shard, window, push_token]
    // and the record promotion leaves the on-disk record at
    // `shamir_n=1` (or absent), which boot-time
    // `recover_partial_phase3_commit` correctly classifies as
    // logically rolled back — the orphan `.staged` files are unlinked
    // and the candidate stays uncommitted. Without this ordering, a
    // crash after the record promotion but before later files would
    // cross the commit marker while M1 sees finalize as failed,
    // producing the R5.7 split-brain on the candidate side.
    let mut staged_files = Vec::new();
    staged_files.push((
        household_rs::storage::machine_cert_for(&state.state_dir, &founder_cert.m_id.to_string()),
        match household_rs::cbor::to_canonical_vec(&founder_cert) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "founder_cert_encode",
                    error = %e,
                );
                return unauthenticated_response();
            }
        },
    ));
    staged_files.push((
        household_rs::storage::machine_cert_for(&state.state_dir, &candidate_m_id_str),
        match household_rs::cbor::to_canonical_vec(&response.machine_cert) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "candidate_cert_encode",
                    error = %e,
                );
                return unauthenticated_response();
            }
        },
    ));
    let mut marker_bytes = candidate_m_id_str.into_bytes();
    marker_bytes.push(b'\n');
    staged_files.push((
        household_rs::storage::self_m_id_marker_path(&state.state_dir),
        marker_bytes,
    ));
    staged_files.push((
        shamir_self_shard_path(&state.state_dir),
        match self_shard.to_canonical_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "self_shard_encode",
                    error = %e,
                );
                return unauthenticated_response();
            }
        },
    ));
    staged_files.push((
        pair_machine_window_path(&state.state_dir),
        match household_rs::cbor::to_canonical_vec(&committed_snap) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "window_encode",
                    error = %e,
                );
                return unauthenticated_response();
            }
        },
    ));
    if let Some(push_token_seed) = &response.push_token_seed {
        if push_token_seed.version != 1 || push_token_seed.platform != "ios" {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "bad_push_token_seed",
            );
            return unauthenticated_response();
        }
        staged_files.push((
            owner_push_token_path(&state.state_dir),
            match household_rs::cbor::to_canonical_vec(push_token_seed) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        stage = "pair_machine.local_finalize.rejected",
                        reason = "push_token_seed_encode",
                        error = %e,
                    );
                    return unauthenticated_response();
                }
            },
        ));
    }
    // R6.2: `household_record.cbor` MUST be the LAST staged entry —
    // its promotion is the canonical "candidate is committed" marker.
    staged_files.push((
        household_rs::storage::household_record_path(&state.state_dir),
        match household_rs::cbor::to_canonical_vec(&response.household_record) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    stage = "pair_machine.local_finalize.rejected",
                    reason = "record_encode",
                    error = %e,
                );
                return unauthenticated_response();
            }
        },
    ));

    // T064: failure-injection crash point — fires before any
    // staged file lands on disk. A registered Panic aborts M2
    // here, simulating an M1 transport failure on the finalize
    // POST. Compiled out in production builds.
    #[cfg(any(test, feature = "failure-injection"))]
    {
        match crate::failure_injection::apply(
            crate::failure_injection::InjectionPoint::M2BeforeStage,
        )
        .await
        {
            crate::failure_injection::Outcome::EarlyReject(_) => {
                return unauthenticated_response();
            }
            crate::failure_injection::Outcome::Skip
            | crate::failure_injection::Outcome::Continue => {}
        }
    }

    let staged = match household_rs::storage::stage_commit_files(&staged_files) {
        Ok(staged) => staged,
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local_finalize.rejected",
                reason = "stage_files_failed",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    // T064: failure-injection crash point — fires after every
    // `.staged` file lands on disk but before `staged.commit()`
    // promotes them. A registered Panic leaves a full `.staged` set
    // (no final files) on disk, exercising boot-time
    // `recover_partial_phase3_commit`'s M2-side rollback branch. A
    // registered SkipWrite skips the commit entirely (same on-disk
    // state but the handler returns 200, which is wrong-for-protocol
    // but the harness expects M1 to crash before observing it).
    #[cfg(any(test, feature = "failure-injection"))]
    {
        match crate::failure_injection::apply(
            crate::failure_injection::InjectionPoint::M2AfterFounderCertStaged,
        )
        .await
        {
            crate::failure_injection::Outcome::Skip => {
                // Drop staged set without unlinking — Drop impl on
                // StagedCommit removes them; the test should arm Panic
                // instead if it needs the .staged files preserved.
                drop(staged);
                return unauthenticated_response();
            }
            crate::failure_injection::Outcome::EarlyReject(_) => {
                drop(staged);
                return unauthenticated_response();
            }
            crate::failure_injection::Outcome::Continue => {}
        }
    }
    if let Err(e) = staged.commit() {
        tracing::warn!(
            stage = "pair_machine.local_finalize.rejected",
            reason = "commit_files_failed",
            error = %e,
        );
        return unauthenticated_response();
    }
    // T064: failure-injection crash point — fires after M2's
    // staged.commit() but BEFORE the FinalizeAck reaches M1. A
    // registered Panic models "M2 committed but the ack packet was
    // lost in flight" — M1 sees a transport error.
    #[cfg(any(test, feature = "failure-injection"))]
    {
        match crate::failure_injection::apply(
            crate::failure_injection::InjectionPoint::M2BeforeAckEncode,
        )
        .await
        {
            crate::failure_injection::Outcome::EarlyReject(_) => {
                return unauthenticated_response();
            }
            crate::failure_injection::Outcome::Skip
            | crate::failure_injection::Outcome::Continue => {}
        }
    }
    state
        .window
        .note_committed_after_external_persist(body.to_vec())
        .await;
    println!("{POST_COMMIT_REDUNDANCY_NOTICE}");
    // u128→u64 truncation impossible in practice (u64 covers ~585 millennia).
    #[allow(clippy::cast_possible_truncation)]
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    tracing::info!(stage = "pair_machine.local_finalize.committed", elapsed_ms,);

    finalize_ack_response(&response.machine_cert)
}

fn finalize_ack_response(cert: &household_rs::MachineCert) -> Response {
    let bytes = FinalizeAck::for_machine_cert(cert)
        .and_then(|ack| ack.to_canonical_bytes())
        .unwrap_or_default();
    cbor_response(StatusCode::OK, bytes)
}

fn verified_founder_cert_from_peer_list(
    response: &JoinResponse,
    trust_hh_pub: &[u8; 33],
) -> Option<(household_rs::MachineCert, household_rs::keys::P256PublicKey)> {
    // Forward-compat for Phase 4+: a single invalid peer must not
    // abort the lookup. `continue` past entries that fail any
    // verification step (missing cert, cert chain, m_id/m_pub binding,
    // self-cert exclusion) and only return `None` if the whole list
    // yields no founder.
    for peer in &response.peer_list {
        let Some(cert) = peer.machine_cert.as_ref() else {
            continue;
        };
        if household_rs::machine_cert::verify_against_household_root(cert, trust_hh_pub).is_err() {
            continue;
        }
        if peer.m_id != cert.m_id.to_string() || peer.m_pub.as_ref() != cert.m_pub.as_bytes() {
            continue;
        }
        if cert.m_id != response.machine_cert.m_id {
            return Some((cert.clone(), cert.m_pub.clone()));
        }
    }
    None
}

fn query_param(uri: &Uri, key: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key { Some(v.to_string()) } else { None }
    })
}

/// `POST /api/v1/household/join-request` handler. Per T042–T046.
///
/// **Auth model**: the external Story 1 endpoint is authenticated by
/// owner `Soyeht-PoP` with `Operation::HouseholdAddMachine`; the inner
/// `JoinRequest.challenge_sig` then proves candidate possession of
/// `M_priv`. Story 2's LAN/browser path uses the private
/// `founder_stage_join_request` helper in-process after fetching the
/// same signed `JoinRequest` from the candidate, so it does not transit
/// an HTTP `PoP` boundary.
///
/// **Failure surface**: Every reject collapses to deterministic CBOR
/// `{v=1, error="unauthenticated"}` with HTTP 401 per R14 — no oracle.
/// The typed reasons travel only via `tracing::warn!` for operator
/// observability.
pub async fn founder_join_request_handler(
    State(state): State<PairMachineRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(now) = time_util::unix_now_secs_checked("join_request.clock") else {
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
            stage = "join_request.rejected",
            reason = "pop_auth_failed",
            error = %e,
        );
        return unauthenticated_response();
    }

    let request: JoinRequest = match household_rs::cbor::from_canonical_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                stage = "join_request.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };

    match founder_stage_join_request(&state, request, JoinSource::OwnerQr, now).await {
        Ok(FounderStageOutcome::Accepted(accepted)) => {
            let bytes = household_rs::cbor::to_canonical_vec(&JoinRequestAccepted {
                version: 1,
                owner_event_cursor: accepted.owner_event_cursor,
                expiry: accepted.expiry,
            })
            .unwrap_or_default();
            cbor_response(StatusCode::CREATED, bytes)
        }
        Ok(FounderStageOutcome::Replay(bytes)) => cbor_response(StatusCode::OK, bytes),
        Err(FounderStageError) => unauthenticated_response(),
    }
}

pub async fn founder_stage_join_request(
    state: &PairMachineRouterState,
    request: JoinRequest,
    source: JoinSource,
    now: u64,
) -> Result<FounderStageOutcome, FounderStageError> {
    // ── 2. Verify signature + field shape ──────────────────────────
    if let Err(e) = verify_join_request(&request) {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "verify_failed",
            error = %e,
        );
        return Err(FounderStageError);
    }

    // The canonical CBOR bytes we cache MUST round-trip the verified
    // request. We re-encode here (rather than reusing `body`) so any
    // non-canonical CBOR sent by a misbehaving client is normalized
    // away before it reaches the owner-event payload — that is the
    // bit-pattern the iPhone re-checks against `challenge_sig`.
    let join_request_cbor = match request.to_canonical_bytes() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "cbor_reencode",
                error = %e,
            );
            return Err(FounderStageError);
        }
    };

    // ── 3. Household identity must be loaded and owner must be paired ─
    let Some(identity) = state.household.current().await else {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "identity_unavailable",
        );
        return Err(FounderStageError);
    };
    let Some(_owner_auth) = state.household.current_owner_auth().await else {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "owner_not_paired",
        );
        return Err(FounderStageError);
    };

    // ── 4. Candidate identity + committed replay branch ──────────────
    let Ok(m_pub_arr) = <[u8; 33]>::try_from(request.m_pub.as_ref()) else {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "m_pub_length",
        );
        return Err(FounderStageError);
    };
    let Ok(candidate_m_pub) = household_rs::keys::P256PublicKey::from_bytes(&m_pub_arr) else {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "m_pub_decode",
        );
        return Err(FounderStageError);
    };
    let candidate_m_id = household_rs::ids::derive_machine_id(&candidate_m_pub);

    let snap = state.window.snapshot().await;

    // Replay-after-commit: same (m_pub, nonce), within grace window.
    //
    // This MUST run before the `shamir_n == 1` and already-member gates:
    // a successful Phase 3 ceremony updates the in-memory household record
    // to post-Shamir (`shamir_n=2`) and adds the candidate to `members`.
    // FR-015 still requires the original completed JoinRequest to return
    // the cached response bytes during its replay grace window.
    if matches!(snap.state, PairMachineState::Committed)
        && same_m_pub_and_nonce(&snap, &m_pub_arr, request.nonce.as_ref())
    {
        if within_replay_grace(&snap, now) {
            let Some(cached) = snap.cached_response.as_ref() else {
                tracing::warn!(
                    stage = "join_request.rejected",
                    source = source.as_str(),
                    reason = "committed_replay_missing_cached_response",
                );
                return Err(FounderStageError);
            };
            tracing::info!(
                stage = "join_request.replay_after_commit",
                source = source.as_str(),
                candidate_m_id = %candidate_m_id,
            );
            return Ok(FounderStageOutcome::Replay(cached.to_vec()));
        }
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "replay_after_grace",
            candidate_m_id = %candidate_m_id,
        );
        return Err(FounderStageError);
    }

    // ── 5. Phase 3 only supports 1→2 growth: refuse if shamir_n != 1 ─
    // A household at shamir_n>=2 has already split the root; admitting
    // a 3rd member needs the (deferred) re-sharding ceremony.
    if identity.record.shamir_n != 1 {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "no_active_sole_shard",
            shamir_n = identity.record.shamir_n,
        );
        return Err(FounderStageError);
    }

    // ── 6. Candidate's m_pub must not already be a member ─────────────
    if identity.record.members.iter().any(|m| m == &candidate_m_id) {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "already_member",
            candidate_m_id = %candidate_m_id,
        );
        return Err(FounderStageError);
    }

    // ── 7. Window state branching ─────────────────────────────────────

    // Idempotent re-stage: same (m_pub, nonce) while AwaitingOwner —
    // surface the existing cursor + expiry rather than appending a
    // duplicate event.
    if matches!(
        snap.state,
        PairMachineState::Staging | PairMachineState::AwaitingOwner
    ) {
        if same_m_pub_and_nonce(&snap, &m_pub_arr, request.nonce.as_ref()) {
            if let (Some(cursor), Some(expiry)) = (snap.owner_event_cursor, snap.expiry) {
                tracing::info!(
                    stage = "join_request.idempotent_restage",
                    source = source.as_str(),
                    candidate_m_id = %candidate_m_id,
                    owner_event_cursor = cursor,
                );
                return Ok(FounderStageOutcome::Accepted(FounderStageAccepted {
                    owner_event_cursor: cursor,
                    expiry,
                }));
            }
            // Staging without cursor yet — race: a concurrent request
            // saw the same window in transition. Fall through to the
            // generic-401 to keep the surface oracle-free.
        }
        // Different m_pub or nonce: a different ceremony is in
        // progress. Generic-401 per spec — no leak that there's an
        // open window.
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "window_already_open",
        );
        return Err(FounderStageError);
    }

    // Aborted / expired Committed (outside grace) / Idle — accept and
    // re-stage. For Aborted/Committed we transition through Idle so
    // `enter_staging`'s precondition is met.
    if !matches!(snap.state, PairMachineState::Idle) {
        if let Err(e) = state.window.return_to_idle().await {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "window_reset_failed",
                error = %e,
            );
            return Err(FounderStageError);
        }
    }

    // ── 7. Fingerprint + ttl ──────────────────────────────────────────
    let fingerprint = household_rs::fingerprint::fingerprint(&m_pub_arr);
    let ttl_secs: u64 = 300;
    let Ok(nonce_arr) = <[u8; 32]>::try_from(request.nonce.as_ref()) else {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "nonce_length",
        );
        return Err(FounderStageError);
    };

    // ── 8. Stage the window with the verified request bytes ───────────
    let expiry = match state
        .window
        .enter_staging(
            m_pub_arr,
            nonce_arr,
            request.transport,
            request.addr.clone(),
            fingerprint.clone(),
            join_request_cbor.clone(),
            ttl_secs,
            // Founder-side staging path (Story 1 join-request POST or
            // Story 2 Bonjour fetch). The founder cannot deliver an
            // anchor to itself; the anchor flow only applies on the
            // candidate side via `local/anchor`.
            None,
        )
        .await
    {
        Ok(expiry) => expiry,
        Err(e) => {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "enter_staging_failed",
                error = %e,
            );
            return Err(FounderStageError);
        }
    };

    // ── 9. Append OwnerEvent{type=join-request} ───────────────────────
    let payload = OwnerEventPayload::JoinRequest(JoinRequestPayload {
        join_request_cbor: serde_bytes::ByteBuf::from(join_request_cbor.clone()),
        fingerprint: fingerprint.clone(),
        expiry,
    });
    let event = match state.event_log.append(
        &identity.cert.m_id.to_string(),
        identity.m_priv.as_ref(),
        OwnerEventType::JoinRequest,
        payload,
    ) {
        Ok(ev) => ev,
        Err(e) => {
            tracing::warn!(
                stage = "join_request.rejected",
                source = source.as_str(),
                reason = "owner_event_append_failed",
                error = %e,
            );
            // Roll the window back to Idle so the next attempt is not
            // blocked by an orphan staging state.
            let _ = state.window.return_to_idle().await;
            return Err(FounderStageError);
        }
    };

    // ── 10. Promote window to AwaitingOwner with the event cursor ─────
    if let Err(e) = state.window.enter_awaiting_owner(event.cursor).await {
        tracing::warn!(
            stage = "join_request.rejected",
            source = source.as_str(),
            reason = "enter_awaiting_owner_failed",
            error = %e,
        );
        let _ = state.window.return_to_idle().await;
        return Err(FounderStageError);
    }
    // Positive observability gate (T093) — the OwnerEvent that
    // becomes the iPhone's approve/decline prompt has been durably
    // appended and broadcast. Distinct from `join_request.accepted`
    // (the wire-level handler outcome): a future regression that
    // splits the prompt-forwarding logic into a separate service
    // would still need to emit this stage to satisfy FR-019.
    tracing::info!(
        stage = "pair_machine.owner_prompt_forwarded",
        source = source.as_str(),
        candidate_m_id = %candidate_m_id,
        owner_event_cursor = event.cursor,
    );
    handlers_owner_events::dispatch_owner_event_tickle_if_idle(
        state.state_dir.clone(),
        &state.event_broadcaster,
    );

    tracing::info!(
        stage = "join_request.accepted",
        source = source.as_str(),
        candidate_m_id = %candidate_m_id,
        owner_event_cursor = event.cursor,
        expiry = expiry,
        fingerprint = %fingerprint,
    );

    Ok(FounderStageOutcome::Accepted(FounderStageAccepted {
        owner_event_cursor: event.cursor,
        expiry,
    }))
}

fn same_m_pub_and_nonce(snap: &PairMachineWindowSnapshot, m_pub: &[u8; 33], nonce: &[u8]) -> bool {
    let Some(snap_m_pub) = snap.m_pub.as_ref() else {
        return false;
    };
    let Some(snap_nonce) = snap.nonce.as_ref() else {
        return false;
    };
    // Constant-time compare not required here: window state is
    // server-side and the comparison gates a logical branch, not a
    // secret. Plain byte equality is sufficient.
    snap_m_pub.as_slice() == m_pub.as_slice() && snap_nonce.as_slice() == nonce
}

fn within_replay_grace(snap: &PairMachineWindowSnapshot, now: u64) -> bool {
    let Some(expiry) = snap.expiry else {
        return false;
    };
    // Grace = TTL + 60 s per R7 / T045.
    let grace_deadline = expiry.saturating_add(60);
    now <= grace_deadline
}
