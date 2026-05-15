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
use household_rs::owner_events::{
    JoinCancelledPayload, MachineJoinedPayload, OwnerDevicePushToken, OwnerEvent, OwnerEventLog,
    OwnerEventPayload, OwnerEventType, OwnerEventsBroadcaster,
};
use household_rs::pair_machine::{
    CeremonyError, CeremonyInputs, CeremonyTxn, FinalizeWithM2Options, FinalizeWithM2Outcome,
    JoinRequest, OwnerApproval, OwnerApprovalContext, PairMachineState, PairMachineWindow,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::apns_dispatcher;
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
    /// Keystore policy under which `HH_priv` was originally persisted.
    /// `owner_approve_handler` forwards it into `CeremonyInputs` so
    /// `CeremonyTxn::commit` can destroy the right backend on Shamir
    /// transition.
    pub key_backing_policy: household_rs::KeyBackingPolicy,
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
            key_backing_policy,
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

    let approval: OwnerApproval = match household_rs::cbor::from_canonical_slice(&body) {
        Ok(approval) => approval,
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "cbor_decode",
                error = %e,
            );
            return unauthenticated_response();
        }
    };
    match approval.to_canonical_bytes() {
        Ok(canonical) if canonical == body.as_ref() => {}
        Ok(_) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "non_canonical_cbor",
            );
            return unauthenticated_response();
        }
        Err(e) => {
            tracing::warn!(
                stage = "owner_events.approve.rejected",
                reason = "cbor_reencode",
                error = %e,
            );
            return unauthenticated_response();
        }
    }
    if approval.version != 1 || approval.cursor != cursor {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "body_cursor_mismatch",
            body_cursor = approval.cursor,
            path_cursor = cursor,
        );
        return unauthenticated_response();
    }

    let Some(identity) = state.household.current().await else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "identity_unavailable",
        );
        return unauthenticated_response();
    };
    let snap = state.window.snapshot().await;
    if snap.state != PairMachineState::AwaitingOwner || snap.owner_event_cursor != Some(cursor) {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "window_cursor_mismatch",
            cursor = cursor,
            window_cursor = ?snap.owner_event_cursor,
        );
        return unauthenticated_response();
    }
    let Some(active_m_pub) = snap.m_pub.clone() else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "window_missing_m_pub",
        );
        return unauthenticated_response();
    };
    let Some(cached_join_request) = snap.cached_join_request.clone() else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "missing_cached_join_request",
        );
        return unauthenticated_response();
    };
    let join_request: JoinRequest =
        match household_rs::cbor::from_canonical_slice(cached_join_request.as_ref()) {
            Ok(join_request) => join_request,
            Err(e) => {
                tracing::warn!(
                    stage = "owner_events.approve.rejected",
                    reason = "cached_join_request_decode",
                    error = %e,
                );
                return unauthenticated_response();
            }
        };
    let approval_context = OwnerApprovalContext::build(
        identity.record.hh_id.clone(),
        owner_auth.owner_person_cert.p_id.clone(),
        cursor,
        join_request.challenge_sig.clone(),
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
        abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed").await;
        return unauthenticated_response();
    }

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
        abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed").await;
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
        abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed").await;
        return unauthenticated_response();
    };
    let Some(m1_priv) = identity.m_priv.as_software_secret().copied() else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "m1_scalar_unavailable",
            hint = "SE-backed M_priv is non-exportable; Phase 3 ECDH for shard encryption requires THEYOS_FORCE_SOFTWARE_KEYS=1 at bootstrap",
        );
        abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed").await;
        return unauthenticated_response();
    };
    let Ok(candidate_m_pub_sec1) = <[u8; 33]>::try_from(join_request.m_pub.as_ref()) else {
        tracing::warn!(
            stage = "owner_events.approve.rejected",
            reason = "candidate_m_pub_length",
        );
        abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed").await;
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
            abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed").await;
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
        candidate_hostname: join_request.hostname.clone(),
        candidate_platform: join_request.platform.clone(),
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
            abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed").await;
            return unauthenticated_response();
        }
    };
    let addr = snap
        .addr_hint
        .clone()
        .unwrap_or_else(|| join_request.addr.clone());
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
    // The marker is "intent" not "ack-success": it is set before the
    // irreversible action (M2's commit). Definitive pre-commit rejects
    // clear it and roll back; ambiguous transport/ack failures leave
    // it with the `.staged` set so recovery can probe M2 instead of
    // destroying evidence. The `phase3_finalize_ack.marker_write_failed`
    // branch surfaces 401 + ABORTS the ceremony before
    // `finalize_with_m2` runs, so a marker-write failure cannot
    // create a half-committed state on M2.
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
        txn.rollback();
        abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed").await;
        return unauthenticated_response();
    }
    // T073: persist the JoinResponse bytes we are about to POST so
    // boot-time `recover_phase3_ceremony` can re-POST them after a
    // crash. `HH_priv` is destroyed during commit, so the
    // encrypted-shard-for-M2 inside `JoinResponse` cannot be
    // reconstructed post-crash. Build the response here using the same
    // options finalize_with_m2 will use.
    let cached_join_request_bytes = cached_join_request.to_vec();
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
                    abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed")
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
                abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed").await;
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
        let _ = household_rs::storage::clear_phase3_finalize_ack_marker(&state.state_dir);
        txn.rollback();
        abort_with_cancel_event(&state, &identity, active_m_pub, "prepare_failed").await;
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
            abort_with_cancel_event(&state, &identity, active_m_pub, "candidate_unreachable").await;
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
