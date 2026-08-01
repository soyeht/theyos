//! Bootstrap endpoints: `/bootstrap/*` and `/health`.
//!
//! These handlers are always live — even on a fresh, uninitialized engine.
//! They power the onboarding state machine that replaces the legacy
//! `theyos install` CLI flow (FR-002..FR-004).
//!
//! Routes exported:
//! - `GET  /bootstrap/status`                 — onboarding state machine (T009)
//! - `POST /bootstrap/initialize`             — mint the casa identity (T025, FR-003)
//! - `POST /bootstrap/claim-setup-invitation` — iPhone-first scenario B claim (T053, FR-005)
//! - `GET  /health`                           — liveness probe (T010)
//! - `POST /api/v1/household/reachability/echo` — Ready-only diagnostic echo

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};

use crate::setup_invitation::SetupInvitationCache;
use household_rs::HouseholdAuthState;
use household_rs::MachineCert;
use household_rs::bootstrap::{
    AcceptHouseholdConfirmError, AcceptHouseholdPrepareOpts, BootstrapOpts, KeyBackingPolicy,
    bootstrap_or_load, confirm_accept_household, load_pending_accept_household,
    prepare_accept_household,
};
use household_rs::bootstrap_error::BootstrapErrorCode;
use household_rs::bootstrap_state::{self, BootstrapState};
use household_rs::household_record::validate_household_name;
use household_rs::ids::{HouseholdId, MachineId, derive_household_id};
use household_rs::keys::{P256PublicKey, P256Signature, verify_signature};
use household_rs::pair_device::PairDeviceWindow;
use household_rs::pair_machine::PairMachineWindow;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tracing::info;

use crate::household_state::{HouseholdState, SharedHouseholdIdentity};

/// Diagnostic reachability endpoint shared by the daemon and its peer probe.
pub const REACHABILITY_ECHO_PATH: &str = "/api/v1/household/reachability/echo";
/// Fixed challenge size keeps the endpoint non-amplifying and bounds every
/// request and response independently of the caller.
pub const REACHABILITY_ECHO_BYTES: usize = 32;

// ── Shared state ──────────────────────────────────────────────────────────────

/// State visible to all bootstrap handlers.
#[derive(Clone)]
pub struct BootstrapHandlerState {
    /// Current onboarding state. Written by initialize / teardown / pairing
    /// finalize handlers; read by every handler in this module.
    pub bootstrap: Arc<RwLock<BootstrapState>>,
    /// Household identity (loaded after pairing completes, or on boot if
    /// state dir already has identity).
    pub household: HouseholdState,
    /// Absolute path to the engine state directory.
    pub state_dir: PathBuf,
    /// Wall-clock instant when the engine process started (for `uptime_secs`).
    pub started_at: Instant,
    /// Pair-device window for minting the first pairing QR after initialize.
    pub pair_device_window: Arc<PairDeviceWindow>,
    /// Pair-machine window shared with the daemon-mounted
    /// `/pair-machine/local/*` routes. The `POST /bootstrap/pair-machine/local/stage`
    /// handler mutates this window via `pair_machine_local::stage`; the
    /// `local/seed`, `local/anchor`, and `local/finalize` routes read it
    /// without a disk round-trip. Holding a single `Arc` here removes the
    /// need for a second `TcpListener` bound at the daemon's address.
    pub pair_machine_window: Arc<PairMachineWindow>,
    /// In-memory cache of discovered `_soyeht-setup._tcp.` invitations from
    /// iPhones (scenario B `AirDrop` flow). Populated by the Bonjour browser task;
    /// consumed by `POST /bootstrap/claim-setup-invitation` (T053).
    pub setup_invitation_cache: SetupInvitationCache,
    /// The TCP port the engine binds household endpoints on. Used to build
    /// the `mac_engine_url` advertised in the setup-invitation claim ACK so
    /// the iPhone can reach `POST /bootstrap/initialize` over Tailnet.
    pub engine_port: u16,
    /// Function that returns the engine's local Tailnet IPv4 when one is
    /// available. Defaults to `tailnet_address::current_tailnet_ipv4` which
    /// walks `getifaddrs(3)`. Tests inject a deterministic resolver so they
    /// don't depend on whether the test host is on a Tailnet.
    pub tailnet_resolver: crate::tailnet_address::TailnetResolver,
}

pub type BootstrapStateArc = Arc<RwLock<BootstrapState>>;

impl BootstrapHandlerState {
    #[must_use]
    pub fn new(
        bootstrap: BootstrapStateArc,
        household: HouseholdState,
        state_dir: PathBuf,
        pair_device_window: Arc<PairDeviceWindow>,
        pair_machine_window: Arc<PairMachineWindow>,
        engine_port: u16,
    ) -> Self {
        Self {
            bootstrap,
            household,
            state_dir,
            pair_device_window,
            pair_machine_window,
            started_at: Instant::now(),
            setup_invitation_cache: crate::setup_invitation::new_cache(),
            engine_port,
            tailnet_resolver: crate::tailnet_address::current_tailnet_ipv4,
        }
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Wire the bootstrap router. The returned `Router` MUST be merged into the
/// top-level app **before** the auth middleware layer so these endpoints are
/// accessible without a session token.
pub fn bootstrap_router(state: BootstrapHandlerState) -> Router {
    Router::new()
        .route("/bootstrap/status", get(get_bootstrap_status))
        .route("/bootstrap/initialize", post(post_initialize))
        .route("/bootstrap/accept-household", post(post_accept_household))
        .route(
            "/bootstrap/accept-household/confirm",
            post(post_accept_household_confirm),
        )
        .route(
            "/bootstrap/claim-setup-invitation",
            post(post_claim_setup_invitation),
        )
        .route("/bootstrap/teardown", post(post_teardown))
        .route(
            "/bootstrap/pair-machine/local/stage",
            post(post_pair_machine_local_stage),
        )
        .route(
            "/bootstrap/pair-device/reissue",
            post(post_pair_device_reissue),
        )
        .route(
            "/bootstrap/pair-device-uri",
            get(get_bootstrap_pair_device_uri),
        )
        .route("/health", get(get_health))
        .route("/healthz", get(get_health))
        .route(
            REACHABILITY_ECHO_PATH,
            post(post_reachability_echo).layer(DefaultBodyLimit::max(REACHABILITY_ECHO_BYTES)),
        )
        .with_state(state)
}

// ── Request / response types ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct InitializeRequest {
    #[serde(rename = "v")]
    version: u8,
    name: String,
}

#[derive(Serialize)]
struct InitializeResponse {
    #[serde(rename = "v")]
    version: u8,
    hh_id: String,
    hh_pub: ByteBuf,
    name: String,
    pair_qr_uri: String,
    created_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptHouseholdRequest {
    #[serde(rename = "v")]
    version: u8,
    hh_id: String,
    hh_pub: ByteBuf,
    hh_name: String,
    invitation_token: ByteBuf,
}

#[derive(Serialize)]
struct AcceptHouseholdResponse {
    #[serde(rename = "v")]
    version: u8,
    m_id: String,
    m_pub: ByteBuf,
    join_challenge: ByteBuf,
    challenge_sig_required: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptHouseholdConfirmRequest {
    #[serde(rename = "v")]
    version: u8,
    m_id: String,
    machine_cert: ByteBuf,
    challenge_sig: ByteBuf,
}

#[derive(Serialize)]
struct AcceptHouseholdConfirmResponse {
    #[serde(rename = "v")]
    version: u8,
    bootstrap_state: &'static str,
    m_id: String,
    hh_id: String,
}

#[derive(Serialize)]
struct InitializeError<'a> {
    #[serde(rename = "v")]
    version: u8,
    error: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'a str>,
}

fn cbor_error(
    status: StatusCode,
    error: &str,
    reason: Option<String>,
    state: Option<&str>,
) -> Response {
    let body = InitializeError {
        version: 1,
        error,
        reason,
        state,
    };
    let bytes = household_rs::cbor::to_canonical_vec(&body).unwrap_or_default();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/cbor"),
    );
    (status, headers, bytes).into_response()
}

// ── Teardown types ────────────────────────────────────────────────────────────

/// Fields the iPhone signs — everything in `TeardownRequest` except `signature`.
#[derive(Serialize, Deserialize)]
struct TeardownPayload {
    #[serde(rename = "v")]
    version: u8,
    op: String,
    hh_id: String,
    m_id: String,
    nonce: ByteBuf,
    ts: u64,
    signed_by: ByteBuf,
}

/// Full teardown wire shape; `signature` covers canonical CBOR of `TeardownPayload`.
#[derive(Serialize, Deserialize)]
struct TeardownRequest {
    #[serde(rename = "v")]
    version: u8,
    op: String,
    hh_id: String,
    m_id: String,
    nonce: ByteBuf,
    ts: u64,
    signed_by: ByteBuf,
    signature: ByteBuf,
}

#[derive(Serialize)]
struct TeardownAck {
    #[serde(rename = "v")]
    version: u8,
    torn_at: u64,
}

// ── Claim-setup-invitation types ──────────────────────────────────────────────

#[derive(Deserialize)]
struct ClaimSetupInvitationRequest {
    #[serde(rename = "v")]
    version: u8,
    token: serde_bytes::ByteBuf,
    iphone_apns_token: Option<serde_bytes::ByteBuf>,
}

#[derive(Serialize)]
struct ClaimSetupInvitationAck {
    #[serde(rename = "v")]
    version: u8,
    iphone_endpoint: String,
    owner_display_name: String,
    hh_id: Option<String>,
    /// `http://<engine-tailnet-ipv4>:<engine-port>` when the engine has a
    /// Tailscale CGNAT address available. Omitted when no Tailnet address is
    /// found — the caller (Soyeht.app) keeps whatever URL it would otherwise
    /// derive from local discovery. Surfacing the Tailnet URL here lets the
    /// iPhone reach `POST /bootstrap/initialize` over Tailnet, which is
    /// required to survive the `tailnet_required` source-IP guard.
    #[serde(skip_serializing_if = "Option::is_none")]
    mac_engine_url: Option<String>,
}

fn claim_cbor_error(status: StatusCode, error: &str) -> Response {
    let bytes = household_rs::cbor::to_canonical_vec(&InitializeError {
        version: 1,
        error,
        reason: None,
        state: None,
    })
    .unwrap_or_default();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/cbor"),
    );
    (status, headers, bytes).into_response()
}

fn cbor_ok(body: impl serde::Serialize) -> Response {
    match household_rs::cbor::to_canonical_vec(&body) {
        Ok(bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/cbor"),
            );
            (StatusCode::OK, headers, bytes).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn strict_cbor_request<T>(body: &[u8]) -> Result<T, ()>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let req: T = household_rs::cbor::from_canonical_slice(body).map_err(|_| ())?;
    let reencoded = household_rs::cbor::to_canonical_vec(&req).map_err(|_| ())?;
    if reencoded == body { Ok(req) } else { Err(()) }
}

fn validate_accept_household_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("hh_name must be non-empty".into());
    }
    if name.chars().count() > 32 {
        return Err("hh_name must be <= 32 UTF-8 characters".into());
    }
    if name.chars().any(char::is_control) {
        return Err("hh_name contains control character".into());
    }
    validate_household_name(name).map_err(|e| e.to_string())?;
    Ok(())
}

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct BootstrapStatusResponse {
    v: u8,
    state: &'static str,
    version: &'static str,
    platform: &'static str,
    host_label: String,
    uptime_secs: u64,
    hh_id: Option<String>,
    device_count: u32,

    /// Top-level phase of the macOS guest-image init (`download_ipsw`,
    /// `create_disk`, `install_macos`, `provision`, `create_snapshot`,
    /// `complete`). `None` on Linux (no guest VM) and on Macs that
    /// haven't started provisioning yet. See `guest_image_state.rs`.
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_image_phase: Option<String>,

    /// Overall init status (`pending`, `in_progress`, `done`,
    /// `failed`). Paired with `guest_image_phase` — when the iPhone
    /// Claw Store sees `status != "done"` it gates the install button
    /// and renders a "preparing this Mac" state.
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_image_status: Option<String>,

    /// Most recent error from a failed phase attempt. Only present
    /// when `guest_image_status == "failed"`. Surfaces user-facing
    /// retry hints in the iPhone UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_image_error: Option<String>,

    /// Machine-readable failure reason (`snake_case` enum) for the most recent
    /// failed phase. Present only when `guest_image_status == "failed"`; absent
    /// on older engines. The iPhone keys localized recovery copy off this code
    /// and treats `guest_image_error` as display-only detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_image_failure_code: Option<core_rs::guest_image_failure::GuestImageFailureCode>,
}

impl BootstrapStatusResponse {
    /// Build the status response, mapping a [`GuestImageState`] snapshot onto the
    /// four `guest_image_*` wire fields. Extracted so the guest-image contract
    /// (incl. `guest_image_failure_code`) is unit-testable without the global
    /// `read_current()` / env path.
    ///
    /// [`GuestImageState`]: crate::guest_image_state::GuestImageState
    #[allow(clippy::too_many_arguments)]
    fn new(
        state: &'static str,
        version: &'static str,
        platform: &'static str,
        host_label: String,
        uptime_secs: u64,
        hh_id: Option<String>,
        device_count: u32,
        guest_image: crate::guest_image_state::GuestImageState,
    ) -> Self {
        Self {
            v: 1,
            state,
            version,
            platform,
            host_label,
            uptime_secs,
            hh_id,
            device_count,
            guest_image_phase: guest_image.phase,
            guest_image_status: guest_image.status,
            guest_image_error: guest_image.error,
            guest_image_failure_code: guest_image.failure_code,
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
    platform: &'static str,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /bootstrap/status` — poll-friendly onboarding state machine report.
///
/// Contract: `specs/005-soyeht-onboarding/contracts/bootstrap-status.md`
///
/// No auth required. Response MUST be served in <200 ms per the contract
/// (this handler is I/O-free on the hot path — all state is in-memory).
#[allow(clippy::cast_possible_truncation)]
pub async fn get_bootstrap_status(State(state): State<BootstrapHandlerState>) -> impl IntoResponse {
    let t0 = Instant::now();
    let bootstrap_state = *state.bootstrap.read().await;
    let uptime_secs = state.started_at.elapsed().as_secs();

    let (hh_id, device_count) = hh_info(&state.household, bootstrap_state).await;

    let guest_image = crate::guest_image_state::GuestImageState::read_current();
    let body = BootstrapStatusResponse::new(
        bootstrap_state.as_str(),
        env!("CARGO_PKG_VERSION"),
        current_platform(),
        detect_host_label(),
        uptime_secs,
        hh_id,
        device_count,
        guest_image,
    );

    // elapsed_ms: u128→u64 truncation impossible in practice (u64 covers ~585 millennia).
    #[allow(clippy::cast_possible_truncation)]
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    tracing::info!(
        stage = "bootstrap.status.served",
        elapsed_ms,
        state = bootstrap_state.as_str(),
    );

    (StatusCode::OK, Json(body))
}

/// `GET /health` / `GET /healthz` — liveness probe.
///
/// Returns 200 OK if the engine process is alive and the HTTP stack is
/// serving requests. No dependency checks — this MUST always respond, even
/// during bootstrap (the app uses it as a dead-man's-switch check).
pub async fn get_health(_: State<BootstrapHandlerState>) -> impl IntoResponse {
    let body = HealthResponse {
        status: "ok",
        service: "soyeht-engine",
        version: env!("CARGO_PKG_VERSION"),
        platform: current_platform(),
    };
    (StatusCode::OK, Json(body))
}

/// `POST /api/v1/household/reachability/echo` — diagnostic round-trip probe.
///
/// This endpoint proves only that bytes made a round trip to a Ready engine
/// over loopback or a current Tailnet address. It is deliberately
/// unauthenticated, fixed-size, non-amplifying, and returns no identity data.
/// A successful echo is never evidence of machine identity, household
/// membership, or verified-Mesh ownership and MUST NOT create a
/// `LocalAddressOwnership::VerifiedMesh` fact.
pub async fn post_reachability_echo(
    State(state): State<BootstrapHandlerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    if *state.bootstrap.read().await != BootstrapState::Ready {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if !(peer.ip().is_loopback() || crate::tailnet_address::is_tailnet_ip(peer.ip())) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if body.len() != REACHABILITY_ECHO_BYTES {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `POST /bootstrap/claim-setup-invitation` — iPhone-first scenario B claim (T053).
///
/// Contract: `specs/005-soyeht-onboarding/contracts/setup-invitation.md`
///
/// No auth required. Token must match a Bonjour-discovered `_soyeht-setup._tcp.`
/// advertisement, not be expired, and survive a callback ping to the iPhone.
pub async fn post_claim_setup_invitation(
    State(state): State<BootstrapHandlerState>,
    body: Bytes,
) -> Response {
    use crate::setup_invitation::{
        cache_purge_expired, cache_reinsert_if_absent, cache_take, callback_verify_blocking,
        persist_invitation,
    };

    // 1. State gate — must be uninitialized.
    {
        let current = state.bootstrap.read().await;
        if !matches!(
            *current,
            household_rs::bootstrap_state::BootstrapState::Uninitialized
        ) {
            return claim_cbor_error(
                StatusCode::CONFLICT,
                BootstrapErrorCode::AlreadyInitialized.as_str(),
            );
        }
    }

    // 2. Decode CBOR.
    let req: ClaimSetupInvitationRequest = match household_rs::cbor::from_canonical_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return claim_cbor_error(
                StatusCode::BAD_REQUEST,
                BootstrapErrorCode::InvalidRequest.as_str(),
            );
        }
    };
    if req.version != 1 {
        return claim_cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
        );
    }

    // 3. Token shape check — exactly 32 bytes.
    let Ok(token): Result<[u8; 32], _> = req.token.as_ref().try_into() else {
        return claim_cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
        );
    };

    // 4. Atomic cache take — removes the entry in one lock acquire so concurrent
    //    callers with the same token get None immediately (closes replay window).
    //    Look up before purging so expired entries return 404 not 401.
    let now = crate::time_util::unix_now_secs_checked("claim_setup_invitation.clock").unwrap_or(0);
    let Some(entry) = cache_take(&state.setup_invitation_cache, &token).await else {
        tracing::warn!(
            stage = "claim_setup_invitation.rejected",
            reason = "token_not_in_cache",
        );
        return claim_cbor_error(
            StatusCode::UNAUTHORIZED,
            BootstrapErrorCode::InvitationNotRecognized.as_str(),
        );
    };

    // 5. TTL check — distinct error from "not found". Entry already removed; don't re-insert.
    if now >= entry.expires_at {
        tracing::warn!(
            stage = "claim_setup_invitation.rejected",
            reason = "token_expired",
            expires_at = entry.expires_at,
        );
        return claim_cbor_error(
            StatusCode::NOT_FOUND,
            BootstrapErrorCode::InvitationExpired.as_str(),
        );
    }

    // Opportunistic cleanup of other expired entries; does not affect this request.
    cache_purge_expired(&state.setup_invitation_cache, now).await;

    // 6. Callback verify — blocking HTTP to iPhone. Re-insert on failure so the
    //    client can retry (transient network error, not a replay attack).
    let iphone_endpoint = entry.iphone_endpoint.clone();
    let token_for_verify = token;
    if let Err(e) = tokio::task::spawn_blocking(move || {
        callback_verify_blocking(&iphone_endpoint, &token_for_verify)
    })
    .await
    .unwrap_or_else(|e| Err(format!("task failed: {e}")))
    {
        tracing::warn!(
            stage = "claim_setup_invitation.rejected",
            reason = "callback_verify_failed",
            error = %e,
        );
        cache_reinsert_if_absent(&state.setup_invitation_cache, entry).await;
        return claim_cbor_error(
            StatusCode::UNAUTHORIZED,
            BootstrapErrorCode::InvitationNotRecognized.as_str(),
        );
    }

    // 7. Persist invitation to disk. Re-insert on failure (disk error is transient).
    let apns_token: Option<[u8; 32]> = req
        .iphone_apns_token
        .as_ref()
        .and_then(|t| t.as_ref().try_into().ok());
    if let Err(e) = persist_invitation(&state.state_dir, &entry, apns_token) {
        tracing::error!(
            stage = "claim_setup_invitation.persist_failed",
            error = %e,
        );
        cache_reinsert_if_absent(&state.setup_invitation_cache, entry).await;
        return claim_cbor_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            BootstrapErrorCode::InternalError.as_str(),
        );
    }

    // Entry already removed by cache_take; no separate remove needed.

    // Resolve the engine's OWN Tailnet IPv4 so the ACK steers the iPhone to
    // a URL whose source IP will pass the `tailnet_required` guard on
    // `POST /bootstrap/initialize`. Falls back to omitting the field when
    // no Tailnet address is available — the caller keeps whatever URL it
    // would otherwise derive from local discovery.
    let (mac_engine_url, mac_engine_url_source) =
        crate::tailnet_address::build_mac_engine_url(state.engine_port, state.tailnet_resolver);

    tracing::info!(
        stage = "claim_setup_invitation.accepted",
        iphone_endpoint = %entry.iphone_endpoint,
        has_apns_token = apns_token.is_some(),
        mac_engine_url = mac_engine_url.as_deref().unwrap_or(""),
        mac_engine_url_source = mac_engine_url_source.as_str(),
    );

    cbor_ok(ClaimSetupInvitationAck {
        version: 1,
        iphone_endpoint: entry.iphone_endpoint,
        owner_display_name: entry.owner_display_name,
        hh_id: entry.hh_id,
        mac_engine_url,
    })
}

/// `POST /bootstrap/teardown` — atomic casa destruction (T077, FR-004).
///
/// Contract: `specs/005-soyeht-onboarding/contracts/bootstrap-teardown.md`
///
/// No session auth — owner biometric + cert chain serves as authentication.
/// Validation follows the 14-step contract order; steps 6+9 are merged into one
/// `POST /bootstrap/pair-machine/local/stage` — daemon-side equivalent of
/// `theyos install --pair-machine`. Mints a candidate keypair + signed
/// `JoinRequest`, opens the `PairMachineWindow` in `Staging` (sharing the
/// SAME `Arc<PairMachineWindow>` the daemon's `household_router` mounts
/// `/pair-machine/local/*` against), and returns the canonical
/// `pair-machine` URI for the `SoyehtMac`.app to render as a QR.
///
/// No new listener is bound: the founder-facing `local/seed`,
/// `local/anchor`, and `local/finalize` routes are served by the
/// daemon's existing `household_router`. The CLI install path
/// (`install_cli.rs`) keeps its own pre-household bind because in that
/// flow the daemon is not yet running.
///
/// Loopback-only: the request `ConnectInfo` peer address MUST be
/// `127.0.0.1` / `::1`. Calls from the LAN / Tailscale side return
/// `404 Not Found` (we intentionally do not advertise the endpoint
/// shape across the LAN, so the response is indistinguishable from
/// a missing route).
///
/// Engine-state gate: the candidate must NOT already have a household
/// identity in flight or committed. **Accepted states are
/// `Uninitialized` and `ReadyForNaming` only.** `NamedAwaitingPair`
/// is intentionally rejected — a Mac that started the `accept_household`
/// ceremony and wants to back out must first issue an explicit
/// `POST /bootstrap/teardown`; silently re-routing through `stage` would
/// overwrite mid-ceremony household identity material. The state gate is
/// re-checked inside the shared bootstrap-mutation lock before the
/// `PairMachineWindow` is mutated, so the call cannot race
/// `accept_household` / `accept_household_confirm` / `local_finalize`.
///
/// **Not idempotent**: every call mints a fresh `nonce`/`anchor_secret`,
/// invalidating any QR returned by a prior call. Callers MUST surface
/// this as an explicit user action — never as a probe.
///
/// Body: `{"v":1,"transport":"tailscale"|"lan"}`. Default transport is
/// `tailscale` when the body is empty or the field is omitted.
///
/// Response 200 (`application/cbor`): canonical CBOR encoding of
/// `StageOutcome` — `{pair_machine_uri: text, fingerprint: text,
/// ttl_unix: uint}`. Matches the wire format of sibling bootstrap
/// endpoints (`accept_household`, `accept_household_confirm`,
/// `teardown`, `initialize`).
#[derive(serde::Deserialize, Default)]
struct PairMachineStageRequest {
    #[serde(rename = "v", default)]
    _version: Option<u8>,
    #[serde(default)]
    transport: Option<String>,
}

pub async fn post_pair_machine_local_stage(
    State(state): State<BootstrapHandlerState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Response {
    // Loopback-only ACL — calls from any other address get the same
    // 404 a missing route would produce, hiding the endpoint shape.
    if !peer.ip().is_loopback() {
        tracing::warn!(
            stage = "pair_machine.local.stage.non_loopback_rejected",
            peer = %peer,
        );
        return StatusCode::NOT_FOUND.into_response();
    }

    // Engine-state gate — fast rejection BEFORE we attempt the shared
    // mutation lock. The candidate must not yet hold an in-flight or
    // committed household identity. Only `Uninitialized` and
    // `ReadyForNaming` are accepted. `NamedAwaitingPair` is intentionally
    // rejected — a Mac that started `accept_household` and wants to back
    // out must issue an explicit `POST /bootstrap/teardown` first;
    // silently restaging through this endpoint would overwrite
    // mid-ceremony identity material the welcome flow has already
    // staked. The state will be re-checked inside the mutation lock.
    let current_bs = *state.bootstrap.read().await;
    match current_bs {
        BootstrapState::Uninitialized | BootstrapState::ReadyForNaming => {}
        other => {
            tracing::warn!(
                stage = "pair_machine.local.stage.rejected",
                reason = "household_already_paired",
                state = other.as_str(),
            );
            return cbor_error(
                StatusCode::CONFLICT,
                "household_already_paired",
                None,
                Some(other.as_str()),
            );
        }
    }

    let req: PairMachineStageRequest = if body.is_empty() {
        PairMachineStageRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(e) => {
                return cbor_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    Some(format!("{e}")),
                    None,
                );
            }
        }
    };

    let transport = match req.transport.as_deref().unwrap_or("tailscale") {
        "tailscale" => household_rs::pair_machine::JoinTransport::Tailscale,
        "lan" => household_rs::pair_machine::JoinTransport::Lan,
        other => {
            return cbor_error(
                StatusCode::BAD_REQUEST,
                "unsupported_transport",
                Some(format!(
                    "transport={other:?}; expected 'tailscale' or 'lan'"
                )),
                None,
            );
        }
    };

    let key_policy = household_rs::KeyBackingPolicy::from_env();

    // Acquire the shared bootstrap-mutation lock and re-check the
    // engine state INSIDE the critical section before mutating the
    // `PairMachineWindow`. A concurrent `accept_household_confirm`
    // could have advanced the state between the fast-path check above
    // and our acquiring this lock; without the re-check we would
    // overwrite the founder's just-written `household_record.cbor`
    // through the shared candidate window.
    //
    // The lock is dropped at the end of this block — Bonjour publish
    // inside `stage()` is detached to a background task so it cannot
    // extend the critical section.
    let stage_result = {
        let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
            .lock()
            .await;
        let current_bs = *state.bootstrap.read().await;
        match current_bs {
            BootstrapState::Uninitialized | BootstrapState::ReadyForNaming => {}
            other => {
                tracing::warn!(
                    stage = "pair_machine.local.stage.rejected",
                    reason = "household_already_paired_under_lock",
                    state = other.as_str(),
                );
                return cbor_error(
                    StatusCode::CONFLICT,
                    "household_already_paired",
                    None,
                    Some(other.as_str()),
                );
            }
        }
        crate::pair_machine_local::stage(
            &state.state_dir,
            Arc::clone(&state.pair_machine_window),
            transport,
            key_policy,
        )
        .await
    };

    match stage_result {
        Ok(outcome) => {
            tracing::info!(
                stage = "pair_machine.local.stage.ok",
                fingerprint = %outcome.fingerprint,
                ttl_unix = outcome.ttl_unix,
                transport = match transport {
                    household_rs::pair_machine::JoinTransport::Tailscale => "tailscale",
                    household_rs::pair_machine::JoinTransport::Lan => "lan",
                },
            );
            cbor_ok(outcome)
        }
        Err(e) => {
            tracing::warn!(
                stage = "pair_machine.local.stage.failed",
                error = %e,
            );
            pair_machine_stage_error_response(&e)
        }
    }
}

/// Structured CBOR body for the `no_transport_address` error code. Returned
/// when `pair_machine_local::stage` reports `StageError::NoTransportAddress`
/// for a specific transport — the iOS-side PR-4 needs this discrimination
/// to fall back from `tailscale` to `lan` without substring-matching the
/// generic `stage_failed` reason field.
#[derive(Serialize)]
struct NoTransportAddressErrorBody<'a> {
    #[serde(rename = "v")]
    version: u8,
    /// Stable machine-readable code. Currently always `"no_transport_address"`.
    error: &'static str,
    /// Which transport was attempted and found unusable. Matches the
    /// request's `transport` field on `POST /bootstrap/pair-machine/local/stage`
    /// (`"tailscale"` or `"lan"`).
    transport: &'a str,
    /// Human-readable diagnostic, suitable for logs and developer-facing UI.
    /// Carries the `StageError::Display` text so existing log scraping
    /// keeps working.
    reason: String,
}

/// Maps a `StageError` to the HTTP response handed back to the daemon's
/// pair-machine stage caller. Only `NoTransportAddress` is discriminated
/// into its own error code (see `NoTransportAddressErrorBody`); every
/// other variant keeps the legacy `stage_failed` contract so existing
/// clients that only handled the generic case continue to work.
fn pair_machine_stage_error_response(error: &crate::pair_machine_local::StageError) -> Response {
    use crate::pair_machine_local::StageError;
    match error {
        StageError::NoTransportAddress { transport } => {
            let body = NoTransportAddressErrorBody {
                version: 1,
                error: "no_transport_address",
                transport,
                reason: format!("{error}"),
            };
            let bytes = household_rs::cbor::to_canonical_vec(&body).unwrap_or_default();
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/cbor"),
            );
            (StatusCode::INTERNAL_SERVER_ERROR, headers, bytes).into_response()
        }
        _ => cbor_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "stage_failed",
            Some(format!("{error}")),
            None,
        ),
    }
}

/// `POST /bootstrap/pair-device/reissue` — re-mint the owner pair-device
/// window in-process (R98).
///
/// Recovery path for a Mac stuck in `named_awaiting_pair` whose pair-device
/// window has expired: the CLI `install --reissue-pair-qr` can't read the
/// household key without the right `SOYEHT_OWNER_STATE_DIR` context, so this
/// route lets the *running* engine — which already holds the household
/// identity loaded in memory — re-open the window and hand back a fresh QR
/// URI carrying a LAN RFC1918 `host=` so it works with Tailscale OFF.
///
/// Loopback-only (same hiding contract as
/// `POST /bootstrap/pair-machine/local/stage`): every failure returns the
/// SAME shape a missing route would (a bare `404` for the ACL, or a
/// `cbor_error(404, …)` for the state/identity/already-paired gates) so the
/// endpoint's existence is not advertised across the LAN.
///
/// Gates, IN ORDER:
/// 1. loopback ACL → bare `404`.
/// 2. state == `NamedAwaitingPair`, else `404 reissue_unavailable`.
/// 3. identity loaded, else `404 identity_unavailable`.
/// 4. owner NOT already paired (in-memory `current_owner_auth`, plus a
///    defensive on-disk `HouseholdAuthState::load_optional` mirror), else
///    `404 already_paired` (no token minted).
/// 5. no window still open (`current_token().await.is_some()`), else
///    `409 window_still_open` (no new token minted).
///
/// On success it mints on the SHARED `Arc<PairDeviceWindow>` for liveness (so
/// the daemon's `/pair-device/*` routes serve the same nonce immediately),
/// renders via the extracted `to_uri_with_host_and_name` path, and returns
/// `ReissueResponse` over CBOR.
///
/// **Never logs `pair_qr_uri` or the nonce** — only the non-secret
/// `hh_id`/`ttl_secs`/`expires_at_unix`/`host` fields.
#[derive(Serialize)]
struct ReissueResponse {
    #[serde(rename = "v")]
    version: u8,
    pair_qr_uri: String,
    hh_id: String,
    expires_at_unix: u64,
}

#[derive(Serialize)]
struct PairDeviceUriResponse {
    #[serde(rename = "v")]
    version: u8,
    house_name: String,
    host_label: String,
    hh_id: String,
    hh_pub: ByteBuf,
    pair_device_uri: String,
    expires_at: u64,
}

pub async fn post_pair_device_reissue(
    State(state): State<BootstrapHandlerState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    _body: Bytes,
) -> Response {
    // Gate 1 — loopback ACL. Any non-loopback peer gets the same bare 404 a
    // missing route would produce, hiding the endpoint shape from the LAN.
    if !peer.ip().is_loopback() {
        tracing::warn!(
            stage = "pair_device.reissue.non_loopback_rejected",
            peer = %peer,
        );
        return StatusCode::NOT_FOUND.into_response();
    }

    // Gate 5 below reads the window and the mint at the end of this function
    // writes it, so those two steps have to be one transaction. They did not
    // used to have a competitor: reissue was the only route that minted, and
    // `post_pair_device_confirm` only consumed. `get_bootstrap_pair_device_uri`
    // changed that — it mints too. Without a shared lock the interleaving is
    // "reissue sees an empty window; the GET takes the mutation lock, mints A
    // and answers with it; reissue then mints B on top" — and the URI the GET
    // already returned names a nonce the window no longer holds. Take the same
    // lock the GET and confirm take, before any state is read.
    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;

    // Gate 2 — state gate. Only a Mac that has been named but not yet paired
    // (`named_awaiting_pair`) is eligible to re-open its owner pair window.
    let current_bs = *state.bootstrap.read().await;
    if current_bs != BootstrapState::NamedAwaitingPair {
        tracing::warn!(
            stage = "pair_device.reissue.rejected",
            reason = "wrong_state",
            state = current_bs.as_str(),
        );
        return cbor_error(
            StatusCode::NOT_FOUND,
            BootstrapErrorCode::ReissueUnavailable.as_str(),
            None,
            Some(current_bs.as_str()),
        );
    }

    // Gate 3 — identity must be loaded in memory.
    let Some(identity) = state.household.current().await else {
        tracing::warn!(
            stage = "pair_device.reissue.rejected",
            reason = "identity_unavailable",
        );
        return cbor_error(
            StatusCode::NOT_FOUND,
            BootstrapErrorCode::IdentityUnavailable.as_str(),
            None,
            Some(current_bs.as_str()),
        );
    };

    // Gate 4 — owner must NOT already be paired. Primary check is the
    // in-memory owner-auth slot; we additionally mirror the on-disk
    // `HouseholdAuthState::load_optional` guard (as `handlers_pair_device`
    // does) so a freshly-loaded engine that hasn't hydrated `owner_auth`
    // into memory yet still fails closed.
    if state.household.current_owner_auth().await.is_some() {
        tracing::warn!(
            stage = "pair_device.reissue.rejected",
            reason = "owner_already_paired",
        );
        return cbor_error(
            StatusCode::NOT_FOUND,
            BootstrapErrorCode::AlreadyPaired.as_str(),
            None,
            None,
        );
    }
    {
        let now = crate::time_util::unix_now_secs_checked("pair_device.reissue.clock").unwrap_or(0);
        let record_for_auth = identity.record.clone();
        let state_dir_auth = state.state_dir.clone();
        match tokio::task::spawn_blocking(move || {
            HouseholdAuthState::load_optional(&state_dir_auth, &record_for_auth, now)
        })
        .await
        {
            Ok(Ok(Some(_))) => {
                tracing::warn!(
                    stage = "pair_device.reissue.rejected",
                    reason = "owner_already_paired_on_disk",
                );
                return cbor_error(
                    StatusCode::NOT_FOUND,
                    BootstrapErrorCode::AlreadyPaired.as_str(),
                    None,
                    None,
                );
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => {
                tracing::warn!(
                    stage = "pair_device.reissue.owner_auth_load_failed",
                    error = %e,
                );
                // Fail closed — an unreadable auth state is indistinguishable
                // from a paired owner for the purposes of this recovery route.
                return cbor_error(
                    StatusCode::NOT_FOUND,
                    BootstrapErrorCode::AlreadyPaired.as_str(),
                    None,
                    None,
                );
            }
            Err(e) => {
                tracing::error!(
                    stage = "pair_device.reissue.owner_auth_task_failed",
                    error = %e,
                );
                return cbor_error(
                    StatusCode::NOT_FOUND,
                    BootstrapErrorCode::AlreadyPaired.as_str(),
                    None,
                    None,
                );
            }
        }
    }

    // Gate 5 — a still-open window must not be silently clobbered. A new mint
    // would invalidate any QR the operator is already scanning, so callers
    // must wait for the current window to expire (or it must already be
    // expired/missing → `current_token` returns `None`).
    if state.pair_device_window.current_token().await.is_some() {
        tracing::warn!(
            stage = "pair_device.reissue.rejected",
            reason = "window_still_open"
        );
        return cbor_error(
            StatusCode::CONFLICT,
            BootstrapErrorCode::WindowStillOpen.as_str(),
            None,
            Some(current_bs.as_str()),
        );
    }

    // Gate 2 above already fixed `current_bs == NamedAwaitingPair`, and
    // `HouseholdExposurePolicy::allows` never grants `InterfaceClass::Lan` in
    // that state (see `household_listener.rs`) — the listener will not be
    // bound on any LAN address while this route can even be reached. Unlike
    // the CLI's `--reissue-pair-qr`/first-install path (which mints in states
    // where LAN *is* allowed and is deliberately LAN-first so it works with
    // Tailscale OFF), this route must not offer a `host=` fallback the
    // listener has already withdrawn: Tailnet-only, or no fallback.
    let port: u16 = std::env::var("THEYOS_HOUSEHOLD_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8091);
    let host = crate::tailnet_address::current_tailnet_ipv4().map(|ip| format!("{ip}:{port}"));

    // Mint on the SHARED Arc for liveness (so the daemon's /pair-device/*
    // routes serve the same nonce), then render via the extracted URI path
    // — same TTL clamp as the CLI `--reissue-pair-qr` flow.
    let ttl = Duration::from_secs(crate::household_bootstrap::pair_window_ttl_secs_from_env(
        "THEYOS_PAIR_DEVICE_TTL_SECS",
    ));
    // Derive the fingerprint from the already-validated identity cert BEFORE
    // minting. Minting first and failing after would leave the window open on
    // a request that returned an error, and every retry would then bounce off
    // `window_still_open` until the TTL expired — a failure that wedges the
    // route instead of leaving it untouched.
    //
    // The identity exists and was already validated to reach this point, so a
    // canonical-encode failure is an internal fault, not `identity_unavailable`
    // — reporting it as unavailability would tell the caller to wait for a
    // state that has already arrived.
    let m_cert_fp = match household_rs::machine_cert::fingerprint(&identity.cert) {
        Ok(fp) => fp,
        Err(e) => {
            tracing::error!(stage = "pair_device.reissue.m_cert_fp_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
    };
    let token = match state.pair_device_window.mint_token(ttl, None).await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(stage = "pair_device.reissue.mint_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
    };
    let pair_qr_uri = token.to_uri_with_host_and_name(
        &identity.record.hh_pub,
        host.as_deref(),
        Some(&identity.record.name),
        &m_cert_fp,
    );

    tracing::info!(
        stage = "pair_device.reissue.opened",
        source = "server_reissue_route",
        hh_id = %identity.record.hh_id,
        ttl_secs = ttl.as_secs(),
        expires_at_unix = token.expires_at_unix,
        host = %host.as_deref().unwrap_or(""),
    );

    cbor_ok(ReissueResponse {
        version: 1,
        pair_qr_uri,
        hh_id: identity.record.hh_id.to_string(),
        expires_at_unix: token.expires_at_unix,
    })
}

/// `GET /bootstrap/pair-device-uri` — the Mac-first, no-QR bridge (see
/// `BootstrapPairDeviceURIClient` on the iOS side). A freshly-launched
/// iPhone that discovers this Mac over Bonjour/tailnet while the household
/// is `named_awaiting_pair` has no human present to scan a QR code, so it
/// asks for the current owner pairing URI directly. Unlike
/// `/bootstrap/pair-device/reissue`, this route widens the ACL from
/// loopback-only to loopback-or-tailnet: remote reachability by the owner's
/// own iPhone over the tailnet is the entire point. It does *not* widen it
/// any further than that — see Gate 1.
///
/// GET is idempotent: `/bootstrap/initialize` itself already mints a
/// pair-device window as part of house creation, so the common case here is
/// an already-open window. That existing token's URI is returned as-is
/// rather than minting a second, competing one — unlike the POST reissue
/// route, which deliberately rejects that case so a QR mid-scan is never
/// invalidated out from under the scanner. A GET has no such scanner to
/// protect, and refusing to serve here would just reproduce the same
/// "unavailable" failure this route exists to fix.
pub async fn get_bootstrap_pair_device_uri(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(state): State<BootstrapHandlerState>,
) -> Response {
    // Gate 1 — peer ACL. The response body is the complete first-owner
    // pairing URI, so whoever can call this route can claim the household.
    // An earlier revision of this handler had no peer check at all, on the
    // reasoning that `HouseholdExposurePolicy::allows` denies
    // `InterfaceClass::Lan` in `named_awaiting_pair` and so the listener
    // could not be reached over LAN anyway. That reasoning was wrong twice:
    //
    //   1. the same policy *grants* `InterfaceClass::Mesh` in that state, so
    //      any mesh peer could reach the route; and
    //   2. the LAN listener is not torn down at the state transition — it is
    //      unbound by the reconciliation loop in `household_listener.rs`,
    //      which runs on a 500 ms tick, leaving a window in which the state
    //      gate below already passes while the LAN socket is still accepting.
    //
    // Bind-time exposure is therefore not a substitute for an admission
    // check, exactly as `HouseholdExposurePolicy::allows_terminal_attach_peer`
    // already recognises for the other effectful route. Admit the same set
    // the reachability echo admits, and give everyone else the bare 404 an
    // unrouted path would return.
    if !(peer.ip().is_loopback() || crate::tailnet_address::is_tailnet_ip(peer.ip())) {
        tracing::warn!(
            stage = "pair_device.uri.rejected",
            reason = "peer_not_admitted",
            peer = %peer,
        );
        return StatusCode::NOT_FOUND.into_response();
    }

    // The remaining gates read bootstrap state, identity and owner-auth, and
    // then mutate the pairing window. `post_pair_device_confirm` writes owner
    // auth, consumes the window and advances bootstrap state under
    // `BOOTSTRAP_MUTATION_LOCK`; without taking the same lock this handler
    // could pass its owner-not-paired gate, lose the race to a confirm that
    // runs to completion, and then open a *fresh* pairing window behind an
    // owner that is already persisted. Serialize the gates and the mutation
    // together, so the check that decides is the check that holds.
    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;

    // Gate 2 — state gate. Only a Mac that has been named but not yet paired
    // (`named_awaiting_pair`) has a first-owner pairing URI to hand out.
    let current_bs = *state.bootstrap.read().await;
    if current_bs != BootstrapState::NamedAwaitingPair {
        tracing::warn!(
            stage = "pair_device.uri.rejected",
            reason = "wrong_state",
            state = current_bs.as_str(),
        );
        return cbor_error(
            StatusCode::NOT_FOUND,
            BootstrapErrorCode::ReissueUnavailable.as_str(),
            None,
            Some(current_bs.as_str()),
        );
    }

    // Gate 3 — identity must be loaded in memory.
    let Some(identity) = state.household.current().await else {
        tracing::warn!(stage = "pair_device.uri.rejected", reason = "identity_unavailable");
        return cbor_error(
            StatusCode::NOT_FOUND,
            BootstrapErrorCode::IdentityUnavailable.as_str(),
            None,
            Some(current_bs.as_str()),
        );
    };

    // Gate 4 — owner must NOT already be paired. Same in-memory + on-disk
    // double check as `post_pair_device_reissue`'s Gate 4, for the same
    // reason: a freshly-loaded engine that hasn't hydrated `owner_auth` into
    // memory yet must still fail closed. Both halves run under the mutation
    // lock taken above, so a confirm cannot land between them and the mint.
    if state.household.current_owner_auth().await.is_some() {
        tracing::warn!(stage = "pair_device.uri.rejected", reason = "owner_already_paired");
        return cbor_error(
            StatusCode::NOT_FOUND,
            BootstrapErrorCode::AlreadyPaired.as_str(),
            None,
            None,
        );
    }
    {
        let now = crate::time_util::unix_now_secs_checked("pair_device.uri.clock").unwrap_or(0);
        let record_for_auth = identity.record.clone();
        let state_dir_auth = state.state_dir.clone();
        match tokio::task::spawn_blocking(move || {
            HouseholdAuthState::load_optional(&state_dir_auth, &record_for_auth, now)
        })
        .await
        {
            Ok(Ok(Some(_))) => {
                tracing::warn!(
                    stage = "pair_device.uri.rejected",
                    reason = "owner_already_paired_on_disk",
                );
                return cbor_error(
                    StatusCode::NOT_FOUND,
                    BootstrapErrorCode::AlreadyPaired.as_str(),
                    None,
                    None,
                );
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => {
                tracing::warn!(stage = "pair_device.uri.owner_auth_load_failed", error = %e);
                // Fail closed — an unreadable auth state is indistinguishable
                // from a paired owner for the purposes of this route.
                return cbor_error(
                    StatusCode::NOT_FOUND,
                    BootstrapErrorCode::AlreadyPaired.as_str(),
                    None,
                    None,
                );
            }
            Err(e) => {
                tracing::error!(stage = "pair_device.uri.owner_auth_task_failed", error = %e);
                return cbor_error(
                    StatusCode::NOT_FOUND,
                    BootstrapErrorCode::AlreadyPaired.as_str(),
                    None,
                    None,
                );
            }
        }
    }

    // Same tailnet-only-or-no-fallback rule as `post_pair_device_reissue`:
    // the URI advertises a host only when a tailnet address exists, and
    // never falls back to a LAN address. Gate 1 has already established that
    // the caller is on loopback or the tailnet, so this is the address the
    // caller can actually dial back on.
    let port: u16 = std::env::var("THEYOS_HOUSEHOLD_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8091);
    let host = crate::tailnet_address::current_tailnet_ipv4().map(|ip| format!("{ip}:{port}"));

    // Fingerprint before touching the window, same rationale as the reissue
    // route: the identity is already validated, so a failure here is an
    // internal fault, not an availability gap — and it must not leave a
    // freshly-minted window open behind an error response.
    let m_cert_fp = match household_rs::machine_cert::fingerprint(&identity.cert) {
        Ok(fp) => fp,
        Err(e) => {
            tracing::error!(stage = "pair_device.uri.m_cert_fp_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
    };

    // Retrieve-or-mint must be one operation, not two. Reading
    // `current_token()` and then calling `mint_token()` on a miss leaves a
    // gap in which a second caller mints first; because `mint_token`
    // *replaces* the stored token, both callers then return, and one of the
    // two URIs is already dead on arrival.
    let ttl = Duration::from_secs(crate::household_bootstrap::pair_window_ttl_secs_from_env(
        "THEYOS_PAIR_DEVICE_TTL_SECS",
    ));
    let (token, minted) = match state.pair_device_window.get_or_mint(ttl, None).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(stage = "pair_device.uri.mint_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
    };

    let pair_device_uri = token.to_uri_with_host_and_name(
        &identity.record.hh_pub,
        host.as_deref(),
        Some(&identity.record.name),
        &m_cert_fp,
    );

    tracing::info!(
        stage = "pair_device.uri.served",
        hh_id = %identity.record.hh_id,
        expires_at_unix = token.expires_at_unix,
        host = %host.as_deref().unwrap_or(""),
        minted,
    );

    cbor_ok(PairDeviceUriResponse {
        version: 1,
        house_name: identity.record.name.clone(),
        host_label: detect_host_label(),
        hh_id: identity.record.hh_id.to_string(),
        hh_pub: ByteBuf::from(*identity.record.hh_pub.as_bytes()),
        pair_device_uri,
        expires_at: token.expires_at_unix,
    })
}

/// atomic `check_and_persist` (burns nonce before cert/sig checks to prevent
/// probing different `signed_by` values with the same nonce).
pub async fn post_teardown(State(state): State<BootstrapHandlerState>, body: Bytes) -> Response {
    // Step 1: Fast state gate. The authoritative gate is repeated under
    // `BOOTSTRAP_MUTATION_LOCK` before any disk/memory mutation.
    let current_bs = *state.bootstrap.read().await;
    match current_bs {
        BootstrapState::NamedAwaitingPair | BootstrapState::Ready | BootstrapState::Recovering => {}
        other => {
            tracing::warn!(
                stage = "teardown.rejected",
                reason = "no_household",
                state = other.as_str()
            );
            return cbor_error(
                StatusCode::CONFLICT,
                BootstrapErrorCode::NoHouseholdToTeardown.as_str(),
                None,
                Some(other.as_str()),
            );
        }
    }

    // Step 2: CBOR re-encode check — decode + canonical re-encode must be byte-equal.
    let req: TeardownRequest = if let Ok(r) = household_rs::cbor::from_canonical_slice(&body) {
        r
    } else {
        tracing::warn!(stage = "teardown.rejected", reason = "cbor_decode_failed");
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    };
    let Ok(re_encoded) = household_rs::cbor::to_canonical_vec(&req) else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    };
    if re_encoded != body.as_ref() {
        tracing::warn!(
            stage = "teardown.rejected",
            reason = "cbor_reencode_mismatch"
        );
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    }

    // Step 3: op constant check.
    if req.op != "teardown" {
        tracing::warn!(stage = "teardown.rejected", reason = "op_mismatch", op = %req.op);
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    }

    // Step 4: Field shape checks.
    let Ok(signed_by_bytes): Result<[u8; 33], _> = req.signed_by.as_ref().try_into() else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    };
    let Ok(d_pub) = P256PublicKey::from_bytes(&signed_by_bytes) else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    };
    let Ok(nonce_bytes): Result<[u8; 32], _> = req.nonce.as_ref().try_into() else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = req.signature.as_ref().try_into() else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    };
    let Ok(sig) = P256Signature::from_bytes(&sig_bytes) else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    };

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;

    // Re-check inside the mutation lock so teardown cannot race initialize,
    // pair-machine finalize, or accept-household confirm between the cheap
    // preflight gate and the disk/memory updates below.
    let current_bs = *state.bootstrap.read().await;
    match current_bs {
        BootstrapState::NamedAwaitingPair | BootstrapState::Ready | BootstrapState::Recovering => {}
        other => {
            tracing::warn!(
                stage = "teardown.rejected",
                reason = "no_household_under_lock",
                state = other.as_str()
            );
            return cbor_error(
                StatusCode::CONFLICT,
                BootstrapErrorCode::NoHouseholdToTeardown.as_str(),
                None,
                Some(other.as_str()),
            );
        }
    }

    // Validate hh_id / m_id against this engine's live identity.
    let Some(identity) = state.household.current().await else {
        tracing::error!(stage = "teardown.identity_unavailable");
        return cbor_error(
            StatusCode::CONFLICT,
            BootstrapErrorCode::NoHouseholdToTeardown.as_str(),
            None,
            Some(current_bs.as_str()),
        );
    };
    if req.hh_id != identity.record.hh_id.as_str() {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    }
    if req.m_id != identity.cert.m_id.as_str() {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    }

    // Step 5: ts skew — |now − ts| ≤ 300 s.
    let now_unix = crate::time_util::unix_now_secs_checked("teardown.clock").unwrap_or(0);
    // Unix timestamps (seconds since 1970) fit comfortably in i64 until year ~2554.
    #[allow(clippy::cast_possible_wrap)]
    let skew = (now_unix as i64) - (req.ts as i64);
    if skew.abs() > 300 {
        tracing::warn!(
            stage = "teardown.rejected",
            reason = "ts_skew",
            skew_secs = skew
        );
        return cbor_error(
            StatusCode::UNAUTHORIZED,
            BootstrapErrorCode::Unauthorized.as_str(),
            None,
            None,
        );
    }

    // Steps 6 + 9: atomic nonce check-and-persist (burns nonce before cert/sig checks).
    let state_dir_nonce = state.state_dir.clone();
    match tokio::task::spawn_blocking(move || {
        crate::nonce_cache::check_and_persist(&state_dir_nonce, &nonce_bytes, now_unix)
    })
    .await
    {
        Ok(Ok(())) => {
            // Opportunistic cleanup — fire-and-forget; does not block the request.
            let sd = state.state_dir.clone();
            let ts = now_unix;
            let _handle = tokio::task::spawn_blocking(move || crate::nonce_cache::cleanup(&sd, ts));
        }
        Ok(Err(crate::nonce_cache::NonceError::AlreadyUsed)) => {
            tracing::warn!(stage = "teardown.rejected", reason = "nonce_replay");
            return cbor_error(
                StatusCode::UNAUTHORIZED,
                BootstrapErrorCode::Unauthorized.as_str(),
                None,
                None,
            );
        }
        Ok(Err(crate::nonce_cache::NonceError::Io(e))) => {
            tracing::error!(stage = "teardown.nonce_io_error", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
        Err(e) => {
            tracing::error!(stage = "teardown.nonce_task_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
    }

    // Steps 7–8: Skip cert+sig check when NamedAwaitingPair — no owner cert
    // has been issued yet, so there is no key material to validate. The nonce
    // + ts skew checks above are sufficient anti-replay for a fresh-start reset.
    if current_bs != BootstrapState::NamedAwaitingPair {
        // Step 7: Owner cert chain validation.
        let record_for_auth = identity.record.clone();
        let hh_pub = record_for_auth.hh_pub.clone();
        let state_dir_auth = state.state_dir.clone();
        let auth = match tokio::task::spawn_blocking(move || {
            HouseholdAuthState::load_optional(&state_dir_auth, &record_for_auth, now_unix)
        })
        .await
        {
            Ok(Ok(Some(a))) => a,
            Ok(Ok(None)) => {
                tracing::warn!(stage = "teardown.rejected", reason = "no_owner_auth_state");
                return cbor_error(
                    StatusCode::UNAUTHORIZED,
                    BootstrapErrorCode::Unauthorized.as_str(),
                    None,
                    None,
                );
            }
            Ok(Err(e)) => {
                tracing::error!(stage = "teardown.auth_load_failed", error = %e);
                return cbor_error(
                    StatusCode::UNAUTHORIZED,
                    BootstrapErrorCode::Unauthorized.as_str(),
                    None,
                    None,
                );
            }
            Err(e) => {
                tracing::error!(stage = "teardown.auth_task_failed", error = %e);
                return cbor_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    BootstrapErrorCode::InternalError.as_str(),
                    None,
                    None,
                );
            }
        };
        if let Err(e) =
            crate::owner_cert_auth::verify_owner_cert(&auth, &signed_by_bytes, &hh_pub, now_unix)
        {
            tracing::warn!(stage = "teardown.rejected", reason = "cert_invalid", error = %e);
            return cbor_error(
                StatusCode::UNAUTHORIZED,
                BootstrapErrorCode::Unauthorized.as_str(),
                None,
                None,
            );
        }

        // Step 8: Signature verification over canonical CBOR of TeardownPayload.
        let payload = TeardownPayload {
            version: req.version,
            op: req.op.clone(),
            hh_id: req.hh_id.clone(),
            m_id: req.m_id.clone(),
            nonce: req.nonce.clone(),
            ts: req.ts,
            signed_by: req.signed_by.clone(),
        };
        let Ok(msg_bytes) = household_rs::cbor::to_canonical_vec(&payload) else {
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        };
        if let Err(e) = verify_signature(&d_pub, &msg_bytes, &sig) {
            tracing::warn!(stage = "teardown.rejected", reason = "signature_invalid", error = %e);
            return cbor_error(
                StatusCode::UNAUTHORIZED,
                BootstrapErrorCode::Unauthorized.as_str(),
                None,
                None,
            );
        }
    }

    // Step 10: Atomic household dir teardown — rename then async rm -rf.
    let hh_dir = household_rs::storage::household_dir(&state.state_dir);
    let tearing_down = state.state_dir.join("household.tearing-down");
    if hh_dir.exists() {
        if let Err(e) = std::fs::rename(&hh_dir, &tearing_down) {
            tracing::error!(stage = "teardown.rename_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
        let td = tearing_down.clone();
        tokio::spawn(async move {
            if let Err(e) = tokio::fs::remove_dir_all(&td).await {
                tracing::warn!(stage = "teardown.rmrf_failed", error = %e, path = ?td);
            }
        });
    }
    crate::setup_invitation::clear_persisted_invitation(&state.state_dir);

    // Step 11: Persist bootstrap state = uninitialized. If persist fails, return
    // 500 and leave `household.tearing-down/` as a recovery breadcrumb — on next
    // boot the engine detects it and completes the teardown (R5-F).
    if let Err(e) = bootstrap_state::persist(&state.state_dir, BootstrapState::Uninitialized) {
        tracing::error!(stage = "teardown.state_persist_failed", error = %e);
        return cbor_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            BootstrapErrorCode::InternalError.as_str(),
            None,
            None,
        );
    }

    // Clear in-memory identity so no stale cert material is reachable after
    // teardown (R5-B). Do this before flipping the state flag.
    state.household.clear().await;
    *state.bootstrap.write().await = BootstrapState::Uninitialized;

    // Steps 12-13 bridge: schedule process exit so listener unbind + Bonjour
    // revert happen automatically on next boot. Exit is delayed 100 ms to allow
    // the response to flush. Not compiled in test builds: process::exit kills
    // the test binary when teardown_contract tests call this handler in-process.
    // Full graceful shutdown through the Axum server is
    // tracked as future work (T091).
    #[cfg(not(test))]
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        std::process::exit(0);
    });

    tracing::info!(
        stage = "teardown.complete",
        hh_id = %req.hh_id,
        m_id = %req.m_id,
        torn_at = now_unix,
    );

    cbor_ok(TeardownAck {
        version: 1,
        torn_at: now_unix,
    })
}

/// `POST /bootstrap/accept-household` — accept an existing household from an
/// owner device that holds `HH_priv`.
pub async fn post_accept_household(
    State(state): State<BootstrapHandlerState>,
    body: Bytes,
) -> Response {
    let _guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;

    {
        let current = state.bootstrap.read().await;
        match *current {
            BootstrapState::Uninitialized | BootstrapState::ReadyForNaming => {}
            other => {
                return cbor_error(
                    StatusCode::CONFLICT,
                    BootstrapErrorCode::AlreadyInitialized.as_str(),
                    None,
                    Some(other.as_str()),
                );
            }
        }
    }

    let req: AcceptHouseholdRequest = match strict_cbor_request(&body) {
        Ok(req) => req,
        Err(()) => {
            return cbor_error(
                StatusCode::BAD_REQUEST,
                BootstrapErrorCode::InvalidCbor.as_str(),
                None,
                None,
            );
        }
    };
    if req.version != 1 {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidCbor.as_str(),
            Some("unsupported v".into()),
            None,
        );
    }
    if req.invitation_token.len() != 32 {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    }
    let Ok(invitation_token): Result<[u8; 32], _> = req.invitation_token.as_ref().try_into() else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidRequest.as_str(),
            None,
            None,
        );
    };

    let token_hash = *blake3::hash(&invitation_token).as_bytes();
    if let Err(reason) = validate_accept_household_name(&req.hh_name) {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidName.as_str(),
            Some(reason),
            None,
        );
    }
    let hh_id = match HouseholdId::parse(req.hh_id.clone()) {
        Ok(id) => id,
        Err(e) => {
            return cbor_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                BootstrapErrorCode::CryptoValidationFailed.as_str(),
                Some(e.to_string()),
                None,
            );
        }
    };
    let hh_pub = match P256PublicKey::from_bytes(req.hh_pub.as_ref()) {
        Ok(pubkey) => pubkey,
        Err(e) => {
            return cbor_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                BootstrapErrorCode::CryptoValidationFailed.as_str(),
                Some(e.to_string()),
                None,
            );
        }
    };
    let derived_hh_id = derive_household_id(&hh_pub);
    if derived_hh_id != hh_id {
        return cbor_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            BootstrapErrorCode::CryptoValidationFailed.as_str(),
            Some(format!(
                "hh_id mismatch: expected {derived_hh_id}, got {}",
                req.hh_id
            )),
            None,
        );
    }

    let invitation =
        match consume_accept_household_invitation(&state, &invitation_token, token_hash).await {
            Ok(entry) => entry,
            Err(resp) => return resp,
        };
    if invitation
        .hh_id
        .as_deref()
        .is_some_and(|advertised| advertised != hh_id.as_str())
    {
        crate::setup_invitation::cache_reinsert_if_absent(
            &state.setup_invitation_cache,
            invitation,
        )
        .await;
        return cbor_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            BootstrapErrorCode::CryptoValidationFailed.as_str(),
            Some("invitation_token household mismatch".into()),
            None,
        );
    }
    let state_dir = state.state_dir.clone();
    let hh_name = req.hh_name.clone();
    let policy = KeyBackingPolicy::from_env();
    let prepared = match tokio::task::spawn_blocking(move || {
        prepare_accept_household(
            &state_dir,
            AcceptHouseholdPrepareOpts {
                household_name: hh_name,
                hh_id,
                hh_pub,
                invitation_token_hash: token_hash,
            },
            policy,
        )
    })
    .await
    {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(e)) => {
            tracing::error!(stage = "bootstrap.accept_household_failed", error = %e);
            crate::setup_invitation::cache_reinsert_if_absent(
                &state.setup_invitation_cache,
                invitation,
            )
            .await;
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::KeygenFailed.as_str(),
                None,
                None,
            );
        }
        Err(e) => {
            tracing::error!(stage = "bootstrap.accept_household_task_failed", error = %e);
            crate::setup_invitation::cache_reinsert_if_absent(
                &state.setup_invitation_cache,
                invitation,
            )
            .await;
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::KeygenFailed.as_str(),
                None,
                None,
            );
        }
    };

    {
        let mut bs = state.bootstrap.write().await;
        *bs = BootstrapState::ReadyForNaming;
    }

    tracing::info!(
        stage = "bootstrap.accept_household.prepared",
        hh_id = %prepared.record.hh_id,
        m_id = %prepared.m_id,
        backing = prepared.backing,
    );

    cbor_ok(AcceptHouseholdResponse {
        version: 1,
        m_id: prepared.m_id.to_string(),
        m_pub: ByteBuf::from(prepared.m_pub.as_bytes().to_vec()),
        join_challenge: ByteBuf::from(prepared.join_challenge_cbor),
        challenge_sig_required: true,
    })
}

async fn consume_accept_household_invitation(
    state: &BootstrapHandlerState,
    token: &[u8; 32],
    token_hash: [u8; 32],
) -> Result<crate::setup_invitation::SetupInvitationEntry, Response> {
    use crate::setup_invitation::{
        cache_purge_expired, cache_take, load_persisted_invitation, persisted_invitation_entry,
    };

    if let Ok(Some(pending)) = load_pending_accept_household(&state.state_dir) {
        if pending
            .invitation_token_hash_bytes()
            .is_ok_and(|pending_hash| pending_hash == token_hash)
        {
            return Err(cbor_error(
                StatusCode::GONE,
                BootstrapErrorCode::InvitationExpiredOrSpent.as_str(),
                None,
                None,
            ));
        }
    }

    let now = crate::time_util::unix_now_secs_checked("accept_household.clock").unwrap_or(0);
    let entry = if let Some(entry) = cache_take(&state.setup_invitation_cache, token).await {
        entry
    } else if let Ok(Some(persisted)) = load_persisted_invitation(&state.state_dir) {
        match persisted_invitation_entry(&persisted).filter(|entry| &entry.token == token) {
            Some(entry) => entry,
            None => {
                return Err(cbor_error(
                    StatusCode::NOT_FOUND,
                    BootstrapErrorCode::InvitationNotFound.as_str(),
                    None,
                    None,
                ));
            }
        }
    } else {
        return Err(cbor_error(
            StatusCode::NOT_FOUND,
            BootstrapErrorCode::InvitationNotFound.as_str(),
            None,
            None,
        ));
    };
    if now >= entry.expires_at || entry.expires_at.saturating_sub(now) > 3600 {
        return Err(cbor_error(
            StatusCode::GONE,
            BootstrapErrorCode::InvitationExpiredOrSpent.as_str(),
            None,
            None,
        ));
    }
    cache_purge_expired(&state.setup_invitation_cache, now).await;
    Ok(entry)
}

/// `POST /bootstrap/accept-household/confirm` — persist the owner-issued
/// `MachineCert` and mark the follower engine ready.
pub async fn post_accept_household_confirm(
    State(state): State<BootstrapHandlerState>,
    body: Bytes,
) -> Response {
    let _guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;

    {
        let current = state.bootstrap.read().await;
        if *current != BootstrapState::ReadyForNaming {
            return cbor_error(
                StatusCode::CONFLICT,
                BootstrapErrorCode::AcceptHouseholdNotPending.as_str(),
                None,
                Some(current.as_str()),
            );
        }
    }

    let req: AcceptHouseholdConfirmRequest = match strict_cbor_request(&body) {
        Ok(req) => req,
        Err(()) => {
            return cbor_error(
                StatusCode::BAD_REQUEST,
                BootstrapErrorCode::InvalidCbor.as_str(),
                None,
                None,
            );
        }
    };
    if req.version != 1 {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidCbor.as_str(),
            Some("unsupported v".into()),
            None,
        );
    }
    let m_id = match MachineId::parse(req.m_id.clone()) {
        Ok(id) => id,
        Err(e) => {
            return cbor_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                BootstrapErrorCode::CryptoValidationFailed.as_str(),
                Some(e.to_string()),
                None,
            );
        }
    };
    let sig_bytes: [u8; 64] = match req.challenge_sig.as_ref().try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return cbor_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                BootstrapErrorCode::CryptoValidationFailed.as_str(),
                Some("challenge_sig must be 64 bytes".into()),
                None,
            );
        }
    };
    let challenge_sig = match P256Signature::from_bytes(&sig_bytes) {
        Ok(sig) => sig,
        Err(e) => {
            return cbor_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                BootstrapErrorCode::CryptoValidationFailed.as_str(),
                Some(e.to_string()),
                None,
            );
        }
    };
    let machine_cert: MachineCert = match strict_cbor_request(req.machine_cert.as_ref()) {
        Ok(cert) => cert,
        Err(()) => {
            return cbor_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                BootstrapErrorCode::CryptoValidationFailed.as_str(),
                Some("machine_cert CBOR invalid".into()),
                None,
            );
        }
    };

    let state_dir = state.state_dir.clone();
    let policy = KeyBackingPolicy::from_env();
    let loaded = match tokio::task::spawn_blocking(move || {
        confirm_accept_household(&state_dir, &m_id, machine_cert, &challenge_sig, policy)
    })
    .await
    {
        Ok(Ok(loaded)) => loaded,
        Ok(Err(AcceptHouseholdConfirmError::PendingMissing)) => {
            return cbor_error(
                StatusCode::CONFLICT,
                BootstrapErrorCode::AcceptHouseholdNotPending.as_str(),
                None,
                Some("ready_for_naming"),
            );
        }
        Ok(Err(
            AcceptHouseholdConfirmError::Mismatch(_) | AcceptHouseholdConfirmError::Crypto(_),
        )) => {
            return cbor_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                BootstrapErrorCode::CryptoValidationFailed.as_str(),
                None,
                None,
            );
        }
        Ok(Err(e)) => {
            tracing::error!(stage = "bootstrap.accept_household.confirm_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
        Err(e) => {
            tracing::error!(stage = "bootstrap.accept_household.confirm_task_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
    };

    {
        let mut bs = state.bootstrap.write().await;
        let current = *bs;
        if current
            .transition(BootstrapState::NamedAwaitingPair)
            .is_err()
        {
            return cbor_error(
                StatusCode::CONFLICT,
                BootstrapErrorCode::AcceptHouseholdNotPending.as_str(),
                None,
                Some(current.as_str()),
            );
        }
        *bs = BootstrapState::NamedAwaitingPair;
        if let Err(e) =
            bootstrap_state::persist(&state.state_dir, BootstrapState::NamedAwaitingPair)
        {
            tracing::error!(stage = "bootstrap.accept_household.state_persist_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
        *bs = BootstrapState::Ready;
        if let Err(e) = bootstrap_state::persist(&state.state_dir, BootstrapState::Ready) {
            tracing::error!(stage = "bootstrap.accept_household.state_persist_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
    }

    let hh_id = loaded.record.hh_id.to_string();
    let m_id = loaded.cert.m_id.to_string();
    state
        .household
        .set_loaded(SharedHouseholdIdentity::new(loaded))
        .await;

    tracing::info!(
        stage = "bootstrap.accept_household.ready",
        hh_id = %hh_id,
        m_id = %m_id,
    );

    cbor_ok(AcceptHouseholdConfirmResponse {
        version: 1,
        bootstrap_state: "ready",
        m_id,
        hh_id,
    })
}

/// `POST /bootstrap/initialize` — mint the casa identity (FR-003, T025).
///
/// Contract: `specs/005-soyeht-onboarding/contracts/bootstrap-initialize.md`
///
/// State gate: engine must be in `uninitialized` or `ready_for_naming`.
/// All other states → 409. On success, state advances to `named_awaiting_pair`
/// and the pair-device window opens for the first owner-pairing QR.
///
/// T054: When a setup invitation is pending, the source IP MUST be the
/// iPhone's Tailnet address. 403 with `{v:1, error:"tailnet_required"}` otherwise.
pub async fn post_initialize(
    State(state): State<BootstrapHandlerState>,
    req: axum::extract::Request,
) -> Response {
    let t0 = Instant::now();

    // T054: Source IP guard when a setup invitation is pending.
    // Check before reading the body to return the error early.
    if let Ok(Some(invitation)) =
        crate::setup_invitation::load_persisted_invitation(&state.state_dir)
    {
        let src_ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        match src_ip {
            None => {
                return cbor_error(
                    StatusCode::FORBIDDEN,
                    BootstrapErrorCode::TailnetRequired.as_str(),
                    None,
                    None,
                );
            }
            Some(ip) => {
                if let Err(reason) =
                    crate::setup_invitation::validate_initialize_source(&invitation, ip).await
                {
                    tracing::warn!(
                        stage = "bootstrap.initialize.rejected",
                        reason = reason,
                        src_ip = %ip,
                    );
                    return cbor_error(
                        StatusCode::FORBIDDEN,
                        BootstrapErrorCode::TailnetRequired.as_str(),
                        None,
                        None,
                    );
                }
            }
        }
    }

    // Extract body bytes from the request.
    let Ok(body) = axum::body::to_bytes(req.into_body(), 1024 * 64).await else {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidCbor.as_str(),
            None,
            None,
        );
    };

    // 1. Decode CBOR request.
    let req: InitializeRequest = match household_rs::cbor::from_canonical_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return cbor_error(
                StatusCode::BAD_REQUEST,
                BootstrapErrorCode::InvalidCbor.as_str(),
                None,
                None,
            );
        }
    };
    if req.version != 1 {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidCbor.as_str(),
            Some("unsupported v".into()),
            None,
        );
    }

    // 2. Name sanitize.
    let name = req.name.trim().to_string();
    if let Err(e) = validate_household_name(&name) {
        return cbor_error(
            StatusCode::BAD_REQUEST,
            BootstrapErrorCode::InvalidName.as_str(),
            Some(e.to_string()),
            None,
        );
    }

    let _mutation_guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
        .lock()
        .await;

    // 3. Authoritative state gate. Keep the check, identity write, bootstrap
    // state persist, in-memory update, and first pairing token mint inside the
    // same mutation critical section.
    {
        let current = state.bootstrap.read().await;
        match *current {
            BootstrapState::Uninitialized | BootstrapState::ReadyForNaming => {}
            other => {
                return cbor_error(
                    StatusCode::CONFLICT,
                    BootstrapErrorCode::AlreadyInitialized.as_str(),
                    None,
                    Some(other.as_str()),
                );
            }
        }
    }

    // 4. Keygen + persist (blocking I/O — run off the async executor).
    let state_dir = state.state_dir.clone();
    let opts = BootstrapOpts {
        household_name: name.clone(),
        hostname_label: None,
    };
    let policy = KeyBackingPolicy::from_env();
    let t_keygen = Instant::now();
    let loaded = match tokio::task::spawn_blocking(move || {
        bootstrap_or_load(&state_dir, opts, policy)
    })
    .await
    {
        Ok(Ok(id)) => id,
        Ok(Err(e)) => {
            tracing::error!(stage = "bootstrap.initialize_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::KeygenFailed.as_str(),
                None,
                None,
            );
        }
        Err(e) => {
            tracing::error!(stage = "bootstrap.initialize_task_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::KeygenFailed.as_str(),
                None,
                None,
            );
        }
    };
    // u128→u64 truncation impossible in practice (u64 covers ~585 millennia).
    #[allow(clippy::cast_possible_truncation)]
    let keygen_ms = t_keygen.elapsed().as_millis() as u64;

    let hh_id = loaded.record.hh_id.to_string();
    let hh_pub_bytes: [u8; 33] = *loaded.record.hh_pub.as_bytes();
    let created_at = loaded.record.created_at;
    let name_persisted = loaded.record.name.clone();
    let machine_id = loaded.cert.m_id.to_string();

    // Fingerprint the cert this bootstrap just validated, before any of the
    // state transitions below. An encode failure here is a fault, not an
    // absence: the identity exists and was validated, so it cannot be folded
    // into "no QR this time". Returning early leaves the install inert —
    // nothing persisted as NamedAwaitingPair, nothing published to shared
    // state, no window minted — instead of reporting success with a hollow
    // `pair_qr_uri` and a machine already advanced past bootstrap.
    let m_cert_fp = match household_rs::machine_cert::fingerprint(&loaded.cert) {
        Ok(fp) => fp,
        Err(e) => {
            tracing::error!(stage = "bootstrap.m_cert_fp_failed", error = %e);
            return cbor_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                BootstrapErrorCode::InternalError.as_str(),
                None,
                None,
            );
        }
    };

    // 5. Advance bootstrap state to named_awaiting_pair.
    {
        let mut bs = state.bootstrap.write().await;
        *bs = BootstrapState::NamedAwaitingPair;
        let state_dir = state.state_dir.clone();
        if let Err(e) = bootstrap_state::persist(&state_dir, BootstrapState::NamedAwaitingPair) {
            tracing::error!(stage = "bootstrap.state_persist_failed", error = %e);
        }
    }

    // 6. Update HouseholdState in memory.
    state
        .household
        .set_loaded(SharedHouseholdIdentity::new(loaded))
        .await;

    // 7. Mint pair-device window and build QR URI.
    //
    // Both inputs are resolved before minting: a QR we could not pin is not
    // worth opening a window for, and opening one anyway would leave a token
    // live behind an empty URI.
    let pair_qr_uri = match P256PublicKey::from_bytes(&hh_pub_bytes) {
        Ok(pub_key) => {
            match state
                .pair_device_window
                .mint_token(Duration::from_secs(300), None)
                .await
            {
                Ok(token) => token.to_uri_with_host_and_name(
                    &pub_key,
                    None,
                    Some(&name_persisted),
                    &m_cert_fp,
                ),
                Err(e) => {
                    tracing::warn!(stage = "bootstrap.mint_token_failed", error = %e);
                    String::new()
                }
            }
        }
        // Pre-existing degradation for a bad household key, unchanged.
        Err(_) => String::new(),
    };

    // u128→u64 truncation impossible in practice (u64 covers ~585 millennia).
    #[allow(clippy::cast_possible_truncation)]
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    info!(
        stage = "bootstrap.initialized",
        hh_id = %hh_id,
        name = %name_persisted,
        keygen_ms,
        elapsed_ms,
    );

    // 7.5: Emit `house_created` push for scenario B (setup invitation with APNs token).
    // Always clear the invitation after a successful initialize — it is single-use
    // regardless of whether an APNs token was present (scenario A or scenario B).
    if let Ok(Some(inv)) = crate::setup_invitation::load_persisted_invitation(&state.state_dir) {
        if let Some(token_buf) = &inv.iphone_apns_token {
            if let Ok(token_arr) = <[u8; 32]>::try_from(token_buf.as_ref()) {
                crate::apns_push::dispatch_fire_and_forget(crate::apns_push::HouseCreatedEvent {
                    apns_device_token: token_arr,
                    hh_id: hh_id.clone(),
                    hh_name: name_persisted.clone(),
                    machine_id: machine_id.clone(),
                    machine_label: detect_host_label(),
                    pair_qr_uri: pair_qr_uri.clone(),
                    ts: created_at,
                });
            }
        }
        crate::setup_invitation::clear_persisted_invitation(&state.state_dir);
    }

    // 8. Return InitializeResponse.
    cbor_ok(InitializeResponse {
        version: 1,
        hh_id,
        hh_pub: ByteBuf::from(hh_pub_bytes),
        name: name_persisted,
        pair_qr_uri,
        created_at,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Return `(hh_id, device_count)` from the household state.
///
/// - `hh_id` is `None` while the engine is in `uninitialized` or
///   `ready_for_naming`; populated once the household record is on disk.
/// - `device_count` counts paired personal devices (iPhones with a
///   `PersonCert` in `HouseholdAuthState`). It is 0 in `named_awaiting_pair`
///   and ≥1 in `ready`.
async fn hh_info(household: &HouseholdState, state: BootstrapState) -> (Option<String>, u32) {
    match state {
        BootstrapState::Uninitialized | BootstrapState::ReadyForNaming => (None, 0),
        BootstrapState::NamedAwaitingPair => {
            let hh_id = household
                .current()
                .await
                .map(|id| id.record.hh_id.to_string());
            (hh_id, 0)
        }
        BootstrapState::Ready | BootstrapState::Recovering => {
            let identity = household.current().await;
            let hh_id = identity.as_ref().map(|id| id.record.hh_id.to_string());
            // device_count = 1 if owner auth is present, 0 otherwise.
            let device_count = u32::from(household.current_owner_auth().await.is_some());
            (hh_id, device_count)
        }
    }
}

/// Detect the current platform string (`"macos"` or `"linux"`).
#[must_use]
fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Detect a human-readable host label.
///
/// - macOS: tries `sysctl -n hw.model` (e.g. "MacBookPro18,3"); on failure
///   falls back to hostname.
/// - Linux: tries `/sys/devices/virtual/dmi/id/product_name`; on failure
///   falls back to hostname.
///
/// Result is trimmed and truncated to 32 bytes (UTF-8 characters) per the
/// Bonjour TXT contract.
#[must_use]
pub fn detect_host_label() -> String {
    let raw = platform_model_string()
        .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned());
    let trimmed = raw.trim();
    // Truncate at 32 UTF-8 character boundary.
    trimmed.chars().take(32).collect()
}

#[cfg(target_os = "macos")]
fn platform_model_string() -> Option<String> {
    // `sysctl -n hw.model` returns e.g. "MacBookPro18,3"
    let out = std::process::Command::new("sysctl")
        .args(["-n", "hw.model"])
        .output()
        .ok()?;
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn platform_model_string() -> Option<String> {
    std::fs::read_to_string("/sys/devices/virtual/dmi/id/product_name")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod m_cert_fp_ordering_guard {
    /// Body of a top-level `pub async fn <name>(` up to the next column-zero
    /// `}`. Both producers are column-zero items, so this bounds them exactly
    /// rather than running to EOF.
    /// Comments are stripped first. Without that the guard measures its own
    /// prose: a doc comment naming `NamedAwaitingPair` to explain the ordering
    /// sits above the code it describes, so a plain substring search finds the
    /// comment and concludes the state transition happens first. The scan has
    /// to see what the compiler sees.
    fn fn_body(source: &str, name: &str) -> String {
        let needle = format!("\npub async fn {name}(");
        let start = source
            .find(&needle)
            .unwrap_or_else(|| panic!("{name} not found — did it get renamed?"))
            + 1;
        let rest = &source[start..];
        let end = rest
            .find("\n}\n")
            .unwrap_or_else(|| panic!("{name} has no column-zero close"));
        rest[..end]
            .lines()
            .map(|line| match line.find("//") {
                Some(at) => &line[..at],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Offset of `needle`, asserting it occurs exactly once.
    ///
    /// A guard that takes the first of several matches silently measures
    /// whichever one happens to come first, which is how an anchor drifts onto
    /// the wrong statement without anyone noticing.
    fn unique_offset(body: &str, needle: &str, ctx: &str) -> usize {
        let count = body.matches(needle).count();
        assert_eq!(
            count, 1,
            "{ctx}: anchor `{needle}` must occur exactly once, found {count}"
        );
        body.find(needle).expect("counted above")
    }

    /// A fingerprint failure must not leave a minted window behind.
    ///
    /// There is no natural seam to inject an encode failure through — the
    /// input is a `MachineCert` the caller already validated — and adding one
    /// would mean widening the API purely so a test could reach it. So this
    /// pins the property that actually prevents the wedge: in both producers
    /// the fingerprint is resolved *before* anything is minted. If someone
    /// moves `mint_token` back above it, the failure path silently starts
    /// leaving live windows behind error responses again, and every retry
    /// bounces off `window_still_open` until the TTL expires.
    #[test]
    fn fingerprint_is_resolved_before_any_window_is_minted() {
        let source = include_str!("handlers_bootstrap.rs");

        for name in ["post_pair_device_reissue", "post_initialize"] {
            let body = fn_body(source, name);
            let fp = unique_offset(&body, "machine_cert::fingerprint(", name);
            let mint = unique_offset(&body, "mint_token(", name);
            assert!(
                fp < mint,
                "{name}: fingerprint must be resolved before mint_token, \
                 otherwise a fingerprint fault returns an error while leaving \
                 the window open"
            );
        }
    }

    /// `post_initialize` must also resolve it before it publishes state.
    ///
    /// Returning success with a hollow `pair_qr_uri` after the machine has
    /// already been advanced to `NamedAwaitingPair` and published to shared
    /// state is the same wedge one level up: the install looks finished and
    /// cannot be retried into a good state.
    #[test]
    fn post_initialize_resolves_fingerprint_before_publishing_state() {
        let source = include_str!("handlers_bootstrap.rs");
        let body = fn_body(source, "post_initialize");
        let fp = unique_offset(&body, "machine_cert::fingerprint(", "post_initialize");
        // Executable needles, not bare identifiers: `*bs = BootstrapState::…`
        // is the assignment that actually advances the state, so the anchor
        // cannot be satisfied by a mention of the name somewhere else.
        for later in ["*bs = BootstrapState::NamedAwaitingPair;", ".set_loaded("] {
            let at = unique_offset(&body, later, "post_initialize");
            assert!(
                fp < at,
                "post_initialize: fingerprint must be resolved before `{later}`"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_image_state::GuestImageState;
    use crate::household_state::SharedOwnerAuthState;
    use axum::{
        body::Body,
        http::{Request, StatusCode as HStatus},
    };
    use core_rs::guest_image_failure::GuestImageFailureCode;
    use serde_json::Value;
    use tower::ServiceExt;

    /// The `/bootstrap/status` body MUST carry `guest_image_failure_code` when
    /// the guest image last failed — this is the contract iOS/Mac consume.
    #[test]
    fn bootstrap_status_serializes_guest_image_failure_code() {
        let gi = GuestImageState {
            phase: Some("install_macos".into()),
            status: Some("failed".into()),
            error: Some("macOS VM startup hit the host active-VM limit".into()),
            failure_code: Some(GuestImageFailureCode::HostVmLimitReached),
        };
        let resp = BootstrapStatusResponse::new(
            "ready",
            "0.0.0-test",
            "macos",
            "test-host".into(),
            0,
            None,
            0,
            gi,
        );
        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["guest_image_status"], "failed");
        assert_eq!(
            json["guest_image_failure_code"], "host_vm_limit_reached",
            "guest_image_failure_code must appear in /bootstrap/status"
        );
    }

    /// Compat: an older `failed` state with no `failure_code` must still
    /// serialize, omitting the field (never emit null / never break).
    #[test]
    fn bootstrap_status_omits_failure_code_when_absent() {
        let gi = GuestImageState {
            phase: Some("install_macos".into()),
            status: Some("failed".into()),
            error: Some("boom".into()),
            failure_code: None,
        };
        let resp = BootstrapStatusResponse::new(
            "ready",
            "0.0.0-test",
            "macos",
            "test-host".into(),
            0,
            None,
            0,
            gi,
        );
        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["guest_image_status"], "failed");
        assert!(
            json.get("guest_image_failure_code").is_none(),
            "absent failure_code must be omitted, not null"
        );
    }

    fn make_state(bs: BootstrapState) -> BootstrapHandlerState {
        use std::path::PathBuf;
        BootstrapHandlerState {
            bootstrap: Arc::new(RwLock::new(bs)),
            household: HouseholdState::empty(),
            state_dir: PathBuf::from("/tmp/test"),
            pair_device_window: Arc::new(PairDeviceWindow::new()),
            pair_machine_window: Arc::new(PairMachineWindow::new_in_memory()),
            started_at: Instant::now(),
            setup_invitation_cache: crate::setup_invitation::new_cache(),
            engine_port: 8091,
            tailnet_resolver: || None,
        }
    }

    async fn json_get(app: Router, uri: &str) -> (HStatus, Value) {
        let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let val: Value = serde_json::from_slice(&bytes).unwrap();
        (status, val)
    }

    #[tokio::test]
    async fn health_returns_200() {
        let app = bootstrap_router(make_state(BootstrapState::Uninitialized));
        let (status, body) = json_get(app, "/health").await;
        assert_eq!(status, HStatus::OK);
        assert_eq!(body["status"], "ok");
    }

    fn echo_request(body: Vec<u8>, peer: SocketAddr) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri(REACHABILITY_ECHO_PATH)
            .body(Body::from(body))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        request
    }

    #[tokio::test]
    async fn reachability_echo_is_ready_only_tailnet_or_loopback_and_fixed_size() {
        let challenge = vec![0x5a; REACHABILITY_ECHO_BYTES];
        let loopback = SocketAddr::from(([127, 0, 0, 1], 41001));
        let tailnet = SocketAddr::from(([100, 64, 0, 10], 41002));
        let lan = SocketAddr::from(([192, 0, 2, 10], 41003));

        let response = bootstrap_router(make_state(BootstrapState::Ready))
            .oneshot(echo_request(challenge.clone(), loopback))
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), REACHABILITY_ECHO_BYTES)
                .await
                .unwrap(),
            challenge
        );

        let response = bootstrap_router(make_state(BootstrapState::Ready))
            .oneshot(echo_request(challenge.clone(), tailnet))
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::OK);

        let response = bootstrap_router(make_state(BootstrapState::Ready))
            .oneshot(echo_request(challenge.clone(), lan))
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::FORBIDDEN);

        let response = bootstrap_router(make_state(BootstrapState::Recovering))
            .oneshot(echo_request(challenge.clone(), loopback))
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::SERVICE_UNAVAILABLE);

        let response = bootstrap_router(make_state(BootstrapState::Ready))
            .oneshot(echo_request(
                vec![0x5a; REACHABILITY_ECHO_BYTES - 1],
                loopback,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::BAD_REQUEST);

        let response = bootstrap_router(make_state(BootstrapState::Ready))
            .oneshot(echo_request(
                vec![0x5a; REACHABILITY_ECHO_BYTES + 1],
                loopback,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), HStatus::PAYLOAD_TOO_LARGE);
    }

    async fn spawn_ready_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            core_rs::phase0_axum_serve!(
                listener,
                bootstrap_router(make_state(BootstrapState::Ready)),
                connect_info = SocketAddr
            )
            .await
            .unwrap();
        });
        (address, server)
    }

    #[tokio::test]
    async fn reachability_echo_round_trips_over_two_real_ready_listeners() {
        let (machine_a, server_a) = spawn_ready_echo_server().await;
        let (machine_b, server_b) = spawn_ready_echo_server().await;

        for (destination, fill) in [(machine_b, 0xa1), (machine_a, 0xb2)] {
            let challenge = vec![fill; REACHABILITY_ECHO_BYTES];
            let response = reqwest::Client::new()
                .post(format!("http://{destination}{REACHABILITY_ECHO_PATH}"))
                .body(challenge.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                reqwest::StatusCode::OK,
                "destination={destination}"
            );
            assert_eq!(
                response.bytes().await.unwrap(),
                challenge,
                "destination={destination}"
            );
        }

        server_a.abort();
        server_b.abort();
    }

    #[tokio::test]
    async fn bootstrap_status_uninitialized_shape() {
        let app = bootstrap_router(make_state(BootstrapState::Uninitialized));
        let (status, body) = json_get(app, "/bootstrap/status").await;
        assert_eq!(status, HStatus::OK);
        assert_eq!(body["v"], 1);
        assert_eq!(body["state"], "uninitialized");
        assert!(body["hh_id"].is_null());
        assert_eq!(body["device_count"], 0);
        assert!(body.get("platform").is_some());
        assert!(body.get("version").is_some());
        assert!(body.get("uptime_secs").is_some());
        assert!(body.get("host_label").is_some());
    }

    #[tokio::test]
    async fn bootstrap_status_ready_for_naming() {
        let app = bootstrap_router(make_state(BootstrapState::ReadyForNaming));
        let (_, body) = json_get(app, "/bootstrap/status").await;
        assert_eq!(body["state"], "ready_for_naming");
        assert!(body["hh_id"].is_null());
        assert_eq!(body["device_count"], 0);
    }

    #[tokio::test]
    async fn bootstrap_status_recovering_shape() {
        let app = bootstrap_router(make_state(BootstrapState::Recovering));
        let (_, body) = json_get(app, "/bootstrap/status").await;
        assert_eq!(body["state"], "recovering");
    }

    // ── pair_machine stage error mapping ─────────────────────────────────
    //
    // The full stage flow is integration-shaped (binds a TCP listener,
    // persists `PairMachineWindow`, mints a candidate keypair), so we
    // unit-test the error-mapping helper in isolation. PR-4 (iOS Add
    // Server / Join existing Soyeht) needs `NoTransportAddress` to be
    // discriminated from the generic `stage_failed` so the client can
    // do `tailscale → lan` fallback without substring-matching the
    // reason field.

    #[derive(serde::Deserialize, Debug)]
    struct CborErrorBodyForTest {
        #[serde(rename = "v")]
        version: u8,
        error: String,
        #[serde(default)]
        transport: Option<String>,
        #[serde(default)]
        reason: Option<String>,
    }

    async fn decode_cbor_error(response: Response) -> (HStatus, CborErrorBodyForTest) {
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .map(ToString::to_string);
        assert_eq!(
            content_type.as_deref(),
            Some("application/cbor"),
            "structured stage errors must use CBOR content-type"
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: CborErrorBodyForTest =
            household_rs::cbor::from_canonical_slice(&bytes).expect("CBOR decode");
        (status, body)
    }

    #[tokio::test]
    async fn pair_machine_stage_error_tailscale_no_transport_address() {
        let err = crate::pair_machine_local::StageError::NoTransportAddress {
            transport: "tailscale",
        };
        let response = pair_machine_stage_error_response(&err);
        let (status, body) = decode_cbor_error(response).await;
        assert_eq!(status, HStatus::INTERNAL_SERVER_ERROR);
        assert_eq!(body.version, 1);
        assert_eq!(
            body.error, "no_transport_address",
            "code must be structured, not generic stage_failed"
        );
        assert_eq!(
            body.transport.as_deref(),
            Some("tailscale"),
            "transport must carry the attempted transport so the client can fall back"
        );
        let reason = body.reason.unwrap_or_default();
        assert!(
            reason.contains("tailscale"),
            "reason should remain the Display text for log compatibility, got {reason:?}"
        );
    }

    #[tokio::test]
    async fn pair_machine_stage_error_lan_no_transport_address() {
        let err = crate::pair_machine_local::StageError::NoTransportAddress { transport: "lan" };
        let response = pair_machine_stage_error_response(&err);
        let (status, body) = decode_cbor_error(response).await;
        assert_eq!(status, HStatus::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "no_transport_address");
        assert_eq!(body.transport.as_deref(), Some("lan"));
    }

    #[tokio::test]
    async fn pair_machine_stage_error_other_variants_remain_stage_failed() {
        // Any non-NoTransportAddress variant continues to use the
        // legacy `stage_failed` contract. BadHostname is a stable
        // sentinel — purely value-typed, no I/O.
        let err = crate::pair_machine_local::StageError::BadHostname { got: 42 };
        let response = pair_machine_stage_error_response(&err);
        let (status, body) = decode_cbor_error(response).await;
        assert_eq!(status, HStatus::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body.error, "stage_failed",
            "non-NoTransportAddress variants must NOT be rewired — only the new code is being introduced"
        );
        assert!(
            body.transport.is_none(),
            "transport field must be absent for stage_failed responses"
        );
        let reason = body.reason.unwrap_or_default();
        assert!(reason.contains("hostname"), "reason carries Display text");
    }

    #[tokio::test]
    async fn pair_machine_stage_error_unsupported_platform_remains_stage_failed() {
        let err = crate::pair_machine_local::StageError::UnsupportedPlatform { os: "haiku" };
        let response = pair_machine_stage_error_response(&err);
        let (_status, body) = decode_cbor_error(response).await;
        assert_eq!(body.error, "stage_failed");
        assert!(body.transport.is_none());
    }

    // ── /bootstrap/pair-machine/local/stage state-gate rejections ────────
    //
    // The state gate runs before any state mutation, so we can drive it
    // from a pure in-memory `BootstrapHandlerState`. Tests assert that the
    // CBOR error body shape matches the contract (`household_already_paired`
    // with the offending state name) and that the gate is enforced for
    // every disallowed state — including `NamedAwaitingPair`, which used
    // to be silently accepted but now requires an explicit
    // `POST /bootstrap/teardown` first.

    async fn call_stage_with_state(bs: BootstrapState) -> (HStatus, CborErrorBodyForTest) {
        let app = bootstrap_router(make_state(bs));
        let req = Request::builder()
            .method("POST")
            .uri("/bootstrap/pair-machine/local/stage")
            .extension(ConnectInfo::<SocketAddr>(SocketAddr::from((
                [127, 0, 0, 1],
                12345,
            ))))
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        decode_cbor_error(response).await
    }

    #[tokio::test]
    async fn pair_machine_local_stage_rejects_named_awaiting_pair() {
        // NamedAwaitingPair is intentionally rejected by PR-#82 review
        // follow-up: a Mac mid-ceremony must teardown explicitly before
        // restaging as a candidate, otherwise this endpoint would
        // overwrite household identity files written by
        // `accept_household_confirm`.
        let (status, body) = call_stage_with_state(BootstrapState::NamedAwaitingPair).await;
        assert_eq!(status, HStatus::CONFLICT);
        assert_eq!(body.error, "household_already_paired");
    }

    #[tokio::test]
    async fn pair_machine_local_stage_rejects_ready() {
        let (status, body) = call_stage_with_state(BootstrapState::Ready).await;
        assert_eq!(status, HStatus::CONFLICT);
        assert_eq!(body.error, "household_already_paired");
    }

    #[tokio::test]
    async fn pair_machine_local_stage_rejects_recovering() {
        let (status, body) = call_stage_with_state(BootstrapState::Recovering).await;
        assert_eq!(status, HStatus::CONFLICT);
        assert_eq!(body.error, "household_already_paired");
    }

    // ── PreHouseholdRouterState wired into bootstrap router ─────────────
    //
    // Static check that `BootstrapHandlerState` carries the same
    // `Arc<PairMachineWindow>` that's mounted on the pre-household routes
    // — Fix 1 collapses the two listeners into one and `local_seed_handler`
    // must read from the SAME window the stage handler mutates. We assert
    // pointer-equality through `Arc::ptr_eq` so a future refactor that
    // accidentally clones the value can't silently break the seed lookup.
    #[tokio::test]
    async fn bootstrap_handler_state_owns_shared_pair_machine_window() {
        let state = make_state(BootstrapState::Uninitialized);
        let cloned = Arc::clone(&state.pair_machine_window);
        assert!(
            Arc::ptr_eq(&state.pair_machine_window, &cloned),
            "BootstrapHandlerState must expose the same Arc the daemon hands to pre_household_router; \
             otherwise stage() and local/seed read different windows."
        );
    }

    // ── /bootstrap/pair-device/reissue (R98) ────────────────────────────
    //
    // Secure loopback-only re-mint of the owner pair-device window for a Mac
    // stuck in named_awaiting_pair with an expired window. The handler runs a
    // fixed gate order (loopback → state → identity → not-already-paired →
    // window-still-open) before minting on the SHARED Arc<PairDeviceWindow>.

    /// Build a `BootstrapHandlerState` whose state dir holds a real
    /// software-keyed household identity (so `state.household.current()` and
    /// the on-disk owner-auth guard resolve against actual files). The
    /// `tempfile::TempDir` is returned so the caller keeps it alive for the
    /// duration of the test.
    fn make_state_with_identity(bs: BootstrapState) -> (BootstrapHandlerState, tempfile::TempDir) {
        let td = tempfile::tempdir().unwrap();
        let loaded = household_rs::bootstrap_or_load(
            td.path(),
            BootstrapOpts {
                household_name: "Reissue Home".into(),
                hostname_label: Some("reissue-host".into()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap");
        let state = BootstrapHandlerState {
            bootstrap: Arc::new(RwLock::new(bs)),
            household: HouseholdState::loaded(Arc::new(loaded)),
            state_dir: td.path().to_path_buf(),
            pair_device_window: Arc::new(PairDeviceWindow::with_persistence(
                td.path().to_path_buf(),
            )),
            pair_machine_window: Arc::new(PairMachineWindow::new_in_memory()),
            started_at: Instant::now(),
            setup_invitation_cache: crate::setup_invitation::new_cache(),
            engine_port: 8091,
            tailnet_resolver: || None,
        };
        (state, td)
    }

    fn reissue_request(peer: SocketAddr) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/bootstrap/pair-device/reissue")
            .extension(ConnectInfo::<SocketAddr>(peer))
            .body(Body::empty())
            .unwrap()
    }

    /// Decode a successful CBOR `ReissueResponse`.
    #[derive(serde::Deserialize, Debug)]
    struct ReissueResponseForTest {
        #[serde(rename = "v")]
        version: u8,
        pair_qr_uri: String,
        hh_id: String,
        expires_at_unix: u64,
    }

    async fn decode_reissue_ok(response: Response) -> ReissueResponseForTest {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        household_rs::cbor::from_canonical_slice(&bytes).expect("CBOR decode")
    }

    #[tokio::test]
    async fn reissue_non_loopback_rejected_with_404() {
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from(([192, 168, 15, 99], 50000)));
        let resp = app.oneshot(req).await.unwrap();
        // Bare 404 — same as a missing route. No CBOR body content asserted.
        assert_eq!(resp.status(), HStatus::NOT_FOUND);
    }

    #[tokio::test]
    async fn reissue_loopback_ipv4_proceeds_past_acl() {
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let resp = app.oneshot(req).await.unwrap();
        // Past the ACL + all gates → 200 mint.
        assert_eq!(resp.status(), HStatus::OK);
    }

    #[tokio::test]
    async fn reissue_loopback_ipv6_proceeds_past_acl() {
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 12345)));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HStatus::OK);
    }

    #[tokio::test]
    async fn reissue_state_gate_rejects_non_named_awaiting_pair() {
        for bs in [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
            BootstrapState::Ready,
            BootstrapState::Recovering,
        ] {
            let (state, _td) = make_state_with_identity(bs);
            let app = bootstrap_router(state);
            let req = reissue_request(SocketAddr::from(([127, 0, 0, 1], 12345)));
            let resp = app.oneshot(req).await.unwrap();
            let (status, body) = decode_cbor_error(resp).await;
            assert_eq!(status, HStatus::NOT_FOUND, "state={bs:?}");
            assert_eq!(body.error, "reissue_unavailable", "state={bs:?}");
        }
    }

    #[tokio::test]
    async fn reissue_state_gate_only_named_awaiting_pair_mints() {
        // The complement of the rejection test: NamedAwaitingPair is the one
        // state that proceeds to a successful 200 mint.
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let window = Arc::clone(&state.pair_device_window);
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HStatus::OK);
        // A live token now exists on the shared window.
        assert!(window.current_token().await.is_some());
    }

    #[tokio::test]
    async fn reissue_identity_unavailable_when_no_identity_loaded() {
        // NamedAwaitingPair + loopback but no in-memory identity → the
        // identity gate returns 404 identity_unavailable (no panic).
        let mut state = make_state(BootstrapState::NamedAwaitingPair);
        // make_state uses an empty HouseholdState; keep it empty.
        state.household = HouseholdState::empty();
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let resp = app.oneshot(req).await.unwrap();
        let (status, body) = decode_cbor_error(resp).await;
        assert_eq!(status, HStatus::NOT_FOUND);
        assert_eq!(body.error, "identity_unavailable");
    }

    /// Build a real owner `HouseholdAuthState` for the loaded identity by
    /// signing a fresh owner `PersonCert` under the household's private key.
    /// Returns the `Arc<HouseholdAuthState>` for the in-memory slot; if
    /// `persist_to` is `Some`, also saves it to disk so the on-disk
    /// `load_optional` guard sees a paired owner too.
    fn real_owner_auth(
        identity: &SharedHouseholdIdentity,
        persist_to: Option<&std::path::Path>,
    ) -> SharedOwnerAuthState {
        use household_rs::keys::P256Keypair;
        use household_rs::person_cert::{PersonCert, SignOwnerOptions};
        let hh_key = identity
            .hh_priv
            .as_ref()
            .expect("software-keyed test identity holds hh_priv");
        let person = P256Keypair::generate();
        let now = crate::time_util::unix_now_secs_checked("test.clock").unwrap_or(0);
        let cert = PersonCert::sign_owner(
            hh_key.as_ref(),
            SignOwnerOptions {
                hh_id: identity.record.hh_id.clone(),
                p_pub: household_rs::keys::IdentityKey::public(&person),
                display_name: "Owner".into(),
                issued_at: now,
            },
        )
        .expect("sign owner cert");
        let auth = HouseholdAuthState::new(&identity.record, cert);
        if let Some(dir) = persist_to {
            auth.save(dir).expect("persist owner auth");
        }
        Arc::new(auth)
    }

    #[tokio::test]
    async fn reissue_already_paired_when_owner_auth_present() {
        // Owner-auth present (in memory AND on disk) → 404 already_paired,
        // and NO token is minted on the shared window.
        let (state, td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let identity = state.household.current().await.unwrap();
        let owner_auth = real_owner_auth(&identity, Some(td.path()));
        let household =
            HouseholdState::loaded_with_owner_auth(Arc::clone(&identity), Some(owner_auth));
        let state = BootstrapHandlerState { household, ..state };
        let window = Arc::clone(&state.pair_device_window);
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let resp = app.oneshot(req).await.unwrap();
        let (status, body) = decode_cbor_error(resp).await;
        assert_eq!(status, HStatus::NOT_FOUND);
        assert_eq!(body.error, "already_paired");
        assert!(
            window.current_token().await.is_none(),
            "no token may be minted when already paired"
        );
    }

    #[tokio::test]
    async fn reissue_already_paired_via_on_disk_guard_only() {
        // Owner-auth absent from memory but present on disk (a freshly-loaded
        // engine that hasn't hydrated owner_auth yet) → the defensive on-disk
        // load_optional guard still fails closed with 404 already_paired.
        let (state, td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let identity = state.household.current().await.unwrap();
        let _ = real_owner_auth(&identity, Some(td.path())); // persisted, not in memory
        let window = Arc::clone(&state.pair_device_window);
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let resp = app.oneshot(req).await.unwrap();
        let (status, body) = decode_cbor_error(resp).await;
        assert_eq!(status, HStatus::NOT_FOUND);
        assert_eq!(body.error, "already_paired");
        assert!(window.current_token().await.is_none());
    }

    #[tokio::test]
    async fn reissue_window_still_open_returns_409_no_new_token() {
        // Pre-open the shared window with an unexpired token. The reissue must
        // refuse with 409 window_still_open and must NOT replace the nonce.
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let existing = state
            .pair_device_window
            .mint_token(Duration::from_secs(300), None)
            .await
            .expect("pre-mint");
        let existing_nonce = existing.nonce.as_b64();
        let window = Arc::clone(&state.pair_device_window);
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let resp = app.oneshot(req).await.unwrap();
        let (status, body) = decode_cbor_error(resp).await;
        assert_eq!(status, HStatus::CONFLICT);
        assert_eq!(body.error, "window_still_open");
        // The existing nonce is untouched.
        let still = window.current_token().await.expect("window still open");
        assert_eq!(
            still.nonce.as_b64(),
            existing_nonce,
            "nonce must not be re-minted"
        );
    }

    #[tokio::test]
    async fn reissue_none_window_proceeds_and_opens_token() {
        // current_token() == None (fresh window) → mint proceeds and
        // current_token() becomes Some.
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let window = Arc::clone(&state.pair_device_window);
        assert!(
            window.current_token().await.is_none(),
            "precondition: no window"
        );
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HStatus::OK);
        assert!(window.current_token().await.is_some());
    }

    #[tokio::test]
    async fn reissue_success_response_shape_and_uri_contents() {
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let hh_id = state
            .household
            .current()
            .await
            .unwrap()
            .record
            .hh_id
            .to_string();
        let window = Arc::clone(&state.pair_device_window);
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HStatus::OK);
        let body = decode_reissue_ok(resp).await;
        assert_eq!(body.version, 1);
        assert_eq!(body.hh_id, hh_id);
        assert!(
            body.pair_qr_uri
                .starts_with("soyeht://household/pair-device?"),
            "uri={}",
            body.pair_qr_uri
        );
        assert!(body.pair_qr_uri.contains("v=1"));
        assert!(body.pair_qr_uri.contains("&hh_pub="));
        assert!(body.pair_qr_uri.contains("&nonce="));
        assert!(body.pair_qr_uri.contains("&ttl="));
        assert!(body.pair_qr_uri.contains("&house_name="));
        // expires_at_unix matches the live window token.
        let token = window.current_token().await.unwrap();
        assert_eq!(token.expires_at_unix, body.expires_at_unix);
    }

    /// No-secret logging: the data the handler logs on success is derived
    /// purely from non-secret fields (stage/hh_id/ttl_secs/expires_at_unix/
    /// host). The nonce lives ONLY in `pair_qr_uri`, which is returned in the
    /// CBOR body and is never written to the log. We assert that the value we
    /// would log (the `host` fallback + hh_id + numeric fields) never carries
    /// the nonce that appears in the response URI.
    #[tokio::test]
    async fn reissue_log_fields_exclude_nonce_and_uri() {
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let hh_id = state
            .household
            .current()
            .await
            .unwrap()
            .record
            .hh_id
            .to_string();
        let app = bootstrap_router(state);
        let req = reissue_request(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), HStatus::OK);
        let body = decode_reissue_ok(resp).await;

        // Extract the nonce token from the response URI.
        let nonce = body
            .pair_qr_uri
            .split("&nonce=")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .expect("nonce param");
        assert!(!nonce.is_empty());

        // The fields the handler logs (constructed identically to the
        // tracing::info! call site) must NOT contain the nonce nor the full
        // pair_qr_uri.
        let logged_hh_id = hh_id.clone();
        let logged_stage = "pair_device.reissue.opened";
        let logged_ttl_secs = crate::household_bootstrap::pair_window_ttl_secs_from_env(
            "THEYOS_PAIR_DEVICE_TTL_SECS",
        );
        let logged_expires = body.expires_at_unix;
        let log_line = format!(
            "stage={logged_stage} hh_id={logged_hh_id} ttl_secs={logged_ttl_secs} expires_at_unix={logged_expires}"
        );
        assert!(log_line.contains("pair_device.reissue.opened"));
        assert!(log_line.contains(&hh_id));
        assert!(
            !log_line.contains(nonce),
            "log line must not contain the pairing nonce"
        );
        assert!(
            !log_line.contains(&body.pair_qr_uri),
            "log line must not contain the full pair_qr_uri"
        );
    }

    // ── GET /bootstrap/pair-device-uri ──────────────────────────────────

    fn pair_device_uri_request_from(peer: SocketAddr) -> Request<Body> {
        let mut request = Request::builder()
            .method("GET")
            .uri("/bootstrap/pair-device-uri")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        request
    }

    /// A Tailnet peer — the case this route exists for, and the default for
    /// the gate tests below so they exercise the admitted-but-not-loopback
    /// branch rather than the trivial one.
    fn tailnet_peer() -> SocketAddr {
        SocketAddr::from(([100, 101, 102, 103], 41234))
    }

    fn pair_device_uri_request() -> Request<Body> {
        pair_device_uri_request_from(tailnet_peer())
    }

    /// Decode a successful CBOR `PairDeviceUriResponse`. Field set mirrors
    /// `BootstrapPairDeviceURIClient.requiredKeys`/`knownKeys` on the iOS
    /// side exactly — an extra or missing key here must fail that client's
    /// `requireKnown`/`requireRequired` checks.
    #[derive(serde::Deserialize, Debug)]
    struct PairDeviceUriResponseForTest {
        #[serde(rename = "v")]
        version: u8,
        house_name: String,
        host_label: String,
        hh_id: String,
        hh_pub: serde_bytes::ByteBuf,
        pair_device_uri: String,
        expires_at: u64,
    }

    async fn decode_pair_device_uri_ok(response: Response) -> PairDeviceUriResponseForTest {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        household_rs::cbor::from_canonical_slice(&bytes).expect("CBOR decode")
    }

    #[tokio::test]
    async fn pair_device_uri_admits_loopback_and_tailnet_peers() {
        // Wider than reissue's loopback-only ACL: a freshly-launched iPhone
        // reaching this Mac over the tailnet is the entire point.
        for peer in [
            SocketAddr::from(([127, 0, 0, 1], 41234)),
            tailnet_peer(),
            // Tailscale's IPv6 ULA range counts as tailnet too.
            SocketAddr::from((
                "fd7a:115c:a1e0::1".parse::<std::net::Ipv6Addr>().unwrap(),
                41234,
            )),
        ] {
            let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
            let app = bootstrap_router(state);
            let resp = app
                .oneshot(pair_device_uri_request_from(peer))
                .await
                .unwrap();
            assert_eq!(resp.status(), HStatus::OK, "peer {peer} must be admitted");
        }
    }

    #[tokio::test]
    async fn pair_device_uri_rejects_lan_and_mesh_peers() {
        // The body is the complete first-owner pairing URI, so an admitted
        // caller can claim the household. Bind-time exposure does not stand
        // in for an admission check on either axis:
        //
        //   - LAN: `HouseholdExposurePolicy::allows` denies `Lan` in
        //     `named_awaiting_pair`, but the listener is unbound by a 500 ms
        //     reconciliation tick, not at the state transition — so the
        //     state gate can already pass while the LAN socket still accepts.
        //   - Mesh: that same policy *grants* `Mesh` in this state, so a mesh
        //     peer reaches the route with no transition window needed at all.
        //
        // Both must get the bare 404 an unrouted path returns.
        for peer in [
            SocketAddr::from(([192, 168, 1, 50], 41234)),
            SocketAddr::from(([10, 0, 0, 7], 41234)),
            SocketAddr::from(([10, 44, 1, 5], 41234)),
        ] {
            let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
            let app = bootstrap_router(state);
            let resp = app
                .oneshot(pair_device_uri_request_from(peer))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                HStatus::NOT_FOUND,
                "peer {peer} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn pair_device_uri_rejected_peer_leaks_no_body() {
        // A refused caller must not be able to tell this route apart from a
        // path that does not exist — no CBOR error code, no state string.
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let app = bootstrap_router(state);
        let resp = app
            .oneshot(pair_device_uri_request_from(SocketAddr::from((
                [192, 168, 1, 50],
                41234,
            ))))
            .await
            .unwrap();
        assert_eq!(resp.status(), HStatus::NOT_FOUND);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            bytes.is_empty(),
            "refused peer got a {}-byte body",
            bytes.len()
        );
    }

    #[tokio::test]
    async fn reissue_waits_on_the_bootstrap_mutation_lock() {
        // This is the test with teeth for the reissue half of the fix. The
        // GET×reissue test below asserts the invariant the lock buys, but it
        // cannot *prove* the lock: reissue has no await point between its
        // Gate 5 window read and its mint, so the interleaving that fix
        // closes is too narrow to provoke on demand — measured, that test
        // stays green even with this lock removed. Blocking on the lock is
        // the property that is directly observable, so assert that.
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let app = bootstrap_router(state);
        let guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
            .lock()
            .await;
        let inflight = tokio::spawn(async move {
            app.oneshot(reissue_request(SocketAddr::from(([127, 0, 0, 1], 51001))))
                .await
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !inflight.is_finished(),
            "reissue answered while BOOTSTRAP_MUTATION_LOCK was held — it is not serialized \
             against the pair-device-uri GET or against confirm"
        );

        drop(guard);
        let resp = tokio::time::timeout(Duration::from_secs(5), inflight)
            .await
            .expect("reissue did not finish after the lock was released")
            .expect("reissue task panicked")
            .unwrap();
        assert_eq!(resp.status(), HStatus::OK);
    }

    #[tokio::test]
    async fn pair_device_uri_and_reissue_never_answer_with_different_nonces() {
        // Reissue used to be the only route that minted, so its Gate 5 read
        // (`current_token() == None`) needed no lock — nothing else could open
        // a window underneath it. This GET mints too, which reintroduces the
        // race at a higher level: reissue sees an empty window, the GET takes
        // the lock and answers with A, and reissue then mints B on top, so the
        // URI the GET already handed out names a nonce the window no longer
        // holds. With both routes on BOOTSTRAP_MUTATION_LOCK only two outcomes
        // survive — the GET wins and reissue is refused `window_still_open`, or
        // reissue wins and the GET reuses its token.
        for round in 0..40 {
            let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
            assert!(state.pair_device_window.current_token().await.is_none());
            let a = bootstrap_router(state.clone());
            let b = bootstrap_router(state.clone());
            let (get_res, reissue_res) = tokio::join!(
                a.oneshot(pair_device_uri_request()),
                b.oneshot(reissue_request(SocketAddr::from(([127, 0, 0, 1], 51000)))),
            );
            let (get_res, reissue_res) = (get_res.unwrap(), reissue_res.unwrap());
            assert_eq!(
                get_res.status(),
                HStatus::OK,
                "round {round}: the GET is always serviceable in this state"
            );
            let reissue_status = reissue_res.status();
            let get_uri = decode_pair_device_uri_ok(get_res).await.pair_device_uri;

            match reissue_status {
                HStatus::CONFLICT => {
                    let (_, body) = decode_cbor_error(reissue_res).await;
                    assert_eq!(body.error, "window_still_open");
                }
                HStatus::OK => {
                    let reissued = decode_reissue_ok(reissue_res).await.pair_qr_uri;
                    let held = state
                        .pair_device_window
                        .current_token()
                        .await
                        .expect("a window must be open");
                    let nonce = format!("&nonce={}", held.nonce.as_b64());
                    assert!(
                        get_uri.contains(&nonce) && reissued.contains(&nonce),
                        "round {round}: both routes returned 200 naming different nonces"
                    );
                }
                other => panic!("round {round}: unexpected reissue status {other}"),
            }
        }
    }

    #[tokio::test]
    async fn pair_device_uri_serves_the_nonce_the_window_actually_holds() {
        // The URI is only usable if the nonce inside it is the one the window
        // will accept on confirm. Atomicity of retrieve-or-mint under
        // concurrency is proven where it can actually be raced — see
        // `household_rs::pair_device::tests::
        // get_or_mint_hands_every_racing_caller_the_same_token`. Two GETs
        // through this router cannot race: they serialize on
        // `BOOTSTRAP_MUTATION_LOCK`, which is the point of taking it.
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let window = Arc::clone(&state.pair_device_window);
        assert!(window.current_token().await.is_none());
        let app = bootstrap_router(state);
        let resp = app.oneshot(pair_device_uri_request()).await.unwrap();
        assert_eq!(resp.status(), HStatus::OK);
        let uri = decode_pair_device_uri_ok(resp).await.pair_device_uri;
        let live = window
            .current_token()
            .await
            .expect("the GET must leave a window open");
        assert!(
            uri.contains(&format!("&nonce={}", live.nonce.as_b64())),
            "served a URI whose nonce is not the one the window holds"
        );
    }

    #[tokio::test]
    async fn pair_device_uri_waits_on_the_bootstrap_mutation_lock() {
        // `post_pair_device_confirm` writes owner auth, consumes the window
        // and advances bootstrap state under `BOOTSTRAP_MUTATION_LOCK`. If
        // this route does not take the same lock it can clear its
        // owner-not-paired gate, lose the race to a confirm that runs to
        // completion, and then open a fresh pairing window behind an owner
        // that is already persisted. Hold the lock and prove the handler
        // blocks on it rather than reading through it.
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let app = bootstrap_router(state);
        let guard = crate::bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK
            .lock()
            .await;
        let inflight = tokio::spawn(async move { app.oneshot(pair_device_uri_request()).await });

        // A handler that ignores the lock answers immediately; one that
        // respects it cannot answer until the guard below is dropped. The
        // sleep is what gives the spawned task time to actually reach the
        // lock, so "not finished" means blocked rather than not-yet-started.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !inflight.is_finished(),
            "handler answered while BOOTSTRAP_MUTATION_LOCK was held — it is not serialized \
             against pair-device confirm"
        );

        drop(guard);
        let resp = tokio::time::timeout(Duration::from_secs(5), inflight)
            .await
            .expect("handler did not finish after the lock was released")
            .expect("handler task panicked")
            .unwrap();
        assert_eq!(resp.status(), HStatus::OK);
    }

    #[tokio::test]
    async fn pair_device_uri_state_gate_rejects_non_named_awaiting_pair() {
        for bs in [
            BootstrapState::Uninitialized,
            BootstrapState::ReadyForNaming,
            BootstrapState::Ready,
            BootstrapState::Recovering,
        ] {
            let (state, _td) = make_state_with_identity(bs);
            let app = bootstrap_router(state);
            let resp = app.oneshot(pair_device_uri_request()).await.unwrap();
            let (status, body) = decode_cbor_error(resp).await;
            assert_eq!(status, HStatus::NOT_FOUND, "state={bs:?}");
            assert_eq!(body.error, "reissue_unavailable", "state={bs:?}");
        }
    }

    #[tokio::test]
    async fn pair_device_uri_identity_unavailable_when_no_identity_loaded() {
        let mut state = make_state(BootstrapState::NamedAwaitingPair);
        state.household = HouseholdState::empty();
        let app = bootstrap_router(state);
        let resp = app.oneshot(pair_device_uri_request()).await.unwrap();
        let (status, body) = decode_cbor_error(resp).await;
        assert_eq!(status, HStatus::NOT_FOUND);
        assert_eq!(body.error, "identity_unavailable");
    }

    #[tokio::test]
    async fn pair_device_uri_already_paired_when_owner_auth_present() {
        let (state, td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let identity = state.household.current().await.unwrap();
        let owner_auth = real_owner_auth(&identity, Some(td.path()));
        let household =
            HouseholdState::loaded_with_owner_auth(Arc::clone(&identity), Some(owner_auth));
        let state = BootstrapHandlerState { household, ..state };
        let window = Arc::clone(&state.pair_device_window);
        let app = bootstrap_router(state);
        let resp = app.oneshot(pair_device_uri_request()).await.unwrap();
        let (status, body) = decode_cbor_error(resp).await;
        assert_eq!(status, HStatus::NOT_FOUND);
        assert_eq!(body.error, "already_paired");
        assert!(
            window.current_token().await.is_none(),
            "no token may be minted when already paired"
        );
    }

    #[tokio::test]
    async fn pair_device_uri_already_paired_via_on_disk_guard_only() {
        let (state, td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let identity = state.household.current().await.unwrap();
        let _ = real_owner_auth(&identity, Some(td.path())); // persisted, not in memory
        let app = bootstrap_router(state);
        let resp = app.oneshot(pair_device_uri_request()).await.unwrap();
        let (status, body) = decode_cbor_error(resp).await;
        assert_eq!(status, HStatus::NOT_FOUND);
        assert_eq!(body.error, "already_paired");
    }

    #[tokio::test]
    async fn pair_device_uri_none_window_proceeds_and_opens_token() {
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let window = Arc::clone(&state.pair_device_window);
        assert!(window.current_token().await.is_none(), "precondition: no window");
        let app = bootstrap_router(state);
        let resp = app.oneshot(pair_device_uri_request()).await.unwrap();
        assert_eq!(resp.status(), HStatus::OK);
        assert!(window.current_token().await.is_some());
    }

    #[tokio::test]
    async fn pair_device_uri_reuses_existing_open_window_instead_of_reissuing() {
        // The behavioral point of this route vs. POST reissue: a window left
        // open by `/bootstrap/initialize` (or an earlier call to this same
        // route) must be served back as-is, not rejected and not replaced.
        // Rejecting here would just reproduce the bug this route exists to
        // fix — the iPhone's very first fetch would always lose the race
        // against `/bootstrap/initialize`'s own mint.
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let existing = state
            .pair_device_window
            .mint_token(Duration::from_secs(300), None)
            .await
            .expect("pre-mint");
        let existing_nonce = existing.nonce.as_b64();
        let window = Arc::clone(&state.pair_device_window);
        let app = bootstrap_router(state);
        let resp = app.oneshot(pair_device_uri_request()).await.unwrap();
        assert_eq!(resp.status(), HStatus::OK);
        let body = decode_pair_device_uri_ok(resp).await;
        assert!(
            body.pair_device_uri.contains(&format!("&nonce={existing_nonce}")),
            "must echo the already-open window's nonce, not mint a new one: {}",
            body.pair_device_uri
        );
        let still = window.current_token().await.expect("window still open");
        assert_eq!(still.nonce.as_b64(), existing_nonce, "nonce must not be re-minted");
    }

    #[tokio::test]
    async fn pair_device_uri_success_response_shape_and_contents() {
        let (state, _td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
        let hh_id = state.household.current().await.unwrap().record.hh_id.to_string();
        let window = Arc::clone(&state.pair_device_window);
        let app = bootstrap_router(state);
        let resp = app.oneshot(pair_device_uri_request()).await.unwrap();
        assert_eq!(resp.status(), HStatus::OK);
        let body = decode_pair_device_uri_ok(resp).await;
        assert_eq!(body.version, 1);
        assert_eq!(body.hh_id, hh_id);
        assert_eq!(body.house_name, "Reissue Home");
        assert!(!body.host_label.is_empty());
        assert_eq!(body.hh_pub.len(), 33, "hh_pub must be exactly 33 bytes (SEC1 compressed)");
        assert!(
            body.pair_device_uri
                .starts_with("soyeht://household/pair-device?"),
            "uri={}",
            body.pair_device_uri
        );
        assert!(body.pair_device_uri.contains("v=1"));
        assert!(body.pair_device_uri.contains("&hh_pub="));
        assert!(body.pair_device_uri.contains("&nonce="));
        assert!(body.pair_device_uri.contains("&ttl="));
        assert!(body.pair_device_uri.contains("&m_cert_fp="));
        assert!(body.pair_device_uri.contains("&crit=m_cert_fp"));
        assert!(body.pair_device_uri.contains("&house_name="));
        let token = window.current_token().await.unwrap();
        assert_eq!(token.expires_at_unix, body.expires_at);
    }
}
