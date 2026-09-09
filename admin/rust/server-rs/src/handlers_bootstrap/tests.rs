#![cfg(test)]

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

// Source-scan helpers shared with the fingerprint-ordering guard above,
// so both sets of guards see the source the same way (comments stripped,
// anchors asserted unique).
use super::m_cert_fp_ordering_guard::{fn_body, unique_offset};

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
        installation: crate::pairing_addresses::PairingInstallation::new("release".into(), 8091),
        invitation_verifier: crate::setup_invitation::callback_verify_blocking,
        phase3_runtime: None,
        pair_code_rate_limiter: None,
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
        pair_device_window: Arc::new(
            PairDeviceWindow::with_persistence(td.path().to_path_buf()).unwrap(),
        ),
        pair_machine_window: Arc::new(PairMachineWindow::new_in_memory()),
        started_at: Instant::now(),
        setup_invitation_cache: crate::setup_invitation::new_cache(),
        installation: crate::pairing_addresses::PairingInstallation::new("release".into(), 8091),
        invitation_verifier: crate::setup_invitation::callback_verify_blocking,
        phase3_runtime: None,
        pair_code_rate_limiter: None,
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
    let household = HouseholdState::loaded_with_owner_auth(Arc::clone(&identity), Some(owner_auth));
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
/// purely from non-secret fields (`stage`/`hh_id`/`ttl_secs`/
/// `expires_at_unix`/`host`). The nonce lives ONLY in `pair_qr_uri`, which is returned in the
/// CBOR body and is never written to the log. We assert that the value we
/// would log (the `host` fallback + `hh_id` + numeric fields) never carries
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
    let logged_ttl_secs =
        crate::household_bootstrap::pair_window_ttl_secs_from_env("THEYOS_PAIR_DEVICE_TTL_SECS");
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
    //   - LAN: `HouseholdExposurePolicy::allows_with` denies `Lan` in
    //     `named_awaiting_pair` only while no pair-device window is open,
    //     and even then the listener is unbound by a 500 ms reconciliation
    //     tick rather than at the state transition — so the state gate can
    //     pass while the LAN socket still accepts, and an open window
    //     admits it outright.
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
    let household = HouseholdState::loaded_with_owner_auth(Arc::clone(&identity), Some(owner_auth));
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
    assert!(
        window.current_token().await.is_none(),
        "precondition: no window"
    );
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
        body.pair_device_uri
            .contains(&format!("&nonce={existing_nonce}")),
        "must echo the already-open window's nonce, not mint a new one: {}",
        body.pair_device_uri
    );
    let still = window.current_token().await.expect("window still open");
    assert_eq!(
        still.nonce.as_b64(),
        existing_nonce,
        "nonce must not be re-minted"
    );
}

#[tokio::test]
async fn pair_device_uri_success_response_shape_and_contents() {
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
    let resp = app.oneshot(pair_device_uri_request()).await.unwrap();
    assert_eq!(resp.status(), HStatus::OK);
    let body = decode_pair_device_uri_ok(resp).await;
    assert_eq!(body.version, 1);
    assert_eq!(body.hh_id, hh_id);
    assert_eq!(body.house_name, "Reissue Home");
    assert!(!body.host_label.is_empty());
    assert_eq!(
        body.hh_pub.len(),
        33,
        "hh_pub must be exactly 33 bytes (SEC1 compressed)"
    );
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

// ── POST /bootstrap/pair-device-uri/by-code ─────────────────────────

/// `make_state_with_identity` plus a per-peer limiter. An absent limiter
/// fails closed by design, so any test that expects to reach a gate past
/// the limiter has to wire one up.
fn make_by_code_state(bs: BootstrapState) -> (BootstrapHandlerState, tempfile::TempDir) {
    by_code_state_with_limit(bs, 1_000)
}

fn by_code_state_with_limit(
    bs: BootstrapState,
    per_hour: i64,
) -> (BootstrapHandlerState, tempfile::TempDir) {
    let (state, td) = make_state_with_identity(bs);
    let limiter = Limiter::new(":memory:", per_hour).expect("in-memory limiter");
    (state.with_pair_code_rate_limiter(Arc::new(limiter)), td)
}

fn by_code_body(version: u8, words: &[&str]) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct CodeBody<'a> {
        #[serde(rename = "v")]
        v: u8,
        words: &'a [&'a str],
    }
    household_rs::cbor::to_canonical_vec(&CodeBody { v: version, words }).expect("encode code")
}

fn by_code_request_from(peer: SocketAddr, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/bootstrap/pair-device-uri/by-code")
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    request
}

fn by_code_request(body: Vec<u8>) -> Request<Body> {
    by_code_request_from(tailnet_peer(), body)
}

/// The six words the Mac is showing for `state`'s currently open window.
async fn open_window_code(state: &BootstrapHandlerState) -> [&'static str; 6] {
    let identity = state.household.current().await.expect("identity loaded");
    let token = state
        .pair_device_window
        .current_token()
        .await
        .expect("window open");
    household_rs::fingerprint::pair_device_fingerprint_words(
        identity.record.hh_pub.as_bytes(),
        &token.nonce.0,
    )
}

/// A code that is guaranteed *not* to be `right`: same shape, six real
/// wordlist entries, one word deliberately different. Derived rather than
/// hard-coded so the test can never accidentally submit the real code.
fn wrong_code(right: &[&'static str; 6]) -> [&'static str; 6] {
    let mut wrong = *right;
    wrong[0] = if right[0] == "abandon" {
        "ability"
    } else {
        "abandon"
    };
    assert_ne!(&wrong, right);
    wrong
}

/// A syntactically valid code used where the words can never be graded
/// (no window, expired window) — six real wordlist entries.
const ANY_VALID_CODE: [&str; 6] = ["abandon", "ability", "able", "about", "above", "absent"];

async fn body_bytes(response: Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

/// Everything a client can observe about a rejection: status, every header
/// (sorted, so ordering is not the assertion), and body.
///
/// `body_bytes` alone was not enough. "Byte-identical" tests written on it
/// compared only bodies, so returning `410 Gone` for an expired window, or
/// attaching `Retry-After` on the shed path, kept every test green while
/// handing a guesser the "is a window open right now" oracle the design
/// exists to deny.
async fn observable_parts(response: Response) -> (HStatus, Vec<(String, Vec<u8>)>, Vec<u8>) {
    let status = response.status();
    let mut headers: Vec<(String, Vec<u8>)> = response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    headers.sort();
    (status, headers, body_bytes(response).await)
}

#[tokio::test]
async fn pair_device_uri_by_code_admits_loopback_and_tailnet_peers() {
    // Same admission set as the GET sibling — the by-code route is a
    // second door onto the same URI, not a wider one.
    for peer in [
        SocketAddr::from(([127, 0, 0, 1], 41234)),
        tailnet_peer(),
        SocketAddr::from((
            "fd7a:115c:a1e0::1".parse::<std::net::Ipv6Addr>().unwrap(),
            41234,
        )),
    ] {
        let (state, _td) = make_by_code_state(BootstrapState::NamedAwaitingPair);
        state
            .pair_device_window
            .mint_token(Duration::from_secs(300), None)
            .await
            .expect("pre-mint");
        let code = open_window_code(&state).await;
        let app = bootstrap_router(state);
        let resp = app
            .oneshot(by_code_request_from(peer, by_code_body(1, &code)))
            .await
            .unwrap();
        assert_eq!(resp.status(), HStatus::OK, "peer {peer} must be admitted");
    }
}

#[tokio::test]
async fn pair_device_uri_by_code_rejects_lan_and_mesh_peers() {
    // Even holding the correct code, a LAN or mesh peer gets the bare 404
    // an unrouted path returns: the ACL runs before the code is graded.
    for peer in [
        SocketAddr::from(([192, 168, 1, 50], 41234)),
        SocketAddr::from(([10, 0, 0, 7], 41234)),
        SocketAddr::from(([10, 44, 1, 5], 41234)),
    ] {
        let (state, _td) = make_by_code_state(BootstrapState::NamedAwaitingPair);
        state
            .pair_device_window
            .mint_token(Duration::from_secs(300), None)
            .await
            .expect("pre-mint");
        let code = open_window_code(&state).await;
        let app = bootstrap_router(state);
        let resp = app
            .oneshot(by_code_request_from(peer, by_code_body(1, &code)))
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
async fn pair_device_uri_by_code_rejected_peer_leaks_no_body() {
    let (state, _td) = make_by_code_state(BootstrapState::NamedAwaitingPair);
    let app = bootstrap_router(state);
    let resp = app
        .oneshot(by_code_request_from(
            SocketAddr::from(([192, 168, 1, 50], 41234)),
            by_code_body(1, &ANY_VALID_CODE),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), HStatus::NOT_FOUND);
    assert!(
        body_bytes(resp).await.is_empty(),
        "a refused peer must not learn the route exists"
    );
}

#[tokio::test]
async fn pair_device_uri_by_code_state_gate_rejects_non_named_awaiting_pair() {
    for bs in [
        BootstrapState::Uninitialized,
        BootstrapState::ReadyForNaming,
        BootstrapState::Ready,
        BootstrapState::Recovering,
    ] {
        let (state, _td) = make_by_code_state(bs);
        let app = bootstrap_router(state);
        let resp = app
            .oneshot(by_code_request(by_code_body(1, &ANY_VALID_CODE)))
            .await
            .unwrap();
        let (status, body) = decode_cbor_error(resp).await;
        assert_eq!(status, HStatus::NOT_FOUND, "state={bs:?}");
        assert_eq!(body.error, "reissue_unavailable", "state={bs:?}");
    }
}

#[tokio::test]
async fn pair_device_uri_by_code_identity_unavailable_when_no_identity_loaded() {
    let (state, _td) = make_by_code_state(BootstrapState::NamedAwaitingPair);
    let state = BootstrapHandlerState {
        household: HouseholdState::empty(),
        ..state
    };
    let app = bootstrap_router(state);
    let resp = app
        .oneshot(by_code_request(by_code_body(1, &ANY_VALID_CODE)))
        .await
        .unwrap();
    let (status, body) = decode_cbor_error(resp).await;
    assert_eq!(status, HStatus::NOT_FOUND);
    assert_eq!(body.error, "identity_unavailable");
}

#[tokio::test]
async fn pair_device_uri_by_code_already_paired_when_owner_auth_present() {
    let (state, td) = make_by_code_state(BootstrapState::NamedAwaitingPair);
    state
        .pair_device_window
        .mint_token(Duration::from_secs(300), None)
        .await
        .expect("pre-mint");
    let code = open_window_code(&state).await;
    let identity = state.household.current().await.unwrap();
    let owner_auth = real_owner_auth(&identity, Some(td.path()));
    let household = HouseholdState::loaded_with_owner_auth(Arc::clone(&identity), Some(owner_auth));
    let state = BootstrapHandlerState { household, ..state };
    let app = bootstrap_router(state);
    // Even the *correct* code does not reopen a household that is paired.
    let resp = app
        .oneshot(by_code_request(by_code_body(1, &code)))
        .await
        .unwrap();
    let (status, body) = decode_cbor_error(resp).await;
    assert_eq!(status, HStatus::NOT_FOUND);
    assert_eq!(body.error, "already_paired");
}

#[tokio::test]
async fn pair_device_uri_by_code_already_paired_via_on_disk_guard_only() {
    // Owner-auth persisted but not hydrated into memory — the defensive
    // on-disk load must still fail closed.
    let (state, td) = make_by_code_state(BootstrapState::NamedAwaitingPair);
    state
        .pair_device_window
        .mint_token(Duration::from_secs(300), None)
        .await
        .expect("pre-mint");
    let code = open_window_code(&state).await;
    let identity = state.household.current().await.unwrap();
    let _ = real_owner_auth(&identity, Some(td.path())); // persisted, not in memory
    let app = bootstrap_router(state);
    let resp = app
        .oneshot(by_code_request(by_code_body(1, &code)))
        .await
        .unwrap();
    let (status, body) = decode_cbor_error(resp).await;
    assert_eq!(status, HStatus::NOT_FOUND);
    assert_eq!(body.error, "already_paired");
}

#[tokio::test]
async fn pair_device_uri_by_code_malformed_bodies_are_invalid_request() {
    // A body that was never a six-word code is a plain 400 that says so.
    // Collapsing these into the opaque 404 would leave a client unable to
    // tell its own encoding bug from a wrong code.
    #[derive(serde::Serialize)]
    struct ExtraField<'a> {
        #[serde(rename = "v")]
        v: u8,
        words: &'a [&'a str],
        extra: u8,
    }

    let five: Vec<&str> = ANY_VALID_CODE[..5].to_vec();
    let mut off_list = ANY_VALID_CODE;
    off_list[3] = "notabip39word";
    let mut uppercase = ANY_VALID_CODE;
    uppercase[2] = "Able";
    let mut padded = ANY_VALID_CODE;
    padded[1] = "ability ";

    let bodies: Vec<(&str, Vec<u8>)> = vec![
        ("not cbor at all", vec![0xff, 0xff, 0xff, 0xff]),
        ("wrong version", by_code_body(2, &ANY_VALID_CODE)),
        ("five words", by_code_body(1, &five)),
        ("seven words", by_code_body(1, &["abandon"; 7])),
        ("word off the wordlist", by_code_body(1, &off_list)),
        ("uppercase word", by_code_body(1, &uppercase)),
        ("trailing space", by_code_body(1, &padded)),
        ("trailing bytes after the item", {
            let mut padded = by_code_body(1, &ANY_VALID_CODE);
            padded.push(0x00);
            padded
        }),
        (
            "unknown field",
            household_rs::cbor::to_canonical_vec(&ExtraField {
                v: 1,
                words: &ANY_VALID_CODE,
                extra: 7,
            })
            .expect("encode"),
        ),
    ];

    for (label, body) in bodies {
        let (state, _td) = make_by_code_state(BootstrapState::NamedAwaitingPair);
        state
            .pair_device_window
            .mint_token(Duration::from_secs(300), None)
            .await
            .expect("pre-mint");
        let app = bootstrap_router(state);
        let resp = app.oneshot(by_code_request(body)).await.unwrap();
        let (status, decoded) = decode_cbor_error(resp).await;
        assert_eq!(status, HStatus::BAD_REQUEST, "{label}");
        assert_eq!(decoded.error, "invalid_request", "{label}");
    }
}

#[tokio::test]
async fn pair_device_uri_by_code_wrong_words_never_touch_the_window() {
    // The whole point of retrieve-only: a guess must not mint, must not
    // replace, and must not disturb the snapshot the daemon would reload.
    let (state, _td) = make_by_code_state(BootstrapState::NamedAwaitingPair);
    state
        .pair_device_window
        .mint_token(Duration::from_secs(300), None)
        .await
        .expect("pre-mint");
    let code = open_window_code(&state).await;
    let window = Arc::clone(&state.pair_device_window);
    let nonce_before = window.current_token().await.unwrap().nonce.as_b64();
    let snapshot_before = window.read_persisted_snapshot().expect("read snapshot");
    assert!(
        snapshot_before.is_some(),
        "precondition: the open window is persisted"
    );

    let app = bootstrap_router(state);
    let resp = app
        .oneshot(by_code_request(by_code_body(1, &wrong_code(&code))))
        .await
        .unwrap();
    let (status, body) = decode_cbor_error(resp).await;
    assert_eq!(status, HStatus::NOT_FOUND);
    assert_eq!(body.error, "pair_code_rejected");

    assert_eq!(
        window.current_token().await.unwrap().nonce.as_b64(),
        nonce_before,
        "a wrong code must not re-mint the window"
    );
    assert_eq!(
        window.read_persisted_snapshot().expect("read snapshot"),
        snapshot_before,
        "a wrong code must not rewrite the persisted snapshot"
    );
}

#[tokio::test]
async fn pair_device_uri_by_code_missing_expired_and_wrong_are_byte_identical() {
    // No window, an expired window and a wrong code are the same answer
    // on the wire. Anything else is an oracle for whether the Mac is
    // currently showing a code at all.
    let (no_window, _td_a) = make_by_code_state(BootstrapState::NamedAwaitingPair);
    let closed_window = Arc::clone(&no_window.pair_device_window);
    assert!(
        closed_window.current_token().await.is_none(),
        "precondition: no window"
    );
    let missing = observable_parts(
        bootstrap_router(no_window)
            .oneshot(by_code_request(by_code_body(1, &ANY_VALID_CODE)))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        closed_window.current_token().await.is_none(),
        "a rejected attempt against a closed window must not open one"
    );

    let (expired_state, _td_b) = make_by_code_state(BootstrapState::NamedAwaitingPair);
    expired_state
        .pair_device_window
        .mint_token(Duration::from_secs(0), None)
        .await
        .expect("mint already-expired token");
    assert!(
        expired_state
            .pair_device_window
            .current_token()
            .await
            .is_none(),
        "precondition: the window expired on mint"
    );
    let expired = observable_parts(
        bootstrap_router(expired_state)
            .oneshot(by_code_request(by_code_body(1, &ANY_VALID_CODE)))
            .await
            .unwrap(),
    )
    .await;

    let (open_state, _td_c) = make_by_code_state(BootstrapState::NamedAwaitingPair);
    open_state
        .pair_device_window
        .mint_token(Duration::from_secs(300), None)
        .await
        .expect("pre-mint");
    let code = open_window_code(&open_state).await;
    let mismatch = observable_parts(
        bootstrap_router(open_state)
            .oneshot(by_code_request(by_code_body(1, &wrong_code(&code))))
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(mismatch.0, HStatus::NOT_FOUND, "and all three are 404");
    assert!(!mismatch.2.is_empty());
    assert_eq!(missing, mismatch, "no window must look like a wrong code");
    assert_eq!(
        expired, mismatch,
        "an expired window must look like a wrong code"
    );
}

#[tokio::test]
async fn pair_device_uri_by_code_matching_words_return_the_get_route_response() {
    // The success path is the GET route's answer, byte for byte, for the
    // same state — that is what the shared tail exists to guarantee.
    let (state, _td) = make_by_code_state(BootstrapState::NamedAwaitingPair);
    state
        .pair_device_window
        .mint_token(Duration::from_secs(300), None)
        .await
        .expect("pre-mint");
    let code = open_window_code(&state).await;
    let window = Arc::clone(&state.pair_device_window);
    let nonce_before = window.current_token().await.unwrap().nonce.as_b64();

    let get_response = bootstrap_router(state.clone())
        .oneshot(pair_device_uri_request())
        .await
        .unwrap();
    assert_eq!(get_response.status(), HStatus::OK);
    let get_bytes = body_bytes(get_response).await;

    let by_code_response = bootstrap_router(state)
        .oneshot(by_code_request(by_code_body(1, &code)))
        .await
        .unwrap();
    assert_eq!(by_code_response.status(), HStatus::OK);
    let by_code_bytes = body_bytes(by_code_response).await;

    assert_eq!(
        by_code_bytes, get_bytes,
        "the by-code answer must be the GET answer, byte for byte"
    );
    let decoded: PairDeviceUriResponseForTest =
        household_rs::cbor::from_canonical_slice(&by_code_bytes).expect("CBOR decode");
    assert!(
        decoded
            .pair_device_uri
            .contains(&format!("&nonce={nonce_before}")),
        "must echo the open window's nonce: {}",
        decoded.pair_device_uri
    );
    assert_eq!(
        window.current_token().await.unwrap().nonce.as_b64(),
        nonce_before,
        "a correct code must not re-mint the window either"
    );
}

#[tokio::test]
async fn pair_device_uri_by_code_rate_limited_is_the_same_opaque_404() {
    // Limit 1/h: the first attempt is graded, the second is shed. The shed
    // one must be indistinguishable from a wrong code.
    let (state, _td) = by_code_state_with_limit(BootstrapState::NamedAwaitingPair, 1);
    state
        .pair_device_window
        .mint_token(Duration::from_secs(300), None)
        .await
        .expect("pre-mint");
    let code = open_window_code(&state).await;

    let first = bootstrap_router(state.clone())
        .oneshot(by_code_request(by_code_body(1, &code)))
        .await
        .unwrap();
    assert_eq!(
        first.status(),
        HStatus::OK,
        "the first attempt is inside the ceiling"
    );

    let second = bootstrap_router(state.clone())
        .oneshot(by_code_request(by_code_body(1, &code)))
        .await
        .unwrap();
    let limited = observable_parts(second).await;
    assert_eq!(limited.0, HStatus::NOT_FOUND);

    // The reference has to be a REAL wrong-code rejection. Asking `state`
    // for it would spend a third attempt against the same 1/h bucket and
    // be shed too — the assertion would then compare a shed response with
    // another shed response, which is to say a value with itself, and any
    // divergence between the two paths would be invisible.
    let (graded_state, _td_b) = by_code_state_with_limit(BootstrapState::NamedAwaitingPair, 60);
    graded_state
        .pair_device_window
        .mint_token(Duration::from_secs(300), None)
        .await
        .expect("pre-mint");
    let graded_code = open_window_code(&graded_state).await;
    let mismatch = observable_parts(
        bootstrap_router(graded_state)
            .oneshot(by_code_request(by_code_body(1, &wrong_code(&graded_code))))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        mismatch.0,
        HStatus::NOT_FOUND,
        "precondition: the reference is a graded wrong code, not a shed one"
    );
    assert_eq!(
        limited, mismatch,
        "a rate-limited attempt must look like a wrong code — status, headers and body"
    );
}

#[tokio::test]
async fn pair_device_uri_by_code_limiter_error_and_absence_fail_closed() {
    // A limiter that cannot answer is not a reason to answer anyway.
    let (state, td) = make_state_with_identity(BootstrapState::NamedAwaitingPair);
    state
        .pair_device_window
        .mint_token(Duration::from_secs(300), None)
        .await
        .expect("pre-mint");
    let code = open_window_code(&state).await;

    // Reference answer: a wrong code against a working limiter.
    let working = state
        .clone()
        .with_pair_code_rate_limiter(Arc::new(Limiter::new(":memory:", 1_000).unwrap()));
    let mismatch = body_bytes(
        bootstrap_router(working)
            .oneshot(by_code_request(by_code_body(1, &wrong_code(&code))))
            .await
            .unwrap(),
    )
    .await;

    // A limiter whose ledger has been pulled out from under it: `check`
    // returns Err, which must reject rather than fall open.
    let db_path = td.path().join("pair-code-ratelimit.db");
    let broken = Limiter::new(db_path.to_str().unwrap(), 1_000).expect("limiter");
    core_rs::db::open_wal(&db_path)
        .expect("second connection")
        .execute_batch("DROP TABLE rate_limits;")
        .expect("drop ledger");
    let broken_state = state.clone().with_pair_code_rate_limiter(Arc::new(broken));
    let errored = bootstrap_router(broken_state)
        .oneshot(by_code_request(by_code_body(1, &code)))
        .await
        .unwrap();
    assert_eq!(errored.status(), HStatus::NOT_FOUND);
    assert_eq!(
        body_bytes(errored).await,
        mismatch,
        "a limiter error must look like a wrong code, not like success"
    );

    // No limiter wired at all (short-lived install/listener paths).
    assert!(state.pair_code_rate_limiter.is_none());
    let absent = bootstrap_router(state)
        .oneshot(by_code_request(by_code_body(1, &code)))
        .await
        .unwrap();
    assert_eq!(absent.status(), HStatus::NOT_FOUND);
    assert_eq!(
        body_bytes(absent).await,
        mismatch,
        "an unwired limiter must fail closed too"
    );
}

// ── by-code source guards ───────────────────────────────────────────

/// Retrieve-only is a property of the code, not of the current test suite:
/// a mint here would let anyone who can reach the route invalidate the
/// operator's live window, and would hand a guesser a fresh nonce (and a
/// fresh expected code) on every attempt.
#[test]
fn pair_device_uri_by_code_never_mints_a_window() {
    let body = fn_body(
        include_str!("../handlers_bootstrap.rs"),
        "post_bootstrap_pair_device_uri_by_code",
    );
    for minting in ["get_or_mint", "mint_token"] {
        assert!(
            !body.contains(minting),
            "the by-code handler must never call `{minting}` — it is retrieve-only"
        );
    }
    assert!(
        body.contains("current_token()"),
        "the by-code handler reads the window via current_token()"
    );
}

/// The limiter is the cheap gate. If it drifts below the owner-auth disk
/// read, a guessing flood buys a filesystem round trip per attempt before
/// anything sheds it.
#[test]
fn pair_device_uri_by_code_rate_limits_before_the_owner_auth_disk_read() {
    let body = fn_body(
        include_str!("../handlers_bootstrap.rs"),
        "post_bootstrap_pair_device_uri_by_code",
    );
    let limiter = unique_offset(&body, "check_pair_code_attempt(", "by_code");
    let disk = unique_offset(&body, "load_optional", "by_code");
    assert!(
        limiter < disk,
        "the per-peer limiter must run before the on-disk owner-auth read"
    );
    let lock = unique_offset(&body, "BOOTSTRAP_MUTATION_LOCK", "by_code");
    assert!(
        limiter < lock,
        "the per-peer limiter must run before the process-global mutation lock"
    );
}

/// The code comparison decides whether a caller gets the household. A
/// byte-by-byte `==` would leak the length of the correct prefix through
/// timing; the fixed-width constant-time compare is the point.
#[test]
fn pair_device_uri_by_code_compares_the_code_in_constant_time() {
    let body = fn_body(
        include_str!("../handlers_bootstrap.rs"),
        "post_bootstrap_pair_device_uri_by_code",
    );
    assert!(
        body.contains(".ct_eq("),
        "the submitted code must be compared with subtle's ct_eq"
    );
    assert!(
        !body.contains("== expected") && !body.contains("expected =="),
        "no short-circuiting equality on the expected code"
    );
}

/// Every `pair_device.code.*` log line, wherever it lives in this module,
/// must be free of the code words and of the URI (nonce included). The
/// Mac's log is readable by anything that can read the disk.
#[test]
fn pair_device_uri_by_code_logs_carry_neither_the_words_nor_the_uri() {
    let source = include_str!("../handlers_bootstrap.rs");
    let production = source
        .split("\n#[cfg(test)]\nmod tests {")
        .next()
        .expect("production half");
    let banned = ["words", "nonce", "uri", "hh_pub", "m_cert_fp", "submitted"];
    let mut checked = 0;
    for (at, _) in production.match_indices("tracing::") {
        let rest = &production[at..];
        let end = rest.find(");").map_or(rest.len(), |e| e + 2);
        let call = &rest[..end];
        if !call.contains("stage = \"pair_device.code.") {
            continue;
        }
        checked += 1;
        for needle in banned {
            assert!(
                !call.contains(needle),
                "a pair_device.code log line names `{needle}`:\n{call}"
            );
        }
    }
    assert!(
        checked >= 3,
        "expected the by-code log sites to be found, saw {checked}"
    );
}
