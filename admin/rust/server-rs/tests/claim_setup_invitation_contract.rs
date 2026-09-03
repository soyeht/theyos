//! T049 — Contract tests for `POST /bootstrap/claim-setup-invitation`
//! and T054 IP-source guard on `POST /bootstrap/initialize`.
//!
//! Coverage:
//!
//! **`POST /bootstrap/claim-setup-invitation`**:
//! - 409 when engine not in `uninitialized` state
//! - 400 on invalid CBOR, wrong version, or token wrong size
//! - 401 when token not found in Bonjour cache
//! - 404 when token TTL expired (`now >= expires_at`)
//! - 401 when iPhone callback verify fails (server returns 404)
//! - 401 when iPhone endpoint is unreachable
//! - 200 success — correct Ack shape + invitation persisted to disk
//! - 200 with optional `iphone_apns_token` field stored on disk
//! - 200 with `hh_id` populated (iPhone joining existing casa)
//!
//! **`POST /bootstrap/initialize` IP guard (T054)**:
//! - 403 when invitation pending and `ConnectInfo` absent
//! - 403 when invitation pending and source IP is LAN
//! - 403 when invitation pending and source IP is Tailnet but not iPhone's
//! - 200 when invitation pending and source IP matches iPhone's Tailnet address
//! - 200 when no invitation pending (guard not active — no `ConnectInfo` required)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
    routing::post,
};
use core_rs::env::set_test_env;
use household_rs::bootstrap_state::BootstrapState;
use household_rs::pair_device::PairDeviceWindow;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use server_rs::handlers_bootstrap::{BootstrapHandlerState, BootstrapStateArc, bootstrap_router};
use server_rs::household_state::HouseholdState;
use server_rs::setup_invitation::{
    SetupInvitationEntry, cache_insert, load_persisted_invitation, persist_invitation,
};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower::ServiceExt;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Tailscale CGNAT address in 100.64.0.0/10 — classified as Tailnet.
const IPHONE_TAILNET_IP: &str = "100.64.1.1";
/// Plain LAN address — classified as `LocalNetwork`, not Tailnet.
const LAN_IP: &str = "192.168.1.10";
/// A different Tailnet IP — valid range but not the iPhone's registered IP.
const OTHER_TAILNET_IP: &str = "100.64.2.2";

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn test_token() -> [u8; 32] {
    let mut t = [0u8; 32];
    for (i, b) in t.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    t
}

fn other_token() -> [u8; 32] {
    let mut t = [0xFFu8; 32];
    t[0] = 0xAA;
    t
}

/// Far-future Unix timestamp (~year 2050), so TTL checks always pass.
const FAR_FUTURE: u64 = 2_524_608_000;

// ── State builder ─────────────────────────────────────────────────────────────

fn make_state_dir() -> PathBuf {
    let dir = tempfile::tempdir().unwrap().keep();
    std::fs::create_dir_all(dir.join("household")).unwrap();
    dir
}

/// Default test resolver returns `None` so `mac_engine_url` is omitted
/// from the ACK and existing assertions continue to hold.
fn no_tailnet() -> Option<std::net::Ipv4Addr> {
    None
}

/// Test resolver returning a privacy-safe Tailnet fixture. Matches
/// `TailnetResolver`'s fn-pointer signature exactly, so the body is
/// unconditionally `Some(_)`.
#[allow(clippy::unnecessary_wraps)]
fn fixed_tailnet_ip() -> Option<std::net::Ipv4Addr> {
    Some(std::net::Ipv4Addr::new(100, 64, 0, 10))
}

fn make_state(bs: BootstrapState, state_dir: PathBuf) -> BootstrapHandlerState {
    BootstrapHandlerState {
        bootstrap: Arc::new(RwLock::new(bs)) as BootstrapStateArc,
        household: HouseholdState::empty(),
        state_dir,
        pair_device_window: Arc::new(PairDeviceWindow::new()),
        pair_machine_window: Arc::new(
            household_rs::pair_machine::PairMachineWindow::new_in_memory(),
        ),
        started_at: Instant::now(),
        setup_invitation_cache: server_rs::setup_invitation::new_cache(),
        engine_port: 8091,
        tailnet_resolver: no_tailnet,
        phase3_runtime: None,
        pair_code_rate_limiter: None,
    }
}

// ── Mock iPhone /setup/verify servers ─────────────────────────────────────────

/// Spawn a mock `POST /setup/verify` that echoes `valid_token` back (success).
async fn spawn_mock_iphone_ok(valid_token: [u8; 32]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = Router::new().route(
        "/setup/verify",
        post(move |_body: Bytes| async move {
            #[derive(Serialize)]
            struct Resp {
                v: u8,
                token: ByteBuf,
            }
            let bytes = household_rs::cbor::to_canonical_vec(&Resp {
                v: 1,
                token: ByteBuf::from(valid_token.to_vec()),
            })
            .unwrap_or_default();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/cbor")],
                bytes,
            )
        }),
    );

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    addr
}

/// Spawn a mock `POST /setup/verify` that always returns 404 (failure).
async fn spawn_mock_iphone_fail() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = Router::new().route("/setup/verify", post(|| async { StatusCode::NOT_FOUND }));

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    addr
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

fn make_entry(token: [u8; 32], iphone_endpoint: &str, expires_at: u64) -> SetupInvitationEntry {
    SetupInvitationEntry {
        token,
        iphone_endpoint: iphone_endpoint.to_string(),
        iphone_addrs: vec![IPHONE_TAILNET_IP.parse().unwrap()],
        owner_display_name: "Test User".to_string(),
        hh_id: None,
        expires_at,
    }
}

async fn populate_cache(state: &BootstrapHandlerState, entry: SetupInvitationEntry) {
    cache_insert(&state.setup_invitation_cache, entry).await;
}

// ── CBOR request builders ─────────────────────────────────────────────────────

fn cbor_claim(token: &[u8]) -> Vec<u8> {
    #[derive(Serialize)]
    struct Req<'a> {
        v: u8,
        token: &'a serde_bytes::Bytes,
    }
    household_rs::cbor::to_canonical_vec(&Req {
        v: 1,
        token: serde_bytes::Bytes::new(token),
    })
    .unwrap()
}

fn cbor_claim_wrong_version(token: &[u8]) -> Vec<u8> {
    #[derive(Serialize)]
    struct Req<'a> {
        v: u8,
        token: &'a serde_bytes::Bytes,
    }
    household_rs::cbor::to_canonical_vec(&Req {
        v: 99,
        token: serde_bytes::Bytes::new(token),
    })
    .unwrap()
}

fn cbor_claim_with_apns(token: &[u8], apns: &[u8]) -> Vec<u8> {
    #[derive(Serialize)]
    struct Req<'a> {
        v: u8,
        token: &'a serde_bytes::Bytes,
        iphone_apns_token: &'a serde_bytes::Bytes,
    }
    household_rs::cbor::to_canonical_vec(&Req {
        v: 1,
        token: serde_bytes::Bytes::new(token),
        iphone_apns_token: serde_bytes::Bytes::new(apns),
    })
    .unwrap()
}

fn cbor_initialize(name: &str) -> Vec<u8> {
    #[derive(Serialize)]
    struct Req<'a> {
        v: u8,
        name: &'a str,
    }
    household_rs::cbor::to_canonical_vec(&Req { v: 1, name }).unwrap()
}

// ── HTTP call helpers ─────────────────────────────────────────────────────────

async fn call_claim(state: BootstrapHandlerState, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let app = bootstrap_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/bootstrap/claim-setup-invitation")
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

/// Call `POST /bootstrap/initialize`. `src_ip` is a bare IP string
/// (`"100.64.1.1"`) or `None` for no `ConnectInfo` header.
async fn call_initialize(
    state: BootstrapHandlerState,
    body: Vec<u8>,
    src_ip: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let app = bootstrap_router(state);
    let mut builder = Request::builder()
        .method("POST")
        .uri("/bootstrap/initialize")
        .header("content-type", "application/cbor");
    if let Some(ip) = src_ip {
        let addr: SocketAddr = format!("{ip}:1234").parse().unwrap();
        builder = builder.extension(ConnectInfo::<SocketAddr>(addr));
    }
    let req = builder.body(Body::from(body)).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

// ── Response decoders ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ClaimAck {
    #[serde(rename = "v")]
    version: u8,
    iphone_endpoint: String,
    owner_display_name: String,
    hh_id: Option<String>,
    #[serde(default)]
    mac_engine_url: Option<String>,
}

#[derive(Deserialize)]
struct ErrBody {
    #[serde(rename = "v")]
    version: u8,
    error: String,
}

fn decode_err(bytes: &[u8]) -> ErrBody {
    household_rs::cbor::from_canonical_slice(bytes).expect("must decode as ErrBody")
}

fn decode_ack(bytes: &[u8]) -> ClaimAck {
    household_rs::cbor::from_canonical_slice(bytes).expect("must decode as ClaimAck")
}

// ── Helper: pre-write a pending invitation to the state_dir ──────────────────

fn write_pending_invitation(state_dir: &std::path::Path) {
    persist_invitation(
        state_dir,
        &make_entry(test_token(), "127.0.0.1:9999", FAR_FUTURE),
        None,
    )
    .expect("persist_invitation must succeed in test");
}

// ═══════════════════════════════════════════════════════════════════════════════
// State gate (409)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn claim_409_when_named_awaiting_pair() {
    let state = make_state(BootstrapState::NamedAwaitingPair, make_state_dir());
    let (status, body) = call_claim(state, cbor_claim(&test_token())).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(decode_err(&body).error, "already_initialized");
}

#[tokio::test]
async fn claim_409_when_ready() {
    let state = make_state(BootstrapState::Ready, make_state_dir());
    let (status, body) = call_claim(state, cbor_claim(&test_token())).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(decode_err(&body).error, "already_initialized");
}

#[tokio::test]
async fn claim_409_when_recovering() {
    let state = make_state(BootstrapState::Recovering, make_state_dir());
    let (status, body) = call_claim(state, cbor_claim(&test_token())).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(decode_err(&body).error, "already_initialized");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Body validation (400)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn claim_400_on_empty_body() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let (status, body) = call_claim(state, vec![]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_request");
}

#[tokio::test]
async fn claim_400_on_garbage_body() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let (status, body) = call_claim(state, b"not cbor at all".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_request");
}

#[tokio::test]
async fn claim_400_on_wrong_version() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let (status, body) = call_claim(state, cbor_claim_wrong_version(&test_token())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_request");
}

#[tokio::test]
async fn claim_400_on_token_31_bytes() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let (status, body) = call_claim(state, cbor_claim(&[0xABu8; 31])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_request");
}

#[tokio::test]
async fn claim_400_on_token_33_bytes() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let (status, body) = call_claim(state, cbor_claim(&[0xABu8; 33])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_request");
}

#[tokio::test]
async fn claim_error_responses_include_v1() {
    let state = make_state(BootstrapState::Ready, make_state_dir());
    let (_, body) = call_claim(state, cbor_claim(&test_token())).await;
    assert_eq!(decode_err(&body).version, 1, "v field must always be 1");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cache lookup (401)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn claim_401_when_cache_empty() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let (status, body) = call_claim(state, cbor_claim(&test_token())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(decode_err(&body).error, "invitation_not_recognized");
}

#[tokio::test]
async fn claim_401_when_different_token_in_cache() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    populate_cache(
        &state,
        make_entry(other_token(), "127.0.0.1:9999", FAR_FUTURE),
    )
    .await;
    let (status, body) = call_claim(state, cbor_claim(&test_token())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(decode_err(&body).error, "invitation_not_recognized");
}

// ═══════════════════════════════════════════════════════════════════════════════
// TTL check (404)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn claim_404_when_token_expired() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    // expires_at = 1 is firmly in the past.
    populate_cache(&state, make_entry(test_token(), "127.0.0.1:9999", 1)).await;
    let (status, body) = call_claim(state, cbor_claim(&test_token())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(decode_err(&body).error, "invitation_expired");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Callback verify (401)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn claim_401_when_callback_returns_404() {
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    let fail_addr = spawn_mock_iphone_fail().await;
    populate_cache(
        &state,
        make_entry(test_token(), &fail_addr.to_string(), FAR_FUTURE),
    )
    .await;
    let (status, body) = call_claim(state, cbor_claim(&test_token())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(decode_err(&body).error, "invitation_not_recognized");
}

#[tokio::test]
async fn claim_401_when_callback_unreachable() {
    // Get a port that has no listener by binding then dropping.
    let dead_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let state = make_state(BootstrapState::Uninitialized, make_state_dir());
    populate_cache(
        &state,
        make_entry(test_token(), &format!("127.0.0.1:{dead_port}"), FAR_FUTURE),
    )
    .await;
    let (status, body) = call_claim(state, cbor_claim(&test_token())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(decode_err(&body).error, "invitation_not_recognized");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Success path (200)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn claim_200_response_shape() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let token = test_token();
    let mock_addr = spawn_mock_iphone_ok(token).await;
    let entry = SetupInvitationEntry {
        token,
        iphone_endpoint: mock_addr.to_string(),
        iphone_addrs: vec![IPHONE_TAILNET_IP.parse().unwrap()],
        owner_display_name: "Sample Owner".to_string(),
        hh_id: None,
        expires_at: FAR_FUTURE,
    };
    populate_cache(&state, entry).await;

    let (status, body) = call_claim(state, cbor_claim(&token)).await;
    assert_eq!(status, StatusCode::OK, "unexpected body: {body:?}");
    let ack = decode_ack(&body);
    assert_eq!(ack.version, 1, "v must be 1");
    assert_eq!(ack.iphone_endpoint, mock_addr.to_string());
    assert_eq!(ack.owner_display_name, "Sample Owner");
    assert!(ack.hh_id.is_none(), "hh_id must be null for fresh casa");
}

#[tokio::test]
async fn claim_200_with_hh_id_for_existing_casa() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let token = test_token();
    let mock_addr = spawn_mock_iphone_ok(token).await;
    populate_cache(
        &state,
        SetupInvitationEntry {
            token,
            iphone_endpoint: mock_addr.to_string(),
            iphone_addrs: vec![IPHONE_TAILNET_IP.parse().unwrap()],
            owner_display_name: "Owner".to_string(),
            hh_id: Some("hh_existing123".to_string()),
            expires_at: FAR_FUTURE,
        },
    )
    .await;

    let (status, body) = call_claim(state, cbor_claim(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let ack = decode_ack(&body);
    assert_eq!(
        ack.hh_id.as_deref(),
        Some("hh_existing123"),
        "hh_id must be forwarded from Bonjour entry"
    );
}

#[tokio::test]
async fn claim_200_persists_invitation_to_disk() {
    let dir = make_state_dir();
    let state_dir = dir.clone();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let token = test_token();
    let mock_addr = spawn_mock_iphone_ok(token).await;
    populate_cache(
        &state,
        make_entry(token, &mock_addr.to_string(), FAR_FUTURE),
    )
    .await;

    let (status, _) = call_claim(state, cbor_claim(&token)).await;
    assert_eq!(status, StatusCode::OK);

    let persisted = load_persisted_invitation(&state_dir)
        .expect("load must succeed")
        .expect("invitation must be on disk");
    assert_eq!(
        persisted.token.as_ref(),
        &token[..],
        "token must be persisted verbatim"
    );
    assert_eq!(persisted.owner_display_name, "Test User");
    assert!(
        persisted.iphone_apns_token.is_none(),
        "no APNs token in request"
    );
}

#[tokio::test]
async fn claim_200_includes_mac_engine_url_when_tailnet_available() {
    // Inject a deterministic resolver so this test does not depend on the
    // test host having a real Tailscale interface.
    let dir = make_state_dir();
    let mut state = make_state(BootstrapState::Uninitialized, dir);
    state.engine_port = 8091;
    state.tailnet_resolver = fixed_tailnet_ip;
    let token = test_token();
    let mock_addr = spawn_mock_iphone_ok(token).await;
    populate_cache(
        &state,
        make_entry(token, &mock_addr.to_string(), FAR_FUTURE),
    )
    .await;

    let (status, body) = call_claim(state, cbor_claim(&token)).await;
    assert_eq!(status, StatusCode::OK, "unexpected body: {body:?}");
    let ack = decode_ack(&body);
    assert_eq!(
        ack.mac_engine_url.as_deref(),
        Some("http://100.64.0.10:8091"),
        "engine must steer iPhone to its OWN Tailnet IPv4 + bound port",
    );
}

#[tokio::test]
async fn claim_200_omits_mac_engine_url_when_no_tailnet() {
    // Default resolver in `make_state` returns None — ACK must omit the field
    // so the Soyeht.app keeps its existing local-discovery URL.
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let token = test_token();
    let mock_addr = spawn_mock_iphone_ok(token).await;
    populate_cache(
        &state,
        make_entry(token, &mock_addr.to_string(), FAR_FUTURE),
    )
    .await;

    let (status, body) = call_claim(state, cbor_claim(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let ack = decode_ack(&body);
    assert!(
        ack.mac_engine_url.is_none(),
        "mac_engine_url must be omitted when engine has no Tailnet IP, got {:?}",
        ack.mac_engine_url,
    );
}

#[tokio::test]
async fn claim_200_apns_token_persisted_when_provided() {
    let dir = make_state_dir();
    let state_dir = dir.clone();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let token = test_token();
    let apns = [0xAAu8; 32];
    let mock_addr = spawn_mock_iphone_ok(token).await;
    populate_cache(
        &state,
        make_entry(token, &mock_addr.to_string(), FAR_FUTURE),
    )
    .await;

    let (status, _) = call_claim(state, cbor_claim_with_apns(&token, &apns)).await;
    assert_eq!(status, StatusCode::OK);

    let persisted = load_persisted_invitation(&state_dir)
        .unwrap()
        .expect("invitation must be on disk");
    let stored_apns = persisted
        .iphone_apns_token
        .expect("APNs token must be persisted");
    assert_eq!(stored_apns.as_ref(), &apns[..]);
}

// ═══════════════════════════════════════════════════════════════════════════════
// T054: /bootstrap/initialize IP-source guard
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn initialize_403_no_connect_info_when_invitation_pending() {
    let dir = make_state_dir();
    write_pending_invitation(&dir);
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, cbor_initialize("Test Home"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(decode_err(&body).error, "tailnet_required");
}

#[tokio::test]
async fn initialize_403_lan_ip_when_invitation_pending() {
    let dir = make_state_dir();
    write_pending_invitation(&dir);
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, cbor_initialize("Test Home"), Some(LAN_IP)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(decode_err(&body).error, "tailnet_required");
}

#[tokio::test]
async fn initialize_403_tailnet_ip_mismatch_when_invitation_pending() {
    let dir = make_state_dir();
    write_pending_invitation(&dir);
    let state = make_state(BootstrapState::Uninitialized, dir);
    // OTHER_TAILNET_IP is valid Tailnet but not the iPhone's registered address.
    let (status, body) =
        call_initialize(state, cbor_initialize("Test Home"), Some(OTHER_TAILNET_IP)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(decode_err(&body).error, "tailnet_required");
}

#[tokio::test]
async fn initialize_200_when_no_invitation_pending_no_connect_info() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let dir = make_state_dir();
    // No invitation file — IP guard is inactive; ConnectInfo not required.
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, _) = call_initialize(state, cbor_initialize("Open Home"), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn initialize_200_matching_iphone_tailnet_ip_when_invitation_pending() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let dir = make_state_dir();
    // write_pending_invitation records IPHONE_TAILNET_IP as the iPhone's address.
    write_pending_invitation(&dir);
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, _) = call_initialize(
        state,
        cbor_initialize("iPhone Home"),
        Some(IPHONE_TAILNET_IP),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "matching Tailnet IP must be allowed through"
    );
}
