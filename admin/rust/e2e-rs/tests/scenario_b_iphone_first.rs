//! T050 — Integration test: iPhone-first `AirDrop` install flow (scenario B).
//!
//! Simulates the full sequence where Soyeht iPhone initiates a Mac install
//! before the user double-clicks Soyeht.dmg:
//!
//! ```text
//! iPhone:  mint token → publish _soyeht-setup._tcp. beacon
//! Mac:     receive AirDrop Soyeht.dmg → launch SoyehtMac.app
//! SoyehtMac.app: browse _soyeht-setup._tcp. → POST /bootstrap/claim-setup-invitation
//! Mac engine: callback-verify token with iPhone → persist invitation
//! iPhone:  POST /bootstrap/initialize (from Tailnet IP) → state = named_awaiting_pair
//! ```
//!
//! Tests in this file:
//!
//! 1. **`scenario_b_full_happy_path`** — complete flow from beacon through initialize.
//! 2. **`scenario_b_hijack_blocked_wrong_tailnet_ip`** — after claim, a different
//!    Tailnet IP tries `/bootstrap/initialize` → 403.
//! 3. **`scenario_b_hijack_blocked_lan_ip`** — after claim, LAN IP initialize → 403.
//! 4. **`scenario_b_second_claim_after_initialize_returns_409`** — engine already
//!    past uninitialized; second claim attempt is rejected.
//! 5. **`scenario_b_mac_normal_initialize_without_beacon`** — no iPhone beacon active;
//!    initialize proceeds as in scenario A (no IP guard).
//!
//! The "fake iPhone" is an in-process axum server on a random loopback port
//! that handles `POST /setup/verify` (echoing the token back → success) or
//! returns 404 (→ failure). No real Bonjour or `AirDrop` is involved.

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
use server_rs::setup_invitation::{SetupInvitationEntry, cache_insert};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower::ServiceExt;

// ── Constants ─────────────────────────────────────────────────────────────────

/// iPhone's Tailscale CGNAT address (100.64.0.0/10 — classified Tailnet).
const IPHONE_TAILNET_IP: &str = "100.64.10.5";
/// A different Tailnet IP — valid range but not the iPhone's registered address.
const ATTACKER_TAILNET_IP: &str = "100.64.99.1";
/// Plain LAN address — not Tailnet.
const LAN_IP: &str = "192.168.0.50";
/// Far-future timestamp so TTL checks always pass.
const FAR_FUTURE: u64 = 2_524_608_000;

// ── State helpers ─────────────────────────────────────────────────────────────

fn make_state_dir() -> PathBuf {
    let dir = tempfile::tempdir().unwrap().keep();
    std::fs::create_dir_all(dir.join("household")).unwrap();
    dir
}

fn make_bootstrap_state(bs: BootstrapState, state_dir: PathBuf) -> BootstrapHandlerState {
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
        // `7cf140ac` replaced the loose (port, resolver) pair with one
        // `PairingInstallation` that carries the profile too, so a Dev engine
        // can no longer be mistaken for a release one. These scenarios were
        // not updated with it and the whole workspace stopped compiling its
        // tests — found on 2026-09-06 while cutting 0.1.30.
        installation: server_rs::pairing_addresses::PairingInstallation::new("release".into(), 8091),
        invitation_verifier: server_rs::setup_invitation::callback_verify_blocking,
        phase3_runtime: None,
        pair_code_rate_limiter: None,
    }
}

// ── Mock iPhone /setup/verify server ─────────────────────────────────────────

/// Spawn a lightweight axum server on a random loopback port that echoes
/// `valid_token` back for `POST /setup/verify` (simulates iPhone still holding
/// the token and willing to confirm it).
async fn spawn_iphone_verify_server(valid_token: [u8; 32]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = Router::new().route(
        "/setup/verify",
        post(move |_body: Bytes| async move {
            #[derive(Serialize)]
            struct VerifyResp {
                v: u8,
                token: ByteBuf,
            }
            let bytes = household_rs::cbor::to_canonical_vec(&VerifyResp {
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

// ── Beacon simulation helper ──────────────────────────────────────────────────

/// Simulate the Mac engine's Bonjour browser discovering the iPhone's
/// `_soyeht-setup._tcp.` beacon: insert the entry directly into the cache.
async fn simulate_beacon_discovered(
    state: &BootstrapHandlerState,
    token: [u8; 32],
    iphone_endpoint: &str,
    owner: &str,
) {
    let entry = SetupInvitationEntry {
        token,
        iphone_endpoint: iphone_endpoint.to_string(),
        iphone_addrs: vec![IPHONE_TAILNET_IP.parse().unwrap()],
        owner_display_name: owner.to_string(),
        hh_id: None,
        expires_at: FAR_FUTURE,
    };
    cache_insert(&state.setup_invitation_cache, entry).await;
}

// ── CBOR builders ─────────────────────────────────────────────────────────────

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

fn cbor_initialize(name: &str) -> Vec<u8> {
    #[derive(Serialize)]
    struct Req<'a> {
        v: u8,
        name: &'a str,
    }
    household_rs::cbor::to_canonical_vec(&Req { v: 1, name }).unwrap()
}

// ── HTTP call helpers ─────────────────────────────────────────────────────────

async fn post_claim(app: Router, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
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

async fn post_initialize(
    app: Router,
    body: Vec<u8>,
    src_ip: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/bootstrap/initialize")
        .header("content-type", "application/cbor");
    if let Some(ip) = src_ip {
        let addr: SocketAddr = format!("{ip}:443").parse().unwrap();
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
}

#[derive(Deserialize)]
struct InitOk {
    #[serde(rename = "v")]
    _version: u8,
    hh_id: String,
    name: String,
    #[serde(with = "serde_bytes")]
    hh_pub: Vec<u8>,
}

#[derive(Deserialize)]
struct ErrResp {
    #[serde(rename = "v")]
    _version: u8,
    error: String,
}

fn err(bytes: &[u8]) -> ErrResp {
    household_rs::cbor::from_canonical_slice(bytes).expect("must decode as ErrResp")
}

// ═══════════════════════════════════════════════════════════════════════════════
// T050 Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Full scenario B happy path:
/// beacon → claim → initialize (from iPhone Tailnet IP) → `NamedAwaitingPair`.
#[tokio::test]
async fn scenario_b_full_happy_path() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    let dir = make_state_dir();
    let bs_arc: BootstrapStateArc = Arc::new(RwLock::new(BootstrapState::Uninitialized));

    // Phase 1: Verify initial state.
    let state = BootstrapHandlerState {
        bootstrap: Arc::clone(&bs_arc),
        household: HouseholdState::empty(),
        state_dir: dir.clone(),
        pair_device_window: Arc::new(PairDeviceWindow::new()),
        pair_machine_window: Arc::new(
            household_rs::pair_machine::PairMachineWindow::new_in_memory(),
        ),
        started_at: Instant::now(),
        setup_invitation_cache: server_rs::setup_invitation::new_cache(),
        // `7cf140ac` replaced the loose (port, resolver) pair with one
        // `PairingInstallation` that carries the profile too, so a Dev engine
        // can no longer be mistaken for a release one. These scenarios were
        // not updated with it and the whole workspace stopped compiling its
        // tests — found on 2026-09-06 while cutting 0.1.30.
        installation: server_rs::pairing_addresses::PairingInstallation::new("release".into(), 8091),
        invitation_verifier: server_rs::setup_invitation::callback_verify_blocking,
        phase3_runtime: None,
        pair_code_rate_limiter: None,
    };
    let (status, body) = {
        let app = bootstrap_router(state.clone());
        let req = Request::builder()
            .uri("/bootstrap/status")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let s = resp.status();
        let b = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        (s, v)
    };
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "uninitialized");

    // Phase 2: iPhone publishes beacon; SoyehtMac.app discovers it.
    let token = {
        let mut t = [0u8; 32];
        for (i, b) in t.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(7);
        }
        t
    };
    let iphone_server = spawn_iphone_verify_server(token).await;
    simulate_beacon_discovered(&state, token, &iphone_server.to_string(), "Sample Owner").await;

    // Phase 3: SoyehtMac.app POSTs claim-setup-invitation.
    let (status, body_bytes) =
        post_claim(bootstrap_router(state.clone()), cbor_claim(&token)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "claim must succeed for uninitialized engine"
    );
    let ack: ClaimAck =
        household_rs::cbor::from_canonical_slice(&body_bytes).expect("must decode ClaimAck");
    assert_eq!(ack.version, 1);
    assert_eq!(ack.iphone_endpoint, iphone_server.to_string());
    assert_eq!(ack.owner_display_name, "Sample Owner");
    assert!(ack.hh_id.is_none(), "fresh casa: hh_id must be null");

    // Verify invitation persisted.
    let persisted = server_rs::setup_invitation::load_persisted_invitation(&dir)
        .expect("load must succeed")
        .expect("invitation must be on disk after claim");
    assert_eq!(persisted.token.as_ref(), &token[..]);

    // Phase 4: Engine remains Uninitialized after claim (waiting for iPhone's initialize).
    {
        let bs = bs_arc.read().await;
        assert_eq!(
            *bs,
            BootstrapState::Uninitialized,
            "state must still be uninitialized after claim-only step"
        );
    }

    // Phase 5: iPhone POSTs initialize from its Tailnet IP → state advances.
    let (status, init_bytes) = post_initialize(
        bootstrap_router(state.clone()),
        cbor_initialize("Sample Home"),
        Some(IPHONE_TAILNET_IP),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "initialize from matching Tailnet IP must succeed"
    );
    let init: InitOk =
        household_rs::cbor::from_canonical_slice(&init_bytes).expect("must decode InitOk");
    assert!(init.hh_id.starts_with("hh_"));
    assert_eq!(init.name, "Sample Home");
    assert_eq!(init.hh_pub.len(), 33, "hh_pub must be 33-byte SEC1");

    // Phase 6: Verify in-memory state advanced.
    {
        let bs = bs_arc.read().await;
        assert_eq!(
            *bs,
            BootstrapState::NamedAwaitingPair,
            "bootstrap state must advance after iPhone-initiated initialize"
        );
    }

    // Phase 7: Verify persisted state.
    let persisted_state =
        household_rs::bootstrap_state::load(&dir).expect("bootstrap state must be persisted");
    assert_eq!(
        persisted_state,
        BootstrapState::NamedAwaitingPair,
        "persisted state must be named_awaiting_pair"
    );
}

/// After claim, a different Tailnet IP (attacker) tries to initialize → 403.
#[tokio::test]
async fn scenario_b_hijack_blocked_wrong_tailnet_ip() {
    let dir = make_state_dir();
    let state = make_bootstrap_state(BootstrapState::Uninitialized, dir.clone());

    let token = [0x42u8; 32];
    let iphone_server = spawn_iphone_verify_server(token).await;
    simulate_beacon_discovered(&state, token, &iphone_server.to_string(), "Owner").await;

    // Claim succeeds from Mac (no IP check on claim endpoint itself).
    let (status, _) = post_claim(bootstrap_router(state.clone()), cbor_claim(&token)).await;
    assert_eq!(status, StatusCode::OK, "claim must succeed");

    // Attacker from a different Tailnet IP tries to initialize.
    let (status, body) = post_initialize(
        bootstrap_router(state),
        cbor_initialize("Hacked Home"),
        Some(ATTACKER_TAILNET_IP),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "wrong Tailnet IP must be blocked even in Tailnet range"
    );
    assert_eq!(err(&body).error, "tailnet_required");
}

/// After claim, a LAN source IP tries to initialize → 403.
#[tokio::test]
async fn scenario_b_hijack_blocked_lan_ip() {
    let dir = make_state_dir();
    let state = make_bootstrap_state(BootstrapState::Uninitialized, dir.clone());

    let token = [0xBBu8; 32];
    let iphone_server = spawn_iphone_verify_server(token).await;
    simulate_beacon_discovered(&state, token, &iphone_server.to_string(), "Owner").await;

    let (status, _) = post_claim(bootstrap_router(state.clone()), cbor_claim(&token)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_initialize(
        bootstrap_router(state),
        cbor_initialize("LAN Home"),
        Some(LAN_IP),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err(&body).error, "tailnet_required");
}

/// After claim, missing `ConnectInfo` (no source IP) → 403.
#[tokio::test]
async fn scenario_b_hijack_blocked_no_connect_info() {
    let dir = make_state_dir();
    let state = make_bootstrap_state(BootstrapState::Uninitialized, dir.clone());

    let token = [0xCCu8; 32];
    let iphone_server = spawn_iphone_verify_server(token).await;
    simulate_beacon_discovered(&state, token, &iphone_server.to_string(), "Owner").await;

    let (status, _) = post_claim(bootstrap_router(state.clone()), cbor_claim(&token)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) =
        post_initialize(bootstrap_router(state), cbor_initialize("No-IP Home"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err(&body).error, "tailnet_required");
}

/// After the engine is past uninitialized, claim returns 409.
#[tokio::test]
async fn scenario_b_second_claim_after_initialize_returns_409() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    let dir = make_state_dir();
    let bs_arc: BootstrapStateArc = Arc::new(RwLock::new(BootstrapState::Uninitialized));
    let state = BootstrapHandlerState {
        bootstrap: Arc::clone(&bs_arc),
        household: HouseholdState::empty(),
        state_dir: dir.clone(),
        pair_device_window: Arc::new(PairDeviceWindow::new()),
        pair_machine_window: Arc::new(
            household_rs::pair_machine::PairMachineWindow::new_in_memory(),
        ),
        started_at: Instant::now(),
        setup_invitation_cache: server_rs::setup_invitation::new_cache(),
        // `7cf140ac` replaced the loose (port, resolver) pair with one
        // `PairingInstallation` that carries the profile too, so a Dev engine
        // can no longer be mistaken for a release one. These scenarios were
        // not updated with it and the whole workspace stopped compiling its
        // tests — found on 2026-09-06 while cutting 0.1.30.
        installation: server_rs::pairing_addresses::PairingInstallation::new("release".into(), 8091),
        invitation_verifier: server_rs::setup_invitation::callback_verify_blocking,
        phase3_runtime: None,
        pair_code_rate_limiter: None,
    };

    // Claim and initialize to advance state.
    let token = [0xDDu8; 32];
    let iphone_server = spawn_iphone_verify_server(token).await;
    simulate_beacon_discovered(&state, token, &iphone_server.to_string(), "Owner").await;
    let (status, _) = post_claim(bootstrap_router(state.clone()), cbor_claim(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post_initialize(
        bootstrap_router(state.clone()),
        cbor_initialize("DD Home"),
        Some(IPHONE_TAILNET_IP),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Second claim attempt → engine already past uninitialized → 409.
    let (status, body) = post_claim(bootstrap_router(state), cbor_claim(&token)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(err(&body).error, "already_initialized");
}

/// No iPhone beacon active: Mac initializes normally (scenario A path, no IP guard).
#[tokio::test]
async fn scenario_b_mac_normal_initialize_without_beacon() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");

    let dir = make_state_dir();
    let state = make_bootstrap_state(BootstrapState::Uninitialized, dir);

    // No claim, no invitation on disk. Initialize without ConnectInfo — guard inactive.
    let (status, bytes) = post_initialize(
        bootstrap_router(state),
        cbor_initialize("Normal Home"),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "without invitation, initialize must succeed regardless of source IP"
    );
    let init: InitOk =
        household_rs::cbor::from_canonical_slice(&bytes).expect("must decode InitOk");
    assert!(init.hh_id.starts_with("hh_"));
    assert_eq!(init.name, "Normal Home");
}
