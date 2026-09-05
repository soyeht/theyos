//! Contract tests for `POST /bootstrap/pair-machine/local/stage` — the daemon-side
//! pair-machine staging route the SoyehtMac.app join flow drives.
//!
//! These cover the route's deterministic guard contract: the loopback-only ACL,
//! the engine-state gate, and the two request-validation branches. The 200 happy
//! path is intentionally not asserted here — `stage()` resolves a real LAN/tailnet
//! transport address (`pick_addr_for_transport`) and returns `NoTransportAddress`
//! when none is available, so a success assertion would be environment-dependent.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use household_rs::bootstrap_state::BootstrapState;
use household_rs::pair_device::PairDeviceWindow;
use serde::Deserialize;
use server_rs::handlers_bootstrap::{BootstrapHandlerState, BootstrapStateArc, bootstrap_router};
use server_rs::household_state::HouseholdState;
use tokio::sync::RwLock;
use tower::ServiceExt;

const STAGE_URI: &str = "/bootstrap/pair-machine/local/stage";
// Loopback peer that passes the ACL; non-loopback uses TEST-NET-3 (doc-safe).
const LOOPBACK_PEER: &str = "127.0.0.1:12345";
const NON_LOOPBACK_PEER: &str = "203.0.113.10:443";

fn make_state_dir() -> PathBuf {
    let dir = tempfile::tempdir().unwrap().keep();
    std::fs::create_dir_all(dir.join("household")).unwrap();
    dir
}


fn make_state(bs: BootstrapState) -> BootstrapHandlerState {
    BootstrapHandlerState {
        bootstrap: Arc::new(RwLock::new(bs)) as BootstrapStateArc,
        household: HouseholdState::empty(),
        state_dir: make_state_dir(),
        pair_device_window: Arc::new(PairDeviceWindow::new()),
        pair_machine_window: Arc::new(
            household_rs::pair_machine::PairMachineWindow::new_in_memory(),
        ),
        started_at: Instant::now(),
        setup_invitation_cache: server_rs::setup_invitation::new_cache(),
        installation: server_rs::pairing_addresses::PairingInstallation::new("release".into(), 8091),
        invitation_verifier: server_rs::setup_invitation::callback_verify_blocking,
        phase3_runtime: None,
        pair_code_rate_limiter: None,
    }
}

/// Drive the stage route with an explicit `ConnectInfo` peer (the route reads the
/// peer address from request `ConnectInfo`, injected here as a request extension).
async fn call_stage(
    state: BootstrapHandlerState,
    peer: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let addr: SocketAddr = peer.parse().unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(STAGE_URI)
        .extension(ConnectInfo::<SocketAddr>(addr))
        .body(Body::from(body))
        .unwrap();
    let resp = bootstrap_router(state).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

#[derive(Deserialize)]
struct ErrBody {
    #[serde(rename = "v")]
    _version: u8,
    error: String,
    #[serde(default)]
    _reason: Option<String>,
    #[serde(default)]
    _state: Option<String>,
}

fn decode_err(bytes: &[u8]) -> ErrBody {
    household_rs::cbor::from_canonical_slice(bytes).unwrap()
}

#[tokio::test]
async fn stage_returns_404_for_non_loopback_peer() {
    // The route hides its shape from off-box callers: a non-loopback peer gets the
    // same bare 404 a missing route would, with no CBOR body to fingerprint.
    let (status, body) = call_stage(
        make_state(BootstrapState::Uninitialized),
        NON_LOOPBACK_PEER,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.is_empty(),
        "non-loopback rejection must not leak a body: {body:?}"
    );
}

#[tokio::test]
async fn stage_returns_409_when_household_already_paired() {
    // Only Uninitialized / ReadyForNaming may stage. A Mac that already holds a
    // committed or mid-ceremony identity must teardown first, not silently restage.
    for bs in [
        BootstrapState::NamedAwaitingPair,
        BootstrapState::Ready,
        BootstrapState::Recovering,
    ] {
        let (status, body) = call_stage(make_state(bs), LOOPBACK_PEER, Vec::new()).await;
        assert_eq!(status, StatusCode::CONFLICT, "state {bs:?}");
        assert_eq!(decode_err(&body).error, "household_already_paired");
    }
}

#[tokio::test]
async fn stage_returns_400_for_unsupported_transport() {
    let (status, body) = call_stage(
        make_state(BootstrapState::Uninitialized),
        LOOPBACK_PEER,
        br#"{"transport":"carrier-pigeon"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "unsupported_transport");
}

#[tokio::test]
async fn stage_returns_400_for_malformed_request_body() {
    // A non-empty body that is not valid JSON is rejected before the transport match.
    let (status, body) = call_stage(
        make_state(BootstrapState::Uninitialized),
        LOOPBACK_PEER,
        b"this is not json".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_request_body");
}
