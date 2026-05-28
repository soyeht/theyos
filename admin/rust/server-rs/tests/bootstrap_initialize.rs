//! T021 — Contract tests for `POST /bootstrap/initialize`.
//!
//! Covers:
//! - CBOR shape: request → response field types
//! - `v` version field present and correct
//! - Name validation edge cases: empty, too long, control chars
//! - State precondition: 409 when engine already initialized
//! - State precondition: 200 when uninitialized or `ready_for_naming`
//! - 400 on invalid CBOR body
//!
//! Integration-level persistence and state machine transitions are covered by
//! T022 (`scenario_a_mac_founder.rs`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use core_rs::env::set_test_env;
use household_rs::bootstrap_state::BootstrapState;
use household_rs::pair_device::PairDeviceWindow;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use server_rs::handlers_bootstrap::{BootstrapHandlerState, BootstrapStateArc, bootstrap_router};
use server_rs::household_state::HouseholdState;
use tokio::sync::RwLock;
use tower::ServiceExt;

// ── Response types for decoding ────────────────────────────────────────────────

#[derive(Deserialize)]
struct InitializeOk {
    #[serde(rename = "v")]
    version: u8,
    hh_id: String,
    hh_pub: ByteBuf,
    name: String,
    pair_qr_uri: String,
    created_at: u64,
}

#[derive(Deserialize)]
struct InitializeErr {
    #[serde(rename = "v")]
    version: u8,
    error: String,
    #[serde(rename = "reason")]
    _reason: Option<String>,
    state: Option<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_state_dir() -> PathBuf {
    let dir = tempfile::tempdir().unwrap().keep();
    std::fs::create_dir_all(dir.join("household")).unwrap();
    dir
}

fn no_tailnet() -> Option<std::net::Ipv4Addr> {
    None
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
    }
}

fn cbor_request(name: &str) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Req<'a> {
        v: u8,
        name: &'a str,
    }
    household_rs::cbor::to_canonical_vec(&Req { v: 1, name }).unwrap()
}

async fn call_initialize(state: BootstrapHandlerState, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let app = bootstrap_router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/bootstrap/initialize")
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

fn decode_ok(bytes: &[u8]) -> InitializeOk {
    household_rs::cbor::from_canonical_slice(bytes).expect("decode InitializeOk")
}

fn decode_err(bytes: &[u8]) -> InitializeErr {
    household_rs::cbor::from_canonical_slice(bytes).expect("decode InitializeErr")
}

// ── Success path ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn initialize_valid_name_returns_200() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, cbor_request("Sample Home")).await;
    assert_eq!(status, StatusCode::OK, "body raw: {body:?}");
}

#[tokio::test]
async fn initialize_response_shape() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, cbor_request("Silva Home")).await;
    assert_eq!(status, StatusCode::OK);

    let resp = decode_ok(&body);
    assert_eq!(resp.version, 1, "v must be 1");
    assert!(resp.hh_id.starts_with("hh_"), "hh_id must start with hh_");
    assert_eq!(resp.name, "Silva Home", "name must match");
    assert_eq!(resp.hh_pub.len(), 33, "hh_pub must be 33 bytes (SEC1)");
    assert!(
        resp.created_at > 0,
        "created_at must be non-zero unix seconds"
    );
    // pair_qr_uri may be empty if pair-device window is not persisted in test,
    // but the field MUST be present (decoded successfully above).
    let _ = resp.pair_qr_uri;
}

#[tokio::test]
async fn initialize_name_is_trimmed() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, cbor_request("  Trim Home  ")).await;
    assert_eq!(status, StatusCode::OK);
    let resp = decode_ok(&body);
    assert_eq!(resp.name, "Trim Home", "name must be trimmed");
}

#[tokio::test]
async fn initialize_when_ready_for_naming_also_succeeds() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let dir = make_state_dir();
    let state = make_state(BootstrapState::ReadyForNaming, dir);
    let (status, _) = call_initialize(state, cbor_request("RFN Home")).await;
    assert_eq!(status, StatusCode::OK);
}

// ── Name validation ───────────────────────────────────────────────────────────

#[tokio::test]
async fn empty_name_returns_400() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, cbor_request("")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err = decode_err(&body);
    assert_eq!(err.version, 1);
    assert_eq!(err.error, "invalid_name");
}

#[tokio::test]
async fn whitespace_only_name_returns_400() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, cbor_request("   ")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_name");
}

#[tokio::test]
async fn name_64_bytes_is_accepted() {
    set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, _) = call_initialize(state, cbor_request(&"A".repeat(64))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn name_65_bytes_returns_400() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, cbor_request(&"A".repeat(65))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_name");
}

#[tokio::test]
async fn control_char_in_name_returns_400() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, cbor_request("Home\x01Hack")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_name");
}

// ── State preconditions ───────────────────────────────────────────────────────

#[tokio::test]
async fn already_named_returns_409() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::NamedAwaitingPair, dir);
    let (status, body) = call_initialize(state, cbor_request("Home X")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let err = decode_err(&body);
    assert_eq!(err.error, "already_initialized");
    assert_eq!(err.state.as_deref(), Some("named_awaiting_pair"));
}

#[tokio::test]
async fn ready_state_returns_409() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Ready, dir);
    let (status, body) = call_initialize(state, cbor_request("Home X")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(decode_err(&body).error, "already_initialized");
}

#[tokio::test]
async fn recovering_state_returns_409() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Recovering, dir);
    let (status, body) = call_initialize(state, cbor_request("Home X")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(decode_err(&body).error, "already_initialized");
}

// ── Invalid body ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn garbage_body_returns_400() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, b"not cbor".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_cbor");
}

#[tokio::test]
async fn empty_body_returns_400() {
    let dir = make_state_dir();
    let state = make_state(BootstrapState::Uninitialized, dir);
    let (status, body) = call_initialize(state, vec![]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(decode_err(&body).error, "invalid_cbor");
}
