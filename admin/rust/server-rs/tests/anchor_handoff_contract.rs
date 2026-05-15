//! T035 — Contract tests for `GET /pair-machine/anchor-handoff`.
//!
//! Covers:
//! - 403 when source IP is not in Tailnet range (LAN or no ConnectInfo)
//! - 403 when ConnectInfo is absent (unconfigured server)
//! - 404 when pair_machine_window is Idle (no active ceremony)
//! - 410 when pair_machine_window is Committed or Aborted (terminated)
//! - 200 with correct response shape for Staging window + Tailnet IP
//! - 200 for AwaitingOwner window + Tailnet IP
//! - Fingerprint field is present and non-empty in success path

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use household_rs::pair_machine::{JoinTransport, PairMachineWindow};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use server_rs::handlers_pair_machine::{PreHouseholdRouterState, pre_household_router};
use tower::ServiceExt;

// ── Test data ─────────────────────────────────────────────────────────────────

const TAILNET_IP: &str = "100.100.1.2:1234";
const LAN_IP: &str = "192.168.1.10:5678";

fn test_m_pub() -> [u8; 33] {
    let mut b = [0u8; 33];
    b[0] = 0x02;
    b[1] = 0xAB;
    b
}

fn test_nonce() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 0xDE;
    b[1] = 0xAD;
    b
}

fn test_anchor_secret() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = 0xBE;
    b[1] = 0xEF;
    b
}

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct HandoffOk {
    v: u8,
    m_pub: ByteBuf,
    nonce: ByteBuf,
    anchor_secret: ByteBuf,
    fingerprint: String,
    expires_at: u64,
}

#[derive(Deserialize)]
struct HandoffErr {
    v: u8,
    error: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_state(window: Arc<PairMachineWindow>) -> PreHouseholdRouterState {
    PreHouseholdRouterState {
        window,
        state_dir: tempfile::tempdir().unwrap().keep(),
        key_policy: household_rs::KeyBackingPolicy::ForceSoftware,
        finalize_lock: Arc::new(tokio::sync::Mutex::new(())),
    }
}

async fn call_anchor_handoff(
    window: Arc<PairMachineWindow>,
    peer_ip: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let router = pre_household_router(make_state(window));
    let mut builder = Request::builder().uri("/pair-machine/anchor-handoff");
    if let Some(addr_str) = peer_ip {
        let addr: SocketAddr = addr_str.parse().unwrap();
        builder = builder.extension(ConnectInfo::<SocketAddr>(addr));
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec();
    (status, bytes)
}

async fn active_staging_window() -> Arc<PairMachineWindow> {
    let w = Arc::new(PairMachineWindow::new_in_memory());
    w.enter_staging(
        test_m_pub(),
        test_nonce(),
        JoinTransport::Tailscale,
        "100.100.1.2".into(),
        "🦊🌙🔑🎯🌊🦋".into(),
        vec![0xCA, 0xFE],
        300,
        Some(test_anchor_secret()),
    )
    .await
    .unwrap();
    w
}

// ── Tests: source IP gating ───────────────────────────────────────────────────

#[tokio::test]
async fn anchor_handoff_403_when_no_connect_info() {
    let w = active_staging_window().await;
    let (status, body) = call_anchor_handoff(w, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let err: HandoffErr = household_rs::cbor::from_canonical_slice(&body).unwrap();
    assert_eq!(err.v, 1);
    assert_eq!(err.error, "tailnet_required");
}

#[tokio::test]
async fn anchor_handoff_403_for_lan_ip() {
    let w = active_staging_window().await;
    let (status, body) = call_anchor_handoff(w, Some(LAN_IP)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let err: HandoffErr = household_rs::cbor::from_canonical_slice(&body).unwrap();
    assert_eq!(err.error, "tailnet_required");
}

#[tokio::test]
async fn anchor_handoff_403_for_loopback() {
    let w = active_staging_window().await;
    let (status, _) = call_anchor_handoff(w, Some("127.0.0.1:9999")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── Tests: window state gating ────────────────────────────────────────────────

#[tokio::test]
async fn anchor_handoff_404_when_idle() {
    let w = Arc::new(PairMachineWindow::new_in_memory());
    let (status, body) = call_anchor_handoff(w, Some(TAILNET_IP)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let err: HandoffErr = household_rs::cbor::from_canonical_slice(&body).unwrap();
    assert_eq!(err.error, "no_active_pair_machine");
}

#[tokio::test]
async fn anchor_handoff_410_when_committed() {
    let w = active_staging_window().await;
    w.enter_awaiting_owner(42).await.unwrap();
    w.enter_committed(vec![0xAA]).await.unwrap();
    let (status, body) = call_anchor_handoff(w, Some(TAILNET_IP)).await;
    assert_eq!(status, StatusCode::GONE);
    let err: HandoffErr = household_rs::cbor::from_canonical_slice(&body).unwrap();
    assert_eq!(err.error, "window_terminated");
}

#[tokio::test]
async fn anchor_handoff_410_when_aborted() {
    let w = active_staging_window().await;
    w.enter_aborted().await.unwrap();
    let (status, body) = call_anchor_handoff(w, Some(TAILNET_IP)).await;
    assert_eq!(status, StatusCode::GONE);
    let err: HandoffErr = household_rs::cbor::from_canonical_slice(&body).unwrap();
    assert_eq!(err.error, "window_terminated");
}

// ── Tests: success path ───────────────────────────────────────────────────────

#[tokio::test]
async fn anchor_handoff_200_staging_response_shape() {
    let w = active_staging_window().await;
    let (status, body) = call_anchor_handoff(w, Some(TAILNET_IP)).await;
    assert_eq!(status, StatusCode::OK);

    let ok: HandoffOk = household_rs::cbor::from_canonical_slice(&body)
        .expect("response must decode as HandoffOk");
    assert_eq!(ok.v, 1, "v must be 1");
    assert_eq!(ok.m_pub.as_ref(), test_m_pub(), "m_pub must match");
    assert_eq!(ok.nonce.as_ref(), test_nonce(), "nonce must match");
    assert_eq!(ok.anchor_secret.as_ref(), test_anchor_secret(), "anchor_secret must match");
    assert_eq!(ok.fingerprint, "🦊🌙🔑🎯🌊🦋", "fingerprint must match");
    assert!(ok.expires_at > 0, "expires_at must be non-zero");
}

#[tokio::test]
async fn anchor_handoff_200_awaiting_owner_also_succeeds() {
    let w = active_staging_window().await;
    w.enter_awaiting_owner(77).await.unwrap();
    let (status, body) = call_anchor_handoff(w, Some(TAILNET_IP)).await;
    assert_eq!(status, StatusCode::OK);
    let ok: HandoffOk = household_rs::cbor::from_canonical_slice(&body).unwrap();
    assert_eq!(ok.v, 1);
    assert!(!ok.fingerprint.is_empty(), "fingerprint must be present");
}

#[tokio::test]
async fn anchor_handoff_200_for_tailscale_ula_ipv6() {
    let w = active_staging_window().await;
    // fd7a:115c:a1e0:: is Tailscale's ULA range
    let (status, _) = call_anchor_handoff(w, Some("[fd7a:115c:a1e0::1]:1234")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn anchor_handoff_response_has_cbor_content_type() {
    let w = active_staging_window().await;
    let router = pre_household_router(make_state(w));
    let addr: SocketAddr = TAILNET_IP.parse().unwrap();
    let req = Request::builder()
        .uri("/pair-machine/anchor-handoff")
        .extension(ConnectInfo::<SocketAddr>(addr))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/cbor"),
    );
}
