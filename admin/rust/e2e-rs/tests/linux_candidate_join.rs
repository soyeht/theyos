//! T036 — Story 2: Linux candidate joins via Tailnet anchor-handoff.
//!
//! Simulates a Linux machine (M2) running `theyos install`, entering Staging,
//! and an owner iPhone discovering it over Tailscale and fetching the anchor
//! secret via `GET /pair-machine/anchor-handoff` instead of scanning a QR code.
//!
//! No QR URI is generated or parsed anywhere in this file — that is the Story 2
//! invariant under test.
//!
//! Flow:
//!   1. Candidate `prepare_candidate()` → Staging (transport=Tailscale)
//!   2. iPhone GET /pair-machine/anchor-handoff (Tailnet IP) → {`m_pub`, nonce, `anchor_secret`, fingerprint}
//!   3. iPhone GET /pair-machine/local/seed?nonce=<short> → `JoinRequest` bytes
//!   4. iPhone POST founder /api/v1/household/join-request → accepted
//!   5. iPhone POST candidate /pair-machine/local/anchor (`anchor_secret` from step 2)
//!   6. iPhone POST founder /owner-events/{cursor}/approve
//!   7. Founder → candidate POST /pair-machine/local/finalize (internal HTTP)
//!   8. Both windows → Committed; elapsed < SC-003 budget (30 s)

mod phase3_support;

use std::net::SocketAddr;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use household_rs::pair_machine::PairMachineState;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::time::Instant;
use tower::ServiceExt;

const TAILNET_IP: &str = "100.100.1.2:9999";
const LAN_IP: &str = "192.168.1.50:8080";

#[derive(Deserialize)]
struct HandoffOk {
    v: u8,
    m_pub: ByteBuf,
    nonce: ByteBuf,
    anchor_secret: ByteBuf,
    fingerprint: String,
    expires_at: u64,
}

async fn get_anchor_handoff(
    candidate: &phase3_support::CandidateHarness,
    peer_ip: &str,
) -> (StatusCode, Vec<u8>) {
    let addr: SocketAddr = peer_ip.parse().unwrap();
    let req = Request::builder()
        .uri("/pair-machine/anchor-handoff")
        .extension(ConnectInfo::<SocketAddr>(addr))
        .body(Body::empty())
        .unwrap();
    let resp = candidate.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

async fn get_local_seed(
    candidate: &phase3_support::CandidateHarness,
    nonce: &[u8],
) -> (StatusCode, Vec<u8>) {
    let nonce_short = household_rs::ids::base32_lower_nopad_encode(&nonce[..8]);
    let req = Request::builder()
        .uri(format!("/pair-machine/local/seed?nonce={nonce_short}"))
        .body(Body::empty())
        .unwrap();
    let resp = candidate.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

/// Full Story 2 ceremony — anchor-handoff replaces QR scan end-to-end.
#[tokio::test]
async fn linux_candidate_joins_via_tailnet_anchor_handoff() {
    let start = Instant::now();
    let founder = phase3_support::founder_harness();
    let candidate = phase3_support::candidate_harness().await;

    // ── 1. iPhone fetches anchor-handoff over Tailnet ─────────────────────────
    let (status, body) = get_anchor_handoff(&candidate, TAILNET_IP).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "anchor-handoff must return 200 for Tailnet IP"
    );

    let handoff: HandoffOk = household_rs::cbor::from_canonical_slice(&body)
        .expect("anchor-handoff response must decode as HandoffOk");
    assert_eq!(handoff.v, 1);
    assert!(
        !handoff.fingerprint.is_empty(),
        "fingerprint must be non-empty"
    );
    assert!(handoff.expires_at > 0, "expires_at must be non-zero");
    assert_eq!(
        handoff.fingerprint, candidate.prepared.fingerprint,
        "handoff fingerprint must match candidate's prepared fingerprint"
    );
    assert_eq!(
        handoff.m_pub.as_ref(),
        candidate.prepared.join_request.m_pub.as_ref(),
        "handoff m_pub must match candidate's join request"
    );

    let anchor_secret: [u8; 32] = handoff
        .anchor_secret
        .as_ref()
        .try_into()
        .expect("anchor_secret must be 32 bytes");
    assert_eq!(
        anchor_secret, candidate.prepared.anchor_secret,
        "anchor-handoff anchor_secret must match candidate's prepared secret"
    );

    // ── 2. iPhone fetches JoinRequest bytes via local/seed (not QR) ──────────
    let (seed_status, join_request_cbor) = get_local_seed(&candidate, handoff.nonce.as_ref()).await;
    assert_eq!(seed_status, StatusCode::OK, "local/seed must return 200");
    assert_eq!(
        join_request_cbor, candidate.prepared.join_request_cbor,
        "local/seed must return the same bytes as prepare_candidate cached"
    );
    // No QR URI was ever generated or scanned. join_request_cbor came from
    // the network endpoint — that is the entire Story 2 distinction.

    // ── 3. iPhone stages JoinRequest with founder ─────────────────────────────
    let (status, _headers, body) = phase3_support::post_cbor(
        founder.router.clone(),
        phase3_support::JOIN_REQUEST_PATH,
        join_request_cbor,
        Some(&founder.owner),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "join-request must be accepted");
    let accepted: phase3_support::JoinRequestAccepted =
        household_rs::cbor::from_canonical_slice(&body).expect("decode JoinRequestAccepted");
    assert_eq!(accepted.version, 1);
    assert_eq!(accepted.owner_event_cursor, 1);

    // ── 4. iPhone posts anchor (sourced from handoff, not QR) ─────────────────
    phase3_support::post_local_anchor(&candidate, &founder, &anchor_secret).await;

    // ── 5. iPhone approves → founder POSTs finalize to candidate ─────────────
    let approve_path = format!(
        "/api/v1/household/owner-events/{}/approve",
        accepted.owner_event_cursor
    );
    let approval_body = phase3_support::owner_approval_body(
        &founder,
        &candidate.prepared.join_request,
        accepted.owner_event_cursor,
        phase3_support::unix_now(),
    );
    let (status, _headers, body) = phase3_support::post_cbor(
        founder.router.clone(),
        &approve_path,
        approval_body,
        Some(&founder.owner),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner approval must succeed");
    let ack: phase3_support::OwnerApprovalAck =
        household_rs::cbor::from_canonical_slice(&body).expect("decode OwnerApprovalAck");
    assert_eq!(ack.version, 1);
    assert_eq!(ack.machine_cert_hash.len(), 32);

    // ── Assertions ────────────────────────────────────────────────────────────
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 30,
        "Story 2 ceremony exceeded SC-003 budget: {elapsed:?}"
    );
    assert_eq!(
        founder.window.snapshot().await.state,
        PairMachineState::Committed,
        "founder window must be Committed"
    );
    assert_eq!(
        candidate.window.snapshot().await.state,
        PairMachineState::Committed,
        "candidate window must be Committed"
    );

    let m1_id = founder.identity.cert.m_id.to_string();
    let m2_id = candidate.prepared.m_id.to_string();
    phase3_support::assert_machine_cert_layout(founder.dir.path(), &m1_id, &m2_id);
    phase3_support::assert_machine_cert_layout(candidate.dir.path(), &m1_id, &m2_id);
    phase3_support::assert_record_is_two_member(founder.dir.path(), &m1_id, &m2_id);
    phase3_support::assert_record_is_two_member(candidate.dir.path(), &m1_id, &m2_id);
}

/// LAN source IP must be refused even when the candidate window is Staging —
/// ensures an attacker on the same LAN cannot intercept the anchor secret.
#[tokio::test]
async fn anchor_handoff_rejected_for_lan_ip_with_active_staging_window() {
    let candidate = phase3_support::candidate_harness().await;
    let (status, _body) = get_anchor_handoff(&candidate, LAN_IP).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "LAN IP must not access anchor-handoff even with active Staging window"
    );
}

/// local/seed with a wrong nonce short must be rejected (401 Unauthorized).
#[tokio::test]
async fn local_seed_rejected_for_wrong_nonce() {
    let candidate = phase3_support::candidate_harness().await;
    let req = Request::builder()
        .uri("/pair-machine/local/seed?nonce=zzzzzzzzzzzz")
        .body(Body::empty())
        .unwrap();
    let resp = candidate.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
