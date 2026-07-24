//! Phase 3 Story 2 — LAN auto-discovery machine-join end-to-end (T091).
//!
//! Mirrors `phase3_machine_join_remote.rs` but drives M1's staging via the
//! Bonjour browser instead of an iPhone POST. The owner approval path is
//! identical (`founder_stage_join_request` is shared between Story 1 and
//! Story 2 per T087), so the final on-disk state is bit-equivalent and is
//! re-asserted with the same helpers as Story 1 (`assert_machine_cert_layout`,
//! `assert_record_is_two_member`, sole-shard absence, self-shard presence).

mod phase3_support;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::http::{StatusCode, header};
use household_rs::owner_events::{OwnerEventPayload, OwnerEventType};
use household_rs::pair_machine::{
    PairMachineState, household_root_sole_path, shamir_self_shard_path,
};
use household_rs::storage::read_known_peer_addr;
use server_rs::bonjour_browser::{JoinerAnnouncement, spawn_bonjour_browser_with_source};
use server_rs::household_bootstrap::household_port_from_env;
use tokio::sync::mpsc;

use phase3_support::{
    OWNER_EVENTS_PATH, OwnerApprovalAck, OwnerEventsResponse, assert_machine_cert_layout,
    assert_record_is_two_member, candidate_harness, cursor_param,
    founder_harness_with_tailnet_resolver, get_cbor, post_local_anchor, post_owner_approval,
};

#[tokio::test]
async fn phase3_machine_join_lan() {
    static FOUNDER_TAILNET_RESOLUTIONS: AtomicUsize = AtomicUsize::new(0);

    #[allow(clippy::unnecessary_wraps)] // `TailnetResolver` is an optional-address seam.
    fn founder_tailnet_address() -> Option<Ipv4Addr> {
        FOUNDER_TAILNET_RESOLUTIONS.fetch_add(1, Ordering::Relaxed);
        Some(Ipv4Addr::new(100, 64, 0, 10))
    }

    FOUNDER_TAILNET_RESOLUTIONS.store(0, Ordering::Relaxed);
    let founder = founder_harness_with_tailnet_resolver(founder_tailnet_address);
    let candidate = candidate_harness().await;

    let pair_nonce = household_rs::ids::base32_lower_nopad_encode(
        &candidate.prepared.join_request.nonce.as_ref()[..8],
    );
    let m_pub_b32 = household_rs::ids::m_pub_short(&candidate.prepared.m_pub_sec1);
    let candidate_addr = candidate.prepared.join_request.addr.clone();

    let (tx, rx) = mpsc::channel(4);
    let browser = spawn_bonjour_browser_with_source(founder.pair_state.clone(), rx);

    // Per protocol §13 the joiner publishes WITHOUT `hh_id`; the founder
    // browser uses the fetched `JoinRequest`'s identity to bind, not the
    // TXT record. Mirror the on-wire shape exactly.
    let bonjour_publish_at = Instant::now();
    tx.send(JoinerAnnouncement {
        hh_id: None,
        addr: candidate_addr,
        pair_nonce,
        m_pub_b32: Some(m_pub_b32),
    })
    .await
    .expect("send Bonjour announcement");

    // SC-002 sub-budget: M1 browser-to-stage MUST complete in < 2s.
    let stage_deadline = bonjour_publish_at + Duration::from_secs(2);
    loop {
        if founder.window.snapshot().await.state == PairMachineState::AwaitingOwner {
            break;
        }
        assert!(
            Instant::now() < stage_deadline,
            "browser-to-stage exceeded 2s SC-002 sub-budget"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let stage_elapsed = bonjour_publish_at.elapsed();

    // Owner reads the staged event off the long-poll endpoint exactly as
    // the iPhone would. The cursor returned here drives the approve path.
    let owner_events_uri = format!("{OWNER_EVENTS_PATH}?since={}", cursor_param(0));
    let (status, _, body) =
        get_cbor(founder.router.clone(), &owner_events_uri, &founder.owner).await;
    assert_eq!(status, StatusCode::OK);
    let events: OwnerEventsResponse =
        household_rs::cbor::from_canonical_slice(&body).expect("decode events");
    assert_eq!(events.version, 1);
    assert_eq!(events.events.len(), 1);
    assert_eq!(events.events[0].event_type, OwnerEventType::JoinRequest);
    let cursor = events.events[0].cursor;
    let OwnerEventPayload::JoinRequest(payload) = &events.events[0].payload else {
        panic!("first owner event should be join-request");
    };
    assert_eq!(
        payload.join_request_cbor.as_ref(),
        candidate.prepared.join_request_cbor.as_slice(),
        "Bonjour-fetched JoinRequest CBOR must match the candidate's cached bytes"
    );
    assert_eq!(payload.fingerprint, candidate.prepared.fingerprint);

    // iPhone simulation: deliver the trust anchor to M2 before approving.
    // Story 2 does not yet have an iPhone-out-of-band path for the
    // anchor secret (Phase 5 follow-up per R5.2); the harness uses the
    // candidate-known secret directly to drive `local/finalize` past the
    // anchor gate.
    post_local_anchor(&candidate, &founder, &candidate.prepared.anchor_secret).await;

    let (status, headers, body) =
        post_owner_approval(&founder, &candidate.prepared.join_request, cursor).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "owner approval should drive 2PC to commit"
    );
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/cbor")
    );
    let approval_ack: OwnerApprovalAck =
        household_rs::cbor::from_canonical_slice(&body).expect("decode approval ack");
    assert_eq!(approval_ack.version, 1);
    assert_eq!(approval_ack.machine_cert_hash.len(), 32);

    let total_elapsed = bonjour_publish_at.elapsed();

    // SC-002 timing budgets.
    assert!(
        stage_elapsed < Duration::from_secs(2),
        "browser-to-stage {stage_elapsed:?} exceeds 2s SC-002 sub-budget"
    );
    assert!(
        total_elapsed < Duration::from_secs(15),
        "LAN ceremony exceeded SC-002 budget: {total_elapsed:?}"
    );

    // Final state assertions are bit-equivalent to Story 1's e2e
    // (`assert_successful_remote_ceremony`): same machine-cert layout,
    // same household record, sole-shard gone on M1, encrypted self-shard
    // present on both, both windows committed, owner-event log shows
    // exactly two events ending with `MachineJoined` at cursor 2.
    let m1_id = founder.identity.cert.m_id.to_string();
    let m2_id = candidate.prepared.m_id.to_string();
    assert_machine_cert_layout(founder.dir.path(), &m1_id, &m2_id);
    assert_machine_cert_layout(candidate.dir.path(), &m1_id, &m2_id);
    assert_record_is_two_member(founder.dir.path(), &m1_id, &m2_id);
    assert_record_is_two_member(candidate.dir.path(), &m1_id, &m2_id);
    let expected_founder_addr = format!("100.64.0.10:{}", household_port_from_env());
    assert_eq!(
        read_known_peer_addr(candidate.dir.path(), &m1_id).expect("read founder address hint"),
        Some(expected_founder_addr),
        "candidate should cache the founder Tailnet hint carried by JoinResponse"
    );
    assert_eq!(
        FOUNDER_TAILNET_RESOLUTIONS.load(Ordering::Relaxed),
        1,
        "pending recovery bytes and the final POST must reuse one resolved hint"
    );
    assert!(!household_root_sole_path(founder.dir.path()).exists());
    assert!(shamir_self_shard_path(founder.dir.path()).exists());
    assert!(shamir_self_shard_path(candidate.dir.path()).exists());

    assert_eq!(
        founder.window.snapshot().await.state,
        PairMachineState::Committed
    );
    assert_eq!(
        candidate.window.snapshot().await.state,
        PairMachineState::Committed
    );

    let final_events = founder.event_log.read_since(0).expect("read owner events");
    assert_eq!(final_events.len(), 2);
    assert_eq!(final_events[1].cursor, 2);
    assert_eq!(final_events[1].event_type, OwnerEventType::MachineJoined);

    browser.abort();
}
