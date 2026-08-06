mod phase3_support;

use axum::http::StatusCode;
use household_rs::owner_events::OwnerEventType;
use household_rs::storage::machine_cert_for;

#[tokio::test]
async fn test_replay_returns_cached_bytes() {
    let ceremony = phase3_support::run_remote_ceremony().await;
    let cached_response = ceremony
        .founder
        .window
        .snapshot()
        .await
        .cached_response
        .expect("committed window cached response")
        .to_vec();

    for _ in 0..100 {
        let (status, _, body) = phase3_support::post_cbor(
            ceremony.founder.router.clone(),
            phase3_support::JOIN_REQUEST_PATH,
            ceremony.candidate.prepared.join_request_cbor.clone(),
            Some(&ceremony.founder.owner),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, cached_response);
    }

    let m2_id = ceremony.candidate.prepared.m_id.to_string();
    assert!(machine_cert_for(ceremony.founder.dir.path(), &m2_id).exists());
    let founder_read = ceremony
        .founder
        .lifecycle
        .lock_shared()
        .expect("lock lifecycle shared");
    let events = ceremony
        .founder
        .event_log
        .read_since(&founder_read, 0)
        .expect("read owner events after replays");
    drop(founder_read);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].cursor, 2);
    assert_eq!(events[1].event_type, OwnerEventType::MachineJoined);
    assert_eq!(ceremony.founder.event_log.cursor_head(), 2);
}

#[tokio::test]
async fn test_replay_after_grace_returns_401() {
    let ceremony = phase3_support::run_remote_ceremony().await;
    let mut snap = ceremony.founder.window.snapshot().await;
    snap.expiry = Some(phase3_support::unix_now().saturating_sub(61));
    let lifecycle_guard = ceremony
        .founder
        .lifecycle
        .lock_exclusive()
        .expect("lock lifecycle exclusive");
    ceremony
        .founder
        .window
        .write_persisted_snapshot_under_lifecycle_for_test(&snap, &lifecycle_guard)
        .expect("persist expired committed window snapshot");
    drop(lifecycle_guard);
    let (router, _window, _event_log) =
        phase3_support::rebuild_founder_router_from_disk(&ceremony.founder);

    let (status, _, body) = phase3_support::post_cbor(
        router,
        phase3_support::JOIN_REQUEST_PATH,
        ceremony.candidate.prepared.join_request_cbor.clone(),
        Some(&ceremony.founder.owner),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let parsed: GenericUnauth =
        household_rs::cbor::from_canonical_slice(&body).expect("generic 401 cbor");
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.error, "unauthenticated");
}

#[derive(serde::Deserialize)]
struct GenericUnauth {
    #[serde(rename = "v")]
    version: u8,
    error: String,
}
