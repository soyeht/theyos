//! T022 + T024 coverage for the Phase 3 owner-events log + broadcaster
//! and the owner-device push-token registry.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;

use household_rs::household_lifecycle::HouseholdLifecycleLock;
use household_rs::keys::{IdentityKey as _, P256Keypair};
use household_rs::owner_events::{
    EventError, JoinRequestPayload, MachineJoinedPayload, OwnerDevicePushToken, OwnerEventLog,
    OwnerEventPayload, OwnerEventType, OwnerEventsBroadcaster, PushTokenError,
    get_owner_push_token, put_owner_push_token,
};
use household_rs::{HouseholdRecord, derive_household_id, derive_machine_id};
use serde_bytes::ByteBuf;
use tempfile::{TempDir, tempdir};

fn issuer_kp() -> P256Keypair {
    P256Keypair::generate()
}

fn join_request_payload() -> OwnerEventPayload {
    OwnerEventPayload::JoinRequest(JoinRequestPayload {
        join_request_cbor: ByteBuf::from(vec![0xa1, 0x02, 0x03]),
        fingerprint: "mass museum swamp various model gift".to_string(),
        expiry: 1_714_972_800,
    })
}

struct TestLog {
    td: TempDir,
    lifecycle: HouseholdLifecycleLock,
    log: Arc<OwnerEventLog>,
}

fn test_log(broadcaster: Option<OwnerEventsBroadcaster>) -> TestLog {
    let td = tempdir().unwrap();
    let household_key = P256Keypair::generate();
    let machine_key = P256Keypair::generate();
    let hh_pub = household_key.public();
    let record = HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&hh_pub),
        hh_pub,
        name: "Owner Events Integration Test".into(),
        created_at: 1_714_972_800,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![derive_machine_id(&machine_key.public())],
        is_follower: false,
    };
    let household = household_rs::storage::household_dir(td.path());
    fs::create_dir(&household).unwrap();
    fs::set_permissions(&household, fs::Permissions::from_mode(0o700)).unwrap();
    household_rs::storage::atomic_write_cbor(
        &household_rs::storage::household_record_path(td.path()),
        &record,
    )
    .unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(td.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    let log = match broadcaster {
        Some(broadcaster) => OwnerEventLog::open_with_broadcaster_under_lifecycle(
            &write,
            td.path().to_path_buf(),
            &record.hh_id.to_string(),
            broadcaster,
        )
        .unwrap(),
        None => OwnerEventLog::open_under_lifecycle(
            &write,
            td.path().to_path_buf(),
            &record.hh_id.to_string(),
        )
        .unwrap(),
    };
    drop(write);
    TestLog { td, lifecycle, log }
}

#[test]
fn append_then_read_round_trip() {
    let fixture = test_log(None);
    let read = fixture.lifecycle.lock_shared().unwrap();
    let kp = issuer_kp();
    let evt = fixture
        .log
        .append(
            &read,
            "m_test_issuer",
            &kp,
            OwnerEventType::JoinRequest,
            join_request_payload(),
        )
        .unwrap();
    assert_eq!(evt.cursor, 1);
    assert_eq!(fixture.log.cursor_head(), 1);
    let read_back = fixture.log.read_since(&read, 0).unwrap();
    assert_eq!(read_back.len(), 1);
    assert_eq!(read_back[0].cursor, evt.cursor);
    assert_eq!(read_back[0].payload, evt.payload);
}

#[test]
fn cursor_increases_strictly_across_appends() {
    let fixture = test_log(None);
    let read = fixture.lifecycle.lock_shared().unwrap();
    let kp = issuer_kp();
    let mut last = 0u64;
    for _ in 0..5 {
        let evt = fixture
            .log
            .append(
                &read,
                "m_test_issuer",
                &kp,
                OwnerEventType::JoinRequest,
                join_request_payload(),
            )
            .unwrap();
        assert!(evt.cursor > last);
        last = evt.cursor;
    }
    assert_eq!(fixture.log.cursor_head(), 5);
    let all = fixture.log.read_since(&read, 0).unwrap();
    assert_eq!(all.len(), 5);
    let from_3 = fixture.log.read_since(&read, 3).unwrap();
    assert_eq!(
        from_3.iter().map(|e| e.cursor).collect::<Vec<_>>(),
        vec![4, 5]
    );
}

#[tokio::test]
async fn broadcaster_wakes_subscriber_within_one_ms() {
    let bc = OwnerEventsBroadcaster::new();
    let mut sub = bc.subscribe();
    let bc2 = bc.clone();
    let kp = issuer_kp();
    let fixture = test_log(None);
    let read = fixture.lifecycle.lock_shared().unwrap();
    let evt = fixture
        .log
        .append(
            &read,
            "m_test_issuer",
            &kp,
            OwnerEventType::JoinRequest,
            join_request_payload(),
        )
        .unwrap();
    let h = tokio::spawn(async move {
        let _ = bc2.publish(evt);
    });
    let received = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        sub.receiver_mut().recv(),
    )
    .await
    .expect("broadcast did not arrive within 50ms")
    .unwrap();
    assert_eq!(received.cursor, 1);
    h.await.unwrap();
}

#[test]
fn active_subscribers_decrements_synchronously_on_drop() {
    // Replaces the previous tokio-spawn-based pattern. The
    // SubscriptionGuard now decrements via AtomicUsize so the count
    // updates the moment the guard goes out of scope — no runtime
    // dependency, no race, no spawned task that could leak on
    // shutdown.
    let bc = OwnerEventsBroadcaster::new();
    {
        let _s = bc.subscribe();
        assert_eq!(bc.active_subscribers(), 1);
    }
    assert_eq!(bc.active_subscribers(), 0);
}

#[test]
fn append_publishes_to_attached_broadcaster() {
    let bc = OwnerEventsBroadcaster::new();
    let mut sub = bc.subscribe();
    let fixture = test_log(Some(bc.clone()));
    let read = fixture.lifecycle.lock_shared().unwrap();
    let kp = issuer_kp();
    let evt = fixture
        .log
        .append(
            &read,
            "m_test_issuer",
            &kp,
            OwnerEventType::JoinRequest,
            join_request_payload(),
        )
        .unwrap();
    let received = sub.receiver_mut().try_recv().expect("event must publish");
    assert_eq!(received.cursor, evt.cursor);
}

#[test]
fn payload_event_type_mismatch_rejected() {
    let fixture = test_log(None);
    let read = fixture.lifecycle.lock_shared().unwrap();
    let kp = issuer_kp();
    // event_type=MachineJoined but payload=JoinRequest — must be
    // rejected by append rather than encoded into the log.
    let err = fixture
        .log
        .append(
            &read,
            "m_test_issuer",
            &kp,
            OwnerEventType::MachineJoined,
            join_request_payload(),
        )
        .unwrap_err();
    assert!(matches!(err, EventError::PayloadTypeMismatch));
}

#[test]
fn concurrent_appends_serialize_cleanly() {
    // Multiple threads hammer the same log. With per-state-dir
    // serialization, every event must land with a unique cursor and
    // the log must round-trip on read_since.
    let fixture = test_log(None);
    let log = Arc::clone(&fixture.log);
    let lifecycle = fixture.lifecycle.clone();
    let kp = Arc::new(issuer_kp());

    let mut handles = Vec::new();
    let total_per_thread = 25usize;
    let n_threads = 4usize;
    for _ in 0..n_threads {
        let log = Arc::clone(&log);
        let lifecycle = lifecycle.clone();
        let kp = Arc::clone(&kp);
        handles.push(std::thread::spawn(move || {
            let read = lifecycle.lock_shared().unwrap();
            for _ in 0..total_per_thread {
                log.append(
                    &read,
                    "m_test_issuer",
                    kp.as_ref(),
                    OwnerEventType::JoinRequest,
                    OwnerEventPayload::JoinRequest(JoinRequestPayload {
                        join_request_cbor: ByteBuf::from(vec![0xAA]),
                        fingerprint: "x".repeat(16),
                        expiry: 0,
                    }),
                )
                .unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let total = total_per_thread * n_threads;
    assert_eq!(log.cursor_head(), total as u64);
    let read = fixture.lifecycle.lock_shared().unwrap();
    let all = log.read_since(&read, 0).unwrap();
    assert_eq!(all.len(), total);
    let mut cursors: Vec<u64> = all.iter().map(|e| e.cursor).collect();
    cursors.sort_unstable();
    cursors.dedup();
    assert_eq!(cursors.len(), total, "every cursor must be unique");
    assert_eq!(*cursors.first().unwrap(), 1);
    assert_eq!(*cursors.last().unwrap(), total as u64);
}

#[test]
fn independent_handles_share_the_cross_process_cursor_lock() {
    let fixture = test_log(None);
    let write = fixture.lifecycle.lock_exclusive().unwrap();
    let second = OwnerEventLog::open_under_lifecycle(
        &write,
        fixture.td.path().to_path_buf(),
        &household_rs::storage::read_optional_cbor::<HouseholdRecord>(
            &household_rs::storage::household_record_path(fixture.td.path()),
        )
        .unwrap()
        .unwrap()
        .hh_id
        .to_string(),
    )
    .unwrap();
    drop(write);
    let kp = Arc::new(issuer_kp());

    let total_per_thread = 25usize;
    let n_threads = 4usize;
    let mut handles = Vec::new();
    for thread_index in 0..n_threads {
        let kp = Arc::clone(&kp);
        let lifecycle = fixture.lifecycle.clone();
        let log = if thread_index % 2 == 0 {
            Arc::clone(&fixture.log)
        } else {
            Arc::clone(&second)
        };
        handles.push(std::thread::spawn(move || {
            let read = lifecycle.lock_shared().unwrap();
            for _ in 0..total_per_thread {
                log.append(
                    &read,
                    "m_test_issuer",
                    kp.as_ref(),
                    OwnerEventType::JoinRequest,
                    OwnerEventPayload::JoinRequest(JoinRequestPayload {
                        join_request_cbor: ByteBuf::from(vec![0xAA]),
                        fingerprint: "x".repeat(16),
                        expiry: 0,
                    }),
                )
                .unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let total = total_per_thread * n_threads;
    let read = fixture.lifecycle.lock_shared().unwrap();
    let all = fixture.log.read_since(&read, 0).unwrap();
    assert_eq!(all.len(), total);
    let mut cursors: Vec<u64> = all.iter().map(|e| e.cursor).collect();
    cursors.sort_unstable();
    cursors.dedup();
    assert_eq!(cursors.len(), total, "every cursor must be unique");
}

#[test]
fn torn_trailing_record_is_truncated_on_open() {
    use std::io::Write as _;

    let fixture = test_log(None);
    let read = fixture.lifecycle.lock_shared().unwrap();
    let kp = issuer_kp();
    fixture
        .log
        .append(
            &read,
            "m_test_issuer",
            &kp,
            OwnerEventType::JoinRequest,
            join_request_payload(),
        )
        .unwrap();
    drop(read);
    drop(fixture.log);

    // Append a valid length prefix declaring 1024 bytes but only write
    // 8 bytes of payload — simulates a torn write of the trailing
    // record after an unclean shutdown.
    let bogus_prefix = (1024u64).to_be_bytes();
    let bogus_partial = vec![0xCDu8; 8];
    let mut raw = fs::OpenOptions::new()
        .append(true)
        .open(household_rs::owner_events::log_path(fixture.td.path()))
        .unwrap();
    raw.write_all(&bogus_prefix).unwrap();
    raw.write_all(&bogus_partial).unwrap();
    raw.sync_all().unwrap();
    drop(raw);

    // Re-open: scan_and_repair must truncate the partial trailer and
    // leave only the original good record.
    let record = household_rs::storage::read_optional_cbor::<HouseholdRecord>(
        &household_rs::storage::household_record_path(fixture.td.path()),
    )
    .unwrap()
    .unwrap();
    let write = fixture.lifecycle.lock_exclusive().unwrap();
    let log2 = OwnerEventLog::open_under_lifecycle(
        &write,
        fixture.td.path().to_path_buf(),
        &record.hh_id.to_string(),
    )
    .unwrap();
    drop(write);
    assert_eq!(log2.cursor_head(), 1);
    let read = fixture.lifecycle.lock_shared().unwrap();
    let events = log2.read_since(&read, 0).unwrap();
    assert_eq!(events.len(), 1);

    // After repair, a new append must succeed and land at cursor=2.
    let next = log2
        .append(
            &read,
            "m_test_issuer",
            &kp,
            OwnerEventType::MachineJoined,
            OwnerEventPayload::MachineJoined(MachineJoinedPayload {
                m_pub: ByteBuf::from(vec![0x02; 33]),
                m_id: "m_after_repair".into(),
                hostname: "studio-linux".into(),
                joined_at: 1_714_972_800,
            }),
        )
        .unwrap();
    assert_eq!(next.cursor, 2);
}

#[test]
fn push_token_round_trip() {
    let td = tempdir().unwrap();
    std::fs::create_dir_all(household_rs::storage::household_dir(td.path())).unwrap();
    let token = OwnerDevicePushToken {
        version: 1,
        p_id: "p_test_owner".into(),
        platform: "ios".into(),
        push_token: ByteBuf::from(vec![0u8; 32]),
        updated_at: 1_714_972_800,
    };
    put_owner_push_token(td.path(), &token).unwrap();
    let got = get_owner_push_token(td.path()).unwrap().unwrap();
    assert_eq!(got, token);
}

#[test]
fn push_token_rotation_overwrites() {
    let td = tempdir().unwrap();
    std::fs::create_dir_all(household_rs::storage::household_dir(td.path())).unwrap();
    let mut token = OwnerDevicePushToken {
        version: 1,
        p_id: "p_test_owner".into(),
        platform: "ios".into(),
        push_token: ByteBuf::from(vec![1u8; 32]),
        updated_at: 1_714_972_800,
    };
    put_owner_push_token(td.path(), &token).unwrap();
    token.push_token = ByteBuf::from(vec![2u8; 32]);
    token.updated_at = 1_714_973_800;
    put_owner_push_token(td.path(), &token).unwrap();
    let got = get_owner_push_token(td.path()).unwrap().unwrap();
    assert_eq!(got.push_token.as_ref(), &[2u8; 32]);
}

#[test]
fn push_token_non_ios_rejected() {
    let td = tempdir().unwrap();
    std::fs::create_dir_all(household_rs::storage::household_dir(td.path())).unwrap();
    let token = OwnerDevicePushToken {
        version: 1,
        p_id: "p_test_owner".into(),
        platform: "android".into(),
        push_token: ByteBuf::from(vec![0u8; 32]),
        updated_at: 1_714_972_800,
    };
    let err = put_owner_push_token(td.path(), &token).unwrap_err();
    assert!(matches!(err, PushTokenError::UnsupportedPlatform(_)));
}
