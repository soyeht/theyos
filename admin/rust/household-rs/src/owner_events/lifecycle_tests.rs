#![cfg(test)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

use super::*;
use crate::household_lifecycle::HouseholdLifecycleLock;
use crate::ids::{derive_household_id, derive_machine_id};
use crate::keys::P256Keypair;

const CHILD_STATE_ENV: &str = "THEYOS_OWNER_EVENT_CHILD_STATE";
const CHILD_HH_ENV: &str = "THEYOS_OWNER_EVENT_CHILD_HH";
const CHILD_INDEX_ENV: &str = "THEYOS_OWNER_EVENT_CHILD_INDEX";
const CHILD_TEST: &str = "owner_events::lifecycle_tests::multiprocess_append_worker";

struct Fixture {
    state: TempDir,
    lifecycle: HouseholdLifecycleLock,
    hh_id: String,
    log: Arc<OwnerEventLog>,
}

fn record() -> HouseholdRecord {
    let household = P256Keypair::generate();
    let machine = P256Keypair::generate();
    let hh_pub = household.public();
    let m_pub = machine.public();
    HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&hh_pub),
        hh_pub,
        name: "Owner Event Test".into(),
        created_at: 1_714_972_800,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![derive_machine_id(&m_pub)],
        is_follower: false,
    }
}

fn install_record(state: &Path, record: &HouseholdRecord) {
    let household = crate::storage::household_dir(state);
    fs::create_dir(&household).unwrap();
    fs::set_permissions(&household, fs::Permissions::from_mode(0o700)).unwrap();
    crate::storage::atomic_write_cbor(&crate::storage::household_record_path(state), record)
        .unwrap();
}

fn fixture(broadcaster: Option<OwnerEventsBroadcaster>) -> Fixture {
    let state = TempDir::new().unwrap();
    let record = record();
    let hh_id = record.hh_id.to_string();
    install_record(state.path(), &record);
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    let log = match broadcaster {
        Some(broadcaster) => OwnerEventLog::open_with_broadcaster_under_lifecycle(
            &write,
            state.path().to_path_buf(),
            &hh_id,
            broadcaster,
        )
        .unwrap(),
        None => {
            OwnerEventLog::open_under_lifecycle(&write, state.path().to_path_buf(), &hh_id).unwrap()
        }
    };
    drop(write);
    Fixture {
        state,
        lifecycle,
        hh_id,
        log,
    }
}

fn payload() -> OwnerEventPayload {
    OwnerEventPayload::JoinRequest(JoinRequestPayload {
        join_request_cbor: ByteBuf::from(vec![0xa1, 0x01, 0x01]),
        fingerprint: "owner-event-test".into(),
        expiry: 1_714_972_800,
    })
}

#[test]
fn stale_generation_handle_cannot_recreate_owner_events_in_reinstalled_household() {
    let fixture = fixture(None);
    let stale_log = Arc::clone(&fixture.log);
    let original: HouseholdRecord = crate::storage::read_optional_cbor(
        &crate::storage::household_record_path(fixture.state.path()),
    )
    .unwrap()
    .unwrap();

    let write = fixture.lifecycle.lock_exclusive().unwrap();
    assert!(write.rename_household_to_tearing_down().unwrap());
    assert!(write.remove_tearing_down().unwrap());
    // Reinstall the original canonical record bytes under a fresh
    // lifecycle generation. Same hh_id, same public root: only the
    // generation distinguishes the authority instance.
    write.reserve_household_install_generation().unwrap();
    install_record(fixture.state.path(), &original);
    drop(write);

    let read = fixture.lifecycle.lock_shared().unwrap();
    let err = stale_log
        .append(
            &read,
            "m_test_issuer",
            &P256Keypair::generate(),
            OwnerEventType::JoinRequest,
            payload(),
        )
        .unwrap_err();
    assert!(matches!(err, EventError::StaleLifecycleBinding));
    assert!(!log_dir(fixture.state.path()).exists());
}

#[test]
fn parent_sync_indeterminate_does_not_publish_head_or_broadcast() {
    let broadcaster = OwnerEventsBroadcaster::new();
    let mut subscriber = broadcaster.subscribe();
    let fixture = fixture(Some(broadcaster));
    let read = fixture.lifecycle.lock_shared().unwrap();
    owner_event_fail_injection::force_parent_sync_failure_once();
    let error = fixture
        .log
        .append(
            &read,
            "m_test_issuer",
            &P256Keypair::generate(),
            OwnerEventType::JoinRequest,
            payload(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        EventError::MayHaveTakenEffect {
            stage: EventDurabilityStage::ParentSync
        }
    ));
    assert_eq!(fixture.log.cursor_head(), 0);
    assert!(matches!(
        subscriber.receiver_mut().try_recv(),
        Err(broadcast::error::TryRecvError::Empty)
    ));
}

#[test]
fn machine_joined_retry_after_ambiguous_append_stabilizes_without_duplicate() {
    let fixture = fixture(None);
    let issuer = P256Keypair::generate();
    let payload = MachineJoinedPayload {
        m_pub: ByteBuf::from(vec![2; 33]),
        m_id: "m_exact_candidate".into(),
        hostname: "candidate".into(),
        joined_at: 1_714_972_801,
    };
    let write = fixture.lifecycle.lock_exclusive().unwrap();
    owner_event_fail_injection::force_parent_sync_failure_once();
    let first = fixture
        .log
        .append_machine_joined_exactly_once_under_lifecycle_write(
            &write,
            "m_test_issuer",
            &issuer,
            payload.clone(),
        )
        .unwrap_err();
    assert!(matches!(
        first,
        EventError::MayHaveTakenEffect {
            stage: EventDurabilityStage::ParentSync
        }
    ));
    let recovered = fixture
        .log
        .append_machine_joined_exactly_once_under_lifecycle_write(
            &write,
            "m_test_issuer",
            &issuer,
            payload,
        )
        .expect("retry must find, stabilize, and reuse the exact tail event");
    assert_eq!(recovered.cursor, 1);
    drop(write);

    let read = fixture.lifecycle.lock_shared().unwrap();
    let events = fixture.log.read_since(&read, 0).unwrap();
    assert_eq!(
        events.len(),
        1,
        "ambiguous retry must not duplicate the event"
    );
}

#[test]
fn machine_joined_same_machine_with_different_payload_fails_closed() {
    let fixture = fixture(None);
    let issuer = P256Keypair::generate();
    let payload = MachineJoinedPayload {
        m_pub: ByteBuf::from(vec![2; 33]),
        m_id: "m_exact_candidate".into(),
        hostname: "candidate".into(),
        joined_at: 1_714_972_801,
    };
    let write = fixture.lifecycle.lock_exclusive().unwrap();
    fixture
        .log
        .append_machine_joined_exactly_once_under_lifecycle_write(
            &write,
            "m_test_issuer",
            &issuer,
            payload.clone(),
        )
        .unwrap();
    let mut divergent = payload;
    divergent.hostname = "replacement".into();
    let error = fixture
        .log
        .append_machine_joined_exactly_once_under_lifecycle_write(
            &write,
            "m_test_issuer",
            &issuer,
            divergent,
        )
        .unwrap_err();
    assert!(matches!(error, EventError::MachineJoinedConflict));
}

#[test]
fn household_id_mismatch_is_rejected_before_log_path_creation() {
    let state = TempDir::new().unwrap();
    let installed = record();
    install_record(state.path(), &installed);
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    let result = OwnerEventLog::open_under_lifecycle(
        &write,
        state.path().to_path_buf(),
        "hh_intentionally-not-the-installed-household",
    );
    let Err(error) = result else {
        panic!("mismatched household id must not open the log");
    };
    assert!(matches!(error, EventError::StaleLifecycleBinding));
    assert!(!log_dir(state.path()).exists());
}

/// A log written by a build that predates the `0600` requirement. Every
/// installation that paired a phone before that change carries one, and
/// without the in-place repair the first boot after updating cannot open
/// its own installed log — which is exactly the fixture that was missing
/// when the requirement landed.
#[test]
fn legacy_world_readable_log_is_repaired_instead_of_rejected() {
    let fixture = fixture(None);
    let read = fixture.lifecycle.lock_shared().unwrap();
    let appended = fixture
        .log
        .append(
            &read,
            "m_test_issuer",
            &P256Keypair::generate(),
            OwnerEventType::JoinRequest,
            payload(),
        )
        .unwrap();
    drop(read);

    let path = log_path(fixture.state.path());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    let write = fixture.lifecycle.lock_exclusive().unwrap();
    let reopened = OwnerEventLog::open_under_lifecycle(
        &write,
        fixture.state.path().to_path_buf(),
        &fixture.hh_id,
    )
    .expect("a pre-0600 log left by an older build must be repaired, not refused");
    drop(write);

    assert_eq!(reopened.cursor_head(), appended.cursor);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600,
        "the repair must tighten the log in place",
    );
}

/// The repair is not a way around the invariant. A second link means the
/// mode cannot be tightened for every name the bytes answer to, so the
/// file is left as found and validation still refuses it.
#[test]
fn multiply_linked_world_readable_log_is_left_alone_and_still_rejected() {
    let fixture = fixture(None);
    let read = fixture.lifecycle.lock_shared().unwrap();
    fixture
        .log
        .append(
            &read,
            "m_test_issuer",
            &P256Keypair::generate(),
            OwnerEventType::JoinRequest,
            payload(),
        )
        .unwrap();
    drop(read);

    let path = log_path(fixture.state.path());
    let second_link = log_dir(fixture.state.path()).join("log.cbor.link");
    fs::hard_link(&path, &second_link).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    let write = fixture.lifecycle.lock_exclusive().unwrap();
    let result = OwnerEventLog::open_under_lifecycle(
        &write,
        fixture.state.path().to_path_buf(),
        &fixture.hh_id,
    );
    drop(write);

    let Err(error) = result else {
        panic!("a multiply linked log must not be opened");
    };
    assert!(matches!(error, EventError::StaleLifecycleBinding));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o644,
        "a log that fails the guard must not be touched",
    );
}

#[test]
fn multiprocess_append_worker() {
    let Ok(state) = std::env::var(CHILD_STATE_ENV) else {
        return;
    };
    let hh_id = std::env::var(CHILD_HH_ENV).unwrap();
    let index = std::env::var(CHILD_INDEX_ENV).unwrap();
    let state = PathBuf::from(state);
    let lifecycle = HouseholdLifecycleLock::open_verified(&state).unwrap();
    let write = lifecycle.lock_exclusive().unwrap();
    let log = OwnerEventLog::open_under_lifecycle(&write, state.clone(), &hh_id).unwrap();
    drop(write);
    fs::write(state.join(format!("ready-{index}")), b"ready").unwrap();
    while !state.join("go").exists() {
        thread::sleep(Duration::from_millis(2));
    }
    let read = lifecycle.lock_shared().unwrap();
    log.append(
        &read,
        "m_test_issuer",
        &P256Keypair::generate(),
        OwnerEventType::JoinRequest,
        payload(),
    )
    .unwrap();
}

#[test]
fn multiprocess_append_allocates_unique_durable_cursors() {
    if std::env::var_os(CHILD_STATE_ENV).is_some() {
        return;
    }
    let fixture = fixture(None);
    drop(fixture.log);
    let executable = std::env::current_exe().unwrap();
    let mut children = Vec::new();
    for index in 0..6 {
        children.push(
            Command::new(&executable)
                .arg("--exact")
                .arg(CHILD_TEST)
                .arg("--nocapture")
                .env(CHILD_STATE_ENV, fixture.state.path())
                .env(CHILD_HH_ENV, &fixture.hh_id)
                .env(CHILD_INDEX_ENV, index.to_string())
                .spawn()
                .unwrap(),
        );
    }
    while (0..6)
        .filter(|index| fixture.state.path().join(format!("ready-{index}")).exists())
        .count()
        != 6
    {
        thread::sleep(Duration::from_millis(2));
    }
    fs::write(fixture.state.path().join("go"), b"go").unwrap();
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }

    let write = fixture.lifecycle.lock_exclusive().unwrap();
    let log = OwnerEventLog::open_under_lifecycle(
        &write,
        fixture.state.path().to_path_buf(),
        &fixture.hh_id,
    )
    .unwrap();
    drop(write);
    let read = fixture.lifecycle.lock_shared().unwrap();
    let events = log.read_since(&read, 0).unwrap();
    assert_eq!(events.len(), 6);
    assert_eq!(
        events.iter().map(|event| event.cursor).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6]
    );
}
