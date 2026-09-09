#![cfg(test)]

use super::*;
use household_rs::machine_cert::SignOptions;
use household_rs::{HouseholdRecord, IdentityKey, P256Keypair, Platform};
use std::sync::mpsc;
use std::time::Duration as StdDuration;

const CRASH_STAGE_ENV: &str = "THEYOS_TEST_HOUSEHOLD_TEARDOWN_CRASH_STAGE";
const CRASH_STATE_DIR_ENV: &str = "THEYOS_TEST_HOUSEHOLD_TEARDOWN_STATE_DIR";
const CRASH_HH_ID_ENV: &str = "THEYOS_TEST_HOUSEHOLD_TEARDOWN_HH_ID";
const CRASH_M_ID_ENV: &str = "THEYOS_TEST_HOUSEHOLD_TEARDOWN_M_ID";
const CRASH_EXIT: i32 = 73;

fn installed_household() -> (tempfile::TempDir, String, String) {
    let temp = tempfile::tempdir().expect("tempdir");
    let state_dir = temp.path();
    let household_key = P256Keypair::generate();
    let machine_key = P256Keypair::generate();
    let hh_pub = household_key.public();
    let hh_id = household_rs::derive_household_id(&hh_pub);
    let m_pub = machine_key.public();
    let m_id = household_rs::derive_machine_id(&m_pub);
    let record = HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: hh_id.clone(),
        hh_pub,
        name: "Lifecycle Test Home".into(),
        created_at: 1,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![m_id.clone()],
        is_follower: false,
    };
    let cert = household_rs::MachineCert::sign(
        &household_key as &dyn IdentityKey,
        &m_pub,
        &SignOptions {
            hh_id: hh_id.clone(),
            hostname: "lifecycle-test".into(),
            platform: Platform::Macos,
            joined_at: 1,
        },
    )
    .expect("machine cert");

    std::fs::create_dir_all(household_rs::storage::household_dir(state_dir))
        .expect("household dir");
    household_rs::storage::atomic_write_cbor(
        &household_rs::storage::household_record_path(state_dir),
        &record,
    )
    .expect("household record");
    household_rs::machine_cert::save_self_cert(state_dir, &cert).expect("self cert");
    let lifecycle = HouseholdLifecycleLock::open_verified(state_dir).expect("lifecycle");
    let guard = lifecycle.lock_exclusive().expect("lifecycle guard");
    let generation = guard
        .ensure_lifecycle_generation()
        .expect("lifecycle generation");
    bootstrap_state::persist_ready_under_lifecycle(&guard, state_dir, generation)
        .expect("bootstrap state");

    (temp, hh_id.to_string(), m_id.to_string())
}

#[test]
fn lifecycle_shared_must_drain_before_teardown_can_rename() {
    let (temp, hh_id, m_id) = installed_household();
    let state_dir = temp.path().to_path_buf();
    let lifecycle = HouseholdLifecycleLock::open_verified(&state_dir).expect("lifecycle");
    let shared = lifecycle.lock_shared().expect("shared");
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker_state_dir = state_dir.clone();

    let worker = std::thread::spawn(move || {
        started_tx.send(()).expect("started");
        let result = teardown_household_on_disk(&worker_state_dir, &hh_id, &m_id);
        done_tx.send(result).expect("done");
    });
    started_rx.recv().expect("worker started");
    assert!(
        done_rx.recv_timeout(StdDuration::from_millis(100)).is_err(),
        "teardown acquired exclusive while a lifecycle-shared operation was live"
    );
    assert!(
        household_rs::storage::household_dir(&state_dir).is_dir(),
        "household was renamed before the shared operation drained"
    );

    drop(shared);
    assert!(matches!(
        done_rx
            .recv_timeout(StdDuration::from_secs(5))
            .expect("teardown did not finish after shared dropped")
            .expect("teardown transaction"),
        HouseholdTeardownDiskOutcome::Detached { .. }
    ));
    worker.join().expect("worker join");
    assert!(!household_rs::storage::household_dir(&state_dir).exists());
    assert_eq!(
        bootstrap_state::load(&state_dir).expect("load state"),
        BootstrapState::Uninitialized
    );
}

#[test]
fn detached_cleanup_guard_blocks_next_lifecycle_writer_until_cleanup_fsync() {
    let (temp, hh_id, m_id) = installed_household();
    let state_dir = temp.path().to_path_buf();
    let guard =
        match teardown_household_on_disk(&state_dir, &hh_id, &m_id).expect("detach household") {
            HouseholdTeardownDiskOutcome::Detached { guard } => guard,
            HouseholdTeardownDiskOutcome::Recovered { .. } => panic!("fresh fixture recovered"),
            HouseholdTeardownDiskOutcome::DetachedNeedsRecovery { error, .. } => {
                panic!("fresh fixture became indeterminate: {error}")
            }
        };
    let contender_dir = state_dir.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel();
    let contender = std::thread::spawn(move || {
        let lifecycle =
            HouseholdLifecycleLock::open_verified(&contender_dir).expect("contender open");
        started_tx.send(()).expect("started");
        let _next = lifecycle.lock_exclusive().expect("contender exclusive");
        acquired_tx.send(()).expect("acquired");
    });
    started_rx.recv().expect("contender started");
    assert!(
        acquired_rx
            .recv_timeout(StdDuration::from_millis(100))
            .is_err(),
        "a second lifecycle writer entered while the detached cleanup guard was live"
    );

    assert!(guard.remove_tearing_down().expect("cleanup + root fsync"));
    drop(guard);
    acquired_rx
        .recv_timeout(StdDuration::from_secs(5))
        .expect("contender stayed blocked after cleanup guard dropped");
    contender.join().expect("contender join");
}

#[test]
fn failed_state_persist_keeps_breadcrumb_and_retry_recovers_it() {
    let (temp, hh_id, m_id) = installed_household();
    let state_dir = temp.path();
    // `bootstrap_state::persist` writes `identity.tmp`. A directory at
    // that exact path deterministically fails the state commit after the
    // household rename, modelling a crash/fault in that window.
    let blocked_tmp = state_dir.join("identity.tmp");
    std::fs::create_dir(&blocked_tmp).expect("block state tmp");

    let (guard, error) = match teardown_household_on_disk(state_dir, &hh_id, &m_id)
        .expect("post-rename failure must retain the lifecycle guard")
    {
        HouseholdTeardownDiskOutcome::DetachedNeedsRecovery { guard, error } => (guard, error),
        HouseholdTeardownDiskOutcome::Detached { .. } => {
            panic!("blocked state commit unexpectedly succeeded")
        }
        HouseholdTeardownDiskOutcome::Recovered { .. } => panic!("fresh fixture recovered"),
    };
    assert!(error.to_string().contains("persist bootstrap state"));
    assert!(!household_rs::storage::household_dir(state_dir).exists());
    assert!(state_dir.join("household.tearing-down").is_dir());
    assert_eq!(
        bootstrap_state::load(state_dir).expect("old state remains readable"),
        BootstrapState::Ready
    );

    // The indeterminate path retains lifecycle-exclusive until the caller
    // has removed every in-memory authority surface and initiated its
    // deterministic fail-stop. A restart cannot recover beneath it.
    let contender_dir = state_dir.to_path_buf();
    let (acquired_tx, acquired_rx) = mpsc::channel();
    let contender = std::thread::spawn(move || {
        let lifecycle =
            HouseholdLifecycleLock::open_verified(&contender_dir).expect("contender lifecycle");
        let _write = lifecycle.lock_exclusive().expect("contender exclusive");
        acquired_tx.send(()).expect("acquired");
    });
    assert!(
        acquired_rx
            .recv_timeout(StdDuration::from_millis(100))
            .is_err(),
        "post-rename failure released lifecycle authority before fail-close"
    );

    std::fs::remove_dir(&blocked_tmp).expect("unblock state tmp");
    drop(guard);
    acquired_rx
        .recv_timeout(StdDuration::from_secs(5))
        .expect("contender stayed blocked after retained guard dropped");
    contender.join().expect("contender join");
    assert!(matches!(
        teardown_household_on_disk(state_dir, &hh_id, &m_id).expect("recover retry"),
        HouseholdTeardownDiskOutcome::Recovered { .. }
    ));
    assert!(!state_dir.join("household.tearing-down").exists());
    assert_eq!(
        bootstrap_state::load(state_dir).expect("recovered state"),
        BootstrapState::Uninitialized
    );
}

#[test]
fn two_household_candidates_fail_closed_without_deleting_either() {
    let (temp, hh_id, m_id) = installed_household();
    let state_dir = temp.path();
    std::fs::create_dir(state_dir.join("household.tearing-down")).expect("second candidate");

    let error = teardown_household_on_disk(state_dir, &hh_id, &m_id)
        .expect_err("ambiguous authority must fail closed");
    assert!(
        error.to_string().contains("refusing to choose authority"),
        "unexpected error: {error}"
    );
    assert!(household_rs::storage::household_dir(state_dir).is_dir());
    assert!(state_dir.join("household.tearing-down").is_dir());
    assert_eq!(
        bootstrap_state::load(state_dir).expect("state unchanged"),
        BootstrapState::Ready
    );
}

#[test]
fn final_disk_identity_recheck_precedes_rename() {
    let (temp, _hh_id, m_id) = installed_household();
    let state_dir = temp.path();
    let error = teardown_household_on_disk(state_dir, "hh_wrong", &m_id)
        .expect_err("wrong household must be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(household_rs::storage::household_dir(state_dir).is_dir());
    assert!(!state_dir.join("household.tearing-down").exists());
}

#[test]
fn teardown_transfers_exclusive_to_cleanup_after_in_memory_publication() {
    let source = include_str!("../handlers_bootstrap.rs");
    let start = source
        .find("pub async fn post_teardown(")
        .expect("post_teardown");
    let end = source[start..]
        .find("\n}\n\n/// `POST /bootstrap/accept-household`")
        .expect("post_teardown end")
        + start;
    let body = &source[start..end];
    let clear = body.find("state.household.clear().await;").expect("clear");
    let publish = body
        .find("*state.bootstrap.write().await = BootstrapState::Uninitialized;")
        .expect("bootstrap publish");
    let cleanup = body
        .find("let _cleanup = tokio::task::spawn_blocking(move ||")
        .expect("guard-owning cleanup");
    assert!(clear < cleanup && publish < cleanup);
    assert!(body[cleanup..].contains("lifecycle_guard.remove_tearing_down()"));
    assert!(
        !body.contains("remove_dir_all("),
        "fixed-name cleanup must stay fd-bound and lifecycle-exclusive"
    );
}

/// Child entrypoint for the subprocess crash matrix below. With no env it
/// is a harmless no-op in an ordinary test run; the parent invokes this
/// exact test with a stage and exits the process without running Drop.
#[test]
fn teardown_crash_worker() {
    let Ok(stage) = std::env::var(CRASH_STAGE_ENV) else {
        return;
    };
    let state_dir = PathBuf::from(std::env::var(CRASH_STATE_DIR_ENV).expect("state dir"));
    let hh_id = std::env::var(CRASH_HH_ID_ENV).expect("hh id");
    let m_id = std::env::var(CRASH_M_ID_ENV).expect("m id");
    let (guard, recovered) =
        acquire_recovered_lifecycle_exclusive(&state_dir).expect("child lifecycle exclusive");
    assert!(!recovered, "fresh child fixture unexpectedly recovered");
    verify_installed_household_for_teardown(&state_dir, &hh_id, &m_id)
        .expect("child authority recheck");

    match stage.as_str() {
        "before_rename" => {}
        "after_rename_before_root_fsync" => {
            std::fs::rename(
                household_rs::storage::household_dir(&state_dir),
                state_dir.join("household.tearing-down"),
            )
            .expect("raw rename before crash");
        }
        "after_root_fsync_before_uninitialized" => {
            assert!(
                guard
                    .rename_household_to_tearing_down()
                    .expect("durable rename")
            );
        }
        "after_uninitialized_before_cleanup" => {
            assert!(
                guard
                    .rename_household_to_tearing_down()
                    .expect("durable rename")
            );
            persist_uninitialized_durably(&guard, &state_dir).expect("durable uninitialized");
        }
        other => panic!("unknown crash stage {other}"),
    }

    // Deliberately bypass destructors, including the lifecycle guard. The
    // OS must release flock and a fresh process must converge from disk.
    std::process::exit(CRASH_EXIT);
}

#[test]
fn subprocess_crash_matrix_converges_under_exclusive_before_reuse() {
    let worker_name =
        "handlers_bootstrap::household_teardown_lifecycle_tests::teardown_crash_worker";
    for (stage, expected_recovery) in [
        ("before_rename", false),
        ("after_rename_before_root_fsync", true),
        ("after_root_fsync_before_uninitialized", true),
        ("after_uninitialized_before_cleanup", true),
    ] {
        let (temp, hh_id, m_id) = installed_household();
        let output = std::process::Command::new(std::env::current_exe().expect("current exe"))
            .args(["--exact", worker_name, "--nocapture", "--test-threads=1"])
            .env(CRASH_STAGE_ENV, stage)
            .env(CRASH_STATE_DIR_ENV, temp.path())
            .env(CRASH_HH_ID_ENV, &hh_id)
            .env(CRASH_M_ID_ENV, &m_id)
            .output()
            .expect("spawn crash worker");
        assert_eq!(
            output.status.code(),
            Some(CRASH_EXIT),
            "stage={stage}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let outcome = teardown_household_on_disk(temp.path(), &hh_id, &m_id)
            .unwrap_or_else(|error| panic!("stage={stage}: recovery failed: {error}"));
        assert_eq!(
            matches!(&outcome, HouseholdTeardownDiskOutcome::Recovered { .. }),
            expected_recovery,
            "stage={stage}"
        );
        drop(outcome);
        assert_eq!(
            bootstrap_state::load(temp.path()).expect("final bootstrap state"),
            BootstrapState::Uninitialized,
            "stage={stage}"
        );
        assert!(!household_rs::storage::household_dir(temp.path()).exists());
        if expected_recovery {
            assert!(!temp.path().join("household.tearing-down").exists());
        }
    }
}
