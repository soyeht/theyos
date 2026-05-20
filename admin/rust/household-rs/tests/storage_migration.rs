//! T005 + T005a regression tests for the one-shot file-layout migrations
//! exposed by `storage::load_state_dir`:
//!
//! - `pair_window.cbor` → `pair_device_window.cbor`
//! - `machine_cert.cbor` (root of `household/`) → `machine_certs/<m_id>.cbor`
//!   plus the new `self_m_id` marker file.

use std::fs;

use household_rs::pair_device::{PairDeviceWindowSnapshot, PairNonce};
use household_rs::storage::{
    HOUSEHOLD_SUBDIR, household_dir, legacy_machine_cert_path, legacy_pair_window_path,
    load_state_dir, machine_cert_for, machine_certs_dir, pair_device_window_path,
    read_optional_cbor, read_self_m_id, self_m_id_marker_path,
};
use tempfile::tempdir;

fn fake_pair_window_snapshot() -> PairDeviceWindowSnapshot {
    PairDeviceWindowSnapshot {
        version: 1,
        nonce_b64: PairNonce::random().as_b64(),
        expires_at_unix: 9_999_999_999,
        p_id_hint: None,
    }
}

#[test]
fn pair_window_rename_is_a_noop_when_target_already_exists() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();

    let snap = fake_pair_window_snapshot();
    household_rs::storage::atomic_write_cbor(&pair_device_window_path(td.path()), &snap).unwrap();
    // Stage a stale legacy file alongside.
    fs::write(legacy_pair_window_path(td.path()), b"\x00").unwrap();

    let outcome = load_state_dir(td.path()).unwrap();
    assert!(!outcome.migrated_pair_device_window);
    // Stale legacy must have been deleted; new path untouched.
    assert!(!legacy_pair_window_path(td.path()).exists());
    let still: PairDeviceWindowSnapshot = read_optional_cbor(&pair_device_window_path(td.path()))
        .unwrap()
        .unwrap();
    assert_eq!(still, snap);
}

#[test]
fn pair_window_rename_migrates_legacy_file() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();

    let snap = fake_pair_window_snapshot();
    household_rs::storage::atomic_write_cbor(&legacy_pair_window_path(td.path()), &snap).unwrap();
    assert!(legacy_pair_window_path(td.path()).exists());
    assert!(!pair_device_window_path(td.path()).exists());

    let outcome = load_state_dir(td.path()).unwrap();
    assert!(outcome.migrated_pair_device_window);
    assert!(!legacy_pair_window_path(td.path()).exists());

    let migrated: PairDeviceWindowSnapshot =
        read_optional_cbor(&pair_device_window_path(td.path()))
            .unwrap()
            .unwrap();
    assert_eq!(migrated, snap);
}

#[test]
fn pair_window_rename_is_noop_on_fresh_state_dir() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let outcome = load_state_dir(td.path()).unwrap();
    assert!(!outcome.migrated_pair_device_window);
    assert!(outcome.migrated_self_machine_cert.is_none());
}

#[test]
fn test_machine_cert_layout_migration() {
    let td = tempdir().unwrap();
    let _bootstrapped = household_rs::bootstrap_or_load(
        td.path(),
        household_rs::BootstrapOpts {
            household_name: "Sample Home".to_string(),
            hostname_label: Some("studio-mac".to_string()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap");

    // After bootstrap the unified layout is in place. Load the cert to learn
    // the m_id, then simulate a downgrade to the legacy single-file layout
    // so we can exercise the migration path.
    let cert = household_rs::machine_cert::load_self_cert(td.path())
        .expect("load")
        .expect("present");
    let m_id_str = cert.m_id.to_string();

    let unified_path = machine_cert_for(td.path(), &m_id_str);
    let legacy_path = legacy_machine_cert_path(td.path());
    let marker_path = self_m_id_marker_path(td.path());

    // Roll back to legacy: move unified → legacy, drop marker, drop dir.
    fs::rename(&unified_path, &legacy_path).unwrap();
    fs::remove_dir_all(machine_certs_dir(td.path())).unwrap();
    fs::remove_file(&marker_path).unwrap();
    assert!(legacy_path.exists());
    assert!(!unified_path.exists());
    assert!(!marker_path.exists());

    // Re-run the migration.
    let outcome = load_state_dir(td.path()).unwrap();
    assert_eq!(
        outcome.migrated_self_machine_cert.as_deref(),
        Some(m_id_str.as_str())
    );

    // Legacy is gone, unified path holds the cert, marker matches.
    assert!(!legacy_path.exists());
    let migrated: household_rs::MachineCert = read_optional_cbor(&unified_path).unwrap().unwrap();
    assert_eq!(migrated, cert);
    assert_eq!(
        read_self_m_id(td.path()).unwrap().as_deref(),
        Some(m_id_str.as_str())
    );

    // Re-running is idempotent.
    let again = load_state_dir(td.path()).unwrap();
    assert!(again.migrated_self_machine_cert.is_none());
    assert!(!again.migrated_pair_device_window);
}

#[test]
fn machine_cert_migration_target_collision_drops_legacy() {
    let td = tempdir().unwrap();
    let _bootstrapped = household_rs::bootstrap_or_load(
        td.path(),
        household_rs::BootstrapOpts {
            household_name: "Sample Home".to_string(),
            hostname_label: Some("studio-mac".to_string()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap");

    let cert = household_rs::machine_cert::load_self_cert(td.path())
        .expect("load")
        .expect("present");
    let m_id_str = cert.m_id.to_string();

    // Stage a stale (but well-formed) legacy file alongside the canonical
    // layout. Real-world this can happen if a buggy older daemon wrote
    // both paths during a partial upgrade.
    let unified_path = machine_cert_for(td.path(), &m_id_str);
    let legacy_bytes = fs::read(&unified_path).unwrap();
    fs::write(legacy_machine_cert_path(td.path()), &legacy_bytes).unwrap();

    let outcome = load_state_dir(td.path()).unwrap();
    // Target already existed → migration reports None and drops the legacy.
    assert!(outcome.migrated_self_machine_cert.is_none());
    assert!(!legacy_machine_cert_path(td.path()).exists());

    // Marker survives and continues to point at the canonical id.
    let marker = read_self_m_id(td.path()).unwrap();
    assert_eq!(marker.as_deref(), Some(m_id_str.as_str()));

    // Subdir must NOT have been emptied.
    let still: household_rs::MachineCert = read_optional_cbor(&unified_path).unwrap().unwrap();
    assert_eq!(still, cert);

    let _ = HOUSEHOLD_SUBDIR; // suppress unused-import lint if it later appears
}

#[test]
fn missing_marker_is_recovered_from_singleton_machine_cert() {
    // Simulates a crash between save_self_cert's two staged renames:
    // the cert landed in machine_certs/<m_id>.cbor but the marker was
    // never promoted. load_state_dir must reconstruct it.
    let td = tempdir().unwrap();
    let _bootstrapped = household_rs::bootstrap_or_load(
        td.path(),
        household_rs::BootstrapOpts {
            household_name: "Sample Home".to_string(),
            hostname_label: Some("studio-mac".to_string()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap");

    let cert = household_rs::machine_cert::load_self_cert(td.path())
        .expect("load")
        .expect("present");
    let m_id_str = cert.m_id.to_string();

    // Drop just the marker — cert stays.
    fs::remove_file(self_m_id_marker_path(td.path())).unwrap();
    assert!(read_self_m_id(td.path()).unwrap().is_none());

    let outcome = load_state_dir(td.path()).unwrap();
    assert_eq!(
        outcome.recovered_self_m_id_marker.as_deref(),
        Some(m_id_str.as_str())
    );
    assert_eq!(
        read_self_m_id(td.path()).unwrap().as_deref(),
        Some(m_id_str.as_str())
    );
}

#[test]
fn marker_recovery_skipped_when_multiple_certs_present() {
    // Phase 3 leaves two certs under machine_certs/. With marker present
    // (the normal case) recovery is a no-op; with marker missing AND
    // ambiguous certs, recovery must NOT pick one — that would risk
    // pinning the wrong identity. Operator must intervene.
    let td = tempdir().unwrap();
    fs::create_dir_all(machine_certs_dir(td.path())).unwrap();
    fs::write(
        machine_certs_dir(td.path()).join("m_first.cbor"),
        b"placeholder1",
    )
    .unwrap();
    fs::write(
        machine_certs_dir(td.path()).join("m_second.cbor"),
        b"placeholder2",
    )
    .unwrap();

    let outcome = load_state_dir(td.path()).unwrap();
    assert!(outcome.recovered_self_m_id_marker.is_none());
    assert!(read_self_m_id(td.path()).unwrap().is_none());
}

#[test]
fn sole_shard_alongside_shamir_is_recovered_at_boot() {
    // Simulates a crash between CeremonyTxn::commit's staged.commit()
    // and remove_file(sole_shard). On reboot, both files are alive and
    // the plaintext root is reachable from disk — a security
    // regression. load_state_dir must delete the sole-shard.
    //
    // R6.5: the probe also gates on `record.shamir_n > 1` so that an
    // intermediate crash that promoted `self_shard.cbor` but not the
    // record cannot mis-classify as committed and lose the pre-Shamir
    // root. This test plants a real post-Shamir record alongside the
    // residual `sole` to model the genuine "commit landed, sole-shard
    // unlink crashed" scenario.
    use household_rs::HouseholdRecord;
    use household_rs::cbor;
    use household_rs::keys::{IdentityKey, P256Keypair};
    use household_rs::storage::household_record_path;

    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let shamir_dir = household_dir(td.path()).join("shamir");
    fs::create_dir_all(&shamir_dir).unwrap();

    let hh_kp = P256Keypair::generate();
    let m1_kp = P256Keypair::generate();
    let m2_kp = P256Keypair::generate();
    let hh_id = household_rs::derive_household_id(&hh_kp.public());
    let m1_id = household_rs::derive_machine_id(&m1_kp.public());
    let m2_id = household_rs::derive_machine_id(&m2_kp.public());
    let mut members = vec![m1_id.clone(), m2_id.clone()];
    members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let post_record = HouseholdRecord {
        version: 1,
        hh_id,
        hh_pub: hh_kp.public(),
        name: "Sample Home".into(),
        created_at: 1_700_000_000,
        shamir_k: 2,
        shamir_n: 2,
        members,
        is_follower: false,
    };
    fs::write(
        household_record_path(td.path()),
        cbor::to_canonical_vec(&post_record).unwrap(),
    )
    .unwrap();

    let sole_path = household_dir(td.path()).join("household_root_sole.cbor");
    let shamir_self_path = shamir_dir.join("self_shard.cbor");
    fs::write(&sole_path, b"plaintext-root-bytes").unwrap();
    fs::write(&shamir_self_path, b"shamir-encrypted-share").unwrap();

    let outcome = load_state_dir(td.path()).unwrap();
    assert!(outcome.recovered_post_join_sole_shard_deleted);
    assert!(!sole_path.exists(), "sole-shard must be deleted");
    assert!(shamir_self_path.exists(), "Shamir state survives");

    // Re-running is idempotent.
    let again = load_state_dir(td.path()).unwrap();
    assert!(!again.recovered_post_join_sole_shard_deleted);
}

#[test]
fn sole_shard_alone_is_not_touched() {
    // 1-machine household before any join: only sole-shard exists.
    // Recovery must NOT delete it (would brick the household).
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let sole_path = household_dir(td.path()).join("household_root_sole.cbor");
    fs::write(&sole_path, b"plaintext-root-bytes").unwrap();

    let outcome = load_state_dir(td.path()).unwrap();
    assert!(!outcome.recovered_post_join_sole_shard_deleted);
    assert!(
        sole_path.exists(),
        "sole-shard must survive in 1-machine state"
    );
}

#[test]
fn shamir_alone_is_not_touched() {
    // Steady state after the join completed cleanly: only Shamir state.
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path()).join("shamir")).unwrap();
    let shamir_path = household_dir(td.path())
        .join("shamir")
        .join("self_shard.cbor");
    fs::write(&shamir_path, b"shamir-encrypted-share").unwrap();

    let outcome = load_state_dir(td.path()).unwrap();
    assert!(!outcome.recovered_post_join_sole_shard_deleted);
    assert!(shamir_path.exists());
}

#[test]
fn detect_orphan_walks_machine_certs_subdir() {
    let td = tempdir().unwrap();
    fs::create_dir_all(machine_certs_dir(td.path())).unwrap();
    let staged_cert = machine_certs_dir(td.path()).join("m_candidate.cbor.staged");
    fs::write(&staged_cert, b"\x01\x02").unwrap();

    let orphans = household_rs::storage::detect_orphan_staged_files(td.path());
    assert!(
        orphans.iter().any(|p| p == &staged_cert),
        "machine_certs/<m>.cbor.staged should be detected; got {orphans:?}"
    );
}
