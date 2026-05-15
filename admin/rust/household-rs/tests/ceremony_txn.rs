//! T033 coverage for `pair_machine::CeremonyTxn`: prepare → commit
//! deletes `household_root_sole.cbor` as the last step; prepare →
//! rollback leaves the sole shard intact and clears every staged
//! file. Drop without commit/rollback also clears staged files.

#![allow(clippy::type_complexity)]

use std::fs;

use household_rs::HouseholdRecord;
use household_rs::ids::derive_household_id;
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::machine_cert::Platform;
use household_rs::pair_machine::{
    CeremonyInputs, CeremonyTxn, household_root_sole_path, shamir_self_shard_path,
};
use household_rs::storage::{
    HOUSEHOLD_SUBDIR, household_dir, household_record_path, machine_cert_for, staged_path_for,
};
use tempfile::tempdir;
use zeroize::Zeroizing;

#[allow(clippy::type_complexity)]
fn fixture() -> (
    tempfile::TempDir,
    P256Keypair,
    P256Keypair,
    P256Keypair,
    Zeroizing<[u8; 32]>,
    [u8; 33],
    [u8; 33],
    [u8; 33],
    String,
    household_rs::HouseholdId,
    HouseholdRecord,
) {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    // Stage a fake sole-shard so commit can delete it.
    fs::write(household_root_sole_path(td.path()), b"fake-sole-shard").unwrap();
    let _ = HOUSEHOLD_SUBDIR; // anchor
    let hh_kp = P256Keypair::generate();
    let m1_kp = P256Keypair::generate();
    let m2_kp = P256Keypair::generate();
    let hh_priv = Zeroizing::new(*hh_kp.as_software_secret().unwrap());
    let hh_pub = *hh_kp.public().as_bytes();
    let m1_pub = *m1_kp.public().as_bytes();
    let m2_pub = *m2_kp.public().as_bytes();
    let m1_id_typed = household_rs::derive_machine_id(&m1_kp.public());
    let m1_id = m1_id_typed.to_string();
    let hh_id = derive_household_id(&hh_kp.public());
    // Pre-join HouseholdRecord (Phase 1 shape: 1-of-1, single member).
    let existing_record = HouseholdRecord {
        version: 1,
        hh_id: hh_id.clone(),
        hh_pub: hh_kp.public(),
        name: "Sample Home".into(),
        created_at: 1_714_972_800,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![m1_id_typed],
    };
    (
        td,
        hh_kp,
        m1_kp,
        m2_kp,
        hh_priv,
        hh_pub,
        m1_pub,
        m2_pub,
        m1_id,
        hh_id,
        existing_record,
    )
}

#[test]
fn commit_deletes_sole_shard_as_last_step() {
    let (td, _hh_kp, m1_kp, m2_kp, hh_priv, hh_pub, m1_pub, m2_pub, m1_id, hh_id, existing_record) =
        fixture();
    let m1_priv = Zeroizing::new(*m1_kp.as_software_secret().unwrap());
    let m2_id = household_rs::derive_machine_id(&m2_kp.public()).to_string();
    let txn = CeremonyTxn::prepare(CeremonyInputs {
        hh_priv,
        hh_id,
        hh_pub_sec1: hh_pub,
        m1_priv_scalar: m1_priv.clone(),
        m1_pub_sec1: m1_pub,
        m1_id,
        candidate_m_pub_sec1: m2_pub,
        candidate_hostname: "studio-linux".into(),
        candidate_platform: Platform::LinuxNix,
        joined_at: 1_714_972_800,
        state_dir: td.path().to_path_buf(),
        existing_record: existing_record.clone(),
        policy: household_rs::KeyBackingPolicy::ForceSoftware,
    })
    .unwrap();

    // Staged files should exist on disk; their final paths should not.
    let cert_path = machine_cert_for(td.path(), &m2_id);
    let shard_path = shamir_self_shard_path(td.path());
    assert!(staged_path_for(&cert_path).exists());
    assert!(staged_path_for(&shard_path).exists());
    assert!(!cert_path.exists());
    assert!(!shard_path.exists());
    // Sole-shard still present pre-commit.
    assert!(household_root_sole_path(td.path()).exists());

    let record_path = household_record_path(td.path());
    assert!(staged_path_for(&record_path).exists());

    let cert_bytes = txn.commit().unwrap();
    assert!(!cert_bytes.is_empty());
    assert!(cert_path.exists());
    assert!(shard_path.exists());
    assert!(record_path.exists());
    assert!(!staged_path_for(&cert_path).exists());
    assert!(!staged_path_for(&shard_path).exists());
    assert!(!staged_path_for(&record_path).exists());
    // Sole-shard deleted as the last step.
    assert!(!household_root_sole_path(td.path()).exists());

    // Post-commit record must reflect the 2-of-2 / two-member shape.
    let bytes = fs::read(&record_path).unwrap();
    let record: HouseholdRecord =
        household_rs::cbor::from_canonical_slice(&bytes).expect("decode post-commit record");
    assert_eq!(record.shamir_k, 2);
    assert_eq!(record.shamir_n, 2);
    assert_eq!(record.members.len(), 2);
    record.validate().expect("post-commit record must validate");
}

#[test]
fn rollback_keeps_sole_shard_and_clears_staged() {
    let (td, _hh_kp, m1_kp, m2_kp, hh_priv, hh_pub, m1_pub, m2_pub, m1_id, hh_id, existing_record) =
        fixture();
    let m1_priv = Zeroizing::new(*m1_kp.as_software_secret().unwrap());
    let m2_id = household_rs::derive_machine_id(&m2_kp.public()).to_string();
    let txn = CeremonyTxn::prepare(CeremonyInputs {
        hh_priv,
        hh_id,
        hh_pub_sec1: hh_pub,
        m1_priv_scalar: m1_priv.clone(),
        m1_pub_sec1: m1_pub,
        m1_id,
        candidate_m_pub_sec1: m2_pub,
        candidate_hostname: "studio-linux".into(),
        candidate_platform: Platform::LinuxNix,
        joined_at: 1_714_972_800,
        state_dir: td.path().to_path_buf(),
        existing_record: existing_record.clone(),
        policy: household_rs::KeyBackingPolicy::ForceSoftware,
    })
    .unwrap();

    txn.rollback();
    let cert_path = machine_cert_for(td.path(), &m2_id);
    let shard_path = shamir_self_shard_path(td.path());
    let record_path = household_record_path(td.path());
    assert!(!staged_path_for(&cert_path).exists());
    assert!(!staged_path_for(&shard_path).exists());
    assert!(!staged_path_for(&record_path).exists());
    assert!(!cert_path.exists());
    assert!(!shard_path.exists());
    // The pre-existing record on disk would survive (we never wrote one
    // here); the staged copy must be absent. Sole-shard untouched.
    assert!(!record_path.exists());
    assert!(household_root_sole_path(td.path()).exists());
}

#[test]
fn drop_without_commit_clears_staged() {
    let (td, _hh_kp, m1_kp, m2_kp, hh_priv, hh_pub, m1_pub, m2_pub, m1_id, hh_id, existing_record) =
        fixture();
    let m1_priv = Zeroizing::new(*m1_kp.as_software_secret().unwrap());
    let m2_id = household_rs::derive_machine_id(&m2_kp.public()).to_string();
    {
        let _txn = CeremonyTxn::prepare(CeremonyInputs {
            hh_priv,
            hh_id,
            hh_pub_sec1: hh_pub,
            m1_priv_scalar: m1_priv.clone(),
            m1_pub_sec1: m1_pub,
            m1_id,
            candidate_m_pub_sec1: m2_pub,
            candidate_hostname: "studio-linux".into(),
            candidate_platform: Platform::LinuxNix,
            joined_at: 1_714_972_800,
            state_dir: td.path().to_path_buf(),
            existing_record: existing_record.clone(),
            policy: household_rs::KeyBackingPolicy::ForceSoftware,
        })
        .unwrap();
        // Drop without commit/rollback.
    }
    let cert_path = machine_cert_for(td.path(), &m2_id);
    let shard_path = shamir_self_shard_path(td.path());
    let record_path = household_record_path(td.path());
    assert!(!staged_path_for(&cert_path).exists());
    assert!(!staged_path_for(&shard_path).exists());
    assert!(!staged_path_for(&record_path).exists());
    assert!(household_root_sole_path(td.path()).exists());
}

/// B1 regression — `CeremonyTxn::commit` MUST destroy the keystore custody
/// of `HH_priv` in addition to deleting the sole-shard plaintext, so that
/// the post-Shamir household has zero plaintext copies of the household
/// root scalar accessible to M1. Reading the scalar back via the same
/// keystore label must fail with `NotFound`.
#[test]
fn commit_destroys_keystore_custody_of_hh_priv() {
    let (td, _hh_kp, m1_kp, _m2_kp, hh_priv, hh_pub, m1_pub, m2_pub, m1_id, hh_id, existing_record) =
        fixture();
    let m1_priv = Zeroizing::new(*m1_kp.as_software_secret().unwrap());

    // Persist hh_priv in the software-fallback keystore as bootstrap
    // would have. After commit, this entry MUST be gone.
    let account = household_rs::keystore::hh_priv_account(&hh_id);
    household_rs::keystore::software_fallback::write_secret_scalar(td.path(), &account, &hh_priv)
        .unwrap();
    let pre =
        household_rs::keystore::software_fallback::read_secret_scalar(td.path(), &account).unwrap();
    assert_eq!(&pre, &*hh_priv);

    let txn = CeremonyTxn::prepare(CeremonyInputs {
        hh_priv,
        hh_id: hh_id.clone(),
        hh_pub_sec1: hh_pub,
        m1_priv_scalar: m1_priv.clone(),
        m1_pub_sec1: m1_pub,
        m1_id,
        candidate_m_pub_sec1: m2_pub,
        candidate_hostname: "studio-linux".into(),
        candidate_platform: Platform::LinuxNix,
        joined_at: 1_714_972_800,
        state_dir: td.path().to_path_buf(),
        existing_record,
        policy: household_rs::KeyBackingPolicy::ForceSoftware,
    })
    .unwrap();

    txn.commit().unwrap();

    // Sole-shard plaintext must be gone.
    assert!(!household_root_sole_path(td.path()).exists());

    // Keystore custody must be gone too. The post-condition is
    // `NotFound`, not the still-readable original scalar.
    let read = household_rs::keystore::software_fallback::read_secret_scalar(td.path(), &account);
    match read {
        Err(household_rs::error::KeystoreError::NotFound { .. }) => {}
        other => panic!(
            "expected NotFound after commit, got {:?}",
            other.as_ref().map(|_| "Ok(_)")
        ),
    }

    // Calling `destroy_household_keystore_material` again is a no-op.
    household_rs::destroy_household_keystore_material(
        td.path(),
        &hh_id,
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("idempotent destroy");
}

/// B6 regression — after the Shamir transition `try_load_existing` MUST
/// deliver `hh_priv: None` so handlers gating on
/// `record.shamir_n == 1 && hh_priv.is_some()` refuse to mint new
/// `MachineCert`s under the now-distributed household root.
#[test]
fn reload_after_commit_returns_no_hh_priv() {
    use household_rs::machine_cert::SignOptions;
    let (td, hh_kp, m1_kp, _m2_kp, hh_priv, hh_pub, m1_pub, m2_pub, m1_id, hh_id, existing_record) =
        fixture();
    let m1_priv = Zeroizing::new(*m1_kp.as_software_secret().unwrap());

    // The post-Shamir reload reads `machine_certs/<self_m_id>.cbor`,
    // which requires (a) a `self_m_id` marker and (b) M1's MachineCert
    // on disk. Stage both.
    let m1_id_typed = household_rs::derive_machine_id(&m1_kp.public());
    let m1_cert = household_rs::machine_cert::MachineCert::sign(
        &hh_kp,
        &m1_kp.public(),
        &SignOptions {
            hh_id: hh_id.clone(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            joined_at: 1_714_972_800,
        },
    )
    .unwrap();
    household_rs::machine_cert::save_self_cert(td.path(), &m1_cert).unwrap();
    fs::write(
        household_dir(td.path()).join("self_m_id"),
        format!("{m1_id_typed}\n"),
    )
    .unwrap();

    // Persist M1's machine key in the software-fallback keystore.
    let m1_account = household_rs::keystore::m_priv_account(&m1_id_typed);
    household_rs::keystore::software_fallback::write_secret_scalar(
        td.path(),
        &m1_account,
        &m1_priv,
    )
    .unwrap();
    // And HH_priv (so commit has something to destroy).
    let hh_account = household_rs::keystore::hh_priv_account(&hh_id);
    household_rs::keystore::software_fallback::write_secret_scalar(
        td.path(),
        &hh_account,
        &hh_priv,
    )
    .unwrap();

    let txn = CeremonyTxn::prepare(CeremonyInputs {
        hh_priv,
        hh_id: hh_id.clone(),
        hh_pub_sec1: hh_pub,
        m1_priv_scalar: m1_priv,
        m1_pub_sec1: m1_pub,
        m1_id,
        candidate_m_pub_sec1: m2_pub,
        candidate_hostname: "studio-linux".into(),
        candidate_platform: Platform::LinuxNix,
        joined_at: 1_714_972_900,
        state_dir: td.path().to_path_buf(),
        existing_record,
        policy: household_rs::KeyBackingPolicy::ForceSoftware,
    })
    .unwrap();
    txn.commit().unwrap();

    let reloaded =
        household_rs::try_load_existing(td.path(), household_rs::KeyBackingPolicy::ForceSoftware)
            .unwrap()
            .expect("post-commit identity");
    assert_eq!(reloaded.record.shamir_n, 2);
    assert!(
        reloaded.hh_priv.is_none(),
        "post-Shamir LoadedIdentity must carry hh_priv = None"
    );
    // M1's machine private key still loads — M1 still has its own
    // signing identity for its MachineCert.
    assert_eq!(
        reloaded.m_priv.public().as_bytes(),
        m1_kp.public().as_bytes()
    );
}

/// R5.4 regression — the B1 invariant ("post-Shamir household carries
/// no plaintext `HH_priv` anywhere") is closed even when the original
/// `CeremonyTxn::commit` keystore-destroy step failed transiently:
/// the next `try_load_existing` on the post-Shamir record MUST
/// idempotently re-attempt the destruction. This is the boot-time
/// safety net for the partial-cleanup state, since T073/T074 (the
/// explicit recovery driver) is still outstanding.
#[test]
fn try_load_existing_retries_keystore_destroy_for_post_shamir_household() {
    use household_rs::machine_cert::SignOptions;
    let (td, hh_kp, m1_kp, _m2_kp, hh_priv, hh_pub, m1_pub, m2_pub, m1_id, hh_id, existing_record) =
        fixture();
    let m1_priv = Zeroizing::new(*m1_kp.as_software_secret().unwrap());

    let m1_id_typed = household_rs::derive_machine_id(&m1_kp.public());
    let m1_cert = household_rs::machine_cert::MachineCert::sign(
        &hh_kp,
        &m1_kp.public(),
        &SignOptions {
            hh_id: hh_id.clone(),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            joined_at: 1_714_972_800,
        },
    )
    .unwrap();
    household_rs::machine_cert::save_self_cert(td.path(), &m1_cert).unwrap();
    fs::write(
        household_dir(td.path()).join("self_m_id"),
        format!("{m1_id_typed}\n"),
    )
    .unwrap();

    let m1_account = household_rs::keystore::m_priv_account(&m1_id_typed);
    household_rs::keystore::software_fallback::write_secret_scalar(
        td.path(),
        &m1_account,
        &m1_priv,
    )
    .unwrap();
    let hh_account = household_rs::keystore::hh_priv_account(&hh_id);
    household_rs::keystore::software_fallback::write_secret_scalar(
        td.path(),
        &hh_account,
        &hh_priv,
    )
    .unwrap();

    // Drive a real ceremony to commit so the on-disk record is
    // shamir_n=2 with all chain artifacts in place.
    let txn = CeremonyTxn::prepare(CeremonyInputs {
        hh_priv,
        hh_id: hh_id.clone(),
        hh_pub_sec1: hh_pub,
        m1_priv_scalar: m1_priv.clone(),
        m1_pub_sec1: m1_pub,
        m1_id,
        candidate_m_pub_sec1: m2_pub,
        candidate_hostname: "studio-linux".into(),
        candidate_platform: Platform::LinuxNix,
        joined_at: 1_714_972_900,
        state_dir: td.path().to_path_buf(),
        existing_record,
        policy: household_rs::KeyBackingPolicy::ForceSoftware,
    })
    .unwrap();
    txn.commit().unwrap();

    // Simulate the residual-cleanup scenario: commit destroyed the
    // entry, but a transient keystore failure under real conditions
    // could have left it. Re-write the entry to model the residue.
    let residue: [u8; 32] = [0xAB; 32];
    household_rs::keystore::software_fallback::write_secret_scalar(
        td.path(),
        &hh_account,
        &residue,
    )
    .unwrap();
    let pre = household_rs::keystore::software_fallback::read_secret_scalar(td.path(), &hh_account)
        .unwrap();
    assert_eq!(pre, residue, "precondition: residue is on disk");

    // Boot the daemon (load_existing path).
    let reloaded =
        household_rs::try_load_existing(td.path(), household_rs::KeyBackingPolicy::ForceSoftware)
            .unwrap()
            .expect("post-commit identity");
    assert_eq!(reloaded.record.shamir_n, 2);
    assert!(reloaded.hh_priv.is_none());

    // The boot-time retry MUST have re-destroyed the residue.
    let post =
        household_rs::keystore::software_fallback::read_secret_scalar(td.path(), &hh_account);
    match post {
        Err(household_rs::error::KeystoreError::NotFound { .. }) => {}
        other => panic!(
            "expected NotFound after boot-time retry, got {:?}",
            other.as_ref().map(|_| "Ok(_)")
        ),
    }
}

/// R6.4 regression — `recover_partial_phase3_commit` MUST run on the
/// server boot path (`try_load_existing`), not just the fresh-install
/// path (`bootstrap_or_load`). The R5.7 split-brain fix is dead code
/// at runtime if this wiring regresses, since `load_state_dir` is only
/// called from `bootstrap_or_load`.
///
/// Constructs a post-Shamir on-disk record + `.staged` orphans, calls
/// `try_load_existing`, and asserts the orphans were rolled forward.
/// CRITICAL: this test MUST NOT call `load_state_dir` directly — that
/// would mask the wiring gap. The wiring lives only in
/// `try_load_existing` (and `bootstrap_or_load`); regressing it would
/// hide R5.7 / R6.x recovery logic at every server reboot.
#[test]
fn try_load_existing_runs_partial_phase3_commit_recovery() {
    use household_rs::cbor;
    use household_rs::keys::P256Keypair;
    use household_rs::machine_cert::SignOptions;
    use household_rs::storage::{
        household_record_path, machine_cert_for, machine_certs_dir, staged_path_for,
    };

    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    fs::create_dir_all(household_dir(td.path()).join("shamir")).unwrap();
    fs::create_dir_all(machine_certs_dir(td.path())).unwrap();

    let hh_kp = P256Keypair::generate();
    let m1_kp = P256Keypair::generate();
    let candidate_kp = P256Keypair::generate();
    let hh_id = household_rs::derive_household_id(&hh_kp.public());
    let m1_id = household_rs::derive_machine_id(&m1_kp.public());
    let candidate_id = household_rs::derive_machine_id(&candidate_kp.public());

    // Real M1 self-cert + self_m_id so try_load_existing chain
    // verification proceeds past the cert-load step.
    let m1_cert = household_rs::machine_cert::MachineCert::sign(
        &hh_kp,
        &m1_kp.public(),
        &SignOptions {
            hh_id: hh_id.clone(),
            hostname: "studio-mac".into(),
            platform: Platform::Macos,
            joined_at: 1_714_972_800,
        },
    )
    .unwrap();
    household_rs::machine_cert::save_self_cert(td.path(), &m1_cert).unwrap();
    fs::write(
        household_dir(td.path()).join("self_m_id"),
        format!("{m1_id}\n"),
    )
    .unwrap();
    // Plant M1's keystore entry so the M_priv read in
    // try_load_existing succeeds. HH_priv is intentionally absent —
    // shamir_n=2 takes the post-Shamir branch that doesn't read it.
    let m1_priv = Zeroizing::new(*m1_kp.as_software_secret().unwrap());
    let m1_account = household_rs::keystore::m_priv_account(&m1_id);
    household_rs::keystore::software_fallback::write_secret_scalar(
        td.path(),
        &m1_account,
        &m1_priv,
    )
    .unwrap();

    // Post-Shamir record on disk — `recover_partial_phase3_commit`
    // takes the roll-forward branch.
    let mut members = vec![candidate_id.clone(), m1_id.clone()];
    members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let record = HouseholdRecord {
        version: 1,
        hh_id: hh_id.clone(),
        hh_pub: hh_kp.public(),
        name: "Sample Home".into(),
        created_at: 1_714_972_800,
        shamir_k: 2,
        shamir_n: 2,
        members,
    };
    fs::write(
        household_record_path(td.path()),
        cbor::to_canonical_vec(&record).unwrap(),
    )
    .unwrap();

    // Orphan `.staged` siblings — the candidate cert + self_shard
    // never finished promotion before the crash.
    let candidate_cert_path = machine_cert_for(td.path(), candidate_id.as_str());
    let cert_staged = staged_path_for(&candidate_cert_path);
    fs::write(&cert_staged, b"cert-bytes").unwrap();
    let shard_path = household_dir(td.path()).join("shamir/self_shard.cbor");
    let shard_staged = staged_path_for(&shard_path);
    fs::write(&shard_staged, b"shard-bytes").unwrap();
    assert!(cert_staged.exists());
    assert!(shard_staged.exists());

    // The wiring under test — try_load_existing runs the recovery
    // probes idempotently, including recover_partial_phase3_commit.
    let _ =
        household_rs::try_load_existing(td.path(), household_rs::KeyBackingPolicy::ForceSoftware)
            .unwrap()
            .expect("post-Shamir identity present");

    // Roll-forward landed: finals exist, .staged is gone.
    assert!(
        candidate_cert_path.exists(),
        "candidate cert MUST be promoted by try_load_existing's recovery"
    );
    assert!(
        shard_path.exists(),
        "self_shard.cbor MUST be promoted by try_load_existing's recovery"
    );
    assert!(!cert_staged.exists());
    assert!(!shard_staged.exists());
}
