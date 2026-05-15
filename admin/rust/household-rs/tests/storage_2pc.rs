//! T031 coverage for `storage::stage_commit_files`/`StagedCommit`/
//! `detect_orphan_staged_files`.

use std::fs;
use std::path::PathBuf;

use household_rs::HouseholdRecord;
use household_rs::IdentityKey as _;
use household_rs::keys::P256Keypair;
use household_rs::storage::{
    STAGED_SUFFIX, clear_phase3_finalize_ack_marker, detect_orphan_staged_files, household_dir,
    household_record_path, load_state_dir, machine_cert_for, machine_certs_dir,
    phase3_finalize_ack_marker_exists, phase3_finalize_ack_marker_path, stage_commit_files,
    staged_path_for, write_phase3_finalize_ack_marker,
};
use tempfile::tempdir;

fn payload(b: u8) -> Vec<u8> {
    vec![b; 16]
}

#[test]
fn stage_then_commit_promotes_all_files() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let a = household_dir(td.path()).join("a.cbor");
    let b = household_dir(td.path()).join("b.cbor");
    let staged = stage_commit_files(&[(a.clone(), payload(0xA1)), (b.clone(), payload(0xB2))])
        .expect("stage");
    assert!(staged_path_for(&a).exists());
    assert!(staged_path_for(&b).exists());
    staged.commit().expect("commit");
    assert!(a.exists());
    assert!(b.exists());
    assert!(!staged_path_for(&a).exists());
    assert!(!staged_path_for(&b).exists());
    assert_eq!(fs::read(&a).unwrap(), payload(0xA1));
    assert_eq!(fs::read(&b).unwrap(), payload(0xB2));
}

#[test]
fn stage_then_rollback_removes_staged_files() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let a = household_dir(td.path()).join("a.cbor");
    let staged = stage_commit_files(&[(a.clone(), payload(0xC3))]).expect("stage");
    assert!(staged_path_for(&a).exists());
    staged.rollback();
    assert!(!staged_path_for(&a).exists());
    assert!(!a.exists());
}

#[test]
fn dropping_uncommitted_staged_commit_cleans_up() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let a = household_dir(td.path()).join("a.cbor");
    {
        let _staged = stage_commit_files(&[(a.clone(), payload(0xD4))]).expect("stage");
        assert!(staged_path_for(&a).exists());
        // Drop without commit — best-effort cleanup runs.
    }
    assert!(!staged_path_for(&a).exists());
}

/// R5.7 regression — `recover_partial_phase3_commit` MUST roll
/// FORWARD when the household record has already been promoted to
/// `shamir_n=2` (the canonical commit marker) and `.staged` siblings
/// of the cert / shard linger from a crash mid-`StagedCommit::commit`.
#[test]
fn recover_partial_phase3_commit_rolls_forward_when_record_post_shamir() {
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

    // On-disk record: post-Shamir.
    let mut members = vec![candidate_id.clone(), m1_id.clone()];
    members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let record = HouseholdRecord {
        version: 1,
        hh_id: hh_id.clone(),
        hh_pub: hh_kp.public(),
        name: "Sample Home".into(),
        created_at: 1_700_000_000,
        shamir_k: 2,
        shamir_n: 2,
        members,
    };
    fs::write(
        household_record_path(td.path()),
        household_rs::cbor::to_canonical_vec(&record).unwrap(),
    )
    .unwrap();

    // The candidate cert and the self_shard are still .staged
    // (mid-commit crash before their renames landed).
    let candidate_cert_path = machine_cert_for(td.path(), candidate_id.as_str());
    let cert_staged = staged_path_for(&candidate_cert_path);
    fs::write(&cert_staged, b"cert-bytes").unwrap();
    let shard_path = household_dir(td.path()).join("shamir/self_shard.cbor");
    let shard_staged = staged_path_for(&shard_path);
    fs::write(&shard_staged, b"shard-bytes").unwrap();

    let outcome = load_state_dir(td.path()).unwrap();
    assert_eq!(outcome.partial_phase3_commit_rolled_forward, 2);
    assert_eq!(outcome.partial_phase3_commit_rolled_back, 0);

    // Roll-forward succeeded: finals exist, .staged are gone.
    assert!(candidate_cert_path.exists());
    assert!(shard_path.exists());
    assert!(!cert_staged.exists());
    assert!(!shard_staged.exists());
}

/// R5.7 regression — `recover_partial_phase3_commit` MUST roll BACK
/// when the household record on disk is still `shamir_n=1` (the
/// commit marker did not flip), unlinking both the `.staged` files
/// and any partially-promoted final-path siblings (the candidate
/// cert in particular). The `.staged` for `household_record.cbor`
/// is read to identify the candidate's `m_id`.
#[test]
fn recover_partial_phase3_commit_rolls_back_when_record_pre_shamir() {
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

    // On-disk record: pre-Shamir (single machine).
    let pre_record = HouseholdRecord {
        version: 1,
        hh_id: hh_id.clone(),
        hh_pub: hh_kp.public(),
        name: "Sample Home".into(),
        created_at: 1_700_000_000,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![m1_id.clone()],
    };
    fs::write(
        household_record_path(td.path()),
        household_rs::cbor::to_canonical_vec(&pre_record).unwrap(),
    )
    .unwrap();

    // Staged record (would-have-been post-Shamir) — used by recovery
    // to identify the candidate.
    let mut staged_members = vec![candidate_id.clone(), m1_id.clone()];
    staged_members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let post_record = HouseholdRecord {
        shamir_k: 2,
        shamir_n: 2,
        members: staged_members,
        ..pre_record.clone()
    };
    fs::write(
        staged_path_for(&household_record_path(td.path())),
        household_rs::cbor::to_canonical_vec(&post_record).unwrap(),
    )
    .unwrap();

    // Candidate cert was already promoted in the partial commit.
    let candidate_cert_path = machine_cert_for(td.path(), candidate_id.as_str());
    fs::write(&candidate_cert_path, b"partial-cert-bytes").unwrap();
    // Its .staged sibling also exists.
    let cert_staged = staged_path_for(&candidate_cert_path);
    fs::write(&cert_staged, b"partial-cert-bytes").unwrap();
    // Self-shard is still .staged only.
    let shard_path = household_dir(td.path()).join("shamir/self_shard.cbor");
    let shard_staged = staged_path_for(&shard_path);
    fs::write(&shard_staged, b"shard-bytes").unwrap();

    let outcome = load_state_dir(td.path()).unwrap();
    assert_eq!(outcome.partial_phase3_commit_rolled_forward, 0);
    // 3 .staged files unlinked: cert, record, shard.
    assert_eq!(outcome.partial_phase3_commit_rolled_back, 3);

    // Partial cert promotion was undone.
    assert!(
        !candidate_cert_path.exists(),
        "partial candidate cert must be unlinked on rollback"
    );
    // Self-shard final stays absent (was never promoted).
    assert!(!shard_path.exists());
    // .staged siblings are gone.
    assert!(!cert_staged.exists());
    assert!(!shard_staged.exists());
    // On-disk record stays pre-Shamir.
    let on_disk: HouseholdRecord = household_rs::cbor::from_canonical_slice(
        &fs::read(household_record_path(td.path())).unwrap(),
    )
    .unwrap();
    assert_eq!(on_disk.shamir_n, 1);
}

/// R6.5 regression — `recover_post_join_sole_shard` MUST NOT delete
/// `household_root_sole.cbor` when both `sole` and `shamir/self_shard.cbor`
/// exist BUT the on-disk record is still pre-Shamir. R5.7's reordered
/// `staged_files` (`[cert, self_shard, record]`) makes that crash state
/// reachable: the previous probe assumed the OLD ordering (record before
/// `self_shard`) and would mis-classify the post-`self_shard`, pre-record
/// crash as committed, irreversibly losing the pre-Shamir root.
///
/// Expected outcome under the fix: the orphan `self_shard.cbor` is
/// unlinked by `recover_partial_phase3_commit`'s roll-back branch (which
/// runs first); `sole` survives.
#[test]
fn recover_post_join_sole_shard_preserves_sole_when_record_pre_shamir() {
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

    // On-disk record: pre-Shamir.
    let pre_record = HouseholdRecord {
        version: 1,
        hh_id: hh_id.clone(),
        hh_pub: hh_kp.public(),
        name: "Sample Home".into(),
        created_at: 1_700_000_000,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![m1_id.clone()],
    };
    fs::write(
        household_record_path(td.path()),
        household_rs::cbor::to_canonical_vec(&pre_record).unwrap(),
    )
    .unwrap();

    // Staged record (post-Shamir would-have-been) so partial-commit
    // recovery can identify the candidate.
    let mut staged_members = vec![candidate_id.clone(), m1_id.clone()];
    staged_members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let post_record = HouseholdRecord {
        shamir_k: 2,
        shamir_n: 2,
        members: staged_members,
        ..pre_record.clone()
    };
    fs::write(
        staged_path_for(&household_record_path(td.path())),
        household_rs::cbor::to_canonical_vec(&post_record).unwrap(),
    )
    .unwrap();

    // Crash state: self_shard already at FINAL path (R5.7 reorder
    // promoted it before record), sole still present (only unlinked
    // after staged.commit() returns Ok).
    let shard_path = household_dir(td.path()).join("shamir/self_shard.cbor");
    fs::write(&shard_path, b"shard-bytes").unwrap();
    let sole_path = household_dir(td.path()).join("household_root_sole.cbor");
    fs::write(&sole_path, b"sole-bytes").unwrap();

    let outcome = load_state_dir(td.path()).unwrap();

    // Roll-back branch unlinked the orphan self_shard (1 file: shard).
    // Note: the record + cert .staged siblings may also be present;
    // count is rolled-back-files, not "shard only". The key
    // invariants are below.
    assert!(outcome.partial_phase3_commit_rolled_back >= 1);
    assert!(
        sole_path.exists(),
        "household_root_sole.cbor MUST survive when record is pre-Shamir; \
         lost the pre-Shamir root would be unrecoverable",
    );
    assert!(
        !shard_path.exists(),
        "orphan self_shard.cbor MUST be unlinked on roll-back",
    );
    // R6.5 explicit: the sole-shard probe MUST NOT have run.
    assert!(!outcome.recovered_post_join_sole_shard_deleted);
}

/// R6.1 regression — `recover_partial_phase3_commit` MUST preserve
/// `.staged` files when the on-disk record is pre-Shamir BUT the
/// `phase3_finalize_ack.marker` exists. The future T073/T074 boot
/// driver needs the `.staged` set + marker to probe M2 and complete or
/// rescind the in-flight or ambiguous ceremony.
#[test]
fn recover_partial_phase3_commit_preserves_staged_when_finalize_ack_marker_present() {
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

    let pre_record = HouseholdRecord {
        version: 1,
        hh_id: hh_id.clone(),
        hh_pub: hh_kp.public(),
        name: "Sample Home".into(),
        created_at: 1_700_000_000,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![m1_id.clone()],
    };
    fs::write(
        household_record_path(td.path()),
        household_rs::cbor::to_canonical_vec(&pre_record).unwrap(),
    )
    .unwrap();

    // .staged set from a CeremonyTxn::prepare that crashed in commit.
    let candidate_cert_path = machine_cert_for(td.path(), candidate_id.as_str());
    let cert_staged = staged_path_for(&candidate_cert_path);
    fs::write(&cert_staged, b"cert-bytes").unwrap();
    let shard_path = household_dir(td.path()).join("shamir/self_shard.cbor");
    let shard_staged = staged_path_for(&shard_path);
    fs::write(&shard_staged, b"shard-bytes").unwrap();
    let mut staged_members = vec![candidate_id.clone(), m1_id.clone()];
    staged_members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let post_record = HouseholdRecord {
        shamir_k: 2,
        shamir_n: 2,
        members: staged_members,
        ..pre_record
    };
    fs::write(
        staged_path_for(&household_record_path(td.path())),
        household_rs::cbor::to_canonical_vec(&post_record).unwrap(),
    )
    .unwrap();

    // Pin post-FinalizeAck state.
    write_phase3_finalize_ack_marker(td.path(), candidate_id.as_str()).unwrap();
    assert!(phase3_finalize_ack_marker_exists(td.path()));

    let outcome = load_state_dir(td.path()).unwrap();
    assert_eq!(outcome.partial_phase3_commit_rolled_forward, 0);
    assert_eq!(
        outcome.partial_phase3_commit_rolled_back, 0,
        "marker MUST gate roll-back; T073/T074 needs the staged evidence",
    );
    // .staged siblings survive.
    assert!(cert_staged.exists());
    assert!(shard_staged.exists());
    assert!(staged_path_for(&household_record_path(td.path())).exists());
    // Marker survives.
    assert!(phase3_finalize_ack_marker_exists(td.path()));
}

/// R6.NB2 regression — corrupt `household_record.cbor` (cannot decode)
/// MUST surface as a tracing crisis and skip recovery; never silently
/// classify as pre-Shamir → roll-back.
#[test]
fn recover_partial_phase3_commit_skips_when_record_undecodable() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    fs::create_dir_all(household_dir(td.path()).join("shamir")).unwrap();
    fs::create_dir_all(machine_certs_dir(td.path())).unwrap();

    // Garbage bytes — not a valid CBOR HouseholdRecord.
    fs::write(household_record_path(td.path()), b"\xff\xff\xff\xffJUNK").unwrap();

    // Plant a `.staged` so collect_phase3_staged returns non-empty;
    // recovery code path is taken.
    let shard_path = household_dir(td.path()).join("shamir/self_shard.cbor");
    let shard_staged = staged_path_for(&shard_path);
    fs::write(&shard_staged, b"shard-bytes").unwrap();

    let outcome = load_state_dir(td.path()).unwrap();
    // Skip both branches.
    assert_eq!(outcome.partial_phase3_commit_rolled_forward, 0);
    assert_eq!(outcome.partial_phase3_commit_rolled_back, 0);
    // .staged survived (no destructive default).
    assert!(shard_staged.exists());
}

/// R6.1 + R6.4 housekeeping — `clear_phase3_finalize_ack_marker` is
/// idempotent on missing-file (best-effort), and round-trips with
/// `write_phase3_finalize_ack_marker`.
#[test]
fn finalize_ack_marker_lifecycle_is_idempotent() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    // Missing -> false.
    assert!(!phase3_finalize_ack_marker_exists(td.path()));
    // Clear on missing is Ok.
    clear_phase3_finalize_ack_marker(td.path()).unwrap();
    // Write -> exists, payload is the candidate m_id.
    write_phase3_finalize_ack_marker(td.path(), "m_test_candidate").unwrap();
    assert!(phase3_finalize_ack_marker_exists(td.path()));
    let payload = fs::read(phase3_finalize_ack_marker_path(td.path())).unwrap();
    assert_eq!(payload, b"m_test_candidate");
    // Clear -> gone.
    clear_phase3_finalize_ack_marker(td.path()).unwrap();
    assert!(!phase3_finalize_ack_marker_exists(td.path()));
}

/// R7.1 regression — `StagedCommit::commit_preserve_on_error` MUST
/// leave `.staged` siblings on disk when partial promotion fails.
/// Plain `commit()` (and the destructor that runs on commit-error)
/// would unlink the surviving `.staged`, destroying the recovery
/// evidence the finalize-intent marker is supposed to protect.
#[test]
fn staged_commit_preserve_on_error_keeps_remaining_staged_on_failure() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let a = household_dir(td.path()).join("a.cbor");
    let b = household_dir(td.path()).join("b.cbor");
    // Block `b`'s rename target by pre-creating a directory at the
    // final path. fs::rename(file → dir) fails with "Is a directory"
    // (or similar) on POSIX, simulating any mid-loop rename failure.
    fs::create_dir(&b).unwrap();

    let staged = stage_commit_files(&[(a.clone(), payload(0xA1)), (b.clone(), payload(0xB2))])
        .expect("stage");
    let staged_a = staged_path_for(&a);
    let staged_b = staged_path_for(&b);
    assert!(staged_a.exists());
    assert!(staged_b.exists());

    // Partial failure: a was promoted (rename consumed `staged_a`),
    // b's rename failed.
    let result = staged.commit_preserve_on_error();
    assert!(result.is_err());

    // `a` ended up at its final path (rename succeeded for the first
    // item) — its `.staged` is gone because `fs::rename` consumes it.
    assert!(a.is_file());
    assert!(!staged_a.exists());
    // `b`'s `.staged` MUST survive — preserve_on_error disarmed
    // both the explicit rollback AND the Drop cleanup.
    assert!(
        staged_b.exists(),
        "preserve_on_error MUST leave `.staged` on disk so boot-time \
         recovery can find it via the phase3_finalize_ack.marker",
    );
}

/// R7.NB2 regression — the stale-marker sweep in `load_state_dir`
/// MUST clear `phase3_finalize_ack.marker` whenever the on-disk
/// record is post-Shamir, including the common steady-state case
/// where there are NO `.staged` siblings.
#[test]
fn stale_phase3_marker_cleared_when_record_post_shamir_and_no_staged() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    fs::create_dir_all(household_dir(td.path()).join("shamir")).unwrap();
    fs::create_dir_all(machine_certs_dir(td.path())).unwrap();

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
    };
    fs::write(
        household_record_path(td.path()),
        household_rs::cbor::to_canonical_vec(&post_record).unwrap(),
    )
    .unwrap();

    // Plant a stale marker — what would be left if the handler's
    // post-`commit_preserve_on_error` clear hit a transient FS error.
    write_phase3_finalize_ack_marker(td.path(), m2_id.as_str()).unwrap();
    assert!(phase3_finalize_ack_marker_exists(td.path()));

    let _ = load_state_dir(td.path()).unwrap();

    assert!(
        !phase3_finalize_ack_marker_exists(td.path()),
        "post-Shamir record MUST trigger stale-marker clear regardless \
         of `.staged` presence",
    );
}

/// R7.NB2 negative — pre-Shamir record MUST keep the marker (it's
/// the in-flight ceremony pin protected by R6.1).
#[test]
fn stale_phase3_marker_sweep_skips_pre_shamir_record() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();

    let hh_kp = P256Keypair::generate();
    let m1_kp = P256Keypair::generate();
    let hh_id = household_rs::derive_household_id(&hh_kp.public());
    let m1_id = household_rs::derive_machine_id(&m1_kp.public());

    let pre_record = HouseholdRecord {
        version: 1,
        hh_id,
        hh_pub: hh_kp.public(),
        name: "Sample Home".into(),
        created_at: 1_700_000_000,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![m1_id],
    };
    fs::write(
        household_record_path(td.path()),
        household_rs::cbor::to_canonical_vec(&pre_record).unwrap(),
    )
    .unwrap();

    write_phase3_finalize_ack_marker(td.path(), "m_in_flight").unwrap();
    let _ = load_state_dir(td.path()).unwrap();
    assert!(
        phase3_finalize_ack_marker_exists(td.path()),
        "pre-Shamir record + marker is the protected in-flight state",
    );
}

/// R7.4 regression — M2-side rollback MUST clean up the wider M2
/// staged set: founder cert, candidate cert, `self_m_id`,
/// `self_shard.cbor`, `pair_machine_window.cbor`,
/// `owner_push_token.cbor`. Recovery distinguishes M2 from M1 by the
/// absence of an on-disk `household_record.cbor`.
#[test]
fn recover_partial_phase3_commit_rolls_back_m2_side_full_staged_set() {
    use household_rs::storage::self_m_id_marker_path;

    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    fs::create_dir_all(household_dir(td.path()).join("shamir")).unwrap();
    fs::create_dir_all(machine_certs_dir(td.path())).unwrap();

    let hh_kp = P256Keypair::generate();
    let m1_kp = P256Keypair::generate();
    let m2_kp = P256Keypair::generate();
    let hh_id = household_rs::derive_household_id(&hh_kp.public());
    let m1_id = household_rs::derive_machine_id(&m1_kp.public());
    let m2_id = household_rs::derive_machine_id(&m2_kp.public());

    // M2 side — NO on-disk record before ceremony.
    assert!(!household_record_path(td.path()).exists());

    // Staged record (would-have-been post-Shamir) so recovery can
    // identify both members.
    let mut staged_members = vec![m1_id.clone(), m2_id.clone()];
    staged_members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let post_record = HouseholdRecord {
        version: 1,
        hh_id: hh_id.clone(),
        hh_pub: hh_kp.public(),
        name: "Sample Home".into(),
        created_at: 1_700_000_000,
        shamir_k: 2,
        shamir_n: 2,
        members: staged_members,
    };
    fs::write(
        staged_path_for(&household_record_path(td.path())),
        household_rs::cbor::to_canonical_vec(&post_record).unwrap(),
    )
    .unwrap();

    // Partially-promoted M2 staged set (R6.2 reorder, record LAST):
    let founder_cert = machine_cert_for(td.path(), m1_id.as_str());
    let candidate_cert = machine_cert_for(td.path(), m2_id.as_str());
    fs::write(&founder_cert, b"founder-cert-bytes").unwrap();
    fs::write(&candidate_cert, b"candidate-cert-bytes").unwrap();
    fs::write(self_m_id_marker_path(td.path()), format!("{m2_id}\n")).unwrap();
    let shard_path = household_dir(td.path()).join("shamir/self_shard.cbor");
    fs::write(&shard_path, b"shard-bytes").unwrap();
    let window_path = household_rs::pair_machine::pair_machine_window_path(td.path());
    fs::write(&window_path, b"window-bytes").unwrap();
    let push_token_path = household_rs::owner_events::owner_push_token_path(td.path());
    fs::write(&push_token_path, b"push-token-bytes").unwrap();
    // .staged for the last item not yet promoted (record).
    let record_staged = staged_path_for(&household_record_path(td.path()));
    assert!(record_staged.exists());

    let outcome = load_state_dir(td.path()).unwrap();
    // 1 .staged (the record) was unlinked.
    assert_eq!(outcome.partial_phase3_commit_rolled_back, 1);

    // All M2-side final-path artifacts are gone.
    assert!(
        !founder_cert.exists(),
        "founder cert must be unlinked on M2 rollback"
    );
    assert!(
        !candidate_cert.exists(),
        "candidate cert must be unlinked on M2 rollback"
    );
    assert!(
        !self_m_id_marker_path(td.path()).exists(),
        "self_m_id must be unlinked on M2 rollback"
    );
    assert!(
        !shard_path.exists(),
        "self_shard must be unlinked on M2 rollback (no `sole` to gate on)"
    );
    assert!(
        !window_path.exists(),
        "pair_machine_window must be unlinked on M2 rollback"
    );
    assert!(
        !push_token_path.exists(),
        "owner_push_token must be unlinked on M2 rollback"
    );
    assert!(!record_staged.exists());
    // On-disk record stays absent (M2 was never committed).
    assert!(!household_record_path(td.path()).exists());
}

#[test]
fn detect_orphans_returns_dropped_staged_files() {
    let td = tempdir().unwrap();
    fs::create_dir_all(household_dir(td.path())).unwrap();
    let shamir = household_dir(td.path()).join("shamir");
    fs::create_dir_all(&shamir).unwrap();
    let orphan_root = household_dir(td.path()).join("hh.cbor.staged");
    let orphan_shamir = shamir.join("self_shard.cbor.staged");
    fs::write(&orphan_root, b"junk").unwrap();
    fs::write(&orphan_shamir, b"junk").unwrap();
    let found: Vec<PathBuf> = detect_orphan_staged_files(td.path())
        .into_iter()
        .filter(|p| p.to_string_lossy().ends_with(STAGED_SUFFIX))
        .collect();
    assert!(found.iter().any(|p| p == &orphan_root));
    assert!(found.iter().any(|p| p == &orphan_shamir));
}
