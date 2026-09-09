#![cfg(test)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::*;
use crate::household_lifecycle::HouseholdLifecycleLock;
use crate::ids::{derive_household_id, derive_machine_id};
use crate::keys::{IdentityKey, P256Keypair};

fn record() -> (HouseholdRecord, MachineId, P256Keypair) {
    let household = P256Keypair::generate();
    let machine = P256Keypair::generate();
    let hh_pub = household.public();
    let m_id = derive_machine_id(&machine.public());
    (
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&hh_pub),
            hh_pub,
            name: "Install transaction test".into(),
            created_at: 1_714_972_800,
            shamir_k: 0,
            shamir_n: 0,
            members: vec![m_id.clone()],
            is_follower: true,
        },
        m_id,
        machine,
    )
}

fn install_exact_marker(state: &TempDir, expectation: &HouseholdInstallExpectation) {
    let household = state.path().join(crate::storage::HOUSEHOLD_SUBDIR);
    fs::create_dir(&household).unwrap();
    fs::set_permissions(&household, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = household.join("household_record.cbor");
    fs::write(&marker, expectation.commit_marker_bytes()).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    File::open(&marker).unwrap().sync_all().unwrap();
    File::open(&household).unwrap().sync_all().unwrap();
    File::open(state.path()).unwrap().sync_all().unwrap();
}

fn terminal_intent(machine: &P256Keypair, request: &[u8]) -> FinalizeTerminalIntent {
    let m_pub = machine.public();
    let m_id = derive_machine_id(&m_pub);
    let nonce = [0x3a; 32];
    let challenge = crate::pair_machine::JoinChallenge::build(
        m_pub.as_bytes(),
        &nonce,
        "install-transaction-test",
        crate::machine_cert::Platform::LinuxNix,
    );
    let challenge_bytes = challenge.to_canonical_bytes().unwrap();
    let challenge_sig = machine.sign(&challenge_bytes).unwrap();
    let join_request = crate::pair_machine::JoinRequest {
        version: crate::pair_machine::PAIR_MACHINE_VERSION,
        m_pub: ByteBuf::from(m_pub.as_bytes().to_vec()),
        hostname: "install-transaction-test".into(),
        platform: crate::machine_cert::Platform::LinuxNix,
        nonce: ByteBuf::from(nonce.to_vec()),
        addr: "192.0.2.44:18091".into(),
        transport: crate::pair_machine::JoinTransport::Lan,
        challenge_sig: ByteBuf::from(challenge_sig.0.to_vec()),
    };
    let join_request_bytes = join_request.to_canonical_bytes().unwrap();
    let ack = crate::pair_machine::FinalizeAck {
        version: crate::pair_machine::PAIR_MACHINE_VERSION,
        m_id: m_id.to_string(),
        machine_cert_hash: ByteBuf::from(vec![0x5a; 32]),
    };
    let ack_bytes = ack.to_canonical_bytes().unwrap();
    FinalizeTerminalIntent::from_exact_ack_bytes(
        FinalizeRequestFingerprintV1::for_canonical_request_bytes(request),
        &m_id,
        &join_request_bytes,
        &ack_bytes,
    )
    .unwrap()
}

fn begin(
    state: &TempDir,
    lifecycle: &HouseholdLifecycleLock,
) -> (
    crate::household_lifecycle::LifecycleWriteGuard,
    HouseholdInstallExpectation,
) {
    let guard = lifecycle.lock_exclusive().unwrap();
    let generation = guard.ensure_lifecycle_generation().unwrap();
    let (record, m_id, machine) = record();
    let terminal_intent = terminal_intent(&machine, b"canonical request");
    let expectation = begin_household_install_under_lifecycle(
        &guard,
        generation,
        &record,
        &m_id,
        &terminal_intent,
    )
    .unwrap();
    assert!(
        state
            .path()
            .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
            .exists()
    );
    (guard, expectation)
}

#[test]
fn breadcrumb_lost_parent_ack_is_recovered_after_restart_without_reinstall() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let generation = guard.ensure_lifecycle_generation().unwrap();
    let (record, m_id, machine) = record();
    let terminal_intent = terminal_intent(&machine, b"lost breadcrumb ack");
    install_fail_injection::arm_after_breadcrumb_rename();
    assert_eq!(
        begin_household_install_under_lifecycle(
            &guard,
            generation,
            &record,
            &m_id,
            &terminal_intent,
        )
        .unwrap_err(),
        HouseholdInstallTransactionError::BreadcrumbPublicationNeedsRecovery
    );
    drop(guard);
    drop(lifecycle);
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    assert!(matches!(
        recover_household_install_under_lifecycle(&guard, |_| {
            panic!("partial recovery must not validate committed artifacts")
        })
        .unwrap(),
        HouseholdInstallRecoveryOutcome::PartialNeedsRollback(_)
    ));
}

#[test]
fn partial_install_never_rotates_and_clears_only_after_rollback_proof() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let before = guard.lifecycle_generation().unwrap().unwrap();
    let residual = state.path().join(crate::storage::HOUSEHOLD_SUBDIR);
    fs::create_dir(&residual).unwrap();
    fs::set_permissions(&residual, fs::Permissions::from_mode(0o700)).unwrap();
    File::open(state.path()).unwrap().sync_all().unwrap();
    drop(guard);
    drop(lifecycle);
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let outcome = recover_household_install_under_lifecycle(&guard, |_| {
        panic!("partial recovery must not validate committed artifacts")
    })
    .unwrap();
    let HouseholdInstallRecoveryOutcome::PartialNeedsRollback(ticket) = outcome else {
        panic!("expected partial rollback")
    };
    assert_eq!(ticket.expectation(), &expectation);
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(before));
    complete_partial_install_rollback_under_lifecycle(&guard, ticket, |_| Ok(())).unwrap();
    assert!(
        !state
            .path()
            .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
            .exists()
    );
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(before));
}

#[test]
fn partial_breadcrumb_from_an_old_generation_is_quarantined_not_rolled_back() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let g0 = expectation.candidate_generation();
    let other = guard.rotate_lifecycle_generation().unwrap();
    assert_ne!(other, g0);
    assert_eq!(
        recover_household_install_under_lifecycle(&guard, |_| {
            panic!("an absent marker from a foreign generation is never committed")
        })
        .unwrap_err(),
        HouseholdInstallTransactionError::Quarantined
    );
    assert!(
        state
            .path()
            .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
            .exists(),
        "quarantine preserves evidence and never authorizes cleanup"
    );
}

#[test]
fn committed_pre_rotate_failure_is_typed_and_retry_rotates_never_rolls_back() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let g0 = expectation.candidate_generation();
    install_exact_marker(&state, &expectation);
    install_fail_injection::arm_before_rotation();
    assert_eq!(
        finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
        HouseholdInstallTransactionError::TerminalRotationNeedsRecovery
    );
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(g0));
    let state_dir = guard.clone_state_dir().unwrap();
    let prepared = read_terminal_record(&state_dir).unwrap().unwrap();
    assert_eq!(prepared.phase, FinalizeTerminalPhaseV1::Prepared);
    assert_eq!(
        prepared.join_request_bytes.as_ref(),
        expectation.terminal_intent().join_request_bytes()
    );
    assert!(
        state
            .path()
            .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
            .exists(),
        "post-commit failure must preserve recovery evidence"
    );
    drop(guard);
    drop(lifecycle);
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let outcome = recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap();
    let HouseholdInstallRecoveryOutcome::RotatedAndCleared { generation, .. } = outcome else {
        panic!("retry must terminally rotate")
    };
    assert_ne!(generation, g0);
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(generation));
    assert_eq!(
        load_active_finalize_terminal_result_under_lifecycle(&guard)
            .unwrap()
            .unwrap()
            .join_request_bytes(),
        expectation.terminal_intent().join_request_bytes()
    );
}

#[test]
fn crash_after_rotate_before_clear_converges_without_second_rotation() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let g0 = expectation.candidate_generation();
    install_exact_marker(&state, &expectation);
    install_fail_injection::arm_before_clear();
    assert_eq!(
        finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
        HouseholdInstallTransactionError::TerminalCleanupNeedsRecovery
    );
    let g1 = guard.lifecycle_generation().unwrap().unwrap();
    assert_ne!(g1, g0);
    assert!(
        state
            .path()
            .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
            .exists()
    );
    let state_dir = guard.clone_state_dir().unwrap();
    let retained = read_terminal_record(&state_dir).unwrap().unwrap();
    assert_eq!(retained.phase, FinalizeTerminalPhaseV1::Final);
    assert_eq!(
        retained.join_request_bytes.as_ref(),
        expectation.terminal_intent().join_request_bytes()
    );
    assert!(matches!(
        lookup_finalize_terminal_result_under_lifecycle(
            &guard,
            expectation.terminal_intent().request_fingerprint(),
            expectation.expected_hh_id(),
            expectation.expected_m_id(),
        )
        .unwrap(),
        FinalizeTerminalLookupOutcome::Exact(_)
    ));
    drop(guard);
    drop(lifecycle);
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let outcome = recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap();
    assert!(matches!(
        outcome,
        HouseholdInstallRecoveryOutcome::AlreadyRotatedAndCleared { generation, .. }
            if generation == g1
    ));
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(g1));
}

#[test]
fn canonical_marker_mismatch_quarantines_without_rotation_or_cleanup() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let g0 = expectation.candidate_generation();
    let (other, _, _) = record();
    let household = state.path().join(crate::storage::HOUSEHOLD_SUBDIR);
    fs::create_dir(&household).unwrap();
    fs::set_permissions(&household, fs::Permissions::from_mode(0o700)).unwrap();
    crate::storage::atomic_write_cbor(&crate::storage::household_record_path(state.path()), &other)
        .unwrap();
    assert_eq!(
        recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap_err(),
        HouseholdInstallTransactionError::CommitMarkerMismatch
    );
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(g0));
    assert!(
        state
            .path()
            .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
            .exists()
    );
}

#[test]
fn required_artifact_failure_never_crosses_terminal_rotation() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let g0 = expectation.candidate_generation();
    install_exact_marker(&state, &expectation);
    assert_eq!(
        recover_household_install_under_lifecycle(&guard, |_| {
            Err(RequiredInstallArtifactsError::new("candidate cert missing"))
        })
        .unwrap_err(),
        HouseholdInstallTransactionError::RequiredArtifactsInvalid("candidate cert missing".into())
    );
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(g0));
}

#[test]
fn crash_between_commit_and_terminal_result_recovers_exact_ack_before_rotation() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let g0 = expectation.candidate_generation();
    let expected_ack = expectation.terminal_intent().ack_bytes().to_vec();
    let fingerprint = expectation.terminal_intent().request_fingerprint();
    install_exact_marker(&state, &expectation);

    install_fail_injection::arm_before_terminal_result();
    assert_eq!(
        finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
        HouseholdInstallTransactionError::TerminalResultPublicationNeedsRecovery
    );
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(g0));
    assert!(
        !state
            .path()
            .join(HOUSEHOLD_INSTALL_FINALIZE_TERMINAL_FILENAME)
            .exists()
    );
    assert!(
        state
            .path()
            .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
            .exists()
    );

    drop(guard);
    drop(lifecycle);
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let HouseholdInstallRecoveryOutcome::RotatedAndCleared {
        generation,
        terminal_result,
    } = recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap()
    else {
        panic!("commit-to-result recovery must rotate exactly once")
    };
    assert_ne!(generation, g0);
    assert_eq!(*terminal_result.terminal_generation(), generation);
    assert_eq!(terminal_result.ack_bytes(), expected_ack);
    assert_eq!(terminal_result.ack_m_id(), expectation.expected_m_id());
    assert_eq!(terminal_result.ack_machine_cert_hash(), &[0x5a; 32]);
    assert!(matches!(
        lookup_finalize_terminal_result_under_lifecycle(
            &guard,
            fingerprint,
            expectation.expected_hh_id(),
            expectation.expected_m_id(),
        )
        .unwrap(),
        FinalizeTerminalLookupOutcome::Exact(ref exact)
            if exact.ack_bytes() == expected_ack
    ));
}

#[test]
fn lost_terminal_result_parent_ack_is_recovered_without_reinstall() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let g0 = expectation.candidate_generation();
    install_exact_marker(&state, &expectation);

    install_fail_injection::arm_after_terminal_result_rename();
    assert_eq!(
        finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
        HouseholdInstallTransactionError::TerminalResultPublicationNeedsRecovery
    );
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(g0));
    let state_dir = guard.clone_state_dir().unwrap();
    let prepared = read_terminal_record(&state_dir).unwrap().unwrap();
    assert_eq!(prepared.phase, FinalizeTerminalPhaseV1::Prepared);
    assert_eq!(
        prepared.join_request_bytes.as_ref(),
        expectation.terminal_intent().join_request_bytes()
    );

    drop(guard);
    drop(lifecycle);
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let HouseholdInstallRecoveryOutcome::RotatedAndCleared {
        terminal_result, ..
    } = recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap()
    else {
        panic!("visible prepared result must converge")
    };
    assert_eq!(
        terminal_result.ack_bytes(),
        expectation.terminal_intent().ack_bytes()
    );
}

#[test]
fn crash_after_rotation_before_terminal_finalize_never_rotates_twice() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let g0 = expectation.candidate_generation();
    install_exact_marker(&state, &expectation);

    install_fail_injection::arm_before_terminal_finalize();
    assert_eq!(
        finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
        HouseholdInstallTransactionError::TerminalResultFinalizationNeedsRecovery
    );
    let g1 = guard.lifecycle_generation().unwrap().unwrap();
    assert_ne!(g1, g0);
    let state_dir = guard.clone_state_dir().unwrap();
    assert_eq!(
        read_terminal_record(&state_dir).unwrap().unwrap().phase,
        FinalizeTerminalPhaseV1::Prepared
    );

    drop(guard);
    drop(lifecycle);
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let HouseholdInstallRecoveryOutcome::AlreadyRotatedAndCleared {
        generation,
        terminal_result,
    } = recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap()
    else {
        panic!("post-rotation recovery must not rotate twice")
    };
    assert_eq!(generation, g1);
    assert_eq!(*terminal_result.terminal_generation(), g1);
    assert_eq!(
        terminal_result.join_request_bytes(),
        expectation.terminal_intent().join_request_bytes()
    );
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(g1));
}

#[test]
fn exact_retry_is_byte_identical_and_divergent_retry_fails_closed() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let fingerprint = expectation.terminal_intent().request_fingerprint();
    let expected_ack = expectation.terminal_intent().ack_bytes().to_vec();
    install_exact_marker(&state, &expectation);
    let finalized =
        finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap();
    let terminal_result = match finalized {
        HouseholdInstallFinalizeOutcome::RotatedAndCleared {
            terminal_result, ..
        }
        | HouseholdInstallFinalizeOutcome::AlreadyRotatedAndCleared {
            terminal_result, ..
        } => terminal_result,
    };
    assert_eq!(terminal_result.ack_bytes(), expected_ack);
    assert_eq!(
        crate::cbor::to_canonical_vec(
            &crate::cbor::from_canonical_slice_strict::<crate::pair_machine::FinalizeAck>(
                terminal_result.ack_bytes()
            )
            .unwrap()
        )
        .unwrap(),
        expected_ack
    );

    drop(guard);
    drop(lifecycle);
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    let exact = lookup_finalize_terminal_result_under_lifecycle(
        &guard,
        fingerprint,
        expectation.expected_hh_id(),
        expectation.expected_m_id(),
    )
    .unwrap();
    assert!(matches!(
        exact,
        FinalizeTerminalLookupOutcome::Exact(ref result)
            if result.ack_bytes() == expected_ack
    ));
    assert_eq!(
        lookup_finalize_terminal_result_under_lifecycle(
            &guard,
            FinalizeRequestFingerprintV1::for_canonical_request_bytes(b"other request"),
            expectation.expected_hh_id(),
            expectation.expected_m_id(),
        )
        .unwrap(),
        FinalizeTerminalLookupOutcome::Divergent
    );
    let (_, other_m_id, _) = record();
    assert_eq!(
        lookup_finalize_terminal_result_under_lifecycle(
            &guard,
            fingerprint,
            expectation.expected_hh_id(),
            &other_m_id,
        )
        .unwrap(),
        FinalizeTerminalLookupOutcome::Divergent
    );
}

#[test]
fn old_terminal_result_is_inactive_after_lifecycle_generation_changes() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    let fingerprint = expectation.terminal_intent().request_fingerprint();
    install_exact_marker(&state, &expectation);
    finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap();
    fs::remove_dir_all(state.path().join(crate::storage::HOUSEHOLD_SUBDIR)).unwrap();
    File::open(state.path()).unwrap().sync_all().unwrap();
    let replacement_generation = guard.rotate_lifecycle_generation().unwrap();
    assert_ne!(replacement_generation, expectation.candidate_generation());
    assert_eq!(
        lookup_finalize_terminal_result_under_lifecycle(
            &guard,
            fingerprint,
            expectation.expected_hh_id(),
            expectation.expected_m_id(),
        )
        .unwrap(),
        FinalizeTerminalLookupOutcome::Absent,
        "an old Ack never survives teardown/reinstall generation change"
    );
    assert!(
        state
            .path()
            .join(HOUSEHOLD_INSTALL_FINALIZE_TERMINAL_FILENAME)
            .exists(),
        "bounded latest-only retention leaves replacement atomic, never erase-first"
    );

    let (replacement_record, replacement_m_id, replacement_machine) = record();
    let replacement_intent = terminal_intent(&replacement_machine, b"replacement request");
    let replacement = begin_household_install_under_lifecycle(
        &guard,
        replacement_generation,
        &replacement_record,
        &replacement_m_id,
        &replacement_intent,
    )
    .unwrap();
    install_exact_marker(&state, &replacement);
    let replacement_result =
        finish_household_install_under_lifecycle(&guard, &replacement, |_| Ok(())).unwrap();
    let replacement_terminal = match replacement_result {
        HouseholdInstallFinalizeOutcome::RotatedAndCleared {
            terminal_result, ..
        }
        | HouseholdInstallFinalizeOutcome::AlreadyRotatedAndCleared {
            terminal_result, ..
        } => terminal_result,
    };
    assert_eq!(
        replacement_terminal.ack_bytes(),
        replacement_intent.ack_bytes()
    );
    assert!(matches!(
        lookup_finalize_terminal_result_under_lifecycle(
            &guard,
            replacement_intent.request_fingerprint(),
            &replacement_record.hh_id,
            &replacement_m_id,
        )
        .unwrap(),
        FinalizeTerminalLookupOutcome::Exact(_)
    ));
    let terminal_entries = fs::read_dir(state.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".household-install-finalize-terminal-v1")
        })
        .count();
    assert_eq!(
        terminal_entries, 1,
        "latest-only result is physically bounded"
    );
}

#[test]
fn foreign_rotation_after_prepared_is_quarantined_not_adopted() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    install_exact_marker(&state, &expectation);

    install_fail_injection::arm_before_rotation();
    assert_eq!(
        finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap_err(),
        HouseholdInstallTransactionError::TerminalRotationNeedsRecovery
    );
    let foreign = guard.rotate_lifecycle_generation().unwrap();
    assert_ne!(foreign, expectation.candidate_generation());
    assert_ne!(foreign, expectation.terminal_generation());

    assert_eq!(
        recover_household_install_under_lifecycle(&guard, |_| Ok(())).unwrap_err(),
        HouseholdInstallTransactionError::Quarantined
    );
    assert_eq!(guard.lifecycle_generation().unwrap(), Some(foreign));
    assert!(
        state
            .path()
            .join(HOUSEHOLD_INSTALL_TRANSACTION_FILENAME)
            .exists(),
        "foreign generation preserves quarantine evidence"
    );
}

const ACK_CRASH_WORKER: &str =
    "household_install_transaction::tests::finalize_ack_delivery_crash_worker";
const ACK_CHILD_PATH_ENV: &str = "THEYOS_ACK_CRASH_CHILD_PATH";
const ACK_CHILD_READY_ENV: &str = "THEYOS_ACK_CRASH_CHILD_READY";

/// Child: drive a real install to its terminal result, announce the
/// delivery boundary, then stop dead — standing in for a process that is
/// about to write the Ack to the peer and never gets to finish.
#[test]
fn finalize_ack_delivery_crash_worker() {
    let Some(path_out) = std::env::var_os(ACK_CHILD_PATH_ENV).map(PathBuf::from) else {
        return;
    };
    let ready = PathBuf::from(std::env::var_os(ACK_CHILD_READY_ENV).unwrap());

    // The child owns the state dir. `TempDir` would delete it on drop, but
    // the parent SIGKILLs this process, so no destructor runs and the
    // directory survives for inspection — which is exactly the state a
    // crashed installer leaves behind.
    let state = TempDir::new().unwrap();
    fs::write(&path_out, state.path().to_str().unwrap()).unwrap();

    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    install_exact_marker(&state, &expectation);
    let outcome =
        finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap();
    let terminal = match outcome {
        HouseholdInstallFinalizeOutcome::RotatedAndCleared {
            terminal_result, ..
        }
        | HouseholdInstallFinalizeOutcome::AlreadyRotatedAndCleared {
            terminal_result, ..
        } => terminal_result,
    };

    // Announce BEFORE the send. Everything after this point is the window
    // in which the peer may or may not have received the Ack.
    let announced = prepare_finalize_ack_delivery_under_lifecycle(&guard, &terminal).unwrap();
    assert!(matches!(
        announced,
        FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(_)
    ));

    fs::write(&ready, b"announced").unwrap();
    std::mem::forget(state); // belt and braces if a fallback path ever exits
    thread::sleep(Duration::from_secs(30));
}

/// A local send is NEVER evidence the peer processed the Ack.
///
/// The type already refuses to say otherwise — `FinalizeAckDeliveryRecoveryOutcome`
/// has no `Delivered` variant, so no code path can record delivery. This
/// is the other half, by execution rather than by reading: kill the
/// process in the window where the Ack may or may not have reached the
/// peer, and a restart must still report `MayHaveTakenEffect`.
///
/// `Absent` here would be the real defect — a retry would conclude nothing
/// had happened and re-run an effect the peer may already have applied.
#[test]
fn sigkill_after_announcing_delivery_never_recovers_as_absent() {
    let scratch = TempDir::new().unwrap();
    let path_out = scratch.path().join("child-state-path");
    let ready = scratch.path().join("child-announced");

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(ACK_CRASH_WORKER)
        .arg("--nocapture")
        .env(ACK_CHILD_PATH_ENV, &path_out)
        .env(ACK_CHILD_READY_ENV, &ready)
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(60);
    while !ready.exists() {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("child exited ({status}) without announcing the delivery boundary");
        }
        assert!(
            Instant::now() < deadline,
            "child never announced the delivery boundary"
        );
        thread::sleep(Duration::from_millis(20));
    }
    child.kill().unwrap();
    assert!(
        !child.wait().unwrap().success(),
        "the child was supposed to be killed in the delivery window"
    );

    let state_path = PathBuf::from(fs::read_to_string(&path_out).unwrap());
    let lifecycle = HouseholdLifecycleLock::open_verified(&state_path).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();

    let recovered = load_finalize_ack_delivery_under_lifecycle(&guard).unwrap();
    let retained = match recovered {
        FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(retained) => retained,
        FinalizeAckDeliveryRecoveryOutcome::Absent => panic!(
            "recovery reported Absent after a crash in the delivery window: a retry                  would conclude nothing had happened and re-apply an effect the peer may                  already have processed"
        ),
    };

    // Retry must complete at the EXACT persisted endpoint. Replaying the
    // retained result is accepted; anything divergent, even by one byte,
    // is quarantine evidence rather than a second delivery.
    assert!(matches!(
        prepare_finalize_ack_delivery_under_lifecycle(&guard, &retained).unwrap(),
        FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(ref again)
            if again == &retained
    ));

    let mut divergent = (*retained).clone();
    divergent.ack_bytes.push(0);
    assert_eq!(
        prepare_finalize_ack_delivery_under_lifecycle(&guard, &divergent).unwrap_err(),
        HouseholdInstallTransactionError::Quarantined,
        "a retry that is not byte-exact must fail closed, not deliver again"
    );

    fs::remove_dir_all(&state_path).ok();
}

#[test]
fn delivery_boundary_accepts_only_the_full_current_terminal_result() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let (guard, expectation) = begin(&state, &lifecycle);
    install_exact_marker(&state, &expectation);
    let outcome =
        finish_household_install_under_lifecycle(&guard, &expectation, |_| Ok(())).unwrap();
    let terminal = match outcome {
        HouseholdInstallFinalizeOutcome::RotatedAndCleared {
            terminal_result, ..
        }
        | HouseholdInstallFinalizeOutcome::AlreadyRotatedAndCleared {
            terminal_result, ..
        } => terminal_result,
    };

    assert!(matches!(
        prepare_finalize_ack_delivery_under_lifecycle(&guard, &terminal).unwrap(),
        FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(ref retained)
            if retained.as_ref() == &terminal
    ));
    assert!(matches!(
        load_finalize_ack_delivery_under_lifecycle(&guard).unwrap(),
        FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(ref retained)
            if retained.as_ref() == &terminal
    ));

    let mut same_generation_but_divergent = terminal.clone();
    same_generation_but_divergent.ack_bytes.push(0);
    assert_eq!(
        prepare_finalize_ack_delivery_under_lifecycle(&guard, &same_generation_but_divergent,)
            .unwrap_err(),
        HouseholdInstallTransactionError::Quarantined
    );

    let replacement_generation = guard.rotate_lifecycle_generation().unwrap();
    assert_ne!(replacement_generation, *terminal.terminal_generation());
    assert_eq!(
        prepare_finalize_ack_delivery_under_lifecycle(&guard, &terminal).unwrap_err(),
        HouseholdInstallTransactionError::Quarantined
    );
}

#[test]
fn exact_nonce_temps_are_swept_and_physically_bounded() {
    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    guard.ensure_lifecycle_generation().unwrap();
    for index in 0..8_u8 {
        for prefix in [
            TRANSACTION_TMP_PREFIX,
            TERMINAL_RESULT_TMP_PREFIX,
            DELIVERY_RECORD_TMP_PREFIX,
        ] {
            let path = state.path().join(format!("{prefix}{index:032x}"));
            fs::write(&path, b"orphan").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    assert_eq!(
        lookup_finalize_terminal_result_under_lifecycle(
            &guard,
            FinalizeRequestFingerprintV1::for_canonical_request_bytes(b"absent"),
            &HouseholdId::parse("hh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            &MachineId::parse("m_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
        )
        .unwrap(),
        FinalizeTerminalLookupOutcome::Absent
    );
    let leftovers = fs::read_dir(state.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            install_tmp_max_len(&name).is_some()
        })
        .count();
    assert_eq!(leftovers, 0);
}

#[test]
fn exact_nonce_symlink_quarantines_without_deleting_target() {
    use std::os::unix::fs::symlink;

    let state = TempDir::new().unwrap();
    let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
    let guard = lifecycle.lock_exclusive().unwrap();
    guard.ensure_lifecycle_generation().unwrap();
    let target = state.path().join("do-not-delete");
    fs::write(&target, b"authority").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let trap = state
        .path()
        .join(format!("{TRANSACTION_TMP_PREFIX}{}", "a".repeat(32)));
    symlink(&target, &trap).unwrap();

    assert_eq!(
        has_active_finalize_terminal_result_under_lifecycle(&guard).unwrap_err(),
        HouseholdInstallTransactionError::Quarantined
    );
    assert_eq!(fs::read(&target).unwrap(), b"authority");
    assert!(trap.symlink_metadata().unwrap().file_type().is_symlink());
}
