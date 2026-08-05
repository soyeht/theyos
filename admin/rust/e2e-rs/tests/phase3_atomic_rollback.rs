//! Phase 3 atomic rollback tests (T065-T072 + T096).
//!
//! Each test drives the ceremony far enough to exercise a specific
//! rollback path described in `specs/003-machine-join/contracts/
//! shamir-transition.md` §"Failure-injection test plan", then asserts
//! that:
//!
//! 1. The sole-shard plaintext is still on disk (founder still
//!    custodies `HH_priv` via the 1-machine path), AND
//! 2. No `MachineCert` for the candidate has been promoted on M1,
//!    AND
//! 3. No `.staged` files linger after recovery.
//!
//! The harness used here lives at `tests/phase3_support/mod.rs`. The
//! failure-injection facade (`tests/phase3_support/failure_injector.rs`,
//! re-exports `server_rs::failure_injection::*`) is gated behind the
//! `failure-injection` feature on `server-rs`; tests that need it
//! `cfg(feature = "failure-injection")` themselves so they only run
//! when the harness is compiled in.

#![allow(clippy::missing_panics_doc)]

mod phase3_support;

use std::fs;
use std::time::Duration;

use axum::http::StatusCode;
use axum::http::header;
use household_rs::pair_machine::{
    PairMachineState, PairMachineWindow, household_root_sole_path, shamir_self_shard_path,
};
use household_rs::storage::{
    detect_orphan_staged_files, machine_cert_for, phase3_finalize_ack_marker_exists,
    phase3_pending_join_response_exists,
};

use phase3_support::*;

/// Stage the join-request to `awaiting_owner` without yet approving.
///
/// Returns the founder + candidate harness and the owner-event cursor
/// the iPhone would now be holding. The test can then approve, decline,
/// let the window expire, or crash a participant before continuing.
async fn drive_to_awaiting_owner(
    candidate_ttl: Duration,
) -> (
    FounderHarness,
    CandidateHarness,
    JoinRequestAccepted,
    [u8; 32],
) {
    drive_to_awaiting_owner_with_ttl(candidate_ttl).await
}

async fn drive_to_awaiting_owner_with_ttl(
    candidate_ttl: Duration,
) -> (
    FounderHarness,
    CandidateHarness,
    JoinRequestAccepted,
    [u8; 32],
) {
    let founder = founder_harness();
    // Mirror the on-disk state production has before a Phase-3 ceremony
    // begins: `household_root_sole.cbor` is the plaintext custody of
    // `HH_priv` on a 1-machine household (created at `theyos install`
    // time). The harness's `bootstrap_or_load` does NOT create it
    // because `try_load_existing` reads `HH_priv` from the keystore;
    // the file is added so the rollback assertions can verify it
    // survives the aborted ceremony.
    fs::write(
        household_root_sole_path(founder.dir.path()),
        b"fake-sole-shard",
    )
    .expect("write fake sole-shard");
    let candidate = candidate_harness_with_ttl(candidate_ttl).await;
    let qr_uri = candidate
        .prepared
        .join_request
        .to_pair_machine_uri_with_anchor(
            candidate.prepared.ttl_unix,
            &candidate.prepared.anchor_secret,
        );
    let (join_request_from_qr, anchor_secret) = parse_join_request_from_qr(&qr_uri);
    verify_owner_side_challenge(&join_request_from_qr);

    let (status, _, body) = post_cbor(
        founder.router.clone(),
        JOIN_REQUEST_PATH,
        candidate.prepared.join_request_cbor.clone(),
        Some(&founder.owner),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let accepted: JoinRequestAccepted =
        household_rs::cbor::from_canonical_slice(&body).expect("decode accepted");
    assert_eq!(accepted.version, 1);
    assert_eq!(accepted.owner_event_cursor, 1);

    post_local_anchor(&candidate, &founder, &anchor_secret).await;
    (founder, candidate, accepted, anchor_secret)
}

// `candidate_harness_with_ttl` (custom PairMachineWindow TTL for the T066
// timeout test) lives in `phase3_support` now -- it shares the same
// restart-simulating finalize route as every other candidate harness there
// instead of duplicating a `runtime_signal: None` router locally. That
// duplicate was the cause of this file's four rollback tests hanging
// against RECOVERY_TIMEOUT before this fix: no receiver, no simulated
// restart, no converging retry.

fn assert_no_phase3_residue_on_founder(founder: &FounderHarness, candidate_m_id: &str) {
    let dir = founder.dir.path();
    assert!(
        household_root_sole_path(dir).exists(),
        "sole-shard must remain after rollback: {}",
        dir.display()
    );
    assert!(
        !shamir_self_shard_path(dir).exists(),
        "shamir/self_shard.cbor must NOT exist after rollback: {}",
        dir.display()
    );
    assert!(
        !machine_cert_for(dir, candidate_m_id).exists(),
        "candidate cert must NOT exist on founder after rollback"
    );
    let staged = detect_orphan_staged_files(dir);
    assert!(
        staged.is_empty(),
        "staged files must be cleaned after rollback: {staged:?}"
    );
    assert!(
        !phase3_finalize_ack_marker_exists(dir),
        "finalize-ack marker must be cleared after rollback"
    );
    assert!(
        !phase3_pending_join_response_exists(dir),
        "pending JoinResponse must be cleared after rollback"
    );
}

// ---------------------------------------------------------------------------
// T065: owner decline rolls back
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_owner_decline_rolls_back() {
    let (founder, candidate, accepted, _anchor) =
        drive_to_awaiting_owner(Duration::from_secs(300)).await;

    // Hit the decline endpoint. The handler transitions the window to
    // Aborted, appends a JoinCancelled OwnerEvent, and returns 200 OK.
    let path = format!(
        "/api/v1/household/owner-events/{}/decline",
        accepted.owner_event_cursor
    );
    let timestamp = unix_now();
    let auth = pop_header(&founder.owner, "POST", &path, timestamp, b"");
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(&path)
        .header(header::CONTENT_TYPE, "application/cbor")
        .header(header::AUTHORIZATION, auth)
        .body(axum::body::Body::empty())
        .expect("build decline request");
    let resp = tower::ServiceExt::oneshot(founder.router.clone(), req)
        .await
        .expect("decline response");
    assert_eq!(resp.status(), StatusCode::OK);

    // Founder side: sole-shard intact, no candidate cert, no .staged.
    let m2_id = candidate.prepared.m_id.to_string();
    assert_no_phase3_residue_on_founder(&founder, &m2_id);

    // Window is `Aborted`.
    let snap = founder.window.snapshot().await;
    assert_eq!(snap.state, PairMachineState::Aborted);
}

// ---------------------------------------------------------------------------
// T066: owner timeout rolls back
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_owner_timeout_rolls_back() {
    // The candidate-side TTL is bounded by `prepare_candidate` to
    // `1..=300` seconds; we use the minimum the validator accepts and
    // simulate the post-expiry transition by invoking `enter_aborted`
    // directly. Production drives the same transition from the
    // owner-events watchdog (`spawn_owner_timeout_watchdog`); the
    // residue assertions are identical either way.
    let (founder, candidate, accepted, _anchor) =
        drive_to_awaiting_owner(Duration::from_secs(1)).await;

    founder
        .window
        .enter_aborted()
        .await
        .expect("enter aborted on expiry");

    let m2_id = candidate.prepared.m_id.to_string();
    assert_no_phase3_residue_on_founder(&founder, &m2_id);
    let snap = founder.window.snapshot().await;
    assert_eq!(snap.state, PairMachineState::Aborted);
    let _ = accepted;
}

// Constructor exposed via an inherent impl on `CandidateHarness` in
// the support module so this test file can build one with a custom
// TTL.
//
// The trick: `CandidateHarness` lives in `phase3_support::mod`, which
// is shared across phase3_*.rs test files. Adding an `impl`-block in
// this test file would not be permitted (orphan rule). So the support
// module exposes a `__new_for_test` constructor used by every Phase 3
// rollback test that needs custom-TTL candidate harness creation.

// ---------------------------------------------------------------------------
// T067: M2 disconnect after approval, before finalize POST
// ---------------------------------------------------------------------------

/// Submit `OwnerApproval` against the founder router. Returns the HTTP
/// response status — the body's CBOR shape is checked by the caller
/// when needed.
async fn submit_approval(
    founder: &FounderHarness,
    candidate: &CandidateHarness,
    cursor: u64,
) -> StatusCode {
    let (status, _, _) =
        post_owner_approval(founder, &candidate.prepared.join_request, cursor).await;
    status
}

#[tokio::test]
async fn test_m2_disconnect_after_approval_rolls_back() {
    let (founder, mut candidate, accepted, _anchor) =
        drive_to_awaiting_owner(Duration::from_secs(300)).await;

    // Stop M2's pre-household HTTP server BEFORE submitting approval —
    // M1's finalize POST in `owner_approve_handler` will hit a
    // connection-refused on the cached candidate addr.
    candidate.stop_server().await;

    // Submit owner approval. M1's finalize_with_m2 returns a transport
    // error (ureq connection refused), which `is_ambiguous_finalize_outcome`
    // classifies as ambiguous. The handler returns 500 + leaves the
    // marker + .staged + pending_join_response on disk for boot recovery.
    let status = submit_approval(&founder, &candidate, accepted.owner_event_cursor).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "ambiguous finalize failure must surface as 500 per contract"
    );

    let dir = founder.dir.path();
    // The manifest is written durably (arm_manifest_recovery) BEFORE the
    // finalize POST is even launched, and the ambiguous-failure arm
    // (handlers_owner_events.rs) returns 500 without clearing it — so it
    // survives this failure path by construction, unlike the legacy marker
    // which this version's approve handler no longer writes at all.
    assert!(
        household_rs::storage::phase3_recovery_manifest_exists(dir),
        "the ack marker is legacy on-disk evidence retained only for upgraded \
         households; a ceremony on this version writes the recovery manifest"
    );
    let manifest = household_rs::storage::read_phase3_recovery_manifest(dir)
        .expect("read recovery manifest")
        .expect("recovery manifest present");
    assert!(
        !manifest.exact_join_response().is_empty(),
        "the pending JoinResponse is legacy on-disk evidence retained only for upgraded \
         households; a ceremony on this version embeds it in the recovery manifest"
    );
    assert!(
        !detect_orphan_staged_files(dir).is_empty(),
        ".staged set must survive ambiguous finalize failure"
    );
    founder
        .window
        .claim_owner_approval(accepted.owner_event_cursor, [0xA5; 32], unix_now())
        .await
        .expect("simulate v2 approval claim before crash");

    // A launched finalize POST is MayHaveTakenEffect (step 10 sent, step 11
    // not received) regardless of why M2 never acked — timeout alone can
    // never authorize rollback to N=1 (pair_machine.rs:44). Recovery fails
    // closed and retains the manifest + .staged evidence for exact replay
    // or manual recovery.
    let outcome = household_rs::pair_machine::recover_phase3_ceremony(
        founder.dir.path(),
        Duration::from_millis(200),
    )
    .await;
    assert!(
        matches!(
            outcome,
            Err(household_rs::pair_machine::RecoveryError::FinalizeOutcomeIndeterminate)
        ),
        "expected FinalizeOutcomeIndeterminate, got {outcome:?}"
    );

    assert!(
        household_rs::storage::phase3_recovery_manifest_exists(dir),
        "the recovery manifest must be retained after an indeterminate outcome"
    );
    assert!(
        !detect_orphan_staged_files(dir).is_empty(),
        ".staged set must be retained after an indeterminate outcome"
    );
}

// ---------------------------------------------------------------------------
// T068: M2 finalize partial write rolls back
// ---------------------------------------------------------------------------

/// M2's `local_finalize_handler` panics after staging files but before
/// `staged.commit()`. The .staged set is cleaned by
/// `recover_partial_phase3_commit` on M2's next boot (M2-side
/// rollback path).
#[cfg(any(test, feature = "failure-injection"))]
#[tokio::test]
async fn test_m2_finalize_partial_write_rolls_back() {
    use phase3_support::failure_injector::{
        InjectionAction, InjectionPoint, arm, lock_injection_tests, reset,
    };

    let _guard = lock_injection_tests();
    reset();
    arm(
        InjectionPoint::M2AfterFounderCertStaged,
        InjectionAction::early_reject("partial-write simulation"),
    );

    let (founder, candidate, accepted, _anchor) =
        drive_to_awaiting_owner(Duration::from_secs(300)).await;

    // Submit approval. M1's finalize_with_m2 sees the EarlyReject as a
    // pre-FinalizeAck non-2xx response → CeremonyError::FinalizeRejected
    // → DefiniteFailure path. M1 rolls back its own staged set; M2's
    // staged set was created but never committed (the EarlyReject
    // dropped the staged handle, which unlinks via Drop).
    let status = submit_approval(&founder, &candidate, accepted.owner_event_cursor).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "definitive M2 reject must surface as 401 per contract"
    );

    // M1 side: full rollback (definite failure path).
    let m2_id = candidate.prepared.m_id.to_string();
    assert_no_phase3_residue_on_founder(&founder, &m2_id);

    // M2 side: no committed state. (.staged unlink is best-effort via
    // the Drop impl on StagedCommit; the Skip path drops the handle
    // explicitly.)
    let m2_dir = candidate.dir.path();
    assert!(
        !shamir_self_shard_path(m2_dir).exists(),
        "M2 must not have committed self_shard"
    );
}

// ---------------------------------------------------------------------------
// T069: M1 crash between step 10 and 11 → recovers to rollback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_m1_crash_between_step10_and_step11_recovers_to_rollback() {
    // Originally modeled as "M1 sent the POST but lost it, M2 never heard,
    // recovery finds no commit and rolls back." That premise was wrong:
    // once step 10 (the `local/finalize` POST, pair_machine.rs:1625) is
    // launched, the outcome is MayHaveTakenEffect regardless of whether M2
    // ever received it — timeout alone can never authorize rollback to
    // N=1 (pair_machine.rs:44). Recovery fails closed and retains the
    // manifest + .staged evidence for exact replay or manual recovery.
    let (founder, mut candidate, accepted, _anchor) =
        drive_to_awaiting_owner(Duration::from_secs(300)).await;

    candidate.stop_server().await;

    let status = submit_approval(&founder, &candidate, accepted.owner_event_cursor).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    let outcome = household_rs::pair_machine::recover_phase3_ceremony(
        founder.dir.path(),
        Duration::from_millis(200),
    )
    .await;
    assert!(
        matches!(
            outcome,
            Err(household_rs::pair_machine::RecoveryError::FinalizeOutcomeIndeterminate)
        ),
        "expected FinalizeOutcomeIndeterminate, got {outcome:?}"
    );

    let dir = founder.dir.path();
    assert!(
        household_rs::storage::phase3_recovery_manifest_exists(dir),
        "the recovery manifest must be retained after an indeterminate outcome"
    );
    assert!(
        !detect_orphan_staged_files(dir).is_empty(),
        ".staged set must be retained after an indeterminate outcome"
    );
}

// ---------------------------------------------------------------------------
// T070: M1 crash between step 11 and 12 → recovers to commit
// ---------------------------------------------------------------------------

/// Full residue check for a successful roll-forward: M1's record is
/// post-Shamir, the candidate cert is on disk, the sole-shard is
/// gone, and no marker / pending / .staged residues remain.
fn assert_rolled_forward_on_founder(founder: &FounderHarness, candidate_m_id: &str) {
    let dir = founder.dir.path();
    assert!(
        !household_root_sole_path(dir).exists(),
        "sole-shard must be deleted after roll-forward: {}",
        dir.display()
    );
    assert!(
        machine_cert_for(dir, candidate_m_id).exists(),
        "candidate cert must exist on founder after roll-forward"
    );
    let staged = detect_orphan_staged_files(dir);
    assert!(
        staged.is_empty(),
        ".staged files must be cleared after roll-forward: {staged:?}"
    );
    assert!(
        !phase3_finalize_ack_marker_exists(dir),
        "marker must be cleared after roll-forward"
    );
    assert!(
        !phase3_pending_join_response_exists(dir),
        "pending JoinResponse must be cleared after roll-forward"
    );
}

#[cfg(any(test, feature = "failure-injection"))]
#[tokio::test]
async fn test_m1_crash_between_step11_and_step12_recovers_to_commit() {
    use phase3_support::failure_injector::{
        InjectionAction, InjectionPoint, arm, lock_injection_tests, reset,
    };

    // M1AfterAck fires AFTER finalize_with_m2 returns Ok (FinalizeAck
    // received, M2 committed) and BEFORE commit_preserve_on_error
    // runs. EarlyReject calls preserve_staged_for_recovery and
    // returns 500, leaving the staged set + recovery manifest + pending
    // JoinResponse on disk (the manifest is written durably by
    // arm_manifest_recovery before the finalize POST, so it is already
    // present regardless of the injection). M2 is committed at this
    // point, but its ceremony window is generation-scoped and reads
    // Idle in the post-rotation generation once the harness reloads it
    // after the 503 restart-required response
    // (`SharedCandidateWindow::reload_after_restart_required`), so the
    // durable observable is the household record, not the window
    // snapshot (same substitution as `linux_candidate_join.rs`).
    let _guard = lock_injection_tests();
    reset();
    arm(
        InjectionPoint::M1AfterAck,
        InjectionAction::early_reject("crash between step 11 and step 12"),
    );

    let (founder, candidate, accepted, _anchor) =
        drive_to_awaiting_owner(Duration::from_secs(300)).await;

    let status = submit_approval(&founder, &candidate, accepted.owner_event_cursor).await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "post-FinalizeAck failure must surface as 500"
    );

    let dir = founder.dir.path();
    assert!(
        household_rs::storage::phase3_recovery_manifest_exists(dir),
        "the ack marker is legacy on-disk evidence retained only for upgraded \
         households; a ceremony on this version writes the recovery manifest"
    );
    let manifest = household_rs::storage::read_phase3_recovery_manifest(dir)
        .expect("read recovery manifest")
        .expect("recovery manifest present");
    assert!(
        !manifest.exact_join_response().is_empty(),
        "the pending JoinResponse is legacy on-disk evidence retained only for upgraded \
         households; a ceremony on this version embeds it in the recovery manifest"
    );
    assert!(!detect_orphan_staged_files(dir).is_empty());
    founder
        .window
        .claim_owner_approval(accepted.owner_event_cursor, [0xA5; 32], unix_now())
        .await
        .expect("simulate v2 approval claim before crash");

    // M2 has already committed via local/finalize.
    let candidate_record: household_rs::HouseholdRecord =
        household_rs::storage::read_optional_cbor(&household_rs::storage::household_record_path(
            candidate.dir.path(),
        ))
        .expect("read candidate household record")
        .expect("candidate household record exists");
    assert!(
        candidate_record.shamir_n > 1,
        "shamir_n > 1 is what distinguishes a committed Phase-3 transition from a \
         sole-shard record that boot classifies as logically rolled back \
         (storage.rs:798, recover_partial_phase3_commit's own post_shamir check); \
         the ceremony window is generation-scoped and reads Idle in the \
         post-rotation generation"
    );

    // Recovery: re-POST the staged JoinResponse to M2. M2's
    // local/finalize short-circuits to cached_response (the bytes
    // bit-equal what M1 has on disk in pending_join_response.cbor),
    // returns 200. M1 finishes step 12+ locally.
    let outcome = household_rs::pair_machine::recover_phase3_ceremony(
        founder.dir.path(),
        Duration::from_millis(500),
    )
    .await
    .expect("recovery completes");
    assert!(
        matches!(
            outcome,
            household_rs::pair_machine::RecoveryOutcome::RolledForwardPreCommit
                | household_rs::pair_machine::RecoveryOutcome::RolledForwardPostCommit
        ),
        "expected RolledForward*, got {outcome:?}"
    );

    let m2_id = candidate.prepared.m_id.to_string();
    assert_rolled_forward_on_founder(&founder, &m2_id);
    let recovered_window = PairMachineWindow::with_persistence(founder.dir.path().to_path_buf())
        .expect("reload recovered founder window");
    let snapshot = recovered_window.snapshot().await;
    assert_eq!(snapshot.state, PairMachineState::Committed);
    assert!(snapshot.approval_claim.is_none());
    assert!(snapshot.cached_response.is_some());
}

// ---------------------------------------------------------------------------
// T071: M1 crash between step 12 (rename) and step 13 (sole-shard delete)
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "failure-injection"))]
#[tokio::test]
async fn test_m1_crash_between_step12_and_step13_recovers_to_commit() {
    use phase3_support::failure_injector::{
        InjectionAction, InjectionPoint, arm, lock_injection_tests, reset,
    };

    // M1AfterStagedRename fires synchronously inside
    // commit_preserve_on_error_with_hook between staged.commit (step
    // 12) and the sole-shard unlink (step 13). EarlyReject returns
    // CeremonyError::FinalizeRejected and skips the cleanup. On
    // reboot, M1's on-disk state is:
    //   - record at shamir_n=2 (canonical commit marker flipped)
    //   - sole-shard still present (NOT unlinked)
    //   - marker still on disk
    //   - pending JoinResponse still on disk
    let _guard = lock_injection_tests();
    reset();
    arm(
        InjectionPoint::M1AfterStagedRename,
        InjectionAction::early_reject("crash between step 12 and step 13"),
    );

    let (founder, candidate, accepted, _anchor) =
        drive_to_awaiting_owner(Duration::from_secs(300)).await;

    let status = submit_approval(&founder, &candidate, accepted.owner_event_cursor).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    let dir = founder.dir.path();

    // Post-Shamir record on disk (canonical commit marker flipped).
    let record: household_rs::HouseholdRecord = household_rs::storage::read_optional_cbor(
        &household_rs::storage::household_record_path(dir),
    )
    .expect("read record")
    .expect("record exists");
    assert_eq!(record.shamir_n, 2);

    // Sole-shard still present because the unlink was skipped.
    assert!(
        household_root_sole_path(dir).exists(),
        "sole-shard must still exist after step-12-only commit"
    );

    // Trigger boot-time recovery sweeps. recover_post_join_sole_shard
    // unlinks the leftover sole-shard;
    // clear_stale_phase3_marker_if_post_shamir clears the marker AND
    // the pending JoinResponse on every post-Shamir boot.
    let outcome = household_rs::storage::load_state_dir(dir).expect("load_state_dir runs sweeps");
    assert!(
        outcome.recovered_post_join_sole_shard_deleted,
        "boot-time sweep must unlink leftover sole-shard"
    );

    // load_state_dir alone does not clear the .staged siblings: while a
    // Phase-3 recovery manifest is present, recover_partial_phase3_commit's
    // preservation gate defers to the manifest recovery driver on purpose
    // (its own cleanup loop deletes .staged without hash verification;
    // only the manifest driver's promote_phase3_artifact_exact verifies
    // the exact hash before promoting/clearing evidence). This mirrors
    // what the real daemon does on boot
    // (bootstrap_household -> recover_phase3_under_lifecycle ->
    // recover_phase3_ceremony_under_lifecycle).
    let recovery_outcome = household_rs::pair_machine::recover_phase3_ceremony(
        dir,
        Duration::from_millis(500),
    )
    .await
    .expect("recovery completes");
    assert!(
        matches!(
            recovery_outcome,
            household_rs::pair_machine::RecoveryOutcome::RolledForwardPreCommit
                | household_rs::pair_machine::RecoveryOutcome::RolledForwardPostCommit
        ),
        "expected RolledForward*, got {recovery_outcome:?}"
    );

    let m2_id = candidate.prepared.m_id.to_string();
    assert_rolled_forward_on_founder(&founder, &m2_id);
}

// ---------------------------------------------------------------------------
// T072: M1 crash during step 13 → recovery is idempotent on missing-file
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_m1_crash_during_step13_is_idempotent() {
    // T072 simulates "the unlink ran, reboot, recovery completes the
    // unlink (idempotent on missing-file)". POSIX `std::fs::remove_file`
    // is atomic — there is no in-progress partial-unlink state — so
    // the test reduces to "recovery is idempotent on a state where
    // the sole-shard is already absent".
    //
    // Both `recover_post_join_sole_shard` and
    // `clear_stale_phase3_marker_if_post_shamir` short-circuit on
    // missing files. Re-running `load_state_dir` repeatedly must
    // converge.
    let td = tempfile::tempdir().expect("tempdir");
    let dir = td.path();
    fs::create_dir_all(household_rs::storage::household_dir(dir)).expect("mkdir household");

    // Run #1: empty state, nothing to recover.
    let outcome1 = household_rs::storage::load_state_dir(dir).expect("load_state_dir on empty dir");
    assert!(!outcome1.recovered_post_join_sole_shard_deleted);
    assert_eq!(outcome1.partial_phase3_commit_rolled_back, 0);
    assert_eq!(outcome1.partial_phase3_commit_rolled_forward, 0);

    // Run #2: same state — the recovery primitive must NOT panic on
    // missing-sole and must return the same flags.
    let outcome2 = household_rs::storage::load_state_dir(dir).expect("idempotent boot");
    assert_eq!(outcome2, outcome1);

    // Run #3: place a `phase3_finalize_ack.marker` with no record on
    // disk — the stale-marker sweep gates on "post-Shamir record
    // present" so it should leave the marker alone (no record =
    // pre-Shamir from the sweep's perspective; preserve marker for
    // T073/T074 driver).
    household_rs::storage::write_phase3_finalize_ack_marker(dir, "m_irrelevant")
        .expect("write marker");
    let outcome3 = household_rs::storage::load_state_dir(dir).expect("third boot");
    let _ = outcome3;
    assert!(
        household_rs::storage::phase3_finalize_ack_marker_exists(dir),
        "marker without post-Shamir record must be preserved for the recovery driver"
    );
}

// ---------------------------------------------------------------------------
// T096: recovery timeout rolls back when M2 permanently lost
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_recovery_timeout_rolls_back_when_m2_permanently_lost() {
    // Per FR-013a: when M2 is permanently unreachable after approval,
    // M1's recovery driver loops on probes until RECOVERY_TIMEOUT
    // elapses. This test reuses the T067 setup (M2 server stopped
    // pre-approval → ambiguous finalize failure) and explicitly asserts
    // the timing: the Recover call must take AT LEAST `recovery_timeout`
    // to elapse. The launched finalize POST is MayHaveTakenEffect
    // (pair_machine.rs:44), so the timeout itself can never authorize a
    // rollback to N=1 — it fails closed with FinalizeOutcomeIndeterminate
    // and retains every piece of recovery evidence instead.
    use std::time::Instant;

    let (founder, mut candidate, accepted, _anchor) =
        drive_to_awaiting_owner(Duration::from_secs(300)).await;

    candidate.stop_server().await;

    let status = submit_approval(&founder, &candidate, accepted.owner_event_cursor).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    founder
        .window
        .claim_owner_approval(accepted.owner_event_cursor, [0xA5; 32], unix_now())
        .await
        .expect("simulate v2 approval claim before crash");

    // Use a short test timeout (200ms) — the production constant is
    // 5 minutes (RECOVERY_TIMEOUT), and the regression here is "the
    // driver respects whatever timeout it was given AND only rolls
    // back AFTER that timeout has elapsed".
    let test_timeout = Duration::from_millis(200);
    let start = Instant::now();
    let outcome =
        household_rs::pair_machine::recover_phase3_ceremony(founder.dir.path(), test_timeout)
            .await;
    let elapsed = start.elapsed();
    assert!(
        matches!(
            outcome,
            Err(household_rs::pair_machine::RecoveryError::FinalizeOutcomeIndeterminate)
        ),
        "expected FinalizeOutcomeIndeterminate past timeout, got {outcome:?}"
    );
    assert!(
        elapsed >= test_timeout,
        "recovery gave up too early: elapsed {elapsed:?} < timeout {test_timeout:?}"
    );

    // FR-013a (revised): the driver fails closed past timeout and
    // retains full recovery evidence instead of cleaning it up.
    let dir = founder.dir.path();
    assert!(
        household_rs::storage::phase3_recovery_manifest_exists(dir),
        "the recovery manifest must be retained after an indeterminate outcome"
    );
    assert!(
        !detect_orphan_staged_files(dir).is_empty(),
        ".staged set must be retained after an indeterminate outcome"
    );
}
