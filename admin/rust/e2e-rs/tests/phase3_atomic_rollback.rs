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
use household_rs::KeyBackingPolicy;
use household_rs::machine_cert::Platform;
use household_rs::pair_machine::{
    JoinTransport, PairMachineState, PairMachineWindow, PrepareCandidateOpts,
    household_root_sole_path, prepare_candidate, shamir_self_shard_path,
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

/// Like `candidate_harness()` from `phase3_support`, but with a custom
/// `PairMachineWindow` TTL so the timeout test (T066) can drive an
/// expiry without waiting 5 minutes.
async fn candidate_harness_with_ttl(ttl: Duration) -> CandidateHarness {
    use server_rs::handlers_pair_machine::{PreHouseholdRouterState, pre_household_router};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    let dir = tempfile::tempdir().expect("m2 tempdir");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind candidate listener");
    let addr = listener.local_addr().expect("candidate local addr");
    let window = Arc::new(
        household_rs::pair_machine::PairMachineWindow::with_persistence(dir.path().to_path_buf())
            .expect("m2 window"),
    );
    let prepared = prepare_candidate(
        &window,
        PrepareCandidateOpts {
            state_dir: dir.path().to_path_buf(),
            transport: JoinTransport::Tailscale,
            addr: addr.to_string(),
            hostname: "studio-m2".into(),
            platform: Platform::LinuxNix,
            policy: KeyBackingPolicy::ForceSoftware,
            ttl,
            now_unix: unix_now(),
        },
    )
    .await
    .expect("prepare candidate");
    let router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: dir.path().to_path_buf(),
        key_policy: KeyBackingPolicy::ForceSoftware,
        bootstrap: None,
        runtime_signal: None,
    });
    let served_router = router.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, served_router).await;
    });

    // The CandidateHarness fields aren't all `pub`; we construct it via
    // the same path the support module uses internally. Importing the
    // helper directly is cleaner — but the support `candidate_harness()`
    // hard-codes a 300s TTL. Replicate just the bits we need locally.
    CandidateHarness::__new_for_test(dir, window, prepared, router, server)
}

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
    assert!(
        phase3_finalize_ack_marker_exists(dir),
        "marker must survive ambiguous finalize failure (boot recovery needs it)"
    );
    assert!(
        phase3_pending_join_response_exists(dir),
        "pending JoinResponse must survive ambiguous finalize failure"
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

    // Now drive boot recovery with a short timeout. M2 is unreachable
    // (server stopped), so both probes fail and recovery rolls back
    // past the timeout.
    let outcome = household_rs::pair_machine::recover_phase3_ceremony(
        founder.dir.path(),
        Duration::from_millis(200),
    )
    .await
    .expect("recovery completes");
    assert!(
        matches!(
            outcome,
            household_rs::pair_machine::RecoveryOutcome::RolledBack
        ),
        "expected RolledBack, got {outcome:?}"
    );

    let m2_id = candidate.prepared.m_id.to_string();
    assert_no_phase3_residue_on_founder(&founder, &m2_id);
    let recovered_window = PairMachineWindow::with_persistence(founder.dir.path().to_path_buf())
        .expect("reload recovered founder window");
    let snapshot = recovered_window.snapshot().await;
    assert_eq!(snapshot.state, PairMachineState::Aborted);
    assert!(snapshot.approval_claim.is_none());
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
    // "M1 sent the POST but lost it (M2 never heard); M1 reboots with
    // .staged files + sole-shard still present; recovery probes M2 and
    // finds no commit; deletes .staged; ceremony rolls back."
    //
    // We model this by stopping M2's server BEFORE M1's POST (so M2
    // never receives anything), submitting approval (M1 transport
    // error → ambiguous → marker + .staged on disk), then running the
    // recovery driver against the stopped M2. Both probes fail; past
    // the test timeout, recovery rolls back.
    let (founder, mut candidate, accepted, _anchor) =
        drive_to_awaiting_owner(Duration::from_secs(300)).await;

    candidate.stop_server().await;

    let status = submit_approval(&founder, &candidate, accepted.owner_event_cursor).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    let outcome = household_rs::pair_machine::recover_phase3_ceremony(
        founder.dir.path(),
        Duration::from_millis(200),
    )
    .await
    .expect("recovery completes");
    assert!(matches!(
        outcome,
        household_rs::pair_machine::RecoveryOutcome::RolledBack
    ));

    let m2_id = candidate.prepared.m_id.to_string();
    assert_no_phase3_residue_on_founder(&founder, &m2_id);
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
    // returns 500, leaving the staged set + marker + pending
    // JoinResponse on disk. M2 is committed at this point —
    // candidate.window.snapshot().state == Committed.
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
    assert!(phase3_finalize_ack_marker_exists(dir));
    assert!(phase3_pending_join_response_exists(dir));
    assert!(!detect_orphan_staged_files(dir).is_empty());
    founder
        .window
        .claim_owner_approval(accepted.owner_event_cursor, [0xA5; 32], unix_now())
        .await
        .expect("simulate v2 approval claim before crash");

    // M2 has already committed via local/finalize.
    assert_eq!(
        candidate.window.snapshot().await.state,
        PairMachineState::Committed,
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
    // elapses, then rolls back. This test reuses the T067 setup
    // (M2 server stopped pre-approval → ambiguous finalize failure)
    // and explicitly asserts the timing: the Recover call must take
    // AT LEAST `recovery_timeout` to elapse, AND must return
    // RolledBack.
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
            .await
            .expect("recovery completes");
    let elapsed = start.elapsed();
    assert!(
        matches!(
            outcome,
            household_rs::pair_machine::RecoveryOutcome::RolledBack
        ),
        "expected RolledBack past timeout, got {outcome:?}"
    );
    assert!(
        elapsed >= test_timeout,
        "recovery rolled back too early: elapsed {elapsed:?} < timeout {test_timeout:?}"
    );

    // FR-013a: full residue cleanup after timeout rollback.
    let m2_id = candidate.prepared.m_id.to_string();
    assert_no_phase3_residue_on_founder(&founder, &m2_id);
    let recovered_window = PairMachineWindow::with_persistence(founder.dir.path().to_path_buf())
        .expect("reload recovered founder window");
    let snapshot = recovered_window.snapshot().await;
    assert_eq!(snapshot.state, PairMachineState::Aborted);
    assert!(snapshot.approval_claim.is_none());
}
