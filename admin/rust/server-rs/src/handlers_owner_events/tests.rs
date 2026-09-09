#![cfg(test)]

use super::*;
use household_rs::ids::{HouseholdId, MachineId};
use household_rs::machine_cert::PersonId;
use household_rs::owner_approval_v2::PairMachineApprovalContextInput;
use household_rs::pair_machine::{JoinTransport, PAIR_MACHINE_VERSION, PairMachineApprovalClaim};
use std::net::Ipv4Addr;

fn bootstrap_lifecycle_test_identity(state_dir: &FsPath) -> household_rs::LoadedIdentity {
    household_rs::bootstrap_or_load(
        state_dir,
        household_rs::BootstrapOpts {
            household_name: "Owner Events Lifecycle Home".to_string(),
            hostname_label: Some("owner-events-lifecycle-host".to_string()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .expect("bootstrap lifecycle test identity")
}

#[test]
fn owner_authority_commit_revalidates_exact_record_and_cert() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let identity = bootstrap_lifecycle_test_identity(state_dir.path());
    let guard = acquire_owner_events_lifecycle_exclusive_blocking(state_dir.path())
        .expect("acquire lifecycle");

    verify_installed_identity_under_lifecycle(
        &guard,
        state_dir.path(),
        &identity.record,
        &identity.cert,
    )
    .expect("exact identity matches");

    let mut stale_record = identity.record.clone();
    stale_record.name.push_str(" stale");
    let error = verify_installed_identity_under_lifecycle(
        &guard,
        state_dir.path(),
        &stale_record,
        &identity.cert,
    )
    .expect_err("stale identity must not authorize owner mutation");
    assert!(error.contains("identity changed"));
}

#[test]
fn interrupted_teardown_is_recovered_but_stale_owner_mutation_is_rejected() {
    let state_dir = tempfile::tempdir().expect("state dir");
    let _identity = bootstrap_lifecycle_test_identity(state_dir.path());
    let lifecycle =
        HouseholdLifecycleLock::open_verified(state_dir.path()).expect("open lifecycle");
    let guard = lifecycle.lock_exclusive().expect("lock lifecycle");
    assert!(
        guard
            .rename_household_to_tearing_down()
            .expect("detach household")
    );
    drop(guard);

    let recovered_guard = acquire_owner_events_lifecycle_exclusive_blocking(state_dir.path())
        .expect("reacquire lifecycle for recovery");
    let error = recover_owner_events_lifecycle_or_reject(&recovered_guard, state_dir.path())
        .expect_err("recovered teardown must reject stale request");
    assert!(error.contains("recovered an interrupted teardown"));
    assert!(!state_dir.path().join("household").exists());
    assert!(!state_dir.path().join("household.tearing-down").exists());
}

#[test]
fn owner_authority_guard_blocks_same_household_teardown_until_anchor_finishes() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let state_dir = tempfile::tempdir().expect("state dir");
    let _identity = bootstrap_lifecycle_test_identity(state_dir.path());
    let owner_guard = acquire_owner_events_lifecycle_exclusive_blocking(state_dir.path())
        .expect("owner mutation lifecycle");
    let anchor_finished = Arc::new(AtomicBool::new(false));
    let contender_saw_anchor = Arc::clone(&anchor_finished);
    let contender_path = state_dir.path().to_path_buf();
    let (attempting_tx, attempting_rx) = std::sync::mpsc::channel();
    let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
    let contender = std::thread::spawn(move || {
        let lifecycle = HouseholdLifecycleLock::open_verified(&contender_path)
            .expect("open teardown contender lifecycle");
        attempting_tx.send(()).expect("signal contender attempt");
        let _teardown_guard = lifecycle
            .lock_exclusive()
            .expect("teardown contender acquires after owner mutation");
        acquired_tx
            .send(contender_saw_anchor.load(Ordering::Acquire))
            .expect("signal contender acquisition");
    });

    attempting_rx.recv().expect("contender started");
    assert!(
        acquired_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "same-household teardown must not enter before the anchor side effect"
    );
    // Model the last authority-coupled anchor/marker side effect while the
    // finish handler still owns the lifecycle guard.
    anchor_finished.store(true, Ordering::Release);
    drop(owner_guard);
    assert!(
        acquired_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("teardown enters after guard drop"),
        "teardown observed acquisition before the anchor side effect"
    );
    contender.join().expect("teardown contender");
}

#[test]
fn every_owner_authority_finish_uses_the_lifecycle_commit_helper() {
    let source = include_str!("../handlers_owner_events.rs");
    let production = source
        .split_once("#[cfg(test)]")
        .expect("owner-events test module boundary")
        .0;
    assert_eq!(
        production
            .matches("persist_owner_auth_under_lifecycle(&state, &identity, &next_auth).await")
            .count(),
        6,
        "all six owner-authority finish handlers must share the exact lifecycle commit path"
    );
    assert_eq!(
        production.matches("drop(owner_lifecycle_guard)").count(),
        6,
        "each finish handler must retain and explicitly release its lifecycle guard"
    );
}

#[test]
fn post_ack_commit_holds_lifecycle_through_reload_and_window_publication() {
    let source = include_str!("../handlers_owner_events.rs");
    // Bound the search to production text before searching for anything.
    // `include_str!` makes this test part of its own haystack: unbounded,
    // every marker below is found inside this function's own literals, in
    // the order they are written here, and the assertions pass against an
    // empty handler.
    let production = source
        .split_once("#[cfg(test)]")
        .expect("owner-events test module boundary")
        .0;
    let anchor = "From this point forward M2 has returned the exact manifest-bound Ack";
    assert_eq!(
        production.matches(anchor).count(),
        1,
        "post-ACK window anchor must exist exactly once in production text"
    );
    let commit_window = production
        .split_once(anchor)
        .expect("post-ACK lifecycle commit window")
        .1;
    let ordered = [
        "BOOTSTRAP_MUTATION_LOCK",
        "acquire_owner_events_lifecycle_exclusive",
        "verify_installed_identity_under_lifecycle",
        "try_load_existing_under_lifecycle",
        "set_loaded",
        "under_lifecycle(&post_ack_lifecycle_guard)",
        "enter_committed",
        "drop(post_ack_mutation_guard)",
    ];
    let mut remainder = commit_window;
    for marker in ordered {
        let (_, after) = remainder
            .split_once(marker)
            .unwrap_or_else(|| panic!("missing or out-of-order post-ACK marker: {marker}"));
        remainder = after;
    }
    // Ordering is not the property that matters here. The window commit
    // must RECEIVE the guard acquired above; the reacquiring variant
    // (`enter_committed` on the bare window) takes a shared lock on the
    // lifecycle file this task already holds exclusively, blocks against
    // itself for CURRENT_LOCK_TIMEOUT, and returns 500 over a commit that
    // is already durable on disk.
    let commit_call = commit_window
        .find(".enter_committed(")
        .expect("post-ACK window commit call");
    let guarded = commit_window
        .find(".under_lifecycle(&post_ack_lifecycle_guard)")
        .expect("post-ACK window commit must reuse the retained lifecycle guard");
    assert!(
        guarded < commit_call && commit_call - guarded < 80,
        "post-ACK enter_committed must be chained onto the retained guard, never reacquire it"
    );
}

fn household_id() -> HouseholdId {
    HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap()
}

fn machine_id() -> MachineId {
    MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()
}

fn owner_person_id() -> PersonId {
    PersonId("p_owner-alpha".to_string())
}

#[test]
fn candidate_tailnet_hint_requires_cgnat_and_signed_join_port() {
    assert_eq!(
        validated_candidate_tailnet_addr(Some("100.64.0.10:8091"), "192.0.2.10:8091"),
        Some("100.64.0.10:8091".to_string())
    );
    assert_eq!(
        validated_candidate_tailnet_addr(Some("100.64.0.10:9091"), "192.0.2.10:8091"),
        None
    );
    assert_eq!(
        validated_candidate_tailnet_addr(Some("192.0.2.20:8091"), "192.0.2.10:8091"),
        None
    );
    assert_eq!(
        validated_candidate_tailnet_addr(None, "192.0.2.10:8091"),
        None
    );
}

#[test]
fn founder_tailnet_hint_uses_resolved_ip_and_household_port() {
    fn resolver() -> Option<Ipv4Addr> {
        Some(Ipv4Addr::new(100, 64, 0, 10))
    }

    assert_eq!(
        build_founder_tailnet_addr(9_091, resolver).as_deref(),
        Some("100.64.0.10:9091")
    );
}

#[test]
fn founder_tailnet_hint_is_absent_when_resolver_has_no_address() {
    fn resolver() -> Option<Ipv4Addr> {
        None
    }

    assert!(build_founder_tailnet_addr(9_091, resolver).is_none());
}

fn approval_context(join_request_bytes: &[u8]) -> OwnerApprovalContextV2 {
    OwnerApprovalContextV2::pair_machine_approve(PairMachineApprovalContextInput {
        hh_id: household_id(),
        owner_p_id: owner_person_id(),
        cursor: 7,
        m_id: machine_id(),
        addr: "192.0.2.10:8091".to_string(),
        transport: JoinTransport::Lan,
        ttl_unix: 1_800,
        nonce: [0x11; 32],
        join_request_hash: join_request_hash(join_request_bytes),
        capabilities: vec!["machine-cert".to_string(), "shamir-2pc".to_string()],
        issued_at: 1_000,
        expires_at: 1_120,
        replay_nonce: [0x22; 32],
    })
}

fn live_snapshot(join_request_bytes: &[u8]) -> PairMachineWindowSnapshot {
    PairMachineWindowSnapshot {
        version: PAIR_MACHINE_VERSION,
        state: PairMachineState::AwaitingOwner,
        m_pub: Some(ByteBuf::from(vec![0x03; 33])),
        nonce: Some(ByteBuf::from(vec![0x11; 32])),
        expiry: Some(1_800),
        transport: Some(JoinTransport::Lan),
        addr_hint: Some("192.0.2.10:8091".to_string()),
        fingerprint: Some("fp-neutral".to_string()),
        owner_event_cursor: Some(7),
        cached_join_request: Some(ByteBuf::from(join_request_bytes.to_vec())),
        cached_response: None,
        anchor_secret: None,
        pinned_hh_pub: None,
        pinned_hh_id: None,
        approval_claim: None,
        lifecycle_generation: None,
    }
}

#[test]
fn owner_approval_policy_is_per_operation_and_default_off() {
    let policy = OwnerApprovalEnforcementPolicy::default();
    assert_eq!(
        policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::NeverEnrolled),
        PairMachineApprovalBodyMode::LegacyV1
    );
    assert_eq!(
        policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::Active { count: 1 }),
        PairMachineApprovalBodyMode::LegacyV1
    );
    assert_eq!(
        policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::RecoveryRequired),
        PairMachineApprovalBodyMode::LegacyV1
    );
    assert_eq!(
        policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::AnchorInvalid),
        PairMachineApprovalBodyMode::LegacyV1
    );
    assert_eq!(
        policy.bootstrap_initialize,
        OwnerOperationEnforcement::LegacyOnly
    );
    assert_eq!(
        policy.bootstrap_teardown,
        OwnerOperationEnforcement::LegacyOnly
    );
    assert_eq!(
        policy.pair_device_confirm,
        OwnerOperationEnforcement::LegacyOnly
    );
    assert_eq!(
        policy.revoke_credential,
        OwnerOperationEnforcement::LegacyOnly
    );
    assert_eq!(policy.recovery_code, RecoveryCodeEnforcement::Disabled);
    assert_eq!(policy.add_credential, OwnerOperationEnforcement::LegacyOnly);
}

#[test]
fn owner_auth_v2_rollout_absent_and_rollback_values_are_legacy_only() {
    for value in [
        None,
        Some(""),
        Some("off"),
        Some("legacy"),
        Some("legacy-only"),
    ] {
        assert_eq!(
            owner_approval_policy_from_rollout_value(value),
            OwnerApprovalEnforcementPolicy::default()
        );
    }
}

#[test]
fn owner_auth_v2_rollout_reviewed_core_enables_only_reviewed_operations() {
    let policy =
        owner_approval_policy_from_rollout_value(Some(OWNER_AUTH_V2_REVIEWED_CORE_ROLLOUT));

    assert_eq!(
        policy.pair_machine_approve,
        OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential
    );
    assert_eq!(
        policy.revoke_credential,
        OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential
    );
    assert_eq!(
        policy.recovery_code,
        RecoveryCodeEnforcement::BreakGlassEnabled,
        "recovery uses the break-glass policy switch, not an active-count gate"
    );
    assert_eq!(
        policy.add_credential,
        OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential
    );
    assert_eq!(
        policy.bootstrap_initialize,
        OwnerOperationEnforcement::LegacyOnly
    );
    assert_eq!(
        policy.bootstrap_teardown,
        OwnerOperationEnforcement::LegacyOnly
    );
    assert_eq!(
        policy.pair_device_confirm,
        OwnerOperationEnforcement::LegacyOnly
    );
}

#[test]
fn owner_auth_v2_rollout_unknown_value_fails_closed() {
    assert_eq!(
        owner_approval_policy_from_rollout_value(Some("1")),
        OwnerApprovalEnforcementPolicy::default()
    );
    assert_eq!(
        owner_approval_policy_from_rollout_value(Some("reviewed-core-v2 ")),
        OwnerApprovalEnforcementPolicy::reviewed_core_v2_rollout(),
        "operator whitespace should not disable an otherwise explicit value"
    );
}

#[test]
fn pair_machine_v2_policy_requires_active_owner_passkey_before_requiring_v2() {
    let policy = OwnerApprovalEnforcementPolicy::default()
        .with_pair_machine_approve(OwnerOperationEnforcement::V2WhenOwnerHasActiveCredential);

    assert_eq!(
        policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::NeverEnrolled),
        PairMachineApprovalBodyMode::LegacyV1,
        "owners who never enrolled passkeys keep the legacy path during migration"
    );
    assert_eq!(
        policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::Active { count: 1 }),
        PairMachineApprovalBodyMode::RequireV2
    );
    assert_eq!(
        policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::RecoveryRequired),
        PairMachineApprovalBodyMode::RejectFailClosed,
        "zero active credentials after prior enrollment must not downgrade to legacy"
    );
    assert_eq!(
        policy.pair_machine_approval_body_mode(OwnerWebauthnTrustState::AnchorInvalid),
        PairMachineApprovalBodyMode::RejectFailClosed,
        "anchor failures must not downgrade to legacy"
    );
}

#[test]
fn pair_machine_reassertion_accepts_unchanged_live_window() {
    let join_request_bytes = b"neutral canonical join request";
    let context = approval_context(join_request_bytes);
    let snapshot = live_snapshot(join_request_bytes);

    reassert_pair_machine_approval_context_against_live_window(&context, &snapshot).unwrap();
}

#[test]
fn pair_machine_reassertion_rejects_window_changed_after_approval() {
    let join_request_bytes = b"neutral canonical join request";
    let context = approval_context(join_request_bytes);
    let mut snapshot = live_snapshot(join_request_bytes);
    snapshot.cached_join_request = Some(ByteBuf::from(b"mutated join request".to_vec()));

    let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
        .unwrap_err();
    assert!(matches!(
        err,
        OwnerApprovalV2Error::TrustedState("live join request changed")
    ));
}

#[test]
fn pair_machine_reassertion_rejects_cursor_or_state_change_after_approval() {
    let join_request_bytes = b"neutral canonical join request";
    let context = approval_context(join_request_bytes);
    let mut snapshot = live_snapshot(join_request_bytes);
    snapshot.owner_event_cursor = Some(8);

    let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
        .unwrap_err();
    assert!(matches!(
        err,
        OwnerApprovalV2Error::TrustedState("live window cursor changed")
    ));

    let mut snapshot = live_snapshot(join_request_bytes);
    snapshot.state = PairMachineState::Committed;
    let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
        .unwrap_err();
    assert!(matches!(
        err,
        OwnerApprovalV2Error::TrustedState("live window cursor changed")
    ));
}

#[test]
fn pair_machine_reassertion_rejects_claimed_window() {
    let join_request_bytes = b"neutral canonical join request";
    let context = approval_context(join_request_bytes);
    let mut snapshot = live_snapshot(join_request_bytes);
    snapshot.approval_claim = Some(PairMachineApprovalClaim {
        claim_id: ByteBuf::from(vec![0xA5; 32]),
        owner_event_cursor: 7,
        claimed_at: 1_700,
    });

    let err = reassert_pair_machine_approval_context_against_live_window(&context, &snapshot)
        .unwrap_err();
    assert!(matches!(
        err,
        OwnerApprovalV2Error::TrustedState("live window already claimed")
    ));
}
