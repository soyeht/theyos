//! Executable invariants converted from the D-4 v10/v11 terminal sweeps.
//! Each test name maps directly to a named blocker from
//! `kiana-d4-v10-closed-sweep.953cc64d…` / `kiana-d4-v11-terminal-sweep.c738e02c…`.

use mesh_session_control_model_rs::gc::gc_worker_tick;
use mesh_session_control_model_rs::locks::{LockEvent, MeshSignerLocks, OrderSpy};
use mesh_session_control_model_rs::record::*;
use mesh_session_control_model_rs::secret_backend::{FakeSecretBackend, SecretBackend};
use mesh_session_control_model_rs::store::{
    AtomicControlRecordStore, FaultInjectingStore, FileBackedStore, LoadOutcome, ReplaceOutcome,
};
use mesh_session_control_model_rs::transition::{
    RecordTransition, TransitionError, apply, new_pending_intent,
};
use std::num::NonZeroU64;
use std::sync::Arc;

fn identity() -> ControlIdentity {
    ControlIdentity {
        hh_id: "hh_test".into(),
        machine_id: "m_test".into(),
        channel: Channel::Dev,
    }
}

fn slot(generation: NonZeroU64, txn_id: [u8; 16]) -> SlotId {
    SlotId {
        identity_digest: [7u8; 32],
        purpose: PurposeId::MeshSession,
        generation,
        txn_id,
        backend_instance: BackendKind::File,
    }
}

fn binding(slot: SlotId) -> ExactBinding {
    ExactBinding {
        slot,
        public_key: vec![1, 2, 3],
        attributes: vec![],
    }
}

fn delegation(not_before: u64, not_after: u64) -> Delegation {
    Delegation {
        domain: "soyeht/mesh-session/v1".into(),
        profile: "mesh-session".into(),
        role: "initiator".into(),
        channel: Channel::Dev,
        hh_id: "hh_test".into(),
        delegator_m_id: "m_test".into(),
        delegator_cert_fingerprint: [9u8; 32],
        delegated_key_id: "k".into(),
        delegated_pub: vec![1, 2, 3],
        not_before,
        not_after,
        sig: vec![0xAA],
    }
}

// ── CAS revision ────────────────────────────────────────────────────────

#[test]
fn revision_increments_on_semantic_mutation() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let pending = new_pending_intent(
        &old,
        PendingOpKind::Create,
        slot(NonZeroU64::new(1).unwrap(), [1; 16]),
        [1; 16],
    )
    .unwrap();
    let new = apply(&old, &RecordTransition::IntentRecorded { pending }, 1000).unwrap();
    assert_eq!(new.revision, old.revision + 1);
}

#[test]
fn stabilization_rewrite_never_bumps_revision() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let new = apply(&old, &RecordTransition::StabilizationRewrite, 1000).unwrap();
    assert_eq!(new.revision, old.revision);
    assert_eq!(new, old);
}

#[test]
fn store_cas_rejects_stale_revision() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileBackedStore::new(dir.path().join("record"));
    let bootstrapped = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    assert_eq!(
        store.replace_exact(INITIAL_REVISION, &bootstrapped),
        ReplaceOutcome::Committed
    );

    // Writer A: reads revision 0, applies a real semantic transition
    // (bumping to revision 1), and commits.
    let s = slot(NonZeroU64::new(1).unwrap(), [42; 16]);
    let pending_a = new_pending_intent(&bootstrapped, PendingOpKind::Create, s, [42; 16]).unwrap();
    let writer_a_next = apply(
        &bootstrapped,
        &RecordTransition::IntentRecorded { pending: pending_a },
        1000,
    )
    .unwrap();
    assert_eq!(writer_a_next.revision, 1);
    assert_eq!(
        store.replace_exact(bootstrapped.revision, &writer_a_next),
        ReplaceOutcome::Committed
    );

    // Writer B: read the SAME original revision 0 before A committed, and
    // only now attempts its own (now-stale) transition against revision 0.
    let s2 = slot(NonZeroU64::new(1).unwrap(), [43; 16]);
    let pending_b = new_pending_intent(&bootstrapped, PendingOpKind::Create, s2, [43; 16]).unwrap();
    let writer_b_next = apply(
        &bootstrapped,
        &RecordTransition::IntentRecorded { pending: pending_b },
        1000,
    )
    .unwrap();
    assert_eq!(
        store.replace_exact(bootstrapped.revision, &writer_b_next),
        ReplaceOutcome::KnownNoEffect,
        "writer B's stale revision-0 CAS must be rejected once writer A already advanced the record to revision 1"
    );
    // Disk must still reflect writer A's content, not a torn mix of both.
    let LoadOutcome::Exact(on_disk) = store.load_canonical() else {
        panic!("expected record")
    };
    assert_eq!(*on_disk, writer_a_next);
}

// ── Typed transitions: exact pending match / late worker ───────────────

#[test]
fn activate_rejects_intent_phase_pending() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let pending = new_pending_intent(
        &old,
        PendingOpKind::Create,
        slot(NonZeroU64::new(1).unwrap(), [1; 16]),
        [1; 16],
    )
    .unwrap();
    let with_intent = apply(&old, &RecordTransition::IntentRecorded { pending }, 1000).unwrap();

    let err = apply(
        &with_intent,
        &RecordTransition::ActivateFromKeyObserved {
            delegation: delegation(0, 100),
            terminal: TerminalResult {
                txn_id: [1; 16],
                outcome: TerminalOutcome::Activated {
                    generation: NonZeroU64::new(1).unwrap(),
                },
                recorded_at: 1000,
            },
        },
        1000,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::WrongPhase);
}

#[test]
fn late_worker_cannot_activate_after_urgent_revoke_preempted_it() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let s = slot(NonZeroU64::new(1).unwrap(), [2; 16]);
    let pending = new_pending_intent(&old, PendingOpKind::Create, s.clone(), [2; 16]).unwrap();
    let with_intent = apply(&old, &RecordTransition::IntentRecorded { pending }, 1000).unwrap();
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            binding: binding(s),
        },
        1000,
    )
    .unwrap();

    // Coordination bumps epoch and preempts the pending into GC while the
    // "old" worker is still mid-flight holding `with_binding` as its view.
    let revoked = apply(
        &with_binding,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
        },
        1000,
    )
    .unwrap();
    assert!(revoked.pending_op.is_none());
    assert_eq!(revoked.gc_pending.len(), 1);

    // The late worker now tries to activate against the CURRENT (post-revoke)
    // record — this is what a real caller does after `replace_exact` tells it
    // its `expected_revision` no longer matches and it re-reads.
    let err = apply(
        &revoked,
        &RecordTransition::ActivateFromKeyObserved {
            delegation: delegation(0, 100),
            terminal: TerminalResult {
                txn_id: [2; 16],
                outcome: TerminalOutcome::Activated {
                    generation: NonZeroU64::new(1).unwrap(),
                },
                recorded_at: 1000,
            },
        },
        1000,
    )
    .unwrap_err();
    assert_eq!(
        err,
        TransitionError::NoPendingOp,
        "a late worker must never activate a preempted pending"
    );
}

// ── Pending Intent preemptable without fabricating a binding ───────────

#[test]
fn revoke_of_intent_phase_pending_never_fabricates_a_binding() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let s = slot(NonZeroU64::new(1).unwrap(), [3; 16]);
    let pending = new_pending_intent(&old, PendingOpKind::Create, s, [3; 16]).unwrap();
    let with_intent = apply(&old, &RecordTransition::IntentRecorded { pending }, 1000).unwrap();
    assert!(with_intent.pending_op.as_ref().unwrap().binding.is_none());

    let revoked = apply(
        &with_intent,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Lost,
        },
        1000,
    )
    .unwrap();
    assert_eq!(revoked.gc_pending.len(), 1);
    match &revoked.gc_pending[0] {
        GcEntry::AwaitingInspection { .. } => {}
        GcEntry::Bound { .. } => {
            panic!("Intent-phase revoke must never produce a Bound entry with a fabricated binding")
        }
    }
}

#[test]
fn revoke_of_key_observed_pending_carries_the_real_binding() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let s = slot(NonZeroU64::new(1).unwrap(), [4; 16]);
    let pending = new_pending_intent(&old, PendingOpKind::Create, s.clone(), [4; 16]).unwrap();
    let with_intent = apply(&old, &RecordTransition::IntentRecorded { pending }, 1000).unwrap();
    let b = binding(s);
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved { binding: b.clone() },
        1000,
    )
    .unwrap();

    let revoked = apply(
        &with_binding,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::OwnerAction,
        },
        1000,
    )
    .unwrap();
    match &revoked.gc_pending[0] {
        GcEntry::Bound { binding: gb, .. } => assert_eq!(*gb, b),
        GcEntry::AwaitingInspection { .. } => {
            panic!("KeyObserved revoke must carry the real observed binding")
        }
    }
}

// ── Cap is structurally neutral across RevokeUrgent ─────────────────────

#[test]
fn revoke_urgent_never_increases_cap_occupancy() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let s = slot(NonZeroU64::new(1).unwrap(), [5; 16]);
    let pending = new_pending_intent(&old, PendingOpKind::Create, s, [5; 16]).unwrap();
    let with_intent = apply(&old, &RecordTransition::IntentRecorded { pending }, 1000).unwrap();
    let before = with_intent.cap_occupancy();

    let revoked = apply(
        &with_intent,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
        },
        1000,
    )
    .unwrap();
    assert!(
        revoked.cap_occupancy() <= before,
        "cap_occupancy must never increase across RevokeUrgent: before={before}, after={}",
        revoked.cap_occupancy()
    );
}

#[test]
fn revoke_urgent_with_no_pending_adds_nothing() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let before = old.cap_occupancy();
    let revoked = apply(
        &old,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
        },
        1000,
    )
    .unwrap();
    assert_eq!(revoked.cap_occupancy(), before);
    assert!(revoked.gc_pending.is_empty());
}

// ── High-water / retained-generation-content invariants ────────────────

#[test]
fn generation_high_water_never_decreases_across_activation() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let s = slot(NonZeroU64::new(1).unwrap(), [6; 16]);
    let pending = new_pending_intent(&old, PendingOpKind::Create, s.clone(), [6; 16]).unwrap();
    let with_intent = apply(&old, &RecordTransition::IntentRecorded { pending }, 1000).unwrap();
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            binding: binding(s),
        },
        1000,
    )
    .unwrap();
    let active = apply(
        &with_binding,
        &RecordTransition::ActivateFromKeyObserved {
            delegation: delegation(0, 100),
            terminal: TerminalResult {
                txn_id: [6; 16],
                outcome: TerminalOutcome::Activated {
                    generation: NonZeroU64::new(1).unwrap(),
                },
                recorded_at: 1000,
            },
        },
        1000,
    )
    .unwrap();
    assert!(active.generation_high_water >= old.generation_high_water);
    assert_eq!(active.current_generation, Some(NonZeroU64::new(1).unwrap()));
    assert_eq!(active.authority, Authority::Active);
}

// ── Terminal results: bounded + idempotent ──────────────────────────────

#[test]
fn terminal_results_are_bounded_and_idempotent_by_txn_id() {
    let mut v: Vec<TerminalResult> = Vec::new();
    for i in 0..(MAX_RECENT_TERMINAL_RESULTS as u8 + 5) {
        v = push_bounded_terminal(
            v,
            TerminalResult {
                txn_id: [i; 16],
                outcome: TerminalOutcome::Reactivated {
                    epoch: NonZeroU64::new(1).unwrap(),
                },
                recorded_at: i as u64,
            },
        );
    }
    assert_eq!(v.len(), MAX_RECENT_TERMINAL_RESULTS);

    // Re-recording an existing txn_id must not grow the list (lost-ack
    // recovery re-derives the same terminal result).
    let same_txn = v.last().unwrap().txn_id;
    let before = v.len();
    v = push_bounded_terminal(
        v,
        TerminalResult {
            txn_id: same_txn,
            outcome: TerminalOutcome::Reactivated {
                epoch: NonZeroU64::new(2).unwrap(),
            },
            recorded_at: 999,
        },
    );
    assert_eq!(v.len(), before);
}

// ── Reactivate: epoch strictly increases, requires Revoked ──────────────

#[test]
fn reactivate_requires_revoked_authority() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let s = slot(NonZeroU64::new(2).unwrap(), [7; 16]);
    let pending = new_pending_intent(&old, PendingOpKind::Reactivate, s, [7; 16]).unwrap();
    let err = apply(
        &old,
        &RecordTransition::ReactivateFromRevoked {
            new_pending: pending,
        },
        1000,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::NotRevoked);
}

#[test]
fn reactivate_strictly_increases_epoch_high_water() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let revoked = apply(
        &old,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
        },
        1000,
    )
    .unwrap();
    let epoch_after_revoke = revoked.epoch_high_water;
    let s = slot(NonZeroU64::new(1).unwrap(), [8; 16]);
    let pending = new_pending_intent(&revoked, PendingOpKind::Reactivate, s, [8; 16]).unwrap();
    let reactivated = apply(
        &revoked,
        &RecordTransition::ReactivateFromRevoked {
            new_pending: pending,
        },
        1000,
    )
    .unwrap();
    assert!(reactivated.epoch_high_water > epoch_after_revoke);
}

// ── Failpoints: KnownNoEffect / MayHaveTakenEffect / Committed ──────────

#[test]
fn failpoint_may_have_taken_effect_still_recoverable_by_reread() {
    let dir = tempfile::tempdir().unwrap();
    let store = FaultInjectingStore::new(dir.path().join("record"));
    let rec = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);

    store.force_next_outcome(ReplaceOutcome::MayHaveTakenEffect);
    let outcome = store.replace_exact(INITIAL_REVISION, &rec);
    assert_eq!(outcome, ReplaceOutcome::MayHaveTakenEffect);

    // Recovery discipline: never trust the pessimistic outcome alone — reread.
    match store.load_canonical() {
        LoadOutcome::Exact(r) => assert_eq!(
            *r, rec,
            "the write actually landed; reread must prove it, not the Err alone"
        ),
        other => panic!("expected the write to have landed on disk, got {other:?}"),
    }
}

#[test]
fn failpoint_known_no_effect_leaves_store_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let store = FaultInjectingStore::new(dir.path().join("record"));
    let rec = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);

    store.force_next_outcome(ReplaceOutcome::KnownNoEffect);
    let outcome = store.replace_exact(INITIAL_REVISION, &rec);
    assert_eq!(outcome, ReplaceOutcome::KnownNoEffect);
    assert_eq!(
        store.load_canonical(),
        LoadOutcome::Missing,
        "KnownNoEffect must mean truly nothing happened"
    );
}

#[test]
fn orphan_tmp_is_swept_without_blocking_future_attempts() {
    let dir = tempfile::tempdir().unwrap();
    let record_path = dir.path().join("record");
    std::fs::write(
        record_path.with_file_name("record.tmp.deadbeefdeadbeef"),
        b"orphan",
    )
    .unwrap();
    let store = FileBackedStore::new(record_path.clone());
    store.sweep_orphan_tmp();
    assert!(
        !record_path
            .with_file_name("record.tmp.deadbeefdeadbeef")
            .exists(),
        "orphan tmp from a crashed prior attempt must be removed"
    );
    // A fresh attempt is unaffected either way, since every attempt uses a
    // unique nonce — this assertion is the regression guard for that design
    // choice, not just the sweep.
    let rec = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    assert_eq!(
        store.replace_exact(INITIAL_REVISION, &rec),
        ReplaceOutcome::Committed
    );
}

// ── Lock ordering: turnstile held until access is actually granted ─────

#[test]
fn turnstile_is_released_only_after_access_is_acquired_shared() {
    let spy = Arc::new(OrderSpy::new());
    let locks = MeshSignerLocks::new(Arc::clone(&spy));
    {
        let _g = locks.acquire_for_sign();
        let events = spy.events();
        assert_eq!(
            events,
            vec![
                LockEvent::TurnstileAcquire,
                LockEvent::AccessAcquireShared,
                LockEvent::TurnstileRelease
            ],
            "turnstile must be released strictly after access is granted, never before acquiring it"
        );
    }
    assert_eq!(spy.events().last(), Some(&LockEvent::AccessRelease));
}

#[test]
fn turnstile_is_released_only_after_access_is_acquired_exclusive() {
    let spy = Arc::new(OrderSpy::new());
    let locks = MeshSignerLocks::new(Arc::clone(&spy));
    {
        let _g = locks.acquire_for_mutation();
        let events = spy.events();
        assert_eq!(
            events,
            vec![
                LockEvent::TurnstileAcquire,
                LockEvent::AccessAcquireExclusive,
                LockEvent::TurnstileRelease
            ]
        );
    }
}

// ── GC: plural, resumable, no permanent "stuck" state ───────────────────

fn record_with_gc_entries(entries: Vec<GcEntry>) -> MeshSignerControlRecordV1 {
    let mut r = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    r.gc_pending = entries;
    r
}

#[test]
fn gc_resolves_awaiting_inspection_to_done_when_backend_has_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileBackedStore::new(dir.path().join("record"));
    let s = slot(NonZeroU64::new(1).unwrap(), [9; 16]);
    let rec = record_with_gc_entries(vec![GcEntry::AwaitingInspection {
        slot: s,
        txn_id: [9; 16],
    }]);
    store.replace_exact(INITIAL_REVISION, &rec);

    let backend = FakeSecretBackend::new(); // deliberately empty
    let spy = Arc::new(OrderSpy::new());
    let locks = MeshSignerLocks::new(spy);
    let resolved = gc_worker_tick(&store, &backend, &locks, 1000).unwrap();
    assert_eq!(resolved, 1);
    let LoadOutcome::Exact(r) = store.load_canonical() else {
        panic!("expected record")
    };
    match &r.gc_pending[0] {
        GcEntry::Bound { state, .. } => assert_eq!(*state, GcState::Done),
        GcEntry::AwaitingInspection { .. } => {
            panic!("must resolve when nothing exists at the slot")
        }
    }
}

/// This is a transition-level test, not a full `gc_worker_tick` run:
/// `gc_worker_tick` legitimately drains an entry through every phase it can
/// reach in one call (inspect *and* the subsequent destroy attempt), so an
/// end-to-end tick against the always-succeeds `FakeSecretBackend` reaches
/// `Done` in a single call — that is correct, not a bug. What this test
/// isolates is the `GcInspected` transition itself: observing a real item
/// must move `AwaitingInspection` to `Bound { state: Pending }`, never
/// straight to `Done` without a destroy attempt ever having been recorded.
#[test]
fn gc_inspected_transition_moves_awaiting_inspection_to_bound_pending() {
    let s = slot(NonZeroU64::new(1).unwrap(), [10; 16]);
    let b = binding(s.clone());
    let old = record_with_gc_entries(vec![GcEntry::AwaitingInspection {
        slot: s.clone(),
        txn_id: [10; 16],
    }]);
    let new = apply(
        &old,
        &RecordTransition::GcInspected {
            slot_id: s.canonical_id(),
            found: Some(b.clone()),
        },
        1000,
    )
    .unwrap();
    match &new.gc_pending[0] {
        GcEntry::Bound {
            state, binding: gb, ..
        } => {
            assert_eq!(
                *state,
                GcState::Pending,
                "must not skip straight to Done without a destroy attempt"
            );
            assert_eq!(*gb, b);
        }
        GcEntry::AwaitingInspection { .. } => {
            panic!("must move to Bound once a real item is observed")
        }
    }
}

/// End-to-end: one `gc_worker_tick` call against a real item correctly
/// drains all the way to `Done`, proving plurality-within-a-tick works
/// across phase boundaries, not just across independent entries.
#[test]
fn gc_worker_tick_drains_inspect_and_destroy_in_one_call() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileBackedStore::new(dir.path().join("record"));
    let s = slot(NonZeroU64::new(1).unwrap(), [10; 16]);
    let sid = s.canonical_id();
    let rec = record_with_gc_entries(vec![GcEntry::AwaitingInspection {
        slot: s.clone(),
        txn_id: [10; 16],
    }]);
    store.replace_exact(INITIAL_REVISION, &rec);

    let backend = FakeSecretBackend::new();
    backend.create_or_inspect(&sid, None); // seed a real item at that slot

    let spy = Arc::new(OrderSpy::new());
    let locks = MeshSignerLocks::new(spy);
    let resolved = gc_worker_tick(&store, &backend, &locks, 1000).unwrap();
    assert_eq!(
        resolved, 2,
        "one commit for GcInspected, one for GcResolved"
    );
    let LoadOutcome::Exact(r) = store.load_canonical() else {
        panic!("expected record")
    };
    match &r.gc_pending[0] {
        GcEntry::Bound { state, .. } => assert_eq!(*state, GcState::Done),
        GcEntry::AwaitingInspection { .. } => panic!("must have progressed"),
    }
}

#[test]
fn gc_is_plural_resolves_multiple_independent_entries_in_one_tick() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileBackedStore::new(dir.path().join("record"));
    let s1 = slot(NonZeroU64::new(1).unwrap(), [11; 16]);
    let s2 = slot(NonZeroU64::new(2).unwrap(), [12; 16]);
    let rec = record_with_gc_entries(vec![
        GcEntry::AwaitingInspection {
            slot: s1,
            txn_id: [11; 16],
        },
        GcEntry::AwaitingInspection {
            slot: s2,
            txn_id: [12; 16],
        },
    ]);
    store.replace_exact(INITIAL_REVISION, &rec);

    let backend = FakeSecretBackend::new();
    let spy = Arc::new(OrderSpy::new());
    let locks = MeshSignerLocks::new(spy);
    let resolved = gc_worker_tick(&store, &backend, &locks, 1000).unwrap();
    assert_eq!(
        resolved, 2,
        "one tick must drain every independently-resolvable entry, not just the first"
    );
    let LoadOutcome::Exact(r) = store.load_canonical() else {
        panic!("expected record")
    };
    assert!(
        r.gc_pending
            .iter()
            .all(GcEntry::observation_complete_and_residual_zero)
    );
}

#[test]
fn gc_reprocesses_a_pending_bound_entry_next_tick_never_stuck() {
    // Simulates: a prior tick moved this entry to Bound{Pending} (attempted
    // once, not yet resolved) and then the process died. There is no
    // separate "Claimed" state to skip on the next tick — this test is the
    // direct regression guard for that v10 bug.
    let dir = tempfile::tempdir().unwrap();
    let store = FileBackedStore::new(dir.path().join("record"));
    let s = slot(NonZeroU64::new(1).unwrap(), [13; 16]);
    let sid = s.canonical_id();
    let b = binding(s.clone());
    let rec = record_with_gc_entries(vec![GcEntry::Bound {
        slot: s,
        txn_id: [13; 16],
        binding: b.clone(),
        state: GcState::Pending,
    }]);
    store.replace_exact(INITIAL_REVISION, &rec);

    let backend = FakeSecretBackend::new();
    backend.create_or_inspect(&sid, Some(&b)); // physical item still exists

    let spy = Arc::new(OrderSpy::new());
    let locks = MeshSignerLocks::new(spy);
    let resolved = gc_worker_tick(&store, &backend, &locks, 1000).unwrap();
    assert_eq!(
        resolved, 1,
        "a Pending entry from a crashed prior tick must be retried, not skipped forever"
    );
    let LoadOutcome::Exact(r) = store.load_canonical() else {
        panic!("expected record")
    };
    match &r.gc_pending[0] {
        GcEntry::Bound { state, .. } => assert_eq!(*state, GcState::Done),
        GcEntry::AwaitingInspection { .. } => unreachable!(),
    }
}

// ── Secret backend opacity: create_or_inspect never overwrites ─────────

#[test]
fn create_or_inspect_second_call_is_idempotent_never_overwrites() {
    let backend = FakeSecretBackend::new();
    let first = backend.create_or_inspect("slot-a", None);
    let second = backend.create_or_inspect("slot-a", None);
    use mesh_session_control_model_rs::secret_backend::{CreateOutcome, CreatedOrExisting};
    let CreateOutcome::Unique {
        created_or_existing: CreatedOrExisting::Created,
        binding: b1,
    } = first
    else {
        panic!("first call must create")
    };
    let CreateOutcome::Unique {
        created_or_existing: CreatedOrExisting::Existing,
        binding: b2,
    } = second
    else {
        panic!("second call on the same slot must report Existing, never generate new material")
    };
    assert_eq!(
        b1, b2,
        "idempotent recovery must observe the SAME physical key both times"
    );
}

#[test]
fn create_or_inspect_reports_conflict_on_mismatched_expectation() {
    let backend = FakeSecretBackend::new();
    let real = backend.create_or_inspect("slot-b", None);
    use mesh_session_control_model_rs::secret_backend::CreateOutcome;
    let CreateOutcome::Unique {
        binding: real_binding,
        ..
    } = real
    else {
        panic!()
    };
    let mut wrong = real_binding.clone();
    wrong.public_key = vec![0xFF, 0xFF];
    let outcome = backend.create_or_inspect("slot-b", Some(&wrong));
    assert_eq!(outcome, CreateOutcome::Conflict);
}
