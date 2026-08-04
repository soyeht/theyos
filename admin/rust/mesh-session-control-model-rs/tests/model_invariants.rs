//! Executable invariants for the D-4 single-record control model.
//! Successor to the generation audited at commit `d4ecb658` (NO-GO across
//! five rounds of CFX). Each section maps to a named finding from that
//! audit; comments cite the finding inline where the test exists
//! specifically because of it.

use mesh_session_control_model_rs::activate::{
    ActivateError, activate_from_key_observed, revalidate_on_load,
};
use mesh_session_control_model_rs::cell::{self, ControlRecordCell};
use mesh_session_control_model_rs::commit::commit_new_bytes;
use mesh_session_control_model_rs::gc::{gc_removal_pass, gc_worker_tick};
use mesh_session_control_model_rs::locks::{GcSerialLock, LockEvent, MeshSignerLocks, OrderSpy};
use mesh_session_control_model_rs::record::*;
use mesh_session_control_model_rs::secret_backend::{
    CreateOutcome, CreatedOrExisting, FakeSecretBackend, GcReport, InspectOutcome,
    LoadExactOutcome, SecretBackend,
};
use mesh_session_control_model_rs::store::{
    AtomicControlRecordStore, FaultInjectingStore, LoadOutcome, ReplaceOutcome,
};
use mesh_session_control_model_rs::transition::{RecordTransition, TransitionError, apply};
use mesh_session_control_model_rs::validator::{
    BindingContext, DelegationPolicy, MeshSessionPurpose, RosterCurrency, RosterLookup,
    RosterSyncPurpose, SignatureVerifier, ValidationError, validate_full_binding,
};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

const TEST_CAP: usize = 8;

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
        version: 1,
        kind: "soyeht/mesh-session/delegation/v1".into(),
        domain: "soyeht/mesh-session/v1".into(),
        profile: "mesh-session".into(),
        roles: vec!["initiator".into()],
        transcript_kinds: vec![
            "final-confirm".into(),
            "activate".into(),
            "activate-ack".into(),
        ],
        channel: Channel::Dev,
        hh_id: "hh_test".into(),
        delegator_m_id: "m_test".into(),
        delegator_cert_fingerprint: [9u8; 32],
        delegated_key_id: "k".into(),
        delegated_pub: vec![1, 2, 3],
        serial: 1,
        not_before,
        not_after,
        sig: vec![0xAA],
    }
}

fn test_cell(path: std::path::PathBuf) -> Arc<ControlRecordCell> {
    cell::open(
        path,
        identity(),
        PurposeId::MeshSession,
        Arc::new(OrderSpy::new()),
    )
}

// `revision: 1` -- the store's genesis check now only accepts the exact
// canonical bootstrap shape (finding 2), so a GC-populated fixture is never
// itself a legitimate genesis write. `seed_record` below always lands the
// real canonical bootstrap first, then this as a one-step mutation on top.
fn record_with_gc_entries(entries: Vec<GcEntry>) -> MeshSignerControlRecordV1 {
    let mut r = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    r.gc_pending = entries;
    r.revision = 1;
    r
}

/// Writes the canonical bootstrap genesis, then `seeded` as the one
/// mutation on top of it -- the only way to get an arbitrary fixture state
/// onto disk now that genesis is restricted to the exact canonical shape.
fn seed_record(
    store: &dyn AtomicControlRecordStore,
    locks: &MeshSignerLocks,
    seeded: &MeshSignerControlRecordV1,
) {
    let bootstrap = MeshSignerControlRecordV1::bootstrap(seeded.identity.clone(), seeded.purpose);
    let g = locks.acquire_for_mutation();
    assert_eq!(
        store.replace_exact(&g, INITIAL_REVISION, &bootstrap),
        ReplaceOutcome::Committed
    );
    assert_eq!(
        store.replace_exact(&g, bootstrap.revision, seeded),
        ReplaceOutcome::Committed
    );
}

struct AlwaysTrueVerifier;
impl SignatureVerifier for AlwaysTrueVerifier {
    fn verify(&self, _public_key: &[u8], _delegation: &Delegation, _sig: &[u8]) -> bool {
        true
    }
}

#[derive(Default)]
struct RecordingVerifier {
    last_delegation: Mutex<Option<Delegation>>,
}
impl SignatureVerifier for RecordingVerifier {
    fn verify(&self, _public_key: &[u8], delegation: &Delegation, _sig: &[u8]) -> bool {
        *self.last_delegation.lock().unwrap() = Some(delegation.clone());
        true
    }
}

struct FixedRoster(RosterCurrency);
impl RosterLookup for FixedRoster {
    fn query_machine_currency(&self, _machine_id: &str) -> RosterCurrency {
        self.0.clone()
    }
}

fn active_roster() -> FixedRoster {
    FixedRoster(RosterCurrency::Active {
        member_pub: vec![1, 2, 3],
        member_cert_fingerprint: [9u8; 32],
    })
}

fn ctx() -> BindingContext<'static> {
    BindingContext {
        hh_id: "hh_test",
        machine_id: "m_test",
        channel: Channel::Dev,
    }
}

// ── CAS revision / real guard-enforced CAS (findings 2) ──────────────────

#[test]
fn revision_increments_on_semantic_mutation() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let new = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [1; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert_eq!(new.revision, old.revision + 1);
}

#[test]
fn stabilization_rewrite_never_bumps_revision() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let new = apply(
        &old,
        &RecordTransition::StabilizationRewrite,
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert_eq!(new.revision, old.revision);
    assert_eq!(new, old);
}

#[test]
fn store_cas_rejects_stale_revision() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let bootstrapped = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = locks.acquire_for_mutation();
        assert_eq!(
            store.replace_exact(&g, INITIAL_REVISION, &bootstrapped),
            ReplaceOutcome::Committed
        );
    }

    let writer_a_next = apply(
        &bootstrapped,
        &RecordTransition::IntentRecorded {
            txn_id: [42; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    {
        let g = locks.acquire_for_mutation();
        assert_eq!(
            store.replace_exact(&g, bootstrapped.revision, &writer_a_next),
            ReplaceOutcome::Committed
        );
    }

    // Writer B built its transition against the SAME original base, before
    // A committed, and only now attempts its own (now-stale) write.
    let writer_b_next = apply(
        &bootstrapped,
        &RecordTransition::IntentRecorded {
            txn_id: [43; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let g = locks.acquire_for_mutation();
    assert_eq!(
        store.replace_exact(&g, bootstrapped.revision, &writer_b_next),
        ReplaceOutcome::KnownNoEffect,
        "writer B's stale revision-0 CAS must be rejected once writer A already advanced to revision 1"
    );
    let LoadOutcome::Exact(on_disk) = store.load_canonical() else {
        panic!("expected record")
    };
    assert_eq!(*on_disk, writer_a_next);
}

#[test]
fn two_writers_race_a_stale_base_under_a_barrier_exactly_one_commits() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let bootstrapped = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = cell.locks().acquire_for_mutation();
        assert_eq!(
            cell.store()
                .replace_exact(&g, INITIAL_REVISION, &bootstrapped),
            ReplaceOutcome::Committed
        );
    }

    let new_a = apply(
        &bootstrapped,
        &RecordTransition::IntentRecorded {
            txn_id: [0xAA; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let new_b = apply(
        &bootstrapped,
        &RecordTransition::IntentRecorded {
            txn_id: [0xBB; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let (c1, b1) = (Arc::clone(&cell), Arc::clone(&barrier));
    let (c2, b2) = (Arc::clone(&cell), Arc::clone(&barrier));
    let base_rev = bootstrapped.revision;
    let h1 = std::thread::spawn(move || {
        b1.wait();
        let g = c1.locks().acquire_for_mutation();
        c1.store().replace_exact(&g, base_rev, &new_a)
    });
    let h2 = std::thread::spawn(move || {
        b2.wait();
        let g = c2.locks().acquire_for_mutation();
        c2.store().replace_exact(&g, base_rev, &new_b)
    });
    let o1 = h1.join().unwrap();
    let o2 = h2.join().unwrap();

    let commits = [o1, o2]
        .iter()
        .filter(|o| **o == ReplaceOutcome::Committed)
        .count();
    assert_eq!(
        commits, 1,
        "exactly one of two writers racing the same stale base must commit; got {o1:?} and {o2:?}"
    );
    assert_eq!(
        [o1, o2]
            .iter()
            .filter(|o| **o == ReplaceOutcome::KnownNoEffect)
            .count(),
        1
    );
}

#[test]
fn store_rejects_new_record_revision_not_old_plus_one() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let bootstrapped = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = locks.acquire_for_mutation();
        assert_eq!(
            store.replace_exact(&g, INITIAL_REVISION, &bootstrapped),
            ReplaceOutcome::Committed
        );
    }
    let mut forged = bootstrapped.clone();
    forged.revision = 99;
    let g = locks.acquire_for_mutation();
    assert_eq!(
        store.replace_exact(&g, INITIAL_REVISION, &forged),
        ReplaceOutcome::KnownNoEffect,
        "new_record.revision must be exactly old.revision+1 (mutation) or == old.revision with byte-identical content (stabilization) -- never trusted verbatim"
    );
}

#[test]
fn store_missing_rejects_non_canonical_first_write() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let mut forged_genesis =
        MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    forged_genesis.epoch_high_water = NonZeroU64::new(5).unwrap();
    let g = locks.acquire_for_mutation();
    assert_eq!(
        store.replace_exact(&g, INITIAL_REVISION, &forged_genesis),
        ReplaceOutcome::KnownNoEffect,
        "Missing must only accept the exact canonical bootstrap record"
    );
    assert_eq!(store.load_canonical(), LoadOutcome::Missing);
}

#[test]
fn genesis_write_is_validated_against_the_stores_own_bound_identity_not_new_records_claim() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let mut other_identity = identity();
    other_identity.hh_id = "hh_other".into();
    let forged = MeshSignerControlRecordV1::bootstrap(other_identity, PurposeId::MeshSession);
    let g = locks.acquire_for_mutation();
    assert_eq!(
        store.replace_exact(&g, INITIAL_REVISION, &forged),
        ReplaceOutcome::KnownNoEffect,
        "genesis must be checked against the store's own bound identity, never whatever new_record itself claims"
    );
}

// ── Guard binding: a MutateGuard is not interchangeable across stores ────
// ── Cell registry: at most one live (store,locks) pair per path ─────────

#[test]
fn store_rejects_a_guard_from_a_foreign_locks_instance() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    // Genuinely foreign: a MeshSignerLocks never paired with this cell's
    // store via cell::open. MeshSignerLocks::new itself stays public --
    // only FileBackedStore::new became pub(crate) -- so this is still
    // constructible, and is exactly the misuse the token must catch.
    let foreign_locks = MeshSignerLocks::new(Arc::new(OrderSpy::new()));
    let foreign_guard = foreign_locks.acquire_for_mutation();
    let rec = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cell.store()
            .replace_exact(&foreign_guard, INITIAL_REVISION, &rec)
    }));
    assert!(
        result.is_err(),
        "a MutateGuard minted by a different MeshSignerLocks must never be accepted"
    );
}

/// Successor to the removed `two_stores_aliasing_the_same_path_...` test:
/// with `FileBackedStore::new` now `pub(crate)`, external code can no
/// longer construct two independent `FileBackedStore`s over the same path
/// at all -- `cell::open` is the only way in, and it deduplicates by path.
/// This proves the dedup structurally, which is the stronger form of the
/// same guarantee the old runtime-panic test was reaching for.
#[test]
fn cell_open_reuses_the_same_pair_for_the_same_path_while_alive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let cell_a = test_cell(path.clone());
    let cell_b = test_cell(path);
    assert_eq!(
        cell_a.locks().token(),
        cell_b.locks().token(),
        "two open() calls for the same live path must return the identical pair, never two independently-consistent ones that could race"
    );
}

#[test]
fn cell_open_creates_a_fresh_pair_once_the_prior_one_is_fully_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let token_a = {
        let cell_a = test_cell(path.clone());
        cell_a.locks().token()
    }; // cell_a's only Arc dropped here
    let cell_b = test_cell(path);
    assert_ne!(
        token_a,
        cell_b.locks().token(),
        "sequential, non-overlapping reuse after a full drop is expected and safe"
    );
}

// ── Canonical CBOR: round-trip validation, not just "it parses" ─────────

#[test]
fn load_canonical_rejects_non_canonical_map_key_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let wrong_order = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("zzz".into()),
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Text("a".into()),
            ciborium::Value::Integer(2.into()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&wrong_order, &mut buf).unwrap();
    std::fs::write(&path, &buf).unwrap();

    let cell = test_cell(path);
    let store = cell.store();
    assert_eq!(store.load_canonical(), LoadOutcome::Corrupt);
}

#[test]
fn load_canonical_rejects_duplicate_map_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let dup = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("a".into()),
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Text("a".into()),
            ciborium::Value::Integer(2.into()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&dup, &mut buf).unwrap();
    std::fs::write(&path, &buf).unwrap();

    let cell = test_cell(path);
    let store = cell.store();
    assert_eq!(store.load_canonical(), LoadOutcome::Corrupt);
}

#[test]
fn load_canonical_rejects_trailing_bytes_after_a_complete_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let v = ciborium::Value::Integer(1.into());
    let mut buf = Vec::new();
    ciborium::into_writer(&v, &mut buf).unwrap();
    buf.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    std::fs::write(&path, &buf).unwrap();

    let cell = test_cell(path);
    let store = cell.store();
    assert_eq!(store.load_canonical(), LoadOutcome::Corrupt);
}

#[test]
fn load_canonical_rejects_non_minimal_integer_encoding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    // Integer 1 encoded via the 4-byte form (major 0, additional info 26)
    // instead of the canonical 1-byte inline form.
    let buf: Vec<u8> = vec![0x1a, 0x00, 0x00, 0x00, 0x01];
    std::fs::write(&path, &buf).unwrap();

    let cell = test_cell(path);
    let store = cell.store();
    assert_eq!(store.load_canonical(), LoadOutcome::Corrupt);
}

#[test]
fn store_write_then_read_round_trips_through_canonicalization() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let rec = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let g = locks.acquire_for_mutation();
    assert_eq!(
        store.replace_exact(&g, INITIAL_REVISION, &rec),
        ReplaceOutcome::Committed
    );
    let LoadOutcome::Exact(read_back) = store.load_canonical() else {
        panic!("expected record")
    };
    assert_eq!(*read_back, rec);
}

// ── MayHaveTakenEffect: durability, not just visibility (finding 3) ─────

#[test]
fn may_have_taken_effect_recovery_requires_a_real_committing_rewrite_not_a_reread() {
    let dir = tempfile::tempdir().unwrap();
    // FaultInjectingStore is test-only and never used by production call
    // paths (gc.rs/activate.rs), so it is exempt from the cell registry --
    // see cell.rs's doc comment for why the registry exists specifically
    // for FileBackedStore.
    let locks = MeshSignerLocks::new(Arc::new(OrderSpy::new()));
    let store = FaultInjectingStore::new(
        dir.path().join("record"),
        locks.token(),
        identity(),
        PurposeId::MeshSession,
    );
    let bootstrapped = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = locks.acquire_for_mutation();
        assert_eq!(
            store.replace_exact(&g, INITIAL_REVISION, &bootstrapped),
            ReplaceOutcome::Committed
        );
    }
    let mutated = apply(
        &bootstrapped,
        &RecordTransition::IntentRecorded {
            txn_id: [200; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();

    // Rename becomes visible every time (the real write always actually
    // lands), but parent fsync is "forced pessimistic" for 3 attempts in a
    // row -- a recovery that concludes from a reread the moment disk
    // visibly equals `new` would stop after attempt 1 and never prove
    // durability.
    let calls_before = store.calls();
    store.force_may_have_taken_effect_for_next_calls(3);
    let guard = locks.acquire_for_mutation();
    commit_new_bytes(&store, &guard, bootstrapped.revision, &mutated, 10)
        .expect("recovery must keep issuing real committing rewrites until one actually succeeds");

    assert_eq!(
        store.calls() - calls_before,
        4,
        "3 forced-pessimistic real writes plus the 4th that finally reports Committed -- a reread-only recovery would stop at 1 call"
    );
    let LoadOutcome::Exact(on_disk) = store.load_canonical() else {
        panic!("expected record")
    };
    assert_eq!(*on_disk, mutated);
}

#[test]
fn failpoint_known_no_effect_leaves_store_untouched() {
    let dir = tempfile::tempdir().unwrap();
    // FaultInjectingStore is test-only and never used by production call
    // paths (gc.rs/activate.rs), so it is exempt from the cell registry --
    // see cell.rs's doc comment for why the registry exists specifically
    // for FileBackedStore.
    let locks = MeshSignerLocks::new(Arc::new(OrderSpy::new()));
    let store = FaultInjectingStore::new(
        dir.path().join("record"),
        locks.token(),
        identity(),
        PurposeId::MeshSession,
    );
    let rec = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);

    store.force_next_outcome(ReplaceOutcome::KnownNoEffect);
    let g = locks.acquire_for_mutation();
    let outcome = store.replace_exact(&g, INITIAL_REVISION, &rec);
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
        record_path.with_file_name("record.tmp.00000000000000000000.deadbeefdeadbeef"),
        b"orphan",
    )
    .unwrap();
    let cell = test_cell(record_path.clone());
    let store = cell.store();
    let locks = cell.locks();
    {
        let g = locks.acquire_for_mutation();
        store.sweep_orphan_tmp(&g);
    }
    assert!(
        !record_path
            .with_file_name("record.tmp.00000000000000000000.deadbeefdeadbeef")
            .exists(),
        "an orphan tmp targeting a revision below current (there is no current record at all, so it predates this session) must be removed"
    );
    let rec = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let g = locks.acquire_for_mutation();
    assert_eq!(
        store.replace_exact(&g, INITIAL_REVISION, &rec),
        ReplaceOutcome::Committed
    );
}

// ── Typed transitions: exact token / late worker (finding 1) ────────────

#[test]
fn activate_rejects_intent_phase_pending() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [1; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();

    let err = apply(
        &with_intent,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            delegation: delegation(0, 100),
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::WrongPhase);
}

#[test]
fn late_worker_cannot_activate_after_urgent_revoke_preempted_it() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [2; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: binding(p.canonical_slot.clone()),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();

    let revoked = apply(
        &with_binding,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [0xE0; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(revoked.pending_op.is_none());
    assert_eq!(revoked.gc_pending.len(), 1);

    let p2 = with_binding.pending_op.clone().unwrap();
    let err = apply(
        &revoked,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p2.txn_id,
            expected_kind: p2.kind,
            expected_generation: p2.generation,
            expected_epoch: p2.epoch,
            expected_purpose: p2.purpose,
            expected_slot_id: p2.canonical_slot.canonical_id(),
            expected_revision: revoked.revision,
            delegation: delegation(0, 100),
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(
        err,
        TransitionError::NoPendingOp,
        "a late worker must never activate a preempted pending"
    );
}

#[test]
fn late_key_observed_rejected_after_revoke_reactivate_creates_new_pending_same_phase() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [1; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let t1 = with_intent.pending_op.clone().unwrap();

    let revoked = apply(
        &with_intent,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [0xE1; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(revoked.pending_op.is_none());

    let reactivated = apply(
        &revoked,
        &RecordTransition::ReactivateFromRevoked {
            txn_id: [0xE2; 16],
            next_txn_id: [2; 16],
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let t2 = reactivated.pending_op.clone().unwrap();
    assert_ne!(t1.txn_id, t2.txn_id);
    assert_eq!(
        t1.phase, t2.phase,
        "both Intent-phase -- the exact ambiguity a phase-only check cannot distinguish"
    );

    let err = apply(
        &reactivated,
        &RecordTransition::KeyObserved {
            expected_txn_id: t1.txn_id,
            expected_kind: t1.kind,
            expected_generation: t1.generation,
            expected_epoch: t1.epoch,
            expected_purpose: t1.purpose,
            expected_slot_id: t1.canonical_slot.canonical_id(),
            expected_revision: reactivated.revision,
            binding: binding(t1.canonical_slot.clone()),
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::StaleWorkerToken);

    let ok = apply(
        &reactivated,
        &RecordTransition::KeyObserved {
            expected_txn_id: t2.txn_id,
            expected_kind: t2.kind,
            expected_generation: t2.generation,
            expected_epoch: t2.epoch,
            expected_purpose: t2.purpose,
            expected_slot_id: t2.canonical_slot.canonical_id(),
            expected_revision: reactivated.revision,
            binding: binding(t2.canonical_slot.clone()),
        },
        1000,
        TEST_CAP,
    );
    assert!(ok.is_ok(), "T2's own correct token must be accepted");
}

#[test]
fn key_observed_rejects_wrong_expected_revision() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [5; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();
    let err = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision + 5, // wrong
            binding: binding(p.canonical_slot.clone()),
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::StaleWorkerToken);
}

#[test]
fn reactivate_never_overwrites_an_existing_pending() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let revoked = apply(
        &old,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [90; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let reactivated = apply(
        &revoked,
        &RecordTransition::ReactivateFromRevoked {
            txn_id: [91; 16],
            next_txn_id: [92; 16],
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(reactivated.pending_op.is_some());

    // Reactivate again while a pending op already exists (e.g. authority
    // somehow still reported Revoked -- exercised directly at the
    // transition level) must never silently overwrite it.
    let mut still_revoked_with_pending = reactivated.clone();
    still_revoked_with_pending.authority = Authority::Revoked {
        reason: RevocationReason::Compromised,
    };
    let err = apply(
        &still_revoked_with_pending,
        &RecordTransition::ReactivateFromRevoked {
            txn_id: [93; 16],
            next_txn_id: [94; 16],
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::PendingAlreadyExists);
}

// ── Closed Authority<->PendingOpKind matrix (round 4, item 2) ───────────

#[test]
fn intent_recorded_rejects_revoked_authority_bypassing_reactivate() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let revoked = apply(
        &old,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [200; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    // Attempt to bypass ReactivateFromRevoked (and the epoch bump it is the
    // only legitimate path to) by going straight through IntentRecorded.
    let err = apply(
        &revoked,
        &RecordTransition::IntentRecorded {
            txn_id: [201; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::InvalidIntentForAuthority);
}

#[test]
fn intent_recorded_rejects_routine_rotate_kind_on_empty_authority() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let err = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [202; 16],
            kind: PendingOpKind::RoutineRotate,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::InvalidIntentForAuthority);
}

// ── Idempotent replay of terminal transitions (round 4, item 3) ────────

#[test]
fn revoke_urgent_replay_after_commit_is_idempotent_not_double_bump() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let t = RecordTransition::RevokeUrgent {
        reason: RevocationReason::Compromised,
        txn_id: [50; 16],
    };
    let revoked = apply(&old, &t, 1000, TEST_CAP).unwrap();
    // Simulate a lost-ack retry: the caller re-reads the (already revoked)
    // record and retries the identical revoke request.
    let replay = apply(&revoked, &t, 2000, TEST_CAP).unwrap();
    assert_eq!(
        replay, revoked,
        "an idempotent replay must return the current record unchanged, never double-bump epoch"
    );
}

#[test]
fn revoke_urgent_reused_txn_id_with_different_outcome_fails_closed() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [60; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: binding(p.canonical_slot.clone()),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let activated = apply(
        &with_binding,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_binding.revision,
            delegation: delegation(0, 100),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    // txn_id [60;16] already has an Activated terminal result -- reusing it
    // for a Revoke must never be silently accepted as "the same replay."
    let err = apply(
        &activated,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [60; 16],
        },
        2000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::TerminalTxnReused);
}

#[test]
fn reactivate_replay_after_full_activation_is_idempotent() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let revoked = apply(
        &old,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [70; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let reactivate_t = RecordTransition::ReactivateFromRevoked {
        txn_id: [71; 16],
        next_txn_id: [72; 16],
        backend: BackendKind::File,
    };
    let reactivated = apply(&revoked, &reactivate_t, 1000, TEST_CAP).unwrap();
    let p = reactivated.pending_op.clone().unwrap();
    let with_binding = apply(
        &reactivated,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: reactivated.revision,
            binding: binding(p.canonical_slot.clone()),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let activated = apply(
        &with_binding,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_binding.revision,
            delegation: delegation(0, 100),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert_eq!(activated.authority, Authority::Active);

    // Lost-ack retry of the ORIGINAL ReactivateFromRevoked, now against a
    // record that has moved all the way to Active. Without idempotent
    // replay this would hit a confusing NotRevoked.
    let replay = apply(&activated, &reactivate_t, 3000, TEST_CAP).unwrap();
    assert_eq!(
        replay, activated,
        "must recognize the already-succeeded reactivate and return the current record unchanged"
    );
}

#[test]
fn activate_replay_after_commit_is_idempotent() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [80; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: binding(p.canonical_slot.clone()),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let activate_t = RecordTransition::ActivateFromKeyObserved {
        expected_txn_id: p.txn_id,
        expected_kind: p.kind,
        expected_generation: p.generation,
        expected_epoch: p.epoch,
        expected_purpose: p.purpose,
        expected_slot_id: p.canonical_slot.canonical_id(),
        expected_revision: with_binding.revision,
        delegation: delegation(0, 100),
    };
    let activated = apply(&with_binding, &activate_t, 1000, TEST_CAP).unwrap();

    // Lost-ack retry: pending_op is now None, so without idempotent replay
    // this would hit NoPendingOp.
    let replay = apply(&activated, &activate_t, 2000, TEST_CAP).unwrap();
    assert_eq!(replay, activated);
}

// ── Pending Intent preemptable without fabricating a binding ───────────

#[test]
fn revoke_of_intent_phase_pending_never_fabricates_a_binding() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [3; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(with_intent.pending_op.as_ref().unwrap().binding.is_none());

    let revoked = apply(
        &with_intent,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Lost,
            txn_id: [95; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert_eq!(revoked.gc_pending.len(), 1);
    match &revoked.gc_pending[0] {
        GcEntry::AwaitingInspection { .. } => {}
        other => panic!(
            "Intent-phase revoke must never produce a Bound entry with a fabricated binding: {other:?}"
        ),
    }
}

#[test]
fn revoke_of_key_observed_pending_carries_the_real_binding() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [4; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();
    let b = binding(p.canonical_slot.clone());
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: b.clone(),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();

    let revoked = apply(
        &with_binding,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::OwnerAction,
            txn_id: [96; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    match &revoked.gc_pending[0] {
        GcEntry::Bound { binding: gb, .. } => assert_eq!(*gb, b),
        other => panic!("KeyObserved revoke must carry the real observed binding: {other:?}"),
    }
}

// ── Cap: injected, structurally neutral across RevokeUrgent ─────────────

#[test]
fn revoke_urgent_never_increases_cap_occupancy() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [5; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let before = with_intent.cap_occupancy();

    let revoked = apply(
        &with_intent,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [97; 16],
        },
        1000,
        TEST_CAP,
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
            txn_id: [98; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert_eq!(revoked.cap_occupancy(), before);
    assert!(revoked.gc_pending.is_empty());
}

#[test]
fn intent_recorded_derives_generation_and_slot_not_caller_supplied() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [6; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.unwrap();
    assert_eq!(p.generation, NonZeroU64::new(1).unwrap());
    assert_eq!(
        p.canonical_slot.identity_digest,
        identity_digest(&identity())
    );
    assert_eq!(p.canonical_slot.purpose, PurposeId::MeshSession);
    assert_eq!(p.canonical_slot.txn_id, [6; 16]);
}

#[test]
fn intent_recorded_rejects_when_cap_exceeded() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [1; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        1,
    )
    .unwrap();
    assert_eq!(with_intent.cap_occupancy(), 1);
    let revoked = apply(
        &with_intent,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [9; 16],
        },
        1000,
        1,
    )
    .unwrap();
    assert_eq!(revoked.cap_occupancy(), 1);
    // Reactivate would add a fresh pending on top of the still-unresolved
    // GC entry -- occupancy would become 2, over cap=1.
    let err = apply(
        &revoked,
        &RecordTransition::ReactivateFromRevoked {
            txn_id: [10; 16],
            next_txn_id: [11; 16],
            backend: BackendKind::File,
        },
        1000,
        1,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::CapExceeded);
}

// ── Generation expiry: GO's missing removal path ─────────────────────────

fn rotated_record_with_two_generations(
    gen1_not_after: u64,
    gen2_not_after: u64,
) -> MeshSignerControlRecordV1 {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [20; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        0,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: binding(p.canonical_slot.clone()),
        },
        0,
        TEST_CAP,
    )
    .unwrap();
    let active = apply(
        &with_binding,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_binding.revision,
            delegation: delegation(0, gen1_not_after),
        },
        0,
        TEST_CAP,
    )
    .unwrap();

    let with_intent2 = apply(
        &active,
        &RecordTransition::IntentRecorded {
            txn_id: [21; 16],
            kind: PendingOpKind::RoutineRotate,
            backend: BackendKind::File,
        },
        0,
        TEST_CAP,
    )
    .unwrap();
    let p2 = with_intent2.pending_op.clone().unwrap();
    let with_binding2 = apply(
        &with_intent2,
        &RecordTransition::KeyObserved {
            expected_txn_id: p2.txn_id,
            expected_kind: p2.kind,
            expected_generation: p2.generation,
            expected_epoch: p2.epoch,
            expected_purpose: p2.purpose,
            expected_slot_id: p2.canonical_slot.canonical_id(),
            expected_revision: with_intent2.revision,
            binding: binding(p2.canonical_slot.clone()),
        },
        0,
        TEST_CAP,
    )
    .unwrap();
    apply(
        &with_binding2,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p2.txn_id,
            expected_kind: p2.kind,
            expected_generation: p2.generation,
            expected_epoch: p2.epoch,
            expected_purpose: p2.purpose,
            expected_slot_id: p2.canonical_slot.canonical_id(),
            expected_revision: with_binding2.revision,
            delegation: delegation(0, gen2_not_after),
        },
        0,
        TEST_CAP,
    )
    .unwrap()
}

#[test]
fn generation_expired_rejects_current_generation() {
    let rotated = rotated_record_with_two_generations(5000, 6000);
    assert_eq!(
        rotated.current_generation,
        Some(NonZeroU64::new(2).unwrap())
    );
    let err = apply(
        &rotated,
        &RecordTransition::GenerationExpired {
            generation: NonZeroU64::new(2).unwrap(),
        },
        7000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::RemovesCurrent);
}

#[test]
fn generation_expired_rejects_before_not_after() {
    let rotated = rotated_record_with_two_generations(5000, 6000);
    let err = apply(
        &rotated,
        &RecordTransition::GenerationExpired {
            generation: NonZeroU64::new(1).unwrap(),
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::GenerationNotExpired);
}

#[test]
fn generation_expired_moves_lapsed_noncurrent_generation_to_gc_and_removes_it() {
    let rotated = rotated_record_with_two_generations(5000, 6000);
    let expired = apply(
        &rotated,
        &RecordTransition::GenerationExpired {
            generation: NonZeroU64::new(1).unwrap(),
        },
        7000,
        TEST_CAP,
    )
    .unwrap();
    assert!(
        !expired
            .live_generations
            .iter()
            .any(|g| g.generation == NonZeroU64::new(1).unwrap())
    );
    assert_eq!(expired.live_generations.len(), 1);
    assert_eq!(expired.gc_pending.len(), 1);
    assert_eq!(
        expired.current_generation,
        Some(NonZeroU64::new(2).unwrap())
    );
}

// ── High-water ────────────────────────────────────────────────────────

#[test]
fn generation_high_water_never_decreases_across_activation() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [6; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: binding(p.canonical_slot.clone()),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let active = apply(
        &with_binding,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_binding.revision,
            delegation: delegation(0, 100),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(active.generation_high_water >= old.generation_high_water);
    assert_eq!(active.current_generation, Some(NonZeroU64::new(1).unwrap()));
    assert_eq!(active.authority, Authority::Active);
}

// ── Terminal results: fail-closed conflict, explicit ack/retention ──────

#[test]
fn terminal_push_is_idempotent_for_identical_outcome() {
    let r = TerminalResult {
        txn_id: [1; 16],
        outcome: TerminalOutcome::Activated {
            generation: NonZeroU64::new(1).unwrap(),
        },
        recorded_at: 10,
        acked: false,
    };
    let v = push_bounded_terminal(vec![], r).unwrap();
    let v2 = push_bounded_terminal(v.clone(), r).unwrap();
    assert_eq!(v, v2);
}

#[test]
fn terminal_push_fails_closed_on_outcome_conflict() {
    let r1 = TerminalResult {
        txn_id: [1; 16],
        outcome: TerminalOutcome::Activated {
            generation: NonZeroU64::new(1).unwrap(),
        },
        recorded_at: 10,
        acked: false,
    };
    let r2 = TerminalResult {
        txn_id: [1; 16],
        outcome: TerminalOutcome::Activated {
            generation: NonZeroU64::new(2).unwrap(),
        },
        recorded_at: 11,
        acked: false,
    };
    let v = push_bounded_terminal(vec![], r1).unwrap();
    let err = push_bounded_terminal(v, r2).unwrap_err();
    assert_eq!(err, TerminalPushError::OutcomeConflict);
}

#[test]
fn terminal_retention_exhausted_when_all_unacked() {
    let mut v = vec![];
    for i in 0..MAX_RECENT_TERMINAL_RESULTS as u8 {
        v = push_bounded_terminal(
            v,
            TerminalResult {
                txn_id: [i; 16],
                outcome: TerminalOutcome::Activated {
                    generation: NonZeroU64::new(1).unwrap(),
                },
                recorded_at: i as u64,
                acked: false,
            },
        )
        .unwrap();
    }
    assert_eq!(v.len(), MAX_RECENT_TERMINAL_RESULTS);
    let overflow = TerminalResult {
        txn_id: [200; 16],
        outcome: TerminalOutcome::Activated {
            generation: NonZeroU64::new(1).unwrap(),
        },
        recorded_at: 999,
        acked: false,
    };
    let err = push_bounded_terminal(v, overflow).unwrap_err();
    assert_eq!(
        err,
        TerminalPushError::RetentionExhausted,
        "no unacked entry may be silently evicted"
    );
}

#[test]
fn terminal_ack_makes_the_oldest_acked_entry_evictable() {
    let mut v = vec![];
    for i in 0..MAX_RECENT_TERMINAL_RESULTS as u8 {
        v = push_bounded_terminal(
            v,
            TerminalResult {
                txn_id: [i; 16],
                outcome: TerminalOutcome::Activated {
                    generation: NonZeroU64::new(1).unwrap(),
                },
                recorded_at: i as u64,
                acked: false,
            },
        )
        .unwrap();
    }
    let first_txn = v[0].txn_id;
    v = ack_terminal(v, first_txn);
    assert!(v.iter().find(|e| e.txn_id == first_txn).unwrap().acked);

    let overflow = TerminalResult {
        txn_id: [200; 16],
        outcome: TerminalOutcome::Activated {
            generation: NonZeroU64::new(1).unwrap(),
        },
        recorded_at: 999,
        acked: false,
    };
    v = push_bounded_terminal(v, overflow).unwrap();
    assert_eq!(v.len(), MAX_RECENT_TERMINAL_RESULTS);
    assert!(
        !v.iter().any(|e| e.txn_id == first_txn),
        "the acked entry, and only it, must have been evicted"
    );
}

#[test]
fn revoke_and_reactivate_each_record_their_own_terminal_result() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let revoked = apply(
        &old,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [50; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(
        revoked
            .recent_terminal_results
            .iter()
            .any(|r| r.txn_id == [50; 16] && matches!(r.outcome, TerminalOutcome::Revoked { .. }))
    );

    let reactivated = apply(
        &revoked,
        &RecordTransition::ReactivateFromRevoked {
            txn_id: [51; 16],
            next_txn_id: [52; 16],
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(
        reactivated
            .recent_terminal_results
            .iter()
            .any(|r| r.txn_id == [51; 16]
                && matches!(r.outcome, TerminalOutcome::Reactivated { .. }))
    );
    assert_ne!(
        reactivated.pending_op.as_ref().unwrap().txn_id,
        [51; 16],
        "the reactivate action's own txn_id must differ from the new pending op's, or a later Activated terminal would conflict with it"
    );
}

#[test]
fn terminal_acked_rejects_unknown_txn_id() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let err = apply(
        &old,
        &RecordTransition::TerminalAcked { txn_id: [1; 16] },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::NoSuchTerminalResult);
}

// ── Reactivate: epoch strictly increases, requires Revoked ──────────────

#[test]
fn reactivate_requires_revoked_authority() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let err = apply(
        &old,
        &RecordTransition::ReactivateFromRevoked {
            txn_id: [7; 16],
            next_txn_id: [8; 16],
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
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
            txn_id: [99; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let epoch_after_revoke = revoked.epoch_high_water;
    let reactivated = apply(
        &revoked,
        &RecordTransition::ReactivateFromRevoked {
            txn_id: [8; 16],
            next_txn_id: [9; 16],
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(reactivated.epoch_high_water > epoch_after_revoke);
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

// ── GC: absent needs two confirmations, no fabricated binding ──────────

#[test]
fn gc_first_absent_observation_moves_to_absent_unconfirmed_not_terminal() {
    let s = slot(NonZeroU64::new(1).unwrap(), [80; 16]);
    let old = record_with_gc_entries(vec![GcEntry::AwaitingInspection {
        slot: s.clone(),
        txn_id: [80; 16],
    }]);
    let new = apply(
        &old,
        &RecordTransition::GcInspected {
            slot_id: s.canonical_id(),
            found: None,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    match &new.gc_pending[0] {
        GcEntry::AbsentUnconfirmed { .. } => {}
        other => {
            panic!("expected AbsentUnconfirmed after a single absent observation, got {other:?}")
        }
    }
    assert!(!new.gc_pending[0].observation_complete_and_residual_zero());
}

#[test]
fn gc_second_absent_observation_confirms_terminal_absent() {
    let s = slot(NonZeroU64::new(1).unwrap(), [81; 16]);
    let old = record_with_gc_entries(vec![GcEntry::AbsentUnconfirmed {
        slot: s.clone(),
        txn_id: [81; 16],
    }]);
    let new = apply(
        &old,
        &RecordTransition::GcInspected {
            slot_id: s.canonical_id(),
            found: None,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    match &new.gc_pending[0] {
        GcEntry::Absent { .. } => {}
        other => {
            panic!("expected terminal Absent after a second absent observation, got {other:?}")
        }
    }
    assert!(new.gc_pending[0].observation_complete_and_residual_zero());
}

#[test]
fn gc_late_apparition_after_absent_unconfirmed_moves_to_bound_never_fabricated() {
    let s = slot(NonZeroU64::new(1).unwrap(), [82; 16]);
    let b = binding(s.clone());
    let old = record_with_gc_entries(vec![GcEntry::AbsentUnconfirmed {
        slot: s.clone(),
        txn_id: [82; 16],
    }]);
    let new = apply(
        &old,
        &RecordTransition::GcInspected {
            slot_id: s.canonical_id(),
            found: Some(b.clone()),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    match &new.gc_pending[0] {
        GcEntry::Bound {
            state, binding: gb, ..
        } => {
            assert_eq!(*state, GcState::Pending);
            assert_eq!(
                *gb, b,
                "must carry the REAL observed binding, never a fabricated placeholder"
            );
        }
        other => panic!(
            "a late apparition must move to Bound, not stay Absent or fabricate a binding: {other:?}"
        ),
    }
}

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
        TEST_CAP,
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
        other => panic!("must move to Bound once a real item is observed: {other:?}"),
    }
}

// ── GC worker: real turnstile→access, crash-resume, plurality ──────────

#[test]
fn gc_worker_requires_two_ticks_to_confirm_absent() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let s = slot(NonZeroU64::new(1).unwrap(), [83; 16]);
    let rec = record_with_gc_entries(vec![GcEntry::AwaitingInspection {
        slot: s.clone(),
        txn_id: [83; 16],
    }]);
    seed_record(store, locks, &rec);
    let backend = FakeSecretBackend::new(); // deliberately empty throughout
    let gc_serial = GcSerialLock::new();

    let resolved_1 = gc_worker_tick(store, &backend, locks, &gc_serial, 1000, TEST_CAP).unwrap();
    assert_eq!(resolved_1, 1);
    let LoadOutcome::Exact(r1) = store.load_canonical() else {
        panic!("expected record")
    };
    match &r1.gc_pending[0] {
        GcEntry::AbsentUnconfirmed { .. } => {}
        other => panic!("expected AbsentUnconfirmed after tick 1, got {other:?}"),
    }

    // Crash-resume: this second call is a completely fresh gc_worker_tick,
    // with nothing carried over except what tick 1 durably wrote.
    let resolved_2 = gc_worker_tick(store, &backend, locks, &gc_serial, 2000, TEST_CAP).unwrap();
    assert_eq!(resolved_2, 1);
    let LoadOutcome::Exact(r2) = store.load_canonical() else {
        panic!("expected record")
    };
    match &r2.gc_pending[0] {
        GcEntry::Absent { .. } => {}
        other => panic!("expected terminal Absent after tick 2, got {other:?}"),
    }
}

#[test]
fn gc_worker_tick_drains_inspect_and_destroy_in_one_call_when_found() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let s = slot(NonZeroU64::new(1).unwrap(), [10; 16]);
    let rec = record_with_gc_entries(vec![GcEntry::AwaitingInspection {
        slot: s.clone(),
        txn_id: [10; 16],
    }]);
    seed_record(store, locks, &rec);

    let backend = FakeSecretBackend::new();
    backend.create_or_inspect(&s, None); // seed a real item

    let gc_serial = GcSerialLock::new();
    let resolved = gc_worker_tick(store, &backend, locks, &gc_serial, 1000, TEST_CAP).unwrap();
    assert_eq!(
        resolved, 2,
        "one commit for GcInspected, one for GcResolved"
    );
    let LoadOutcome::Exact(r) = store.load_canonical() else {
        panic!("expected record")
    };
    match &r.gc_pending[0] {
        GcEntry::Bound { state, .. } => assert_eq!(*state, GcState::Done),
        other => panic!("must have progressed: {other:?}"),
    }
}

#[test]
fn gc_is_plural_resolves_multiple_independent_entries_in_one_tick() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
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
    seed_record(store, locks, &rec);

    let backend = FakeSecretBackend::new();
    let gc_serial = GcSerialLock::new();
    let resolved = gc_worker_tick(store, &backend, locks, &gc_serial, 1000, TEST_CAP).unwrap();
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
            .all(|e| matches!(e, GcEntry::AbsentUnconfirmed { .. }))
    );
}

#[test]
fn gc_reprocesses_a_pending_bound_entry_next_tick_never_stuck() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let s = slot(NonZeroU64::new(1).unwrap(), [13; 16]);
    let b = binding(s.clone());
    let rec = record_with_gc_entries(vec![GcEntry::Bound {
        slot: s.clone(),
        txn_id: [13; 16],
        binding: b.clone(),
        state: GcState::Pending,
    }]);
    seed_record(store, locks, &rec);

    let backend = FakeSecretBackend::new();
    backend.create_or_inspect(&s, Some(&b));

    let gc_serial = GcSerialLock::new();
    let resolved = gc_worker_tick(store, &backend, locks, &gc_serial, 1000, TEST_CAP).unwrap();
    assert_eq!(
        resolved, 1,
        "a Pending entry from a crashed prior tick must be retried, not skipped forever"
    );
    let LoadOutcome::Exact(r) = store.load_canonical() else {
        panic!("expected record")
    };
    match &r.gc_pending[0] {
        GcEntry::Bound { state, .. } => assert_eq!(*state, GcState::Done),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn gc_resolved_quarantines_on_backend_reported_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let s = slot(NonZeroU64::new(1).unwrap(), [70; 16]);
    let expected_binding = binding(s.clone());
    let mut actual_binding = expected_binding.clone();
    actual_binding.public_key = vec![0xDE, 0xAD];

    let rec = record_with_gc_entries(vec![GcEntry::Bound {
        slot: s.clone(),
        txn_id: [70; 16],
        binding: expected_binding.clone(),
        state: GcState::Pending,
    }]);
    seed_record(store, locks, &rec);
    let backend = FakeSecretBackend::new();
    backend.create_or_inspect(&s, Some(&actual_binding));

    let gc_serial = GcSerialLock::new();
    let resolved = gc_worker_tick(store, &backend, locks, &gc_serial, 1000, TEST_CAP).unwrap();
    assert_eq!(resolved, 1);
    let LoadOutcome::Exact(r) = store.load_canonical() else {
        panic!("expected record")
    };
    match &r.gc_pending[0] {
        GcEntry::Bound { state, .. } => assert_eq!(*state, GcState::Quarantine),
        other => panic!("unexpected: {other:?}"),
    }
}

struct IndeterminateOnceBackend {
    inner: FakeSecretBackend,
    indeterminate_slot: Mutex<Option<String>>,
}
impl IndeterminateOnceBackend {
    fn new(inner: FakeSecretBackend, indeterminate_slot: String) -> Self {
        Self {
            inner,
            indeterminate_slot: Mutex::new(Some(indeterminate_slot)),
        }
    }
}
impl SecretBackend for IndeterminateOnceBackend {
    fn create_or_inspect(&self, slot: &SlotId, expected: Option<&ExactBinding>) -> CreateOutcome {
        self.inner.create_or_inspect(slot, expected)
    }
    fn load_exact(&self, slot: &SlotId, expected_public_key: &[u8]) -> LoadExactOutcome {
        self.inner.load_exact(slot, expected_public_key)
    }
    fn inspect(&self, slot: &SlotId) -> InspectOutcome {
        self.inner.inspect(slot)
    }
    fn gc_best_effort(&self, slot: &SlotId, expected_binding: &ExactBinding) -> GcReport {
        let mut guard = self.indeterminate_slot.lock().unwrap();
        if guard.as_deref() == Some(slot.canonical_id().as_str()) {
            *guard = None;
            return GcReport {
                attempted: true,
                residual: false,
                observation_complete: false,
                mismatch: false,
            };
        }
        drop(guard);
        self.inner.gc_best_effort(slot, expected_binding)
    }
}

#[test]
fn gc_indeterminate_entry_does_not_block_other_entries_in_the_same_tick() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let s_indeterminate = slot(NonZeroU64::new(1).unwrap(), [60; 16]);
    let s_ok = slot(NonZeroU64::new(2).unwrap(), [61; 16]);
    let b_indeterminate = binding(s_indeterminate.clone());
    let b_ok = binding(s_ok.clone());
    let rec = record_with_gc_entries(vec![
        GcEntry::Bound {
            slot: s_indeterminate.clone(),
            txn_id: [60; 16],
            binding: b_indeterminate.clone(),
            state: GcState::Pending,
        },
        GcEntry::Bound {
            slot: s_ok.clone(),
            txn_id: [61; 16],
            binding: b_ok.clone(),
            state: GcState::Pending,
        },
    ]);
    seed_record(store, locks, &rec);

    let fake = FakeSecretBackend::new();
    fake.create_or_inspect(&s_indeterminate, Some(&b_indeterminate));
    fake.create_or_inspect(&s_ok, Some(&b_ok));
    let backend = IndeterminateOnceBackend::new(fake, s_indeterminate.canonical_id());

    let gc_serial = GcSerialLock::new();
    let resolved = gc_worker_tick(store, &backend, locks, &gc_serial, 1000, TEST_CAP).unwrap();
    assert_eq!(
        resolved, 1,
        "only the non-indeterminate entry resolves this tick"
    );

    let LoadOutcome::Exact(r) = store.load_canonical() else {
        panic!("expected record")
    };
    let ok_entry = r
        .gc_pending
        .iter()
        .find(|e| e.slot().canonical_id() == s_ok.canonical_id())
        .unwrap();
    match ok_entry {
        GcEntry::Bound { state, .. } => assert_eq!(*state, GcState::Done),
        _ => panic!("expected Bound"),
    }
    let indeterminate_entry = r
        .gc_pending
        .iter()
        .find(|e| e.slot().canonical_id() == s_indeterminate.canonical_id())
        .unwrap();
    match indeterminate_entry {
        GcEntry::Bound { state, .. } => assert_eq!(
            *state,
            GcState::Pending,
            "must remain Pending, retried next tick"
        ),
        _ => panic!("expected Bound"),
    }
}

#[test]
fn gc_removal_pass_removes_done_and_absent_entries() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let s1 = slot(NonZeroU64::new(1).unwrap(), [90; 16]);
    let s2 = slot(NonZeroU64::new(2).unwrap(), [91; 16]);
    let rec = record_with_gc_entries(vec![
        GcEntry::Bound {
            slot: s1.clone(),
            txn_id: [90; 16],
            binding: binding(s1.clone()),
            state: GcState::Done,
        },
        GcEntry::Absent {
            slot: s2.clone(),
            txn_id: [91; 16],
        },
    ]);
    seed_record(store, locks, &rec);
    let removed = gc_removal_pass(store, locks, 1000, TEST_CAP).unwrap();
    assert_eq!(removed, 2);
    let LoadOutcome::Exact(r) = store.load_canonical() else {
        panic!("expected record")
    };
    assert!(r.gc_pending.is_empty());
}

// ── Secret backend: typed slot, opacity, coherent synth, mismatch check ─

#[test]
fn create_or_inspect_second_call_is_idempotent_never_overwrites() {
    let backend = FakeSecretBackend::new();
    let s = slot(NonZeroU64::new(1).unwrap(), [100; 16]);
    let first = backend.create_or_inspect(&s, None);
    let second = backend.create_or_inspect(&s, None);
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
        panic!("second call must report Existing")
    };
    assert_eq!(b1, b2);
}

#[test]
fn create_or_inspect_reports_conflict_on_mismatched_expectation() {
    let backend = FakeSecretBackend::new();
    let s = slot(NonZeroU64::new(1).unwrap(), [101; 16]);
    let real = backend.create_or_inspect(&s, None);
    let CreateOutcome::Unique {
        binding: real_binding,
        ..
    } = real
    else {
        panic!()
    };
    let mut wrong = real_binding.clone();
    wrong.public_key = vec![0xFF, 0xFF];
    let outcome = backend.create_or_inspect(&s, Some(&wrong));
    assert_eq!(outcome, CreateOutcome::Conflict);
}

#[test]
fn synth_binding_echoes_the_real_slot_verbatim() {
    let backend = FakeSecretBackend::new();
    let s = slot(NonZeroU64::new(7).unwrap(), [102; 16]);
    let outcome = backend.create_or_inspect(&s, None);
    let CreateOutcome::Unique { binding, .. } = outcome else {
        panic!()
    };
    assert_eq!(
        binding.slot, s,
        "the returned binding's slot must be the REAL slot, never a fabricated one with e.g. generation=1/txn_id=0"
    );
}

#[test]
fn inspect_has_no_create_side_effect() {
    let backend = FakeSecretBackend::new();
    let s = slot(NonZeroU64::new(1).unwrap(), [103; 16]);
    assert_eq!(backend.inspect(&s), InspectOutcome::Absent);
    assert_eq!(backend.inspect(&s), InspectOutcome::Absent);
}

#[test]
fn gc_best_effort_checks_expected_binding_before_destroying() {
    let backend = FakeSecretBackend::new();
    let s = slot(NonZeroU64::new(1).unwrap(), [104; 16]);
    let real_binding = binding(s.clone());
    backend.create_or_inspect(&s, Some(&real_binding));

    let mut wrong = real_binding.clone();
    wrong.public_key = vec![0x00];
    let report = backend.gc_best_effort(&s, &wrong);
    assert!(
        report.mismatch,
        "must report a mismatch, not silently destroy or silently succeed"
    );
    assert!(report.residual);
    assert_eq!(
        backend.inspect(&s),
        InspectOutcome::Present(real_binding.clone()),
        "must not have been destroyed on a mismatch"
    );

    let report2 = backend.gc_best_effort(&s, &real_binding);
    assert!(!report2.mismatch);
    assert!(!report2.residual);
    assert_eq!(
        backend.inspect(&s),
        InspectOutcome::Absent,
        "the correct expected_binding must actually destroy it"
    );
}

// ── SlotId::canonical_id includes backend_instance ───────────────────────

#[test]
fn canonical_id_distinguishes_slots_that_differ_only_by_backend() {
    let base = slot(NonZeroU64::new(1).unwrap(), [110; 16]);
    let mut other_backend = base.clone();
    other_backend.backend_instance = BackendKind::SecureEnclave;
    assert_ne!(
        base.canonical_id(),
        other_backend.canonical_id(),
        "two slots identical except for backend_instance must never collapse to the same string id"
    );
}

// ── Validator: PURPOSE_ID binds the type parameter to the runtime record ─

#[test]
fn validate_full_binding_rejects_delegated_pub_not_matching_binding_public_key() {
    let s = slot(NonZeroU64::new(1).unwrap(), [111; 16]);
    let b = binding(s.clone());
    let policy = DelegationPolicy::test(1000);
    let mut d = delegation(0, 100);
    d.delegated_key_id = s.canonical_id();
    d.delegated_pub = vec![0xFF, 0xFF];
    let gr = GenerationRecord {
        generation: NonZeroU64::new(1).unwrap(),
        delegation: d,
        binding: b,
        not_after: 100,
    };
    let err = validate_full_binding::<MeshSessionPurpose>(
        &gr,
        &ctx(),
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .unwrap_err();
    assert_eq!(err, ValidationError::DelegatedPubBindingMismatch);
}

#[test]
fn verifier_receives_the_full_delegation_including_channel() {
    let s = slot(NonZeroU64::new(1).unwrap(), [112; 16]);
    let b = binding(s.clone());
    let policy = DelegationPolicy::test(1000);
    let mut d_release = delegation(0, 100);
    d_release.channel = Channel::Release;
    d_release.delegated_key_id = s.canonical_id();
    d_release.delegated_pub = b.public_key.clone();
    let gr = GenerationRecord {
        generation: NonZeroU64::new(1).unwrap(),
        delegation: d_release,
        binding: b,
        not_after: 100,
    };
    let ctx_release = BindingContext {
        hh_id: "hh_test",
        machine_id: "m_test",
        channel: Channel::Release,
    };
    let verifier = RecordingVerifier::default();
    validate_full_binding::<MeshSessionPurpose>(
        &gr,
        &ctx_release,
        &policy,
        &active_roster(),
        &verifier,
        50,
    )
    .unwrap();
    let seen = verifier
        .last_delegation
        .lock()
        .unwrap()
        .clone()
        .expect("verifier must have been called");
    assert_eq!(
        seen.channel,
        Channel::Release,
        "the verifier must see the real delegation, including channel, rather than raw bytes this model invented"
    );
}

fn pending_intent_record() -> (MeshSignerControlRecordV1, PendingOp) {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [121; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();
    (with_intent, p)
}

#[test]
fn activate_from_key_observed_rejects_purpose_type_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = locks.acquire_for_mutation();
        assert_eq!(
            store.replace_exact(&g, INITIAL_REVISION, &old),
            ReplaceOutcome::Committed
        );
    }
    let backend = FakeSecretBackend::new();
    let policy = DelegationPolicy::test(1000);
    let d = delegation(0, 100);

    // The record's runtime purpose is MeshSession; validating it against
    // RosterSyncPurpose's type parameter must be rejected structurally,
    // never left to whatever domain/profile the caller's delegation
    // happens to claim.
    let err = activate_from_key_observed::<RosterSyncPurpose>(
        store,
        &backend,
        locks,
        &active_roster(),
        &AlwaysTrueVerifier,
        &policy,
        &ctx(),
        d,
        50,
        TEST_CAP,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ActivateError::Validation(ValidationError::PurposeMismatch)
    ));
}

#[test]
fn activate_from_key_observed_rejects_when_physical_key_not_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let (with_intent, p) = pending_intent_record();
    {
        let g = locks.acquire_for_mutation();
        let base = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        assert_eq!(
            store.replace_exact(&g, INITIAL_REVISION, &base),
            ReplaceOutcome::Committed
        );
        assert_eq!(
            store.replace_exact(&g, base.revision, &with_intent),
            ReplaceOutcome::Committed
        );
    }
    let claimed_binding = binding(p.canonical_slot.clone());
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: claimed_binding,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    {
        let g = locks.acquire_for_mutation();
        assert_eq!(
            store.replace_exact(&g, with_intent.revision, &with_binding),
            ReplaceOutcome::Committed
        );
    }

    // The backend never actually has this key.
    let backend = FakeSecretBackend::new();
    let policy = DelegationPolicy::test(1000);
    let mut d = delegation(0, 100);
    d.delegated_key_id = p.canonical_slot.canonical_id();

    let err = activate_from_key_observed::<MeshSessionPurpose>(
        store,
        &backend,
        locks,
        &active_roster(),
        &AlwaysTrueVerifier,
        &policy,
        &ctx(),
        d,
        50,
        TEST_CAP,
    )
    .unwrap_err();
    assert!(matches!(err, ActivateError::PhysicalKeyNotConfirmed));
}

#[test]
fn activate_from_key_observed_succeeds_full_path() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [121; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    {
        let g = locks.acquire_for_mutation();
        assert_eq!(
            store.replace_exact(&g, INITIAL_REVISION, &old),
            ReplaceOutcome::Committed
        );
        assert_eq!(
            store.replace_exact(&g, old.revision, &with_intent),
            ReplaceOutcome::Committed
        );
    }
    let p = with_intent.pending_op.clone().unwrap();

    let backend = FakeSecretBackend::new();
    let CreateOutcome::Unique {
        binding: real_binding,
        ..
    } = backend.create_or_inspect(&p.canonical_slot, None)
    else {
        panic!()
    };

    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: real_binding.clone(),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    {
        let g = locks.acquire_for_mutation();
        assert_eq!(
            store.replace_exact(&g, with_intent.revision, &with_binding),
            ReplaceOutcome::Committed
        );
    }

    let policy = DelegationPolicy::test(1000);
    let mut d = delegation(0, 100);
    d.delegated_key_id = p.canonical_slot.canonical_id();
    d.delegated_pub = real_binding.public_key.clone();

    let activated = activate_from_key_observed::<MeshSessionPurpose>(
        store,
        &backend,
        locks,
        &active_roster(),
        &AlwaysTrueVerifier,
        &policy,
        &ctx(),
        d,
        50,
        TEST_CAP,
    )
    .unwrap();
    assert_eq!(
        activated.current_generation,
        Some(NonZeroU64::new(1).unwrap())
    );
    assert!(
        activated
            .recent_terminal_results
            .iter()
            .any(|r| r.txn_id == p.txn_id && matches!(r.outcome, TerminalOutcome::Activated { .. }))
    );
}

#[test]
fn revalidate_on_load_rejects_purpose_type_mismatch() {
    let record = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let policy = DelegationPolicy::test(1000);
    let err = revalidate_on_load::<RosterSyncPurpose>(
        &record,
        &ctx(),
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .unwrap_err();
    assert_eq!(err, ValidationError::PurposeMismatch);
}

#[test]
fn revalidate_on_load_detects_roster_revocation() {
    let rotated = rotated_record_with_two_generations(5000, 6000);
    let policy = DelegationPolicy::test(10_000);
    let revoked_roster = FixedRoster(RosterCurrency::Revoked);
    let err = revalidate_on_load::<MeshSessionPurpose>(
        &rotated,
        &ctx(),
        &policy,
        &revoked_roster,
        &AlwaysTrueVerifier,
        50,
    )
    .unwrap_err();
    assert_eq!(err, ValidationError::DelegatorRevoked);
}

// ── activate must not block an urgent revoke during slow I/O (round 4, item 5) ─

/// Blocks inside `query_machine_currency` until told to proceed, signalling
/// via `ready_tx` the instant it enters the slow section so the test can
/// deterministically race a concurrent revoke against it.
struct BlockingRoster {
    ready_tx: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    proceed_rx: Mutex<std::sync::mpsc::Receiver<()>>,
}
impl RosterLookup for BlockingRoster {
    fn query_machine_currency(&self, _machine_id: &str) -> RosterCurrency {
        if let Some(tx) = self.ready_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        self.proceed_rx.lock().unwrap().recv().unwrap();
        RosterCurrency::Active {
            member_pub: vec![1, 2, 3],
            member_cert_fingerprint: [9u8; 32],
        }
    }
}

#[test]
fn activate_does_not_block_a_concurrent_urgent_revoke_during_slow_roster_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = locks.acquire_for_mutation();
        assert_eq!(
            store.replace_exact(&g, INITIAL_REVISION, &old),
            ReplaceOutcome::Committed
        );
    }
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [90; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();
    let backend = FakeSecretBackend::new();
    let CreateOutcome::Unique {
        binding: real_binding,
        ..
    } = backend.create_or_inspect(&p.canonical_slot, None)
    else {
        panic!()
    };
    let with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: real_binding.clone(),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    {
        let g = locks.acquire_for_mutation();
        assert_eq!(
            store.replace_exact(&g, old.revision, &with_intent),
            ReplaceOutcome::Committed
        );
        assert_eq!(
            store.replace_exact(&g, with_intent.revision, &with_binding),
            ReplaceOutcome::Committed
        );
    }

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
    let roster = BlockingRoster {
        ready_tx: Mutex::new(Some(ready_tx)),
        proceed_rx: Mutex::new(proceed_rx),
    };
    let policy = DelegationPolicy::test(1000);
    let mut d = delegation(0, 100);
    d.delegated_key_id = p.canonical_slot.canonical_id();
    d.delegated_pub = real_binding.public_key.clone();

    std::thread::scope(|scope| {
        let activate_handle = scope.spawn(|| {
            activate_from_key_observed::<MeshSessionPurpose>(
                store,
                &backend,
                locks,
                &roster,
                &AlwaysTrueVerifier,
                &policy,
                &ctx(),
                d,
                50,
                TEST_CAP,
            )
        });
        // Wait until activate is genuinely inside the slow roster call --
        // proves what follows races against real in-progress I/O, not a
        // timing guess.
        ready_rx.recv().unwrap();

        // While activate is blocked in the roster lookup, an urgent revoke
        // must still be able to proceed -- proving no exclusive guard is
        // held across that call.
        let revoke_g = locks.acquire_for_mutation();
        let revoked = apply(
            &with_binding,
            &RecordTransition::RevokeUrgent {
                reason: RevocationReason::Compromised,
                txn_id: [91; 16],
            },
            60,
            TEST_CAP,
        )
        .unwrap();
        assert_eq!(
            store.replace_exact(&revoke_g, with_binding.revision, &revoked),
            ReplaceOutcome::Committed,
            "revoke must be able to commit while activate is still busy with I/O"
        );
        drop(revoke_g);

        proceed_tx.send(()).unwrap();
        let result = activate_handle.join().unwrap();
        // Activate must detect the preemption once it reacquires the guard
        // and rereads fresh -- never silently reactivating over a revoke
        // that landed while it was busy.
        assert!(
            matches!(
                result,
                Err(ActivateError::Transition(TransitionError::NoPendingOp))
            ),
            "activate must reject once it sees the revoke that preempted it, got {result:?}"
        );
    });
}

// ── InspectOutcome::Conflict persists durably (round 4, item 6) ────────

struct ConflictBackend {
    inner: FakeSecretBackend,
}
impl SecretBackend for ConflictBackend {
    fn create_or_inspect(&self, slot: &SlotId, expected: Option<&ExactBinding>) -> CreateOutcome {
        self.inner.create_or_inspect(slot, expected)
    }
    fn load_exact(&self, slot: &SlotId, expected_public_key: &[u8]) -> LoadExactOutcome {
        self.inner.load_exact(slot, expected_public_key)
    }
    fn inspect(&self, _slot: &SlotId) -> InspectOutcome {
        InspectOutcome::Conflict
    }
    fn gc_best_effort(&self, slot: &SlotId, expected_binding: &ExactBinding) -> GcReport {
        self.inner.gc_best_effort(slot, expected_binding)
    }
}

#[test]
fn gc_worker_persists_inspection_conflict_and_excludes_it_from_retry() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let store = cell.store();
    let locks = cell.locks();
    let s = slot(NonZeroU64::new(1).unwrap(), [95; 16]);
    let rec = record_with_gc_entries(vec![GcEntry::AwaitingInspection {
        slot: s.clone(),
        txn_id: [95; 16],
    }]);
    seed_record(store, locks, &rec);

    let backend = ConflictBackend {
        inner: FakeSecretBackend::new(),
    };
    let gc_serial = GcSerialLock::new();
    let resolved = gc_worker_tick(store, &backend, locks, &gc_serial, 1000, TEST_CAP).unwrap();
    assert_eq!(resolved, 1);
    let LoadOutcome::Exact(r) = store.load_canonical() else {
        panic!("expected record")
    };
    match &r.gc_pending[0] {
        GcEntry::InspectionConflict { .. } => {}
        other => panic!("expected InspectionConflict, got {other:?}"),
    }

    // A second tick must never reprocess it -- it stays excluded from
    // automatic retry pending administrative resolution, not silently
    // retried forever with no durable trace.
    let resolved_2 = gc_worker_tick(store, &backend, locks, &gc_serial, 2000, TEST_CAP).unwrap();
    assert_eq!(
        resolved_2, 0,
        "InspectionConflict must never be auto-retried"
    );
}
