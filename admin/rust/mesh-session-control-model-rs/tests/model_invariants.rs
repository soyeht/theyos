//! Executable invariants for the D-4 single-record control model.
//! Successor to the generation audited at commit `d4ecb658` (NO-GO across
//! five rounds of CFX). Each section maps to a named finding from that
//! audit; comments cite the finding inline where the test exists
//! specifically because of it.

use mesh_session_control_model_rs::activate::{
    ActivateError, AuthorizedUseError, LoadRevalidatedError, activate_from_key_observed,
    load_revalidated_report_for_test, revalidate_on_load, with_authorized_use,
};
use mesh_session_control_model_rs::cell::{
    self, CommitTransitionError, ControlRecordCell, OpenConflict,
};
use mesh_session_control_model_rs::commit::commit_new_bytes;
use mesh_session_control_model_rs::gc::{gc_removal_pass, gc_worker_tick};
use mesh_session_control_model_rs::locks::{LockEvent, MeshSignerLocks, OrderSpy};
use mesh_session_control_model_rs::record::*;
use mesh_session_control_model_rs::secret_backend::{
    CreateOutcome, CreatedOrExisting, FakeSecretBackend, GcReport, InspectOutcome,
    LoadExactOutcome, SecretBackend,
};
use mesh_session_control_model_rs::store::{AtomicControlRecordStore, LoadOutcome, ReplaceOutcome};
use mesh_session_control_model_rs::transition::{RecordTransition, TransitionError, apply};
use mesh_session_control_model_rs::validator::{
    BindingContext, CurrencyLease, DelegationPolicy, MeshSessionPurpose, RosterChanged,
    RosterCurrency, RosterLookup, RosterSyncPurpose, SignatureVerifier, ValidationError,
    validate_full_binding,
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
    // Round 6, wave 6: must use the REAL derived digest for `identity()`,
    // not a fixed placeholder -- invariants_hold now cross-checks every
    // gc_pending/live_generations/pending_op slot's identity_digest
    // against `identity_digest(&record.identity)`, so a fixture built
    // with an arbitrary constant here would fail that check even though
    // every other field is legitimate.
    SlotId {
        identity_digest: identity_digest(&identity()),
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
        // Round 5, item C8: MeshSessionPurpose's production scope now
        // requires the EXACT set {initiator, responder} -- see
        // validator.rs's `DelegationScopePolicy` doc comment.
        roles: vec!["initiator".into(), "responder".into()],
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
    .expect("fresh path, no prior live cell registered for it")
}

// `revision: 1` -- the store's genesis check now only accepts the exact
// canonical bootstrap shape (finding 2), so a GC-populated fixture is never
// itself a legitimate genesis write. `seed_record` below always lands the
// real canonical bootstrap first, then this as a one-step mutation on top.
fn record_with_gc_entries(entries: Vec<GcEntry>) -> MeshSignerControlRecordV1 {
    let mut r = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    // Round 6, wave 6: invariants_hold now requires every gc_pending
    // entry's slot.generation <= generation_high_water -- bump it to
    // cover whatever generations these fixture entries actually
    // reference, rather than leaving it at the bootstrap default of 1.
    for e in &entries {
        if e.slot().generation > r.generation_high_water {
            r.generation_high_water = e.slot().generation;
        }
    }
    r.gc_pending = entries;
    r.revision = 1;
    r
}

/// Writes the canonical bootstrap genesis, then `seeded` as the one
/// mutation on top of it -- the only way to get an arbitrary fixture state
/// onto disk now that genesis is restricted to the exact canonical shape.
fn seed_record(cell: &ControlRecordCell, seeded: &MeshSignerControlRecordV1) {
    let bootstrap = MeshSignerControlRecordV1::bootstrap(seeded.identity.clone(), seeded.purpose);
    let g = cell.acquire_for_mutation();
    assert_eq!(
        cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
        ReplaceOutcome::Committed
    );
    assert_eq!(
        cell.seed_for_test(&g, bootstrap.revision, seeded),
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

/// Trivial `CurrencyLease` for test doubles whose currency never actually
/// changes -- holding it guarantees nothing extra, because there is
/// nothing to guarantee against.
struct TrivialLease;
impl CurrencyLease for TrivialLease {}

struct FixedRoster(RosterCurrency);
impl RosterLookup for FixedRoster {
    fn query_machine_currency(&self, _machine_id: &str) -> RosterCurrency {
        self.0.clone()
    }
    fn currency_revision(&self, _machine_id: &str) -> u64 {
        // Never changes -- a before/after comparison always matches,
        // which is correct: FixedRoster never goes stale mid-flight.
        0
    }
    fn acquire_currency_lease(
        &self,
        _machine_id: &str,
        expected_revision: u64,
    ) -> Result<Box<dyn CurrencyLease + '_>, RosterChanged> {
        if expected_revision == 0 {
            Ok(Box::new(TrivialLease))
        } else {
            Err(RosterChanged)
        }
    }
}

fn active_roster() -> FixedRoster {
    FixedRoster(RosterCurrency::Active {
        member_pub: vec![1, 2, 3],
        member_cert_fingerprint: [9u8; 32],
    })
}

/// Shorthand `TerminalRequestFingerprint::Activate` for terminal-retention
/// tests that only care about txn_id/eviction bookkeeping, not the request
/// content itself -- `generation` just needs to be distinguishable when a
/// test specifically wants two DIFFERENT requests sharing one txn_id.
fn activate_request(generation: u64) -> TerminalRequestFingerprint {
    TerminalRequestFingerprint::Activate {
        generation: NonZeroU64::new(generation).unwrap(),
        delegation: Box::new(delegation(0, 100)),
    }
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
    let bootstrapped = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrapped),
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
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, bootstrapped.revision, &writer_a_next),
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
    let g = cell.acquire_for_mutation();
    assert_eq!(
        cell.seed_for_test(&g, bootstrapped.revision, &writer_b_next),
        ReplaceOutcome::KnownNoEffect,
        "writer B's stale revision-0 CAS must be rejected once writer A already advanced to revision 1"
    );
    let LoadOutcome::Exact(on_disk) = cell.load_canonical_for_test() else {
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
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrapped),
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
        let g = c1.acquire_for_mutation();
        c1.seed_for_test(&g, base_rev, &new_a)
    });
    let h2 = std::thread::spawn(move || {
        b2.wait();
        let g = c2.acquire_for_mutation();
        c2.seed_for_test(&g, base_rev, &new_b)
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
    let bootstrapped = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrapped),
            ReplaceOutcome::Committed
        );
    }
    let mut forged = bootstrapped.clone();
    forged.revision = 99;
    let g = cell.acquire_for_mutation();
    assert_eq!(
        cell.seed_for_test(&g, INITIAL_REVISION, &forged),
        ReplaceOutcome::KnownNoEffect,
        "new_record.revision must be exactly old.revision+1 (mutation) or == old.revision with byte-identical content (stabilization) -- never trusted verbatim"
    );
}

#[test]
fn store_missing_rejects_non_canonical_first_write() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let mut forged_genesis =
        MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    forged_genesis.epoch_high_water = NonZeroU64::new(5).unwrap();
    let g = cell.acquire_for_mutation();
    assert_eq!(
        cell.seed_for_test(&g, INITIAL_REVISION, &forged_genesis),
        ReplaceOutcome::KnownNoEffect,
        "Missing must only accept the exact canonical bootstrap record"
    );
    assert_eq!(cell.load_canonical_for_test(), LoadOutcome::Missing);
}

#[test]
fn genesis_write_is_validated_against_the_stores_own_bound_identity_not_new_records_claim() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let mut other_identity = identity();
    other_identity.hh_id = "hh_other".into();
    let forged = MeshSignerControlRecordV1::bootstrap(other_identity, PurposeId::MeshSession);
    let g = cell.acquire_for_mutation();
    assert_eq!(
        cell.seed_for_test(&g, INITIAL_REVISION, &forged),
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
        cell.seed_for_test(&foreign_guard, INITIAL_REVISION, &rec)
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
        cell_a.token(),
        cell_b.token(),
        "two open() calls for the same live path must return the identical pair, never two independently-consistent ones that could race"
    );
}

#[test]
fn cell_open_creates_a_fresh_pair_once_the_prior_one_is_fully_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let token_a = {
        let cell_a = test_cell(path.clone());
        cell_a.token()
    }; // cell_a's only Arc dropped here
    let cell_b = test_cell(path);
    assert_ne!(
        token_a,
        cell_b.token(),
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
    assert_eq!(cell.load_canonical_for_test(), LoadOutcome::Corrupt);
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
    assert_eq!(cell.load_canonical_for_test(), LoadOutcome::Corrupt);
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
    assert_eq!(cell.load_canonical_for_test(), LoadOutcome::Corrupt);
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
    assert_eq!(cell.load_canonical_for_test(), LoadOutcome::Corrupt);
}

#[test]
fn store_write_then_read_round_trips_through_canonicalization() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let rec = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let g = cell.acquire_for_mutation();
    assert_eq!(
        cell.seed_for_test(&g, INITIAL_REVISION, &rec),
        ReplaceOutcome::Committed
    );
    let LoadOutcome::Exact(read_back) = cell.load_canonical_for_test() else {
        panic!("expected record")
    };
    assert_eq!(*read_back, rec);
}

// ── MayHaveTakenEffect: durability, not just visibility (finding 3) ─────

#[test]
fn may_have_taken_effect_recovery_requires_a_real_committing_rewrite_not_a_reread() {
    let dir = tempfile::tempdir().unwrap();
    // Round 5, item A2: FaultInjectingStore now goes through its own
    // registry (`cell::open_fault_injecting`) too, same as FileBackedStore
    // -- two independently-constructed pairs over the same path would
    // alias/race exactly like the pre-registry bug this crate already
    // closed for the real store.
    let fi_cell = cell::open_fault_injecting(
        dir.path().join("record"),
        identity(),
        PurposeId::MeshSession,
        Arc::new(OrderSpy::new()),
    )
    .unwrap();
    let store = fi_cell.store();
    let locks = fi_cell.locks();
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
    commit_new_bytes(store, &guard, bootstrapped.revision, &mutated, 10)
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
    // Round 5, item A2: see the sibling test above for why this now goes
    // through the registry instead of constructing directly.
    let fi_cell = cell::open_fault_injecting(
        dir.path().join("record"),
        identity(),
        PurposeId::MeshSession,
        Arc::new(OrderSpy::new()),
    )
    .unwrap();
    let store = fi_cell.store();
    let locks = fi_cell.locks();
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
    {
        let g = cell.acquire_for_mutation();
        cell.sweep_orphan_tmp(&g);
    }
    assert!(
        !record_path
            .with_file_name("record.tmp.00000000000000000000.deadbeefdeadbeef")
            .exists(),
        "an orphan tmp targeting a revision below current (there is no current record at all, so it predates this session) must be removed"
    );
    let rec = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let g = cell.acquire_for_mutation();
    assert_eq!(
        cell.seed_for_test(&g, INITIAL_REVISION, &rec),
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
        request: activate_request(1),
        recorded_at: 10,
        acked: false,
    };
    let v = push_bounded_terminal(vec![], r.clone()).unwrap();
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
        request: activate_request(1),
        recorded_at: 10,
        acked: false,
    };
    let r2 = TerminalResult {
        txn_id: [1; 16],
        outcome: TerminalOutcome::Activated {
            generation: NonZeroU64::new(2).unwrap(),
        },
        request: activate_request(2),
        recorded_at: 11,
        acked: false,
    };
    let v = push_bounded_terminal(vec![], r1).unwrap();
    let err = push_bounded_terminal(v, r2).unwrap_err();
    assert_eq!(err, TerminalPushError::RequestConflict);
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
                request: activate_request(1),
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
        request: activate_request(1),
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
                request: activate_request(1),
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
        request: activate_request(1),
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
    let s = slot(NonZeroU64::new(1).unwrap(), [83; 16]);
    let rec = record_with_gc_entries(vec![GcEntry::AwaitingInspection {
        slot: s.clone(),
        txn_id: [83; 16],
    }]);
    seed_record(&cell, &rec);
    let backend = FakeSecretBackend::new(); // deliberately empty throughout

    let resolved_1 = gc_worker_tick(&cell, &backend, 1000, TEST_CAP).unwrap();
    assert_eq!(resolved_1, 1);
    let LoadOutcome::Exact(r1) = cell.load_canonical_for_test() else {
        panic!("expected record")
    };
    match &r1.gc_pending[0] {
        GcEntry::AbsentUnconfirmed { .. } => {}
        other => panic!("expected AbsentUnconfirmed after tick 1, got {other:?}"),
    }

    // Crash-resume: this second call is a completely fresh gc_worker_tick,
    // with nothing carried over except what tick 1 durably wrote.
    let resolved_2 = gc_worker_tick(&cell, &backend, 2000, TEST_CAP).unwrap();
    assert_eq!(resolved_2, 1);
    let LoadOutcome::Exact(r2) = cell.load_canonical_for_test() else {
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
    let s = slot(NonZeroU64::new(1).unwrap(), [10; 16]);
    let rec = record_with_gc_entries(vec![GcEntry::AwaitingInspection {
        slot: s.clone(),
        txn_id: [10; 16],
    }]);
    seed_record(&cell, &rec);

    let backend = FakeSecretBackend::new();
    backend.create_or_inspect(&s, None); // seed a real item

    let resolved = gc_worker_tick(&cell, &backend, 1000, TEST_CAP).unwrap();
    assert_eq!(
        resolved, 2,
        "one commit for GcInspected, one for GcResolved"
    );
    let LoadOutcome::Exact(r) = cell.load_canonical_for_test() else {
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
    seed_record(&cell, &rec);

    let backend = FakeSecretBackend::new();
    let resolved = gc_worker_tick(&cell, &backend, 1000, TEST_CAP).unwrap();
    assert_eq!(
        resolved, 2,
        "one tick must drain every independently-resolvable entry, not just the first"
    );
    let LoadOutcome::Exact(r) = cell.load_canonical_for_test() else {
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
    let s = slot(NonZeroU64::new(1).unwrap(), [13; 16]);
    let b = binding(s.clone());
    let rec = record_with_gc_entries(vec![GcEntry::Bound {
        slot: s.clone(),
        txn_id: [13; 16],
        binding: b.clone(),
        state: GcState::Pending,
    }]);
    seed_record(&cell, &rec);

    let backend = FakeSecretBackend::new();
    backend.create_or_inspect(&s, Some(&b));

    let resolved = gc_worker_tick(&cell, &backend, 1000, TEST_CAP).unwrap();
    assert_eq!(
        resolved, 1,
        "a Pending entry from a crashed prior tick must be retried, not skipped forever"
    );
    let LoadOutcome::Exact(r) = cell.load_canonical_for_test() else {
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
    seed_record(&cell, &rec);
    let backend = FakeSecretBackend::new();
    backend.create_or_inspect(&s, Some(&actual_binding));

    let resolved = gc_worker_tick(&cell, &backend, 1000, TEST_CAP).unwrap();
    assert_eq!(resolved, 1);
    let LoadOutcome::Exact(r) = cell.load_canonical_for_test() else {
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
    seed_record(&cell, &rec);

    let fake = FakeSecretBackend::new();
    fake.create_or_inspect(&s_indeterminate, Some(&b_indeterminate));
    fake.create_or_inspect(&s_ok, Some(&b_ok));
    let backend = IndeterminateOnceBackend::new(fake, s_indeterminate.canonical_id());

    let resolved = gc_worker_tick(&cell, &backend, 1000, TEST_CAP).unwrap();
    assert_eq!(
        resolved, 1,
        "only the non-indeterminate entry resolves this tick"
    );

    let LoadOutcome::Exact(r) = cell.load_canonical_for_test() else {
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
    seed_record(&cell, &rec);
    let removed = gc_removal_pass(&cell, 1000, TEST_CAP).unwrap();
    assert_eq!(removed, 2);
    let LoadOutcome::Exact(r) = cell.load_canonical_for_test() else {
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
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &old),
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
        &cell,
        &backend,
        &active_roster(),
        &AlwaysTrueVerifier,
        &policy,
        [0; 16],
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
    let (with_intent, p) = pending_intent_record();
    {
        let g = cell.acquire_for_mutation();
        let base = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &base),
            ReplaceOutcome::Committed
        );
        assert_eq!(
            cell.seed_for_test(&g, base.revision, &with_intent),
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
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, with_intent.revision, &with_binding),
            ReplaceOutcome::Committed
        );
    }

    // The backend never actually has this key.
    let backend = FakeSecretBackend::new();
    let policy = DelegationPolicy::test(1000);
    let mut d = delegation(0, 100);
    d.delegated_key_id = p.canonical_slot.canonical_id();

    let err = activate_from_key_observed::<MeshSessionPurpose>(
        &cell,
        &backend,
        &active_roster(),
        &AlwaysTrueVerifier,
        &policy,
        p.txn_id,
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
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &old),
            ReplaceOutcome::Committed
        );
        assert_eq!(
            cell.seed_for_test(&g, old.revision, &with_intent),
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
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, with_intent.revision, &with_binding),
            ReplaceOutcome::Committed
        );
    }

    let policy = DelegationPolicy::test(1000);
    let mut d = delegation(0, 100);
    d.delegated_key_id = p.canonical_slot.canonical_id();
    d.delegated_pub = real_binding.public_key.clone();

    let activated = activate_from_key_observed::<MeshSessionPurpose>(
        &cell,
        &backend,
        &active_roster(),
        &AlwaysTrueVerifier,
        &policy,
        p.txn_id,
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
    let backend = FakeSecretBackend::new();
    let err = revalidate_on_load::<RosterSyncPurpose>(
        &record,
        &backend,
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
    let backend = FakeSecretBackend::new();
    for g in &rotated.live_generations {
        backend.create_or_inspect(&g.binding.slot, Some(&g.binding));
    }
    let policy = DelegationPolicy::test(10_000);
    let revoked_roster = FixedRoster(RosterCurrency::Revoked);
    let err = revalidate_on_load::<MeshSessionPurpose>(
        &rotated,
        &backend,
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
    fn currency_revision(&self, _machine_id: &str) -> u64 {
        0
    }
    fn acquire_currency_lease(
        &self,
        _machine_id: &str,
        expected_revision: u64,
    ) -> Result<Box<dyn CurrencyLease + '_>, RosterChanged> {
        if expected_revision == 0 {
            Ok(Box::new(TrivialLease))
        } else {
            Err(RosterChanged)
        }
    }
}

#[test]
fn activate_does_not_block_a_concurrent_urgent_revoke_during_slow_roster_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &old),
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
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, old.revision, &with_intent),
            ReplaceOutcome::Committed
        );
        assert_eq!(
            cell.seed_for_test(&g, with_intent.revision, &with_binding),
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
                &cell,
                &backend,
                &roster,
                &AlwaysTrueVerifier,
                &policy,
                p.txn_id,
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
        let revoke_g = cell.acquire_for_mutation();
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
            cell.seed_for_test(&revoke_g, with_binding.revision, &revoked),
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
                Err(ActivateError::Commit(CommitTransitionError::Transition(
                    TransitionError::NoPendingOp
                )))
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
    let s = slot(NonZeroU64::new(1).unwrap(), [95; 16]);
    let rec = record_with_gc_entries(vec![GcEntry::AwaitingInspection {
        slot: s.clone(),
        txn_id: [95; 16],
    }]);
    seed_record(&cell, &rec);

    let backend = ConflictBackend {
        inner: FakeSecretBackend::new(),
    };
    let resolved = gc_worker_tick(&cell, &backend, 1000, TEST_CAP).unwrap();
    assert_eq!(resolved, 1);
    let LoadOutcome::Exact(r) = cell.load_canonical_for_test() else {
        panic!("expected record")
    };
    match &r.gc_pending[0] {
        GcEntry::InspectionConflict { .. } => {}
        other => panic!("expected InspectionConflict, got {other:?}"),
    }

    // A second tick must never reprocess it -- it stays excluded from
    // automatic retry pending administrative resolution, not silently
    // retried forever with no durable trace.
    let resolved_2 = gc_worker_tick(&cell, &backend, 2000, TEST_CAP).unwrap();
    assert_eq!(
        resolved_2, 0,
        "InspectionConflict must never be auto-retried"
    );
}

// ══════════════════════════════════════════════════════════════════════
// Round 5 REDs/POS -- one section per audited finding on c5fb2da5.
// ══════════════════════════════════════════════════════════════════════

// ── C6: closed CBOR shape must reject an unknown field NESTED inside a
// substruct, not just at the top level ──────────────────────────────────

#[test]
fn load_canonical_rejects_an_unknown_field_nested_inside_a_substruct() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let cell = test_cell(path.clone());
    let rec = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &rec),
            ReplaceOutcome::Committed
        );
    }
    // Read back the REAL canonical bytes this store just wrote, decode to
    // the generic Value tree, and inject an extra key nested inside
    // `identity` -- a key the generic Value round-trip preserves
    // faithfully (so the bytes still pass the canonical-encoding check),
    // but that the TYPED decode of `ControlIdentity` must now reject via
    // `deny_unknown_fields`. Before that fix, serde's default behavior
    // would have silently dropped this key and returned `Some(record)`
    // anyway -- a load that claimed `Exact` for content it did not
    // actually fully account for.
    let bytes = std::fs::read(&path).unwrap();
    let mut value: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
    {
        let ciborium::Value::Map(top) = &mut value else {
            panic!("expected top-level map")
        };
        let (_, identity_val) = top
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("identity"))
            .expect("record must have an identity field");
        let ciborium::Value::Map(identity_map) = identity_val else {
            panic!("expected identity to be a map")
        };
        identity_map.push((
            ciborium::Value::Text("bogus_extra_field".into()),
            ciborium::Value::Bool(true),
        ));
    }
    let value = test_canonicalize(value);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).unwrap();
    std::fs::write(&path, &out).unwrap();

    assert_eq!(cell.load_canonical_for_test(), LoadOutcome::Corrupt);
}

/// Local mirror of `store::canonicalize_value` (private to that module) --
/// sorts every map's entries into RFC 8949 §4.2.3 canonical key order using
/// the same `ciborium::value::CanonicalValue` comparator, so hand-mutated
/// fixtures in these tests can be re-encoded into a form the real store's
/// own canonical round-trip check will accept.
fn test_canonicalize(v: ciborium::Value) -> ciborium::Value {
    use ciborium::Value;
    use ciborium::value::CanonicalValue;
    match v {
        Value::Array(items) => Value::Array(items.into_iter().map(test_canonicalize).collect()),
        Value::Map(entries) => {
            let mut entries: Vec<_> = entries
                .into_iter()
                .map(|(k, val)| (test_canonicalize(k), test_canonicalize(val)))
                .collect();
            entries.sort_by(|(k1, _), (k2, _)| {
                CanonicalValue::from(k1.clone()).cmp(&CanonicalValue::from(k2.clone()))
            });
            Value::Map(entries)
        }
        Value::Tag(t, inner) => Value::Tag(t, Box::new(test_canonicalize(*inner))),
        other => other,
    }
}

// ── C7: byte-holding fields must encode as CBOR bstr, not array-of-ints ──

#[test]
fn byte_holding_fields_encode_as_cbor_bstr_not_array_of_ints() {
    // Verified empirically via a standalone probe crate before this fix:
    // Vec<u8>/[u8;N] serialize as CBOR arrays of individual integers by
    // DEFAULT, not byte strings, unless `#[serde(with = "serde_bytes")]`
    // is present. This asserts the actual wire form of real fields, not
    // just that they round-trip.
    let s = slot(NonZeroU64::new(1).unwrap(), [0xAB; 16]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&s, &mut bytes).unwrap();
    let value: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
    let ciborium::Value::Map(entries) = value else {
        panic!("expected map")
    };
    let (_, txn_id_value) = entries
        .iter()
        .find(|(k, _)| k.as_text() == Some("txn_id"))
        .unwrap();
    assert_eq!(
        txn_id_value,
        &ciborium::Value::Bytes(vec![0xAB; 16]),
        "txn_id must encode as a CBOR byte string (major type 2), not an array of integers"
    );
    let (_, digest_value) = entries
        .iter()
        .find(|(k, _)| k.as_text() == Some("identity_digest"))
        .unwrap();
    assert!(
        matches!(digest_value, ciborium::Value::Bytes(_)),
        "identity_digest must also encode as bstr, got {digest_value:?}"
    );
}

// ── C8: MeshSessionPurpose's ratified production scope is an EXACT set ──
// (roles + transcript_kinds), not a nonempty subset -- see
// validator::DelegationScopePolicy's doc comment for provenance: this is a
// NEW integration clause, not a citation from the frozen B-SESSAO v6 wire
// schema, which declares both fields as open lists.

fn mesh_session_generation_record(d: Delegation, b: ExactBinding) -> GenerationRecord {
    GenerationRecord {
        generation: NonZeroU64::new(1).unwrap(),
        delegation: d,
        binding: b,
        not_after: 100,
    }
}

#[test]
fn mesh_session_delegation_roles_subset_is_rejected() {
    let s = slot(NonZeroU64::new(1).unwrap(), [120; 16]);
    let b = binding(s.clone());
    let mut d = delegation(0, 100);
    d.delegated_key_id = s.canonical_id();
    d.delegated_pub = b.public_key.clone();
    d.roles = vec!["initiator".into()]; // missing "responder"
    let policy = DelegationPolicy::test(1000);
    let err = validate_full_binding::<MeshSessionPurpose>(
        &mesh_session_generation_record(d, b),
        &ctx(),
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .unwrap_err();
    assert_eq!(err, ValidationError::RoleScopeMismatch);
}

#[test]
fn mesh_session_delegation_roles_extra_is_rejected() {
    let s = slot(NonZeroU64::new(1).unwrap(), [121; 16]);
    let b = binding(s.clone());
    let mut d = delegation(0, 100);
    d.delegated_key_id = s.canonical_id();
    d.delegated_pub = b.public_key.clone();
    d.roles = vec!["initiator".into(), "responder".into(), "observer".into()]; // extra beyond the ratified scope
    let policy = DelegationPolicy::test(1000);
    let err = validate_full_binding::<MeshSessionPurpose>(
        &mesh_session_generation_record(d, b),
        &ctx(),
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .unwrap_err();
    assert_eq!(err, ValidationError::RoleScopeMismatch);
}

#[test]
fn mesh_session_delegation_roles_duplicate_is_rejected() {
    let s = slot(NonZeroU64::new(1).unwrap(), [122; 16]);
    let b = binding(s.clone());
    let mut d = delegation(0, 100);
    d.delegated_key_id = s.canonical_id();
    d.delegated_pub = b.public_key.clone();
    // Same length as the ratified scope, but "responder" is missing and
    // "initiator" is duplicated -- must be rejected on the duplicate check,
    // never silently collapsed to a set and treated as valid.
    d.roles = vec!["initiator".into(), "initiator".into()];
    let policy = DelegationPolicy::test(1000);
    let err = validate_full_binding::<MeshSessionPurpose>(
        &mesh_session_generation_record(d, b),
        &ctx(),
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .unwrap_err();
    assert_eq!(err, ValidationError::RoleScopeMismatch);
}

#[test]
fn mesh_session_delegation_transcript_kinds_subset_is_rejected() {
    let s = slot(NonZeroU64::new(1).unwrap(), [123; 16]);
    let b = binding(s.clone());
    let mut d = delegation(0, 100);
    d.delegated_key_id = s.canonical_id();
    d.delegated_pub = b.public_key.clone();
    d.transcript_kinds = vec!["final-confirm".into(), "activate".into()]; // missing "activate-ack"
    let policy = DelegationPolicy::test(1000);
    let err = validate_full_binding::<MeshSessionPurpose>(
        &mesh_session_generation_record(d, b),
        &ctx(),
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .unwrap_err();
    assert_eq!(err, ValidationError::TranscriptKindsScopeMismatch);
}

#[test]
fn mesh_session_delegation_channel_mismatch_is_rejected() {
    let s = slot(NonZeroU64::new(1).unwrap(), [124; 16]);
    let b = binding(s.clone());
    let mut d = delegation(0, 100);
    d.delegated_key_id = s.canonical_id();
    d.delegated_pub = b.public_key.clone();
    d.channel = Channel::Release; // ctx() below is Dev
    let policy = DelegationPolicy::test(1000);
    let err = validate_full_binding::<MeshSessionPurpose>(
        &mesh_session_generation_record(d, b),
        &ctx(),
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .unwrap_err();
    assert_eq!(err, ValidationError::ChannelMismatch);
}

#[test]
fn mesh_session_delegation_exact_scope_is_accepted() {
    // POS: the default fixture's roles/transcript_kinds are exactly the
    // ratified scope -- confirms the exact-match case itself is accepted,
    // not just that deviations are rejected.
    let s = slot(NonZeroU64::new(1).unwrap(), [125; 16]);
    let b = binding(s.clone());
    let mut d = delegation(0, 100);
    d.delegated_key_id = s.canonical_id();
    d.delegated_pub = b.public_key.clone();
    assert_eq!(d.roles, vec!["initiator", "responder"]);
    assert_eq!(
        d.transcript_kinds,
        vec!["final-confirm", "activate", "activate-ack"]
    );
    let policy = DelegationPolicy::test(1000);
    validate_full_binding::<MeshSessionPurpose>(
        &mesh_session_generation_record(d, b),
        &ctx(),
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .expect("the exact ratified scope must be accepted");
}

// ── A1: cell registry must validate identity/purpose on reuse, not hand
// back a live cell for a mismatched request ──────────────────────────────

#[test]
fn cell_open_rejects_reuse_of_a_live_path_for_a_different_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let _cell_a = test_cell(path.clone()); // held alive for the whole test
    let mut other = identity();
    other.hh_id = "hh_other".into();
    match cell::open(
        path,
        other,
        PurposeId::MeshSession,
        Arc::new(OrderSpy::new()),
    ) {
        Err(e) => assert_eq!(e, OpenConflict),
        Ok(_) => panic!("expected OpenConflict on identity mismatch"),
    }
}

#[test]
fn cell_open_rejects_reuse_of_a_live_path_for_a_different_purpose() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let _cell_a = test_cell(path.clone());
    match cell::open(
        path,
        identity(),
        PurposeId::RosterSync,
        Arc::new(OrderSpy::new()),
    ) {
        Err(e) => assert_eq!(e, OpenConflict),
        Ok(_) => panic!("expected OpenConflict on purpose mismatch"),
    }
}

// ── A2: FaultInjectingStore goes through its own registry too ───────────

#[test]
fn open_fault_injecting_reuses_the_same_pair_and_rejects_identity_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let cell_a = cell::open_fault_injecting(
        path.clone(),
        identity(),
        PurposeId::MeshSession,
        Arc::new(OrderSpy::new()),
    )
    .unwrap();
    let cell_b = cell::open_fault_injecting(
        path.clone(),
        identity(),
        PurposeId::MeshSession,
        Arc::new(OrderSpy::new()),
    )
    .unwrap();
    assert!(
        Arc::ptr_eq(&cell_a, &cell_b),
        "same path, same identity/purpose, still live -- must reuse the same pair"
    );

    let mut other = identity();
    other.hh_id = "hh_other".into();
    match cell::open_fault_injecting(
        path,
        other,
        PurposeId::MeshSession,
        Arc::new(OrderSpy::new()),
    ) {
        Err(e) => assert_eq!(e, OpenConflict),
        Ok(_) => panic!("expected OpenConflict on identity mismatch"),
    }
}

// ── B5: KeyObserved's binding must be for the pending op's OWN slot; the
// fake backend must reject an expected_binding whose own .slot disagrees
// with the key it is being stored under ─────────────────────────────────

#[test]
fn key_observed_rejects_a_binding_whose_slot_does_not_match_the_pending_ops_canonical_slot() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [8; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();

    // A binding for an unrelated slot -- different generation, so its
    // canonical_id() differs from p.canonical_slot's.
    let wrong_slot = slot(NonZeroU64::new(999).unwrap(), [9; 16]);
    let err = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: binding(wrong_slot),
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::BindingSlotMismatch);
}

#[test]
fn fake_secret_backend_rejects_an_expected_binding_whose_own_slot_disagrees_with_the_key() {
    let backend = FakeSecretBackend::new();
    let target_slot = slot(NonZeroU64::new(1).unwrap(), [30; 16]);
    let mismatched_binding = binding(slot(NonZeroU64::new(2).unwrap(), [31; 16])); // .slot claims a DIFFERENT slot
    let outcome = backend.create_or_inspect(&target_slot, Some(&mismatched_binding));
    assert_eq!(outcome, CreateOutcome::Conflict);
}

// ── D9: idempotent replay compares the FULL request, not just the outcome
// variant; IntentRecorded/ReactivateFromRevoked reject reusing a txn_id
// that already has a terminal result; a self-colliding
// txn_id/next_txn_id pair is structurally safe, not silently corrupting ──

#[test]
fn activate_replay_with_a_different_delegation_for_the_same_txn_id_fails_closed() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [7; 16],
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

    let mut d1 = delegation(0, 100);
    d1.delegated_key_id = p.canonical_slot.canonical_id();
    d1.delegated_pub = binding(p.canonical_slot.clone()).public_key;
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
            delegation: d1.clone(),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();

    // A retry of the SAME txn_id but with a DIFFERENT delegation (here:
    // different not_after) must be rejected, never silently accepted as
    // "the same replay" via a wildcard match on just the outcome variant.
    let mut d2 = d1.clone();
    d2.not_after = 200;
    let err = apply(
        &activated,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: activated.revision,
            delegation: d2,
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::TerminalTxnReused);

    // Meanwhile the TRUE replay (byte-identical request) must still
    // succeed as a no-op, proving this isn't just "reject everything."
    let replayed = apply(
        &activated,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: activated.revision,
            delegation: d1,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert_eq!(replayed, activated);
}

#[test]
fn intent_recorded_rejects_reuse_of_a_txn_id_with_an_existing_terminal_result() {
    let mut old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    old.recent_terminal_results = vec![TerminalResult {
        txn_id: [55; 16],
        outcome: TerminalOutcome::Revoked {
            epoch: NonZeroU64::new(2).unwrap(),
        },
        request: TerminalRequestFingerprint::Revoke {
            reason: RevocationReason::Compromised,
        },
        recorded_at: 10,
        acked: false,
    }];
    // authority stays Empty (bootstrap default) so (Empty, Create) is
    // otherwise a perfectly valid authority/kind pair -- the ONLY thing
    // that must reject this is the txn_id reuse.
    let err = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [55; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::TerminalTxnReused);
}

#[test]
fn reactivate_self_colliding_txn_id_blocks_the_new_pendings_own_later_activation() {
    // Not an explicit up-front check inside ReactivateFromRevoked itself
    // (nothing there compares txn_id to next_txn_id) -- but proven here to
    // be structurally safe anyway: reusing the revoke-action's own txn_id
    // as the new pending op's txn_id records a `Reactivated` terminal
    // result under that id, and the later Activate attempt on the SAME id
    // then hits idempotent_replay against that (different-shaped) request
    // and fails closed, instead of silently completing or corrupting
    // state.
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let revoked = apply(
        &old,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [1; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();

    let colliding = [200; 16];
    let reactivated = apply(
        &revoked,
        &RecordTransition::ReactivateFromRevoked {
            txn_id: colliding,
            next_txn_id: colliding, // deliberately identical to the action's own txn_id
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
            .any(|r| r.txn_id == colliding
                && matches!(r.outcome, TerminalOutcome::Reactivated { .. }))
    );
    let p = reactivated.pending_op.clone().unwrap();
    assert_eq!(p.txn_id, colliding);

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

    let mut d = delegation(0, 100);
    d.delegated_key_id = p.canonical_slot.canonical_id();
    d.delegated_pub = binding(p.canonical_slot.clone()).public_key;
    let err = apply(
        &with_binding,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_binding.revision,
            delegation: d,
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(
        err,
        TransitionError::TerminalTxnReused,
        "the colliding txn_id already has a Reactivated terminal result with a different request shape, so Activate must fail closed rather than silently completing"
    );
}

// ── D10: RevokeUrgent must never be blockable by terminal-result retention
// capacity, even when every existing entry is unacked ───────────────────

#[test]
fn revoke_urgent_still_commits_when_terminal_retention_is_full_of_unacked_entries() {
    let mut old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    old.recent_terminal_results = (0u8..MAX_RECENT_TERMINAL_RESULTS as u8)
        .map(|i| TerminalResult {
            txn_id: [i; 16],
            outcome: TerminalOutcome::Revoked {
                epoch: NonZeroU64::new(2).unwrap(),
            },
            request: TerminalRequestFingerprint::Revoke {
                reason: RevocationReason::Lost,
            },
            recorded_at: i as u64,
            acked: false, // every entry unacked -- ordinary push_bounded_terminal fails closed here
        })
        .collect();
    assert_eq!(
        old.recent_terminal_results.len(),
        MAX_RECENT_TERMINAL_RESULTS
    );

    let new_txn_id = [0xEE; 16];
    let new = apply(
        &old,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: new_txn_id,
        },
        1000,
        TEST_CAP,
    )
    .expect(
        "RevokeUrgent must never fail closed due to retention capacity, even when every existing entry is unacked",
    );
    assert_eq!(
        new.recent_terminal_results.len(),
        MAX_RECENT_TERMINAL_RESULTS,
        "still bounded -- the oldest entry was force-evicted, not appended without limit"
    );
    assert!(
        new.recent_terminal_results
            .iter()
            .any(|r| r.txn_id == new_txn_id),
        "the new urgent revoke's own terminal result must be present"
    );
    assert!(
        !new.recent_terminal_results
            .iter()
            .any(|r| r.txn_id == [0; 16]),
        "the oldest entry ([0;16]) must have been force-evicted to make room"
    );
}

// ── D11: an already-Quarantine entry must never be silently overwritten by
// a later GcResolved; GcSerialLock now belongs to the cell, so two ticks
// against the SAME cell genuinely serialize ──────────────────────────────

#[test]
fn gc_resolved_never_overwrites_an_already_quarantined_entry() {
    let s = slot(NonZeroU64::new(1).unwrap(), [40; 16]);
    let b = binding(s.clone());
    let old = record_with_gc_entries(vec![GcEntry::Bound {
        slot: s.clone(),
        txn_id: [40; 16],
        binding: b,
        state: GcState::Quarantine,
    }]);
    let err = apply(
        &old,
        &RecordTransition::GcResolved {
            slot_id: s.canonical_id(),
            residual_zero: true,
            quarantine: false,
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::WrongPhase);
}

#[test]
fn gc_serial_is_owned_by_the_cell_so_two_ticks_against_the_same_cell_serialize() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();

    let g1 = cell.acquire_gc_serial();
    let c2 = Arc::clone(&cell);
    let handle = std::thread::spawn(move || {
        let _g2 = c2.acquire_gc_serial();
        acquired_tx.send(()).unwrap();
    });
    // A short timeout proves the second acquire is genuinely BLOCKED (not
    // just "hasn't run yet"): recv_timeout returning Timeout here, then
    // succeeding immediately after g1 is dropped, is the same non-flaky
    // pattern this suite already uses for the opposite property (see
    // activate_does_not_block_a_concurrent_urgent_revoke_during_slow_roster_lookup).
    assert_eq!(
        acquired_rx.recv_timeout(std::time::Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        "a second gc_serial acquire on the SAME cell must block while the first is held"
    );
    drop(g1);
    acquired_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("must acquire promptly once released");
    handle.join().unwrap();
}

// ── Round 6, item 3: SlotId::canonical_id -- distinct "mesh-slot.v1."
// namespace (never the keystore's own internal "p256.v1." account
// coordinate), fixed-width, well under the keystore integration's
// tested 128-byte bound ──────────────────────────────────────────────────

#[test]
fn canonical_id_matches_a_golden_vector() {
    // Locks the exact algorithm (BLAKE3 over 8-byte-LE-length-prefixed
    // identity_digest/purpose/generation/txn_id/backend, "mesh-slot.v1."
    // prefix) against silent drift -- computed once from the real
    // implementation, not hand-derived.
    let s = SlotId {
        identity_digest: [7u8; 32],
        purpose: PurposeId::MeshSession,
        generation: NonZeroU64::new(1).unwrap(),
        txn_id: [0xAB; 16],
        backend_instance: BackendKind::SecureEnclave,
    };
    assert_eq!(
        s.canonical_id(),
        "mesh-slot.v1.4085288b37d50cc619697ffa77e1b9615bbeaca768162d6609b679dec205faee"
    );
}

#[test]
fn canonical_id_is_fixed_width_and_under_the_128_byte_keystore_bound() {
    for purpose in [PurposeId::MeshSession, PurposeId::RosterSync] {
        for backend_instance in [
            BackendKind::SecureEnclave,
            BackendKind::TpmSealedSoftware,
            BackendKind::File,
        ] {
            let s = SlotId {
                identity_digest: [0xFF; 32], // worst-case byte value, not that it matters for a fixed-width digest
                purpose,
                generation: NonZeroU64::new(u64::MAX).unwrap(),
                txn_id: [0xFF; 16],
                backend_instance,
            };
            let id = s.canonical_id();
            assert_eq!(
                id.len(),
                77,
                "\"mesh-slot.v1.\" (13) + 64 hex chars must be exactly 77 bytes regardless of field values"
            );
            assert!(
                id.len() <= 128,
                "must stay under the keystore integration's own tested 128-byte bound"
            );
            assert!(
                id.starts_with("mesh-slot.v1."),
                "must never collide with the keystore's own internal \"p256.v1.\" account namespace"
            );
        }
    }
}

#[test]
fn canonical_id_distinguishes_slots_that_differ_only_by_generation_or_txn_id() {
    let base = slot(NonZeroU64::new(1).unwrap(), [10; 16]);
    let mut other_generation = base.clone();
    other_generation.generation = NonZeroU64::new(2).unwrap();
    assert_ne!(base.canonical_id(), other_generation.canonical_id());

    let mut other_txn = base.clone();
    other_txn.txn_id = [11; 16];
    assert_ne!(base.canonical_id(), other_txn.canonical_id());
}

// ══════════════════════════════════════════════════════════════════════
// Round 6 REDs -- second and third audit waves on bef34379.
// ══════════════════════════════════════════════════════════════════════

// ── wave 2, item 1: generation must not reset after revoke; defense in
// depth against a derived slot colliding with an unresolved GC entry ────

#[test]
fn generation_continues_incrementing_after_revoke_not_reset_to_one() {
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
    assert_eq!(activated.generation_high_water, NonZeroU64::new(1).unwrap());

    let revoked = apply(
        &activated,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [2; 16],
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(revoked.current_generation.is_none());
    assert!(revoked.live_generations.is_empty());

    let reactivated = apply(
        &revoked,
        &RecordTransition::ReactivateFromRevoked {
            txn_id: [3; 16],
            next_txn_id: [4; 16],
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p2 = reactivated.pending_op.clone().unwrap();
    assert_eq!(
        p2.generation,
        NonZeroU64::new(2).unwrap(),
        "must continue the monotonic sequence from generation_high_water, never reset to 1 just because current_generation was legitimately cleared by revoke"
    );
}

#[test]
fn intent_recorded_rejects_a_derived_slot_that_collides_with_an_unresolved_gc_entry() {
    let mut old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let would_derive = SlotId {
        identity_digest: identity_digest(&old.identity),
        purpose: PurposeId::MeshSession,
        generation: NonZeroU64::new(1).unwrap(),
        txn_id: [9; 16],
        backend_instance: BackendKind::File,
    };
    old.gc_pending.push(GcEntry::AwaitingInspection {
        slot: would_derive,
        txn_id: [9; 16],
    });
    let err = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [9; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap_err();
    assert_eq!(err, TransitionError::SlotCollidesWithPendingGc);
}

// ── wave 2, item 2: a Bound entry gets at most one destroy attempt per
// tick, even when the backend never resolves it ──────────────────────────

struct AlwaysResidualBackend {
    inner: FakeSecretBackend,
    calls: std::sync::atomic::AtomicU64,
}
impl SecretBackend for AlwaysResidualBackend {
    fn create_or_inspect(&self, slot: &SlotId, expected: Option<&ExactBinding>) -> CreateOutcome {
        self.inner.create_or_inspect(slot, expected)
    }
    fn load_exact(&self, slot: &SlotId, expected_public_key: &[u8]) -> LoadExactOutcome {
        self.inner.load_exact(slot, expected_public_key)
    }
    fn inspect(&self, slot: &SlotId) -> InspectOutcome {
        self.inner.inspect(slot)
    }
    fn gc_best_effort(&self, _slot: &SlotId, _expected_binding: &ExactBinding) -> GcReport {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        GcReport {
            attempted: true,
            residual: true,
            observation_complete: true,
            mismatch: false,
        }
    }
}

#[test]
fn gc_bound_entry_gets_at_most_one_destroy_attempt_per_tick_even_when_backend_never_resolves() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let s = slot(NonZeroU64::new(1).unwrap(), [50; 16]);
    let rec = record_with_gc_entries(vec![GcEntry::Bound {
        slot: s.clone(),
        txn_id: [50; 16],
        binding: binding(s.clone()),
        state: GcState::Pending,
    }]);
    seed_record(&cell, &rec);
    let backend = AlwaysResidualBackend {
        inner: FakeSecretBackend::new(),
        calls: std::sync::atomic::AtomicU64::new(0),
    };

    let resolved = gc_worker_tick(&cell, &backend, 1000, TEST_CAP).unwrap();
    // `resolved` counts commits, not terminal resolutions -- a residual
    // report still commits a (Pending -> Pending) GcResolved, so this is 1,
    // not 0. The property under test is the call count below: the entry
    // stays Pending forever if the backend never stops reporting residual,
    // so without the fix this tick would never terminate at all.
    assert_eq!(resolved, 1);
    assert_eq!(
        backend.calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a Bound entry must get at most one destroy attempt per tick, not be reselected in a tight loop within the same call"
    );
}

// ── wave 2/4/6, item 3: activate must reject if roster currency changed
// before the lease could be granted, and a real lease genuinely blocks a
// conflicting roster-side mutation until it is released -- not just a
// bare revision-number recheck (this crate's own two prior attempts) ────

/// Round 6, wave 6 (rebuilt in wave 8): replaces the obsolete
/// `RevisionBumpingBlockingRoster`, which only re-checked a bare number
/// and enforced nothing.
///
/// Two SEPARATE locks, deliberately:
/// - `mutation` is taken by `acquire_currency_lease` and held for the
///   lease's entire lifetime, and is also what `revoke_on_roster_side`
///   needs -- so a held lease genuinely, mechanically blocks a roster-side
///   revoke rather than merely failing to notice one.
/// - `currency` covers the cheap reads (`query_machine_currency`,
///   `currency_revision`) and is released immediately.
///
/// Wave 8: these were ONE lock, which made a held lease also block every
/// plain currency read. That masked the lock-order cycle the deadlock
/// tests below exist to detect -- a thread blocked in step 1's roster
/// query never reaches the acquisition order under test at all, so the
/// cycle could never form and the test passed against deliberately
/// inverted code. A real roster blocks conflicting MUTATIONS while a
/// lease is out; it does not stop the world.
struct LeaseEnforcingRoster {
    // Optional rendezvous hook so a test can pause a caller inside
    // query_machine_currency (reached from validate_full_binding, AFTER
    // currency_revision_before was captured but BEFORE
    // acquire_currency_lease runs) to deterministically land a roster-side
    // change in that exact window.
    sync: Option<RosterSync>,
    // Optional rendezvous hook that fires once, immediately AFTER a lease
    // is granted and while it is still held -- lets a test pin one thread
    // in the "holds the roster lease, has not yet taken the cell guard"
    // state that the lock-order cycle needs.
    lease_sync: Option<RosterSync>,
    currency: Mutex<RosterLeaseState>,
    mutation: Mutex<()>,
}
struct RosterSync {
    ready_tx: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    proceed_rx: Mutex<std::sync::mpsc::Receiver<()>>,
}
impl RosterSync {
    /// Announce arrival, then park until released. Fires at most once.
    fn rendezvous(&self) {
        if let Some(tx) = self.ready_tx.lock().unwrap().take() {
            let _ = tx.send(());
            self.proceed_rx.lock().unwrap().recv().unwrap();
        }
    }
}
struct RosterLeaseState {
    currency: RosterCurrency,
    revision: u64,
}
// Held only for its Drop (releases `mutation`); never read.
#[allow(dead_code)]
struct HeldRosterLease<'a>(std::sync::MutexGuard<'a, ()>);
impl CurrencyLease for HeldRosterLease<'_> {}

impl LeaseEnforcingRoster {
    fn new(
        member_pub: Vec<u8>,
        member_cert_fingerprint: [u8; 32],
        sync: Option<RosterSync>,
        lease_sync: Option<RosterSync>,
    ) -> Self {
        Self {
            sync,
            lease_sync,
            currency: Mutex::new(RosterLeaseState {
                currency: RosterCurrency::Active {
                    member_pub,
                    member_cert_fingerprint,
                },
                revision: 0,
            }),
            mutation: Mutex::new(()),
        }
    }

    fn active(member_pub: Vec<u8>, member_cert_fingerprint: [u8; 32]) -> Self {
        Self::new(member_pub, member_cert_fingerprint, None, None)
    }

    fn active_blocking(
        member_pub: Vec<u8>,
        member_cert_fingerprint: [u8; 32],
        ready_tx: std::sync::mpsc::Sender<()>,
        proceed_rx: std::sync::mpsc::Receiver<()>,
    ) -> Self {
        Self::new(
            member_pub,
            member_cert_fingerprint,
            Some(RosterSync {
                ready_tx: Mutex::new(Some(ready_tx)),
                proceed_rx: Mutex::new(proceed_rx),
            }),
            None,
        )
    }

    /// Parks the first caller that is granted a lease, while it still
    /// holds that lease -- see `lease_sync`.
    fn active_parking_the_first_lease(
        member_pub: Vec<u8>,
        member_cert_fingerprint: [u8; 32],
        ready_tx: std::sync::mpsc::Sender<()>,
        proceed_rx: std::sync::mpsc::Receiver<()>,
    ) -> Self {
        Self::new(
            member_pub,
            member_cert_fingerprint,
            None,
            Some(RosterSync {
                ready_tx: Mutex::new(Some(ready_tx)),
                proceed_rx: Mutex::new(proceed_rx),
            }),
        )
    }

    /// Blocks for as long as any lease is outstanding -- see the struct
    /// doc comment.
    fn revoke_on_roster_side(&self) {
        let _mutation = self.mutation.lock().unwrap();
        let mut c = self.currency.lock().unwrap();
        c.currency = RosterCurrency::Revoked;
        c.revision += 1;
    }

    /// Simulates a roster-side change to a *different* machine bumping the
    /// shared monotonic revision counter (see `RosterLookup::currency_revision`'s
    /// doc comment) without touching this machine's own currency -- unlike
    /// `revoke_on_roster_side`, `query_machine_currency` still reports
    /// `Active` afterward, so `validate_full_binding` still passes and the
    /// rejection this simulates can only be caught by
    /// `acquire_currency_lease`'s own revision check, not by
    /// `ValidationError::DelegatorRevoked`.
    fn bump_revision_for_an_unrelated_change(&self) {
        self.currency.lock().unwrap().revision += 1;
    }
}
impl RosterLookup for LeaseEnforcingRoster {
    fn query_machine_currency(&self, _machine_id: &str) -> RosterCurrency {
        if let Some(sync) = &self.sync {
            sync.rendezvous();
        }
        self.currency.lock().unwrap().currency.clone()
    }
    fn currency_revision(&self, _machine_id: &str) -> u64 {
        self.currency.lock().unwrap().revision
    }
    fn acquire_currency_lease(
        &self,
        _machine_id: &str,
        expected_revision: u64,
    ) -> Result<Box<dyn CurrencyLease + '_>, RosterChanged> {
        let mutation = self.mutation.lock().unwrap();
        if self.currency.lock().unwrap().revision != expected_revision {
            return Err(RosterChanged);
        }
        // Still holding `mutation` -- a test that parks here pins this
        // caller in the "has the roster lease, has not yet taken any cell
        // guard" state.
        if let Some(lease_sync) = &self.lease_sync {
            lease_sync.rendezvous();
        }
        Ok(Box::new(HeldRosterLease(mutation)))
    }
}

#[test]
fn roster_lease_genuinely_blocks_a_concurrent_revoke_until_dropped() {
    // Direct, deterministic proof of the MECHANISM itself (not threaded
    // through activate_from_key_observed, which would add unrelated
    // timing noise to what this specifically needs to prove): a held
    // lease REALLY blocks a conflicting roster-side mutation, using the
    // same recv_timeout non-flaky pattern this suite already uses for the
    // analogous gc_serial_is_owned_by_the_cell test.
    let roster = LeaseEnforcingRoster::active(vec![1, 2, 3], [9u8; 32]);
    let lease = roster.acquire_currency_lease("m_test", 0).unwrap();

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let roster_ref = &roster;
        scope.spawn(move || {
            roster_ref.revoke_on_roster_side();
            done_tx.send(()).unwrap();
        });
        assert_eq!(
            done_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "a roster-side revoke must be genuinely blocked while a lease is outstanding"
        );
        drop(lease);
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("must proceed promptly once the lease is released");
    });
    assert_eq!(roster.currency.lock().unwrap().revision, 1);
}

#[test]
fn activate_rejects_when_roster_already_changed_before_the_lease_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
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
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &old),
            ReplaceOutcome::Committed
        );
        assert_eq!(
            cell.seed_for_test(&g, old.revision, &with_intent),
            ReplaceOutcome::Committed
        );
        assert_eq!(
            cell.seed_for_test(&g, with_intent.revision, &with_binding),
            ReplaceOutcome::Committed
        );
    }

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
    // currency_revision_before is captured BEFORE validate_full_binding runs,
    // so the roster-side change has to land inside query_machine_currency
    // (which validate_full_binding calls) to fall in the exact
    // captured-revision -> acquire_currency_lease window this test needs to
    // prove is closed.
    let roster =
        LeaseEnforcingRoster::active_blocking(vec![1, 2, 3], [9u8; 32], ready_tx, proceed_rx);
    let policy = DelegationPolicy::test(1000);
    let mut d = delegation(0, 100);
    d.delegated_key_id = p.canonical_slot.canonical_id();
    d.delegated_pub = real_binding.public_key.clone();

    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            activate_from_key_observed::<MeshSessionPurpose>(
                &cell,
                &backend,
                &roster,
                &AlwaysTrueVerifier,
                &policy,
                p.txn_id,
                d,
                50,
                TEST_CAP,
            )
        });
        ready_rx.recv().unwrap(); // activate is now inside query_machine_currency
        roster.bump_revision_for_an_unrelated_change(); // lands after currency_revision_before was captured; currency itself stays Active
        proceed_tx.send(()).unwrap(); // let query_machine_currency return (still Active, stale answer)
        let result = handle.join().unwrap();
        assert!(
            matches!(
                result,
                Err(ActivateError::Validation(
                    ValidationError::RosterChangedDuringActivation
                ))
            ),
            "got {result:?}"
        );
    });

    // Zero commits: the record must be exactly as it was before the
    // rejected activation attempt.
    let LoadOutcome::Exact(still_pending) = cell.load_canonical_for_test() else {
        panic!("record must still be present")
    };
    assert_eq!(*still_pending, with_binding);
}

// ── wave 2, item 4: ControlRecordCell::commit must reject
// ActivateFromKeyObserved directly ────────────────────────────────────────

#[test]
fn commit_rejects_activate_from_key_observed_directly() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    {
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &old),
            ReplaceOutcome::Committed
        );
    }
    let t = RecordTransition::ActivateFromKeyObserved {
        expected_txn_id: [1; 16],
        expected_kind: PendingOpKind::Create,
        expected_generation: NonZeroU64::new(1).unwrap(),
        expected_epoch: NonZeroU64::new(1).unwrap(),
        expected_purpose: PurposeId::MeshSession,
        expected_slot_id: "bogus".into(),
        expected_revision: old.revision,
        delegation: delegation(0, 100),
    };
    let err = cell.commit(&t, 50, TEST_CAP).unwrap_err();
    assert!(matches!(err, CommitTransitionError::PrivilegedTransition));
}

// ── wave 3, item 3: cap must only block growth, never a cap-neutral or
// cap-reducing transition, even when already at/over a lowered cap ──────

#[test]
fn revoke_urgent_succeeds_even_when_max_cap_was_lowered_below_current_occupancy() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [80; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        8,
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
        8,
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
        8,
    )
    .unwrap();
    assert_eq!(activated.cap_occupancy(), 1);

    // max_cap is now LOWER than current occupancy (simulating a config
    // change) -- an absolute check would reject EVERYTHING, including
    // RevokeUrgent, which is cap-neutral (see its own doc comment).
    let lowered_cap = 0;
    let revoked = apply(
        &activated,
        &RecordTransition::RevokeUrgent {
            reason: RevocationReason::Compromised,
            txn_id: [81; 16],
        },
        1000,
        lowered_cap,
    )
    .expect(
        "cap-neutral RevokeUrgent must succeed even when max_cap was lowered below current occupancy",
    );
    assert_eq!(
        revoked.cap_occupancy(),
        activated.cap_occupancy(),
        "cap-neutral, confirmed"
    );

    let gc_entry_slot = revoked.gc_pending[0].slot().canonical_id();
    let resolved = apply(
        &revoked,
        &RecordTransition::GcResolved {
            slot_id: gc_entry_slot,
            residual_zero: true,
            quarantine: false,
        },
        1000,
        lowered_cap,
    )
    .expect("cap-reducing GcResolved must succeed even under a lowered cap");
    assert!(resolved.cap_occupancy() < revoked.cap_occupancy());
}

// ── wave 3, item 4: load_canonical rejects a CBOR-valid but semantically
// inconsistent record ─────────────────────────────────────────────────────

#[test]
fn load_canonical_rejects_a_cbor_valid_but_semantically_inconsistent_record() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let mut corrupt = bootstrap.clone();
    corrupt.revision = bootstrap.revision + 1;
    // Active authority with no current_generation -- apply() would never
    // produce this; only a hand-corrupted file can.
    corrupt.authority = Authority::Active;
    {
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
        assert_eq!(
            cell.seed_for_test(&g, bootstrap.revision, &corrupt),
            ReplaceOutcome::Committed,
            "the store's CAS/genesis checks don't validate semantic invariants -- only load_canonical does"
        );
    }
    assert_eq!(cell.load_canonical_for_test(), LoadOutcome::Corrupt);
}

// ── wave 3, item 5: revalidate_on_load detects physical key replacement ──

#[test]
fn revalidate_on_load_detects_physical_key_replacement() {
    let rotated = rotated_record_with_two_generations(5000, 6000);
    let backend = FakeSecretBackend::new();
    for g in &rotated.live_generations {
        backend.create_or_inspect(&g.binding.slot, Some(&g.binding));
    }
    // Simulate physical tampering: the backend's item at this slot is
    // replaced with a different public key, entirely outside this
    // record's own state machine.
    let tampered_slot = rotated.live_generations[0].binding.slot.clone();
    let mut tampered_binding = rotated.live_generations[0].binding.clone();
    tampered_binding.public_key = vec![0xDE, 0xAD, 0xBE, 0xEF];
    backend.gc_best_effort(&tampered_slot, &rotated.live_generations[0].binding);
    backend.create_or_inspect(&tampered_slot, Some(&tampered_binding));

    let policy = DelegationPolicy::test(10_000);
    let err = revalidate_on_load::<MeshSessionPurpose>(
        &rotated,
        &backend,
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .unwrap_err();
    assert_eq!(err, ValidationError::PhysicalKeyNotConfirmed);
}

// ══════════════════════════════════════════════════════════════════════
// Round 6, wave 4 -- read-only audit against the WIP successor.
// ══════════════════════════════════════════════════════════════════════

// ── item 1: commit()/commit_built() must reject every Gc* transition
// directly, not just ActivateFromKeyObserved -- otherwise a caller can
// forge "the backend confirmed a clean destroy" with no backend at all ──

#[test]
fn commit_rejects_every_gc_transition_directly() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let s = slot(NonZeroU64::new(1).unwrap(), [90; 16]);
    let b = binding(s.clone());
    let rec = record_with_gc_entries(vec![GcEntry::Bound {
        slot: s.clone(),
        txn_id: [90; 16],
        binding: b,
        state: GcState::Pending,
    }]);
    seed_record(&cell, &rec);

    for t in [
        RecordTransition::GcInspected {
            slot_id: s.canonical_id(),
            found: None,
        },
        RecordTransition::GcInspectionConflict {
            slot_id: s.canonical_id(),
        },
        RecordTransition::GcResolved {
            slot_id: s.canonical_id(),
            residual_zero: true,
            quarantine: false,
        },
        RecordTransition::GcRemoval {
            slot_id: s.canonical_id(),
            txn_id: [90; 16],
        },
    ] {
        let err = cell.commit(&t, 1000, TEST_CAP).unwrap_err();
        assert!(
            matches!(err, CommitTransitionError::PrivilegedTransition),
            "got {err:?}"
        );
    }
}

#[test]
fn public_gc_bypass_cannot_forge_a_clean_destroy_and_erase_the_marker() {
    // The exact exploit chain from the audit: commit(GcResolved{clean})
    // followed by GcRemoval, with no SecretBackend ever consulted, used
    // to be able to erase a live-key GC marker entirely.
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let s = slot(NonZeroU64::new(1).unwrap(), [91; 16]);
    let b = binding(s.clone());
    let rec = record_with_gc_entries(vec![GcEntry::Bound {
        slot: s.clone(),
        txn_id: [91; 16],
        binding: b,
        state: GcState::Pending,
    }]);
    seed_record(&cell, &rec);

    let resolve_err = cell
        .commit(
            &RecordTransition::GcResolved {
                slot_id: s.canonical_id(),
                residual_zero: true,
                quarantine: false,
            },
            1000,
            TEST_CAP,
        )
        .unwrap_err();
    assert!(matches!(
        resolve_err,
        CommitTransitionError::PrivilegedTransition
    ));

    // The marker must still be there, untouched, exactly as seeded.
    let LoadOutcome::Exact(still_there) = cell.load_canonical_for_test() else {
        panic!("expected record")
    };
    assert_eq!(still_there.gc_pending.len(), 1);
    match &still_there.gc_pending[0] {
        GcEntry::Bound { state, .. } => assert_eq!(*state, GcState::Pending),
        other => panic!("unexpected: {other:?}"),
    }
}

// ── item 4 (wave 4): the generation_high_water reservation fix -- an
// in-flight RoutineRotate/Reactivate must pass invariants_hold, not be
// rejected as semantically corrupt (round 6's own regression, caught by
// kiana's independent audit before this successor froze) ────────────────

#[test]
fn invariants_hold_accepts_an_in_flight_routine_rotate() {
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
    assert!(activated.invariants_hold());

    let rotate_intent = apply(
        &activated,
        &RecordTransition::IntentRecorded {
            txn_id: [2; 16],
            kind: PendingOpKind::RoutineRotate,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p2 = rotate_intent.pending_op.clone().unwrap();
    assert_eq!(p2.generation, NonZeroU64::new(2).unwrap());
    assert_eq!(
        rotate_intent.generation_high_water,
        NonZeroU64::new(2).unwrap(),
        "reserved at Intent time, not left until Activate -- see transition::apply's IntentRecorded arm"
    );
    assert!(
        rotate_intent.invariants_hold(),
        "a legitimate in-flight RoutineRotate (pending.generation == generation_high_water) must pass -- this is the exact regression kiana's independent audit caught"
    );

    let rotate_key_observed = apply(
        &rotate_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p2.txn_id,
            expected_kind: p2.kind,
            expected_generation: p2.generation,
            expected_epoch: p2.epoch,
            expected_purpose: p2.purpose,
            expected_slot_id: p2.canonical_slot.canonical_id(),
            expected_revision: rotate_intent.revision,
            binding: binding(p2.canonical_slot.clone()),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(rotate_key_observed.invariants_hold());
}

// ── item 7 (wave 4): invariants_hold must also catch cross-purpose
// pending ops, foreign (non-derived) slots, and a GC binding whose own
// .slot disagrees with the entry it's filed under ────────────────────────

#[test]
fn invariants_hold_rejects_a_pending_op_with_the_wrong_purpose() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let mut with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [10; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(with_intent.invariants_hold());
    with_intent.pending_op.as_mut().unwrap().purpose = PurposeId::RosterSync;
    assert!(!with_intent.invariants_hold());
}

#[test]
fn invariants_hold_rejects_a_pending_op_with_a_foreign_canonical_slot() {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let mut with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [11; 16],
            kind: PendingOpKind::Create,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    assert!(with_intent.invariants_hold());
    // A slot that could never have been derived from this record's own
    // identity -- a foreign identity_digest.
    with_intent
        .pending_op
        .as_mut()
        .unwrap()
        .canonical_slot
        .identity_digest = [0xEE; 32];
    assert!(!with_intent.invariants_hold());
}

#[test]
fn invariants_hold_rejects_a_gc_bound_entry_whose_binding_slot_disagrees_with_its_own_slot() {
    let s = slot(NonZeroU64::new(1).unwrap(), [92; 16]);
    let foreign_binding = binding(slot(NonZeroU64::new(2).unwrap(), [93; 16]));
    let corrupt = record_with_gc_entries(vec![GcEntry::Bound {
        slot: s,
        txn_id: [92; 16],
        binding: foreign_binding,
        state: GcState::Pending,
    }]);
    assert!(!corrupt.invariants_hold());
}

#[test]
fn invariants_hold_rejects_duplicate_terminal_txn_ids() {
    let mut old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let one = TerminalResult {
        txn_id: [95; 16],
        outcome: TerminalOutcome::Revoked {
            epoch: NonZeroU64::new(2).unwrap(),
        },
        request: TerminalRequestFingerprint::Revoke {
            reason: RevocationReason::Compromised,
        },
        recorded_at: 0,
        acked: false,
    };
    old.recent_terminal_results = vec![one.clone(), one];
    assert!(!old.invariants_hold());
}

// ══════════════════════════════════════════════════════════════════════
// Round 6, wave 5 -- REAL cross-process CAS, via genuinely separate OS
// processes (see src/bin/cas_race_helper.rs). Threads within this one
// test process would all share the same process-local
// MeshSignerLocks/registry and so could never demonstrate what these
// tests demonstrate.
// ══════════════════════════════════════════════════════════════════════

/// Legacy unpinned spawn -- every worker commits from whatever revision it
/// happens to read, with its own txn_id and no barrier. Kept ONLY for the
/// fail-closed alias tests (where no worker gets far enough to commit at
/// all) and for the negative control that demonstrates why this shape
/// cannot support an exactly-one-commits assertion. See
/// `src/bin/cas_race_helper.rs`'s module doc.
fn run_cas_race_helper(record_path: &std::path::Path, worker_id: u8) -> std::process::Child {
    std::process::Command::new(env!("CARGO_BIN_EXE_cas_race_helper"))
        .arg(record_path)
        .arg(worker_id.to_string())
        .arg("unpinned")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn cas_race_helper")
}

/// Pinned spawn: every worker is handed the SAME `expected_revision` and
/// builds byte-identical content, then waits at `barrier_dir` until all
/// `total_workers` have arrived before attempting its CAS.
fn run_pinned_cas_race_helper(
    record_path: &std::path::Path,
    worker_id: u8,
    expected_revision: u64,
    barrier_dir: &std::path::Path,
    total_workers: usize,
) -> std::process::Child {
    std::process::Command::new(env!("CARGO_BIN_EXE_cas_race_helper"))
        .arg(record_path)
        .arg(worker_id.to_string())
        .arg("pinned")
        .arg(expected_revision.to_string())
        .arg(barrier_dir)
        .arg(total_workers.to_string())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn cas_race_helper")
}

fn wait_and_read_stdout(child: std::process::Child) -> String {
    let output = child.wait_with_output().unwrap();
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// Round 6, wave 8 (CFX-5). The predecessor of this test spawned six
/// unpinned workers and asserted exactly one committed -- an assertion
/// that did not follow from what the workers actually did, and that an
/// independent audit run caught failing (120 passed / 1 failed, two
/// COMMITTED). See `src/bin/cas_race_helper.rs`'s module doc for the full
/// account. Every worker here starts from the SAME pinned revision with
/// byte-identical content and only begins after all six have arrived at
/// the barrier, so exactly one CAS genuinely can win.
#[test]
fn six_real_processes_racing_one_pinned_revision_exactly_one_cas_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let barrier = dir.path().join("barrier");
    std::fs::create_dir(&barrier).unwrap();

    // Seed the genesis bootstrap for real, through this process's own
    // cell, before any race worker starts.
    let pinned_revision = {
        let cell = test_cell(path.clone());
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
        bootstrap.revision
    };

    let children: Vec<_> = (0u8..6)
        .map(|i| run_pinned_cas_race_helper(&path, i, pinned_revision, &barrier, 6))
        .collect();
    let outputs: Vec<String> = children.into_iter().map(wait_and_read_stdout).collect();

    assert!(
        !outputs.iter().any(|o| o == "BARRIER_TIMEOUT"),
        "every worker must reach the barrier -- a timeout means this measured startup skew, not the CAS; got {outputs:?}"
    );
    assert!(
        !outputs.iter().any(|o| o == "BASE_MOVED"),
        "every worker must start from the pinned revision -- BASE_MOVED means the race was never on a common base, the exact defect this test replaced; got {outputs:?}"
    );
    let committed = outputs.iter().filter(|o| o.as_str() == "COMMITTED").count();
    assert_eq!(
        committed, 1,
        "exactly one of six independent processes proposing byte-identical content against one pinned revision must win the CAS; got {outputs:?}"
    );
    assert_eq!(
        outputs.iter().filter(|o| o.as_str() == "NO_EFFECT").count(),
        5,
        "the five losers must each be a definitive no-effect rejection, never MAY_HAVE_TAKEN_EFFECT; got {outputs:?}"
    );
}

/// Negative control for the test above, and the standing evidence that
/// the predecessor's assertion was vacuous rather than merely unlucky:
/// run two unpinned workers strictly SEQUENTIALLY (each fully finished
/// before the next starts, so they provably never contend) and watch both
/// commit. Under the old shape that was indistinguishable from a genuine
/// race, which is why "exactly one committed" could flip to two on a
/// machine where the workers happened not to overlap.
#[test]
fn unpinned_sequential_runs_both_commit_which_is_why_the_old_test_was_vacuous() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    {
        let cell = test_cell(path.clone());
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
    }

    let first = wait_and_read_stdout(run_cas_race_helper(&path, 0));
    let second = wait_and_read_stdout(run_cas_race_helper(&path, 1));

    assert_eq!(
        (first.as_str(), second.as_str()),
        ("COMMITTED", "COMMITTED"),
        "two strictly sequential unpinned workers both commit -- each reads the revision the previous one wrote and legitimately advances it. This is correct CAS behaviour, which is exactly why asserting 'exactly one committed' over unpinned workers measured scheduling luck instead of the CAS."
    );
}

#[test]
fn preexisting_hardlink_alias_makes_every_process_fail_closed_not_double_commit() {
    // Round 6, wave 6 (corrected, retracting an earlier false claim in
    // this same test): `open_non_aliased`'s nlink check does NOT make
    // this store immune to a hardlink alias in general -- see store.rs's
    // top doc comment for the full, honest boundary. A hardlink created
    // DURING a `replace_exact` call (between its nlink check and its
    // rename) is NOT caught by this or any check in this crate: after
    // that rename, the two names permanently and independently show
    // nlink == 1, because they are, from that point on, genuinely two
    // separate files -- there is nothing left to detect.
    //
    // What IS true, and is what this test actually demonstrates: an alias
    // that already exists BEFORE any operation begins is detected and
    // rejected, fail-closed, by every process that tries to use either
    // spelling -- the hardlink here is created before any worker starts,
    // not raced against one.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let alias_path = dir.path().join("alias");
    {
        let cell = test_cell(path.clone());
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
    }
    std::fs::hard_link(&path, &alias_path).expect("hard_link must succeed on a local filesystem");

    let children: Vec<_> = (0u8..6)
        .map(|i| {
            let target = if i % 2 == 0 { &path } else { &alias_path };
            run_cas_race_helper(target, i)
        })
        .collect();
    let outputs: Vec<String> = children.into_iter().map(wait_and_read_stdout).collect();

    let committed = outputs.iter().filter(|o| o.as_str() == "COMMITTED").count();
    assert_eq!(
        committed, 0,
        "once a hardlink alias exists, every process (via either spelling) must fail closed -- never a silent double-commit through the two spellings; got {outputs:?}"
    );
    assert!(
        outputs.iter().all(|o| o.starts_with("REJECTED")),
        "every worker must observe the alias as a rejection, not silently succeed or crash; got {outputs:?}"
    );
}

// ── mandatory (not opt-in) validated load ─────────────────────────────

#[test]
fn load_revalidated_succeeds_for_a_genuinely_active_record() {
    // rotated_record_with_two_generations's shared `delegation()` fixture
    // uses a placeholder delegated_key_id that never matches a real
    // canonical_slot -- fine for the roster-revocation test (which fails
    // closed before ever reaching that check), not fine here, where this
    // test specifically wants full end-to-end success. Built directly
    // instead, mirroring activate_from_key_observed_succeeds_full_path's
    // own correctly-matched delegation.
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [130; 16],
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
    let mut d = delegation(0, 100);
    d.delegated_key_id = p.canonical_slot.canonical_id();
    d.delegated_pub = real_binding.public_key.clone();
    let mut activated = apply(
        &with_binding,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_binding.revision,
            delegation: d,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    activated.revision = 1; // see seed_record's own two-step requirement
    seed_record(&cell, &activated);

    let policy = DelegationPolicy::test(1000);
    let loaded = load_revalidated_report_for_test::<MeshSessionPurpose>(
        &cell,
        &backend,
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .expect("a genuinely valid, backend-confirmed record must load");
    assert_eq!(loaded, activated);
}

#[test]
fn load_revalidated_rejects_when_physical_key_was_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let mut rotated = rotated_record_with_two_generations(5000, 6000);
    rotated.revision = 1; // see the sibling test above for why
    let backend = FakeSecretBackend::new();
    for g in &rotated.live_generations {
        backend.create_or_inspect(&g.binding.slot, Some(&g.binding));
    }
    seed_record(&cell, &rotated);

    // Tamper the physical key AFTER seeding -- load_revalidated_report must
    // catch this; the low-level load_canonical alone never could.
    let tampered_slot = rotated.live_generations[0].binding.slot.clone();
    let mut tampered_binding = rotated.live_generations[0].binding.clone();
    tampered_binding.public_key = vec![0xDE, 0xAD];
    backend.gc_best_effort(&tampered_slot, &rotated.live_generations[0].binding);
    backend.create_or_inspect(&tampered_slot, Some(&tampered_binding));

    let policy = DelegationPolicy::test(10_000);
    let err = load_revalidated_report_for_test::<MeshSessionPurpose>(
        &cell,
        &backend,
        &policy,
        &active_roster(),
        &AlwaysTrueVerifier,
        50,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        LoadRevalidatedError::Validation(ValidationError::PhysicalKeyNotConfirmed)
    ));
}

// ── wave 8, CFX-1/2/3/4: with_authorized_use replaces RevalidatedGuard ──
//
// The wave-7 RevalidatedGuard is gone. It handed back
// `&MeshSignerControlRecordV1` from a `record()` accessor, and that type
// derives Clone -- so `let r = g.record().clone(); drop(g);` detached a
// fully "validated" snapshot from the only thing making it true. It also
// took the cell's SignGuard BEFORE its slow backend/roster/sig I/O, which
// both blocked urgent revokes for the whole duration and established a
// cell -> roster lock order that deadlocked against activation's
// roster -> cell order. See `AuthorizedUse`'s doc comment in activate.rs.

/// The common fixture: a fully activated, backend-confirmed record.
fn activated_fixture(txn_seed: u8) -> (FakeSecretBackend, MeshSignerControlRecordV1) {
    let old = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
    let with_intent = apply(
        &old,
        &RecordTransition::IntentRecorded {
            txn_id: [txn_seed; 16],
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
    let mut d = delegation(0, 100);
    d.delegated_key_id = p.canonical_slot.canonical_id();
    d.delegated_pub = real_binding.public_key.clone();
    let mut activated = apply(
        &with_binding,
        &RecordTransition::ActivateFromKeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_binding.revision,
            delegation: d,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    activated.revision = 1; // see seed_record's own two-step requirement
    (backend, activated)
}

/// Like `activated_fixture`, but the record ALSO carries an in-flight
/// `RoutineRotate` pending op already in `KeyObserved` phase -- so
/// `activate_from_key_observed` can be driven against it concurrently
/// with a `with_authorized_use` against the still-current generation.
/// That pairing is the only one that can exercise the wave-7 lock cycle:
/// both paths touch the roster AND the cell, which `cell.commit` alone
/// (no roster involvement at all) never does.
fn activated_with_pending_rotation_fixture(
    txn_seed: u8,
) -> (
    FakeSecretBackend,
    MeshSignerControlRecordV1,
    [u8; 16],
    Delegation,
) {
    let (backend, activated) = activated_fixture(txn_seed);
    let rotate_txn = [txn_seed.wrapping_add(1); 16];
    let with_intent = apply(
        &activated,
        &RecordTransition::IntentRecorded {
            txn_id: rotate_txn,
            kind: PendingOpKind::RoutineRotate,
            backend: BackendKind::File,
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let p = with_intent.pending_op.clone().unwrap();
    let CreateOutcome::Unique {
        binding: rotate_binding,
        ..
    } = backend.create_or_inspect(&p.canonical_slot, None)
    else {
        panic!()
    };
    let mut with_binding = apply(
        &with_intent,
        &RecordTransition::KeyObserved {
            expected_txn_id: p.txn_id,
            expected_kind: p.kind,
            expected_generation: p.generation,
            expected_epoch: p.epoch,
            expected_purpose: p.purpose,
            expected_slot_id: p.canonical_slot.canonical_id(),
            expected_revision: with_intent.revision,
            binding: rotate_binding.clone(),
        },
        1000,
        TEST_CAP,
    )
    .unwrap();
    let mut d2 = delegation(0, 100);
    d2.delegated_key_id = p.canonical_slot.canonical_id();
    d2.delegated_pub = rotate_binding.public_key.clone();
    with_binding.revision = 1; // see seed_record's own two-step requirement
    (backend, with_binding, rotate_txn, d2)
}

#[test]
fn with_authorized_use_blocks_a_concurrent_revoke_so_no_use_linearizes_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let (backend, activated) = activated_fixture(140);
    seed_record(&cell, &activated);
    let policy = DelegationPolicy::test(1000);
    let order = Arc::new(Mutex::new(Vec::new()));

    std::thread::scope(|scope| {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        let generation = with_authorized_use::<MeshSessionPurpose, _>(
            &cell,
            &backend,
            &policy,
            &active_roster(),
            &AlwaysTrueVerifier,
            50,
            |authorized| {
                // Spawned from INSIDE the closure on purpose: the
                // SignGuard is provably already held at this point, so
                // there is no window in which the revoke could win the
                // race and turn this into a flaky test rather than a
                // deterministic one.
                let order_ref = Arc::clone(&order);
                let cell_ref = &cell;
                scope.spawn(move || {
                    started_tx.send(()).unwrap();
                    let r = cell_ref.commit(
                        &RecordTransition::RevokeUrgent {
                            reason: RevocationReason::OwnerAction,
                            txn_id: [141; 16],
                        },
                        60,
                        TEST_CAP,
                    );
                    order_ref.lock().unwrap().push("revoke_done");
                    done_tx.send(r).unwrap();
                });
                // Wait until the revoke thread is genuinely live before
                // asserting it cannot finish -- otherwise a thread that
                // simply had not started yet would make the assertion
                // below pass without proving anything.
                started_rx.recv().unwrap();
                assert!(
                    matches!(
                        done_rx.recv_timeout(std::time::Duration::from_millis(150)),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    ),
                    "RevokeUrgent must be genuinely blocked while an authorized use is in flight"
                );
                order.lock().unwrap().push("use_done");
                authorized.generation()
            },
        )
        .expect("a genuinely active, backend-confirmed record must authorize a use");
        assert_eq!(generation, activated.current_generation.unwrap());

        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("revoke must proceed promptly once the authorized use returns")
            .expect("revoke must succeed once unblocked");
    });

    assert_eq!(
        *order.lock().unwrap(),
        vec!["use_done", "revoke_done"],
        "no authorized use can ever linearize after a revoke -- proven by the converse: the revoke cannot complete until the use already happened and released the guard"
    );
}

#[test]
fn with_authorized_use_holds_no_cell_lock_during_slow_io_and_then_refuses_the_stale_snapshot() {
    // Two properties at once, both required by the wave-8 lock order:
    // (1) step 1's slow roster I/O holds NO cell lock -- proven because a
    //     RevokeUrgent commits to completion while it is in flight;
    // (2) the snapshot validated during that window is then refused,
    //     rather than authorizing a use that a revoke already invalidated.
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let (backend, activated) = activated_fixture(142);
    seed_record(&cell, &activated);
    let policy = DelegationPolicy::test(1000);

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
    let roster = BlockingRoster {
        ready_tx: Mutex::new(Some(ready_tx)),
        proceed_rx: Mutex::new(proceed_rx),
    };

    std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            with_authorized_use::<MeshSessionPurpose, _>(
                &cell,
                &backend,
                &policy,
                &roster,
                &AlwaysTrueVerifier,
                50,
                |_authorized| panic!("the closure must never run against a stale snapshot"),
            )
        });

        ready_rx.recv().unwrap(); // now parked inside the slow roster query
        cell.commit(
            &RecordTransition::RevokeUrgent {
                reason: RevocationReason::OwnerAction,
                txn_id: [143; 16],
            },
            60,
            TEST_CAP,
        )
        .expect("a revoke must be able to commit while step 1's slow I/O is in flight -- that is the whole point of holding no cell lock there");
        proceed_tx.send(()).unwrap();

        let err = handle.join().unwrap().unwrap_err();
        assert!(
            matches!(err, AuthorizedUseError::RecordChangedDuringAcquire),
            "got {err:?}"
        );
    });
}

#[test]
fn a_held_currency_lease_blocks_a_roster_side_revoke_for_the_whole_authorized_use() {
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let (backend, activated) = activated_fixture(144);
    seed_record(&cell, &activated);
    let policy = DelegationPolicy::test(1000);
    let roster = LeaseEnforcingRoster::active(vec![1, 2, 3], [9u8; 32]);

    std::thread::scope(|scope| {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        with_authorized_use::<MeshSessionPurpose, _>(
            &cell,
            &backend,
            &policy,
            &roster,
            &AlwaysTrueVerifier,
            50,
            |_authorized| {
                let roster_ref = &roster;
                scope.spawn(move || {
                    started_tx.send(()).unwrap();
                    roster_ref.revoke_on_roster_side();
                    done_tx.send(()).unwrap();
                });
                started_rx.recv().unwrap();
                assert!(
                    matches!(
                        done_rx.recv_timeout(std::time::Duration::from_millis(150)),
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                    ),
                    "a roster-side revoke must be genuinely blocked by the held currency lease for the whole authorized use"
                );
            },
        )
        .expect("a genuinely active record must authorize a use");

        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the roster-side revoke must proceed once the lease is released");
    });

    assert_eq!(roster.currency.lock().unwrap().revision, 1);
}

// ── the lock-order cycle itself ────────────────────────────────────────

#[test]
fn activation_and_authorized_use_running_concurrently_never_deadlock() {
    // The absence-of-cycle RED, made DETERMINISTIC rather than hopeful.
    //
    // A first attempt at this test simply spawned both paths and asserted
    // both finished. That instrument was vacuous: run against deliberately
    // inverted (cell -> roster) code in a scratch copy it still passed,
    // because nothing forced the two threads into the interleaving the
    // cycle needs. It confirmed its own prior. This version pins the
    // interleaving:
    //
    //   1. the activation thread is parked the instant it holds the roster
    //      lease and before it takes any cell guard (`lease_sync`);
    //   2. only then does the authorized-use thread start;
    //   3. only then is the activation thread released.
    //
    // Under the sanctioned roster -> cell order, the use thread blocks on
    // the roster lease while holding NO cell guard, so activation takes
    // the cell guard freely and both finish. Under the inverted
    // cell -> roster order, the use thread holds the cell's SignGuard
    // while waiting for the lease, activation blocks forever on the cell
    // guard, and neither finishes -- which this test then reports as the
    // cycle it is. Verified against an inverted scratch copy: this version
    // times out there and passes here.
    let dir = tempfile::tempdir().unwrap();
    let cell = test_cell(dir.path().join("record"));
    let (backend, seeded, rotate_txn, d2) = activated_with_pending_rotation_fixture(150);
    seed_record(&cell, &seeded);
    let policy = DelegationPolicy::test(1000);

    let (lease_held_tx, lease_held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let roster = LeaseEnforcingRoster::active_parking_the_first_lease(
        vec![1, 2, 3],
        [9u8; 32],
        lease_held_tx,
        release_rx,
    );

    // Detached, not scoped: a genuinely deadlocked thread can never be
    // joined, so the harness must be able to give up on it.
    let shared = Arc::new((cell, backend, policy, roster));
    let (activate_done_tx, activate_done_rx) = std::sync::mpsc::channel();
    let (use_done_tx, use_done_rx) = std::sync::mpsc::channel();

    {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            let (cell, backend, policy, roster) = (&shared.0, &shared.1, &shared.2, &shared.3);
            // roster lease -> cell MutateGuard
            let _ = activate_from_key_observed::<MeshSessionPurpose>(
                cell,
                backend,
                roster,
                &AlwaysTrueVerifier,
                policy,
                rotate_txn,
                d2,
                50,
                TEST_CAP,
            );
            let _ = activate_done_tx.send(());
        });
    }

    // Activation now holds the roster lease and has taken no cell guard.
    lease_held_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("activation must reach its lease");

    {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            let (cell, backend, policy, roster) = (&shared.0, &shared.1, &shared.2, &shared.3);
            // cell SignGuard + roster lease -- the pair whose ORDER is
            // the whole question.
            let _ = with_authorized_use::<MeshSessionPurpose, _>(
                cell,
                backend,
                policy,
                roster,
                &AlwaysTrueVerifier,
                50,
                |authorized| authorized.generation(),
            );
            let _ = use_done_tx.send(());
        });
    }

    // Let the use thread reach whichever acquisition its order takes
    // first, then release activation into its cell guard.
    std::thread::sleep(std::time::Duration::from_millis(200));
    release_tx.send(()).unwrap();

    activate_done_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("activation must not deadlock -- a timeout here IS the cycle");
    use_done_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the authorized use must not deadlock -- a timeout here IS the cycle");
}

#[test]
fn the_deadlock_instrument_itself_can_detect_a_real_cycle() {
    // Non-vacuity control for the test above. A "no deadlock" assertion
    // built on recv_timeout is only worth something if that harness would
    // actually catch a cycle -- otherwise it confirms its own prior.
    //
    // A first version of this control just spawned two threads taking two
    // locks in opposite orders and expected a deadlock. That was itself
    // racy (2 of 15 suite runs saw the second thread take both locks
    // before the first had taken either, and trip its own `unreachable!`).
    // The acquisitions are now explicitly sequenced, so the cycle forms
    // every time:
    //
    //   T1 takes A, announces      -> T2 takes B, announces
    //   T2 reaches for A (blocked) -> T1 reaches for B (blocked)
    let a = Arc::new(Mutex::new(()));
    let b = Arc::new(Mutex::new(()));
    let (a_held_tx, a_held_rx) = std::sync::mpsc::channel();
    let (b_held_tx, b_held_rx) = std::sync::mpsc::channel();
    let (progressed_tx, progressed_rx) = std::sync::mpsc::channel();

    {
        let (a, b) = (Arc::clone(&a), Arc::clone(&b));
        let progressed_tx = progressed_tx.clone();
        // Detached, not scoped: a genuinely deadlocked thread can never
        // be joined.
        std::thread::spawn(move || {
            let _ga = a.lock().unwrap();
            a_held_tx.send(()).unwrap();
            b_held_rx.recv().unwrap(); // B is provably taken by now
            let _gb = b.lock().unwrap(); // blocks forever
            let _ = progressed_tx.send("t1");
        });
    }
    {
        let (a, b) = (Arc::clone(&a), Arc::clone(&b));
        std::thread::spawn(move || {
            a_held_rx.recv().unwrap(); // A is provably taken by now
            let _gb = b.lock().unwrap();
            b_held_tx.send(()).unwrap();
            let _ga = a.lock().unwrap(); // blocks forever
            let _ = progressed_tx.send("t2");
        });
    }

    assert!(
        matches!(
            progressed_rx.recv_timeout(std::time::Duration::from_millis(500)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "neither thread may get past its second acquisition -- if one did, this harness cannot detect a cycle and the no-deadlock test above proves nothing"
    );
    assert!(
        a.try_lock().is_err() && b.try_lock().is_err(),
        "both locks must still be held by the deadlocked pair"
    );
    // The two threads stay blocked for the rest of the process. That is
    // what a cycle looks like, and it is exactly what
    // activation_and_authorized_use_running_concurrently_never_deadlock
    // asserts cannot happen between the two real code paths.
}

#[test]
fn load_canonical_rejects_a_symlink_at_the_record_path() {
    let dir = tempfile::tempdir().unwrap();
    let real_path = dir.path().join("real_record");
    let symlink_path = dir.path().join("record");
    {
        let cell = test_cell(real_path.clone());
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();
    #[cfg(unix)]
    {
        let cell = test_cell(symlink_path);
        assert_eq!(cell.load_canonical_for_test(), LoadOutcome::Corrupt);
    }
}

#[test]
fn six_processes_via_a_preexisting_symlink_all_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let real_path = dir.path().join("real_record");
    let symlink_path = dir.path().join("record");
    {
        let cell = test_cell(real_path.clone());
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();
        let children: Vec<_> = (0u8..6)
            .map(|i| run_cas_race_helper(&symlink_path, i))
            .collect();
        let outputs: Vec<String> = children.into_iter().map(wait_and_read_stdout).collect();
        assert!(
            outputs.iter().all(|o| o == "REJECTED:RecordCorrupt"),
            "opening the record through a symlink must fail closed for every worker; got {outputs:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn store_directory_that_is_world_writable_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    {
        let cell = test_cell(path.clone());
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
    }
    let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
    perms.set_mode(0o777);
    std::fs::set_permissions(dir.path(), perms).unwrap();

    // A fresh cell (fresh registry entry, since the path is the same but
    // this proves the OPEN-TIME check, not a cached decision) must now
    // refuse to trust anything under this directory.
    let outcome = {
        let cell = test_cell(dir.path().join("record2")); // different path, same (now-tampered) dir
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation();
        cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap)
    };
    assert_eq!(
        outcome,
        ReplaceOutcome::KnownNoEffect,
        "a world-writable store directory must be rejected fail-closed, not silently trusted"
    );

    // Restore permissions so tempfile's own cleanup doesn't choke on a
    // world-writable directory it didn't expect.
    let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(dir.path(), perms).unwrap();
}
