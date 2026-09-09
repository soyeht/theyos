#![cfg(test)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Barrier, Mutex as StdMutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::*;
use crate::keys::P256PublicKey;
use crate::machine_cert::PersonId;
use crate::machine_roster_authority::{
    AcceptedRosterData, AuthenticatedPeerClaim, ExpectedResponder, MachineRosterMemberV1,
    MachineRosterRevocationV1, PeerExpectation, PeerSelectionSource,
};

#[derive(Default)]
struct RecordingSession {
    notices_sent: AtomicUsize,
    closed: AtomicBool,
}

impl RevocableMeshSession for RecordingSession {
    fn send_best_effort_revoke_notice(&self) {
        self.notices_sent.fetch_add(1, Ordering::SeqCst);
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

fn test_m_id(n: u8) -> MachineId {
    MachineId(format!("m-{n:032x}"))
}

fn test_hh_id() -> HouseholdId {
    HouseholdId("hh-mesh-session-registry-test".to_string())
}

fn other_hh_id() -> HouseholdId {
    HouseholdId("hh-different-household".to_string())
}

fn dummy_pubkey() -> P256PublicKey {
    P256PublicKey::from_bytes(&[
        0x02, 0x18, 0x62, 0x99, 0x63, 0x3f, 0x2c, 0x2f, 0x53, 0xd5, 0x4b, 0xf8, 0x9b, 0x03, 0xd0,
        0x82, 0x03, 0x2c, 0x42, 0xb7, 0xef, 0x35, 0x0c, 0xcd, 0x35, 0x5b, 0xcc, 0x8b, 0x0b, 0xf5,
        0xca, 0x66, 0x36,
    ])
    .expect("valid compressed P-256 point fixture")
}

fn dummy_sig() -> crate::keys::P256Signature {
    crate::keys::P256Signature::from_bytes(&[7u8; 64]).expect("valid signature fixture shape")
}

fn member_with_fp(m_id: &MachineId, fp: [u8; 32]) -> MachineRosterMemberV1 {
    MachineRosterMemberV1 {
        m_id: m_id.clone(),
        m_pub: dummy_pubkey(),
        machine_cert: Vec::new(),
        machine_cert_fingerprint: fp,
    }
}

fn revocation(m_id: &MachineId) -> MachineRosterRevocationV1 {
    MachineRosterRevocationV1 {
        v: 1,
        kind: "machine_roster_revocation_v1".to_string(),
        hh_id: test_hh_id(),
        epoch: [1u8; 32],
        sequence: 1,
        prev_event_hash: [0u8; 32],
        m_id: m_id.clone(),
        m_pub: dummy_pubkey(),
        machine_cert_fingerprint: [5u8; 32],
        revoked_at: 1,
        reason: crate::machine_roster_authority::RevocationReason::OwnerAction,
        cascade: crate::machine_roster_authority::RevocationCascade::MachineOnly,
        owner_p_id: PersonId("owner".to_string()),
        owner_cert_fingerprint: [4u8; 32],
        owner_person_cert: Vec::new(),
        signature: dummy_sig(),
    }
}

/// `sequence`/`checkpoint_hash` are what the whole regression/fork/
/// idempotent/advance/recovery suite pivots on; `active` carries
/// `(m_id, machine_cert_fingerprint)` pairs so fingerprint-change
/// revocation (round 3, point 3) is directly testable.
fn snapshot_at(
    sequence: u64,
    checkpoint_hash: [u8; 32],
    active: &[(MachineId, [u8; 32])],
    revoked: &[MachineId],
) -> RosterSnapshotView {
    snapshot_at_hh(&test_hh_id(), sequence, checkpoint_hash, active, revoked)
}

fn snapshot_at_hh(
    hh_id: &HouseholdId,
    sequence: u64,
    checkpoint_hash: [u8; 32],
    active: &[(MachineId, [u8; 32])],
    revoked: &[MachineId],
) -> RosterSnapshotView {
    let data = AcceptedRosterData {
        epoch: [1u8; 32],
        checkpoint_sequence: sequence,
        checkpoint_hash,
        prev_checkpoint_hash: [0u8; 32],
        event_sequence: sequence,
        event_head_hash: [3u8; 32],
        predecessor_event_sequence: 0,
        predecessor_event_head_hash: [0u8; 32],
        issued_at: 1,
        not_after: u64::MAX,
        owner_cert_fingerprint: [4u8; 32],
        genesis_basis: crate::machine_roster_authority::VerifiedGenesisRoster {
            epoch: [1u8; 32],
            members: Vec::new(),
        },
        active: active
            .iter()
            .map(|(m_id, fp)| member_with_fp(m_id, *fp))
            .collect(),
        tombstones: revoked.iter().map(revocation).collect(),
    };
    RosterSnapshotView::project(hh_id, &data)
}

const FP_A: [u8; 32] = [0xAAu8; 32];
const FP_B: [u8; 32] = [0xBBu8; 32];

fn new_registry_with(
    sequence: u64,
    checkpoint_hash: [u8; 32],
    active: &[(MachineId, [u8; 32])],
) -> MeshSessionRegistry<RecordingSession> {
    let snapshot = snapshot_at(sequence, checkpoint_hash, active, &[]);
    MeshSessionRegistry::new(&snapshot)
}

/// Builds a `SealedBinding` the only way it can be built — through the
/// real `PeerExpectation`/`ExpectedResponder` pipeline against a real
/// snapshot, exactly as production code would. No test-only shortcut
/// constructor exists on `SealedBinding` itself (round 3, point 1).
fn sealed_binding(snapshot: &RosterSnapshotView, m_id: &MachineId) -> SealedBinding {
    let expectation = PeerExpectation::injected_for_harness(
        snapshot.checkpoint_hash(),
        m_id.clone(),
        PeerSelectionSource::LocalOwnerPresentSelection,
    );
    let responder = ExpectedResponder::from_peer_expectation(expectation, snapshot)
        .expect("test fixture: m_id must be active and non-revoked in snapshot");
    SealedBinding::from_expected_responder(&responder, snapshot)
}

/// Builds a `SealedBinding` via the RESPONDER-side origin (D-1
/// successor, @kiana E1) — an `AuthenticatedPeerClaim` and a real
/// snapshot, with no `PeerExpectation`/`ExpectedResponder` involved at
/// all.
fn sealed_binding_responder(snapshot: &RosterSnapshotView, m_id: &MachineId) -> SealedBinding {
    let claim = AuthenticatedPeerClaim::injected_for_harness(m_id.clone());
    SealedBinding::from_responding_peer(&claim, snapshot)
        .expect("test fixture: m_id must be active and non-revoked in snapshot")
}

#[test]
fn register_refuses_wrong_household() {
    let m_id = test_m_id(1);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    // Binding sealed against a DIFFERENT household's snapshot at the
    // exact same (hash, sequence, m_id, fingerprint).
    let foreign_snapshot =
        snapshot_at_hh(&other_hh_id(), 1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&foreign_snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let outcome = registry.register(&binding, Arc::downgrade(&session));
    assert_eq!(outcome.err(), Some(RegisterRefusal::HouseholdMismatch));
}

#[test]
fn register_refuses_unlisted_machine() {
    let m_id = test_m_id(2);
    let registry = new_registry_with(1, [1u8; 32], &[]); // not active
    let snapshot_with_m_id_active_elsewhere =
        snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot_with_m_id_active_elsewhere, &m_id);
    let session = Arc::new(RecordingSession::default());
    let outcome = registry.register(&binding, Arc::downgrade(&session));
    assert_eq!(outcome.err(), Some(RegisterRefusal::MachineNotActive));
}

#[test]
fn register_refuses_stale_revision() {
    let m_id = test_m_id(3);
    let registry = new_registry_with(5, [9u8; 32], &[(m_id.clone(), FP_A)]);
    // Binding sealed against an older revision.
    let stale_snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&stale_snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let outcome = registry.register(&binding, Arc::downgrade(&session));
    assert_eq!(outcome.err(), Some(RegisterRefusal::RevisionMismatch));
}

/// A `SealedBinding` proves the fingerprint that was active WHEN IT WAS
/// SEALED, not necessarily the one active now. If the registry's own
/// revision already has a different fingerprint for this `m_id` (e.g. the
/// binding is stale relative to a same-revision reality it doesn't
/// match — constructed here by hand-building a binding whose fingerprint
/// disagrees with the registry's revision at the identical
/// (hash, sequence)), register refuses.
#[test]
fn register_refuses_fingerprint_mismatch_against_current_revision() {
    let m_id = test_m_id(4);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot_with_different_fp = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_B)], &[]);
    let binding = sealed_binding(&snapshot_with_different_fp, &m_id);
    let session = Arc::new(RecordingSession::default());
    let outcome = registry.register(&binding, Arc::downgrade(&session));
    assert_eq!(outcome.err(), Some(RegisterRefusal::MachineNotActive));
}

#[test]
fn register_refuses_already_dropped_handle() {
    let m_id = test_m_id(5);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let weak = {
        let session = Arc::new(RecordingSession::default());
        Arc::downgrade(&session)
    };
    let outcome = registry.register(&binding, weak);
    assert_eq!(outcome.err(), Some(RegisterRefusal::HandleAlreadyDropped));
}

#[test]
fn register_succeeds_and_gate_starts_true() {
    let m_id = test_m_id(6);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .expect("active machine, matching revision, matching fingerprint");
    assert!(gate.is_authorized());
    assert!(registry.is_registered(&m_id));
}

/// MIGRATED (@kiana audit `caf6d1e4`) from
/// `pending_has_no_forwarding_gate_and_drop_aborts_closed`, which
/// required `H::close()` from `Drop`. Under D3, Pending `Drop` is
/// callback-free: it closes the phase atomically and nothing else, so
/// the assertion is now atomic closure plus eventual reconciliation.
#[test]
fn pending_has_no_forwarding_gate_and_drop_closes_atomically_then_reconciles() {
    let m_id = test_m_id(60);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());

    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .expect("exact live binding must enter Pending");

    assert_eq!(registry.registered_count(&m_id), 0);
    assert!(admission.sync.try_enter().is_none());
    let sync = Arc::clone(&admission.sync);
    assert_eq!(sync.phase(), PHASE_PENDING);

    drop(admission);

    // Authority: closed immediately and unconditionally by the Drop
    // itself, with no lock and no callback.
    assert_eq!(sync.phase(), PHASE_CLOSED);
    assert!(sync.try_enter().is_none());
    assert!(
        !session.closed.load(Ordering::SeqCst),
        "Pending Drop must NOT call into H — protocol I/O never runs from a destructor"
    );
    assert_eq!(registry.registered_count(&m_id), 0);

    // Bookkeeping: reconcilable debt, swept by any later registry
    // operation (here, the explicit sweep).
    assert_eq!(
        registry.reconcile_closed_pending(),
        ReconcileOutcome::Swept { removed: 0 },
        "registered_count above already swept it opportunistically"
    );
    let guard = registry.inner.lock().unwrap();
    let Mode::Live { sessions, .. } = &guard.mode else {
        panic!("registry must remain live after a local Ack abort");
    };
    assert!(
        sessions.is_empty(),
        "the Closed Pending entry must be reconciled away"
    );
}

#[test]
fn successful_ack_commit_is_the_only_path_that_opens_forwarding() {
    let m_id = test_m_id(61);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());

    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .expect("exact live binding must enter Pending");
    assert_eq!(registry.registered_count(&m_id), 0);

    // This call models the statement immediately following a
    // successful write_all(Ack). There is no exposed gate before it.
    let active = admission.commit_after_ack();

    assert_eq!(registry.registered_count(&m_id), 1);
    let forwarding = active
        .try_authorize_forwarding()
        .expect("Active session must authorize forwarding");
    drop(forwarding);
    assert!(!session.closed.load(Ordering::SeqCst));
}

#[test]
fn pending_permit_holds_no_registry_mutex_across_ack_io() {
    let m_id = test_m_id(66);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .unwrap();
    let (done_tx, done_rx) = mpsc::channel();

    let observer = {
        let registry = Arc::clone(&registry);
        let m_id = m_id.clone();
        thread::spawn(move || {
            done_tx.send(registry.registered_count(&m_id)).unwrap();
        })
    };

    assert_eq!(
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        0,
        "Pending is not Active, but unrelated registry access must not block behind its permit"
    );
    observer.join().unwrap();
    drop(admission);
}

/// RED-4 (@kiana audit `caf6d1e4`) — **INVERTED** from
/// `unrelated_revision_advance_between_pending_and_ack_fails_closed`,
/// which certified the pre-terminal-rule behavior.
///
/// An unrelated checkpoint advance between reserve and full Ack used to
/// make activation fail with `RevisionMismatch`. That is now wrong: the
/// peer holds a complete Ack, so refusing locally would diverge. The
/// advance did not revoke THIS machine, so the session simply commits
/// and stays live.
#[test]
fn unrelated_revision_advance_between_pending_and_ack_still_commits() {
    let m_id = test_m_id(62);
    let other = test_m_id(63);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .unwrap();

    let advanced = snapshot_at(2, [2u8; 32], &[(m_id.clone(), FP_A)], &[other]);
    assert_eq!(
        registry.observe_new_checkpoint(&advanced),
        ObserveOutcome::Applied
    );

    // No Result to unwrap: post-Ack commit is infallible by design.
    let active = admission.commit_after_ack();

    assert_eq!(
        registry.registered_count(&m_id),
        1,
        "an advance that does not revoke this machine must not veto a completed Ack"
    );
    assert!(
        active.try_authorize_forwarding().is_some(),
        "the committed session must be able to forward"
    );
    assert!(!session.closed.load(Ordering::SeqCst));
}

/// RED-CARRIER-E1-ACK-FAIL: the permit itself is the observable
/// barrier. Once `writer_intent` is non-zero, revoke has completed its
/// short registry phase and is deterministically waiting on this
/// Pending admission — no sleep is used as the proof of ordering.
#[test]
fn ack_failure_drops_pending_then_waiting_revoke_completes() {
    let m_id = test_m_id(64);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .unwrap();
    let (done_tx, done_rx) = mpsc::channel();

    let revoker = {
        let registry = Arc::clone(&registry);
        let m_id = m_id.clone();
        thread::spawn(move || {
            let revoked = snapshot_at(2, [2u8; 32], &[], &[m_id]);
            let outcome = registry.observe_new_checkpoint(&revoked);
            done_tx.send(outcome).unwrap();
        })
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    while admission.sync.writer_intent.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "revoke never announced intent while Pending was held"
        );
        thread::yield_now();
    }
    assert!(
        done_rx.try_recv().is_err(),
        "revoke must not finish before Ack failure releases the permit"
    );

    // Simulated partial/failed Ack: no activation call, just unwind.
    drop(admission);
    assert_eq!(done_rx.recv().unwrap(), ObserveOutcome::Applied);
    revoker.join().unwrap();

    assert_eq!(registry.registered_count(&m_id), 0);
    assert!(session.closed.load(Ordering::SeqCst));
}

/// RED-3 (@kiana audit `caf6d1e4`) — **INVERTED** from
/// `revoke_announced_during_ack_window_prevents_activation`.
///
/// A revoke announced during the Ack window used to veto activation.
/// Under the terminal rule it must not: the peer already holds a
/// complete Ack, so the commit happens, and the revoker then closes the
/// freshly-Active session. The property that keeps this safe is not the
/// veto but `writer_intent` — no forwarding guard may be admitted at
/// ANY point, before or after the commit.
#[test]
fn revoke_announced_during_ack_window_still_commits_but_admits_no_forwarding() {
    let m_id = test_m_id(65);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .unwrap();
    let (done_tx, done_rx) = mpsc::channel();

    let revoker = {
        let registry = Arc::clone(&registry);
        let m_id = m_id.clone();
        thread::spawn(move || {
            let revoked = snapshot_at(2, [2u8; 32], &[], &[m_id]);
            done_tx
                .send(registry.observe_new_checkpoint(&revoked))
                .unwrap();
        })
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    while admission.sync.writer_intent.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "revoke never announced intent while Pending was held"
        );
        thread::yield_now();
    }
    assert!(done_rx.try_recv().is_err());

    // The Ack completed, so the commit happens. No Result: refusing
    // here is exactly what the terminal rule forbids.
    let active = admission.commit_after_ack();

    // The decisive property: even in the window where the phase is
    // Active, the announced writer means nothing can forward. This is
    // what makes honouring the Ack safe rather than merely permissive.
    assert!(
        active.try_authorize_forwarding().is_none(),
        "an announced revoke must admit zero forwarding across the commit gap"
    );

    assert_eq!(done_rx.recv().unwrap(), ObserveOutcome::Applied);
    revoker.join().unwrap();

    // ...and the revoker closes it immediately afterward.
    assert!(active.try_authorize_forwarding().is_none());
    assert_eq!(registry.registered_count(&m_id), 0);
    assert!(session.closed.load(Ordering::SeqCst));
}

#[test]
fn pending_barrier_survives_poison_and_revoke_still_waits_for_abort() {
    let m_id = test_m_id(67);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .unwrap();

    let sync = Arc::clone(&admission.sync);
    let poisoner = thread::spawn(move || {
        let _state = sync.state.lock().unwrap();
        panic!("deliberate Pending SessionSync poison");
    });
    assert!(poisoner.join().is_err());

    let (done_tx, done_rx) = mpsc::channel();
    let revoker = {
        let registry = Arc::clone(&registry);
        let m_id = m_id.clone();
        thread::spawn(move || {
            let revoked = snapshot_at(2, [2u8; 32], &[], &[m_id]);
            done_tx
                .send(registry.observe_new_checkpoint(&revoked))
                .unwrap();
        })
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    while admission.sync.writer_intent.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline);
        thread::yield_now();
    }
    assert!(
        done_rx.try_recv().is_err(),
        "poison must not let revoke abandon the Pending barrier"
    );

    drop(admission);
    assert_eq!(done_rx.recv().unwrap(), ObserveOutcome::Applied);
    revoker.join().unwrap();
    assert!(session.closed.load(Ordering::SeqCst));
}

#[test]
fn two_concurrent_sessions_for_the_same_machine_both_close_on_revoke() {
    let m_id = test_m_id(7);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session_a = Arc::new(RecordingSession::default());
    let session_b = Arc::new(RecordingSession::default());
    let (_, gate_a) = registry
        .register(&binding, Arc::downgrade(&session_a))
        .unwrap();
    let (_, gate_b) = registry
        .register(&binding, Arc::downgrade(&session_b))
        .unwrap();
    assert_eq!(registry.registered_count(&m_id), 2);

    let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], std::slice::from_ref(&m_id));
    let outcome = registry.observe_new_checkpoint(&revoke_snapshot);

    assert_eq!(outcome, ObserveOutcome::Applied);
    assert!(!gate_a.is_authorized());
    assert!(!gate_b.is_authorized());
    assert!(session_a.closed.load(Ordering::SeqCst));
    assert!(session_b.closed.load(Ordering::SeqCst));
    assert!(!registry.is_registered(&m_id));
}

#[test]
fn register_after_revoke_is_refused_not_added() {
    let m_id = test_m_id(8);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], std::slice::from_ref(&m_id));
    registry.observe_new_checkpoint(&revoke_snapshot);

    let late_snapshot = snapshot_at(2, [2u8; 32], &[], std::slice::from_ref(&m_id));
    // Can't seal a binding for a revoked m_id via the real pipeline
    // (from_peer_expectation refuses it) -- which is itself part of the
    // proof: there is no way to construct a binding admissible here.
    let expectation = PeerExpectation::injected_for_harness(
        late_snapshot.checkpoint_hash(),
        m_id.clone(),
        PeerSelectionSource::LocalOwnerPresentSelection,
    );
    let result = ExpectedResponder::from_peer_expectation(expectation, &late_snapshot);
    assert!(
        result.is_err(),
        "revoked machine must not yield an ExpectedResponder at all"
    );
}

/// Round 3, point 3: fingerprint change (cert reissue) revokes even
/// though the machine is still active and not tombstoned.
#[test]
fn fingerprint_change_revokes_even_though_machine_stays_active() {
    let m_id = test_m_id(9);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    // Still active, NOT tombstoned, but a different fingerprint (cert
    // reissue).
    let reissued_snapshot = snapshot_at(2, [2u8; 32], &[(m_id.clone(), FP_B)], &[]);
    let outcome = registry.observe_new_checkpoint(&reissued_snapshot);

    assert_eq!(outcome, ObserveOutcome::Applied);
    assert!(!gate.is_authorized());
    assert!(session.closed.load(Ordering::SeqCst));
    assert!(!registry.is_registered(&m_id));
}

/// Companion to the fingerprint test: a session registered AFTER a cert
/// reissue (matching the NEW fingerprint) must survive a later
/// checkpoint that changes nothing about this machine, proving
/// revocation is per-session identity, not per-machine-as-a-whole.
#[test]
fn session_registered_under_current_fingerprint_survives_unrelated_advance() {
    let m_id = test_m_id(10);
    let other = test_m_id(11);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_B)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_B)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let unrelated_advance = snapshot_at(2, [2u8; 32], &[(m_id.clone(), FP_B)], &[other]);
    let outcome = registry.observe_new_checkpoint(&unrelated_advance);

    assert_eq!(outcome, ObserveOutcome::Applied);
    assert!(gate.is_authorized());
    assert!(!session.closed.load(Ordering::SeqCst));
    assert!(registry.is_registered(&m_id));
}

#[test]
fn unrevoked_registered_session_is_left_untouched() {
    let m_id = test_m_id(12);
    let other = test_m_id(13);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let advance = snapshot_at(2, [2u8; 32], &[(m_id.clone(), FP_A)], &[other]);
    registry.observe_new_checkpoint(&advance);

    assert!(gate.is_authorized());
    assert!(!session.closed.load(Ordering::SeqCst));
    assert!(registry.is_registered(&m_id));
}

/// Round 3, point b: a dead `Weak` is pruned/ignored by a plain read,
/// with no new checkpoint required to notice it.
#[test]
fn is_registered_ignores_dropped_handle_without_a_new_checkpoint() {
    let m_id = test_m_id(14);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    {
        let session = Arc::new(RecordingSession::default());
        registry
            .register(&binding, Arc::downgrade(&session))
            .unwrap();
    }
    // `session` dropped; no observe_new_checkpoint call happens at all.
    assert!(!registry.is_registered(&m_id));
    assert_eq!(registry.registered_count(&m_id), 0);
}

/// Round 4, pass 4 (@kiana): `unregister` must disable the gate, not
/// leave it `true` — losing tracking must never mean "now permanently
/// authorized with no way to ever revoke it" (a caller bug that
/// unregisters a still-live session must not create a silent,
/// unrevocable authority leak). Only the named session is affected;
/// the sibling registered for the same `m_id` is untouched.
#[test]
fn unregister_removes_only_the_named_session_and_disables_its_gate() {
    let m_id = test_m_id(15);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session_a = Arc::new(RecordingSession::default());
    let session_b = Arc::new(RecordingSession::default());
    let (id_a, gate_a) = registry
        .register(&binding, Arc::downgrade(&session_a))
        .unwrap();
    let (_, gate_b) = registry
        .register(&binding, Arc::downgrade(&session_b))
        .unwrap();
    assert_eq!(registry.registered_count(&m_id), 2);

    registry.unregister(id_a);

    assert_eq!(registry.registered_count(&m_id), 1);
    assert!(
        !gate_a.is_authorized(),
        "unregister must disable the gate, not leave it authorized forever"
    );
    assert!(session_a.closed.load(Ordering::SeqCst));
    assert!(
        gate_b.is_authorized(),
        "the sibling session must be untouched"
    );
    assert!(!session_b.closed.load(Ordering::SeqCst));
}

/// Round 4, pass 4 (@kiana): `unregister` must genuinely linearize
/// against an in-flight forward, the same as every other revoke path —
/// it must not return while a `ForwardingGuard` for this session is
/// still held. Observable barrier (not a sleep): polls `writer_intent`
/// until it confirms `unregister`'s `revoke()` call has announced
/// intent, at which point — since this test alone controls when the
/// guard is released — `unregister` is deterministically still
/// blocked, not just probably.
#[test]
fn unregister_waits_for_an_in_flight_forward_before_returning() {
    let m_id = test_m_id(55);
    let registry = Arc::new(new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]));
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let log: Arc<StdMutex<Vec<&'static str>>> = Arc::new(StdMutex::new(Vec::new()));
    let (acquired_tx, acquired_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();

    let holder = {
        let gate = gate.clone();
        let log = Arc::clone(&log);
        thread::spawn(move || {
            let guard = gate
                .try_authorize_forwarding()
                .expect("session active, no revoke has started yet");
            acquired_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            log.lock().unwrap().push("guard_released");
            drop(guard);
        })
    };
    acquired_rx.recv().unwrap();

    let unregisterer = {
        let registry = Arc::clone(&registry);
        let log = Arc::clone(&log);
        thread::spawn(move || {
            registry.unregister(id);
            log.lock().unwrap().push("unregister_returned");
        })
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if gate.sync.writer_intent.load(Ordering::SeqCst) > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "unregister never announced revoke intent within the deadline"
        );
        thread::yield_now();
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "unregister must not return while a ForwardingGuard for this session is still held"
    );

    release_tx.send(()).unwrap();
    holder.join().unwrap();
    unregisterer.join().unwrap();

    assert_eq!(
        &*log.lock().unwrap(),
        &["guard_released", "unregister_returned"]
    );
    assert!(!gate.is_authorized());
    assert!(session.closed.load(Ordering::SeqCst));
}

#[test]
fn observe_rejects_sequence_regression_and_goes_unavailable() {
    let m_id = test_m_id(16);
    let registry = new_registry_with(5, [5u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(5, [5u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let regressed = snapshot_at(3, [3u8; 32], &[], &[]);
    let outcome = registry.observe_new_checkpoint(&regressed);

    assert_eq!(outcome, ObserveOutcome::Rejected);
    assert!(registry.is_unavailable());
    assert!(!gate.is_authorized());
    assert!(session.closed.load(Ordering::SeqCst));
}

#[test]
fn observe_rejects_same_sequence_different_hash_as_fork_and_goes_unavailable() {
    let m_id = test_m_id(17);
    let registry = new_registry_with(5, [5u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(5, [5u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let forked = snapshot_at(5, [0xFFu8; 32], &[], &[]);
    let outcome = registry.observe_new_checkpoint(&forked);

    assert_eq!(outcome, ObserveOutcome::Rejected);
    assert!(registry.is_unavailable());
    assert!(session.closed.load(Ordering::SeqCst));
}

#[test]
fn observe_same_sequence_same_hash_is_idempotent() {
    let m_id = test_m_id(18);
    let registry = new_registry_with(5, [5u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(5, [5u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let same_again = snapshot_at(5, [5u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let outcome = registry.observe_new_checkpoint(&same_again);

    assert_eq!(outcome, ObserveOutcome::Idempotent);
    assert!(gate.is_authorized());
    assert!(registry.is_registered(&m_id));
}

#[test]
fn observe_rejects_wrong_household_and_goes_unavailable() {
    let m_id = test_m_id(19);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let foreign = snapshot_at_hh(&other_hh_id(), 2, [2u8; 32], &[], &[]);
    let outcome = registry.observe_new_checkpoint(&foreign);
    assert_eq!(outcome, ObserveOutcome::Rejected);
    assert!(registry.is_unavailable());
}

#[test]
fn mark_unavailable_closes_all_active_sessions_and_blocks_new_registrations() {
    let m_id_a = test_m_id(20);
    let m_id_b = test_m_id(21);
    let registry = new_registry_with(
        1,
        [1u8; 32],
        &[(m_id_a.clone(), FP_A), (m_id_b.clone(), FP_A)],
    );
    let snapshot = snapshot_at(
        1,
        [1u8; 32],
        &[(m_id_a.clone(), FP_A), (m_id_b.clone(), FP_A)],
        &[],
    );
    let binding_a = sealed_binding(&snapshot, &m_id_a);
    let binding_b = sealed_binding(&snapshot, &m_id_b);
    let session_a = Arc::new(RecordingSession::default());
    let session_b = Arc::new(RecordingSession::default());
    let (_, gate_a) = registry
        .register(&binding_a, Arc::downgrade(&session_a))
        .unwrap();
    let (_, gate_b) = registry
        .register(&binding_b, Arc::downgrade(&session_b))
        .unwrap();

    registry.mark_unavailable();

    assert!(!gate_a.is_authorized());
    assert!(!gate_b.is_authorized());
    assert!(session_a.closed.load(Ordering::SeqCst));
    assert!(session_b.closed.load(Ordering::SeqCst));
    assert!(registry.is_unavailable());

    let m_id_c = test_m_id(22);
    let binding_c = sealed_binding(
        &snapshot_at(1, [1u8; 32], &[(m_id_c.clone(), FP_A)], &[]),
        &m_id_c,
    );
    let new_session = Arc::new(RecordingSession::default());
    let outcome = registry.register(&binding_c, Arc::downgrade(&new_session));
    assert_eq!(outcome.err(), Some(RegisterRefusal::RegistryUnavailable));
}

#[test]
fn mark_unavailable_twice_is_idempotent_no_storm() {
    let m_id = test_m_id(23);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    registry.mark_unavailable();
    assert_eq!(session.notices_sent.load(Ordering::SeqCst), 1);
    registry.mark_unavailable(); // second call: must not re-notice/re-close
    registry.mark_unavailable();
    assert_eq!(session.notices_sent.load(Ordering::SeqCst), 1);
}

/// Round 3, point 5: explicit recovery. Same `(hash, sequence)` as
/// `last_known_revision`, re-observed while `Unavailable`, recovers to
/// `Live` — distinct `Recovered` outcome, not `Applied`.
#[test]
fn recovery_on_identical_last_known_revision() {
    let registry = new_registry_with(5, [5u8; 32], &[]);
    registry.mark_unavailable();
    assert!(registry.is_unavailable());

    let same_revision = snapshot_at(5, [5u8; 32], &[], &[]);
    let outcome = registry.observe_new_checkpoint(&same_revision);

    assert_eq!(outcome, ObserveOutcome::Recovered);
    assert!(!registry.is_unavailable());
}

#[test]
fn recovery_on_strictly_newer_revision() {
    let registry = new_registry_with(5, [5u8; 32], &[]);
    registry.mark_unavailable();

    let newer = snapshot_at(9, [9u8; 32], &[], &[]);
    let outcome = registry.observe_new_checkpoint(&newer);

    assert_eq!(outcome, ObserveOutcome::Recovered);
    assert!(!registry.is_unavailable());

    // Registry is genuinely Live again: a fresh registration against a
    // FURTHER advance (not just the recovery snapshot itself) succeeds
    // normally.
    let m_id = test_m_id(24);
    let advance = snapshot_at(10, [10u8; 32], &[(m_id.clone(), FP_A)], &[]);
    assert_eq!(
        registry.observe_new_checkpoint(&advance),
        ObserveOutcome::Applied
    );
    let binding = sealed_binding(&advance, &m_id);
    let session = Arc::new(RecordingSession::default());
    assert!(
        registry
            .register(&binding, Arc::downgrade(&session))
            .is_ok()
    );
}

/// Round 3, CFX: recovery must advance a generation, so a gate issued
/// BEFORE `mark_unavailable` never reauthorizes even after a later,
/// genuinely successful recovery — belt and suspenders alongside the
/// per-session flip that already happened at `mark_unavailable` time.
#[test]
fn recovery_advances_generation_so_a_gate_issued_before_unavailable_never_reauthorizes() {
    let m_id = test_m_id(30);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_id, old_gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();
    assert!(old_gate.is_authorized());

    registry.mark_unavailable();
    assert!(!old_gate.is_authorized());

    // Recover at the SAME revision (idempotent-while-Unavailable ->
    // Recovered).
    let recovered = snapshot_at(1, [1u8; 32], &[], &[]);
    assert_eq!(
        registry.observe_new_checkpoint(&recovered),
        ObserveOutcome::Recovered
    );

    // The old gate must STILL read unauthorized post-recovery, even
    // though registry_live is true again — only the generation check
    // can be why, since the per-session flag and registry_live alone
    // would both now read as "authorized".
    assert!(!old_gate.is_authorized());

    // A brand new registration at the post-recovery revision
    // authorizes normally, proving recovery itself works and this
    // isn't just a permanently-broken registry.
    let new_snapshot = snapshot_at(2, [2u8; 32], &[(m_id.clone(), FP_A)], &[]);
    registry.observe_new_checkpoint(&new_snapshot);
    let new_binding = sealed_binding(&new_snapshot, &m_id);
    let new_session = Arc::new(RecordingSession::default());
    let (_, new_gate) = registry
        .register(&new_binding, Arc::downgrade(&new_session))
        .unwrap();
    assert!(new_gate.is_authorized());
}

/// Round 4, pass 4 (@kiana): generation must never wrap. Forced to
/// `u64::MAX` directly (private field, same module) rather than
/// actually recovering that many times. A recovery attempt at that
/// point must refuse (stay `Unavailable`) rather than wrap the counter
/// to `0` — wrapping would make a gate issued at generation `0` (the
/// registry's very first, pre-recovery generation) read authorized
/// again.
#[test]
fn generation_exhaustion_refuses_to_recover_rather_than_wrap() {
    let registry = new_registry_with(5, [5u8; 32], &[]);
    registry.generation.store(u64::MAX, Ordering::SeqCst);
    registry.mark_unavailable();
    assert!(registry.is_unavailable());

    let recovered = snapshot_at(5, [5u8; 32], &[], &[]);
    let outcome = registry.observe_new_checkpoint(&recovered);

    assert_eq!(outcome, ObserveOutcome::Rejected);
    assert!(
        registry.is_unavailable(),
        "must stay Unavailable rather than wrap generation to 0"
    );
    assert_eq!(
        registry.generation.load(Ordering::SeqCst),
        u64::MAX,
        "generation must not have changed on a refused recovery"
    );
}

/// Round 3, CFX: a poisoned lock cannot be reached to individually flip
/// each outstanding session's flag, but `registry_live` is a SEPARATE
/// atomic — set `false` the instant any method observes the poison,
/// without ever touching the poisoned interior (no `into_inner`
/// anywhere in this file). Proves an outstanding gate, issued before
/// the poison, reads unauthorized afterward, and that poisoning is
/// permanent — there is no reachable recovery path once the mutex
/// itself is poisoned (every subsequent `lock()` fails forever).
#[test]
fn poison_makes_all_outstanding_gates_unauthorized_without_touching_the_interior() {
    let m_id = test_m_id(31);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();
    assert!(gate.is_authorized());

    // Poison the mutex via poison_for_test, which panics through the
    // SAME lock -> PoisonGuard sequence every real method uses — not by
    // reaching around to `inner` directly, which would bypass
    // PoisonGuard entirely and prove nothing about the real mechanism.
    let poison_registry = Arc::clone(&registry);
    let poisoner = thread::spawn(move || {
        poison_registry.poison_for_test();
    });
    assert!(
        poisoner.join().is_err(),
        "poisoning thread must have panicked while holding the lock"
    );

    // Without ever calling into_inner anywhere in this crate, the
    // outstanding gate from BEFORE the poison must now read
    // unauthorized, and the registry must report Unavailable.
    assert!(!gate.is_authorized());
    assert!(registry.is_unavailable());

    // Poisoning is permanent: even an observation consistent with the
    // last known revision cannot recover a poisoned mutex (lock()
    // fails unconditionally from here on), so the old gate can never
    // be resurrected by a later "successful" recovery either.
    let would_be_recovery = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let outcome = registry.observe_new_checkpoint(&would_be_recovery);
    assert_eq!(outcome, ObserveOutcome::Rejected);
    assert!(!gate.is_authorized());
    assert!(registry.is_unavailable());
}

#[test]
fn recovery_refused_on_regression_relative_to_last_known_revision() {
    let registry = new_registry_with(5, [5u8; 32], &[]);
    registry.mark_unavailable();

    let still_older = snapshot_at(3, [3u8; 32], &[], &[]);
    let outcome = registry.observe_new_checkpoint(&still_older);

    assert_eq!(outcome, ObserveOutcome::Rejected);
    assert!(registry.is_unavailable());
}

#[test]
fn recovery_refused_on_fork_relative_to_last_known_revision() {
    let registry = new_registry_with(5, [5u8; 32], &[]);
    registry.mark_unavailable();

    let conflicting = snapshot_at(5, [0xEEu8; 32], &[], &[]);
    let outcome = registry.observe_new_checkpoint(&conflicting);

    assert_eq!(outcome, ObserveOutcome::Rejected);
    assert!(registry.is_unavailable());
}

#[test]
fn observe_authority_result_ok_routes_to_observe_new_checkpoint() {
    let registry = new_registry_with(1, [1u8; 32], &[]);
    let advance = snapshot_at(2, [2u8; 32], &[], &[]);
    let outcome = registry.observe_authority_result(Ok(advance));
    assert_eq!(outcome, ObserveOutcome::Applied);
}

#[test]
fn observe_authority_result_err_routes_to_mark_unavailable() {
    let m_id = test_m_id(25);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let outcome = registry.observe_authority_result(Err(
        crate::machine_roster_authority::RosterSnapshotError::ClockStateUnavailable,
    ));

    assert_eq!(outcome, ObserveOutcome::Rejected);
    assert!(registry.is_unavailable());
    assert!(session.closed.load(Ordering::SeqCst));
}

/// RED-R20, made rigorous (round 3, point c): proves the exact ORDER
/// gate=false -> notice -> close, that neither notice nor close runs
/// under the registry's lock, and that reentrancy from BOTH notice and
/// close is deadlock-free — not just inspected, executed.
struct OrderRecordingSession {
    gate: std::sync::OnceLock<SessionGate>,
    registry: std::sync::OnceLock<Arc<MeshSessionRegistry<OrderRecordingSession>>>,
    probe_m_id: std::sync::OnceLock<MachineId>,
    log: StdMutex<Vec<&'static str>>,
    gate_was_false_at_notice: AtomicBool,
    gate_was_false_at_close: AtomicBool,
    reentrant_call_succeeded: AtomicBool,
}

impl Default for OrderRecordingSession {
    fn default() -> Self {
        Self {
            gate: std::sync::OnceLock::new(),
            registry: std::sync::OnceLock::new(),
            probe_m_id: std::sync::OnceLock::new(),
            log: StdMutex::new(Vec::new()),
            gate_was_false_at_notice: AtomicBool::new(false),
            gate_was_false_at_close: AtomicBool::new(false),
            reentrant_call_succeeded: AtomicBool::new(false),
        }
    }
}

impl RevocableMeshSession for OrderRecordingSession {
    fn send_best_effort_revoke_notice(&self) {
        self.log.lock().unwrap().push("notice");
        if let Some(gate) = self.gate.get() {
            self.gate_was_false_at_notice
                .store(!gate.is_authorized(), Ordering::SeqCst);
        }
        // Reentrancy: if this ran while the registry's lock were still
        // held, this would deadlock (std::sync::Mutex is not
        // reentrant) instead of completing.
        if let (Some(registry), Some(m_id)) = (self.registry.get(), self.probe_m_id.get()) {
            let _ = registry.is_registered(m_id);
            self.reentrant_call_succeeded.store(true, Ordering::SeqCst);
        }
    }

    fn close(&self) {
        self.log.lock().unwrap().push("close");
        if let Some(gate) = self.gate.get() {
            self.gate_was_false_at_close
                .store(!gate.is_authorized(), Ordering::SeqCst);
        }
        // Reentrancy from close() too, per round 3, point c.
        if let (Some(registry), Some(m_id)) = (self.registry.get(), self.probe_m_id.get()) {
            let _ = registry.registered_count(m_id);
        }
    }
}

#[test]
fn revocation_order_is_gate_false_then_notice_then_close_and_neither_reenters_under_lock() {
    let revoked_m_id = test_m_id(26);
    let other_m_id = test_m_id(27);
    let snapshot = snapshot_at(
        1,
        [1u8; 32],
        &[(revoked_m_id.clone(), FP_A), (other_m_id.clone(), FP_A)],
        &[],
    );
    let registry: Arc<MeshSessionRegistry<OrderRecordingSession>> =
        Arc::new(MeshSessionRegistry::new(&snapshot));

    let session = Arc::new(OrderRecordingSession::default());
    session.registry.set(Arc::clone(&registry)).ok();
    session.probe_m_id.set(other_m_id.clone()).ok();
    let binding = {
        let expectation = PeerExpectation::injected_for_harness(
            snapshot.checkpoint_hash(),
            revoked_m_id.clone(),
            PeerSelectionSource::LocalOwnerPresentSelection,
        );
        let responder = ExpectedResponder::from_peer_expectation(expectation, &snapshot).unwrap();
        SealedBinding::from_expected_responder(&responder, &snapshot)
    };
    let (_, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();
    session.gate.set(gate).ok();

    let revoke_snapshot = snapshot_at(2, [2u8; 32], &[(other_m_id, FP_A)], &[revoked_m_id]);
    registry.observe_new_checkpoint(&revoke_snapshot);

    assert!(session.gate_was_false_at_notice.load(Ordering::SeqCst));
    assert!(session.gate_was_false_at_close.load(Ordering::SeqCst));
    assert!(session.reentrant_call_succeeded.load(Ordering::SeqCst));
    assert_eq!(&*session.log.lock().unwrap(), &["notice", "close"]);
}

// ── Real thread-based race tests (round 2 request, round 3 reaffirmed
// as an acceptance criterion) ─────────────────────────────────────────

/// N register attempts race M revoke-triggering observes on real OS
/// threads, synchronized to start together via a Barrier, repeated over
/// many rounds. Invariant checked after every round: no session whose
/// gate reads true is for a machine the LAST successfully-applied
/// snapshot does not list as active-with-matching-fingerprint.
#[test]
fn concurrent_register_and_revoke_never_leaves_an_authorized_session_for_a_revoked_machine() {
    for round in 0..200u32 {
        let m_id = MachineId(format!("race-m-{round:06x}"));
        let live_snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
        let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&live_snapshot));
        let binding = Arc::new(sealed_binding(&live_snapshot, &m_id));
        let revoke_snapshot = Arc::new(snapshot_at(2, [2u8; 32], &[], std::slice::from_ref(&m_id)));

        let barrier = Arc::new(Barrier::new(2));
        let session = Arc::new(RecordingSession::default());

        let register_thread = {
            let registry = Arc::clone(&registry);
            let binding = Arc::clone(&binding);
            let barrier = Arc::clone(&barrier);
            let session = Arc::clone(&session);
            thread::spawn(move || {
                barrier.wait();
                registry.register(&binding, Arc::downgrade(&session))
            })
        };
        let revoke_thread = {
            let registry = Arc::clone(&registry);
            let revoke_snapshot = Arc::clone(&revoke_snapshot);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.observe_new_checkpoint(&revoke_snapshot)
            })
        };

        let register_outcome = register_thread.join().expect("register thread panicked");
        let _ = revoke_thread.join().expect("revoke thread panicked");

        if let Ok((_, gate)) = register_outcome {
            // Whichever order the two threads actually ran in, by the
            // time both have joined the machine is revoked in the
            // registry's revision, so the gate must now read false.
            // (If register ran first, observe's per-session sweep
            // revoked it; if observe ran first, register would have
            // seen MachineRevoked and this arm would not execute.)
            assert!(
                !gate.is_authorized(),
                "round {round}: session survived authorized past a concurrent revoke"
            );
        }
        assert!(
            !registry.is_registered(&m_id),
            "round {round}: machine still tracked after revoke"
        );
    }
}

#[test]
fn concurrent_register_and_mark_unavailable_never_leaves_an_authorized_session() {
    for round in 0..200u32 {
        let m_id = MachineId(format!("race-unavail-{round:06x}"));
        let live_snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
        let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&live_snapshot));
        let binding = Arc::new(sealed_binding(&live_snapshot, &m_id));

        let barrier = Arc::new(Barrier::new(2));
        let session = Arc::new(RecordingSession::default());

        let register_thread = {
            let registry = Arc::clone(&registry);
            let binding = Arc::clone(&binding);
            let barrier = Arc::clone(&barrier);
            let session = Arc::clone(&session);
            thread::spawn(move || {
                barrier.wait();
                registry.register(&binding, Arc::downgrade(&session))
            })
        };
        let unavailable_thread = {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.mark_unavailable();
            })
        };

        let register_outcome = register_thread.join().expect("register thread panicked");
        unavailable_thread
            .join()
            .expect("mark_unavailable thread panicked");

        match register_outcome {
            Ok((_, gate)) => assert!(
                !gate.is_authorized(),
                "round {round}: session survived authorized past a concurrent mark_unavailable"
            ),
            Err(RegisterRefusal::RegistryUnavailable) => {}
            Err(other) => panic!("round {round}: unexpected refusal {other:?}"),
        }
        assert!(
            registry.is_unavailable(),
            "round {round}: registry did not end Unavailable"
        );
    }
}

#[test]
fn concurrent_recovery_and_register_only_admits_sessions_consistent_with_recovered_revision() {
    for round in 0..200u32 {
        let m_id = MachineId(format!("race-recover-{round:06x}"));
        let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot_at(
            1,
            [1u8; 32],
            &[],
            &[],
        )));
        registry.mark_unavailable();
        let recovery_snapshot = Arc::new(snapshot_at(2, [2u8; 32], &[(m_id.clone(), FP_A)], &[]));
        let binding = Arc::new(sealed_binding(&recovery_snapshot, &m_id));

        let barrier = Arc::new(Barrier::new(2));
        let session = Arc::new(RecordingSession::default());

        let recover_thread = {
            let registry = Arc::clone(&registry);
            let recovery_snapshot = Arc::clone(&recovery_snapshot);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                registry.observe_new_checkpoint(&recovery_snapshot)
            })
        };
        let register_thread = {
            let registry = Arc::clone(&registry);
            let binding = Arc::clone(&binding);
            let barrier = Arc::clone(&barrier);
            let session = Arc::clone(&session);
            thread::spawn(move || {
                barrier.wait();
                registry.register(&binding, Arc::downgrade(&session))
            })
        };

        recover_thread.join().expect("recover thread panicked");
        let register_outcome = register_thread.join().expect("register thread panicked");

        // Either ordering is a valid, non-authorization-crossing
        // outcome: recovery-then-register succeeds (registry now Live
        // at the exact revision the binding names); register-then-
        // recovery is refused (registry was still Unavailable when
        // register ran).
        match register_outcome {
            Ok((_, gate)) => assert!(
                gate.is_authorized(),
                "round {round}: admitted with a false gate"
            ),
            Err(RegisterRefusal::RegistryUnavailable) => {}
            Err(other) => panic!("round {round}: unexpected refusal {other:?}"),
        }
    }
}

// ── Round 4 (@kiana): is_authorized() alone is check-then-forward, not
// a linearization. These prove try_authorize_forwarding()'s
// ForwardingGuard actually IS one, with real threads and real blocking
// — not just same-thread interleaving. ──────────────────────────────

/// `try_authorize_forwarding()` succeeds pre-revoke and fails post-revoke
/// on a single thread — the cheap sanity check the real race tests
/// below build on.
#[test]
fn try_authorize_forwarding_succeeds_pre_revoke_and_fails_post_revoke() {
    let m_id = test_m_id(50);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let guard = gate.try_authorize_forwarding();
    assert!(guard.is_some());
    drop(guard);

    let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], &[m_id]);
    registry.observe_new_checkpoint(&revoke_snapshot);

    assert!(gate.try_authorize_forwarding().is_none());
}

/// Round 4, pass 4 (@kiana): `try_enter()` must fail closed on a
/// poisoned `SessionSync.state`, never recover-and-trust. Poisons this
/// session's OWN state mutex directly (private field, same module) —
/// not via any registry-level method, since the registry's own
/// `PoisonGuard` only wraps `self.inner`, not any individual
/// `SessionSync`, so this is a genuinely distinct poison surface.
/// Proves ZERO guards are ever granted afterward, across many
/// attempts, not just once.
#[test]
fn poisoned_session_state_never_admits_a_reader() {
    let m_id = test_m_id(54);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();
    assert!(gate.try_authorize_forwarding().is_some());

    let sync = Arc::clone(&gate.sync);
    let poisoner = thread::spawn(move || {
        let _guard = sync.state.lock().unwrap();
        panic!("deliberate poison for RED test: SessionSync.state");
    });
    assert!(
        poisoner.join().is_err(),
        "poisoning thread must have panicked while holding SessionSync.state"
    );

    for attempt in 0..10 {
        assert!(
            gate.try_authorize_forwarding().is_none(),
            "attempt {attempt}: poisoned session state must never admit a reader"
        );
    }
}

/// Round 4, pass 5 (@kiana, a REAL executable RED from an independent
/// audit worktree, not a reading pass): admits a `ForwardingGuard`,
/// poisons `SessionSync.state` from an UNRELATED thread while that
/// guard is still held (mirrors `poisoned_session_state_never_admits_a_reader`'s
/// pattern — a panic that never touches `active_readers` at all), then
/// calls `revoke` from a third thread. `revoke` must NOT return before
/// the still-held guard is dropped, because poisoning the mutex does
/// not make its `active_readers` count untrustworthy (a plain `usize`
/// field cannot be torn by a panic that happened elsewhere in the same
/// critical section), and `ForwardingGuard::drop` already keeps that
/// count correct across poison — so `revoke` giving up on it early was
/// a real bug, not a defensible fail-closed choice.
#[test]
fn revoke_waits_for_an_admitted_reader_even_if_the_state_lock_is_poisoned_meanwhile() {
    let m_id = test_m_id(57);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    // (1) Admit a ForwardingGuard, held by this test thread for the
    // whole scenario.
    let guard = gate
        .try_authorize_forwarding()
        .expect("session active, no revoke has started yet");

    // (2) Poison SessionSync.state from an UNRELATED thread while the
    // guard above is still alive. This panic never touches
    // active_readers -- it only proves poisoning the mutex, not
    // corrupting the count.
    let sync = Arc::clone(&gate.sync);
    let poisoner = thread::spawn(move || {
        let _lock = sync.state.lock().unwrap();
        panic!("deliberate poison for RED test: revoke must still wait out an admitted reader");
    });
    assert!(
        poisoner.join().is_err(),
        "poisoning thread must have panicked while holding SessionSync.state"
    );

    // (3) A third thread calls revoke() (via observe_new_checkpoint)
    // while the guard from (1) is STILL held.
    let log: Arc<StdMutex<Vec<&'static str>>> = Arc::new(StdMutex::new(Vec::new()));
    let revoker = {
        let registry = Arc::clone(&registry);
        let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], std::slice::from_ref(&m_id));
        let log = Arc::clone(&log);
        thread::spawn(move || {
            registry.observe_new_checkpoint(&revoke_snapshot);
            log.lock().unwrap().push("revoke_returned");
        })
    };

    // Observable barrier: confirm the writer has actually announced
    // intent (real observation, not a timing guess) before checking
    // that it has not (yet) returned.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if gate.sync.writer_intent.load(Ordering::SeqCst) > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "writer never announced intent within the deadline"
        );
        thread::yield_now();
    }
    // A real window for the writer to have (incorrectly, if the bug
    // were still present) returned early -- then confirm it has not.
    thread::sleep(Duration::from_millis(200));
    assert!(
        log.lock().unwrap().is_empty(),
        "revoke must not return while an admitted ForwardingGuard is still held, \
             even if SessionSync.state was poisoned by an unrelated panic meanwhile"
    );

    // (4) Drop the guard -- revoke must complete promptly afterward.
    drop(guard);
    revoker.join().unwrap();

    assert_eq!(&*log.lock().unwrap(), &["revoke_returned"]);
    assert!(!gate.is_authorized());
}

/// The core linearization proof: a `ForwardingGuard` acquired BEFORE a
/// revoke starts must still be alive when the revoke call attempts to
/// close this session — and the revoke call (`observe_new_checkpoint`)
/// must NOT return until that guard is dropped. Proven with real OS
/// threads and an OBSERVABLE barrier: the test polls `SessionSync`'s
/// own `writer_intent` (accessible — this module's own test submodule)
/// until it confirms the revoker has actually announced intent, rather
/// than assuming a fixed sleep was "probably" enough. From that point,
/// since `active_readers` cannot drop to zero until this test
/// explicitly releases reader1, revoke is DETERMINISTICALLY still
/// blocked, not just probably.
#[test]
fn forwarding_guard_blocks_revoke_until_released_and_reader1_precedes_revoke_returned() {
    let m_id = test_m_id(51);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let log: Arc<StdMutex<Vec<&'static str>>> = Arc::new(StdMutex::new(Vec::new()));
    let (acquired_tx, acquired_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();

    let reader = {
        let gate = gate.clone();
        let log = Arc::clone(&log);
        thread::spawn(move || {
            let guard = gate
                .try_authorize_forwarding()
                .expect("session still active, no revoke has started yet");
            acquired_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            log.lock().unwrap().push("reader_released");
            drop(guard);
        })
    };
    acquired_rx.recv().unwrap();

    let revoker = {
        let registry = Arc::clone(&registry);
        let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], &[m_id]);
        let log = Arc::clone(&log);
        thread::spawn(move || {
            registry.observe_new_checkpoint(&revoke_snapshot);
            log.lock().unwrap().push("revoke_returned");
        })
    };

    // Observable barrier: poll the session's own state until the
    // writer has actually announced intent — a real observation, not a
    // timing guess. Once true, revoke is guaranteed still blocked
    // (this test controls exactly when reader1's guard is released).
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let announced = gate.sync.writer_intent.load(Ordering::SeqCst) > 0;
        if announced {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "writer never announced intent within the deadline"
        );
        thread::yield_now();
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "revoke must not complete while a ForwardingGuard for the revoked session is still held"
    );

    release_tx.send(()).unwrap();
    reader.join().unwrap();
    revoker.join().unwrap();

    assert_eq!(
        &*log.lock().unwrap(),
        &["reader_released", "revoke_returned"]
    );
    assert!(gate.try_authorize_forwarding().is_none());
}

/// A reader that attempts authorization only AFTER a writer has
/// announced intent to revoke (`writer_intent > 0`) must never
/// receive a guard — `try_enter` is non-blocking, so it is refused
/// IMMEDIATELY rather than waiting for the revoke to finish and only
/// then observing it closed. The barrier below confirms, by directly
/// observing state (not a sleep), both that the writer has announced
/// AND that it is still genuinely waiting on reader1 — and since this
/// test alone controls when reader1's guard is released, revoke is
/// deterministically still blocked at the moment reader2 attempts, not
/// probably.
#[test]
fn reader_that_attempts_after_writer_announces_intent_never_authorizes() {
    let m_id = test_m_id(52);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let log: Arc<StdMutex<Vec<&'static str>>> = Arc::new(StdMutex::new(Vec::new()));
    let (r1_acquired_tx, r1_acquired_rx) = mpsc::channel::<()>();
    let (release_r1_tx, release_r1_rx) = mpsc::channel::<()>();

    let reader1 = {
        let gate = gate.clone();
        let log = Arc::clone(&log);
        thread::spawn(move || {
            let guard = gate
                .try_authorize_forwarding()
                .expect("session active before any revoke");
            log.lock().unwrap().push("reader1_acquired");
            r1_acquired_tx.send(()).unwrap();
            release_r1_rx.recv().unwrap();
            log.lock().unwrap().push("reader1_released");
            drop(guard);
        })
    };
    r1_acquired_rx.recv().unwrap();

    let revoker = {
        let registry = Arc::clone(&registry);
        let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], std::slice::from_ref(&m_id));
        let log = Arc::clone(&log);
        thread::spawn(move || {
            registry.observe_new_checkpoint(&revoke_snapshot);
            log.lock().unwrap().push("revoke_returned");
        })
    };

    // Observable barrier: poll until the writer has actually announced
    // intent AND is confirmed still waiting on reader1 (active_readers
    // > 0). Real observation of internal state, not a sleep.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let announced = gate.sync.writer_intent.load(Ordering::SeqCst) > 0;
        let still_waiting = gate.sync.state.lock().unwrap().active_readers > 0;
        if announced && still_waiting {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "writer never announced intent (and kept waiting on reader1) within the deadline"
        );
        thread::yield_now();
    }

    // reader2's attempt happens strictly after the barrier confirmed
    // the writer had announced intent, and reader1's guard is still
    // held (not yet released by this test) — so revoke cannot possibly
    // have completed yet. try_enter() is non-blocking: this returns
    // immediately rather than waiting for revoke to finish.
    let reader2_authorized = gate.try_authorize_forwarding().is_some();
    log.lock().unwrap().push("reader2_result");

    assert!(
        !reader2_authorized,
        "a reader that attempted after the writer announced intent must never receive a guard"
    );

    release_r1_tx.send(()).unwrap();
    reader1.join().unwrap();
    revoker.join().unwrap();

    let final_log = log.lock().unwrap();
    let pos = |needle: &str| final_log.iter().position(|s| *s == needle).unwrap();
    // reader2's (correctly unauthorized) result was observed strictly
    // BEFORE reader1 was released and before revoke returned — proving
    // it was refused immediately by state, not merely refused late
    // after waiting for either.
    assert!(pos("reader2_result") < pos("reader1_released"));
    assert!(pos("reader2_result") < pos("revoke_returned"));
}

/// Writer starvation, bounded: a continuous stream of short-lived
/// forwarding guards (acquired and immediately released in a tight
/// loop across several threads) must not prevent a concurrent revoke
/// from ever completing. This holds by construction, not by scheduler
/// luck: the instant `revoke()` increments `writer_intent`, EVERY
/// subsequent `try_enter()` call — no matter how many readers keep
/// arriving — is refused before it can increment `active_readers`. So
/// `revoke()` only ever waits out the FIXED set of readers already
/// admitted at the moment it announced intent, never a growing one.
#[test]
fn revoke_is_not_starved_by_a_continuous_stream_of_short_lived_forwarding_guards() {
    let m_id = test_m_id(53);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (_id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..8)
        .map(|_| {
            let gate = gate.clone();
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Some(g) = gate.try_authorize_forwarding() {
                        drop(g);
                    }
                }
            })
        })
        .collect();

    // Let the reader storm actually get running before starting the
    // timed revoke — otherwise an unrelated thread-startup delay could
    // look like it was caused by the revoke itself.
    thread::sleep(Duration::from_millis(50));

    let (done_tx, done_rx) = mpsc::channel();
    let revoker = {
        let registry = Arc::clone(&registry);
        let m_id = m_id.clone();
        thread::spawn(move || {
            let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], &[m_id]);
            registry.observe_new_checkpoint(&revoke_snapshot);
            done_tx.send(()).ok();
        })
    };

    let bound = Duration::from_secs(5);
    let result = done_rx.recv_timeout(bound);
    stop.store(true, Ordering::Relaxed);
    for r in readers {
        r.join().unwrap();
    }
    revoker.join().unwrap();

    assert!(
        result.is_ok(),
        "revoke starved for more than {bound:?} under a continuous stream of short-lived forwarding guards"
    );
    assert!(gate.try_authorize_forwarding().is_none());
}

// ── D-1 successor (@kiana, 9664d363 audit) ──────────────────────────

/// P0/P1 E1 — compile/API proof, SCOPED: proves the REGISTRY's
/// production `try_preauthorize_before` -> `commit_after_ack` machinery has
/// no structural bias toward initiator-shaped bindings — a
/// responder-shaped `SealedBinding` (from `from_responding_peer`, not
/// `from_expected_responder`) reaches Active through the exact same
/// path, with no `PeerExpectation`/`ExpectedResponder` involved at
/// all. This does NOT by itself close E1 in production: constructing
/// the `AuthenticatedPeerClaim` this test starts from still requires
/// `#[cfg(test)] pub(crate) injected_for_harness`, which — being
/// `pub(crate)` — is invisible to any OTHER crate in ANY build mode,
/// not merely gated pending a future source. A real, cross-crate
/// production responder (the not-yet-integrated B-SESSAO CORE
/// handshake) still has no legitimate way to construct a claim today;
/// that remains an open, separately-tracked integration blocker (see
/// `AuthenticatedPeerClaim`'s doc comment). What this test DOES prove,
/// and what is safe to rely on: once something proves a claim by
/// whatever mechanism is eventually approved, the roster-authority
/// projection and the registry's admission path are already correct
/// and already tested for it.
#[test]
fn responder_side_binding_reaches_active_via_the_production_preauthorize_path() {
    let m_id = test_m_id(68);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding_responder(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .expect("active machine, matching revision, matching fingerprint");
    let active = admission.commit_after_ack();
    assert!(active.try_authorize_forwarding().is_some());
    assert!(registry.is_registered(&m_id));
}

/// P0-1 — RED, now fixed: a single `observe_new_checkpoint` call that
/// revokes TWO different sessions in one batch must not leave the
/// SECOND still admitting brand-new forwarding while the FIRST is
/// still draining a long-lived `ForwardingGuard`. Before the fix,
/// Phase B called `SessionSync::revoke()` sequentially per target, so
/// target B's own `writer_intent` stayed at zero — and its gate kept
/// reading authorized — for the entire time target A's drain was in
/// flight, even though the SAME checkpoint observation already
/// condemned both. See `revoke_batch`'s doc comment.
#[test]
fn batch_revoke_announces_to_every_target_before_draining_any() {
    let m_id_a = test_m_id(69);
    let m_id_b = test_m_id(70);
    let snapshot = snapshot_at(
        1,
        [1u8; 32],
        &[(m_id_a.clone(), FP_A), (m_id_b.clone(), FP_B)],
        &[],
    );
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding_a = sealed_binding(&snapshot, &m_id_a);
    let binding_b = sealed_binding(&snapshot, &m_id_b);
    let session_a = Arc::new(RecordingSession::default());
    let session_b = Arc::new(RecordingSession::default());
    let (_id_a, gate_a) = registry
        .register(&binding_a, Arc::downgrade(&session_a))
        .unwrap();
    let (_id_b, gate_b) = registry
        .register(&binding_b, Arc::downgrade(&session_b))
        .unwrap();

    // Session A holds an open ForwardingGuard across the whole revoke.
    let (acquired_tx, acquired_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder = {
        let gate_a = gate_a.clone();
        thread::spawn(move || {
            let guard = gate_a
                .try_authorize_forwarding()
                .expect("session A active before any revoke");
            acquired_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        })
    };
    acquired_rx.recv().unwrap();

    // Both A and B get revoked by the SAME checkpoint observation.
    let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], &[m_id_a.clone(), m_id_b.clone()]);
    let revoker = {
        let registry = Arc::clone(&registry);
        thread::spawn(move || registry.observe_new_checkpoint(&revoke_snapshot))
    };

    // Observable barrier: wait until Phase B has genuinely started
    // draining A (A's writer_intent > 0) before checking B — a real
    // observation, not a timing guess.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if gate_a.sync.writer_intent.load(Ordering::SeqCst) > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "writer never announced intent on A within the deadline"
        );
        thread::yield_now();
    }

    // The crux assertion: B must ALREADY reject new forwarding, even
    // though A's drain has not finished and B's own SessionSync was
    // never individually revoke()'d yet.
    assert!(
        gate_b.try_authorize_forwarding().is_none(),
        "B must already reject new forwarding once the batch announced revoke intent, \
             not only after A's drain finishes"
    );

    release_tx.send(()).unwrap();
    holder.join().unwrap();
    let outcome = revoker.join().unwrap();

    assert_eq!(outcome, ObserveOutcome::Applied);
    assert!(!gate_a.is_authorized());
    assert!(!gate_b.is_authorized());
    assert!(session_a.closed.load(Ordering::SeqCst));
    assert!(session_b.closed.load(Ordering::SeqCst));
}

/// Recheck (@kiana), on top of P0-1's own fix above: `announce_revoke`
/// for a revoked-by-Advance session must happen BEFORE
/// `last_known_revision` becomes externally observable (before
/// `self.inner`'s lock releases) — not merely before Phase B drains a
/// DIFFERENT target, which is all the previous test proves. Otherwise a
/// concurrent `preauthorize` for an unrelated machine could already act
/// on the new revision while the just-revoked session's gate is still
/// fully authorized, not even announced — breaking the
/// linearization-point contract this registry documents itself as
/// providing (module doc comment, CFX-5).
///
/// Uses the `#[cfg(test)]`-only hook rather than a timing race: with
/// the fix, `announce_batch` runs strictly before the SAME lock
/// `preauthorize` (for the new machine) must acquire to succeed, so the
/// hook -- which runs strictly AFTER that lock releases -- is
/// GUARANTEED by `Mutex`'s release/acquire semantics to observe
/// `writer_intent` already incremented, deterministically, not merely
/// probably. Both checks happen synchronously on one thread from
/// inside the hook, so this is a structural proof, not a race.
#[test]
fn advance_revocation_announces_before_the_new_revision_is_externally_observable() {
    let m_id_a = test_m_id(76);
    let m_id_new = test_m_id(77);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id_a.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding_a = sealed_binding(&snapshot, &m_id_a);
    let session_a = Arc::new(RecordingSession::default());
    let (_id_a, gate_a) = registry
        .register(&binding_a, Arc::downgrade(&session_a))
        .unwrap();
    assert!(gate_a.is_authorized());

    // A is revoked, and a brand-new machine becomes active, in the
    // SAME Advance.
    let snapshot2 = snapshot_at(2, [2u8; 32], &[(m_id_new.clone(), FP_A)], &[m_id_a.clone()]);
    let binding_new = sealed_binding(&snapshot2, &m_id_new);
    let session_new = Arc::new(RecordingSession::default());

    let outcome = registry.observe_new_checkpoint_with_hook_for_test(&snapshot2, || {
        // Runs strictly after Phase A's lock released
        // (last_known_revision is already snapshot2) and strictly
        // before Phase B starts draining.
        let admission = registry
            .preauthorize(&binding_new, Arc::downgrade(&session_new))
            .expect("the new revision must already be authoritative here");
        // A must already be refusing new forwarding at this EXACT
        // instant -- not "will be revoked soon", not "refused once
        // Phase B gets around to it".
        assert!(
            gate_a.sync.writer_intent.load(Ordering::SeqCst) > 0,
            "A's revoke must be announced before the lock publishing the new \
                 revision is released, not only before Phase B drains a sibling target"
        );
        assert!(gate_a.try_authorize_forwarding().is_none());
        drop(admission); // aborts cleanly; not what this test is about
    });

    assert_eq!(outcome, ObserveOutcome::Applied);
    assert!(!gate_a.is_authorized());
    assert!(session_a.closed.load(Ordering::SeqCst));
}

/// Second recheck (@kiana): the SAME class of race as the Advance test
/// above, but in `unregister`. A dead-simple sequential read of the
/// code shows `unregister` removed the session from `sessions`/
/// `by_machine` under the lock, released it, and ONLY THEN called
/// revoke -- so `registered_count`/`is_registered` for this machine
/// would already report the session gone the instant the lock
/// released, while a `SessionGate` cloned earlier could still obtain a
/// fresh `ForwardingGuard`, since nothing had announced revoke intent
/// yet. Deterministic via the same hook technique: the hook runs
/// strictly after the bookkeeping-removal lock released and strictly
/// before the drain, and checks `writer_intent`/`try_authorize_forwarding`
/// from there.
#[test]
fn unregister_announces_before_absence_is_externally_observable() {
    let m_id = test_m_id(78);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();
    assert!(gate.is_authorized());

    registry.unregister_with_hook_for_test(id, || {
        // Runs strictly after the removal lock released (registry
        // already reports this machine unregistered) and strictly
        // before the drain.
        assert_eq!(
            registry.registered_count(&m_id),
            0,
            "the lock publishing this session's absence must already be released here"
        );
        assert!(
            gate.sync.writer_intent.load(Ordering::SeqCst) > 0,
            "revoke must be announced before this session's absence is externally \
                 observable, not only before the (possibly slow) drain completes"
        );
        assert!(gate.try_authorize_forwarding().is_none());
    });

    assert!(!gate.is_authorized());
    assert!(session.closed.load(Ordering::SeqCst));
}

/// Second recheck (@kiana): same class of race in `registered_count`'s
/// own dead-Weak prune. The dead entry's `SessionSync` was collected
/// and removed from bookkeeping under the lock, but announcing only
/// happened via `revoke_batch` AFTER the lock released and `count`
/// had already been computed/published -- so a sibling
/// `registered_count`/`is_registered` call, or a stale `SessionGate`
/// clone, could observe the contradiction (session absent, but its old
/// gate still forwards) in that window.
#[test]
fn registered_count_prune_announces_before_absence_is_externally_observable() {
    let m_id = test_m_id(79);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let cloned_gate = {
        let session = Arc::new(RecordingSession::default());
        let (_id, gate) = registry
            .register(&binding, Arc::downgrade(&session))
            .unwrap();
        let cloned = gate.clone();
        assert!(cloned.is_authorized());
        cloned
        // `session` (the last strong Arc<H>) drops here.
    };

    let count = registry.registered_count_with_hook_for_test(&m_id, || {
        // Runs strictly after the prune's removal lock released
        // (count/absence already computed) and strictly before drain.
        assert!(
            cloned_gate.sync.writer_intent.load(Ordering::SeqCst) > 0,
            "revoke must be announced before this prune's absence is externally \
                 observable via `count`, not only before the drain completes"
        );
        assert!(cloned_gate.try_authorize_forwarding().is_none());
    });

    assert_eq!(count, 0);
    assert!(!cloned_gate.is_authorized());
}

/// P0-2 — RED, now fixed: pruning a dead `Weak` bookkeeping entry (the
/// session's last strong `Arc<H>` already dropped) must revoke its
/// `SessionSync`, not merely stop tracking it. Before the fix, a
/// `SessionGate` cloned BEFORE the handle was dropped kept reading
/// authorized forever after the prune, with no future observation
/// able to reach it (it is no longer in `sessions`/`by_machine` at
/// all).
#[test]
fn registered_count_prune_revokes_a_gate_cloned_before_the_handle_dropped() {
    let m_id = test_m_id(71);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let cloned_gate = {
        let session = Arc::new(RecordingSession::default());
        let (_id, gate) = registry
            .register(&binding, Arc::downgrade(&session))
            .unwrap();
        let cloned = gate.clone();
        assert!(cloned.is_authorized());
        cloned
        // `session` (the last strong Arc<H>) drops here.
    };

    // Triggers the dead-Weak prune path.
    assert_eq!(registry.registered_count(&m_id), 0);

    assert!(
        !cloned_gate.is_authorized(),
        "a gate cloned before its handle dropped must be revoked by the prune, \
             not merely untracked and left permanently authorized"
    );
    assert!(
        cloned_gate.try_authorize_forwarding().is_none(),
        "the production authorization surface must also reject it"
    );
}

/// Same defect class as the previous test, exercised at the OTHER
/// site that prunes a naturally-dead handle without going through
/// `unregister` — `observe_new_checkpoint`'s `Advance` branch, for a
/// session whose machine is untouched by the new revision (so it is
/// never in `to_revoke_ids`) but whose handle already dropped.
#[test]
fn observe_new_checkpoint_advance_prune_revokes_a_gate_cloned_before_the_handle_dropped() {
    let m_id = test_m_id(72);
    let other = test_m_id(73);
    let registry = new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let cloned_gate = {
        let session = Arc::new(RecordingSession::default());
        let (_id, gate) = registry
            .register(&binding, Arc::downgrade(&session))
            .unwrap();
        let cloned = gate.clone();
        assert!(cloned.is_authorized());
        cloned
        // `session` drops here; nothing observes it yet.
    };

    // `m_id` stays active with the SAME fingerprint (so `should_revoke`
    // is false for it -- it is NOT in `to_revoke_ids`); only `other`,
    // an unrelated machine never registered here, is tombstoned. Must
    // still sweep `m_id`'s dead handle out of `by_machine` via the
    // Advance branch's own bookkeeping-prune loop (`still_tracked`),
    // not the to_revoke_ids machinery.
    let unrelated_advance = snapshot_at(2, [2u8; 32], &[(m_id.clone(), FP_A)], &[other]);
    let outcome = registry.observe_new_checkpoint(&unrelated_advance);
    assert_eq!(outcome, ObserveOutcome::Applied);

    assert!(
        !cloned_gate.is_authorized(),
        "a gate cloned before its handle dropped must be revoked when the Advance branch \
             prunes the dead entry, not merely untracked"
    );
}

// ── retire_locally: callback-free retirement (D-9 facade seam) ──────

/// A session handle whose every trait method panics. Registering one and
/// keeping a strong `Arc` alive means ANY call into `H` — even a single
/// `handle.upgrade().close()` — aborts the test loudly. Non-vacuity is
/// established by `unregister_does_call_into_the_session_handle_positive_control`
/// below, which uses this same double and MUST panic.
struct PanicOnCallbackSession;

impl RevocableMeshSession for PanicOnCallbackSession {
    fn send_best_effort_revoke_notice(&self) {
        panic!("retire_locally must never call send_best_effort_revoke_notice");
    }

    fn close(&self) {
        panic!("retire_locally must never call close");
    }
}

/// RED 1 (@kiana): `retire_locally` must not call into `H` at all — it
/// is the operation a runtime facade's `Drop` uses, where external
/// protocol I/O is exactly what must not run.
///
/// Non-vacuous by construction: `session` (the strong `Arc`) is held
/// alive across the whole call, so `entry.handle.upgrade()` WOULD
/// succeed if anything tried it — the panicking double is genuinely
/// reachable, not silently skipped by a dead `Weak`. Asserted
/// explicitly below, and cross-checked by the positive control.
#[test]
fn retire_locally_never_calls_into_the_session_handle() {
    let m_id = test_m_id(80);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<PanicOnCallbackSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(PanicOnCallbackSession);
    let (id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();
    assert!(gate.is_authorized());

    registry.retire_locally(id);

    assert_eq!(
        Arc::strong_count(&session),
        1,
        "the handle must still be alive here — otherwise upgrade() would return None \
             and this test would pass without ever exercising the callback path"
    );
    // The authority guarantee still holds, callbacks or not.
    assert!(!gate.is_authorized());
    assert!(gate.try_authorize_forwarding().is_none());
    assert_eq!(registry.registered_count(&m_id), 0);
    drop(session);
}

/// Positive control for the test above: the SAME panicking double, the
/// SAME registration, but via `unregister` — which is documented to
/// notify and close. It must panic. Without this, "retire_locally did
/// not panic" would be consistent with the double never being wired up
/// correctly in the first place.
#[test]
#[should_panic(expected = "send_best_effort_revoke_notice")]
fn unregister_does_call_into_the_session_handle_positive_control() {
    let m_id = test_m_id(81);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<PanicOnCallbackSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(PanicOnCallbackSession);
    let (id, _gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();
    registry.unregister(id);
}

/// RED 2 (@kiana): `retire_locally` must genuinely linearize against an
/// in-flight forward — it must not return while a `ForwardingGuard` for
/// this session is still held, and the gate must reject afterward.
/// Same observable-barrier technique as
/// `unregister_waits_for_an_in_flight_forward_before_returning` (poll
/// `writer_intent` to confirm the announce landed; since this test alone
/// controls when the guard is released, the retirement is then
/// deterministically still blocked, not merely probably).
#[test]
fn retire_locally_waits_for_an_in_flight_forward_before_returning() {
    let m_id = test_m_id(82);
    let registry = Arc::new(new_registry_with(1, [1u8; 32], &[(m_id.clone(), FP_A)]));
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let log: Arc<StdMutex<Vec<&'static str>>> = Arc::new(StdMutex::new(Vec::new()));
    let (acquired_tx, acquired_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();

    let holder = {
        let gate = gate.clone();
        let log = Arc::clone(&log);
        thread::spawn(move || {
            let guard = gate
                .try_authorize_forwarding()
                .expect("session active, no retirement has started yet");
            acquired_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            log.lock().unwrap().push("guard_released");
            drop(guard);
        })
    };
    acquired_rx.recv().unwrap();

    let retirer = {
        let registry = Arc::clone(&registry);
        let log = Arc::clone(&log);
        thread::spawn(move || {
            registry.retire_locally(id);
            log.lock().unwrap().push("retire_returned");
        })
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if gate.sync.writer_intent.load(Ordering::SeqCst) > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "retire_locally never announced revoke intent within the deadline"
        );
        thread::yield_now();
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "retire_locally must not return while a ForwardingGuard for this session is \
             still held"
    );

    release_tx.send(()).unwrap();
    holder.join().unwrap();
    retirer.join().unwrap();

    assert_eq!(
        &*log.lock().unwrap(),
        &["guard_released", "retire_returned"]
    );
    assert!(!gate.is_authorized());
    assert!(gate.try_authorize_forwarding().is_none());
    // No notice/close ever ran, even though this handle records them.
    assert_eq!(session.notices_sent.load(Ordering::SeqCst), 0);
    assert!(!session.closed.load(Ordering::SeqCst));
}

/// RED 3 (@kiana): same happens-before property proven for `unregister`
/// and the Advance branch, now for `retire_locally` — announce must land
/// before this session's absence is externally observable, not merely
/// before the (possibly slow) drain completes.
#[test]
fn retire_locally_announces_before_absence_is_externally_observable() {
    let m_id = test_m_id(83);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();
    assert!(gate.is_authorized());

    registry.retire_locally_with_hook_for_test(id, || {
        assert_eq!(
            registry.registered_count(&m_id),
            0,
            "the lock publishing this session's absence must already be released here"
        );
        assert!(
            gate.sync.writer_intent.load(Ordering::SeqCst) > 0,
            "revoke must be announced before this session's absence is externally \
                 observable, not only before the drain completes"
        );
        assert!(gate.try_authorize_forwarding().is_none());
    });

    assert!(!gate.is_authorized());
    assert_eq!(session.notices_sent.load(Ordering::SeqCst), 0);
    assert!(!session.closed.load(Ordering::SeqCst));
}

/// Round D-1 successor (@kiana): the completion half of
/// `retire_locally`'s guarantee belongs to the caller that actually
/// removed the entry, and the API must say so rather than claim it
/// unconditionally.
///
/// Reproduces the exact race deterministically, without threads or
/// timing: the hook runs after the winner released the lock but BEFORE
/// the winner drained, and a second `retire_locally` issued from
/// exactly that point finds the entry already gone. That second call is
/// the "loser" — it must report `NotTracked`, not
/// `RetiredAndDrained`, because at that instant the winner genuinely
/// has not drained yet.
#[test]
fn a_second_retire_that_finds_the_entry_already_gone_reports_not_tracked() {
    let m_id = test_m_id(84);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (id, gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    let loser_outcome: StdMutex<Option<RetireOutcome>> = StdMutex::new(None);
    let winner_outcome = registry.retire_locally_with_hook_for_test(id, || {
        // The winner has removed + announced and released the lock, but
        // has NOT drained yet. A concurrent retirement arriving now
        // sees the absence.
        *loser_outcome.lock().unwrap() = Some(registry.retire_locally(id));
    });

    assert_eq!(winner_outcome, RetireOutcome::RetiredAndDrained);
    assert_eq!(
        *loser_outcome.lock().unwrap(),
        Some(RetireOutcome::NotTracked),
        "a caller that found the entry already gone must not claim the drain guarantee"
    );
    // Authority is closed regardless of which caller observed what.
    assert!(!gate.is_authorized());
    assert!(gate.try_authorize_forwarding().is_none());
}

/// The ordinary single-owner path — what the official facade wrapper
/// does — reports the full guarantee.
#[test]
fn a_sole_retire_reports_retired_and_drained() {
    let m_id = test_m_id(85);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (id, _gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    assert_eq!(
        registry.retire_locally(id),
        RetireOutcome::RetiredAndDrained
    );
    // Retiring an unknown session is NotTracked, not a full guarantee.
    assert_eq!(registry.retire_locally(id), RetireOutcome::NotTracked);
}

/// An `Unavailable` registry cannot announce or drain any individual
/// session, and must say so rather than report a guarantee it did not
/// provide.
#[test]
fn retire_on_an_unavailable_registry_reports_registry_unavailable() {
    let m_id = test_m_id(86);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let (id, _gate) = registry
        .register(&binding, Arc::downgrade(&session))
        .unwrap();

    registry.mark_unavailable();

    assert_eq!(
        registry.retire_locally(id),
        RetireOutcome::RegistryUnavailable
    );
}

// ── D-1 bounded admission REDs (@kiana audit `caf6d1e4`) ────────────

/// RED-1: `inner` held ⇒ `try_preauthorize_before` reports `Busy`
/// immediately, with **zero** effect: no insert, and no `SessionId`
/// consumed. Also covers the expired-deadline arm doing nothing.
#[test]
fn red1_try_preauthorize_is_busy_under_contention_and_inserts_nothing() {
    let m_id = test_m_id(87);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());

    let far = Instant::now() + Duration::from_secs(60);
    let busy = registry.hold_inner_while(|| {
        registry
            .try_preauthorize_before(&binding, Arc::downgrade(&session), far)
            .err()
    });
    assert_eq!(busy, Some(TryPreauthorizeError::Busy));

    // An already-expired deadline is refused too, and equally without
    // effect -- the check happens inside the lock, before any mutation.
    let expired = Instant::now();
    let outcome = registry.try_preauthorize_before(&binding, Arc::downgrade(&session), expired);
    assert_eq!(outcome.err(), Some(TryPreauthorizeError::Expired));

    // The decisive assertion: neither refusal consumed a SessionId, so
    // the next real reserve still gets the first one.
    let admission = registry
        .try_preauthorize_before(&binding, Arc::downgrade(&session), far)
        .expect("uncontended, unexpired");
    assert_eq!(
        admission.session_id,
        SessionId(1),
        "a Busy/Expired reserve must not consume a SessionId"
    );
}

/// RED-2: Pending `Drop` completes with BOTH `inner` and
/// `SessionSync.state` held, closes the phase, and calls nothing on
/// `H` — proven with a handle whose every method panics, kept strongly
/// alive so it is genuinely reachable.
#[test]
fn red2_pending_drop_is_lock_free_and_callback_free() {
    let m_id = test_m_id(88);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<PanicOnCallbackSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(PanicOnCallbackSession);
    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .unwrap();
    let sync = Arc::clone(&admission.sync);

    // Hold `state` too, so both mutexes are unavailable to Drop.
    let state_guard = sync.state.lock().unwrap();
    registry.hold_inner_while(|| {
        drop(admission); // must not block on either lock, must not call H
        assert_eq!(
            sync.phase(),
            PHASE_CLOSED,
            "Drop must close authority with no lock at all"
        );
    });
    drop(state_guard);

    assert_eq!(Arc::strong_count(&session), 1, "handle stayed reachable");
    assert!(sync.try_enter().is_none());
    drop(session);
}

/// RED-5: partial Ack. Cancel closes authority instantly even though
/// `inner` is unavailable, a revoker parked on the Pending phase is
/// released, the outcome honestly reports deferred cleanup, and a later
/// reconcile removes the entry. No Active ever exists.
#[test]
fn red5_cancel_closes_immediately_and_defers_only_bookkeeping() {
    let m_id = test_m_id(89);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<RecordingSession>::new(&snapshot));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .unwrap();
    let sync = Arc::clone(&admission.sync);

    // A revoker announces and parks waiting for the phase to leave
    // Pending.
    let (done_tx, done_rx) = mpsc::channel();
    let revoker = {
        let sync = Arc::clone(&sync);
        thread::spawn(move || {
            sync.announce_revoke();
            sync.drain_after_announce();
            done_tx.send(()).unwrap();
        })
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while sync.writer_intent.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "revoker never announced");
        thread::yield_now();
    }
    assert!(done_rx.try_recv().is_err(), "revoker must still be parked");

    // Cancel while `inner` is unavailable.
    let outcome = registry.hold_inner_while(|| admission.cancel_before_ack());

    assert_eq!(outcome, PendingCancelOutcome::ClosedCleanupDeferred);
    assert_eq!(sync.phase(), PHASE_CLOSED);
    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("closing the phase must release the parked revoker");
    revoker.join().unwrap();

    // The deferred debt is real, then reconciled.
    assert!(matches!(
        registry.reconcile_closed_pending(),
        ReconcileOutcome::Swept { removed: 1 }
    ));
    assert_eq!(registry.registered_count(&m_id), 0);
}

/// RED-6: the lost-wakeup property. The hook fires while `state` is
/// held, after the phase check and before the `Condvar` wait — exactly
/// where a lock-free `close_if_pending` + `notify_all` has no waiter to
/// wake. An untimed wait would wedge here permanently; the timed
/// recheck must recover.
#[test]
fn pending_drop_never_wedges_a_revoker_that_notified_before_waiting() {
    let sync = SessionSync::new_pending();
    sync.announce_revoke();

    let closed_once = AtomicBool::new(false);
    let drainer = {
        let sync = Arc::clone(&sync);
        thread::spawn(move || {
            sync.drain_after_announce_inner(|| {
                // Deliver the notification into the gap where nobody
                // is waiting yet. Idempotent, so only the first
                // iteration actually transitions.
                if !closed_once.swap(true, Ordering::SeqCst) {
                    sync.close_if_pending();
                }
            });
        })
    };

    assert!(
        drainer.join().is_ok(),
        "a notify delivered before the wait must not wedge the drain"
    );
    assert_eq!(sync.phase(), PHASE_CLOSED);
}

/// RED-7: closing and reconciling are idempotent — repeated closes do
/// not double-transition, and repeated sweeps do not underflow or
/// remove twice.
#[test]
fn red7_close_and_reconcile_are_idempotent() {
    let sync = SessionSync::new_pending();
    assert!(sync.close_if_pending(), "first close transitions");
    assert!(!sync.close_if_pending(), "second close is a no-op");
    assert!(!sync.close_if_pending());
    assert_eq!(sync.phase(), PHASE_CLOSED);
    // A Closed session must never be resurrected by a late commit.
    assert!(!sync.commit_after_ack());
    assert_eq!(sync.phase(), PHASE_CLOSED);

    let m_id = test_m_id(90);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());
    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .unwrap();
    assert_eq!(
        admission.cancel_before_ack(),
        PendingCancelOutcome::ClosedAndRemoved
    );
    assert!(matches!(
        registry.reconcile_closed_pending(),
        ReconcileOutcome::Swept { removed: 0 }
    ));
    assert!(matches!(
        registry.reconcile_closed_pending(),
        ReconcileOutcome::Swept { removed: 0 }
    ));
}

/// RED-8, household half: a ceremony deadline that expired during the
/// final Ack syscall cannot affect the commit, because `commit_after_ack`
/// takes no deadline at all. (Refusing the first DATA authorization on
/// the stored effective expiry is the runtime adapter's half — household
/// stores no expiry.)
#[test]
fn red8_an_expired_ceremony_deadline_cannot_veto_a_completed_ack() {
    let m_id = test_m_id(91);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());

    let ceremony_deadline = Instant::now() + Duration::from_millis(5);
    let admission = registry
        .try_preauthorize_before(&binding, Arc::downgrade(&session), ceremony_deadline)
        .expect("reserved while the deadline was still valid");

    // The deadline lapses during the (modelled) Ack write.
    while Instant::now() < ceremony_deadline {
        std::hint::spin_loop();
    }
    assert!(Instant::now() >= ceremony_deadline);

    let active = admission.commit_after_ack();
    assert!(active.try_authorize_forwarding().is_some());
    assert_eq!(registry.registered_count(&m_id), 1);
}

/// RED-9: Active RAII `Drop` retires without any callback into `H`.
/// Positive control lives in
/// `unregister_does_call_into_the_session_handle_positive_control`.
#[test]
fn red9_active_registration_drop_retires_without_callbacks() {
    let m_id = test_m_id(92);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<PanicOnCallbackSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(PanicOnCallbackSession);

    let sync = {
        let active = registry
            .preauthorize(&binding, Arc::downgrade(&session))
            .unwrap()
            .commit_after_ack();
        assert!(active.try_authorize_forwarding().is_some());
        assert_eq!(registry.registered_count(&m_id), 1);
        let sync = {
            let guard = registry.inner.lock().unwrap();
            let Mode::Live { sessions, .. } = &guard.mode else {
                panic!("live");
            };
            Arc::clone(&sessions[&active.session_id()].sync)
        };
        sync
        // `active` drops here -> retire_locally, callback-free.
    };

    assert_eq!(Arc::strong_count(&session), 1, "handle stayed reachable");
    assert_eq!(sync.phase(), PHASE_CLOSED);
    assert!(sync.try_enter().is_none());
    assert_eq!(registry.registered_count(&m_id), 0);
    drop(session);
}

/// RED-11: a poisoned `inner` still gets a fully closed phase from
/// Pending `Drop` (it takes no lock), no callback runs, and reconcile
/// reports `RegistryUnavailable` rather than claiming a drain it could
/// not perform.
#[test]
fn red11_poisoned_registry_still_closes_pending_atomically() {
    let m_id = test_m_id(93);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = Arc::new(MeshSessionRegistry::<PanicOnCallbackSession>::new(
        &snapshot,
    ));
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(PanicOnCallbackSession);
    let admission = registry
        .preauthorize(&binding, Arc::downgrade(&session))
        .unwrap();
    let sync = Arc::clone(&admission.sync);

    {
        let registry = Arc::clone(&registry);
        thread::spawn(move || registry.poison_for_test())
            .join()
            .expect_err("poisoning panics by design");
    }

    drop(admission);

    assert_eq!(sync.phase(), PHASE_CLOSED);
    assert!(sync.try_enter().is_none());
    assert_eq!(Arc::strong_count(&session), 1, "no callback, handle intact");
    assert_eq!(
        registry.reconcile_closed_pending(),
        ReconcileOutcome::RegistryUnavailable
    );
    drop(session);
}

/// RED-10, compile-POSITIVE half: the household permit really does bind
/// to a GAT whose `Pending<'a>` borrows the registry. The audit flagged
/// this as blocking — a plain associated type cannot name
/// `PendingSessionAdmission<'registry, H>` without erasing the lifetime
/// or reaching for a self-referential adapter — so the seam is proven
/// here rather than asserted, and it lives in household (no extra cargo
/// target) even though the real trait will live in core.
///
/// The compile-fail companions are in
/// `tests/compile-fail/` (non-`Clone` permit, and the Active wrapper
/// hiding its raw gate).
#[test]
fn red10_pending_permit_binds_to_a_lifetime_generic_associated_type() {
    trait D1AdmissionSeam {
        type Session: RevocableMeshSession;
        type Pending<'a>
        where
            Self: 'a;
        type Active<'a>
        where
            Self: 'a;

        fn reserve_pending<'a>(
            &'a self,
            binding: &SealedBinding,
            handle: Weak<Self::Session>,
            deadline_at: Instant,
        ) -> Result<Self::Pending<'a>, TryPreauthorizeError>;

        fn commit<'a>(pending: Self::Pending<'a>) -> Self::Active<'a>;
    }

    impl<H: RevocableMeshSession> D1AdmissionSeam for MeshSessionRegistry<H> {
        type Session = H;
        type Pending<'a>
            = PendingSessionAdmission<'a, H>
        where
            Self: 'a;
        type Active<'a>
            = ActiveSessionRegistration<'a, H>
        where
            Self: 'a;

        fn reserve_pending<'a>(
            &'a self,
            binding: &SealedBinding,
            handle: Weak<H>,
            deadline_at: Instant,
        ) -> Result<Self::Pending<'a>, TryPreauthorizeError> {
            self.try_preauthorize_before(binding, handle, deadline_at)
        }

        fn commit<'a>(pending: Self::Pending<'a>) -> Self::Active<'a> {
            // No deadline, no Result -- the seam preserves the terminal
            // rule rather than re-opening it.
            pending.commit_after_ack()
        }
    }

    let m_id = test_m_id(94);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);
    let session = Arc::new(RecordingSession::default());

    let pending = registry
        .reserve_pending(
            &binding,
            Arc::downgrade(&session),
            Instant::now() + Duration::from_secs(60),
        )
        .expect("uncontended reserve through the GAT seam");
    let active = <MeshSessionRegistry<RecordingSession> as D1AdmissionSeam>::commit(pending);
    assert!(active.try_authorize_forwarding().is_some());
    assert_eq!(registry.registered_count(&m_id), 1);
}

/// RED for @kiana's recheck of `d721f889`: a successful reserve — and
/// ONLY a successful reserve — must pay down deferred-cancel debt.
///
/// The adversarial shape this closes: cancel while `inner` is busy (so
/// cleanup defers), then never call `reconcile_closed_pending`,
/// `registered_count`/`is_registered`, or `observe_new_checkpoint`
/// again — just keep reserving. Before the fix each Closed entry stayed
/// in the map forever and the set grew without bound.
///
/// Deliberately does NOT let the handle die: keeping `victim_session`
/// strongly alive means the pre-existing dead-`Weak` prune cannot be
/// what removes the entry, so the assertion can only be satisfied by
/// phase-based pruning at the reserve site.
#[test]
fn a_successful_reserve_pays_down_deferred_cancel_debt() {
    let m_id = test_m_id(95);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);

    // Keep the victim's handle ALIVE for the whole test.
    let victim_session = Arc::new(RecordingSession::default());
    let victim = registry
        .preauthorize(&binding, Arc::downgrade(&victim_session))
        .unwrap();

    // Cancel under contention -> authority closed, cleanup deferred.
    let outcome = registry.hold_inner_while(|| victim.cancel_before_ack());
    assert_eq!(outcome, PendingCancelOutcome::ClosedCleanupDeferred);
    assert_eq!(
        live_entry_count(&registry),
        1,
        "the Closed entry is still tracked debt at this point"
    );

    // From here on: no reconcile, no registered_count/is_registered, no
    // observe_new_checkpoint. A single successful reserve, nothing else.
    let next_session = Arc::new(RecordingSession::default());
    let admission = registry
        .try_preauthorize_before(
            &binding,
            Arc::downgrade(&next_session),
            Instant::now() + Duration::from_secs(60),
        )
        .expect("uncontended, unexpired");

    assert_eq!(
        live_entry_count(&registry),
        1,
        "the debt must be gone, leaving only the newly reserved entry"
    );
    assert!(
        Arc::strong_count(&victim_session) > 0,
        "the victim handle stayed alive — a dead-Weak prune cannot be what cleaned up"
    );
    drop(admission);
    drop(victim_session);
}

/// Reads the tracked-entry count directly, without going through
/// `registered_count`/`is_registered` — those prune, which would mask
/// exactly the property under test.
fn live_entry_count<H: RevocableMeshSession>(registry: &MeshSessionRegistry<H>) -> usize {
    let guard = registry.inner.lock().unwrap();
    let Mode::Live { sessions, .. } = &guard.mode else {
        panic!("registry must be live");
    };
    sessions.len()
}

/// RED for @kiana's recheck of `28c5e992`: `SessionIdSpaceExhausted` is
/// a REFUSAL, so like every other refusal it must leave the registry
/// bit-for-bit unchanged — including not paying down reconcile debt.
///
/// The previous ordering swept Closed entries before `checked_add`, so
/// an exhausted id space returned a refusal that had already mutated
/// the map. Small, but it silently contradicted the contract documented
/// at that very call site, and "refusals change nothing" is the
/// property the whole bounded-reserve design leans on.
///
/// Debt is created with a LIVE handle so the dead-`Weak` prune cannot
/// be what does (or does not) remove it.
#[test]
fn an_exhausted_session_id_space_refuses_without_paying_debt() {
    let m_id = test_m_id(96);
    let snapshot = snapshot_at(1, [1u8; 32], &[(m_id.clone(), FP_A)], &[]);
    let registry = MeshSessionRegistry::<RecordingSession>::new(&snapshot);
    let binding = sealed_binding(&snapshot, &m_id);

    // Deferred-cancel debt, handle kept strongly alive throughout.
    let victim_session = Arc::new(RecordingSession::default());
    let victim = registry
        .preauthorize(&binding, Arc::downgrade(&victim_session))
        .unwrap();
    assert_eq!(
        registry.hold_inner_while(|| victim.cancel_before_ack()),
        PendingCancelOutcome::ClosedCleanupDeferred
    );
    assert_eq!(live_entry_count(&registry), 1, "debt is present");

    // Exhaust the id space.
    registry.inner.lock().unwrap().next_session_id = u64::MAX;

    let session = Arc::new(RecordingSession::default());
    let outcome = registry.try_preauthorize_before(
        &binding,
        Arc::downgrade(&session),
        Instant::now() + Duration::from_secs(60),
    );

    assert_eq!(
        outcome.err(),
        Some(TryPreauthorizeError::Refused(
            RegisterRefusal::SessionIdSpaceExhausted
        ))
    );
    assert_eq!(
        live_entry_count(&registry),
        1,
        "a refused reserve must not sweep debt — refusals change nothing"
    );
    assert_eq!(
        registry.inner.lock().unwrap().next_session_id,
        u64::MAX,
        "a refused reserve must not consume a SessionId"
    );
    assert!(Arc::strong_count(&victim_session) > 0);
    drop(victim_session);
}
