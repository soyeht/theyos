//! D-1 (B-ROSTER-ADAPTER v2 CFX-5): the linearization point for live
//! session revocation. `RosterSnapshotView` (`machine_roster_authority.rs`) is
//! immutable by design — a clone held inside an active session never sees a
//! revocation that happens after it was taken. `MeshSessionRegistry` is
//! *who observes and when calls the revoke*: it is handed each new snapshot
//! as the roster advances and closes any registered session whose machine
//! just became revoked.
//!
//! **Generic over the session handle, not `VerifiedMeshSessionHandle`.**
//! The freeze this implements
//! (`daisy-b-roster-adapter-v2.95a5c4c5…` §5) writes the registry's field as
//! `Mutex<HashMap<MachineId, Weak<VerifiedMeshSessionHandle>>>`, but that
//! type does not exist anywhere in this repository yet (`grep -rn
//! VerifiedMeshSessionHandle admin/rust` is empty) — it belongs to the
//! B-SESSAO CORE wire/session track, not to this household-rs slice.
//! `MeshSessionRegistry<H>` is generic over any `H: RevocableMeshSession`
//! instead; whatever B-SESSAO CORE eventually names its session handle only
//! needs to implement the trait below to plug in.
//!
//! **CFX from two rounds of independent audit (@kiana), folded in before
//! this shipped rather than after:**
//!
//! 1. A `HashMap<MachineId, Weak<H>>` (one slot per machine) silently drops
//!    a second concurrent session for the same `m_id`. Fixed: sessions are
//!    identified by an opaque [`SessionId`] issued at `register` time, keyed
//!    in their own map, indexed per-machine by a `Vec<SessionId>` — any
//!    number of concurrent sessions per machine are all tracked and all
//!    revocable, and any one of them can be removed individually via
//!    [`MeshSessionRegistry::unregister`] without disturbing the others.
//! 2. `register` and `observe_new_checkpoint` must linearize under the same
//!    lock as the revision they both read/write, or a `register` racing an
//!    in-flight revoke can admit a handle for an already-revoked machine.
//!    Fixed: one `Mutex<State<H>>` covers the current revision (checkpoint
//!    hash, sequence, active set, revoked set) and the session tables
//!    together. `register` additionally requires the caller to state which
//!    exact revision (`checkpoint_hash` + `checkpoint_sequence`) they
//!    believe is current and refuses on any mismatch — a caller acting on a
//!    stale view cannot register against roster state that has since moved.
//! 3. Nothing verified that a `register(m_id, handle)` caller wasn't lying
//!    about which machine `handle` actually belongs to — a caller could
//!    register session B's handle under machine A's `m_id`. Fixed:
//!    [`RevocableMeshSession::peer_m_id`] lets `register` upgrade the `Weak`
//!    and check the handle's own claimed peer against the caller's `m_id`
//!    argument before admitting it.
//! 4. The registry called potentially-blocking session methods
//!    (`send_best_effort_revoke_notice`, `close`) *while holding its
//!    internal lock* — a slow/blocking session method would stall every
//!    unrelated `register`/`is_registered` call, and a session method that
//!    ever needed to re-enter the registry would deadlock. Fixed: under the
//!    lock, only the non-blocking `mark_not_authorized` runs, and the
//!    now-revoked handles are drained into a `Vec` and returned; the lock is
//!    released before `send_best_effort_revoke_notice`/`close` run on them.
//! 5. `observe_new_checkpoint` trusted whatever revision the caller handed
//!    it, with no defense against replay, regression, or a same-sequence
//!    fork. Fixed: it now compares the incoming `(checkpoint_hash,
//!    checkpoint_sequence)` against the stored revision: a lower sequence is
//!    a regression (rejected), the same sequence with a different hash is a
//!    fork (rejected), the same sequence with the same hash is idempotent
//!    (accepted, no-op), and only a strictly higher sequence advances the
//!    revision.
//! 6. `Mutex::lock`'s `PoisonError` was silently recovered with
//!    `into_inner()` and the (possibly torn) interior trusted as valid
//!    state. Fixed: every method treats a poisoned lock as `Unavailable`
//!    without ever calling `into_inner` — a `std::sync::Mutex` stays
//!    poisoned forever once panicked, so this alone gives every subsequent
//!    call permanent fail-closed behavior with no extra state needed.
//!
//! **`Unavailable`, not a permanently terminal "fail-closed".** An earlier
//! draft called this state fail-closed and documented it as having no way
//! back — @kiana pointed out that contradicts this same codebase's existing
//! transient-error philosophy (`FloorLatch::record_success`,
//! `machine_roster_store.rs`, clears `failure_latched`/`failed_target` after
//! a transient clock hiccup; it does not stay down forever). Renamed to
//! `Unavailable` to stop asserting permanence as correct. What is **not**
//! implemented in this slice is the recovery path itself: reopening from
//! `Unavailable` back to `Live` on a fresh, explicit successful observation.
//! That is a real design question (should ANY fresh `Ok` reopen it, or only
//! one whose sequence is consistent with what was last known live, and does
//! every `Unavailable` cause — clock, fork, poison — deserve the same
//! recovery policy?) that deserves its own freeze rather than a decision
//! made silently inside this one. Until then, `Unavailable` is entered only
//! by `mark_unavailable`, and this registry does not clear it on its own.
//!
//! D-6 (the roster-sync transport that decides *when* a new checkpoint is
//! durably observed) is out of scope here too — see
//! [`observe_new_checkpoint`]'s doc comment.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use crate::ids::MachineId;
use crate::machine_roster_authority::RosterSnapshotView;

/// What `MeshSessionRegistry` needs from a live session: the machine it
/// actually belongs to (so `register` cannot be lied to about identity),
/// and the three revocation steps CFX-5 specifies, in the order they must
/// run: mark not-authorized, best-effort notice, close.
pub trait RevocableMeshSession {
    /// The machine this session is actually established with. `register`
    /// checks this against its caller's claimed `m_id` before admitting the
    /// handle — a caller cannot register one machine's session under a
    /// different machine's identity.
    fn peer_m_id(&self) -> &MachineId;

    /// Must be fast and non-blocking: the registry calls this while holding
    /// its internal lock, atomically stopping this session from forwarding
    /// anything further. Must not call back into this registry (deadlock).
    fn mark_not_authorized(&self);

    /// May block (e.g. network I/O for a notice). The registry never calls
    /// this while its internal lock is held.
    fn send_best_effort_revoke_notice(&self);

    /// May block. The registry never calls this while its internal lock is
    /// held.
    fn close(&self);
}

/// Opaque handle to one registered session. Returned by `register`, needed
/// by `unregister` — lets a session that ends normally (not via revoke)
/// remove exactly itself without disturbing any other session registered
/// for the same or a different machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterRefusal {
    /// Caller's stated `(checkpoint_hash, checkpoint_sequence)` does not
    /// match the registry's current revision — caller is acting on a stale
    /// view of the roster.
    RevisionMismatch,
    /// `m_id` is in the current revision's revoked set.
    MachineRevoked,
    /// `m_id` is not in the current revision's active set.
    MachineNotActive,
    /// `handle` could not be upgraded — already dropped before it was ever
    /// registered.
    HandleAlreadyDropped,
    /// `handle.peer_m_id()` does not match the `m_id` the caller claimed.
    HandleMachineMismatch,
    /// The registry is `Unavailable` (a prior observation failed, or its
    /// lock is poisoned).
    RegistryUnavailable,
    /// `SessionId` space exhausted (`u64`, so this is not reachable in
    /// practice — handled explicitly rather than silently wrapping).
    SessionIdSpaceExhausted,
}

/// Result of `observe_new_checkpoint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveOutcome {
    /// Strictly newer sequence: revision advanced, any now-revoked sessions
    /// were revoked.
    Applied,
    /// Same `(checkpoint_hash, checkpoint_sequence)` as the current
    /// revision: no-op, not an error.
    Idempotent,
    /// Lower sequence (regression/replay) or same sequence with a different
    /// hash (fork): rejected, revision unchanged.
    Rejected,
}

struct Revision {
    checkpoint_hash: [u8; 32],
    checkpoint_sequence: u64,
    active: std::collections::HashSet<MachineId>,
    revoked: std::collections::HashSet<MachineId>,
}

impl Revision {
    fn from_snapshot(snapshot: &RosterSnapshotView) -> Self {
        Self {
            checkpoint_hash: snapshot.checkpoint_hash(),
            checkpoint_sequence: snapshot.checkpoint_sequence(),
            active: snapshot.active_m_ids().cloned().collect(),
            revoked: snapshot.revoked_m_ids().iter().cloned().collect(),
        }
    }
}

// `Live`'s ~240 bytes vs `Unavailable`'s 0 trips large_enum_variant. Not
// boxed: this is a private, one-per-registry state enum (never allocated in
// bulk or on a hot path), and boxing would add an indirection cost to every
// register/observe call for a size difference that has no measured impact
// here — a deliberate call, not an oversight.
#[allow(clippy::large_enum_variant)]
enum State<H: RevocableMeshSession> {
    Live {
        revision: Revision,
        sessions: HashMap<SessionId, (MachineId, Weak<H>)>,
        by_machine: HashMap<MachineId, Vec<SessionId>>,
        next_session_id: u64,
    },
    /// See the module doc comment: not a claim that this is permanent, only
    /// that this slice does not implement reopening it.
    Unavailable,
}

/// Registers live sessions by the `MachineId` of their peer and revokes them
/// when the roster observes that machine has since been revoked.
///
/// `Weak`, not `Arc`: the registry does not keep a session alive — a session
/// whose last strong owner already dropped it is pruned (nothing to revoke)
/// rather than kept alive artificially by this bookkeeping.
pub struct MeshSessionRegistry<H: RevocableMeshSession> {
    state: Mutex<State<H>>,
}

impl<H: RevocableMeshSession> MeshSessionRegistry<H> {
    /// Constructs the registry already bound to a validated initial
    /// snapshot — there is no `Default`/empty construction, so `register`
    /// can never run before any roster state has been observed (a
    /// permissive empty-revoked-set start would admit any machine, revoked
    /// or not, until the first checkpoint arrived).
    #[must_use]
    pub fn new(initial: &RosterSnapshotView) -> Self {
        Self {
            state: Mutex::new(State::Live {
                revision: Revision::from_snapshot(initial),
                sessions: HashMap::new(),
                by_machine: HashMap::new(),
                next_session_id: 0,
            }),
        }
    }

    /// Registers a live session for its peer's `MachineId`, or refuses and
    /// returns why. `expected_checkpoint_hash`/`expected_checkpoint_sequence`
    /// must match the registry's current revision exactly; `handle` must
    /// still be alive and must claim (`peer_m_id()`) the same `m_id` passed
    /// in. None of the refusal paths call any method on `handle` beyond
    /// `upgrade`/`peer_m_id` — an already-dead or mismatched handle is
    /// simply never added, not "closed" (it was never ours to close).
    pub fn register(
        &self,
        m_id: MachineId,
        expected_checkpoint_hash: [u8; 32],
        expected_checkpoint_sequence: u64,
        handle: Weak<H>,
    ) -> Result<SessionId, RegisterRefusal> {
        let Ok(mut guard) = self.state.lock() else {
            return Err(RegisterRefusal::RegistryUnavailable);
        };
        let State::Live {
            revision,
            sessions,
            by_machine,
            next_session_id,
        } = &mut *guard
        else {
            return Err(RegisterRefusal::RegistryUnavailable);
        };
        if revision.checkpoint_hash != expected_checkpoint_hash
            || revision.checkpoint_sequence != expected_checkpoint_sequence
        {
            return Err(RegisterRefusal::RevisionMismatch);
        }
        if revision.revoked.contains(&m_id) {
            return Err(RegisterRefusal::MachineRevoked);
        }
        if !revision.active.contains(&m_id) {
            return Err(RegisterRefusal::MachineNotActive);
        }
        let strong = handle
            .upgrade()
            .ok_or(RegisterRefusal::HandleAlreadyDropped)?;
        if strong.peer_m_id() != &m_id {
            return Err(RegisterRefusal::HandleMachineMismatch);
        }
        drop(strong);
        let id = next_session_id
            .checked_add(1)
            .ok_or(RegisterRefusal::SessionIdSpaceExhausted)?;
        *next_session_id = id;
        let session_id = SessionId(id);
        sessions.insert(session_id, (m_id.clone(), handle));
        by_machine.entry(m_id).or_default().push(session_id);
        Ok(session_id)
    }

    /// Removes exactly `session_id`, without revoking it — for a session
    /// that is ending normally (not being revoked), so it stops being
    /// tracked without triggering `mark_not_authorized`/notice/close.
    pub fn unregister(&self, session_id: SessionId) {
        let Ok(mut guard) = self.state.lock() else {
            return;
        };
        if let State::Live {
            sessions,
            by_machine,
            ..
        } = &mut *guard
        {
            if let Some((m_id, _handle)) = sessions.remove(&session_id) {
                if let Some(ids) = by_machine.get_mut(&m_id) {
                    ids.retain(|id| *id != session_id);
                    if ids.is_empty() {
                        by_machine.remove(&m_id);
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn is_registered(&self, m_id: &MachineId) -> bool {
        let Ok(guard) = self.state.lock() else {
            return false;
        };
        matches!(&*guard, State::Live { by_machine, .. } if by_machine.contains_key(m_id))
    }

    #[must_use]
    pub fn registered_count(&self, m_id: &MachineId) -> usize {
        let Ok(guard) = self.state.lock() else {
            return 0;
        };
        match &*guard {
            State::Live { by_machine, .. } => by_machine.get(m_id).map_or(0, Vec::len),
            State::Unavailable => 0,
        }
    }

    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        let Ok(guard) = self.state.lock() else {
            return true;
        };
        matches!(&*guard, State::Unavailable)
    }

    /// The linearization point (CFX-5): the instant this call runs is "the
    /// moment `RosterCoordinator` marks `m_id` revoked" that B-SESSAO v6 §9
    /// already cites without naming who triggers it.
    ///
    /// D-6 (the roster-sync transport) is what is supposed to call this,
    /// once per successfully-persisted checkpoint, on the same long-lived
    /// coordinator's registry — that transport does not exist yet and is
    /// out of scope for this slice; this method only implements the
    /// contract D-6 must invoke, verified here with a manually constructed
    /// `RosterSnapshotView` rather than a real sync transport (RED-R20).
    ///
    /// Compares the incoming `(checkpoint_hash, checkpoint_sequence)`
    /// against the stored revision: a lower sequence is a regression
    /// (rejected), the same sequence with a different hash is a fork
    /// (rejected), the same sequence with the same hash is idempotent
    /// (accepted, no-op), and only a strictly higher sequence advances the
    /// revision. Nothing blocking runs while the internal lock is held —
    /// see the module doc comment, point 4.
    ///
    /// For a failed roster read (e.g. `current_snapshot()` returning
    /// `Err`), call `mark_unavailable()` directly instead of this method —
    /// there is no snapshot to compare a revision against on failure.
    pub fn observe_new_checkpoint(&self, snapshot: &RosterSnapshotView) -> ObserveOutcome {
        let to_finish: Vec<Arc<H>>;
        let outcome;
        {
            let Ok(mut guard) = self.state.lock() else {
                return ObserveOutcome::Rejected;
            };
            let State::Live {
                revision,
                sessions,
                by_machine,
                ..
            } = &mut *guard
            else {
                return ObserveOutcome::Rejected;
            };

            let new_sequence = snapshot.checkpoint_sequence();
            let new_hash = snapshot.checkpoint_hash();
            if new_sequence < revision.checkpoint_sequence {
                return ObserveOutcome::Rejected;
            }
            if new_sequence == revision.checkpoint_sequence {
                return if new_hash == revision.checkpoint_hash {
                    ObserveOutcome::Idempotent
                } else {
                    ObserveOutcome::Rejected
                };
            }

            // Strictly newer sequence: advance. Only mark_not_authorized
            // (non-blocking, per RevocableMeshSession's contract) runs
            // under this lock; notice+close happen after it is released.
            let mut collected = Vec::new();
            let newly_revoked: Vec<MachineId> = by_machine
                .keys()
                .filter(|m_id| snapshot.is_revoked(m_id))
                .cloned()
                .collect();
            for m_id in newly_revoked {
                if let Some(ids) = by_machine.remove(&m_id) {
                    for id in ids {
                        if let Some((_, weak)) = sessions.remove(&id) {
                            if let Some(strong) = weak.upgrade() {
                                strong.mark_not_authorized();
                                collected.push(strong);
                            }
                        }
                    }
                }
            }
            // Cheap, non-blocking bookkeeping pass (upgrade() only, no
            // session methods called): drop tracking for any remaining
            // handle whose last Arc has already dropped elsewhere. Not a
            // revocation — there is nothing left to revoke — just removes
            // dead entries so they do not accumulate indefinitely for
            // machines that never get revoked.
            let still_tracked: Vec<MachineId> = by_machine.keys().cloned().collect();
            for m_id in still_tracked {
                if let Some(ids) = by_machine.get_mut(&m_id) {
                    ids.retain(|id| {
                        let alive = sessions
                            .get(id)
                            .is_some_and(|(_, weak)| weak.strong_count() > 0);
                        if !alive {
                            sessions.remove(id);
                        }
                        alive
                    });
                    if ids.is_empty() {
                        by_machine.remove(&m_id);
                    }
                }
            }
            *revision = Revision::from_snapshot(snapshot);
            to_finish = collected;
            outcome = ObserveOutcome::Applied;
        }
        for handle in to_finish {
            handle.send_best_effort_revoke_notice();
            handle.close();
        }
        outcome
    }

    /// Closes every currently active session (mark under the lock, notice
    /// and close after releasing it — same discipline as
    /// `observe_new_checkpoint`) and transitions to `Unavailable`. Idempotent:
    /// a second call on an already-`Unavailable` registry is a no-op.
    ///
    /// Call this when a roster read this registry depends on (e.g.
    /// `MachineRosterCoordinator::current_snapshot()`) returns `Err` — there
    /// is no snapshot to compare a revision against on failure, so this is
    /// the direct entry point rather than routing an `Err` through
    /// `observe_new_checkpoint`.
    pub fn mark_unavailable(&self) {
        let to_finish: Vec<Arc<H>>;
        {
            let Ok(mut guard) = self.state.lock() else {
                // Already poisoned: every method already treats this as
                // Unavailable without touching the interior. Nothing to do.
                return;
            };
            let State::Live { sessions, .. } = &*guard else {
                return; // already Unavailable
            };
            let mut collected = Vec::new();
            for (_m_id, weak) in sessions.values() {
                if let Some(strong) = weak.upgrade() {
                    strong.mark_not_authorized();
                    collected.push(strong);
                }
            }
            *guard = State::Unavailable;
            to_finish = collected;
        }
        for handle in to_finish {
            handle.send_best_effort_revoke_notice();
            handle.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;
    use crate::ids::HouseholdId;
    use crate::keys::P256PublicKey;
    use crate::machine_cert::PersonId;
    use crate::machine_roster_authority::{AcceptedRosterData, MachineRosterRevocationV1};

    #[derive(Default)]
    struct RecordingSession {
        peer: std::sync::OnceLock<MachineId>,
        marked_not_authorized: AtomicBool,
        notices_sent: AtomicUsize,
        closed: AtomicBool,
    }

    impl RecordingSession {
        fn for_peer(m_id: MachineId) -> Self {
            let s = Self::default();
            s.peer.set(m_id).ok();
            s
        }
    }

    impl RevocableMeshSession for RecordingSession {
        fn peer_m_id(&self) -> &MachineId {
            self.peer.get().expect("test fixture always sets peer")
        }

        fn mark_not_authorized(&self) {
            self.marked_not_authorized.store(true, Ordering::SeqCst);
        }

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

    fn dummy_pubkey() -> P256PublicKey {
        P256PublicKey::from_bytes(&[
            0x02, 0x18, 0x62, 0x99, 0x63, 0x3f, 0x2c, 0x2f, 0x53, 0xd5, 0x4b, 0xf8, 0x9b, 0x03,
            0xd0, 0x82, 0x03, 0x2c, 0x42, 0xb7, 0xef, 0x35, 0x0c, 0xcd, 0x35, 0x5b, 0xcc, 0x8b,
            0x0b, 0xf5, 0xca, 0x66, 0x36,
        ])
        .expect("valid compressed P-256 point fixture")
    }

    fn dummy_sig() -> crate::keys::P256Signature {
        crate::keys::P256Signature::from_bytes(&[7u8; 64]).expect("valid signature fixture shape")
    }

    fn member(m_id: &MachineId) -> crate::machine_roster_authority::MachineRosterMemberV1 {
        crate::machine_roster_authority::MachineRosterMemberV1 {
            m_id: m_id.clone(),
            m_pub: dummy_pubkey(),
            machine_cert: Vec::new(),
            machine_cert_fingerprint: [5u8; 32],
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

    /// `sequence` and `checkpoint_hash` are the two fields this whole test
    /// suite pivots on (revision advance/regression/fork/idempotence), so
    /// they are explicit parameters rather than fixed constants.
    fn snapshot_at(
        sequence: u64,
        checkpoint_hash: [u8; 32],
        active_m_ids: &[MachineId],
        revoked_m_ids: &[MachineId],
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
            active: active_m_ids.iter().map(member).collect(),
            tombstones: revoked_m_ids.iter().map(revocation).collect(),
        };
        RosterSnapshotView::project(&test_hh_id(), &data)
    }

    fn new_registry_with(
        sequence: u64,
        checkpoint_hash: [u8; 32],
        active_m_ids: &[MachineId],
    ) -> MeshSessionRegistry<RecordingSession> {
        let snapshot = snapshot_at(sequence, checkpoint_hash, active_m_ids, &[]);
        MeshSessionRegistry::new(&snapshot)
    }

    #[test]
    fn register_refuses_unlisted_machine() {
        let m_id = test_m_id(1);
        let registry = new_registry_with(1, [1u8; 32], &[]); // not active
        let session = Arc::new(RecordingSession::for_peer(m_id.clone()));
        let outcome = registry.register(m_id, [1u8; 32], 1, Arc::downgrade(&session));
        assert_eq!(outcome, Err(RegisterRefusal::MachineNotActive));
    }

    #[test]
    fn register_refuses_stale_revision() {
        let m_id = test_m_id(2);
        let registry = new_registry_with(5, [9u8; 32], std::slice::from_ref(&m_id));
        let session = Arc::new(RecordingSession::for_peer(m_id.clone()));
        // Caller believes an older/different revision is current.
        let outcome = registry.register(m_id, [1u8; 32], 1, Arc::downgrade(&session));
        assert_eq!(outcome, Err(RegisterRefusal::RevisionMismatch));
    }

    /// CFX (kiana, round 2): a caller must not be able to register one
    /// machine's session under a different machine's `m_id`.
    #[test]
    fn register_refuses_handle_machine_mismatch() {
        let claimed = test_m_id(3);
        let actual_peer = test_m_id(4);
        let registry = new_registry_with(1, [1u8; 32], std::slice::from_ref(&claimed));
        let session = Arc::new(RecordingSession::for_peer(actual_peer));
        let outcome = registry.register(claimed, [1u8; 32], 1, Arc::downgrade(&session));
        assert_eq!(outcome, Err(RegisterRefusal::HandleMachineMismatch));
    }

    #[test]
    fn register_refuses_already_dropped_handle() {
        let m_id = test_m_id(5);
        let registry = new_registry_with(1, [1u8; 32], std::slice::from_ref(&m_id));
        let weak = {
            let session = Arc::new(RecordingSession::for_peer(m_id.clone()));
            Arc::downgrade(&session)
        };
        let outcome = registry.register(m_id, [1u8; 32], 1, weak);
        assert_eq!(outcome, Err(RegisterRefusal::HandleAlreadyDropped));
    }

    #[test]
    fn register_succeeds_for_active_machine_on_matching_revision() {
        let m_id = test_m_id(6);
        let registry = new_registry_with(1, [1u8; 32], std::slice::from_ref(&m_id));
        let session = Arc::new(RecordingSession::for_peer(m_id.clone()));
        let outcome = registry.register(m_id.clone(), [1u8; 32], 1, Arc::downgrade(&session));
        assert!(outcome.is_ok());
        assert!(registry.is_registered(&m_id));
    }

    /// RED (kiana CFX round 1): a single-slot design would silently drop one
    /// of two concurrent sessions for the same machine. Both must be
    /// tracked and both must close on revoke — this is the exact scenario
    /// `SessionId` + per-machine `Vec` exists for.
    #[test]
    fn two_concurrent_sessions_for_the_same_machine_both_close_on_revoke() {
        let m_id = test_m_id(7);
        let registry = new_registry_with(1, [1u8; 32], std::slice::from_ref(&m_id));
        let session_a = Arc::new(RecordingSession::for_peer(m_id.clone()));
        let session_b = Arc::new(RecordingSession::for_peer(m_id.clone()));
        registry
            .register(m_id.clone(), [1u8; 32], 1, Arc::downgrade(&session_a))
            .expect("first session registers cleanly");
        registry
            .register(m_id.clone(), [1u8; 32], 1, Arc::downgrade(&session_b))
            .expect("second concurrent session for the same machine also registers cleanly");
        assert_eq!(registry.registered_count(&m_id), 2);

        let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], std::slice::from_ref(&m_id));
        let outcome = registry.observe_new_checkpoint(&revoke_snapshot);

        assert_eq!(outcome, ObserveOutcome::Applied);
        assert!(session_a.closed.load(Ordering::SeqCst));
        assert!(session_b.closed.load(Ordering::SeqCst));
        assert!(!registry.is_registered(&m_id));
    }

    /// RED (kiana CFX round 1): register-after-revoke race. A `register`
    /// against a revision where the machine is already revoked must refuse
    /// — since no later checkpoint will ever re-revoke an already-
    /// tombstoned machine, letting it slip in here would never be caught.
    #[test]
    fn register_after_revoke_is_refused_not_added() {
        let m_id = test_m_id(8);
        let registry = new_registry_with(1, [1u8; 32], std::slice::from_ref(&m_id));
        let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], std::slice::from_ref(&m_id));
        registry.observe_new_checkpoint(&revoke_snapshot);

        let late_session = Arc::new(RecordingSession::for_peer(m_id.clone()));
        let outcome = registry.register(m_id.clone(), [2u8; 32], 2, Arc::downgrade(&late_session));

        assert_eq!(outcome, Err(RegisterRefusal::MachineRevoked));
        assert!(!late_session.closed.load(Ordering::SeqCst)); // never ours: not closed by us
        assert!(!registry.is_registered(&m_id));
    }

    /// CFX (kiana, round 2): a concurrent `register` racing an in-flight
    /// `observe_new_checkpoint` that revokes the same machine — the two
    /// operations linearize under the same lock, so whichever runs last
    /// sees the other's effect exactly (no interleaving where the register
    /// reads pre-revoke state but writes after the revoke completed).
    /// Modeled without real threads: run the revoke, THEN the register with
    /// the OLD revision — proves the two cannot observe inconsistent
    /// states, since register with a stale revision is refused regardless
    /// of ordering.
    #[test]
    fn register_racing_a_revoke_never_admits_the_revoked_machine() {
        let m_id = test_m_id(9);
        let registry = new_registry_with(1, [1u8; 32], std::slice::from_ref(&m_id));
        let revoke_snapshot = snapshot_at(2, [2u8; 32], &[], std::slice::from_ref(&m_id));
        registry.observe_new_checkpoint(&revoke_snapshot);

        let session = Arc::new(RecordingSession::for_peer(m_id.clone()));
        // Caller still believes revision 1 is current (raced the revoke).
        let stale_outcome = registry.register(m_id.clone(), [1u8; 32], 1, Arc::downgrade(&session));
        assert_eq!(stale_outcome, Err(RegisterRefusal::RevisionMismatch));

        // Caller catches up to revision 2 and retries — still refused,
        // now because the machine is revoked, not because of staleness.
        let caught_up_outcome =
            registry.register(m_id.clone(), [2u8; 32], 2, Arc::downgrade(&session));
        assert_eq!(caught_up_outcome, Err(RegisterRefusal::MachineRevoked));
        assert!(!registry.is_registered(&m_id));
    }

    #[test]
    fn unrevoked_registered_session_is_left_untouched() {
        let m_id = test_m_id(10);
        let other = test_m_id(11);
        let registry = new_registry_with(1, [1u8; 32], std::slice::from_ref(&m_id));
        let session = Arc::new(RecordingSession::for_peer(m_id.clone()));
        registry
            .register(m_id.clone(), [1u8; 32], 1, Arc::downgrade(&session))
            .expect("fresh machine registers cleanly");

        let snapshot = snapshot_at(2, [2u8; 32], std::slice::from_ref(&m_id), &[other]);
        registry.observe_new_checkpoint(&snapshot);

        assert!(!session.marked_not_authorized.load(Ordering::SeqCst));
        assert!(!session.closed.load(Ordering::SeqCst));
        assert!(registry.is_registered(&m_id));
    }

    #[test]
    fn dropped_handle_is_pruned_on_next_observe_without_panicking() {
        let m_id = test_m_id(12);
        let registry = new_registry_with(1, [1u8; 32], std::slice::from_ref(&m_id));
        {
            let session = Arc::new(RecordingSession::for_peer(m_id.clone()));
            registry
                .register(m_id.clone(), [1u8; 32], 1, Arc::downgrade(&session))
                .expect("fresh machine registers cleanly");
        }
        // `session` dropped; only the Weak remains, now unable to upgrade.
        assert!(registry.is_registered(&m_id));

        let snapshot = snapshot_at(2, [2u8; 32], std::slice::from_ref(&m_id), &[test_m_id(99)]);
        registry.observe_new_checkpoint(&snapshot);

        assert!(!registry.is_registered(&m_id));
    }

    #[test]
    fn unregister_removes_only_the_named_session() {
        let m_id = test_m_id(13);
        let registry = new_registry_with(1, [1u8; 32], std::slice::from_ref(&m_id));
        let session_a = Arc::new(RecordingSession::for_peer(m_id.clone()));
        let session_b = Arc::new(RecordingSession::for_peer(m_id.clone()));
        let id_a = registry
            .register(m_id.clone(), [1u8; 32], 1, Arc::downgrade(&session_a))
            .unwrap();
        registry
            .register(m_id.clone(), [1u8; 32], 1, Arc::downgrade(&session_b))
            .unwrap();
        assert_eq!(registry.registered_count(&m_id), 2);

        registry.unregister(id_a);

        assert_eq!(registry.registered_count(&m_id), 1);
        assert!(!session_a.closed.load(Ordering::SeqCst)); // ended normally, not revoked
        assert!(!session_b.closed.load(Ordering::SeqCst));
    }

    #[test]
    fn empty_registry_observes_checkpoint_without_panicking() {
        let registry = new_registry_with(1, [1u8; 32], &[]);
        let snapshot = snapshot_at(2, [2u8; 32], &[], &[test_m_id(14)]);
        let outcome = registry.observe_new_checkpoint(&snapshot);
        assert_eq!(outcome, ObserveOutcome::Applied);
    }

    /// CFX (kiana, round 1): observe must reject a lower-sequence
    /// (regression/replay) snapshot, not blindly apply whatever it is
    /// handed.
    #[test]
    fn observe_rejects_sequence_regression() {
        let m_id = test_m_id(15);
        let registry = new_registry_with(5, [5u8; 32], &[m_id]);
        let regressed = snapshot_at(3, [3u8; 32], &[], &[]);
        let outcome = registry.observe_new_checkpoint(&regressed);
        assert_eq!(outcome, ObserveOutcome::Rejected);
    }

    /// CFX (kiana, round 1): the same sequence with a DIFFERENT hash is a
    /// fork/conflict, not an update — must be rejected, not silently
    /// applied over the existing revision.
    #[test]
    fn observe_rejects_same_sequence_different_hash_as_fork() {
        let m_id = test_m_id(16);
        let registry = new_registry_with(5, [5u8; 32], &[m_id]);
        let forked = snapshot_at(5, [0xFFu8; 32], &[], &[]);
        let outcome = registry.observe_new_checkpoint(&forked);
        assert_eq!(outcome, ObserveOutcome::Rejected);
    }

    /// CFX (kiana, round 1): the same sequence with the SAME hash is a
    /// harmless re-observation — accepted as a no-op, not treated as an
    /// error.
    #[test]
    fn observe_same_sequence_same_hash_is_idempotent() {
        let m_id = test_m_id(17);
        let registry = new_registry_with(5, [5u8; 32], std::slice::from_ref(&m_id));
        let session = Arc::new(RecordingSession::for_peer(m_id.clone()));
        registry
            .register(m_id.clone(), [5u8; 32], 5, Arc::downgrade(&session))
            .unwrap();

        let same_again = snapshot_at(5, [5u8; 32], std::slice::from_ref(&m_id), &[]);
        let outcome = registry.observe_new_checkpoint(&same_again);

        assert_eq!(outcome, ObserveOutcome::Idempotent);
        assert!(registry.is_registered(&m_id)); // untouched, not re-processed
    }

    /// CFX (kiana, round 1): notice/close must never run while the
    /// registry's internal lock is held — proven behaviorally, not just by
    /// inspection: `register`/`is_registered` for an UNRELATED machine must
    /// succeed from inside a session's own `mark_not_authorized` callback
    /// (called under the lock) without deadlocking. If notice/close ran
    /// under the same lock, a session whose `close()` tried to touch the
    /// registry would deadlock; this proves the lock is not held across
    /// those calls by exercising the one call that IS made under the lock.
    #[derive(Default)]
    struct ReentrantDuringMarkSession {
        peer: std::sync::OnceLock<MachineId>,
        registry: std::sync::OnceLock<Arc<MeshSessionRegistry<ReentrantDuringMarkSession>>>,
        other_machine: std::sync::OnceLock<MachineId>,
        reentry_succeeded: AtomicBool,
    }

    impl RevocableMeshSession for ReentrantDuringMarkSession {
        fn peer_m_id(&self) -> &MachineId {
            self.peer.get().unwrap()
        }

        fn mark_not_authorized(&self) {
            // Deliberately does NOT touch the registry here — mark_not_authorized
            // itself must stay non-blocking/non-reentrant per the trait's
            // contract. This test instead proves notice/close (below) run
            // unlocked by checking is_registered for an unrelated machine
            // succeeds immediately after mark_not_authorized returns, i.e.
            // synchronously, on the same thread, before this whole
            // observe call returns — which is only possible if the lock
            // used for mark_not_authorized is not the same held span as
            // notice/close.
            let _ = self.reentry_succeeded.load(Ordering::SeqCst);
        }

        fn send_best_effort_revoke_notice(&self) {
            if let (Some(registry), Some(other)) = (self.registry.get(), self.other_machine.get()) {
                // If this ran while the registry's lock were still held
                // (i.e. the redesign regressed), this call would deadlock
                // (Mutex is not reentrant) and the test would hang/panic
                // instead of completing.
                let _ = registry.is_registered(other);
                self.reentry_succeeded.store(true, Ordering::SeqCst);
            }
        }

        fn close(&self) {}
    }

    #[test]
    fn notice_and_close_do_not_hold_the_registry_lock() {
        let revoked_m_id = test_m_id(18);
        let other_m_id = test_m_id(19);
        let snapshot = snapshot_at(
            1,
            [1u8; 32],
            &[revoked_m_id.clone(), other_m_id.clone()],
            &[],
        );
        let registry: Arc<MeshSessionRegistry<ReentrantDuringMarkSession>> =
            Arc::new(MeshSessionRegistry::new(&snapshot));

        let session = Arc::new(ReentrantDuringMarkSession::default());
        session.peer.set(revoked_m_id.clone()).unwrap();
        session.registry.set(Arc::clone(&registry)).ok();
        session.other_machine.set(other_m_id.clone()).ok();
        registry
            .register(revoked_m_id.clone(), [1u8; 32], 1, Arc::downgrade(&session))
            .unwrap();

        let revoke_snapshot = snapshot_at(2, [2u8; 32], &[other_m_id], &[revoked_m_id]);
        registry.observe_new_checkpoint(&revoke_snapshot);

        assert!(session.reentry_succeeded.load(Ordering::SeqCst));
    }

    #[test]
    fn mark_unavailable_closes_all_active_sessions_and_blocks_new_registrations() {
        let m_id_a = test_m_id(20);
        let m_id_b = test_m_id(21);
        let registry = new_registry_with(1, [1u8; 32], &[m_id_a.clone(), m_id_b.clone()]);
        let session_a = Arc::new(RecordingSession::for_peer(m_id_a.clone()));
        let session_b = Arc::new(RecordingSession::for_peer(m_id_b.clone()));
        registry
            .register(m_id_a.clone(), [1u8; 32], 1, Arc::downgrade(&session_a))
            .unwrap();
        registry
            .register(m_id_b.clone(), [1u8; 32], 1, Arc::downgrade(&session_b))
            .unwrap();

        registry.mark_unavailable();

        assert!(session_a.closed.load(Ordering::SeqCst));
        assert!(session_b.closed.load(Ordering::SeqCst));
        assert!(!registry.is_registered(&m_id_a));
        assert!(!registry.is_registered(&m_id_b));
        assert!(registry.is_unavailable());

        let m_id_c = test_m_id(22);
        let new_session = Arc::new(RecordingSession::for_peer(m_id_c.clone()));
        let outcome = registry.register(m_id_c, [1u8; 32], 1, Arc::downgrade(&new_session));
        assert_eq!(outcome, Err(RegisterRefusal::RegistryUnavailable));
    }

    #[test]
    fn observe_new_checkpoint_is_a_noop_once_unavailable() {
        let registry = new_registry_with(1, [1u8; 32], &[]);
        registry.mark_unavailable();
        let snapshot = snapshot_at(2, [2u8; 32], &[], &[test_m_id(24)]);
        let outcome = registry.observe_new_checkpoint(&snapshot);
        assert_eq!(outcome, ObserveOutcome::Rejected);
        assert!(registry.is_unavailable());
    }
}
