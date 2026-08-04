//! D-1 (B-ROSTER-ADAPTER v2 CFX-5): the linearization point for live
//! session revocation. `RosterSnapshotView` (`machine_roster_authority.rs`)
//! is immutable by design — a clone held inside an active session never
//! sees a revocation that happens after it was taken. `MeshSessionRegistry`
//! is *who observes and when calls the revoke*: it is handed each new
//! snapshot as the roster advances and revokes any registered session whose
//! machine just became revoked, dropped from the active set, or whose
//! certificate fingerprint changed (cert reissue).
//!
//! **Generic over the session handle, not `VerifiedMeshSessionHandle`** —
//! that type does not exist anywhere in this repository yet; it belongs to
//! the not-yet-built B-SESSAO CORE wire/session track. `MeshSessionRegistry<H>`
//! is generic over any `H: RevocableMeshSession`.
//!
//! ## Three rounds of independent audit (@kiana), folded in before this
//! shipped
//!
//! Round 1 (session identity, linearization, non-blocking-under-lock,
//! regression/fork rejection, poison discipline) and round 2 (per-session
//! identity binding, real deadlock-freedom proof) are summarized in the
//! git history of this file. Round 3, reflected in the design below:
//!
//! 1. **No self-declared identity, not even via a trait method.** Round 2
//!    added `RevocableMeshSession::peer_m_id()` so `register` could check
//!    the handle's claimed identity — but that is still just the handle's
//!    own claim; nothing stops a buggy or malicious `H` from lying in its
//!    own trait impl. Fixed: `register` now takes a [`SealedBinding`]
//!    (`machine_roster_authority.rs`), which only exists by projecting an
//!    `ExpectedResponder` that itself only exists by passing
//!    `from_peer_expectation`'s revoked/active/hash-pairing checks against
//!    a real `RosterSnapshotView`. The `RevocableMeshSession` trait no
//!    longer has any identity method at all.
//! 2. **The revocation signal is a primitive, not a virtual call.** Round 2
//!    called `H::mark_not_authorized()` under the lock, trusting the trait
//!    impl to be fast/non-blocking/non-reentrant. Fixed: `register` returns
//!    an `Arc<AtomicBool>` "gate" that the caller's forwarding hot path
//!    reads directly; the registry's own clone is the only thing flipped
//!    under the lock, via `AtomicBool::store` — a wait-free primitive, not
//!    a call into `H` — so there is no longer a trait method whose
//!    blocking/reentrancy behavior the lock's safety depends on.
//!    `RevocableMeshSession` shrinks to `send_best_effort_revoke_notice`
//!    and `close`, both always called after the lock is released (proven
//!    behaviorally, not just documented — see
//!    `notice_and_close_do_not_hold_the_registry_lock`).
//! 3. **Fingerprint change revokes too.** A snapshot advance now revokes a
//!    tracked session if its machine is tombstoned, no longer in the active
//!    set, OR the active member's `machine_cert_fingerprint` no longer
//!    matches what the session was registered with (cert reissue — the
//!    same "same `m_id`, different fingerprint across snapshots" case
//!    `machine_roster_authority.rs`'s design notes on `ExpectedResponder`
//!    already flag as not provably safe to treat as the same identity).
//! 4. **Fork/regression fail closed, not just reject-in-place.** Previously
//!    a fork or regression only rejected that one observation and left
//!    whatever was Live untouched. Fixed: `observe_new_checkpoint` treats a
//!    fork or regression as an integrity violation — the same as an `Err`
//!    from the roster read — closing every active session and entering
//!    `Unavailable`, not silently continuing to trust sessions admitted
//!    under a revision that just proved inconsistent.
//! 5. **`Unavailable` now explicitly recovers**, closing the design
//!    question round 2 left open. `last_known_revision` is preserved across
//!    the transition (not discarded). A fresh observation recovers to
//!    `Live` exactly when it is *consistent* with `last_known_revision` by
//!    the same rule used for a normal Live-state advance: a strictly newer
//!    sequence, or the identical `(hash, sequence)` re-observed — either
//!    counts as `Recovered`, not just `Applied`, so a caller/test can tell
//!    "we just came back" from "routine advance while already live". A
//!    lower sequence or a same-sequence-different-hash while `Unavailable`
//!    is still rejected — recovering into overtly conflicting state is not
//!    "coming back online". Poison is still permanent — see round 1.
//!
//! ## Round 4 (@kiana, five passes): `is_authorized()` was
//! check-then-forward, not a linearization
//!
//! **Pass 1.** A bare `Arc<AtomicBool>` read by a caller, followed *later*
//! by the caller actually forwarding bytes, has a real race window: revoke
//! can run and flip the flag to `false` strictly between the caller's read
//! and the caller's write, so a forward can still land after its session
//! was revoked even though the caller "checked first". Fixed:
//! [`SessionGate::try_authorize_forwarding`] hands back a
//! [`ForwardingGuard`] on `Some` that must be held for the *entire*
//! forward, not just the check — revoke cannot finish closing a session
//! while any `ForwardingGuard` for it is still alive. `is_authorized()`
//! remains, but only as a `#[cfg(test)]` diagnostic snapshot — not
//! reachable from a non-test build, so "production forwarding must use the
//! guard" is a compiler fact, not a comment.
//!
//! **Pass 2.** The first cut used a `Mutex`-as-"turnstile" plus a separate
//! `RwLock` for the authorization bit, with the turnstile released *before*
//! the `RwLock` read was acquired — reopening a window between "no writer
//! active" and "I now hold the room" for a writer to interleave into.
//!
//! **Pass 3.** Fixed by *not* layering two separate locks at all: ONE
//! `Mutex`-protected explicit state machine (`authorized`, a
//! writer-announcement signal, `writer_active`, `active_readers`) —
//! admitting a reader and reading `authorized` happen in the same critical
//! section, so there is no window between them. But the writer-announcement
//! signal (`waiting_writers`) still lived *inside* that same `Mutex`, which
//! pass 4 found was not enough on its own.
//!
//! **Pass 4.** Four more @kiana catches on the same recheck:
//!
//! 1. Parking the writer-announcement counter inside `state`'s `Mutex`
//!    meant a writer had to *win that Mutex* just to announce — and
//!    `std::sync::Mutex` makes no fairness guarantee (the stdlib docs say
//!    so explicitly), so a continuous stream of readers could in principle
//!    keep winning the race to lock `state` before the writer ever got a
//!    turn to announce at all. A 5-second bounded test measures one
//!    execution; it does not close this structurally. Fixed: `writer_intent`
//!    is now an `AtomicUsize`, OUTSIDE `state`'s `Mutex` entirely —
//!    incrementing it is a lock-free CPU operation with no OS-scheduler
//!    involvement, so a reader checks it *before* even attempting
//!    `state.lock()` (closing the race to the mutex itself) and *again*
//!    after acquiring the lock (for the gap between the two checks).
//! 2. [`SessionSync::try_enter`] recovered a poisoned `state` via
//!    `into_inner` and could then trust a torn `authorized == true` —
//!    fail-*open*, exactly the hazard this type exists to close, despite a
//!    comment claiming otherwise. Fixed: the reader side now uses
//!    `.lock().ok()?` — ANY poison fails closed immediately, no recovery,
//!    no trust.
//! 3. `unregister` removed a session from tracking but left its gate
//!    `true` — "for a session ending normally". But losing tracking also
//!    means no FUTURE checkpoint observation can ever reach this session
//!    again (it is not in `sessions`/`by_machine` anymore) — so if a
//!    caller unregisters a session that is actually still alive/forwarding
//!    (a caller bug, or a race with the peer), that was a permanent,
//!    silent authority leak. Fixed: `unregister` now revokes the session's
//!    `SessionSync` (unlocked, same as every other revoke path) before it
//!    ever loses tracking of it — see
//!    `unregister_waits_for_an_in_flight_forward_before_returning`.
//! 4. The `Unavailable -> Live` recovery path bumped `generation` with a
//!    plain `fetch_add`, unchecked. At `u64::MAX` that wraps to `0` —
//!    exactly the registry's very first, pre-recovery generation — which
//!    would make a gate issued back then read authorized again. Fixed:
//!    `checked_add`, with an exhaustion path that refuses to recover
//!    (stays `Unavailable`) rather than wrap — see
//!    `generation_exhaustion_refuses_to_recover_rather_than_wrap`.
//!
//! **Pass 5 (final).** A REAL executable RED from @kiana's own audit
//! worktree, not a reading pass: admit a `ForwardingGuard`, poison
//! `SessionSync.state` from an unrelated thread WHILE that guard is still
//! held, then call `revoke` from a third thread — `revoke` returned
//! immediately, before the guard was ever dropped, violating the
//! documented contract that it does not return until every in-flight
//! forward has finished. Root cause: pass 4's `revoke` treated ANY poison
//! as license to stop trusting `active_readers` and abandon the wait —
//! but poisoning a `Mutex` only records that SOME panic happened while it
//! was held, not that the guarded data is torn, and a plain `usize` field
//! recovered via `into_inner` is not torn in any sense Rust's memory model
//! can produce for it. [`ForwardingGuard`]'s `Drop` already recovers
//! poison the same way and still correctly decrements `active_readers`
//! and notifies — so the counter stays meaningful, and `revoke` had no
//! real reason to stop trusting it. Fixed: `revoke` now recovers a
//! poisoned `state` (on the initial lock, or on any `Condvar::wait`) via
//! `into_inner` and KEEPS WAITING on `active_readers` regardless, exactly
//! as it would unpoisoned — only `authorized` is forced unconditionally.
//! See [`SessionSync`]'s own doc comment for the sharper distinction this
//! pass drew out: `try_enter`'s poison handling is a security decision
//! (refuse under any doubt — correct to fail closed), `revoke`'s is a
//! completion guarantee (has everyone actually drained — giving up under
//! doubt does not achieve that, it only pretends to by returning early).
//! See `revoke_waits_for_an_admitted_reader_even_if_the_state_lock_is_poisoned_meanwhile`.
//!
//! Revoking a per-session `SessionSync` never happens while `self.inner`'s
//! registry-wide lock is held (it can block waiting for readers to drain)
//! — every revoke path (including `unregister`) collects the sessions to
//! close under one short lock, releases it, calls `SessionSync::revoke()`
//! on each unlocked, then briefly re-locks only to remove the now-closed
//! entries from the bookkeeping maps. See [`SessionSync`]'s own doc comment
//! for the full construction, and
//! `forwarding_guard_blocks_revoke_until_released_and_reader1_precedes_revoke_returned`,
//! `reader_that_attempts_after_writer_announces_intent_never_authorizes`,
//! `revoke_is_not_starved_by_a_continuous_stream_of_short_lived_forwarding_guards`,
//! `poisoned_session_state_never_admits_a_reader`,
//! `revoke_waits_for_an_admitted_reader_even_if_the_state_lock_is_poisoned_meanwhile`,
//! `unregister_waits_for_an_in_flight_forward_before_returning`, and
//! `generation_exhaustion_refuses_to_recover_rather_than_wrap`.
//!
//! D-6 (the roster-sync transport that decides *when* a new checkpoint is
//! durably observed) is out of scope here too — see
//! [`observe_new_checkpoint`]'s doc comment.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};

use crate::ids::{HouseholdId, MachineId};
use crate::machine_roster_authority::{RosterSnapshotError, RosterSnapshotView, SealedBinding};

/// What `MeshSessionRegistry` needs from a live session once it has
/// decided to revoke it. No identity method — see the module doc comment,
/// point 1. No "mark not authorized" method either — see point 2; that
/// signal is the `SessionGate` `register` returns, not a trait call.
pub trait RevocableMeshSession {
    /// May block (e.g. network I/O for a notice). The registry never calls
    /// this while its internal lock is held.
    fn send_best_effort_revoke_notice(&self);

    /// May block. The registry never calls this while its internal lock is
    /// held.
    fn close(&self);
}

/// Opaque handle to one registered session. Returned by `register`, needed
/// by `unregister`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

/// Per-session forwarding-authorization synchronization (round 4, revised
/// three more times @kiana). NOT built on a `Mutex`-as-turnstile plus a
/// separate `RwLock` — `std::sync::Mutex`/`RwLock` make no fairness or
/// writer-priority guarantee at all (the stdlib docs explicitly do not
/// specify a policy for unblocking). And NOT built by parking
/// "`waiting_writers`" inside the SAME `Mutex` a reader must lock either —
/// that still let a continuous stream of readers starve a writer, not by
/// racing *past* an announced writer, but by racing to win `state.lock()`
/// *before* the writer could ever call it to announce in the first place.
/// A 5-second bounded test measures one execution; it proves nothing
/// structural either way. Instead:
///
/// - `writer_intent`: an `AtomicUsize`, OUTSIDE `state`'s `Mutex`.
///   Incrementing it is a lock-free CPU operation with no OS-scheduler
///   involvement, so it cannot itself be delayed by readers winning a
///   mutex race — this is what makes writer preference structural rather
///   than empirical. [`try_enter`](SessionSync::try_enter) checks it
///   *before* even attempting `state.lock()` (so a continuous stream of
///   readers never gets to compete for the mutex at all once a writer has
///   announced) AND rechecks it *after* acquiring the lock (the outer
///   check and the lock acquisition are not atomic with each other, so a
///   writer's `fetch_add` could land in the gap between them). A counter,
///   not a bool: two different threads can call
///   [`revoke`](SessionSync::revoke) on the same `SessionSync`
///   concurrently (two different `observe_new_checkpoint`/
///   `mark_unavailable` calls can both decide to revoke the same session
///   before either has removed it from the registry's bookkeeping maps),
///   and the signal must stay "a writer is active" until ALL of them
///   finish, not drop to zero the moment the first one does;
/// - `authorized`: the actual bit, folded into the SAME lock as the
///   admission bookkeeping below — reading it and admitting a reader
///   happen in the one critical section, so there is no window between the
///   two for a writer to interleave into;
/// - `writer_active`: set once a writer has drained `active_readers` to
///   zero and is doing its (here, trivial) exclusive work;
/// - `active_readers`: readers currently holding a [`ForwardingGuard`].
///   `revoke` waits on `drained` (a `Condvar`) until this reaches zero —
///   woken by a `ForwardingGuard`'s `Drop`, which decrements it under the
///   same lock and only then notifies — so revoke does not return until
///   every in-flight forward for this session has actually finished, not
///   merely until it flipped a flag. No new reader can join while any
///   writer is announced (`writer_intent`), so this wait is bounded by the
///   FIXED set of readers already admitted at the instant the writer
///   announced intent, regardless of how many more readers arrive
///   afterward.
///
/// Poison is handled differently on each side, deliberately — and for a
/// more precise reason than "the data might be torn" (round 4, pass 5,
/// @kiana catch: an earlier revision of `revoke` treated ANY poison as
/// license to abandon its wait on `active_readers`, which broke the
/// documented contract that `revoke` does not return until every in-flight
/// forward has actually finished — a panic marks the `Mutex` poisoned
/// whenever ANY panic happens while it is held, regardless of whether that
/// panic had anything to do with mutating `active_readers`; a `usize`
/// field recovered via `into_inner` is not "torn" in any sense Rust's
/// memory model can produce for a plain field store, so there was never a
/// real reason to stop trusting it). [`revoke`](SessionSync::revoke)
/// recovers a poisoned `state` via `into_inner` on both the initial lock
/// and every `Condvar::wait`, but KEEPS WAITING on `active_readers`
/// regardless — [`ForwardingGuard`]'s `Drop` recovers poison the same way
/// and still correctly decrements it and notifies, so the counter remains
/// meaningful and will still reach zero. `authorized` is still forced to
/// `false` unconditionally, since that is the one outcome that must hold
/// regardless of what the recovered state says. [`try_enter`](SessionSync::try_enter)
/// is different again — it does NOT recover a poisoned `state` at all,
/// `.lock().ok()?` fails closed immediately on ANY poison. That asymmetry
/// is deliberate: `try_enter`'s job is a security decision (admit or not),
/// where refusing under any doubt is the correct fail-closed posture;
/// `revoke`'s job is a completion guarantee (has everyone actually
/// drained), where giving up under doubt does not achieve the guarantee —
/// it only pretends to by returning early.
struct GateState {
    authorized: bool,
    writer_active: bool,
    active_readers: usize,
}

struct SessionSync {
    /// See the struct doc comment above — deliberately outside `state`'s
    /// `Mutex`.
    writer_intent: AtomicUsize,
    state: Mutex<GateState>,
    /// Signaled by a `ForwardingGuard`'s `Drop` when `active_readers`
    /// reaches zero, so a writer waiting in `revoke` wakes promptly rather
    /// than polling.
    drained: Condvar,
}

impl SessionSync {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            writer_intent: AtomicUsize::new(0),
            state: Mutex::new(GateState {
                authorized: true,
                writer_active: false,
                active_readers: 0,
            }),
            drained: Condvar::new(),
        })
    }

    /// Writer side: announce intent on the lock-free counter (blocks every
    /// NEW reader from this instant, structurally — see the struct doc
    /// comment), wait out any readers already admitted, then commit the
    /// fail-closed bit. A poisoned `state` (initial lock, or observed
    /// during the `Condvar` wait) is recovered via `into_inner` but does
    /// NOT short-circuit the wait — see the struct doc comment for why
    /// `active_readers` remains trustworthy across poison and abandoning
    /// the wait would violate the documented contract that `revoke` does
    /// not return until every in-flight forward has actually finished.
    fn revoke(&self) {
        self.writer_intent.fetch_add(1, Ordering::SeqCst);
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        while state.active_readers > 0 {
            state = match self.drained.wait(state) {
                Ok(next) => next,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        state.writer_active = true;
        state.authorized = false;
        state.writer_active = false;
        drop(state);
        self.writer_intent.fetch_sub(1, Ordering::SeqCst);
    }

    /// Reader side: admitted only if no writer has announced intent or is
    /// active, AND the session currently reads authorized — all three
    /// checked in the SAME locked critical section as the admission
    /// itself (after an outer, lock-free fast-reject on `writer_intent`).
    /// Never blocks: a reader that arrives while a writer is
    /// announced/active is refused immediately (`None`), it does not wait
    /// to be admitted later. A poisoned `state` is fail-closed via
    /// `.ok()?` — no `into_inner`, no trusting a torn `authorized` value —
    /// see the struct doc comment.
    fn try_enter(&self) -> Option<ForwardingGuard<'_>> {
        if self.writer_intent.load(Ordering::SeqCst) > 0 {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        if self.writer_intent.load(Ordering::SeqCst) > 0 || state.writer_active || !state.authorized
        {
            return None;
        }
        state.active_readers += 1;
        Some(ForwardingGuard { sync: self })
    }
}

/// Proof that a session's forwarding authorization is held for as long as
/// this guard is alive (round 4). Hold it for exactly the duration of the
/// forward it authorizes: dropping it early re-opens the check-then-forward
/// gap [`SessionGate::try_authorize_forwarding`] exists to close; holding
/// it longer than necessary needlessly delays a legitimate revoke, which
/// cannot finish closing this session while any `ForwardingGuard` for it is
/// still alive. `Drop` decrements `active_readers` and, if that reaches
/// zero, wakes any writer waiting in [`SessionSync::revoke`].
pub struct ForwardingGuard<'a> {
    sync: &'a SessionSync,
}

impl Drop for ForwardingGuard<'_> {
    fn drop(&mut self) {
        let mut state = self
            .sync
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_readers -= 1;
        if state.active_readers == 0 {
            self.sync.drained.notify_all();
        }
    }
}

/// What `register`'s caller uses to decide whether — and, via
/// [`try_authorize_forwarding`](SessionGate::try_authorize_forwarding),
/// for how long — this session is still authorized. `sync` alone
/// (round 4) cannot detect a *registry-wide* transition (a poisoned lock,
/// or a clean `mark_unavailable`/fork/regression closing every session at
/// once): those flip `registry_live`/`generation` without necessarily
/// having reached this specific session's `SessionSync` yet, or at all (a
/// poisoned lock can never be reached to iterate sessions individually —
/// see [`MeshSessionRegistry::registry_live`]'s doc comment). So
/// authorization ANDs three independent signals:
///
/// - `sync`'s `room` (flipped by an ordinary per-machine/per-session
///   revocation, or by any registry-wide close);
/// - `registry_live`, a registry-wide flag set `false` the instant ANY
///   method observes a poisoned lock — set without ever touching the
///   poisoned interior, so it is reachable even when nothing else is;
/// - a generation check: `register`'s own generation must still equal the
///   registry's current one, so a gate issued in an earlier generation
///   never reauthorizes after an `Unavailable -> Live` recovery even if
///   `registry_live` reads `true` again.
#[derive(Clone)]
pub struct SessionGate {
    sync: Arc<SessionSync>,
    registry_live: Arc<AtomicBool>,
    generation: u64,
    current_generation: Arc<AtomicU64>,
}

impl SessionGate {
    /// Diagnostic/test-only point-in-time snapshot — check-then-forward,
    /// with the exact race window round 4 exists to close. Not reachable
    /// outside a test build, so "production forwarding must use
    /// `try_authorize_forwarding` instead" is enforced by the compiler, not
    /// just documented here.
    #[cfg(test)]
    #[must_use]
    pub fn is_authorized(&self) -> bool {
        self.registry_live.load(Ordering::SeqCst)
            && self.generation == self.current_generation.load(Ordering::SeqCst)
            && self
                .sync
                .state
                .lock()
                .map(|s| s.authorized)
                .unwrap_or(false)
    }

    /// The production authorization surface (round 4). On `Some`, the
    /// returned [`ForwardingGuard`] must be held for the entire forward it
    /// authorizes — see the guard's own doc comment.
    #[must_use]
    pub fn try_authorize_forwarding(&self) -> Option<ForwardingGuard<'_>> {
        if !self.registry_live.load(Ordering::SeqCst)
            || self.generation != self.current_generation.load(Ordering::SeqCst)
        {
            return None;
        }
        let guard = self.sync.try_enter()?;
        // A registry-wide transition (clean mark_unavailable/fork/
        // regression, or poison) flips these two WITHOUT going through
        // this session's SessionSync at all — only a per-session revoke
        // does that. Recheck now that admission into `sync` is held: from
        // here until the guard drops, nothing can flip `authorized` itself
        // (that needs `revoke`, which this guard's presence in
        // `active_readers` blocks from completing), so this is the last
        // recheck this guard's lifetime needs.
        if !self.registry_live.load(Ordering::SeqCst)
            || self.generation != self.current_generation.load(Ordering::SeqCst)
        {
            return None;
        }
        Some(guard)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterRefusal {
    /// `binding.hh_id()` does not match the household this registry was
    /// constructed for.
    HouseholdMismatch,
    /// `binding`'s `(checkpoint_hash, checkpoint_sequence)` does not match
    /// the registry's current revision — the `ExpectedResponder`/snapshot
    /// this binding was derived from is stale.
    RevisionMismatch,
    /// `binding.m_id()` is in the current revision's revoked set.
    MachineRevoked,
    /// `binding.m_id()` is not in the current revision's active set, or is
    /// active with a different `machine_cert_fingerprint` than `binding`
    /// carries.
    MachineNotActive,
    /// `handle` could not be upgraded — already dropped before it was ever
    /// registered.
    HandleAlreadyDropped,
    /// The registry is `Unavailable` (a prior observation failed or was
    /// inconsistent, or its lock is poisoned).
    RegistryUnavailable,
    /// `SessionId` space exhausted (`u64`, not reachable in practice —
    /// handled explicitly rather than silently wrapping).
    SessionIdSpaceExhausted,
}

/// Result of `observe_new_checkpoint`/`observe_authority_result`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveOutcome {
    /// Strictly newer sequence while already `Live`: revision advanced, any
    /// now-revoked (tombstoned/dropped/fingerprint-changed) sessions were
    /// revoked.
    Applied,
    /// Transitioned `Unavailable` -> `Live`: the observation was consistent
    /// with `last_known_revision` (same `(hash, sequence)` or strictly
    /// newer).
    Recovered,
    /// Already `Live`, same `(checkpoint_hash, checkpoint_sequence)` as the
    /// current revision: no-op, not an error.
    Idempotent,
    /// A lower sequence (regression/replay) or same sequence with a
    /// different hash (fork) — rejected. If this was seen while `Live`, the
    /// registry is now `Unavailable` (round 3, point 4); if already
    /// `Unavailable`, it stays `Unavailable`.
    Rejected,
}

struct Revision {
    checkpoint_hash: [u8; 32],
    checkpoint_sequence: u64,
    /// `m_id` -> `machine_cert_fingerprint`, so an observe can detect a
    /// fingerprint change (cert reissue) for an already-tracked machine,
    /// not just tombstone/absence.
    active: HashMap<MachineId, [u8; 32]>,
    revoked: HashSet<MachineId>,
}

impl Revision {
    fn from_snapshot(snapshot: &RosterSnapshotView) -> Self {
        let active = snapshot
            .active_m_ids()
            .filter_map(|m_id| {
                snapshot
                    .lookup_active(m_id)
                    .map(|member| (m_id.clone(), member.machine_cert_fingerprint()))
            })
            .collect();
        Self {
            checkpoint_hash: snapshot.checkpoint_hash(),
            checkpoint_sequence: snapshot.checkpoint_sequence(),
            active,
            revoked: snapshot.revoked_m_ids().iter().cloned().collect(),
        }
    }

    /// Regression (lower sequence) / fork (same sequence, different hash) /
    /// idempotent (same sequence, same hash) / advance (strictly higher
    /// sequence) — the one comparison rule shared by the Live-state advance
    /// path and the Unavailable-state recovery path (round 3, point 5).
    fn compare(&self, checkpoint_hash: [u8; 32], checkpoint_sequence: u64) -> RevisionComparison {
        match checkpoint_sequence.cmp(&self.checkpoint_sequence) {
            std::cmp::Ordering::Less => RevisionComparison::Regression,
            std::cmp::Ordering::Equal if checkpoint_hash == self.checkpoint_hash => {
                RevisionComparison::Idempotent
            }
            std::cmp::Ordering::Equal => RevisionComparison::Fork,
            std::cmp::Ordering::Greater => RevisionComparison::Advance,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RevisionComparison {
    Regression,
    Fork,
    Idempotent,
    Advance,
}

struct SessionEntry<H: RevocableMeshSession> {
    m_id: MachineId,
    machine_cert_fingerprint: [u8; 32],
    handle: Weak<H>,
    sync: Arc<SessionSync>,
}

// `Live`'s bookkeeping maps vs `Unavailable`'s unit-ish payload trips
// large_enum_variant. Not boxed: this is a private, one-per-registry state
// enum (never allocated in bulk or on a hot path), and boxing would add an
// indirection cost to every register/observe call for a size difference
// that has no measured impact here — a deliberate call, not an oversight.
#[allow(clippy::large_enum_variant)]
enum Mode<H: RevocableMeshSession> {
    Live {
        sessions: HashMap<SessionId, SessionEntry<H>>,
        by_machine: HashMap<MachineId, Vec<SessionId>>,
    },
    Unavailable,
}

/// Closes the remaining poison gap the RED test caught: setting
/// `registry_live` false only when some LATER method call happens to hit
/// the poisoned `std::sync::Mutex` leaves a window where nothing has
/// called the registry since the poisoning panic, so nothing has run the
/// code that would set `registry_live` false — every outstanding
/// `SessionGate` would read authorized during that window even though the
/// registry is already broken. Fixed by mirroring how `std::sync::Mutex`
/// itself detects poisoning: a guard whose `Drop` checks
/// `std::thread::panicking()`. `std::thread::panicking()` already
/// correctly distinguishes a panic-unwind drop from an ordinary
/// early-return drop for every exit path in the critical section it spans
/// — no manual "was this the risky part" bookkeeping needed. Constructed
/// immediately after a *successful* lock acquisition and left to drop
/// naturally at the end of that critical section's scope: if anything in
/// between panics, this guard's `Drop` runs during the SAME unwind that
/// poisons the mutex and sets `registry_live` false synchronously — before
/// the panicking thread's `join()` even returns on another thread, not on
/// some later, possibly-never-arriving method call.
struct PoisonGuard<'a> {
    registry_live: &'a AtomicBool,
}

impl<'a> PoisonGuard<'a> {
    fn new(registry_live: &'a AtomicBool) -> Self {
        Self { registry_live }
    }
}

impl Drop for PoisonGuard<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.registry_live.store(false, Ordering::SeqCst);
        }
    }
}

struct Inner<H: RevocableMeshSession> {
    hh_id: HouseholdId,
    /// Preserved across `Live` <-> `Unavailable` transitions (round 3,
    /// point 5) so a later recovery has something to compare consistency
    /// against.
    last_known_revision: Revision,
    /// Monotonic for the registry's whole lifetime, never reset on a
    /// recovery — no `SessionId` is ever reused.
    next_session_id: u64,
    mode: Mode<H>,
}

/// Registers live sessions by the `MachineId` of their peer and revokes them
/// when the roster observes that machine has since been revoked, dropped,
/// or re-certified. `Weak`, not `Arc`: the registry does not keep a session
/// alive — a session whose last strong owner already dropped it is pruned
/// (nothing to revoke) rather than kept alive artificially by this
/// bookkeeping.
pub struct MeshSessionRegistry<H: RevocableMeshSession> {
    inner: Mutex<Inner<H>>,
    /// Outside the mutex on purpose (round 3, CFX): must be reachable and
    /// settable to `false` even when `inner`'s lock is poisoned. Only ever
    /// set back to `true` from inside a successful (non-poisoned) lock
    /// acquisition — see `observe_new_checkpoint`'s recovery arm — which is
    /// structurally unreachable once poisoned, so poisoning this registry
    /// is permanent in practice even though this flag's type does not
    /// enforce that by itself.
    registry_live: Arc<AtomicBool>,
    /// Bumped on every `Unavailable -> Live` transition. See `SessionGate`.
    generation: Arc<AtomicU64>,
}

impl<H: RevocableMeshSession> MeshSessionRegistry<H> {
    /// Constructs the registry already bound to a validated initial
    /// snapshot and the household it was captured for — there is no
    /// `Default`/empty construction, so `register` can never run before any
    /// roster state has been observed.
    #[must_use]
    pub fn new(initial: &RosterSnapshotView) -> Self {
        Self {
            inner: Mutex::new(Inner {
                hh_id: initial.hh_id().clone(),
                last_known_revision: Revision::from_snapshot(initial),
                next_session_id: 0,
                mode: Mode::Live {
                    sessions: HashMap::new(),
                    by_machine: HashMap::new(),
                },
            }),
            registry_live: Arc::new(AtomicBool::new(true)),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Registers a live session, or refuses and returns why. `binding` must
    /// name this registry's household, match the current revision exactly
    /// (`checkpoint_hash` + `checkpoint_sequence`), and name a machine that
    /// is active in that revision with a matching
    /// `machine_cert_fingerprint`; `handle` must still be alive. On
    /// success, returns the `SessionId` (for `unregister`) and an
    /// `Arc<AtomicBool>` gate, initially `true`, that the caller's
    /// forwarding hot path should read — the registry flips it to `false`
    /// (never anything else) if this session is later revoked.
    pub fn register(
        &self,
        binding: &SealedBinding,
        handle: Weak<H>,
    ) -> Result<(SessionId, SessionGate), RegisterRefusal> {
        let Ok(mut guard) = self.inner.lock() else {
            self.registry_live.store(false, Ordering::SeqCst);
            return Err(RegisterRefusal::RegistryUnavailable);
        };
        let _poison_guard = PoisonGuard::new(&self.registry_live);
        let Inner {
            hh_id,
            last_known_revision,
            next_session_id,
            mode,
        } = &mut *guard;
        let Mode::Live {
            sessions,
            by_machine,
        } = mode
        else {
            return Err(RegisterRefusal::RegistryUnavailable);
        };
        if binding.hh_id() != hh_id {
            return Err(RegisterRefusal::HouseholdMismatch);
        }
        if last_known_revision.checkpoint_hash != binding.checkpoint_hash()
            || last_known_revision.checkpoint_sequence != binding.checkpoint_sequence()
        {
            return Err(RegisterRefusal::RevisionMismatch);
        }
        if last_known_revision.revoked.contains(binding.m_id()) {
            return Err(RegisterRefusal::MachineRevoked);
        }
        match last_known_revision.active.get(binding.m_id()) {
            Some(fp) if *fp == binding.machine_cert_fingerprint() => {}
            _ => return Err(RegisterRefusal::MachineNotActive),
        }
        if handle.upgrade().is_none() {
            return Err(RegisterRefusal::HandleAlreadyDropped);
        }
        let id = next_session_id
            .checked_add(1)
            .ok_or(RegisterRefusal::SessionIdSpaceExhausted)?;
        *next_session_id = id;
        let session_id = SessionId(id);
        let sync = SessionSync::new();
        sessions.insert(
            session_id,
            SessionEntry {
                m_id: binding.m_id().clone(),
                machine_cert_fingerprint: binding.machine_cert_fingerprint(),
                handle,
                sync: Arc::clone(&sync),
            },
        );
        by_machine
            .entry(binding.m_id().clone())
            .or_default()
            .push(session_id);
        let gate = SessionGate {
            sync,
            registry_live: Arc::clone(&self.registry_live),
            generation: self.generation.load(Ordering::SeqCst),
            current_generation: Arc::clone(&self.generation),
        };
        Ok((session_id, gate))
    }

    /// Removes `session_id` AND disables its `SessionGate` first (round 4,
    /// pass 4, @kiana catch — this used to leave the gate `true` "for a
    /// session ending normally"). Losing tracking must never mean "now
    /// permanently authorized with no way to ever revoke it": once a
    /// session is removed from `sessions`/`by_machine`, a FUTURE
    /// checkpoint observation has no way to reach it at all (it is not in
    /// either map anymore) — so if a caller unregisters a session that is
    /// actually still alive/forwarding (a caller bug, or a race with the
    /// peer), failing to close it here would be a permanent, silent
    /// authority leak. `unregister` is therefore equivalent to a
    /// single-session revoke, not a "leave it be" removal.
    pub fn unregister(&self, session_id: SessionId) {
        let entry = {
            let Ok(mut guard) = self.inner.lock() else {
                self.registry_live.store(false, Ordering::SeqCst);
                return;
            };
            let _poison_guard = PoisonGuard::new(&self.registry_live);
            if let Mode::Live {
                sessions,
                by_machine,
            } = &mut guard.mode
            {
                let removed = sessions.remove(&session_id);
                if let Some(entry) = &removed {
                    if let Some(ids) = by_machine.get_mut(&entry.m_id) {
                        ids.retain(|id| *id != session_id);
                        if ids.is_empty() {
                            by_machine.remove(&entry.m_id);
                        }
                    }
                }
                removed
            } else {
                None
            }
        };
        let Some(entry) = entry else {
            return;
        };
        // Unlocked (round 4): may block waiting out an in-flight
        // ForwardingGuard, same as every other revoke path in this file —
        // never while `self.inner`'s lock is held.
        entry.sync.revoke();
        if let Some(handle) = entry.handle.upgrade() {
            handle.send_best_effort_revoke_notice();
            handle.close();
        }
    }

    /// True if at least one still-live (upgradable) session is registered
    /// for `m_id`. Prunes any dead `Weak` entries for `m_id` it finds along
    /// the way (round 3, point b) — a read can observe and clean up
    /// staleness without waiting for the next checkpoint to do it.
    #[must_use]
    pub fn is_registered(&self, m_id: &MachineId) -> bool {
        self.registered_count(m_id) > 0
    }

    /// Count of still-live (upgradable) sessions registered for `m_id`.
    /// Same pruning behavior as `is_registered`.
    #[must_use]
    pub fn registered_count(&self, m_id: &MachineId) -> usize {
        let Ok(mut guard) = self.inner.lock() else {
            self.registry_live.store(false, Ordering::SeqCst);
            return 0;
        };
        let _poison_guard = PoisonGuard::new(&self.registry_live);
        let Mode::Live {
            sessions,
            by_machine,
        } = &mut guard.mode
        else {
            return 0;
        };
        let Some(ids) = by_machine.get_mut(m_id) else {
            return 0;
        };
        ids.retain(|id| {
            let alive = sessions
                .get(id)
                .is_some_and(|entry| entry.handle.strong_count() > 0);
            if !alive {
                sessions.remove(id);
            }
            alive
        });
        let count = ids.len();
        if ids.is_empty() {
            by_machine.remove(m_id);
        }
        count
    }

    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        let Ok(guard) = self.inner.lock() else {
            self.registry_live.store(false, Ordering::SeqCst);
            return true;
        };
        let _poison_guard = PoisonGuard::new(&self.registry_live);
        matches!(&guard.mode, Mode::Unavailable)
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
    /// See the module doc comment (points 3-5) for the exact
    /// regression/fork/idempotent/advance/recovery rules. Nothing blocking
    /// runs while the internal lock is held (point 2).
    ///
    /// Prefer `observe_authority_result` when you have a
    /// `Result<RosterSnapshotView, RosterSnapshotError>` straight from
    /// `MachineRosterCoordinator::current_snapshot()` — it routes the `Err`
    /// case to `mark_unavailable` for you.
    pub fn observe_new_checkpoint(&self, snapshot: &RosterSnapshotView) -> ObserveOutcome {
        // Phase A (short registry-mutex critical section): decide, mutate
        // registry-owned bookkeeping, and collect which sessions need
        // revoking -- but do NOT call SessionSync::revoke() on any of them
        // yet. revoke() can block, waiting out an in-flight
        // ForwardingGuard; calling it here, still holding `self.inner`'s
        // lock, would block every unrelated register/unregister/observe on
        // this registry for as long as that one forward takes (round 4).
        let to_revoke: Vec<(SessionId, Arc<SessionSync>, Weak<H>)>;
        let outcome;
        {
            let Ok(mut guard) = self.inner.lock() else {
                self.registry_live.store(false, Ordering::SeqCst);
                return ObserveOutcome::Rejected;
            };
            let _poison_guard = PoisonGuard::new(&self.registry_live);

            // Wrong household is treated exactly like a fork/regression —
            // an integrity violation, not a value to apply (round 3, point
            // a). Folded into the same comparison so the rest of the match
            // below has one decision axis, not two.
            let comparison = if snapshot.hh_id() == &guard.hh_id {
                guard
                    .last_known_revision
                    .compare(snapshot.checkpoint_hash(), snapshot.checkpoint_sequence())
            } else {
                RevisionComparison::Fork
            };

            match (&mut guard.mode, comparison) {
                (Mode::Live { .. }, RevisionComparison::Regression | RevisionComparison::Fork) => {
                    // Integrity violation while Live: close everything,
                    // transition to Unavailable, do NOT update
                    // last_known_revision (it still names the last state
                    // that was actually trusted).
                    let Mode::Live { sessions, .. } =
                        std::mem::replace(&mut guard.mode, Mode::Unavailable)
                    else {
                        unreachable!("matched Mode::Live above")
                    };
                    to_revoke = sessions
                        .into_iter()
                        .map(|(id, entry)| (id, entry.sync, entry.handle))
                        .collect();
                    // Registry-wide: rejects any NEW try_authorize_forwarding
                    // immediately for every session at once, without
                    // waiting for Phase B's per-session SessionSync::revoke()
                    // calls below to individually reach each one — belt and
                    // suspenders alongside them, and the only defense at
                    // all for the poison case (see registry_live's own doc
                    // comment).
                    self.registry_live.store(false, Ordering::SeqCst);
                    outcome = ObserveOutcome::Rejected;
                }
                (Mode::Unavailable, RevisionComparison::Regression | RevisionComparison::Fork) => {
                    // Still inconsistent with the last trusted truth: stay
                    // Unavailable. Nothing tracked to close.
                    to_revoke = Vec::new();
                    outcome = ObserveOutcome::Rejected;
                }
                (Mode::Live { .. }, RevisionComparison::Idempotent) => {
                    // Already live, nothing changed: true no-op.
                    to_revoke = Vec::new();
                    outcome = ObserveOutcome::Idempotent;
                }
                (
                    Mode::Unavailable,
                    RevisionComparison::Idempotent | RevisionComparison::Advance,
                ) => {
                    // Consistent with last_known_revision (same state
                    // re-observed, or a newer one) while Unavailable:
                    // recover — but only if the generation counter can
                    // still be safely advanced (round 4, pass 4, @kiana
                    // catch). Wrapping u64::MAX back to 0 would make a
                    // gate issued at the registry's very first
                    // (pre-recovery) generation read authorized again —
                    // the same class of bug as reusing a SessionId, just
                    // for generations. checked_add, not fetch_add: on
                    // exhaustion, refuse to recover at all rather than
                    // risk that — stay Unavailable, the same fail-closed
                    // posture as an actually-poisoned mutex. Only ever
                    // mutated from inside this exact branch, itself
                    // already under `self.inner`'s lock, so a plain
                    // load-then-store here has no race to guard against.
                    if let Some(next_generation) =
                        self.generation.load(Ordering::SeqCst).checked_add(1)
                    {
                        guard.mode = Mode::Live {
                            sessions: HashMap::new(),
                            by_machine: HashMap::new(),
                        };
                        guard.last_known_revision = Revision::from_snapshot(snapshot);
                        // Only reachable from inside a successful
                        // (non-poisoned) lock acquisition — see
                        // MeshSessionRegistry::registry_live's doc
                        // comment for why that makes poisoning
                        // permanent in practice. Generation stored
                        // BEFORE registry_live is set true: any
                        // SessionGate issued before this instant now
                        // reads a stale generation regardless of
                        // registry_live's value, even under a torn
                        // read from another thread observing these two
                        // stores out of program order.
                        self.generation.store(next_generation, Ordering::SeqCst);
                        self.registry_live.store(true, Ordering::SeqCst);
                        to_revoke = Vec::new();
                        outcome = ObserveOutcome::Recovered;
                    } else {
                        to_revoke = Vec::new();
                        outcome = ObserveOutcome::Rejected;
                    }
                }
                (Mode::Live { .. }, RevisionComparison::Advance) => {
                    let Mode::Live {
                        sessions,
                        by_machine,
                    } = &mut guard.mode
                    else {
                        unreachable!("matched Mode::Live above")
                    };
                    let new_revision = Revision::from_snapshot(snapshot);

                    // Per-SESSION, not per-machine: two sessions for the
                    // same m_id registered under different
                    // machine_cert_fingerprints (one before a cert reissue,
                    // one after) must be judged independently — the stale
                    // one revoked, the current one left alone. Collected
                    // here only — Phase B (below, unlocked) is what
                    // actually calls SessionSync::revoke() on each.
                    let to_revoke_ids: HashSet<SessionId> = sessions
                        .iter()
                        .filter(|(_, entry)| should_revoke(entry, &new_revision))
                        .map(|(id, _)| *id)
                        .collect();
                    to_revoke = to_revoke_ids
                        .iter()
                        .map(|id| {
                            let entry = &sessions[id];
                            (*id, Arc::clone(&entry.sync), entry.handle.clone())
                        })
                        .collect();

                    // Cheap, non-blocking bookkeeping (upgrade()/
                    // strong_count() only, no SessionSync/session methods
                    // called): drop tracking for any remaining handle, NOT
                    // one of this round's to_revoke_ids, whose last Arc
                    // already dropped elsewhere. to_revoke_ids are skipped
                    // here — Phase C below removes those once their
                    // SessionSync::revoke() has actually run.
                    let still_tracked: Vec<MachineId> = by_machine.keys().cloned().collect();
                    for m_id in still_tracked {
                        if let Some(ids) = by_machine.get_mut(&m_id) {
                            ids.retain(|id| {
                                if to_revoke_ids.contains(id) {
                                    return true;
                                }
                                let alive = sessions
                                    .get(id)
                                    .is_some_and(|entry| entry.handle.strong_count() > 0);
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
                    guard.last_known_revision = new_revision;
                    outcome = ObserveOutcome::Applied;
                }
            }
        }

        // Phase B (unlocked): for each session actually being revoked,
        // announce revoke intent for the whole call (blocking out any NEW
        // forwarding attempt for exactly this session from this instant,
        // by state — see SessionSync's doc comment) and wait out any
        // IN-FLIGHT forward for this session — all without holding
        // `self.inner`'s lock, so unrelated registry operations are never
        // blocked by a slow forward (round 4).
        for (_, sync, _) in &to_revoke {
            sync.revoke();
        }

        // Phase C: bookkeeping only. By this point every revoked session's
        // `room` already reads false — Phase B already closed authorization
        // for all of them — so nothing here is security-relevant; this
        // only removes now-dead entries from the tracking maps
        // (is_registered/registered_count accuracy, memory). A no-op for
        // the Fork/Regression path: that map was already fully drained in
        // Phase A via mem::replace.
        if !to_revoke.is_empty() {
            if let Ok(mut guard) = self.inner.lock() {
                let _poison_guard = PoisonGuard::new(&self.registry_live);
                if let Mode::Live {
                    sessions,
                    by_machine,
                } = &mut guard.mode
                {
                    for (id, _, _) in &to_revoke {
                        if let Some(entry) = sessions.remove(id) {
                            if let Some(ids) = by_machine.get_mut(&entry.m_id) {
                                ids.retain(|existing| existing != id);
                                if ids.is_empty() {
                                    by_machine.remove(&entry.m_id);
                                }
                            }
                        }
                    }
                }
            } else {
                self.registry_live.store(false, Ordering::SeqCst);
            }
        }

        let to_finish: Vec<Arc<H>> = to_revoke
            .into_iter()
            .filter_map(|(_, _, handle)| handle.upgrade())
            .collect();
        for handle in to_finish {
            handle.send_best_effort_revoke_notice();
            handle.close();
        }
        outcome
    }

    /// Routes a `Result` straight from
    /// `MachineRosterCoordinator::current_snapshot()`: `Ok` goes to
    /// `observe_new_checkpoint`, `Err` goes to `mark_unavailable` (any error
    /// reason is treated the same way — fail closed). Idempotent: repeating
    /// the same `Err` while already `Unavailable` does not repeat any
    /// closing work (`mark_unavailable` itself is a no-op once
    /// `Unavailable`).
    pub fn observe_authority_result(
        &self,
        result: Result<RosterSnapshotView, RosterSnapshotError>,
    ) -> ObserveOutcome {
        match result {
            Ok(snapshot) => self.observe_new_checkpoint(&snapshot),
            Err(_) => self.mark_unavailable(),
        }
    }

    /// Closes every currently active session (gate flipped under the lock,
    /// notice and close after releasing it) and transitions to
    /// `Unavailable`, preserving `last_known_revision` for a later
    /// recovery. Idempotent: a second call on an already-`Unavailable`
    /// registry is a no-op — no repeated closing work.
    pub fn mark_unavailable(&self) -> ObserveOutcome {
        // Same two-phase shape as observe_new_checkpoint's Fork/Regression
        // arm (round 4): collect under the lock, revoke() each unlocked.
        let to_revoke: Vec<(SessionId, Arc<SessionSync>, Weak<H>)>;
        {
            let Ok(mut guard) = self.inner.lock() else {
                // Poisoned: cannot reach the interior's sessions to close
                // them individually, but registry_live is a separate
                // atomic, reachable without the lock — set it false so
                // every outstanding SessionGate reads unauthorized
                // regardless.
                self.registry_live.store(false, Ordering::SeqCst);
                return ObserveOutcome::Rejected;
            };
            let _poison_guard = PoisonGuard::new(&self.registry_live);
            let Mode::Live {
                sessions,
                by_machine,
            } = std::mem::replace(&mut guard.mode, Mode::Unavailable)
            else {
                guard.mode = Mode::Unavailable; // was already Unavailable; no-op
                return ObserveOutcome::Rejected;
            };
            drop(by_machine);
            to_revoke = sessions
                .into_iter()
                .map(|(id, entry)| (id, entry.sync, entry.handle))
                .collect();
            self.registry_live.store(false, Ordering::SeqCst);
        }
        for (_, sync, _) in &to_revoke {
            sync.revoke();
        }
        let to_finish: Vec<Arc<H>> = to_revoke
            .into_iter()
            .filter_map(|(_, _, handle)| handle.upgrade())
            .collect();
        for handle in to_finish {
            handle.send_best_effort_revoke_notice();
            handle.close();
        }
        ObserveOutcome::Rejected
    }

    /// Test-only: poisons `inner` through the SAME lock -> `PoisonGuard`
    /// sequence every real method uses, then panics — simulating "some bug
    /// inside a real critical section panicked" honestly, rather than a
    /// test reaching around this type's private field to lock and panic
    /// directly (which cannot happen in real production code — `inner` is
    /// private to this module; nothing outside `MeshSessionRegistry`'s own
    /// methods can ever acquire it, so a raw external lock+panic is not a
    /// scenario this type can occur in practice, only a test artifact that
    /// would bypass `PoisonGuard` entirely and prove nothing).
    #[cfg(test)]
    fn poison_for_test(&self) {
        let _guard = self.inner.lock().unwrap();
        let _poison_guard = PoisonGuard::new(&self.registry_live);
        panic!("deliberate poison for test, via the same guard sequence every real method uses");
    }
}

fn should_revoke<H: RevocableMeshSession>(entry: &SessionEntry<H>, revision: &Revision) -> bool {
    if revision.revoked.contains(&entry.m_id) {
        return true;
    }
    match revision.active.get(&entry.m_id) {
        None => true,
        Some(fp) => *fp != entry.machine_cert_fingerprint,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Barrier, Mutex as StdMutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::keys::P256PublicKey;
    use crate::machine_cert::PersonId;
    use crate::machine_roster_authority::{
        AcceptedRosterData, ExpectedResponder, MachineRosterMemberV1, MachineRosterRevocationV1,
        PeerExpectation, PeerSelectionSource,
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
            0x02, 0x18, 0x62, 0x99, 0x63, 0x3f, 0x2c, 0x2f, 0x53, 0xd5, 0x4b, 0xf8, 0x9b, 0x03,
            0xd0, 0x82, 0x03, 0x2c, 0x42, 0xb7, 0xef, 0x35, 0x0c, 0xcd, 0x35, 0x5b, 0xcc, 0x8b,
            0x0b, 0xf5, 0xca, 0x66, 0x36,
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
            let responder =
                ExpectedResponder::from_peer_expectation(expectation, &snapshot).unwrap();
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
            let revoke_snapshot =
                Arc::new(snapshot_at(2, [2u8; 32], &[], std::slice::from_ref(&m_id)));

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
            let recovery_snapshot =
                Arc::new(snapshot_at(2, [2u8; 32], &[(m_id.clone(), FP_A)], &[]));
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
}
