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
//! ## D-9 carrier B erratum1 E4 + bounded admission: Pending -> Ack -> Active
//!
//! Production admission is deliberately two-phase, and the boundary between
//! the phases is the **full `ActivateAck`**, which is a point of no return
//! (round D-1 bounded admission, @kiana audit `caf6d1e4`).
//!
//! [`MeshSessionRegistry::try_preauthorize_before`] performs the exact D-1
//! revision/membership checks and inserts a tracked Pending session with no
//! forwarding gate. It never waits: it `try_lock`s, and a `Busy` result has
//! no effect at all, leaving the ceremony-deadline backoff to the runtime
//! adapter.
//!
//! A fully successful Ack write is followed immediately by
//! [`PendingSessionAdmission::commit_after_ack`], which is **infallible by
//! design** — no deadline, no roster/revision/membership recheck, no
//! registry lock, no call into `H`, no `Result`. Once the peer holds the
//! complete Ack, a local refusal would leave the two sides disagreeing
//! about whether the session exists. A revoke announced during the Ack
//! window does not veto the commit; it closes the session immediately
//! afterward instead, and nothing can forward in between because
//! [`SessionSync::try_enter`] rejects on `writer_intent` *before* it reads
//! the phase.
//!
//! A partial or failed Ack takes [`PendingSessionAdmission::cancel_before_ack`],
//! and simply dropping the permit is the same fail-closed path reduced to
//! its minimum: one atomic phase CAS plus a notify, with no lock, no wait,
//! and no callback into `H`.
//!
//! **Do not reintroduce a post-Ack recheck.** The evidence it would need
//! (the pre-Ack binding copy) was deliberately deleted, precisely so the
//! decision cannot be made.
//!
//! The old immediate `register` helper exists only in this module's tests
//! and is absent from production builds.
//!
//! D-6 (the roster-sync transport that decides *when* a new checkpoint is
//! durably observed) is out of scope here too — see
//! [`observe_new_checkpoint`]'s doc comment.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::ids::{HouseholdId, MachineId};
use crate::machine_roster_authority::{RosterSnapshotError, RosterSnapshotView, SealedBinding};

/// What `MeshSessionRegistry` needs from a live session once it has
/// decided to revoke it. No identity method — see the module doc comment,
/// point 1. No "mark not authorized" method either — see point 2; that
/// signal is the [`SessionGate`] returned only after Pending -> Active, not
/// a trait call.
pub trait RevocableMeshSession {
    /// May block (e.g. network I/O for a notice). The registry never calls
    /// this while its internal lock is held.
    fn send_best_effort_revoke_notice(&self);

    /// May block. The registry never calls this while its internal lock is
    /// held.
    fn close(&self);
}

/// Opaque handle to one Active session. Reachable via
/// [`ActiveSessionRegistration::session_id`] after
/// [`PendingSessionAdmission::commit_after_ack`], and needed by
/// [`MeshSessionRegistry::unregister`]/
/// [`MeshSessionRegistry::retire_locally`].
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
///   [`announce_revoke`](SessionSync::announce_revoke) on the same
///   `SessionSync` concurrently (two different `observe_new_checkpoint`/
///   `mark_unavailable` calls can both decide to revoke the same session
///   before either has removed it from the registry's bookkeeping maps),
///   and the signal must stay "a writer is active" until ALL of them
///   finish, not drop to zero the moment the first one does;
/// - `phase`: the single source of truth for whether this session may
///   forward — an `AtomicU8` OUTSIDE `state`'s `Mutex`, so cancel and the
///   Pending `Drop` can close authority with no lock at all. It replaced
///   the former `authorized` bool and `pending_admissions` counter, which
///   lived inside the `Mutex` and duplicated a fact that
///   `SessionEntry.lifecycle` also stored;
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
/// real reason to stop trusting it). [`drain_after_announce`](SessionSync::drain_after_announce)
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
    writer_active: bool,
    active_readers: usize,
}

/// The one lifecycle a session has (round D-1 bounded admission, @kiana
/// audit `caf6d1e4`). Replaces BOTH the old `GateState.authorized` +
/// `GateState.pending_admissions` pair AND the old per-map
/// `SessionEntry.lifecycle` copy: two sources of truth for "is this
/// session live" is exactly the shape that lets them disagree.
///
/// ```text
/// Pending --commit_after_ack--> Active --revoke/retire--> Closed
/// Pending --cancel/Drop-------> Closed
/// ```
///
/// An `AtomicU8` and not a field of `state` on purpose: cancel and the
/// Pending `Drop` must be able to close authority **without acquiring any
/// mutex at all** (D3), and a revoker must be able to observe the phase
/// without blocking. See [`SessionSync::drain_after_announce`] for the
/// lost-wakeup consequence that buys.
const PHASE_PENDING: u8 = 0;
const PHASE_ACTIVE: u8 = 1;
const PHASE_CLOSED: u8 = 2;

/// How often [`SessionSync::drain_after_announce`] rechecks the phase while
/// waiting for it to leave `Pending`.
///
/// A timed wait is REQUIRED, not a tuning choice: `cancel_before_ack` and
/// the Pending `Drop` change `phase` with a bare atomic CAS and then
/// `notify_all` **without ever holding `state`**. A waiter that evaluated
/// the predicate, then entered an untimed `Condvar::wait`, can therefore
/// have the notification land in the gap between those two steps and sleep
/// forever. Rechecking on a timer turns a permanent wedge into at most one
/// extra interval of latency. See the RED
/// `pending_drop_never_wedges_a_revoker_that_notified_before_waiting`.
const PHASE_RECHECK_INTERVAL: Duration = Duration::from_millis(2);

struct SessionSync {
    /// See the struct doc comment above — deliberately outside `state`'s
    /// `Mutex`.
    writer_intent: AtomicUsize,
    /// The single source of truth for this session's lifecycle — see the
    /// `PHASE_*` constants. Outside `state`'s `Mutex` so a cancel/`Drop`
    /// can close authority with no lock at all.
    phase: AtomicU8,
    state: Mutex<GateState>,
    /// Signaled on every phase transition and whenever an Active
    /// forwarding guard drains, so a writer waiting in
    /// `drain_after_announce` wakes promptly rather than only on its
    /// recheck timer.
    drained: Condvar,
}

impl SessionSync {
    fn new_pending() -> Arc<Self> {
        Arc::new(Self {
            writer_intent: AtomicUsize::new(0),
            phase: AtomicU8::new(PHASE_PENDING),
            state: Mutex::new(GateState {
                writer_active: false,
                active_readers: 0,
            }),
            drained: Condvar::new(),
        })
    }

    fn phase(&self) -> u8 {
        self.phase.load(Ordering::SeqCst)
    }

    /// `Pending -> Active`, the terminal post-Ack transition (D1). Takes NO
    /// lock, consults no roster, and — critically — **an already-announced
    /// writer does not veto it**. Once the peer holds a complete
    /// `ActivateAck`, refusing locally would make the peer believe the
    /// session is Active while we do not; instead the announced writer
    /// simply closes the freshly-Active session immediately afterward. No
    /// forwarding can slip into that gap, because `try_enter` rejects on
    /// `writer_intent > 0` before it ever looks at the phase.
    ///
    /// Returns whether this call performed the transition. `false` means
    /// the phase was no longer `Pending` — unreachable while the caller
    /// still owns the permit (only `cancel_before_ack`/`Drop` close a
    /// Pending session, and both consume it), and fail-closed if it ever
    /// happened: the session stays Closed and nothing can forward.
    fn commit_after_ack(&self) -> bool {
        let won = self
            .phase
            .compare_exchange(
                PHASE_PENDING,
                PHASE_ACTIVE,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok();
        // Wake any revoker parked waiting for the phase to leave Pending.
        self.drained.notify_all();
        won
    }

    /// Idempotent `Pending -> Closed` (D3). This is the whole of what a
    /// Pending `Drop` is allowed to do: one atomic CAS plus a `notify_all`
    /// — no mutex acquisition, no wait, no `Weak` upgrade, no call into
    /// `H`, no allocation. Authority is therefore closed immediately and
    /// unconditionally, even while both `inner` and `state` are held by
    /// other threads and even during a panic unwind.
    ///
    /// Deliberately does NOT downgrade an already-`Active` session: that
    /// is a revoke, which belongs to `drain_after_announce`.
    fn close_if_pending(&self) -> bool {
        let closed = self
            .phase
            .compare_exchange(
                PHASE_PENDING,
                PHASE_CLOSED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok();
        self.drained.notify_all();
        closed
    }

    /// Phase 1 of a revoke: increment `writer_intent` only. Lock-free,
    /// cannot itself be delayed by another target's slow drain — see
    /// [`revoke_batch`]. Split from [`drain_after_announce`](Self::drain_after_announce)
    /// (round D-1 successor, @kiana P0-1, sharpened by a second recheck)
    /// so a caller can announce to every target in a batch — or, just as
    /// importantly, announce while STILL HOLDING a coarser lock that is
    /// about to publish some other state (a revoked machine's absence from
    /// `by_machine`, a reduced `registered_count`, a new
    /// `last_known_revision`) — strictly BEFORE that publication becomes
    /// externally observable. `unregister` and `registered_count`'s
    /// dead-Weak prune both call this while still under `self.inner`'s
    /// lock for exactly that reason: without it, another caller could
    /// already observe the session as gone/unregistered while a
    /// `SessionGate` cloned earlier still obtains a fresh
    /// `ForwardingGuard`, since nothing had announced revoke intent to its
    /// `SessionSync` yet. A single combined "revoke now" method that
    /// always announces immediately before draining does not offer this —
    /// see [`revoke_batch`] for the equivalent batch-vs-sequential
    /// argument.
    fn announce_revoke(&self) {
        self.writer_intent.fetch_add(1, Ordering::SeqCst);
    }

    /// Must be preceded by exactly one [`announce_revoke`](Self::announce_revoke)
    /// on the same instance — every call site in this file pairs them,
    /// either directly or via [`revoke_batch`]/[`drain_batch`]. Waits out
    /// any already-admitted readers/pending-admissions, commits the
    /// fail-closed bit, then balances `writer_intent` back down. A
    /// poisoned `state` (initial lock, or observed during the `Condvar`
    /// wait) is recovered via `into_inner` but does NOT short-circuit the
    /// wait — see the struct doc comment for why `active_readers` remains
    /// trustworthy across poison and abandoning the wait would violate the
    /// documented contract that draining does not return until every
    /// in-flight forward has actually finished.
    fn drain_after_announce(&self) {
        self.drain_after_announce_inner(|| {});
    }

    /// Test seam for the lost-wakeup property: `before_phase_wait` runs
    /// while `state` is held, immediately after the phase check and
    /// immediately before the `Condvar` wait — the exact window in which a
    /// `notify_all` from a lock-free `close_if_pending` has no waiter to
    /// deliver to. See
    /// `pending_drop_never_wedges_a_revoker_that_notified_before_waiting`.
    fn drain_after_announce_inner(&self, before_phase_wait: impl Fn()) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Step 1: a Pending session has not reached its terminal Ack
        // decision yet, and closing it here would pre-empt a commit the
        // peer may already be entitled to. Wait for the runtime to either
        // commit or cancel. TIMED — see `PHASE_RECHECK_INTERVAL` for why an
        // untimed wait can be lost permanently here.
        while self.phase() == PHASE_PENDING {
            before_phase_wait();
            let (next, _timed_out) = match self.drained.wait_timeout(state, PHASE_RECHECK_INTERVAL)
            {
                Ok(pair) => pair,
                Err(poisoned) => poisoned.into_inner(),
            };
            state = next;
        }
        // Step 2: close under `state`, so `try_enter`'s own under-lock
        // phase recheck cannot interleave between observing Active and
        // this store.
        self.phase.store(PHASE_CLOSED, Ordering::SeqCst);
        // Step 3: wait out the FIXED set of readers admitted before the
        // announce. No new reader can join: `try_enter` rejects on
        // `writer_intent > 0` and now also on a non-Active phase.
        while state.active_readers > 0 {
            state = match self.drained.wait(state) {
                Ok(next) => next,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        state.writer_active = true;
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
        // `writer_intent` is checked FIRST, before the phase, and that
        // order is load-bearing: it is what guarantees zero forwarding in
        // the `commit_after_ack` -> revoker-closes gap. A revoker that
        // announced while the session was still Pending has already
        // raised this counter, so the brief Active window that the
        // terminal Ack rule requires admits nobody.
        if self.writer_intent.load(Ordering::SeqCst) > 0 {
            return None;
        }
        if self.phase() != PHASE_ACTIVE {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        if self.writer_intent.load(Ordering::SeqCst) > 0
            || state.writer_active
            || self.phase() != PHASE_ACTIVE
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
///
/// `Clone` is intentional, evaluated and kept (round D-1 successor,
/// @kiana P0-2 asked this be weighed against a non-`Clone` structural
/// wrapper joining registration and gate). Real concurrent forwarding
/// needs an owned copy per worker/thread — this file's own tests already
/// clone a `SessionGate` to move into a spawned thread for exactly that
/// reason. A non-`Clone` wrapper would not remove that need; it would only
/// force callers to reach for `Arc<SessionGate>` instead, which has the
/// identical "can be held past what created it" shape `Arc` always has —
/// no structural gain, just a renamed one. The property P0-2 actually
/// needs — a clone can never outlive its session's REVOCABILITY — already
/// holds by construction and does not depend on `Clone`'s absence: every
/// field here is a shared `Arc`/`Arc<Atomic*>`, so revoking the underlying
/// `sync` (or a registry-wide close/poison) is instantly visible to EVERY
/// existing and future clone, because they all read the SAME atomics —
/// `try_authorize_forwarding` rechecks all three on every single call, not
/// once at construction. What P0-2's actual RED exercised was a DIFFERENT
/// bug: a bookkeeping-removal path that dropped a session's tracking
/// entry without ever calling `SessionSync::revoke()` on it at all, so
/// there was nothing for a clone to observe — fixed at the three sites
/// that remove entries (`observe_new_checkpoint`'s Advance-branch
/// naturally-dead cleanup, `registered_count`'s dead-Weak prune, and
/// `mark_unavailable`), not by touching `Clone`.
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
            && self.sync.phase() == PHASE_ACTIVE
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

/// Why [`MeshSessionRegistry::try_preauthorize_before`] did not produce a
/// permit (round D-1 bounded admission, @kiana audit `caf6d1e4`, D2).
///
/// `Busy` and `Expired` are deliberately distinct from `Refused`: the first
/// two say nothing about this peer's admissibility and leave the registry
/// bit-for-bit unchanged, so a runtime adapter may retry `Busy` freely
/// while its ceremony deadline lasts. Collapsing them into one refusal
/// would make a lock collision indistinguishable from a roster rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TryPreauthorizeError {
    /// `inner` was held by someone else. Nothing was read, checked, or
    /// mutated. Retry is safe and is the adapter's decision, not
    /// household's.
    Busy,
    /// `deadline_at` had already passed when the lock was obtained,
    /// re-read inside the critical section before any mutation.
    Expired,
    /// `inner` is poisoned; `registry_live` has been set false.
    Poisoned,
    /// The D-1 admission checks themselves rejected this binding.
    Refused(RegisterRefusal),
}

/// Result of [`PendingSessionAdmission::cancel_before_ack`] (D3).
///
/// Authority is closed in **every** variant, before any of them is
/// computed — the phase CAS happens first and needs no lock. These describe
/// only what happened to the *bookkeeping*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingCancelOutcome {
    /// Closed, and the tracking entry was removed.
    ClosedAndRemoved,
    /// Closed, but `inner` was busy, so the entry is still in the maps as
    /// reconcilable debt. NOT an error and NOT an authority gap: the
    /// session cannot forward, and a later registry operation or
    /// [`reconcile_closed_pending`](MeshSessionRegistry::reconcile_closed_pending)
    /// removes it.
    ClosedCleanupDeferred,
    /// Closed, but the registry is `Unavailable`/poisoned, so no
    /// per-session bookkeeping could run at all.
    RegistryUnavailable,
}

/// Result of
/// [`reconcile_closed_pending`](MeshSessionRegistry::reconcile_closed_pending).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// Swept; `removed` entries whose phase was already `Closed` are gone.
    Swept { removed: usize },
    /// `inner` was busy. Nothing swept, nothing broken — the debt simply
    /// survives to the next caller.
    Busy,
    /// Registry is `Unavailable` or poisoned.
    RegistryUnavailable,
}

/// Result of [`MeshSessionRegistry::retire_locally`] (round D-1 successor,
/// @kiana): which caller the *completion* half of the guarantee actually
/// belongs to.
///
/// Authority is closed in every variant — that part never depends on who
/// won. Only [`RetiredAndDrained`](Self::RetiredAndDrained) additionally
/// means "and nothing was still in flight when this returned".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireOutcome {
    /// This call is the one that removed the session: it announced under
    /// `self.inner`'s lock and then drained. Full guarantee — on return the
    /// session's `SessionGate` (and every clone) is closed AND no forward
    /// that was in flight is still running.
    RetiredAndDrained,
    /// The session was already absent when this call reached the lock —
    /// concurrently retired by another caller, already unregistered, or
    /// never registered. This call announced nothing and drained nothing.
    /// Authority is still closed (whoever removed it announced under the
    /// lock, before the absence this call observed), but the drain
    /// guarantee belongs to that caller, not this one.
    NotTracked,
    /// The registry is `Unavailable`, or its lock is poisoned. Registry-wide
    /// fail-closed has been applied (`registry_live = false`), so no gate on
    /// this registry authorizes anything — but no per-session announce or
    /// drain could run.
    RegistryUnavailable,
}

/// Opaque, non-clonable proof that one session is tracked as Pending at an
/// exact D-1 revision. The permit deliberately exposes neither a
/// [`SessionGate`] nor the fields needed to forge another permit: Pending
/// cannot forward. Hold it across exactly one Ack write, then consume it
/// with [`commit_after_ack`](Self::commit_after_ack) on full success or
/// [`cancel_before_ack`](Self::cancel_before_ack) on partial write/failure.
///
/// Dropping it without either is the fail-closed path and is deliberately
/// trivial: one atomic CAS plus a notify, nothing else (see `Drop`).
#[must_use = "dropping the admission closes the Pending session without committing it"]
pub struct PendingSessionAdmission<'registry, H: RevocableMeshSession> {
    registry: &'registry MeshSessionRegistry<H>,
    session_id: SessionId,
    /// The only binding field the permit still needs: which `by_machine`
    /// bucket to clean up. Everything else the old `PendingBinding` carried
    /// existed solely to re-run the roster checks after the Ack, which the
    /// terminal rule now forbids (round D-1 bounded admission, D1) — so
    /// keeping it would be keeping evidence for a decision that is no
    /// longer allowed to be made.
    m_id: MachineId,
    sync: Arc<SessionSync>,
    generation: u64,
    completed: bool,
}

impl<'registry, H: RevocableMeshSession> PendingSessionAdmission<'registry, H> {
    /// The terminal post-Ack transition (round D-1 bounded admission,
    /// @kiana audit `caf6d1e4`, D1). Call it as the immediate next
    /// statement after the `write_all` that completed the `ActivateAck`.
    ///
    /// **Infallible on purpose — there is no `Result` and no deadline.**
    /// Once the final syscall wrote every byte of the Ack, the peer holds
    /// it; a local refusal at that point would leave the peer believing the
    /// session is Active while we deny it. So this method performs no
    /// roster/revision/membership/handle/generation recheck, takes no
    /// registry lock, calls nothing on `H`, and is not vetoed by an
    /// already-announced revoke.
    ///
    /// Safety of that is not a promise, it is a mechanism: a revoke that
    /// announced during the Ack window has `writer_intent > 0`, and
    /// [`SessionSync::try_enter`] rejects on that counter *before* it looks
    /// at the phase. So the interval between `Pending -> Active` here and
    /// the revoker's `Active -> Closed` admits no forwarding at all. The
    /// Ack is honoured locally and the session is closed immediately after,
    /// which is precisely what the protocol asks for.
    pub fn commit_after_ack(mut self) -> ActiveSessionRegistration<'registry, H> {
        // `false` means the phase had already left Pending. Unreachable
        // while this permit exists (only cancel/Drop close a Pending
        // session, and both consume `self`) and fail-closed if it ever
        // happened: the phase stays Closed, so the returned registration
        // authorizes nothing and its own Drop retires it.
        let _committed = self.sync.commit_after_ack();
        self.completed = true;
        ActiveSessionRegistration {
            registry: self.registry,
            session_id: self.session_id,
            gate: SessionGate {
                sync: Arc::clone(&self.sync),
                registry_live: Arc::clone(&self.registry.registry_live),
                generation: self.generation,
                current_generation: Arc::clone(&self.registry.generation),
            },
            retired: false,
        }
    }

    /// The partial-write/failure path (D3). Closes authority **first**, with
    /// an atomic CAS that needs no lock, then makes exactly one non-blocking
    /// attempt at bookkeeping.
    ///
    /// Cancellation never needs time to be correct: closure is immediate and
    /// unconditional, and only the map cleanup can be deferred. That turns
    /// "the ceremony deadline expired while cancelling" from an
    /// authorization ambiguity into bounded bookkeeping debt.
    #[must_use]
    pub fn cancel_before_ack(mut self) -> PendingCancelOutcome {
        self.completed = true;
        self.sync.close_if_pending();
        self.registry
            .try_remove_closed_pending(self.session_id, &self.sync, &self.m_id)
    }
}

impl<H: RevocableMeshSession> Drop for PendingSessionAdmission<'_, H> {
    /// Idempotent atomic close and nothing else (D3).
    ///
    /// It must not acquire `inner`, must not acquire `state`, must not wait,
    /// must not upgrade the `Weak<H>`, must not call `close`/notice/any
    /// callback, and must not allocate. Everything that could block or
    /// re-enter is therefore structurally absent — which is what lets this
    /// run safely from a panic unwind, and while both mutexes are held by
    /// other threads.
    ///
    /// The bookkeeping entry it leaves behind is reconcilable debt, not an
    /// authority gap: phase `Closed` means `try_enter` refuses forever.
    fn drop(&mut self) {
        if !self.completed {
            self.sync.close_if_pending();
        }
    }
}

/// RAII ownership of one Active session (round D-1 bounded admission, D5).
///
/// Returned by [`PendingSessionAdmission::commit_after_ack`] instead of a
/// bare `(SessionId, SessionGate)` pair, because handing out the raw
/// [`SessionGate`] hands out a `Clone`able authorization that can outlive
/// any single owner. This wrapper is not `Clone`, keeps its fields private,
/// and exposes forwarding only through a guard.
///
/// Its `Drop` retires the session through the callback-free
/// [`retire_locally`](MeshSessionRegistry::retire_locally) — never
/// `unregister`, because protocol CLOSE/notice is external I/O that must
/// not run from a destructor. An explicit, non-`Drop` close operation is the
/// runtime's job.
#[must_use = "dropping this retires the session"]
pub struct ActiveSessionRegistration<'registry, H: RevocableMeshSession> {
    registry: &'registry MeshSessionRegistry<H>,
    session_id: SessionId,
    gate: SessionGate,
    retired: bool,
}

impl<H: RevocableMeshSession> ActiveSessionRegistration<'_, H> {
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The only forwarding surface. Hold the returned guard for exactly the
    /// duration of the forward it authorizes — see [`ForwardingGuard`].
    /// Deliberately mirrors `SessionGate::try_authorize_forwarding` rather
    /// than exposing the gate itself.
    #[must_use]
    pub fn try_authorize_forwarding(&self) -> Option<ForwardingGuard<'_>> {
        self.gate.try_authorize_forwarding()
    }

    /// Retires explicitly, consuming the wrapper, and reports which
    /// guarantee the caller actually got. Same callback-free path as `Drop`;
    /// this exists so a caller that cares can observe
    /// [`RetireOutcome`] instead of discarding it.
    #[must_use]
    pub fn retire(mut self) -> RetireOutcome {
        self.retired = true;
        self.registry.retire_locally(self.session_id)
    }

    /// Test-only: defuses the `Drop` and yields the raw parts, so this
    /// module's pre-existing tests can keep asserting on a `SessionGate`
    /// directly. Absent from production builds, where handing out a
    /// clonable gate is exactly what this wrapper exists to prevent.
    #[cfg(test)]
    fn disarm_into_parts(mut self) -> (SessionId, SessionGate) {
        self.retired = true;
        (self.session_id, self.gate.clone())
    }
}

impl<H: RevocableMeshSession> Drop for ActiveSessionRegistration<'_, H> {
    fn drop(&mut self) {
        if !self.retired {
            // Callback-free by construction, and its `RetireOutcome` is
            // deliberately discarded: a one-owner wrapper's `Drop` has
            // nothing to decide, and `writer_intent`/`registry_live` have
            // already fail-closed by the time it could look.
            let _ = self.registry.retire_locally(self.session_id);
        }
    }
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

impl<H: RevocableMeshSession> SessionEntry<H> {
    /// Lifecycle is DERIVED from the shared phase, never stored a second
    /// time here (round D-1 bounded admission, @kiana audit `caf6d1e4`).
    /// The previous `lifecycle: SessionLifecycle` field was a second
    /// mutable copy of the same fact, updated under `inner` while the real
    /// transition happened under `state` — two owners of one truth, free to
    /// disagree. There is now exactly one.
    fn phase(&self) -> u8 {
        self.sync.phase()
    }
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

/// Tracks Pending and Active sessions by the `MachineId` of their peer and
/// revokes them when the roster observes that machine has since been
/// revoked, dropped, or re-certified. `Weak`, not `Arc`: the registry does
/// not keep a session alive — a session whose last strong owner already
/// dropped it is pruned rather than kept alive artificially by this
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
    /// `Default`/empty construction, so `try_preauthorize_before` can never
    /// run before any roster state has been observed.
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

    /// Performs the final exact D-1 recheck and inserts a tracked Pending
    /// session whose forwarding gate is closed. The returned opaque permit
    /// is the only production route to Active; hold it across exactly one
    /// Ack write and then consume it with
    /// [`PendingSessionAdmission::commit_after_ack`].
    ///
    /// **Never waits** (round D-1 bounded admission, @kiana audit
    /// `caf6d1e4`, D2). Uses `Mutex::try_lock`, so household holds no
    /// ceremony policy of its own: `Busy` simply means "not now", with no
    /// effect whatsoever on registry state, and the runtime adapter owns
    /// the backoff loop against its single monotonic `CeremonyDeadline`.
    ///
    /// `deadline_at` is re-read **inside** the acquired critical section,
    /// before any mutation and before a `SessionId` is consumed, closing
    /// the check-to-insert gap an adapter-side check alone would leave. A
    /// caller callback under `inner` was rejected as the alternative: it
    /// could block or re-enter the registry.
    ///
    /// Every refusal here leaves the registry exactly as it was — all
    /// mutation happens after every check, so "reserve fails without
    /// inserting" is structural rather than defended.
    pub fn try_preauthorize_before(
        &self,
        binding: &SealedBinding,
        handle: Weak<H>,
        deadline_at: Instant,
    ) -> Result<PendingSessionAdmission<'_, H>, TryPreauthorizeError> {
        let mut guard = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Err(TryPreauthorizeError::Busy),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.registry_live.store(false, Ordering::SeqCst);
                return Err(TryPreauthorizeError::Poisoned);
            }
        };
        let _poison_guard = PoisonGuard::new(&self.registry_live);
        // Inside the lock, before anything is mutated or allocated.
        if Instant::now() >= deadline_at {
            return Err(TryPreauthorizeError::Expired);
        }
        self.preauthorize_locked(&mut guard, binding, handle)
            .map_err(TryPreauthorizeError::Refused)
    }

    /// The exact D-1 admission checks plus the Pending insert, factored out
    /// so both the bounded production entry point above and this module's
    /// test helper run byte-identical logic.
    fn preauthorize_locked<'a>(
        &'a self,
        guard: &mut std::sync::MutexGuard<'_, Inner<H>>,
        binding: &SealedBinding,
        handle: Weak<H>,
    ) -> Result<PendingSessionAdmission<'a, H>, RegisterRefusal> {
        let Inner {
            hh_id,
            last_known_revision,
            next_session_id,
            mode,
        } = &mut **guard;
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
        // The LAST fallible step, computed before anything is mutated —
        // `checked_add` only reads (round D-1 bounded admission, @kiana
        // recheck of `28c5e992`). Sequencing this ahead of the sweep is
        // what keeps "a refusal changes nothing" true without exception:
        // with the sweep first, an exhausted id space would have returned a
        // refusal that had already mutated the map, quietly contradicting
        // the contract documented right below.
        let id = next_session_id
            .checked_add(1)
            .ok_or(RegisterRefusal::SessionIdSpaceExhausted)?;
        // Every SUCCESSFUL reserve — and only a successful one — pays down
        // the deferred-cancel debt (@kiana recheck of `d721f889`).
        //
        // Placement is exact and load-bearing in both directions. AFTER
        // every fallible check, including the id-space one above, so a
        // refusal leaves the registry bit-for-bit unchanged and "reserve
        // fails without inserting" stays structural. BEFORE the insert, so
        // the sweep shares the critical section that grows the map.
        //
        // Without this, the reconcile claim was stronger than the
        // mechanism: `prune_closed_locked` ran only in
        // `reconcile_closed_pending`, `registered_count_inner` and the
        // Advance branch, so a peer could cancel under a busy `inner` and
        // then issue nothing but successful reserves, growing Closed
        // entries without bound — each with a live `Weak`, so the
        // dead-handle prune would never have reclaimed them either.
        prune_closed_locked(sessions, by_machine);
        *next_session_id = id;
        let session_id = SessionId(id);
        let sync = SessionSync::new_pending();
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
        Ok(PendingSessionAdmission {
            registry: self,
            session_id,
            m_id: binding.m_id().clone(),
            sync,
            generation: self.generation.load(Ordering::SeqCst),
            completed: false,
        })
    }

    /// Test-only blocking reserve: spins on the non-blocking production
    /// entry point until it stops returning `Busy`. Production deliberately
    /// has no blocking reserve at all (D2) — the ceremony-deadline backoff
    /// belongs to the runtime adapter, not to household.
    #[cfg(test)]
    fn preauthorize(
        &self,
        binding: &SealedBinding,
        handle: Weak<H>,
    ) -> Result<PendingSessionAdmission<'_, H>, RegisterRefusal> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.try_preauthorize_before(binding, handle.clone(), deadline) {
                Ok(admission) => return Ok(admission),
                Err(TryPreauthorizeError::Busy) => std::thread::yield_now(),
                Err(TryPreauthorizeError::Refused(refusal)) => return Err(refusal),
                Err(TryPreauthorizeError::Poisoned | TryPreauthorizeError::Expired) => {
                    return Err(RegisterRefusal::RegistryUnavailable);
                }
            }
        }
    }

    /// Compatibility helper for this module's pre-existing tests: reserve
    /// then immediately commit, with no Ack in between. It is deliberately
    /// absent from production builds — making an immediately Active session
    /// without an Ack boundary would be an authorization bypass for D-9.
    ///
    /// Spins on `try_preauthorize_before` rather than blocking, because the
    /// production surface no longer offers a blocking reserve at all (D2).
    #[cfg(test)]
    fn register(
        &self,
        binding: &SealedBinding,
        handle: Weak<H>,
    ) -> Result<(SessionId, SessionGate), RegisterRefusal> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.try_preauthorize_before(binding, handle.clone(), deadline) {
                Ok(admission) => return Ok(admission.commit_after_ack().disarm_into_parts()),
                Err(TryPreauthorizeError::Busy) => std::thread::yield_now(),
                Err(TryPreauthorizeError::Refused(refusal)) => return Err(refusal),
                Err(TryPreauthorizeError::Poisoned | TryPreauthorizeError::Expired) => {
                    return Err(RegisterRefusal::RegistryUnavailable);
                }
            }
        }
    }

    /// Bookkeeping half of [`PendingSessionAdmission::cancel_before_ack`]
    /// and of the Pending `Drop` (round D-1 bounded admission, @kiana audit
    /// `caf6d1e4`, D3).
    ///
    /// **Authority is NOT closed here** — the caller has already done that
    /// with an atomic phase CAS before calling, which is what makes closure
    /// independent of every lock in this file. This only tries, exactly
    /// once, to remove the now-Closed entry from the tracking maps. On
    /// contention or poison it reports the debt instead of pretending, and
    /// a later registry operation or an explicit
    /// [`reconcile_closed_pending`](Self::reconcile_closed_pending) sweeps
    /// it up.
    ///
    /// Never calls into `H`. The previous `abort_pending` called
    /// `handle.close()` here, which put external protocol I/O on the
    /// Pending `Drop` path — the exact hazard `retire_locally` was built to
    /// avoid on the Active side.
    fn try_remove_closed_pending(
        &self,
        session_id: SessionId,
        sync: &Arc<SessionSync>,
        m_id: &MachineId,
    ) -> PendingCancelOutcome {
        let mut guard = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                return PendingCancelOutcome::ClosedCleanupDeferred;
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.registry_live.store(false, Ordering::SeqCst);
                return PendingCancelOutcome::RegistryUnavailable;
            }
        };
        let _poison_guard = PoisonGuard::new(&self.registry_live);
        let Mode::Live {
            sessions,
            by_machine,
        } = &mut guard.mode
        else {
            return PendingCancelOutcome::RegistryUnavailable;
        };
        // Identity, not just id: a `SessionId` is never reused, but
        // comparing the `Arc` too makes "remove the entry I closed" a
        // provable statement rather than a positional one.
        let is_mine = sessions
            .get(&session_id)
            .is_some_and(|entry| Arc::ptr_eq(&entry.sync, sync));
        if !is_mine {
            return PendingCancelOutcome::ClosedAndRemoved;
        }
        sessions.remove(&session_id);
        if let Some(ids) = by_machine.get_mut(m_id) {
            ids.retain(|id| *id != session_id);
            if ids.is_empty() {
                by_machine.remove(m_id);
            }
        }
        PendingCancelOutcome::ClosedAndRemoved
    }

    /// Opportunistic sweep of entries whose phase is already `Closed`
    /// (round D-1 bounded admission, D4). Never blocks and never calls into
    /// `H`; a `Busy` registry simply means the debt survives to the next
    /// caller. Every other method that already holds `inner` performs the
    /// same sweep inline, so an adapter that never calls this still
    /// converges.
    pub fn reconcile_closed_pending(&self) -> ReconcileOutcome {
        let mut guard = match self.inner.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return ReconcileOutcome::Busy,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                self.registry_live.store(false, Ordering::SeqCst);
                return ReconcileOutcome::RegistryUnavailable;
            }
        };
        let _poison_guard = PoisonGuard::new(&self.registry_live);
        let Mode::Live {
            sessions,
            by_machine,
        } = &mut guard.mode
        else {
            return ReconcileOutcome::RegistryUnavailable;
        };
        let removed = prune_closed_locked(sessions, by_machine);
        ReconcileOutcome::Swept { removed }
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
        self.unregister_inner(session_id, || {});
    }

    /// Test-only seam (round D-1 successor, @kiana second recheck): runs
    /// `after_unlock_before_drain` at the exact point between the
    /// bookkeeping-removal lock releasing and the (possibly blocking)
    /// drain starting — see
    /// `unregister_announces_before_absence_is_externally_observable`.
    #[cfg(test)]
    pub(crate) fn unregister_with_hook_for_test(
        &self,
        session_id: SessionId,
        after_unlock_before_drain: impl FnOnce(),
    ) {
        self.unregister_inner(session_id, after_unlock_before_drain);
    }

    fn unregister_inner(&self, session_id: SessionId, after_unlock_before_drain: impl FnOnce()) {
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
                    // Round D-1 successor (@kiana second recheck): announce
                    // BEFORE this session's absence becomes externally
                    // observable — i.e. before this lock releases, not
                    // merely before the (unlocked, possibly slow) drain
                    // below. Without this, `registered_count`/
                    // `is_registered` for `entry.m_id` could already report
                    // this session gone the instant the lock below
                    // releases, while a `SessionGate` cloned before this
                    // call still obtains a `ForwardingGuard`, since nothing
                    // had announced revoke intent to its `SessionSync` yet.
                    // Lock-free, cannot block — see `SessionSync`'s doc
                    // comment.
                    entry.sync.announce_revoke();
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
        after_unlock_before_drain();
        // Unlocked (round 4): may block waiting out an in-flight
        // ForwardingGuard, same as every other revoke path in this file —
        // never while `self.inner`'s lock is held. Announce already ran
        // above, under the lock; only the (possibly blocking) drain
        // remains.
        entry.sync.drain_after_announce();
        if let Some(handle) = entry.handle.upgrade() {
            handle.send_best_effort_revoke_notice();
            handle.close();
        }
    }

    /// Callback-free local retirement — the `Drop`-safe counterpart to
    /// [`unregister`](Self::unregister) (round D-1 successor, @kiana, from
    /// the D-9 runtime-facade audit).
    ///
    /// Does exactly what `unregister` does to THIS registry's own state:
    /// removes `session_id` from `sessions`/`by_machine`, announces revoke
    /// intent under `self.inner`'s lock (before the removal is externally
    /// observable — see [`announce_revoke`](SessionSync::announce_revoke)),
    /// and drains any in-flight [`ForwardingGuard`] after releasing it.
    ///
    /// **The completion half of the guarantee is scoped to the caller that
    /// actually removed the entry** (round D-1 successor, @kiana — the
    /// first cut claimed it unconditionally, which is too strong). Only
    /// [`RetireOutcome::RetiredAndDrained`] means "on return, no forward
    /// that was in flight is still running". Two concurrent
    /// `retire_locally` calls for the same `SessionId` are the case that
    /// breaks the unconditional claim: the loser finds the entry already
    /// gone and returns [`NotTracked`](RetireOutcome::NotTracked)
    /// immediately, while the WINNER may still be draining. Authority is
    /// closed either way — the winner's `announce_revoke` landed under the
    /// lock, strictly before the removal the loser observed — so nothing
    /// can newly authorize; it is specifically the "already in flight has
    /// finished" part that a `NotTracked` caller must not assume.
    ///
    /// The official one-owner facade wrapper never produces this race, and
    /// its `Drop` may ignore the outcome outright: `writer_intent` and
    /// `registry_live` have already fail-closed by then, so there is
    /// nothing for a `Drop` to decide. The explicit path, which can care
    /// whether it was the one that drained, is free to observe it. Hence
    /// no `#[must_use]`.
    ///
    /// What it deliberately does NOT do: it never calls
    /// [`send_best_effort_revoke_notice`](RevocableMeshSession::send_best_effort_revoke_notice),
    /// never calls [`close`](RevocableMeshSession::close), and never calls
    /// ANY other method of `H` — it does not even `upgrade()` the `Weak<H>`.
    /// That is the whole point: a runtime facade that owns an Active session
    /// needs a fail-closed `Drop`, and `unregister`'s notice/close are
    /// external protocol I/O — a blocking, fallible, possibly-reentrant
    /// callback into `H`, which is exactly what must not run from a `Drop`
    /// (including a `Drop` during panic unwind). Dropping the removed
    /// `SessionEntry` here cannot reach `H` either: the entry holds a
    /// `Weak<H>`, and dropping a `Weak` never runs `H`'s destructor.
    ///
    /// Use [`unregister`](Self::unregister) for the ordinary explicit path,
    /// where telling the peer is wanted. Use this one when local authority
    /// must be given up unconditionally and telling the peer is either
    /// impossible, unsafe, or someone else's job.
    ///
    /// **Poison, stated honestly:** if `self.inner` is poisoned this sets
    /// `registry_live = false` and returns
    /// [`RegistryUnavailable`](RetireOutcome::RegistryUnavailable). That
    /// denies every outstanding `SessionGate` on this registry, including
    /// this session's, so no authority survives — but it is NOT the same
    /// guarantee as the normal path: the poisoned interior cannot be
    /// reached to find this entry, so nothing can announce or drain its
    /// `SessionSync`, and a forward already in flight is therefore NOT
    /// waited out. Fail-closed on authorization, not on completion. Same
    /// asymmetry [`SessionSync`]'s doc comment draws for `try_enter` vs
    /// draining, and the same one every other method here has in the poison
    /// case.
    pub fn retire_locally(&self, session_id: SessionId) -> RetireOutcome {
        self.retire_locally_inner(session_id, || {})
    }

    /// Test-only seam (same technique as
    /// [`unregister_with_hook_for_test`](Self::unregister_with_hook_for_test)):
    /// runs `after_unlock_before_drain` exactly between the
    /// bookkeeping-removal lock releasing and the drain starting.
    #[cfg(test)]
    pub(crate) fn retire_locally_with_hook_for_test(
        &self,
        session_id: SessionId,
        after_unlock_before_drain: impl FnOnce(),
    ) -> RetireOutcome {
        self.retire_locally_inner(session_id, after_unlock_before_drain)
    }

    fn retire_locally_inner(
        &self,
        session_id: SessionId,
        after_unlock_before_drain: impl FnOnce(),
    ) -> RetireOutcome {
        // Only the `Arc<SessionSync>` escapes this block — deliberately NOT
        // the whole `SessionEntry`, so there is no `Weak<H>` in scope below
        // that a later edit could be tempted to `upgrade()`. "No callback
        // into H" is thereby a property of what this function can still
        // reach, not only of what it currently writes.
        let sync = {
            let Ok(mut guard) = self.inner.lock() else {
                self.registry_live.store(false, Ordering::SeqCst);
                return RetireOutcome::RegistryUnavailable;
            };
            let _poison_guard = PoisonGuard::new(&self.registry_live);
            let Mode::Live {
                sessions,
                by_machine,
            } = &mut guard.mode
            else {
                return RetireOutcome::RegistryUnavailable;
            };
            let removed = sessions.remove(&session_id);
            if let Some(entry) = &removed {
                // Before the removal below makes this session's absence
                // externally observable — identical ordering to
                // `unregister_inner`, for identical reasons.
                entry.sync.announce_revoke();
                if let Some(ids) = by_machine.get_mut(&entry.m_id) {
                    ids.retain(|id| *id != session_id);
                    if ids.is_empty() {
                        by_machine.remove(&entry.m_id);
                    }
                }
            }
            removed.map(|entry| entry.sync)
        };
        // Already absent when this call reached the lock: this call
        // announced nothing and drains nothing, so it cannot claim the
        // completion half of the guarantee — a concurrent winner may still
        // be draining right now. See `retire_locally`'s doc comment.
        let Some(sync) = sync else {
            return RetireOutcome::NotTracked;
        };
        after_unlock_before_drain();
        // Unlocked: may block waiting out an in-flight ForwardingGuard.
        sync.drain_after_announce();
        RetireOutcome::RetiredAndDrained
    }

    /// True if at least one still-live (upgradable) **Active** session is
    /// registered for `m_id`. Pending entries stay tracked for revocation
    /// but are deliberately not counted as registered/forwardable. Prunes
    /// any dead `Weak` entries for `m_id` it finds along the way (round 3,
    /// point b) — a read can observe and clean up staleness without waiting
    /// for the next checkpoint to do it.
    #[must_use]
    pub fn is_registered(&self, m_id: &MachineId) -> bool {
        self.registered_count(m_id) > 0
    }

    /// Count of still-live (upgradable) Active sessions registered for
    /// `m_id`. Same pruning behavior as `is_registered`; Pending entries
    /// are tracked but not included.
    #[must_use]
    pub fn registered_count(&self, m_id: &MachineId) -> usize {
        self.registered_count_inner(m_id, || {})
    }

    /// Test-only seam (round D-1 successor, @kiana second recheck): runs
    /// `after_unlock_before_drain` at the exact point between the
    /// dead-Weak-prune lock releasing and the (possibly blocking) drain
    /// starting — see
    /// `registered_count_prune_announces_before_absence_is_externally_observable`.
    #[cfg(test)]
    pub(crate) fn registered_count_with_hook_for_test(
        &self,
        m_id: &MachineId,
        after_unlock_before_drain: impl FnOnce(),
    ) -> usize {
        self.registered_count_inner(m_id, after_unlock_before_drain)
    }

    fn registered_count_inner(
        &self,
        m_id: &MachineId,
        after_unlock_before_drain: impl FnOnce(),
    ) -> usize {
        let mut dead: Vec<Arc<SessionSync>> = Vec::new();
        let count = {
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
            // Opportunistic sweep (D4): any path that already holds `inner`
            // pays down the cleanup debt a deferred cancel left behind, so
            // convergence never depends on the runtime remembering to call
            // `reconcile_closed_pending`.
            prune_closed_locked(sessions, by_machine);
            let Some(ids) = by_machine.get_mut(m_id) else {
                return 0;
            };
            ids.retain(|id| {
                let alive = sessions
                    .get(id)
                    .is_some_and(|entry| entry.handle.strong_count() > 0);
                if !alive {
                    if let Some(entry) = sessions.remove(id) {
                        // Round D-1 successor (@kiana second recheck):
                        // announce BEFORE this prune's absence becomes
                        // externally observable — i.e. before this lock
                        // releases, not merely before the unlocked drain
                        // below. Without this, `count` (and any sibling
                        // `registered_count`/`is_registered` call for this
                        // `m_id`) already reflects the removal the instant
                        // this lock releases, while a `SessionGate` cloned
                        // before this call still obtains a
                        // `ForwardingGuard`. Lock-free, cannot block.
                        entry.sync.announce_revoke();
                        dead.push(entry.sync);
                    }
                }
                alive
            });
            let count = ids
                .iter()
                .filter(|id| {
                    sessions
                        .get(id)
                        .is_some_and(|entry| entry.phase() == PHASE_ACTIVE)
                })
                .count();
            if ids.is_empty() {
                by_machine.remove(m_id);
            }
            count
        };
        // Round D-1 successor (@kiana P0-2, sharpened by a second recheck):
        // a dead Weak's bookkeeping removal must not leave any
        // `SessionGate` clone taken for it earlier still reading authorized
        // — `try_authorize_forwarding` does not consult `handle`/
        // `strong_count` at all, only `sync`/`registry_live`/`generation`,
        // so dropping the entry here without revoking its `SessionSync`
        // would make that clone permanently authorized and permanently
        // unreachable by any future observation (this session is no longer
        // in `sessions`/`by_machine`). `announce_revoke` already ran above,
        // under the lock — only the (possibly blocking) drain, unlocked,
        // after `guard` above has already been dropped.
        after_unlock_before_drain();
        drain_batch(dead.iter());
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
    /// Production entry point — always runs with an empty (no-op) hook. See
    /// [`observe_new_checkpoint_inner`](Self::observe_new_checkpoint_inner)
    /// for the actual logic.
    pub fn observe_new_checkpoint(&self, snapshot: &RosterSnapshotView) -> ObserveOutcome {
        self.observe_new_checkpoint_inner(snapshot, || {})
    }

    /// Test-only seam (round D-1 successor, @kiana recheck): runs
    /// `after_unlock_before_phase_b` at the exact point between `self.inner`'s
    /// lock releasing and Phase B starting, so a test can deterministically
    /// inspect what is externally observable in that window — see
    /// `advance_revocation_announces_before_the_new_revision_is_externally_observable`.
    /// Production code always goes through
    /// [`observe_new_checkpoint`](Self::observe_new_checkpoint), which
    /// passes an empty closure; this exists only so the hook never has to
    /// live on the struct itself or be threaded through every call site.
    #[cfg(test)]
    pub(crate) fn observe_new_checkpoint_with_hook_for_test(
        &self,
        snapshot: &RosterSnapshotView,
        after_unlock_before_phase_b: impl FnOnce(),
    ) -> ObserveOutcome {
        self.observe_new_checkpoint_inner(snapshot, after_unlock_before_phase_b)
    }

    fn observe_new_checkpoint_inner(
        &self,
        snapshot: &RosterSnapshotView,
        after_unlock_before_phase_b: impl FnOnce(),
    ) -> ObserveOutcome {
        // Phase A (short registry-mutex critical section): decide, mutate
        // registry-owned bookkeeping, and collect which sessions need
        // revoking -- but do NOT call SessionSync::drain_after_announce()
        // (blocking) on any of them yet. Draining can block, waiting out an
        // in-flight ForwardingGuard; calling it here, still holding
        // `self.inner`'s lock, would block every unrelated
        // register/unregister/observe on this registry for as long as that
        // one forward takes (round 4). `announce_revoke` (lock-free, never
        // blocks) DOES run before this block ends — see the round D-1
        // successor comment right before Phase B below for why that part
        // cannot wait for Phase B.
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
                    let mut collected: Vec<(SessionId, Arc<SessionSync>, Weak<H>)> = to_revoke_ids
                        .iter()
                        .map(|id| {
                            let entry = &sessions[id];
                            (*id, Arc::clone(&entry.sync), entry.handle.clone())
                        })
                        .collect();

                    // Bookkeeping-only prune (upgrade()/strong_count()
                    // only, no blocking I/O) for any remaining handle, NOT
                    // one of this round's to_revoke_ids, whose last Arc
                    // already dropped elsewhere. Round D-1 successor
                    // (@kiana — same root cause as P0-2): a naturally-dead
                    // handle's `SessionSync` must still be revoked, not
                    // merely dropped from tracking, or a `SessionGate`
                    // clone taken for it earlier keeps reading authorized
                    // forever with no future observation able to reach it
                    // (it is no longer in `sessions`/`by_machine` at all).
                    // Folded into the SAME `collected` batch as the
                    // roster-driven revocations above so Phase B's
                    // `revoke_batch` announces intent to everything
                    // (roster-driven AND naturally-dead) in one pass —
                    // to_revoke_ids entries are skipped here and left for
                    // Phase C, which removes those once their
                    // `SessionSync::revoke()` has actually run.
                    // Opportunistic sweep (D4), same rationale as
                    // `registered_count_inner`'s: this path already holds
                    // `inner`, so it pays down any deferred-cancel debt for
                    // free. Runs before the dead-handle prune below because
                    // a Closed entry needs no announce — its phase already
                    // denies everything.
                    prune_closed_locked(sessions, by_machine);
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
                                    if let Some(entry) = sessions.remove(id) {
                                        collected.push((*id, entry.sync, entry.handle));
                                    }
                                }
                                alive
                            });
                            if ids.is_empty() {
                                by_machine.remove(&m_id);
                            }
                        }
                    }
                    to_revoke = collected;
                    guard.last_known_revision = new_revision;
                    outcome = ObserveOutcome::Applied;
                }
            }

            // Round D-1 successor (@kiana recheck, on top of P0-1): must run
            // HERE, still holding `self.inner`'s lock -- not merely before
            // Phase B starts draining a sibling target (P0-1's own fix,
            // still correct and still needed on its own). The Advance branch
            // above just published `guard.last_known_revision` as the new
            // truth; the instant this lock releases, any OTHER caller
            // (e.g. a concurrent `try_preauthorize_before` for an unrelated
            // machine)
            // can already see and act on it. `announce_revoke` is the ONLY
            // thing that makes a revoked target's gate stop admitting new
            // forwarding, and it is lock-free/non-blocking (a single atomic
            // increment per target — see `SessionSync`'s doc comment), so
            // running it here cannot introduce the very blocking-under-lock
            // problem Phase A's split from Phase B exists to avoid. Without
            // this, a revoked session's gate would remain fully authorized
            // during the (however brief) window between this lock releasing
            // and Phase B's own announce actually executing — breaking the
            // linearization-point contract this method documents itself as
            // providing (module doc comment, CFX-5): the roster's own
            // truth and this registry's per-session authorization would be
            // observably out of sync. Empty for every branch except
            // Advance/Fork-Regression; a no-op loop otherwise.
            announce_batch(to_revoke.iter().map(|(_, sync, _)| sync));
        }

        after_unlock_before_phase_b();

        // Phase B (unlocked): drain each already-announced target. Announcing
        // already happened above, for EVERY collected target, before this
        // lock released — so there is no window, at any granularity, where
        // an external caller could observe the new revision as truth while
        // any of these gates was still admitting new forwarding. All without
        // holding `self.inner`'s lock here, so unrelated registry operations
        // are never blocked by a slow forward (round 4).
        drain_batch(to_revoke.iter().map(|(_, sync, _)| sync));

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
        // Round D-1 successor (@kiana P0-1): same batch-announce-then-drain
        // discipline as `observe_new_checkpoint`'s Phase B — see
        // `revoke_batch`'s doc comment.
        revoke_batch(to_revoke.iter().map(|(_, sync, _)| sync));
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

    /// Test-only contention seam: runs `f` while `inner` is held.
    ///
    /// Deterministic without threads, because `Mutex::try_lock` returns
    /// `WouldBlock` rather than deadlocking when the same thread already
    /// holds the lock — so a `try_*` call issued from inside `f` takes the
    /// contended branch with certainty, not with luck.
    #[cfg(test)]
    fn hold_inner_while<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self.inner.lock().unwrap();
        f()
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

/// Round D-1 successor (@kiana P0-1): revoking several sessions collected
/// in one registry-wide decision (a batch fork/regression close, an
/// `Advance` that tombstones/drops multiple machines at once, or
/// `mark_unavailable`) must announce writer intent to EVERY target BEFORE
/// draining ANY of them. `SessionSync::revoke()` called one target at a
/// time in a plain loop does not do that: `writer_intent` lives on each
/// individual `SessionSync`, so a later target's phase stays `Active` — and
/// can still admit a BRAND NEW `ForwardingGuard` — for the entire time an
/// earlier target's drain is in flight, even though the very same decision
/// already condemned it. `announce_revoke` is a lock-free atomic
/// increment, so the first loop below cannot itself be delayed by a slow
/// drain elsewhere in the batch; every target has stopped admitting new
/// readers before the second loop starts draining any of them.
fn revoke_batch<'a>(targets: impl Iterator<Item = &'a Arc<SessionSync>> + Clone) {
    announce_batch(targets.clone());
    drain_batch(targets);
}

/// Phase 1 of [`revoke_batch`], split out (round D-1 successor, @kiana
/// recheck) so a caller that itself already holds a coarser lock guarding
/// the decision being published can announce BEFORE releasing that lock —
/// see `observe_new_checkpoint`'s Advance branch, and that method's own
/// comment for exactly why lock-release-before-announce is its own,
/// narrower race than the one `revoke_batch` alone closes.
fn announce_batch<'a>(targets: impl Iterator<Item = &'a Arc<SessionSync>>) {
    for sync in targets {
        sync.announce_revoke();
    }
}

/// Phase 2 of [`revoke_batch`] — MUST be preceded by exactly one
/// [`announce_batch`] over the SAME targets.
fn drain_batch<'a>(targets: impl Iterator<Item = &'a Arc<SessionSync>>) {
    for sync in targets {
        sync.drain_after_announce();
    }
}

/// Removes every entry whose phase is already `Closed` (round D-1 bounded
/// admission, @kiana audit `caf6d1e4`, D4). Cheap, allocation-light, and
/// called from every path that both holds `inner` and can grow or inspect
/// the maps — `reconcile_closed_pending`, `registered_count_inner`, the
/// `Advance` branch, and (since @kiana's recheck of `d721f889`)
/// `preauthorize_locked` — so a cancel that had to defer its own cleanup
/// converges without a queue, a worker thread, or an explicit reconcile
/// call from the runtime.
///
/// The reserve call site is what makes that claim true rather than
/// aspirational: it is the one path an adversary can drive indefinitely
/// while touching nothing else.
///
/// Deliberately keyed on PHASE, not on `handle.strong_count()`. A cancelled
/// Pending session can keep a perfectly live `Weak<H>` — the runtime may
/// still own its `Arc<H>` — so the pre-existing dead-handle prune would
/// never have reclaimed it.
fn prune_closed_locked<H: RevocableMeshSession>(
    sessions: &mut HashMap<SessionId, SessionEntry<H>>,
    by_machine: &mut HashMap<MachineId, Vec<SessionId>>,
) -> usize {
    let closed: Vec<(SessionId, MachineId)> = sessions
        .iter()
        .filter(|(_, entry)| entry.phase() == PHASE_CLOSED)
        .map(|(id, entry)| (*id, entry.m_id.clone()))
        .collect();
    for (id, m_id) in &closed {
        sessions.remove(id);
        if let Some(ids) = by_machine.get_mut(m_id) {
            ids.retain(|existing| existing != id);
            if ids.is_empty() {
                by_machine.remove(m_id);
            }
        }
    }
    closed.len()
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
mod tests;
