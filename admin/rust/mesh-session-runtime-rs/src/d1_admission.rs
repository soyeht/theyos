//! Real `D1Admission` + `ActiveGateAuthorization` over household-rs's
//! `MeshSessionRegistry` (Lane R, @daisy, design confirmed by @ilia
//! 2026-08-05 after independently re-verifying all three underlying
//! facts herself: no real `H: RevocableMeshSession` exists anywhere in
//! this workspace, `reserve_pending`'s signature carries no handle
//! parameter, and `try_preauthorize_before` requires one).
//!
//! Generic over `H: RevocableMeshSession` on purpose: the concrete
//! session-handle type, and whatever produces real `Weak<H>` handles, are
//! a different piece of this pipeline — not fabricated here, matching
//! `signer_seam.rs`'s own precedent ("building a seam for something that
//! doesn't exist yet would be fabricating the seam"). `handle` is
//! supplied at CONSTRUCTION, not inside `reserve_pending`'s call: the
//! trait's own signature has no handle parameter, and a fresh adapter is
//! expected to be built per session-admission attempt by whoever
//! initiates the handshake and already knows which session's handle this
//! is.
//!
//! `reserve_pending` composes three real, independently-owned pieces, in
//! order: (1) `MachineRosterCoordinator::current_snapshot` for a current
//! `RosterSnapshotView`; (2) `SealedBinding::from_membership_key`
//! (household-rs, feature `mesh-session-runtime`, already landed —
//! not duplicated here) to project the ceremony's `D1MembershipKey` into
//! the registry's own binding type; (3)
//! `MeshSessionRegistry::try_preauthorize_before`, retried locally against
//! `deadline` on `TryPreauthorizeError::Busy` — household's own doc says
//! the runtime adapter owns that backoff loop, not the registry.
//!
//! Every fallible step maps to its OWN `IntentError` variant
//! (`RosterSnapshotUnavailable` / `D1MembershipRejected` /
//! `D1RegistryUnavailable` / `DeadlineExceeded`) — snapshot-acquisition
//! failure is never folded into a membership rejection (@zain, explicit):
//! the first is a local/IO condition, the second is a genuine admission
//! decision, and collapsing them would hide which one happened from every
//! caller.

use std::sync::Weak;
use std::time::Instant;

use household_rs::machine_roster_authority::SealedBinding;
use household_rs::machine_roster_store::MachineRosterCoordinator;
use household_rs::mesh_session_registry::{
    ActiveSessionRegistration, ForwardingGuard, MeshSessionRegistry, PendingCancelOutcome,
    PendingSessionAdmission, RevocableMeshSession, TryPreauthorizeError,
};
use mesh_session_core_rs::auth_state_machine::ActiveGateAuthorization;
use mesh_session_core_rs::error::IntentError;
use mesh_session_core_rs::ingress::CeremonyDeadline;
use mesh_session_core_rs::intent::{D1Admission, D1CancelOutcome, D1MembershipKey, D1Pending};

/// Borrows a real, already-constructed registry and roster coordinator —
/// this crate never constructs either itself, same discipline as
/// `roster_bridge::HouseholdRosterSource`. `handle` is the `Weak<H>` this
/// specific admission attempt's session will need inside the registry.
pub struct RegistryD1Admission<'r, H: RevocableMeshSession> {
    registry: &'r MeshSessionRegistry<H>,
    roster: &'r MachineRosterCoordinator,
    handle: Weak<H>,
}

impl<'r, H: RevocableMeshSession> RegistryD1Admission<'r, H> {
    #[must_use]
    pub fn new(
        registry: &'r MeshSessionRegistry<H>,
        roster: &'r MachineRosterCoordinator,
        handle: Weak<H>,
    ) -> Self {
        Self {
            registry,
            roster,
            handle,
        }
    }
}

impl<H: RevocableMeshSession> D1Admission for RegistryD1Admission<'_, H> {
    type Pending<'a>
        = RegistryD1Pending<'a, H>
    where
        Self: 'a;
    type Active<'a>
        = RegistryActiveGate<'a, H>
    where
        Self: 'a;

    fn reserve_pending<'a>(
        &'a self,
        key: &D1MembershipKey,
        deadline: &CeremonyDeadline,
    ) -> Result<Self::Pending<'a>, IntentError> {
        let snapshot = self
            .roster
            .current_snapshot()
            .map_err(|_| IntentError::RosterSnapshotUnavailable)?;
        let binding = SealedBinding::from_membership_key(key, &snapshot)
            .map_err(|_| IntentError::D1MembershipRejected)?;

        retry_until_admitted(
            || {
                let deadline_at = Instant::now() + deadline.remaining();
                self.registry
                    .try_preauthorize_before(&binding, self.handle.clone(), deadline_at)
            },
            || deadline.is_expired(),
        )
        .map(RegistryD1Pending)
    }
}

/// The retry loop itself, inverted into a pure function over an `attempt`
/// closure and an `is_deadline_expired` closure (@ilia, 2026-08-05,
/// measured finding — this replaces an earlier version where the loop
/// lived directly in `reserve_pending` and was completely untested,
/// including its own termination): `attempt` stands in for one
/// `try_preauthorize_before` call, `is_deadline_expired` for
/// `deadline.is_expired()`. Neither closure needs a real
/// `MeshSessionRegistry` or `CeremonyDeadline` to construct in a test —
/// `CeremonyDeadline`'s own test-only constructors are `pub(crate)` to
/// mesh-session-core-rs and unreachable from here, so this was the only
/// way to exercise termination directly at all.
///
/// **Why this was more than a documentation gap:** household's own
/// registry returns `Busy` from `Mutex::try_lock`'s `WouldBlock` arm
/// BEFORE it ever reaches its internal `Instant::now() >= deadline_at`
/// check — that check only runs once the lock is actually acquired
/// (`mesh_session_registry.rs`, `try_preauthorize_before`). Under
/// sustained contention the registry can return `Busy` forever and NEVER
/// return `Expired`. This adapter's own `is_deadline_expired` check was
/// therefore not a redundant second guard — it was the ONLY thing that
/// could ever end the loop on that path. Untested, a future edit could
/// silently drop or miscompute it (as a stray `false` literal in place
/// of the real call once did, transiently, in this exact function) and
/// turn `Busy` under contention into an unbounded spin burning a core,
/// with `DeadlineExceeded` permanently unreachable.
fn retry_until_admitted<T>(
    mut attempt: impl FnMut() -> Result<T, TryPreauthorizeError>,
    mut is_deadline_expired: impl FnMut() -> bool,
) -> Result<T, IntentError> {
    loop {
        match attempt() {
            Ok(v) => return Ok(v),
            Err(err) => match map_preauthorize_error(err, is_deadline_expired()) {
                PreauthorizeAction::Retry => {
                    // household's own registry never waits internally
                    // (`try_lock` only) — the backoff loop is explicitly
                    // this adapter's job. A yield, not a sleep: the
                    // registry's lock is held only for in-memory
                    // HashMap/Vec mutation, never I/O, so the contended
                    // holder is expected back almost immediately.
                    std::thread::yield_now();
                }
                PreauthorizeAction::Fail(e) => return Err(e),
            },
        }
    }
}

/// What one `try_preauthorize_before` refusal decides for
/// `retry_until_admitted` above. Factored to a pure function so it is
/// directly testable against constructed `TryPreauthorizeError` values —
/// same discipline as `roster_bridge::map_currency_outcome`.
///
/// (@zain) The registry/coordinator calls in `reserve_pending` itself
/// remain untested by construction — their thinness is a property of
/// the current code, not an invariant. What moved `retry_until_admitted`
/// out of that same category (@ilia) is that a decision — the retry
/// loop's own termination condition — used to live only at that
/// untested call site; it does not anymore.
#[derive(Debug)]
enum PreauthorizeAction {
    Retry,
    Fail(IntentError),
}

fn map_preauthorize_error(err: TryPreauthorizeError, deadline_expired: bool) -> PreauthorizeAction {
    match err {
        TryPreauthorizeError::Busy if deadline_expired => {
            PreauthorizeAction::Fail(IntentError::DeadlineExceeded)
        }
        TryPreauthorizeError::Busy => PreauthorizeAction::Retry,
        TryPreauthorizeError::Expired => PreauthorizeAction::Fail(IntentError::DeadlineExceeded),
        TryPreauthorizeError::Poisoned => {
            PreauthorizeAction::Fail(IntentError::D1RegistryUnavailable)
        }
        // One flat class for every sub-reason (household mismatch,
        // revision mismatch, revoked, not active, handle already
        // dropped, session-id space exhausted) — including the
        // STALENESS case (RevisionMismatch), where this adapter's own
        // pre-check against a possibly-older snapshot passed but the
        // registry's internal recheck against its own, possibly more
        // advanced, tracked revision did not. See `IntentError::
        // D1MembershipRejected`'s own doc for why this is one class, not
        // a re-leaked household-rs taxonomy.
        TryPreauthorizeError::Refused(_) => {
            PreauthorizeAction::Fail(IntentError::D1MembershipRejected)
        }
    }
}

/// Pure mapping, same discipline as `map_preauthorize_error` above:
/// `PendingCancelOutcome` is a plain, `Copy`, publicly-constructible enum,
/// so this is directly testable without a live registry.
fn map_cancel_outcome(outcome: PendingCancelOutcome) -> D1CancelOutcome {
    match outcome {
        PendingCancelOutcome::ClosedAndRemoved => D1CancelOutcome::CancelledAndRemoved,
        PendingCancelOutcome::ClosedCleanupDeferred => {
            D1CancelOutcome::BarrierReleasedBookkeepingDeferred
        }
        PendingCancelOutcome::RegistryUnavailable => D1CancelOutcome::RegistryUnavailable,
    }
}

/// Wraps the real, opaque, `!Clone` two-phase permit. Deliberately no
/// fields beyond the household type itself — this adapter adds no state
/// of its own to what `PendingSessionAdmission` already tracks.
pub struct RegistryD1Pending<'r, H: RevocableMeshSession>(PendingSessionAdmission<'r, H>);

impl<'r, H: RevocableMeshSession> D1Pending<RegistryActiveGate<'r, H>>
    for RegistryD1Pending<'r, H>
{
    fn commit_after_ack(self) -> RegistryActiveGate<'r, H> {
        RegistryActiveGate(self.0.commit_after_ack())
    }

    fn cancel_before_ack(self) -> D1CancelOutcome {
        map_cancel_outcome(self.0.cancel_before_ack())
    }
}

/// Wraps the real RAII Active-session handle. `try_authorize` forwards
/// directly to `ActiveSessionRegistration::try_authorize_forwarding`,
/// which itself forwards to `SessionGate::try_authorize_forwarding` —
/// the exact production authorization surface
/// `ActiveGateAuthorization`'s own doc names.
pub struct RegistryActiveGate<'r, H: RevocableMeshSession>(ActiveSessionRegistration<'r, H>);

impl<H: RevocableMeshSession> ActiveGateAuthorization for RegistryActiveGate<'_, H> {
    type Guard<'a>
        = ForwardingGuard<'a>
    where
        Self: 'a;

    fn try_authorize(&self) -> Option<Self::Guard<'_>> {
        self.0.try_authorize_forwarding()
    }
}

#[cfg(test)]
mod tests {
    use household_rs::mesh_session_registry::RegisterRefusal;

    use super::*;

    // `MeshSessionRegistry`/`MachineRosterCoordinator` fixtures need a
    // full bootstrapped household (private fields, no test-support
    // constructor reachable from outside household-rs — confirmed:
    // `MachineRosterCoordinator`'s only public constructor,
    // `from_validated_household`, needs a validated `HouseholdRecord` +
    // `HouseholdAuthState`, and neither type nor any lighter fixture is
    // exposed for external-crate tests). Same constraint
    // `roster_bridge.rs` already documents and works around: what's
    // tested directly here is the DECISION each pure mapping function
    // makes, using only the plain, `pub`, `Copy`-constructible error
    // enums household-rs already exports. The registry/coordinator calls
    // themselves are thin, no-branching delegations covered by
    // household-rs's own test suite, not duplicated here.

    // ── `retry_until_admitted` termination (@ilia, 2026-08-05) ──────────
    //
    // The property that matters here is LIVENESS under sustained `Busy`,
    // not any particular return value — a mutant that hardcoded the
    // `is_deadline_expired` argument survived the entire suite (17
    // passed, 0 failed) precisely because nothing exercised
    // `reserve_pending`'s own retry loop at all before this loop was
    // inverted into a pure function over closures. These three tests are
    // what closes that: they need no `MeshSessionRegistry` and no real
    // `CeremonyDeadline` (whose own test-only constructors are
    // `pub(crate)` to mesh-session-core-rs and unreachable from here) —
    // only a closure standing in for one `try_preauthorize_before` call.

    /// The exact scenario `try_preauthorize_before`'s own doc warns
    /// about: `Busy` under sustained contention, with the deadline
    /// already expired. Must return promptly, never loop.
    #[test]
    fn busy_forever_with_expired_deadline_returns_immediately_not_a_hang() {
        let attempts = std::cell::Cell::new(0);
        let result = retry_until_admitted(
            || {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(TryPreauthorizeError::Busy)
            },
            || true,
        );
        assert!(matches!(result, Err(IntentError::DeadlineExceeded)));
        // Exactly one attempt: the first `Busy` observed against an
        // already-expired deadline must fail, not retry once "to be
        // sure" — a `2` here would mean the deadline check runs AFTER
        // deciding to retry rather than gating it.
        assert_eq!(attempts.get(), 1);
    }

    /// The happy liveness path: genuinely transient contention resolves,
    /// and the loop returns the real success value once `attempt`
    /// stops failing — proving this is a retry loop, not just an
    /// early-exit wrapper that happens to pass the deadline-exceeded
    /// test above.
    #[test]
    fn busy_a_few_times_then_success_returns_the_value_after_retrying() {
        let attempts = std::cell::Cell::new(0);
        let result = retry_until_admitted(
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() < 4 {
                    Err(TryPreauthorizeError::Busy)
                } else {
                    Ok(42u32)
                }
            },
            || false,
        );
        assert!(matches!(result, Ok(42)));
        assert_eq!(attempts.get(), 4);
    }

    /// The deadline transitioning mid-retry: not expired for the first
    /// two attempts (retries), expired from the third attempt onward
    /// (fails) — proves the loop re-checks the deadline on every
    /// iteration rather than caching a stale answer from its first call.
    #[test]
    fn deadline_expiring_between_retries_stops_the_loop_on_the_next_one() {
        let attempts = std::cell::Cell::new(0);
        let result = retry_until_admitted(
            || {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(TryPreauthorizeError::Busy)
            },
            || attempts.get() >= 2,
        );
        assert!(matches!(result, Err(IntentError::DeadlineExceeded)));
        // Attempt 1: not expired yet -> retry. Attempt 2: now expired ->
        // fail. Never reaches a third attempt.
        assert_eq!(attempts.get(), 2);
    }

    #[test]
    fn busy_before_deadline_retries() {
        assert!(matches!(
            map_preauthorize_error(TryPreauthorizeError::Busy, false),
            PreauthorizeAction::Retry
        ));
    }

    #[test]
    fn busy_after_deadline_fails_deadline_exceeded() {
        assert!(matches!(
            map_preauthorize_error(TryPreauthorizeError::Busy, true),
            PreauthorizeAction::Fail(IntentError::DeadlineExceeded)
        ));
    }

    #[test]
    fn expired_fails_deadline_exceeded_regardless_of_the_flag() {
        // `Expired` already means "the deadline had passed inside the
        // registry's own critical section" — the caller-observed
        // `deadline_expired` flag is irrelevant to this arm.
        for flag in [false, true] {
            assert!(matches!(
                map_preauthorize_error(TryPreauthorizeError::Expired, flag),
                PreauthorizeAction::Fail(IntentError::DeadlineExceeded)
            ));
        }
    }

    #[test]
    fn poisoned_fails_d1_registry_unavailable() {
        assert!(matches!(
            map_preauthorize_error(TryPreauthorizeError::Poisoned, false),
            PreauthorizeAction::Fail(IntentError::D1RegistryUnavailable)
        ));
    }

    /// The staleness RED (@ilia's required list): the registry's own
    /// internal recheck can reject a binding this adapter's own
    /// pre-check already accepted, because the registry's tracked
    /// revision advanced between this adapter's snapshot read and the
    /// registry's lock acquisition. Must surface as a real, distinct
    /// admission rejection — not silently retried, not conflated with
    /// "registry unavailable".
    #[test]
    fn refused_revision_mismatch_staleness_fails_membership_rejected_not_retried_or_unavailable() {
        assert!(matches!(
            map_preauthorize_error(
                TryPreauthorizeError::Refused(RegisterRefusal::RevisionMismatch),
                false,
            ),
            PreauthorizeAction::Fail(IntentError::D1MembershipRejected)
        ));
    }

    /// Every other `RegisterRefusal` sub-reason collapses to the SAME
    /// flat class — pins the deliberate loss (no re-leaked household-rs
    /// taxonomy across the seam) and would catch a future variant added
    /// to `RegisterRefusal` that this match forgets to route, since the
    /// real match in `map_preauthorize_error` has no wildcard arm on
    /// `Refused`'s inner value.
    #[test]
    fn every_other_refusal_reason_also_collapses_to_membership_rejected() {
        let reasons = [
            RegisterRefusal::HouseholdMismatch,
            RegisterRefusal::MachineRevoked,
            RegisterRefusal::MachineNotActive,
            RegisterRefusal::HandleAlreadyDropped,
            RegisterRefusal::RegistryUnavailable,
            RegisterRefusal::SessionIdSpaceExhausted,
        ];
        for reason in reasons {
            assert!(matches!(
                map_preauthorize_error(TryPreauthorizeError::Refused(reason), false),
                PreauthorizeAction::Fail(IntentError::D1MembershipRejected)
            ));
        }
    }

    #[test]
    fn cancel_outcome_maps_losslessly_across_all_three_variants() {
        assert!(matches!(
            map_cancel_outcome(PendingCancelOutcome::ClosedAndRemoved),
            D1CancelOutcome::CancelledAndRemoved
        ));
        assert!(matches!(
            map_cancel_outcome(PendingCancelOutcome::ClosedCleanupDeferred),
            D1CancelOutcome::BarrierReleasedBookkeepingDeferred
        ));
        assert!(matches!(
            map_cancel_outcome(PendingCancelOutcome::RegistryUnavailable),
            D1CancelOutcome::RegistryUnavailable
        ));
    }
}
