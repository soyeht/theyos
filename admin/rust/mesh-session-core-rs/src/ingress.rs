//! `PrevalidatedIngress<T>` scaffolding (Fila 1 item 5, CFX-1/RED-42).
//!
//! B-SESSAO v6 §2: the v4 bug was `authorize_mesh_peer(ingress, session,
//! ...)` accepting a *separate* ingress parameter alongside a session that
//! already embedded one — evidence from stream A could be paired with
//! stream B. The fix is an aggregate the adapter builds once, that a
//! constructor consumes by move and never re-exposes in pieces.
//!
//! **Hardened 2026-08-04, independent audit of `911409eb`:** `consume`
//! used to be `pub`, which meant *any* external caller — not just this
//! crate's own auth state machine — could unpack a `PrevalidatedIngress<T>`
//! back into its raw `(T, IngressEvidence)` and then call
//! [`PrevalidatedIngress::new`] again with a stream from one ingress and
//! evidence from a *different* one. That is exactly the v4 bug the type
//! exists to prevent, just moved one step later: the adapter can only
//! create the pair once, but nothing stopped a caller from taking it apart
//! and reassembling a mismatched one. `consume` is now `pub(crate)` — only
//! this crate's own `start_session` (the auth state machine) may take the
//! aggregate apart, and it does so internally, embedding the evidence in
//! whatever session type it returns rather than handing either piece back
//! out.
//!
//! **`CeremonyDeadline` (2026-08-04, @kiana, D9 carrier-B erratum1 E3,
//! definitive):** a monotonic time budget, never a caller-suppliable
//! wall-clock `u64`. The only production constructor is
//! [`PrevalidatedIngress::admit_at_accept`], which captures
//! `Instant::now()` internally, once — there is no production path for a
//! caller to hand in their own `Instant`/`u64`/timestamp. The token stays
//! private inside `PrevalidatedIngress` and is moved out only via
//! `consume`, into the handshake, alongside the stream and evidence it
//! was born with. `#[cfg(test)]` gets its own deterministic
//! constructors — never reachable from a production build.

use std::time::{Duration, Instant};

/// Evidence an adapter attaches to a stream it has already prefiltered
/// (e.g. accepted a TCP connection, matched some coarse allow-list). CORE
/// trusts this only for DoS/prefiltering, never for identity — v6 §11.
///
/// Concrete fields are the adapter's decision (Fila 3/4), not restated
/// here; `observed_at` is a placeholder shape, not a normative field list.
///
/// **`ingress_expiry` (2026-08-04, @kiana, WIP audit point A, v6 §7,
/// self-hash verified against `daisy-bsessao-v6.7343d075…`):** one of the
/// components of `effective_expires_at = min(checkpoint.not_after,
/// local_delegation.not_after, peer_delegation.not_after,
/// lease_expires_at, ingress_expiry)` — the adapter's own bound on how
/// long this specific ingress admission may be treated as valid, wall-clock
/// (the same `u64` domain as `intent`/delegation `not_after`, never the
/// monotonic anti-slow-loris `CeremonyDeadline`). Required, not optional:
/// v6 §7 does not permit an unmeasured component to default to unbounded.
#[derive(Debug)]
pub struct IngressEvidence {
    pub observed_at: u64,
    pub ingress_expiry: u64,
}

/// A hard ceiling on how large a [`CeremonyBudget`] may be, supplied by
/// the runtime/config, never invented inside this crate (2026-08-04,
/// @kiana: the frozen D9/B-SESSAO spec does not itself fix a numeric
/// protocol maximum for this window, so the core must not guess one —
/// it requires an explicit policy from its caller and never falls back to
/// "unlimited"). There is deliberately no `Default` impl: a
/// [`CeremonyBudget`] cannot be constructed without a policy reaching this
/// type first, so "no policy configured" fails closed by construction,
/// the same discipline as `NoD1AdmissionConfigured`/`NoClockConfigured`.
#[derive(Debug, Clone, Copy)]
pub struct CeremonyDeadlinePolicy {
    max_budget: Duration,
}

impl CeremonyDeadlinePolicy {
    /// `max_budget` itself must be nonzero — a zero ceiling would make
    /// every [`CeremonyBudget::new`] call fail, which is a config bug to
    /// reject at the policy boundary rather than surface as a mysterious
    /// per-connection admission failure later.
    pub fn new(max_budget: Duration) -> Option<Self> {
        if max_budget.is_zero() {
            None
        } else {
            Some(Self { max_budget })
        }
    }
}

/// A validated ceremony time budget — nonzero AND within the runtime's
/// declared [`CeremonyDeadlinePolicy`] ceiling, checked once at
/// construction rather than trusted to already be sane. `pub`: the
/// adapter (a different crate) must be able to construct one; the
/// *duration itself* carries no authority, only [`CeremonyDeadline`]
/// (which additionally binds it to a specific `Instant`) does.
///
/// (2026-08-04, @kiana, CFX: an earlier version of this type accepted any
/// nonzero duration including `Duration::MAX`, which let an adapter
/// construct a budget that is "nonzero" by the letter of the check but
/// unlimited in practice — defeating the whole anti-slow-loris purpose.
/// The frozen decision said nonzero *and* bounded by policy; both halves
/// are now enforced together, not just the first.)
#[derive(Debug, Clone, Copy)]
pub struct CeremonyBudget(Duration);

impl CeremonyBudget {
    pub fn new(duration: Duration, policy: &CeremonyDeadlinePolicy) -> Option<Self> {
        if duration.is_zero() || duration > policy.max_budget {
            None
        } else {
            Some(Self(duration))
        }
    }
}

/// Opaque, monotonic ceremony deadline. `started`/`budget` are private —
/// the only ways to obtain a value of this type are
/// [`PrevalidatedIngress::admit_at_accept`] (production; mints `started`
/// from `Instant::now()` internally) or the `#[cfg(test)]`-only
/// constructors below (test doubles, never reachable from a production
/// build). Nothing here is wall-clock/`u64`-based — `Instant` cannot go
/// backwards and is immune to wall-clock adjustment, exactly the property
/// an anti-slow-loris deadline needs and a `SystemTime`/`u64` timestamp
/// does not have.
#[derive(Debug, Clone, Copy)]
pub struct CeremonyDeadline {
    started: Instant,
    budget: Duration,
}

impl CeremonyDeadline {
    /// Time left before this deadline, recomputed fresh against the same
    /// `started` `Instant` every call — never cached, never reset.
    ///
    /// `pub` (2026-08-04, @kiana, WIP audit, seam-visibility correction):
    /// a real `D1Admission`/`IntentNonceLedger` adapter (a different
    /// crate) receives `&CeremonyDeadline` and must be able to inspect it
    /// to linearize its own commit against the same deadline this crate
    /// enforces — an opaque token it could not read at all would defeat
    /// the entire point of threading it through.
    pub fn remaining(&self) -> Duration {
        self.budget.saturating_sub(self.started.elapsed())
    }

    pub fn is_expired(&self) -> bool {
        self.remaining().is_zero()
    }

    /// Test-only, deterministic constructor — lets a test build a
    /// `CeremonyDeadline` from a specific `Instant`/`Duration` pair
    /// (e.g. already expired) without depending on real wall-clock
    /// timing. Never reachable outside `#[cfg(test)]`.
    #[cfg(test)]
    pub(crate) fn for_test(started: Instant, budget: Duration) -> Self {
        Self { started, budget }
    }

    /// Test-only: a deadline that has already expired by construction —
    /// used by REDs that need "expired before any I/O" without a real
    /// sleep.
    #[cfg(test)]
    pub(crate) fn already_expired_for_test() -> Self {
        Self {
            started: Instant::now() - Duration::from_secs(3600),
            budget: Duration::from_secs(1),
        }
    }
}

/// `stream` and `evidence` are inseparable from the moment the adapter
/// builds this: no `Clone`, no public accessor that returns one without
/// the other, and the only way to get either out —
/// [`consume`](Self::consume) — is `pub(crate)`, reachable only from this
/// crate's own `start_session`.
///
/// `PrevalidatedIngress<T>` derives no `Clone` impl, so cloning one — even
/// when `T` itself is `Clone` (`u32` is) — does not compile:
///
/// ```compile_fail
/// use mesh_session_core_rs::ingress::{PrevalidatedIngress, IngressEvidence, CeremonyBudget, CeremonyDeadlinePolicy};
/// use std::time::Duration;
/// let policy = CeremonyDeadlinePolicy::new(Duration::from_secs(60)).unwrap();
/// let ingress = PrevalidatedIngress::admit_at_accept(42u32, IngressEvidence { observed_at: 100, ingress_expiry: u64::MAX / 2 }, CeremonyBudget::new(Duration::from_secs(30), &policy).unwrap());
/// let _duplicate = ingress.clone(); // no Clone impl — does not compile
/// ```
///
/// There is no accessor that returns just the stream or just the evidence
/// — both fields are private:
///
/// ```compile_fail
/// use mesh_session_core_rs::ingress::{PrevalidatedIngress, IngressEvidence, CeremonyBudget, CeremonyDeadlinePolicy};
/// use std::time::Duration;
/// let policy = CeremonyDeadlinePolicy::new(Duration::from_secs(60)).unwrap();
/// let ingress = PrevalidatedIngress::admit_at_accept(42u32, IngressEvidence { observed_at: 100, ingress_expiry: u64::MAX / 2 }, CeremonyBudget::new(Duration::from_secs(30), &policy).unwrap());
/// let _just_the_stream: u32 = ingress.stream; // field is private
/// ```
///
/// And unlike the pre-hardening version, `consume` itself is not reachable
/// from outside this crate at all — the aggregate can be created (by an
/// adapter, a different crate) but not taken apart except internally:
///
/// ```compile_fail
/// use mesh_session_core_rs::ingress::{PrevalidatedIngress, IngressEvidence, CeremonyBudget, CeremonyDeadlinePolicy};
/// use std::time::Duration;
/// let policy = CeremonyDeadlinePolicy::new(Duration::from_secs(60)).unwrap();
/// let ingress = PrevalidatedIngress::admit_at_accept(42u32, IngressEvidence { observed_at: 100, ingress_expiry: u64::MAX / 2 }, CeremonyBudget::new(Duration::from_secs(30), &policy).unwrap());
/// let _ = ingress.consume(); // pub(crate) — does not compile from outside the crate
/// ```
#[derive(Debug)]
pub struct PrevalidatedIngress<T> {
    stream: T,
    evidence: IngressEvidence,
    deadline: CeremonyDeadline,
}

impl<T> PrevalidatedIngress<T> {
    /// The only production constructor. Mints [`CeremonyDeadline`]
    /// internally from `Instant::now()` — there is no parameter through
    /// which a caller could supply their own instant, timestamp, or raw
    /// `u64`. CORE itself never fabricates evidence for a stream it did
    /// not prefilter, and never trusts a deadline it did not mint itself
    /// at this exact call.
    pub fn admit_at_accept(stream: T, evidence: IngressEvidence, budget: CeremonyBudget) -> Self {
        Self {
            stream,
            evidence,
            deadline: CeremonyDeadline {
                started: Instant::now(),
                budget: budget.0,
            },
        }
    }

    /// Test-only constructor accepting a pre-built [`CeremonyDeadline`]
    /// (e.g. already-expired, for REDs) — never reachable from a
    /// production build.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        stream: T,
        evidence: IngressEvidence,
        deadline: CeremonyDeadline,
    ) -> Self {
        Self {
            stream,
            evidence,
            deadline,
        }
    }

    /// Consume `self` once, returning the stream, its evidence, and its
    /// ceremony deadline as an inseparable triple. `pub(crate)`: only
    /// this crate's own `start_session` may call this, and it does so
    /// internally, embedding the evidence in whatever session type it
    /// returns rather than handing either piece back out to its own
    /// caller. Taking `self` by value (not `&PrevalidatedIngress<T>`)
    /// also means a second call on the same binding is a use-after-move
    /// the compiler rejects outright.
    pub(crate) fn consume(self) -> (T, IngressEvidence, CeremonyDeadline) {
        (self.stream, self.evidence, self.deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> CeremonyDeadlinePolicy {
        CeremonyDeadlinePolicy::new(Duration::from_secs(60)).unwrap()
    }

    #[test]
    fn consume_yields_the_same_stream_and_evidence_it_was_built_from() {
        let ingress = PrevalidatedIngress::admit_at_accept(
            42u32,
            IngressEvidence {
                observed_at: 100,
                ingress_expiry: u64::MAX / 2,
            },
            CeremonyBudget::new(Duration::from_secs(30), &test_policy()).unwrap(),
        );
        let (stream, evidence, deadline) = ingress.consume();
        assert_eq!(stream, 42);
        assert_eq!(evidence.observed_at, 100);
        assert!(!deadline.is_expired());
    }

    #[test]
    fn zero_budget_rejected_at_construction() {
        assert!(CeremonyBudget::new(Duration::ZERO, &test_policy()).is_none());
    }

    #[test]
    fn zero_max_policy_rejected_at_construction() {
        assert!(CeremonyDeadlinePolicy::new(Duration::ZERO).is_none());
    }

    #[test]
    fn budget_at_exactly_the_policy_ceiling_is_accepted() {
        let policy = test_policy();
        assert!(CeremonyBudget::new(Duration::from_secs(60), &policy).is_some());
    }

    #[test]
    fn red_budget_one_epsilon_over_the_policy_ceiling_is_rejected() {
        let policy = test_policy();
        assert!(
            CeremonyBudget::new(Duration::from_secs(60) + Duration::from_nanos(1), &policy)
                .is_none()
        );
    }

    #[test]
    fn red_duration_max_does_not_bypass_the_policy_ceiling() {
        // The bug this guards against: an earlier CeremonyBudget::new
        // checked only "nonzero", so Duration::MAX passed the check and
        // silently produced a de-facto-unlimited budget. Duration::MAX
        // must be rejected against ANY finite policy ceiling.
        let policy = test_policy();
        assert!(CeremonyBudget::new(Duration::MAX, &policy).is_none());
    }

    #[test]
    fn already_expired_test_deadline_reports_expired() {
        let deadline = CeremonyDeadline::already_expired_for_test();
        assert!(deadline.is_expired());
        assert_eq!(deadline.remaining(), Duration::ZERO);
    }
}
