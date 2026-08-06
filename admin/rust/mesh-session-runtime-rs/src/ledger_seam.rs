//! Lane R (@ilia): the `IntentNonceLedger` seam this facade required
//! before it had a real backend to wire to.
//!
//! **Superseded by a real adapter (2026-08-05, @daisy):**
//! `intent_nonce_ledger_bridge::HouseholdIntentNonceLedger` now
//! implements `IntentNonceLedger` for real, against household-rs's
//! `MeshIntentNonceLedger`. That bridge does NOT use the
//! [`TrustedTimeSource`]/[`TrustedFloorProof`] types below — it sources
//! its `TrustedWallFloor` fresh on every `consume()` call directly from
//! `MachineRosterCoordinator::current_snapshot_with_trusted_wall_floor`,
//! rather than through a construction-time mandatory parameter. That is
//! a deliberate divergence from this seam's original prescription, not
//! an oversight: a `TrustedFloorProof` captured once at construction and
//! reused across many later `consume()` calls on a long-lived adapter
//! would go stale the same way a cached `RosterSnapshotView` would —
//! sourcing it per-call is strictly tighter than what this seam asked
//! for.
//!
//! This module still stands for anything ELSE in this crate that later
//! needs durable nonce consumption and does not have a natural per-call
//! floor source of its own: every such future constructor must accept
//! `L: mesh_session_core_rs::intent::IntentNonceLedger` generically,
//! exactly the way `mesh-session-core-rs`'s own handshake functions
//! already do — the re-export below exists so that requirement is
//! visible in this crate's own type surface, not only in prose
//! disconnected from any code a future implementer will actually touch.
//!
//! **The only sanctioned source, once it lands:**
//! `household-rs::MachineRosterCoordinator::open_mesh_intent_nonce_ledger`
//! (feature `mesh-session-runtime` on that crate). No other construction
//! path is approved — see the frozen adapter-design contract this seam
//! anticipates (`daisy-nonce-ledger-adapter-design.7571e9a3….md`,
//! 2026-08-04, self-hash verified).
//!
//! **`MayHaveTakenEffect` must never be reclassified.** A future adapter
//! mapping the real ledger's own outcome down to
//! [`NonceConsumeOutcome`] must map its `MayHaveTakenEffect`-shaped case
//! to [`NonceConsumeOutcome::MayHaveTakenEffect`] — never `Committed`,
//! never `AlreadyConsumed` — matching that enum's own documented contract
//! (`mesh-session-core-rs/src/intent.rs`). A durable ledger that guesses
//! `Committed` on an ambiguous outcome reintroduces exactly the
//! double-admission risk the three-valued outcome exists to prevent.
//!
//! # Capacity cliff (2026-08-05, @zain finding, traced by @ilia) — READ
//! BEFORE WIRING THIS SEAM
//!
//! The real ledger's capacity is hard-capped at `MAX_CONFIGURED_ENTRIES =
//! 8192` (`household-rs/src/mesh_intent_nonce_ledger.rs`) and, on
//! reaching it, does **not** evict — `consume()` returns
//! `Unavailable{reason: CapacityExhausted}` and refuses admission. This is
//! the correct security choice (a live, unexpired entry is never evicted
//! to make room for a new one), but it has a real operational price:
//! pruning is OPPORTUNISTIC on the admission path only, never a
//! background task — `retain(|_, e| trusted_floor.unix_seconds() <=
//! e.not_after)`, run only when a caller supplies a `TrustedWallFloor`.
//!
//! **Unavailable trusted time source + admissions continuing => nothing
//! gets reclaimed => the ledger fills to 8192 => ALL new intents for that
//! household are refused.** A cliff, not graceful degradation — the price
//! is availability, traded for replay-safety, and it is exactly 8192
//! intents wide. Confirmed unreachable in production today
//! (`MachineRosterCoordinator::open_mesh_intent_nonce_ledger` has zero
//! production callers anywhere in this workspace) — this cliff is born
//! the day this facade wires the ledger up. It is this crate's to own.
//!
//! **Required of any future ledger-backed constructor in this crate:**
//! 1. A [`TrustedTimeSource`] is a MANDATORY constructor input — never
//!    optional, never defaulted, never something a caller can omit and
//!    still get a working adapter. [`TrustedFloorProof`] exists so this
//!    is enforced at the type level today, ahead of the real adapter:
//!    its only constructor, [`TrustedFloorProof::obtain`], requires a
//!    working `TrustedTimeSource` call to succeed, so a future
//!    constructor that takes `TrustedFloorProof` (not
//!    `Option<TrustedFloorProof>`) cannot be satisfied by a caller who
//!    "forgot" to wire a clock — there is nothing to forget to pass.
//! 2. [`TimeSourceUnavailable`] is a distinct, declared outcome — never
//!    folded into or made indistinguishable from
//!    `NonceConsumeOutcome::Unavailable`'s `CapacityExhausted` case. The
//!    two share a symptom (admission refused) but have different causes
//!    an operator must be able to tell apart — see the compile-time proof
//!    in this module's own tests that the two types cannot be converted
//!    into each other.
//! 3. [`NonceConsumeOutcome::MayHaveTakenEffect`] is still never
//!    reclassified — and `CapacityExhausted` is not `MayHaveTakenEffect`
//!    either: it is refusal WITHOUT effect, not an ambiguous one. Do not
//!    fold the two together.

pub use mesh_session_core_rs::intent::{IntentNonceLedger, NonceConsumeOutcome};

/// Mandatory capability a future ledger-backed constructor in this crate
/// must require — see the module doc's capacity-cliff finding for why
/// this cannot be optional. Modeled on household-rs's own
/// `TrustedWallFloor` concept (crate-private constructor there; a real
/// implementation obtains one via `MachineRosterCoordinator`, per the
/// frozen adapter-design contract this seam anticipates).
pub trait TrustedTimeSource {
    /// A fresh reading, in Unix seconds, or [`TimeSourceUnavailable`] —
    /// a type DISTINCT from any ledger outcome, never conflated with
    /// `CapacityExhausted` by a caller mapping this seam's eventual real
    /// errors.
    fn trusted_floor_unix_seconds(&self) -> Result<u64, TimeSourceUnavailable>;
}

/// See [`TrustedTimeSource`]. Deliberately its own type — not
/// `mesh_session_core_rs::error::IntentError`, not
/// [`NonceConsumeOutcome`], not anything ledger-shaped — so a future
/// adapter's own error enum can require callers to match on this
/// distinctly from `CapacityExhausted`. Never `PartialEq`-comparable or
/// convertible to/from `NonceConsumeOutcome` — see this module's own
/// `static_assertions` checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeSourceUnavailable;

impl std::fmt::Display for TimeSourceUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "trusted time source unavailable")
    }
}

impl std::error::Error for TimeSourceUnavailable {}

/// Proof that a [`TrustedTimeSource`] was consulted successfully — the
/// ONLY way to obtain one (private field, no other constructor). A future
/// ledger-backed constructor in this crate should require this as a
/// plain, non-optional parameter (never `Option<TrustedFloorProof>`,
/// never defaulted) — making "forgot to wire a clock" a compile error
/// instead of the capacity cliff documented above.
///
/// ```compile_fail
/// use mesh_session_runtime_rs::ledger_seam::TrustedFloorProof;
/// let _ = TrustedFloorProof { unix_seconds: 0 }; // field is private — does not compile
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TrustedFloorProof {
    unix_seconds: u64,
}

impl TrustedFloorProof {
    /// The only constructor. Fails exactly when `source` itself reports
    /// [`TimeSourceUnavailable`] — this function never invents a reading
    /// on its own.
    pub fn obtain(source: &impl TrustedTimeSource) -> Result<Self, TimeSourceUnavailable> {
        Ok(Self {
            unix_seconds: source.trusted_floor_unix_seconds()?,
        })
    }

    pub fn unix_seconds(&self) -> u64 {
        self.unix_seconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysAvailable(u64);
    impl TrustedTimeSource for AlwaysAvailable {
        fn trusted_floor_unix_seconds(&self) -> Result<u64, TimeSourceUnavailable> {
            Ok(self.0)
        }
    }

    struct NeverAvailable;
    impl TrustedTimeSource for NeverAvailable {
        fn trusted_floor_unix_seconds(&self) -> Result<u64, TimeSourceUnavailable> {
            Err(TimeSourceUnavailable)
        }
    }

    #[test]
    fn trusted_floor_proof_obtained_from_a_working_source() {
        let proof = TrustedFloorProof::obtain(&AlwaysAvailable(1_767_225_600)).unwrap();
        assert_eq!(proof.unix_seconds(), 1_767_225_600);
    }

    #[test]
    fn red_trusted_floor_proof_fails_distinctly_when_source_unavailable() {
        let err = TrustedFloorProof::obtain(&NeverAvailable).unwrap_err();
        assert_eq!(err, TimeSourceUnavailable);
    }

    // `TimeSourceUnavailable` must never be interchangeable with a ledger
    // outcome — proves items 2/3 of the module doc's requirements at
    // compile time, not by convention. Same technique as
    // mesh-session-core-rs's own item-14 checks this session.
    static_assertions::assert_not_impl_any!(TimeSourceUnavailable: Into<NonceConsumeOutcome>);
    static_assertions::assert_not_impl_any!(NonceConsumeOutcome: Into<TimeSourceUnavailable>);
    static_assertions::assert_not_impl_any!(TimeSourceUnavailable: PartialEq<NonceConsumeOutcome>);
    // @khai's cross-audit (2026-08-05) found this direction missing: the
    // orphan rule permits a foreign trait (`PartialEq`) on a foreign
    // `Self` (`NonceConsumeOutcome`) as long as the type PARAMETER is
    // local (`TimeSourceUnavailable`) — so `impl PartialEq<TimeSourceUnavailable>
    // for NonceConsumeOutcome` compiles today, the three checks above all
    // still pass with it present, and `NonceConsumeOutcome::MayHaveTakenEffect
    // == TimeSourceUnavailable` would silently return `true`. The module
    // doc's "never comparable... in either direction" claim was wider than
    // what the mechanism actually enforced until this line.
    //
    // If this line's build ever breaks, it will very likely surface as
    // `E0283` (type-annotations-needed / ambiguity), NOT the plainer
    // "trait is implemented for this type" diagnostic the other three
    // checks produce. That is not this assertion failing to compile as
    // itself — `NonceConsumeOutcome` already derives `PartialEq` for
    // comparisons with its own type, so a foreign `impl
    // PartialEq<TimeSourceUnavailable> for NonceConsumeOutcome` makes
    // `static_assertions`' own trait-resolution probe ambiguous between
    // the two impls, and rustc reports that ambiguity rather than a clean
    // "yes, it's implemented." It still fails the build, and the build
    // failing is exactly what this assertion exists to force — do not
    // read an `E0283` here as this check being broken and remove it.
    static_assertions::assert_not_impl_any!(NonceConsumeOutcome: PartialEq<TimeSourceUnavailable>);
}
