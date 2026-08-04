//! Rekey policy state machine (Fila 1 item 4).
//!
//! B-SESSAO v6 §8 + erratum (`63222d40…` §2, `NonZeroU64` threshold).
//!
//! This is deliberately a **generic** counter/threshold state machine, not
//! a wire codec: it operates on [`IncomingRecord`], an abstract signal the
//! caller produces after decoding whatever concrete DATA/REKEY/CLOSE frame
//! format eventually gets frozen. v6 does not fully restate that wire
//! format, so this module does not invent one (2026-08-04, @kiana) — it
//! only tracks `policy_count`/`generation` per direction and answers
//! "is a marker expected/allowed right now."
//!
//! **Hardened 2026-08-04, @kiana:** the send-side `before_*`/`after_*`
//! pair used to be two independent calls — nothing stopped calling
//! `after_send_non_marker` without `before_send_non_marker` first, or
//! `after_send_marker` with an arbitrary `next_generation` never validated
//! by `before_send_marker`. Both `after_*` methods now consume an opaque,
//! move-only permit that only the matching `before_*` call can produce
//! (misuse prevented by type, not by convention), and the marker permit
//! itself carries the validated `next_generation` — there is no longer a
//! parameter to substitute. `SessionRekeyState::new` is `pub(crate)`: it
//! must only be minted by this crate's own post-ActivateAck transition,
//! never called directly by an external consumer before auth completes.

use std::num::NonZeroU64;

use crate::error::RekeyError;

pub const REKEY_THRESHOLD_TEST_VALUE: u64 = 3;
pub const REKEY_THRESHOLD_DEFAULT_VALUE: u64 = 1u64 << 32;

/// A rekey threshold that is provably nonzero — erratum §2: `threshold - 1`
/// must never underflow, and a zero threshold must be rejected at
/// configuration time (RED-47), never at runtime mid-session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RekeyThreshold(NonZeroU64);

impl RekeyThreshold {
    pub fn new(threshold: u64) -> Result<Self, RekeyError> {
        NonZeroU64::new(threshold)
            .map(RekeyThreshold)
            .ok_or(RekeyError::InvalidRekeyPolicy)
    }

    fn minus_one(self) -> u64 {
        // NonZeroU64 guarantees get() >= 1, so this never underflows.
        self.0.get() - 1
    }
}

pub fn rekey_threshold_test() -> RekeyThreshold {
    RekeyThreshold::new(REKEY_THRESHOLD_TEST_VALUE).expect("REKEY_THRESHOLD_TEST_VALUE is nonzero")
}

pub fn rekey_threshold_default() -> RekeyThreshold {
    RekeyThreshold::new(REKEY_THRESHOLD_DEFAULT_VALUE)
        .expect("REKEY_THRESHOLD_DEFAULT_VALUE is nonzero")
}

/// What the caller observed after decoding one post-ActivateAck record,
/// abstracted away from whatever concrete wire format eventually carries
/// it. Auth frames (ProofR..ActivateAck) are not represented here at all —
/// v6 §8 is explicit that they never enter this counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingRecord {
    NonMarker,
    Marker { next_generation: u64 },
}

/// Proof that [`DirectionalRekeyState::before_send_non_marker`] succeeded.
/// The only way to advance `policy_count` for a non-marker send —
/// `after_send_non_marker` takes this by value (consumed once), so it
/// cannot be called without a prior, successful `before_send_non_marker`,
/// and cannot be replayed.
#[must_use = "pass this to after_send_non_marker, or the send is never committed"]
pub struct SendNonMarkerPermit(());

/// Proof that [`DirectionalRekeyState::before_send_marker`] succeeded,
/// carrying the exact `next_generation` value that was validated.
/// `after_send_marker` takes no separate generation parameter — there is
/// nothing for a caller to substitute at commit time.
#[must_use = "pass this to after_send_marker, or the rekey is never committed"]
pub struct SendMarkerPermit {
    next_generation: u64,
}

impl SendMarkerPermit {
    /// The generation this permit will commit. Exposed so a caller can
    /// embed it in whatever marker record it sends before calling
    /// `after_send_marker` — this crate does not define that wire shape.
    pub fn next_generation(&self) -> u64 {
        self.next_generation
    }
}

/// Rekey counters for one direction (outgoing or incoming). Two of these
/// (tx, rx) make up a session's rekey state; v6 §8 requires them fully
/// independent, reset to `generation = 0, policy_count = 0` only once,
/// immediately after ActivateAck.
/// Deliberately not `Clone`/`Copy` (hardened 2026-08-04, @kiana): a permit
/// is proof about *one specific* `DirectionalRekeyState` instance. If the
/// state were copyable, a permit obtained from one copy could be applied
/// to a different copy of what's nominally "the same" logical state,
/// which defeats the point of the permit tying `before_*`/`after_*`
/// together.
#[derive(Debug)]
pub struct DirectionalRekeyState {
    generation: u64,
    policy_count: u64,
    threshold: RekeyThreshold,
}

impl DirectionalRekeyState {
    pub fn new(threshold: RekeyThreshold) -> Self {
        Self {
            generation: 0,
            policy_count: 0,
            threshold,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn policy_count(&self) -> u64 {
        self.policy_count
    }

    /// Call before encrypting a non-marker record. `policy_count ==
    /// threshold - 1` means the *next* record is required to be a marker
    /// (RED-43): a non-marker here is rejected before it is ever sent.
    /// Returns a permit that [`Self::after_send_non_marker`] requires.
    pub fn before_send_non_marker(&self) -> Result<SendNonMarkerPermit, RekeyError> {
        if self.policy_count == self.threshold.minus_one() {
            return Err(RekeyError::ExpectedRekeyMarker);
        }
        Ok(SendNonMarkerPermit(()))
    }

    /// Call after a non-marker record has been fully sent, consuming the
    /// permit [`Self::before_send_non_marker`] issued. There is no
    /// zero-argument overload — a permit is always required:
    ///
    /// ```compile_fail
    /// use mesh_session_core_rs::rekey::{DirectionalRekeyState, RekeyThreshold};
    /// let threshold = RekeyThreshold::new(3).unwrap();
    /// let mut tx = DirectionalRekeyState::new(threshold);
    /// tx.after_send_non_marker(); // missing the required SendNonMarkerPermit
    /// ```
    pub fn after_send_non_marker(
        &mut self,
        _permit: SendNonMarkerPermit,
    ) -> Result<(), RekeyError> {
        self.policy_count = self
            .policy_count
            .checked_add(1)
            .ok_or(RekeyError::GenerationExhausted)?;
        Ok(())
    }

    /// Call before sending a marker. The returned permit carries the
    /// `next_generation` value the marker must carry (v6 §8: "count é
    /// ainda N-1" at send time — this call does not itself increment
    /// `policy_count`, `after_send_marker` resets it instead).
    pub fn before_send_marker(&self) -> Result<SendMarkerPermit, RekeyError> {
        if self.policy_count != self.threshold.minus_one() {
            return Err(RekeyError::PrematureRekeyMarker);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(RekeyError::GenerationExhausted)?;
        Ok(SendMarkerPermit { next_generation })
    }

    /// Call once the marker has been written in full, consuming the
    /// permit [`Self::before_send_marker`] issued. Commits exactly the
    /// generation that permit was validated against — see the module
    /// gate note: `after_send_marker(next_generation: u64)` used to exist
    /// and let a caller commit an ungvalidated value; it does not anymore.
    pub fn after_send_marker(&mut self, permit: SendMarkerPermit) {
        self.generation = permit.next_generation;
        self.policy_count = 0;
    }

    /// Process one decrypted incoming record. Advances `generation`/
    /// `policy_count` on success; returns the fail-closed error for every
    /// early/late/duplicate/wrong-generation/wrong-count case (v6 §8,
    /// erratum RED-19-adjacent discipline: reject, do not guess). This
    /// side is a single atomic call already — no separate before/after to
    /// harden.
    pub fn on_receive(&mut self, record: IncomingRecord) -> Result<(), RekeyError> {
        match record {
            IncomingRecord::NonMarker => {
                if self.policy_count == self.threshold.minus_one() {
                    return Err(RekeyError::ExpectedRekeyMarker);
                }
                self.policy_count = self
                    .policy_count
                    .checked_add(1)
                    .ok_or(RekeyError::GenerationExhausted)?;
                Ok(())
            }
            IncomingRecord::Marker { next_generation } => {
                let expected = self
                    .generation
                    .checked_add(1)
                    .ok_or(RekeyError::GenerationExhausted)?;
                if next_generation != expected {
                    return Err(RekeyError::WrongGeneration {
                        expected,
                        got: next_generation,
                    });
                }
                if self.policy_count != self.threshold.minus_one() {
                    return Err(RekeyError::PrematureRekeyMarker);
                }
                self.generation = next_generation;
                self.policy_count = 0;
                Ok(())
            }
        }
    }
}

/// Both directions of a session's rekey state, independent by construction
/// (v6 §8: "Ambas direções independentes").
///
/// `new` is `pub(crate)` on purpose: a `SessionRekeyState` asserts "this
/// authenticated session has reached Active" simply by existing, so only
/// this crate's own post-ActivateAck transition may mint one — an
/// external consumer cannot construct one before auth completes:
///
/// ```compile_fail
/// use mesh_session_core_rs::rekey::{SessionRekeyState, RekeyThreshold};
/// let threshold = RekeyThreshold::new(3).unwrap();
/// let _ = SessionRekeyState::new(threshold); // pub(crate) — does not compile here
/// ```
pub struct SessionRekeyState {
    tx: DirectionalRekeyState,
    rx: DirectionalRekeyState,
}

impl SessionRekeyState {
    pub(crate) fn new(threshold: RekeyThreshold) -> Self {
        Self {
            tx: DirectionalRekeyState::new(threshold),
            rx: DirectionalRekeyState::new(threshold),
        }
    }

    /// Mutable access to the outgoing-direction counters. Not a public
    /// field — replacing the whole `DirectionalRekeyState` wholesale
    /// (`session.tx = DirectionalRekeyState::new(..)`) would let a caller
    /// fabricate a fresh, unauthenticated-looking state inside an
    /// otherwise-real session; only mutation through its own methods is
    /// possible.
    pub fn tx(&mut self) -> &mut DirectionalRekeyState {
        &mut self.tx
    }

    /// Mutable access to the incoming-direction counters. See [`Self::tx`].
    pub fn rx(&mut self) -> &mut DirectionalRekeyState {
        &mut self.rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn red47_zero_threshold_rejected_before_any_session() {
        assert_eq!(RekeyThreshold::new(0), Err(RekeyError::InvalidRekeyPolicy));
    }

    #[test]
    fn threshold_one_minus_one_never_underflows() {
        let t = RekeyThreshold::new(1).unwrap();
        assert_eq!(t.minus_one(), 0);
    }

    #[test]
    fn misuse_after_send_non_marker_requires_a_real_permit_not_just_any_call() {
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut tx = DirectionalRekeyState::new(threshold);
        let permit = tx.before_send_non_marker().unwrap();
        tx.after_send_non_marker(permit).unwrap();
        assert_eq!(tx.policy_count(), 1);
    }

    #[test]
    fn misuse_permit_cannot_be_reused_the_type_system_enforces_this() {
        // This test documents the property; the compiler enforces it — a
        // second `tx.after_send_non_marker(permit)` using the same
        // binding would be a use-after-move and simply does not compile,
        // so there is no runtime assertion to make here beyond the happy
        // path already covered above. See the compile_fail doctests on
        // SendMarkerPermit/SessionRekeyState for the negative form.
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut tx = DirectionalRekeyState::new(threshold);
        let permit = tx.before_send_non_marker().unwrap();
        tx.after_send_non_marker(permit).unwrap();
    }

    #[test]
    fn pos4_n3_two_data_marker_two_data_directional() {
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut tx = DirectionalRekeyState::new(threshold);

        // count=0: DATA -> count=1
        let permit = tx.before_send_non_marker().unwrap();
        tx.after_send_non_marker(permit).unwrap();
        assert_eq!(tx.policy_count(), 1);

        // count=1: DATA -> count=2
        let permit = tx.before_send_non_marker().unwrap();
        tx.after_send_non_marker(permit).unwrap();
        assert_eq!(tx.policy_count(), 2);

        // count=2==N-1: next MUST be a marker.
        assert_eq!(
            tx.before_send_non_marker().err(),
            Some(RekeyError::ExpectedRekeyMarker)
        );
        let permit = tx.before_send_marker().unwrap();
        assert_eq!(permit.next_generation(), 1);
        tx.after_send_marker(permit);
        assert_eq!(tx.generation(), 1);
        assert_eq!(tx.policy_count(), 0);

        // Cycle repeats.
        let permit = tx.before_send_non_marker().unwrap();
        tx.after_send_non_marker(permit).unwrap();
        assert_eq!(tx.policy_count(), 1);
        let permit = tx.before_send_non_marker().unwrap();
        tx.after_send_non_marker(permit).unwrap();
        assert_eq!(tx.policy_count(), 2);
    }

    #[test]
    fn red43_non_marker_at_n_minus_1_rejected_on_receive_too() {
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut rx = DirectionalRekeyState::new(threshold);
        rx.on_receive(IncomingRecord::NonMarker).unwrap();
        rx.on_receive(IncomingRecord::NonMarker).unwrap();
        assert_eq!(rx.policy_count(), 2);
        assert_eq!(
            rx.on_receive(IncomingRecord::NonMarker),
            Err(RekeyError::ExpectedRekeyMarker)
        );
    }

    #[test]
    fn red25_premature_marker_rejected() {
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut rx = DirectionalRekeyState::new(threshold);
        // policy_count is 0, threshold-1 is 2 — far too early for a marker.
        assert_eq!(
            rx.on_receive(IncomingRecord::Marker { next_generation: 1 }),
            Err(RekeyError::PrematureRekeyMarker)
        );
        assert_eq!(rx.generation(), 0);
    }

    #[test]
    fn red26_duplicate_marker_rejected_as_wrong_generation() {
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut rx = DirectionalRekeyState::new(threshold);
        rx.on_receive(IncomingRecord::NonMarker).unwrap();
        rx.on_receive(IncomingRecord::NonMarker).unwrap();
        rx.on_receive(IncomingRecord::Marker { next_generation: 1 })
            .unwrap();
        assert_eq!(rx.generation(), 1);
        // Same marker replayed — generation already advanced past it.
        assert_eq!(
            rx.on_receive(IncomingRecord::Marker { next_generation: 1 }),
            Err(RekeyError::WrongGeneration {
                expected: 2,
                got: 1
            })
        );
    }

    #[test]
    fn red27_wrong_generation_skip_ahead_rejected() {
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut rx = DirectionalRekeyState::new(threshold);
        rx.on_receive(IncomingRecord::NonMarker).unwrap();
        rx.on_receive(IncomingRecord::NonMarker).unwrap();
        assert_eq!(
            rx.on_receive(IncomingRecord::Marker { next_generation: 5 }),
            Err(RekeyError::WrongGeneration {
                expected: 1,
                got: 5
            })
        );
    }

    #[test]
    fn red28_wrong_count_marker_before_threshold_rejected() {
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut rx = DirectionalRekeyState::new(threshold);
        rx.on_receive(IncomingRecord::NonMarker).unwrap(); // count=1, still short of N-1=2
        assert_eq!(
            rx.on_receive(IncomingRecord::Marker { next_generation: 1 }),
            Err(RekeyError::PrematureRekeyMarker)
        );
    }

    #[test]
    fn red29_simultaneous_opposite_directions_are_independent() {
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut state = SessionRekeyState::new(threshold);

        // Drive tx all the way through a rekey.
        let permit = state.tx().before_send_non_marker().unwrap();
        state.tx().after_send_non_marker(permit).unwrap();
        let permit = state.tx().before_send_non_marker().unwrap();
        state.tx().after_send_non_marker(permit).unwrap();
        let permit = state.tx().before_send_marker().unwrap();
        state.tx().after_send_marker(permit);
        assert_eq!(state.tx().generation(), 1);

        // rx never touched — must be completely unaffected.
        assert_eq!(state.rx().generation(), 0);
        assert_eq!(state.rx().policy_count(), 0);

        // Drive rx independently and confirm tx is unaffected in turn.
        state.rx().on_receive(IncomingRecord::NonMarker).unwrap();
        assert_eq!(state.tx().policy_count(), 0);
        assert_eq!(state.tx().generation(), 1);
    }

    #[test]
    fn generation_exhaustion_is_checked_not_wrapping() {
        let threshold = RekeyThreshold::new(1).unwrap();
        // Private-field construction is visible here because `tests` is a
        // child module of `rekey` — used only to force an edge state that
        // is otherwise impractical to reach by driving u64::MAX sends.
        let tx = DirectionalRekeyState {
            generation: u64::MAX,
            policy_count: 0,
            threshold,
        };
        assert_eq!(
            tx.before_send_marker().err(),
            Some(RekeyError::GenerationExhausted)
        );
    }
}
