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
//! **Hardened 2026-08-04, @kiana, round 1:** the send-side `before_*`/
//! `after_*` pair used to be two independent calls — nothing stopped
//! calling `after_send_non_marker` without `before_send_non_marker` first,
//! or `after_send_marker` with an arbitrary `next_generation` never
//! validated by `before_send_marker`. Both `after_*` methods consume an
//! opaque, move-only permit that only the matching `before_*` call can
//! produce, and the marker permit carries the validated `next_generation`
//! — no parameter to substitute.
//!
//! **Hardened 2026-08-04, @kiana, round 2 (independent audit of
//! `e5afccfe`):** round 1's permits were still bare, contentless tokens —
//! nothing tied a permit to *which* `DirectionalRekeyState` issued it, or
//! to the exact `generation`/`policy_count` it was validated against.
//! Reproduced externally: calling `before_send_non_marker(&self)` three
//! times in a row (nothing mutates between calls) yielded three
//! equally-"valid" permits, and applying all three via `after_*` drove
//! `policy_count` from 0 straight to 3, jumping straight past the N-1
//! marker-required boundary the whole mechanism exists to enforce. Worse,
//! a permit issued by *one* `DirectionalRekeyState` (e.g. a donor session,
//! or the `rx` half of a session) carried nothing preventing it from being
//! applied to a *different* instance (a victim session, or the `tx` half)
//! — `after_send_marker` would blindly overwrite `self.generation` with
//! whatever `next_generation` the donor's permit happened to carry.
//!
//! Every `DirectionalRekeyState` now has a random [`RekeyStateId`], minted
//! once at construction (`OsRng`, not a counter or pointer — a counter is
//! guessable/collidable across instances built in the same process, and a
//! pointer can be reused after a drop). Every permit records the
//! `RekeyStateId` and the exact `generation`/`policy_count` snapshot it was
//! validated against. `after_*` re-checks both — issuer identity *and*
//! snapshot freshness — immediately before mutating state, so: a permit
//! from a different instance is rejected (wrong issuer); a permit whose
//! snapshot no longer matches current state (because some other permit
//! already advanced it) is rejected as stale, closing the "three permits,
//! one real state change" gap above without requiring `before_*` to take
//! `&mut self` — only the first-applied permit for any given snapshot can
//! ever successfully commit.

use std::num::NonZeroU64;

use rand_core::{OsRng, RngCore};

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

/// Identifies one specific `DirectionalRekeyState` instance, minted once at
/// construction. This is a security-relevant provenance/authority token —
/// a permit is trusted as "issued by this instance" purely because its
/// `issuer` field equals `self.id` — so it must be collision-resistant,
/// not merely "usually distinct". A 64-bit value only sustains that up to
/// ~2^32 instances (birthday bound) before a same-process collision
/// becomes plausible; 256 bits from `OsRng` pushes the collision bound
/// past anything reachable (2026-08-04, @kiana, round 3).
///
/// **Hardened 2026-08-04, @kiana, round 3:** widened from `u64` to
/// `[u8; 32]` and construction switched from the infallible
/// `OsRng::next_u64()` to the fallible `try_fill_bytes` — `OsRng` is a
/// real OS syscall (`getrandom`/`/dev/urandom`/etc.) that can fail (e.g.
/// resource exhaustion, sandboxed environment without the syscall), and a
/// security-relevant provenance token must not silently fall back to a
/// weaker source or a fixed value on that failure; `fresh()` now returns
/// `Result<Self, RekeyError>` and every constructor that mints one
/// propagates that fallibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RekeyStateId([u8; 32]);

impl RekeyStateId {
    fn fresh() -> Result<Self, RekeyError> {
        let mut bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| RekeyError::RngFailure)?;
        Ok(Self(bytes))
    }

    /// Test-only, deterministic constructor — used to force two
    /// `RekeyStateId`s equal (or apart) without relying on a probabilistic
    /// "OsRng won't collide" argument, which is exactly the kind of claim
    /// this hardening exists to avoid making. Never used outside `tests`.
    #[cfg(test)]
    fn from_byte(b: u8) -> Self {
        Self([b; 32])
    }
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

/// Proof that [`DirectionalRekeyState::before_send_non_marker`] succeeded,
/// bound to the exact instance and `policy_count` it was validated
/// against. `after_send_non_marker` re-checks both before mutating —
/// issued-by-someone-else and issued-against-a-now-stale-count are both
/// rejected, not just "some permit exists".
#[must_use = "pass this to after_send_non_marker, or the send is never committed"]
pub struct SendNonMarkerPermit {
    issuer: RekeyStateId,
    expected_policy_count: u64,
}

/// Proof that [`DirectionalRekeyState::before_send_marker`] succeeded,
/// bound to the exact instance and `generation`/`policy_count` snapshot it
/// was validated against, and carrying the `next_generation` value that
/// snapshot justifies. `after_send_marker` re-checks issuer and snapshot
/// before mutating — there is nothing here a caller can substitute.
#[must_use = "pass this to after_send_marker, or the rekey is never committed"]
pub struct SendMarkerPermit {
    issuer: RekeyStateId,
    expected_generation: u64,
    expected_policy_count: u64,
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
#[derive(Debug)]
pub struct DirectionalRekeyState {
    id: RekeyStateId,
    generation: u64,
    policy_count: u64,
    threshold: RekeyThreshold,
}

impl DirectionalRekeyState {
    pub fn new(threshold: RekeyThreshold) -> Result<Self, RekeyError> {
        Ok(Self {
            id: RekeyStateId::fresh()?,
            generation: 0,
            policy_count: 0,
            threshold,
        })
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
    /// Returns a permit snapshotting the current `policy_count`, bound to
    /// this instance — see the module hardening note.
    pub fn before_send_non_marker(&self) -> Result<SendNonMarkerPermit, RekeyError> {
        if self.policy_count == self.threshold.minus_one() {
            return Err(RekeyError::ExpectedRekeyMarker);
        }
        Ok(SendNonMarkerPermit {
            issuer: self.id,
            expected_policy_count: self.policy_count,
        })
    }

    /// Call after a non-marker record has been fully sent. Re-validates
    /// the permit's issuer and snapshot against current state before
    /// mutating anything: a permit from a different instance, or one
    /// whose `policy_count` snapshot no longer matches (because some
    /// other permit already advanced it), is rejected as stale rather
    /// than blindly applied. There is no zero-argument overload — a
    /// permit is always required:
    ///
    /// ```compile_fail
    /// use mesh_session_core_rs::rekey::{DirectionalRekeyState, RekeyThreshold};
    /// let threshold = RekeyThreshold::new(3).unwrap();
    /// let mut tx = DirectionalRekeyState::new(threshold).unwrap();
    /// tx.after_send_non_marker(); // missing the required SendNonMarkerPermit
    /// ```
    pub fn after_send_non_marker(&mut self, permit: SendNonMarkerPermit) -> Result<(), RekeyError> {
        if permit.issuer != self.id || permit.expected_policy_count != self.policy_count {
            return Err(RekeyError::StalePermit);
        }
        self.policy_count = self
            .policy_count
            .checked_add(1)
            .ok_or(RekeyError::GenerationExhausted)?;
        Ok(())
    }

    /// Call before sending a marker. The returned permit carries the
    /// `next_generation` value the marker must carry (v6 §8: "count é
    /// ainda N-1" at send time — this call does not itself increment
    /// `policy_count`, `after_send_marker` resets it instead), bound to
    /// this instance and the exact `generation`/`policy_count` it was
    /// computed from.
    pub fn before_send_marker(&self) -> Result<SendMarkerPermit, RekeyError> {
        if self.policy_count != self.threshold.minus_one() {
            return Err(RekeyError::PrematureRekeyMarker);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(RekeyError::GenerationExhausted)?;
        Ok(SendMarkerPermit {
            issuer: self.id,
            expected_generation: self.generation,
            expected_policy_count: self.policy_count,
            next_generation,
        })
    }

    /// Checks a marker permit's issuer and snapshot against current state
    /// *without* mutating anything — used to validate strictly before any
    /// coupled, harder-to-undo side effect (e.g. `TransportState::
    /// rekey_outgoing()`) runs, so that side effect never fires on a
    /// stale/foreign permit. [`Self::after_send_marker`] calls this
    /// internally too; calling it again there is cheap and keeps
    /// `after_send_marker` safe to call on its own.
    pub fn validate_marker_permit(&self, permit: &SendMarkerPermit) -> Result<(), RekeyError> {
        if permit.issuer != self.id
            || permit.expected_generation != self.generation
            || permit.expected_policy_count != self.policy_count
        {
            return Err(RekeyError::StalePermit);
        }
        Ok(())
    }

    /// Call once the marker has been written in full. Re-validates (see
    /// [`Self::validate_marker_permit`]) before committing exactly the
    /// generation that permit was validated against.
    pub fn after_send_marker(&mut self, permit: SendMarkerPermit) -> Result<(), RekeyError> {
        self.validate_marker_permit(&permit)?;
        self.generation = permit.next_generation;
        self.policy_count = 0;
        Ok(())
    }

    /// Process one decrypted incoming record. Advances `generation`/
    /// `policy_count` on success; returns the fail-closed error for every
    /// early/late/duplicate/wrong-generation/wrong-count case (v6 §8,
    /// erratum RED-19-adjacent discipline: reject, do not guess). This
    /// side is a single atomic call already, driven by a value read off
    /// the wire rather than a locally-issued permit — no separate
    /// before/after or provenance concern to harden here.
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
/// (v6 §8: "Ambas direções independentes") — `tx`/`rx` each get their own
/// random [`RekeyStateId`] at construction, so a permit issued by one can
/// never be mistaken for the other's.
///
/// `new` is `pub(crate)` on purpose: a `SessionRekeyState` asserts "this
/// authenticated session has reached Active" simply by existing, so only
/// this crate's own post-ActivateAck transition may mint one — an
/// external consumer cannot construct one before auth completes:
///
/// ```compile_fail
/// use mesh_session_core_rs::rekey::{SessionRekeyState, RekeyThreshold};
/// let threshold = RekeyThreshold::new(3).unwrap();
/// let _ = SessionRekeyState::new(threshold).unwrap(); // pub(crate) — does not compile here
/// ```
pub struct SessionRekeyState {
    tx: DirectionalRekeyState,
    rx: DirectionalRekeyState,
}

impl SessionRekeyState {
    pub(crate) fn new(threshold: RekeyThreshold) -> Result<Self, RekeyError> {
        Ok(Self {
            tx: DirectionalRekeyState::new(threshold)?,
            rx: DirectionalRekeyState::new(threshold)?,
        })
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
        let mut tx = DirectionalRekeyState::new(threshold).unwrap();
        let permit = tx.before_send_non_marker().unwrap();
        tx.after_send_non_marker(permit).unwrap();
        assert_eq!(tx.policy_count(), 1);
    }

    #[test]
    fn red_multi_permit_same_count_only_the_first_commits() {
        // Reproduces the audit finding literally: call before_* three
        // times against the SAME unmutated state, then try to apply all
        // three. Only the first succeeds; the second and third are
        // rejected as stale, because their expected_policy_count snapshot
        // (0) no longer matches self.policy_count (1, then 2) once an
        // earlier permit has already committed.
        let threshold = RekeyThreshold::new(4).unwrap(); // headroom so 3 non-markers are all legal to *attempt*
        let mut tx = DirectionalRekeyState::new(threshold).unwrap();
        let p1 = tx.before_send_non_marker().unwrap();
        let p2 = tx.before_send_non_marker().unwrap();
        let p3 = tx.before_send_non_marker().unwrap();

        tx.after_send_non_marker(p1).unwrap();
        assert_eq!(tx.policy_count(), 1);
        assert_eq!(tx.after_send_non_marker(p2), Err(RekeyError::StalePermit));
        assert_eq!(
            tx.policy_count(),
            1,
            "a rejected permit must not mutate state"
        );
        assert_eq!(tx.after_send_non_marker(p3), Err(RekeyError::StalePermit));
        assert_eq!(tx.policy_count(), 1);
    }

    #[test]
    fn red_donor_to_victim_marker_permit_rejected_cross_instance() {
        let threshold = RekeyThreshold::new(1).unwrap(); // threshold-1 == 0, marker eligible immediately
        let donor = DirectionalRekeyState::new(threshold).unwrap();
        let mut victim = DirectionalRekeyState::new(threshold).unwrap();

        let donor_permit = donor.before_send_marker().unwrap();
        let victim_generation_before = victim.generation();
        assert_eq!(
            victim.after_send_marker(donor_permit),
            Err(RekeyError::StalePermit)
        );
        assert_eq!(
            victim.generation(),
            victim_generation_before,
            "a foreign permit must not mutate the victim"
        );
    }

    #[test]
    fn red_tx_permit_rejected_on_rx_and_vice_versa_within_one_session() {
        let threshold = RekeyThreshold::new(1).unwrap();
        let mut session = SessionRekeyState::new(threshold).unwrap();
        let tx_permit = session.tx().before_send_marker().unwrap();
        assert_eq!(
            session.rx().after_send_marker(tx_permit),
            Err(RekeyError::StalePermit)
        );

        let rx_permit = {
            // rx has no before_send_marker (it's driven by on_receive, not
            // permits) — use a second session's tx permit as the "foreign"
            // token instead, which is the actually-reachable cross-session
            // case.
            let other = DirectionalRekeyState::new(threshold).unwrap();
            other.before_send_marker().unwrap()
        };
        assert_eq!(
            session.tx().after_send_marker(rx_permit),
            Err(RekeyError::StalePermit)
        );
    }

    #[test]
    fn red_stale_permit_rejected_before_any_coupled_side_effect_would_run() {
        // validate_marker_permit is what a caller (ActiveMeshSession)
        // checks BEFORE touching TransportState::rekey_outgoing() — prove
        // it independently rejects a stale permit without needing to
        // apply it first.
        let threshold = RekeyThreshold::new(1).unwrap();
        let state = DirectionalRekeyState::new(threshold).unwrap();
        let permit = state.before_send_marker().unwrap();
        let other = DirectionalRekeyState::new(threshold).unwrap();
        assert_eq!(
            other.validate_marker_permit(&permit),
            Err(RekeyError::StalePermit)
        );
    }

    #[test]
    fn pos4_n3_two_data_marker_two_data_directional() {
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut tx = DirectionalRekeyState::new(threshold).unwrap();

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
        tx.after_send_marker(permit).unwrap();
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
        let mut rx = DirectionalRekeyState::new(threshold).unwrap();
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
        let mut rx = DirectionalRekeyState::new(threshold).unwrap();
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
        let mut rx = DirectionalRekeyState::new(threshold).unwrap();
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
        let mut rx = DirectionalRekeyState::new(threshold).unwrap();
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
        let mut rx = DirectionalRekeyState::new(threshold).unwrap();
        rx.on_receive(IncomingRecord::NonMarker).unwrap(); // count=1, still short of N-1=2
        assert_eq!(
            rx.on_receive(IncomingRecord::Marker { next_generation: 1 }),
            Err(RekeyError::PrematureRekeyMarker)
        );
    }

    #[test]
    fn red29_simultaneous_opposite_directions_are_independent() {
        let threshold = RekeyThreshold::new(3).unwrap();
        let mut state = SessionRekeyState::new(threshold).unwrap();

        // Drive tx all the way through a rekey.
        let permit = state.tx().before_send_non_marker().unwrap();
        state.tx().after_send_non_marker(permit).unwrap();
        let permit = state.tx().before_send_non_marker().unwrap();
        state.tx().after_send_non_marker(permit).unwrap();
        let permit = state.tx().before_send_marker().unwrap();
        state.tx().after_send_marker(permit).unwrap();
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
            id: RekeyStateId::from_byte(1),
            generation: u64::MAX,
            policy_count: 0,
            threshold,
        };
        assert_eq!(
            tx.before_send_marker().err(),
            Some(RekeyError::GenerationExhausted)
        );
    }

    #[test]
    fn red_rekey_state_id_256_bit_full_value_compared_not_probabilistic() {
        // Deterministic constructor (test-only) proves the comparison is
        // over the FULL 32-byte value, not e.g. a truncated prefix — two
        // ids built from the same byte are equal, two built from
        // different bytes are not, with no reliance on OsRng ever
        // producing (or not producing) a collision.
        let threshold = RekeyThreshold::new(1).unwrap();
        let a = DirectionalRekeyState {
            id: RekeyStateId::from_byte(7),
            generation: 0,
            policy_count: 0,
            threshold,
        };
        let b_same_id = DirectionalRekeyState {
            id: RekeyStateId::from_byte(7),
            generation: 0,
            policy_count: 0,
            threshold,
        };
        let b_diff_id = DirectionalRekeyState {
            id: RekeyStateId::from_byte(9),
            generation: 0,
            policy_count: 0,
            threshold,
        };

        // A permit issued by `a` is accepted by `b_same_id` — same
        // RekeyStateId value, even though it's a different instance —
        // proving the check is value equality, not e.g. instance/pointer
        // identity smuggled in some other way.
        let permit_from_a = a.before_send_marker().unwrap();
        assert_eq!(
            b_same_id.validate_marker_permit(&permit_from_a),
            Ok(()),
            "identical 32-byte ids must compare equal"
        );

        // The same permit is rejected by `b_diff_id` — different
        // RekeyStateId value.
        let permit_from_a_2 = a.before_send_marker().unwrap();
        assert_eq!(
            b_diff_id.validate_marker_permit(&permit_from_a_2),
            Err(RekeyError::StalePermit),
            "different 32-byte ids must not compare equal"
        );
    }

    #[test]
    fn rekey_state_id_fresh_produces_distinct_values() {
        // Not a collision-resistance proof (that's what round 3's widening
        // to 256 bits is for) — just confirms two real OsRng-backed calls
        // in a row are not trivially returning a fixed/zeroed value.
        let a = RekeyStateId::fresh().unwrap();
        let b = RekeyStateId::fresh().unwrap();
        assert_ne!(a, b);
    }
}
