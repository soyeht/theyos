//! Clock sanity for the claw-share / VPN-T1 admission and live-recheck paths.
//!
//! Scoped deliberately to this track. The global [`crate::time_util`] helper is
//! used by device pairing, `WebAuthn`, household and bootstrap flows; widening
//! its policy would change those without their own review, so the stronger
//! property lives here and is opt-in.
//!
//! # Why a floor
//!
//! Expiry (`offer.not_after`, `slot.expires_at`) is enforced by comparing
//! against a server-supplied `now`. A `now` of `0` makes `not_after <= now`
//! ALWAYS false, so nothing ever expires — fail-open on the only temporal
//! authority in the system. A merely *late* clock weakens expiry
//! proportionally (a clock reading 2020 treats a 2026 offer as still valid).
//!
//! `SystemTime::now().duration_since(UNIX_EPOCH)` returns `Err` only when the
//! clock is *before* 1970. A host with no RTC, or one that has not reached NTP
//! sync, typically reports exactly `1970-01-01`, which returns **`Ok(0)`** —
//! the success branch. Refusing only the `Err` branch (or substituting a
//! sentinel for it) leaves the principal hole open while looking fixed.
//!
//! # Why two clocks, never one in place of the other
//!
//! - **Wall alone** is defeated by rollback: moving the clock back (to any
//!   value, even one above the floor) would keep a session alive.
//! - **Monotonic alone under-enforces a wall-signed bound.** `not_after` is
//!   signed in wall time; `CLOCK_MONOTONIC` freezes across suspend while real
//!   time runs, so a host that sleeps for three days resumes with a small
//!   elapsed and a session whose signed `not_after` has really passed still
//!   looks valid. That is theyos#336 (a HIGH, merged as `66403fcd`), whose
//!   recorded contract requires keeping the signed wall expiry and expiring on
//!   `monotonic >= deadline || wall >= signed expiry`.
//!
//! [`SessionClock`] keeps BOTH and revokes on the MORE RESTRICTIVE outcome.
//! Monotonic time may only ADD restriction; it never replaces the wall check.
//! Never `max(observed, floor)` — masking a failure prolongs exactly the
//! session that should die.

use std::time::{Duration, Instant};

/// Lower bound for a plausible wall clock: 2026-01-01T00:00:00Z.
///
/// Local and named on purpose: it must never be derived from the offer, or a
/// signed input would define the gate that judges it.
///
/// This is the earliest supported deployment instant — a policy floor, not a
/// build stamp. It only has to be earlier than any real deployment and late
/// enough to exclude a cold-boot/pre-NTP clock, so it never needs to track
/// "now" and never needs bumping as the code ages.
pub const MIN_PLAUSIBLE_UNIX_SECS: u64 = 1_767_225_600;

/// Apply the sanity floor to an already-read unix timestamp.
///
/// Pure and total, so the floor is testable without touching the host clock.
/// Returns `None` for `0` and for anything else below [`MIN_PLAUSIBLE_UNIX_SECS`].
#[must_use]
pub fn plausible_unix_secs(secs: u64) -> Option<u64> {
    (secs >= MIN_PLAUSIBLE_UNIX_SECS).then_some(secs)
}

/// Read the wall clock for this track, refusing implausible readings.
///
/// `None` when the clock is before the epoch (`Err`), at the epoch (`Ok(0)`),
/// or below the floor. Callers MUST fail closed.
pub fn wall_now_secs(stage: &'static str) -> Option<u64> {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            let sane = plausible_unix_secs(d.as_secs());
            if sane.is_none() {
                tracing::warn!(
                    stage = stage,
                    floor = MIN_PLAUSIBLE_UNIX_SECS,
                    "system clock is implausibly early; failing closed"
                );
            }
            sane
        }
        Err(e) => {
            tracing::warn!(
                stage = stage,
                error = %e,
                "system clock is before UNIX_EPOCH"
            );
            None
        }
    }
}

/// An admission's clock pair, captured once.
///
/// The monotonic anchor is sampled BEFORE the wall reading, so any delay or
/// suspend between the two can only make the derived deadline *earlier* (more
/// restrictive), never later. Transport this pair; never synthesise a fresh
/// anchor downstream, which would restart the session's life.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionInstant {
    wall: u64,
    anchor: Instant,
}

impl AdmissionInstant {
    /// Sample the pair now, or `None` if the wall clock is implausible.
    #[must_use]
    pub fn capture(stage: &'static str) -> Option<Self> {
        Self::capture_with(|| wall_now_secs(stage))
    }

    /// [`Self::capture`] reading the wall clock through an injectable seam.
    ///
    /// The anchor is sampled BEFORE the seam runs, so however long the seam
    /// takes, the derived deadline can only end up EARLIER (more restrictive),
    /// never later. This is the only production way to pair an injected clock:
    /// reading the wall first and anchoring afterwards is the late-anchor bug.
    #[must_use]
    pub fn capture_with(seam: impl FnOnce() -> Option<u64>) -> Option<Self> {
        let anchor = Instant::now();
        Self::capture_at(anchor, seam())
    }

    /// [`Self::capture`] with the wall reading injected, so admission refusal
    /// is provable for `Err` (`None`), `Ok(0)` and below-floor inputs rather
    /// than inferred from reading the composition.
    fn capture_at(anchor: Instant, wall: Option<u64>) -> Option<Self> {
        let wall = plausible_unix_secs(wall?)?;
        Some(Self { wall, anchor })
    }

    /// Pair a synthetic wall reading with an anchor taken now — TESTS ONLY.
    ///
    /// This anchors AFTER the wall value, which is the late-anchor shape that
    /// must never reach production; it exists so tests can drive a synthetic
    /// clock. Production paths use [`Self::capture_with`].
    #[cfg(test)]
    #[must_use]
    pub fn from_seam_wall(wall: u64) -> Option<Self> {
        Self::capture_at(Instant::now(), Some(wall))
    }

    /// The admission wall time, so the SAME value feeds admission/handshake
    /// rather than each caller reading its own `now`.
    #[must_use]
    pub fn wall(self) -> u64 {
        self.wall
    }
}

/// Why a session may not proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockVerdict {
    /// The wall clock is unusable: before the epoch, at it, or below the floor.
    ImplausibleWallClock,
    /// The offer's signed `not_after` has passed on a direct wall re-read.
    /// Catches suspend and forward jumps.
    SignedExpiryPassed,
    /// The monotonic deadline derived at admission has passed. Catches a
    /// rolled-back or frozen wall clock.
    MonotonicDeadlinePassed,
    /// The wall clock moved backwards relative to the monotonic lower bound.
    WallRegressed,
    /// The monotonic clock itself regressed: a live reading landed BEFORE the
    /// admission anchor. Never saturated to zero — that would mask the failure
    /// and could keep the session alive.
    MonotonicRegressed,
    /// A derivation overflowed.
    Overflow,
}

/// A session's dual-clock authority, derived once at admission.
#[derive(Debug, Clone)]
pub struct SessionClock {
    accepted_at: u64,
    /// The SIGNED wall bound. Never recomputed, never replaced.
    not_after: u64,
    anchor: Instant,
    /// Monotonic deadline derived at admission via `checked_add`.
    deadline: Instant,
    stage: &'static str,
}

impl SessionClock {
    /// Admit a session from a captured pair, or refuse it BEFORE Open.
    ///
    /// Refuses when the offer has already expired at admission or when
    /// deriving the monotonic deadline overflows.
    pub fn admit(
        admission: AdmissionInstant,
        not_after: u64,
        stage: &'static str,
    ) -> Result<Self, ClockVerdict> {
        let accepted_at = admission.wall;
        let ttl_secs = not_after
            .checked_sub(accepted_at)
            .ok_or(ClockVerdict::SignedExpiryPassed)?;
        if ttl_secs == 0 {
            return Err(ClockVerdict::SignedExpiryPassed);
        }
        let deadline = admission
            .anchor
            .checked_add(Duration::from_secs(ttl_secs))
            .ok_or(ClockVerdict::Overflow)?;
        Ok(Self {
            accepted_at,
            not_after,
            anchor: admission.anchor,
            deadline,
            stage,
        })
    }

    /// The live time for a mid-session recheck.
    ///
    /// `Err` MUST be treated as revoked. Reads the wall clock directly — it is
    /// NOT derived from the anchor, which would inherit monotonic blindness to
    /// suspend.
    pub fn live_now(&self) -> Result<u64, ClockVerdict> {
        self.live_at(wall_now_secs(self.stage), Instant::now())
    }

    /// [`Self::live_now`] with both clock readings injected, so every branch is
    /// provable without touching the host clock.
    ///
    /// Revokes if ANY fires — the more restrictive always wins.
    fn live_at(&self, wall: Option<u64>, mono_now: Instant) -> Result<u64, ClockVerdict> {
        // Monotonic deadline: catches rollback and a frozen wall clock.
        if mono_now >= self.deadline {
            return Err(ClockVerdict::MonotonicDeadlinePassed);
        }
        // Revalidate rather than trusting that the caller floor-checked it.
        let wall = wall
            .and_then(plausible_unix_secs)
            .ok_or(ClockVerdict::ImplausibleWallClock)?;
        // Direct wall re-read against the SIGNED bound: catches suspend and
        // forward jumps (theyos#336).
        if wall >= self.not_after {
            return Err(ClockVerdict::SignedExpiryPassed);
        }
        // Wall regression relative to the monotonic lower bound.
        // NOT saturating: a monotonic reading before the anchor is a failure,
        // and saturating it to zero would mask that and keep the session alive.
        let elapsed = mono_now
            .checked_duration_since(self.anchor)
            .ok_or(ClockVerdict::MonotonicRegressed)?
            .as_secs();
        let lower_bound = self
            .accepted_at
            .checked_add(elapsed)
            .ok_or(ClockVerdict::Overflow)?;
        if wall < lower_bound {
            return Err(ClockVerdict::WallRegressed);
        }
        Ok(wall)
    }

    /// Drive the live gate through the same admitted clock in integration
    /// tests without changing the host wall clock.
    #[cfg(test)]
    pub(crate) fn live_at_for_test(
        &self,
        wall: Option<u64>,
        elapsed: Duration,
    ) -> Result<u64, ClockVerdict> {
        let mono_now = self
            .anchor
            .checked_add(elapsed)
            .ok_or(ClockVerdict::Overflow)?;
        self.live_at(wall, mono_now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: u64 = MIN_PLAUSIBLE_UNIX_SECS;

    /// A coherent admission built through the real constructor.
    fn admitted(accepted_at: u64, ttl: u64) -> SessionClock {
        let admission = AdmissionInstant {
            wall: accepted_at,
            anchor: Instant::now(),
        };
        SessionClock::admit(admission, accepted_at + ttl, "test").expect("admits")
    }

    #[test]
    fn floor_rejects_zero_clock() {
        // The principal hole: a cold-boot/pre-NTP host reports exactly the
        // epoch, which is `Ok(0)` — the SUCCESS branch, not `Err`.
        assert_eq!(plausible_unix_secs(0), None);
    }

    #[test]
    fn floor_rejects_late_but_nonzero_clock() {
        assert_eq!(plausible_unix_secs(FLOOR - 1), None);
        assert_eq!(plausible_unix_secs(1_577_836_800), None); // 2020-01-01
    }

    #[test]
    fn floor_accepts_itself_and_later() {
        assert_eq!(plausible_unix_secs(FLOOR), Some(FLOOR));
        assert_eq!(plausible_unix_secs(FLOOR + 86_400), Some(FLOOR + 86_400));
    }

    #[test]
    fn admit_rejects_offer_already_expired() {
        let admission = AdmissionInstant {
            wall: FLOOR + 100,
            anchor: Instant::now(),
        };
        assert_eq!(
            SessionClock::admit(admission, FLOOR + 100, "test").unwrap_err(),
            ClockVerdict::SignedExpiryPassed
        );
        assert_eq!(
            SessionClock::admit(admission, FLOOR + 50, "test").unwrap_err(),
            ClockVerdict::SignedExpiryPassed
        );
    }

    #[test]
    fn admit_rejects_deadline_overflow() {
        // A ttl large enough to overflow the monotonic deadline must be refused
        // BEFORE Open rather than wrapping into a short or absurd deadline.
        let admission = AdmissionInstant {
            wall: FLOOR,
            anchor: Instant::now(),
        };
        assert_eq!(
            SessionClock::admit(admission, u64::MAX, "test").unwrap_err(),
            ClockVerdict::Overflow
        );
    }

    #[test]
    fn live_revokes_on_implausible_wall_clock() {
        // Err / Ok(0) / below-floor all arrive here as `None`, injected rather
        // than inferred from the host.
        let clock = admitted(FLOOR, 600);
        assert_eq!(
            clock.live_at(None, clock.anchor),
            Err(ClockVerdict::ImplausibleWallClock)
        );
    }

    #[test]
    fn live_revokes_when_signed_expiry_passed_with_monotonic_still_short() {
        // THE SUSPEND CASE (theyos#336): the monotonic deadline has NOT fired
        // (mono barely moved), so only the direct wall re-read can catch that
        // the signed bound is already past. If this fails, the implementation
        // has regressed to monotonic-only.
        let clock = admitted(FLOOR, 600);
        let mono_now = clock.anchor + Duration::from_secs(1);
        assert!(mono_now < clock.deadline, "monotonic term must not fire");
        assert_eq!(
            clock.live_at(Some(FLOOR + 600), mono_now),
            Err(ClockVerdict::SignedExpiryPassed)
        );
    }

    #[test]
    fn live_revokes_when_monotonic_deadline_passed_with_wall_still_live() {
        // The mirror case: the wall says the session is fine, only the
        // monotonic deadline catches a frozen/rolled-back clock.
        let clock = admitted(FLOOR, 600);
        let mono_now = clock.anchor + Duration::from_secs(601);
        assert_eq!(
            clock.live_at(Some(FLOOR + 1), mono_now),
            Err(ClockVerdict::MonotonicDeadlinePassed)
        );
    }

    #[test]
    fn live_revokes_on_wall_regression_above_the_floor() {
        // Rollback to a value still above the floor must not prolong.
        let clock = admitted(FLOOR + 10_000, 600);
        let mono_now = clock.anchor + Duration::from_secs(300);
        assert_eq!(
            clock.live_at(Some(FLOOR + 1), mono_now),
            Err(ClockVerdict::WallRegressed)
        );
    }

    #[test]
    fn admission_refuses_implausible_wall_readings() {
        // Err (`None`), Ok(0) and a below-floor clock must all refuse BEFORE
        // Open — injected, not inferred.
        let anchor = Instant::now();
        assert!(AdmissionInstant::capture_at(anchor, None).is_none());
        assert!(AdmissionInstant::capture_at(anchor, Some(0)).is_none());
        assert!(AdmissionInstant::capture_at(anchor, Some(FLOOR - 1)).is_none());
        assert!(AdmissionInstant::capture_at(anchor, Some(FLOOR)).is_some());
    }

    #[test]
    fn live_revokes_on_implausible_wall_even_if_some() {
        // A `Some` that is below the floor must still revoke: `live_at`
        // revalidates instead of trusting the caller.
        let clock = admitted(FLOOR, 600);
        let mono_now = clock.anchor + Duration::from_secs(1);
        assert_eq!(
            clock.live_at(Some(0), mono_now),
            Err(ClockVerdict::ImplausibleWallClock)
        );
        assert_eq!(
            clock.live_at(Some(FLOOR - 1), mono_now),
            Err(ClockVerdict::ImplausibleWallClock)
        );
    }

    #[test]
    fn live_revokes_when_monotonic_clock_regresses() {
        // A live monotonic reading BEFORE the anchor must revoke, not saturate
        // to elapsed = 0 and let the session continue.
        // Build the anchor in the FUTURE and read from `base`, so the fixture
        // never subtracts from a real `Instant` (which would underflow on a
        // host with an uptime below the offset).
        let base = Instant::now();
        let admission = AdmissionInstant {
            wall: FLOOR,
            anchor: base + Duration::from_secs(5),
        };
        let clock = SessionClock::admit(admission, FLOOR + 600, "test").expect("admits");
        assert_eq!(
            clock.live_at(Some(FLOOR + 1), base),
            Err(ClockVerdict::MonotonicRegressed)
        );
    }

    #[test]
    fn live_allows_a_healthy_session() {
        // Sanity: this must not have become fail-closed for everything.
        let clock = admitted(FLOOR, 600);
        let mono_now = clock.anchor + Duration::from_secs(10);
        assert_eq!(clock.live_at(Some(FLOOR + 10), mono_now), Ok(FLOOR + 10));
    }
}
