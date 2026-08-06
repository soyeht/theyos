//! Real wall-clock `Clock` for `mesh_session_core_rs::intent::Clock`. No
//! adapter needed — the trait's own contract (`mesh-session-core-rs/src/
//! intent.rs`, `Clock` doc) requires only a fresh, non-blocking, bounded
//! reading; a direct `SystemTime::now()` read satisfies it exactly, with
//! zero dependency on household-rs/keystore-rs. `now()` returns Unix
//! seconds, matching this workspace's existing `not_after`/deadline-style
//! `u64` convention throughout mesh-session-core-rs.

use std::time::{SystemTime, UNIX_EPOCH};

use mesh_session_core_rs::error::IntentError;
use mesh_session_core_rs::intent::Clock;

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64, IntentError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| IntentError::ClockUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_a_plausible_unix_timestamp() {
        let clock = SystemClock;
        let now = clock.now().unwrap();
        // 2026-01-01T00:00:00Z, loosely — proves this reads a real clock,
        // not a stub returning 0 or a fixed constant.
        assert!(now > 1_767_225_600);
    }

    #[test]
    fn system_clock_is_non_blocking_and_monotonic_enough_for_two_consecutive_reads() {
        let clock = SystemClock;
        let first = clock.now().unwrap();
        let second = clock.now().unwrap();
        assert!(second >= first);
    }
}
