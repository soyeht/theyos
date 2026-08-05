//! Real `keystore_rs::mesh_session_bridge::ClockSource` (D4's own `Clock`,
//! distinct from `mesh_session_core_rs::intent::Clock` — see this crate's
//! `clock.rs` for that one). Same reasoning as `SystemClock`: the trait's
//! only contract is a fresh, non-blocking `u64` Unix-seconds reading, and
//! `SystemTime::now()` satisfies it directly. Infallible by signature
//! (`crate::sign::Clock::now(&self) -> u64`, no `Result`) — unlike
//! `mesh_session_core_rs::intent::Clock`, there is no `IntentError` to
//! report through, so a clock failure here has nowhere honest to go but a
//! panic; kept narrow (`expect`, not a silent zero) so it fails loudly
//! rather than reporting a plausible-looking wrong timestamp.

use std::time::{SystemTime, UNIX_EPOCH};

use keystore_rs::mesh_session_bridge::ClockSource;

pub struct SystemD4Clock;

impl ClockSource for SystemD4Clock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_d4_clock_returns_a_plausible_unix_timestamp() {
        let clock = SystemD4Clock;
        // 2026-01-01T00:00:00Z, loosely — proves this reads a real clock,
        // not a stub returning 0 or a fixed constant.
        assert!(clock.now() > 1_767_225_600);
    }

    #[test]
    fn system_d4_clock_is_monotonic_enough_for_two_consecutive_reads() {
        let clock = SystemD4Clock;
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
    }
}
