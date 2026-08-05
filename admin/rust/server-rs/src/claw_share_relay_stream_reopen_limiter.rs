//! Per-principal reopen-rate gate for `ClawSite` `relay_stream` dials,
//! applied by BOTH the Group/Public arm and the Device arm of the responder.
//!
//! The `OpenPersistent` byte/open budget in `household_rs::claw_share_data_tunnel`
//! bounds volume for ONE authenticated `ClawSite` connection, but that budget
//! resets on every reconnect: nothing upstream of it bounds how often a
//! principal can mint a fresh budget. This module closes that gap with a
//! small, independent, in-memory windowed counter — it does NOT depend on
//! `claw_share_relay_stream_abuse` (that guard buckets by source IP for the
//! anonymous pre-auth rendezvous pairing step, a different trust layer with a
//! ~7-orders-of-magnitude-cheaper per-event cost) and it does not touch
//! Product A/nvpn: callers (the responder's Group/Public and Device closures)
//! only invoke this for `resource == ClawSite`. `IpTunnel` — Product A/nvpn's
//! T1 datapath — and `Pty` never reach it.
//!
//! Keyed on `(claw_id, guest_device_pub)` — the SAME pair each arm's
//! authentication already proves: the offer's proof-of-possession and live
//! gate for Group/Public, and the owner-signed `GuestCredential` for Device.
//! Per-principal by decision: multiple slots/offers held by one device must
//! NOT multiply buckets, so the key is the device, not a slot or session id
//! (`RelayStreamOfferSession::session_id` is explicitly not a stable roster/
//! deny-list key). Callers must only invoke
//! [`ReopenStreamLimiter::check_and_record`] AFTER authentication succeeds —
//! checking on unauthenticated, caller-claimed fields would let an attacker
//! burn another principal's bucket by spoofing its key.
//!
//! V1 scope: single-process, in-memory, fixed window. Does not aggregate across
//! horizontally-scaled instances — the same non-goal the existing per-connection
//! budget counters already carry.

use std::collections::HashMap;
use std::sync::Mutex;

use household_rs::claw_share_data_tunnel::DataTunnelError;
use household_rs::keys::P256PublicKey;

/// Fixed-window reopen-rate defaults for V1: 8 authenticated connections per
/// 60s per `(claw_id, guest_device_pub)`, a table capacity of 65,536 tracked
/// principals, and idle eviction after 300s of inactivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReopenLimiterConfig {
    pub window_secs: u64,
    pub max_per_window: u32,
    pub table_capacity: usize,
    pub idle_ttl_secs: u64,
}

impl Default for ReopenLimiterConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            max_per_window: 8,
            table_capacity: 65_536,
            idle_ttl_secs: 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReopenLimiterKey {
    claw_id: String,
    guest_device_pub: P256PublicKey,
}

#[derive(Debug, Clone, Copy)]
struct ReopenWindowEntry {
    window_start: u64,
    count: u32,
    // Tracks the last touch (accept OR reject), not just accepts, so a
    // throttled principal who keeps hammering past their cap cannot make
    // their own entry look idle and get themselves evicted-then-refreshed
    // early by the table-full sweep.
    last_seen: u64,
}

/// Per-principal reopen-rate gate. See module docs for the key, the reset
/// boundary, and the fail-closed posture on table exhaustion / poison.
pub struct ReopenStreamLimiter {
    config: ReopenLimiterConfig,
    // Computed once at construction: a window/cap/capacity/TTL of 0 would
    // otherwise fail OPEN (window_secs == 0 makes every call look like the
    // window already elapsed, resetting to a fresh accept; max_per_window ==
    // 0 still lets the first-ever insert through, since the cap is only
    // checked on the existing-key path). Checked before touching the mutex.
    config_valid: bool,
    state: Mutex<HashMap<ReopenLimiterKey, ReopenWindowEntry>>,
}

impl ReopenStreamLimiter {
    #[must_use]
    pub fn new(config: ReopenLimiterConfig) -> Self {
        Self {
            config,
            config_valid: config.window_secs > 0
                && config.max_per_window > 0
                && config.table_capacity > 0
                && config.idle_ttl_secs > 0,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Record one authenticated-connection "mint" for `(claw_id,
    /// guest_device_pub)` at `now_unix`, rejecting once the window's cap is
    /// exceeded.
    ///
    /// Fail-closed: a poisoned mutex (a prior panic while the lock was held)
    /// rejects every future call rather than recovering into unknown state —
    /// the same "never fails open" posture the rest of this module family
    /// already declares. Table exhaustion also rejects new principals rather
    /// than evicting a live one to make room. A degenerate zero-valued config
    /// rejects every call rather than silently acting as no limit at all.
    pub fn check_and_record(
        &self,
        claw_id: &str,
        guest_device_pub: &P256PublicKey,
        now_unix: u64,
    ) -> Result<(), DataTunnelError> {
        if !self.config_valid {
            return Err(DataTunnelError::TokenRejected(
                "relay-stream-reopen-config-invalid".to_string(),
            ));
        }
        let Ok(mut table) = self.state.lock() else {
            return Err(DataTunnelError::TokenRejected(
                "relay-stream-reopen-limiter-poisoned".to_string(),
            ));
        };
        let key = ReopenLimiterKey {
            claw_id: claw_id.to_string(),
            guest_device_pub: guest_device_pub.clone(),
        };

        if let Some(entry) = table.get_mut(&key) {
            if now_unix.saturating_sub(entry.window_start) >= self.config.window_secs {
                entry.window_start = now_unix;
                entry.count = 1;
                entry.last_seen = now_unix;
                return Ok(());
            }
            entry.last_seen = now_unix;
            // Saturating: this also increments on a rejected call (see
            // ReopenWindowEntry::last_seen doc), so a principal hammering
            // well past its cap within one window must not wrap `count`
            // back around to a small, once-again-acceptable value.
            entry.count = entry.count.saturating_add(1);
            if entry.count > self.config.max_per_window {
                return Err(DataTunnelError::TokenRejected(
                    "relay-stream-reopen-rate-exceeded".to_string(),
                ));
            }
            return Ok(());
        }

        if table.len() >= self.config.table_capacity {
            // Lazy sweep: only pay the full-table scan when a NEW principal
            // actually needs room, not on every call. Eviction boundary is
            // inclusive of the TTL itself: an entry idle for EXACTLY
            // `idle_ttl_secs` still survives (`elapsed <= ttl`); only
            // `elapsed > ttl` (idle_ttl_secs + 1 and beyond) is evicted. Pinned
            // by `table_full_survives_at_exact_ttl_then_evicts_one_second_later`.
            let idle_ttl = self.config.idle_ttl_secs;
            table.retain(|_, entry| now_unix.saturating_sub(entry.last_seen) <= idle_ttl);
            if table.len() >= self.config.table_capacity {
                return Err(DataTunnelError::TokenRejected(
                    "relay-stream-reopen-table-full".to_string(),
                ));
            }
        }

        table.insert(
            key,
            ReopenWindowEntry {
                window_start: now_unix,
                count: 1,
                last_seen: now_unix,
            },
        );
        Ok(())
    }

    /// Test-only introspection: current in-window count for a key, or 0 if
    /// untracked. Lets a caller-spoofing test prove a rejected/forged auth
    /// attempt never touched the real principal's bucket.
    #[cfg(test)]
    pub(crate) fn count_for(&self, claw_id: &str, guest_device_pub: &P256PublicKey) -> u32 {
        let table = self.state.lock().expect("test-only poison check");
        let key = ReopenLimiterKey {
            claw_id: claw_id.to_string(),
            guest_device_pub: guest_device_pub.clone(),
        };
        table.get(&key).map_or(0, |entry| entry.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pub_key(tag: u8) -> P256PublicKey {
        use household_rs::keys::{IdentityKey, P256Keypair};
        // Same pattern as claw_share_relay_stream_test_support's
        // owner_pub()/guest_pub(): derive a real (on-curve) key from a fixed
        // scalar so distinct tags give distinct, deterministic keys.
        P256Keypair::from_secret_scalar(&[tag; 32])
            .unwrap()
            .public()
    }

    const CLAW_A: &str = "claw_a";
    const CLAW_B: &str = "claw_b";

    #[test]
    fn eight_accepted_ninth_rejected_within_the_window() {
        let limiter = ReopenStreamLimiter::new(ReopenLimiterConfig::default());
        let key = pub_key(1);
        let start = 1_000u64;

        for i in 0..8 {
            assert!(
                limiter.check_and_record(CLAW_A, &key, start + i).is_ok(),
                "mint {i} should be accepted"
            );
        }
        let ninth = limiter.check_and_record(CLAW_A, &key, start + 8);
        assert!(matches!(
            ninth,
            Err(DataTunnelError::TokenRejected(reason)) if reason == "relay-stream-reopen-rate-exceeded"
        ));
    }

    #[test]
    fn window_boundary_resets_the_count() {
        let limiter = ReopenStreamLimiter::new(ReopenLimiterConfig::default());
        let key = pub_key(2);
        let start = 1_000u64;

        for _ in 0..8 {
            limiter.check_and_record(CLAW_A, &key, start).unwrap();
        }
        assert!(
            limiter.check_and_record(CLAW_A, &key, start + 59).is_err(),
            "still inside the 60s window: must stay rejected"
        );
        assert!(
            limiter.check_and_record(CLAW_A, &key, start + 60).is_ok(),
            "60s fully elapsed: a fresh window must accept again"
        );
    }

    #[test]
    fn distinct_claws_and_devices_do_not_share_a_bucket() {
        let limiter = ReopenStreamLimiter::new(ReopenLimiterConfig::default());
        let device_x = pub_key(3);
        let device_y = pub_key(4);
        let start = 1_000u64;

        for _ in 0..8 {
            limiter.check_and_record(CLAW_A, &device_x, start).unwrap();
        }
        assert!(
            limiter.check_and_record(CLAW_A, &device_x, start).is_err(),
            "device_x on claw_a is exhausted"
        );
        assert!(
            limiter.check_and_record(CLAW_B, &device_x, start).is_ok(),
            "same device, different claw: independent bucket"
        );
        assert!(
            limiter.check_and_record(CLAW_A, &device_y, start).is_ok(),
            "same claw, different device: independent bucket"
        );
    }

    #[test]
    fn full_table_fails_closed_and_recovers_after_idle_ttl() {
        let limiter = ReopenStreamLimiter::new(ReopenLimiterConfig {
            window_secs: 60,
            max_per_window: 8,
            table_capacity: 2,
            idle_ttl_secs: 300,
        });
        let device_a = pub_key(5);
        let device_b = pub_key(6);
        let device_c = pub_key(7);
        let start = 1_000u64;

        assert!(limiter.check_and_record(CLAW_A, &device_a, start).is_ok());
        assert!(limiter.check_and_record(CLAW_A, &device_b, start).is_ok());

        let full = limiter.check_and_record(CLAW_A, &device_c, start + 1);
        assert!(matches!(
            full,
            Err(DataTunnelError::TokenRejected(reason)) if reason == "relay-stream-reopen-table-full"
        ));

        let still_before_ttl = limiter.check_and_record(CLAW_A, &device_c, start + 299);
        assert!(
            still_before_ttl.is_err(),
            "idle entries are not yet eligible for eviction"
        );

        let after_ttl = limiter.check_and_record(CLAW_A, &device_c, start + 301);
        assert!(
            after_ttl.is_ok(),
            "device_a/device_b went idle past the 300s TTL, freeing room for device_c"
        );
    }

    /// Pins the eviction boundary documented on `check_and_record`: idle for
    /// EXACTLY `idle_ttl_secs` still survives (inclusive), only idle_ttl_secs
    /// + 1 and beyond is evicted.
    #[test]
    fn table_full_survives_at_exact_ttl_then_evicts_one_second_later() {
        let limiter = ReopenStreamLimiter::new(ReopenLimiterConfig {
            window_secs: 60,
            max_per_window: 8,
            table_capacity: 1,
            idle_ttl_secs: 300,
        });
        let device_a = pub_key(10);
        let device_b = pub_key(11);
        let start = 1_000u64;

        assert!(limiter.check_and_record(CLAW_A, &device_a, start).is_ok());

        assert!(
            limiter
                .check_and_record(CLAW_A, &device_b, start + 300)
                .is_err(),
            "idle for exactly idle_ttl_secs must still survive (inclusive boundary)"
        );
        assert!(
            limiter
                .check_and_record(CLAW_A, &device_b, start + 301)
                .is_ok(),
            "idle for idle_ttl_secs + 1 must be evicted"
        );
    }

    #[test]
    fn zero_valued_config_fails_closed_on_every_axis() {
        let key = pub_key(12);
        let base = ReopenLimiterConfig::default();

        let zero_window = ReopenStreamLimiter::new(ReopenLimiterConfig {
            window_secs: 0,
            ..base
        });
        let zero_max = ReopenStreamLimiter::new(ReopenLimiterConfig {
            max_per_window: 0,
            ..base
        });
        let zero_table = ReopenStreamLimiter::new(ReopenLimiterConfig {
            table_capacity: 0,
            ..base
        });
        let zero_idle = ReopenStreamLimiter::new(ReopenLimiterConfig {
            idle_ttl_secs: 0,
            ..base
        });

        for (label, limiter) in [
            ("window_secs=0", &zero_window),
            ("max_per_window=0", &zero_max),
            ("table_capacity=0", &zero_table),
            ("idle_ttl_secs=0", &zero_idle),
        ] {
            assert!(
                matches!(
                    limiter.check_and_record(CLAW_A, &key, 1_000),
                    Err(DataTunnelError::TokenRejected(reason)) if reason == "relay-stream-reopen-config-invalid"
                ),
                "{label} must fail closed instead of silently acting as no limit"
            );
        }
    }

    #[test]
    fn count_saturates_instead_of_wrapping_under_sustained_rejection() {
        let limiter = ReopenStreamLimiter::new(ReopenLimiterConfig::default());
        let key = pub_key(13);
        let start = 1_000u64;
        {
            let mut table = limiter.state.lock().unwrap();
            table.insert(
                ReopenLimiterKey {
                    claw_id: CLAW_A.to_string(),
                    guest_device_pub: key.clone(),
                },
                ReopenWindowEntry {
                    window_start: start,
                    count: u32::MAX,
                    last_seen: start,
                },
            );
        }

        let rejected = limiter.check_and_record(CLAW_A, &key, start);
        assert!(
            matches!(
                rejected,
                Err(DataTunnelError::TokenRejected(reason)) if reason == "relay-stream-reopen-rate-exceeded"
            ),
            "still over cap, must stay rejected"
        );
        assert_eq!(
            limiter.count_for(CLAW_A, &key),
            u32::MAX,
            "count must saturate at u32::MAX, not wrap around to a small accept-again value"
        );
    }

    #[test]
    fn poisoned_state_fails_closed() {
        let limiter = ReopenStreamLimiter::new(ReopenLimiterConfig::default());
        let key = pub_key(8);
        let guard_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = limiter.state.lock().unwrap();
            panic!("poison the mutex on purpose");
        }));
        assert!(guard_result.is_err());

        let rejected = limiter.check_and_record(CLAW_A, &key, 1_000);
        assert!(matches!(
            rejected,
            Err(DataTunnelError::TokenRejected(reason)) if reason == "relay-stream-reopen-limiter-poisoned"
        ));
    }

    #[test]
    fn count_for_reflects_recorded_mints_only() {
        let limiter = ReopenStreamLimiter::new(ReopenLimiterConfig::default());
        let key = pub_key(9);
        assert_eq!(limiter.count_for(CLAW_A, &key), 0);
        limiter.check_and_record(CLAW_A, &key, 1_000).unwrap();
        limiter.check_and_record(CLAW_A, &key, 1_000).unwrap();
        assert_eq!(limiter.count_for(CLAW_A, &key), 2);
    }
}
