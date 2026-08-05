//! Aggregate, secret-free observability for the blind rendezvous stream relay.
//!
//! This module intentionally exposes only process-local counters and a
//! serializable snapshot. It does not know about household state, owner keys, or
//! source IP identities. Exact source buckets stay out of the default status
//! surface; operators get aggregate health and drop counts without turning the
//! relay into a source-surveillance log.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use serde::Serialize;

use crate::claw_share_relay_stream_abuse::RelayRejectReason;
use crate::claw_share_rendezvous_stream_relay::RendezvousRejectReason;
use crate::claw_share_rendezvous_stream_relay_listener::RendezvousStreamRelayListenerConfig;

#[derive(Clone, Debug)]
pub struct RendezvousStreamRelayStatusHandle {
    inner: Arc<RendezvousStreamRelayStatusInner>,
}

impl RendezvousStreamRelayStatusHandle {
    pub fn new(
        bind_addr: impl Into<String>,
        public_mode: bool,
        config: &RendezvousStreamRelayListenerConfig,
    ) -> Self {
        Self {
            inner: Arc::new(RendezvousStreamRelayStatusInner {
                started_at: Instant::now(),
                bind_addr: bind_addr.into(),
                public_mode,
                limits: RendezvousStreamRelayLimitSnapshot::from_config(config),
                active_connections: AtomicUsize::new(0),
                pending_tokens: AtomicUsize::new(0),
                source_buckets: AtomicUsize::new(0),
                accepted_connections: AtomicU64::new(0),
                parked_hellos: AtomicU64::new(0),
                paired_sessions: AtomicU64::new(0),
                splice_closed: AtomicU64::new(0),
                splice_idle_timeout: AtomicU64::new(0),
                splice_lifetime_elapsed: AtomicU64::new(0),
                splice_failed: AtomicU64::new(0),
                splice_byte_cap_exceeded_guest_to_claw: AtomicU64::new(0),
                splice_byte_cap_exceeded_claw_to_guest: AtomicU64::new(0),
                pending_expired: AtomicU64::new(0),
                source_buckets_pruned: AtomicU64::new(0),
                bytes_guest_to_claw: AtomicU64::new(0),
                bytes_claw_to_guest: AtomicU64::new(0),
                drops: RendezvousStreamRelayDropAtomicCounters::default(),
            }),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> RendezvousStreamRelayStatusSnapshot {
        RendezvousStreamRelayStatusSnapshot {
            enabled: true,
            bind_addr: self.inner.bind_addr.clone(),
            public_mode: self.inner.public_mode,
            external_reachability: "not_checked",
            uptime_secs: self.inner.started_at.elapsed().as_secs(),
            active_connections: self.inner.active_connections.load(Ordering::Relaxed),
            pending_tokens: self.inner.pending_tokens.load(Ordering::Relaxed),
            source_buckets: self.inner.source_buckets.load(Ordering::Relaxed),
            limits: self.inner.limits.clone(),
            counters: RendezvousStreamRelayAggregateCounters {
                accepted_connections: self.inner.accepted_connections.load(Ordering::Relaxed),
                parked_hellos: self.inner.parked_hellos.load(Ordering::Relaxed),
                paired_sessions: self.inner.paired_sessions.load(Ordering::Relaxed),
                splice_closed: self.inner.splice_closed.load(Ordering::Relaxed),
                splice_idle_timeout: self.inner.splice_idle_timeout.load(Ordering::Relaxed),
                splice_lifetime_elapsed: self.inner.splice_lifetime_elapsed.load(Ordering::Relaxed),
                splice_failed: self.inner.splice_failed.load(Ordering::Relaxed),
                splice_byte_cap_exceeded_guest_to_claw: self
                    .inner
                    .splice_byte_cap_exceeded_guest_to_claw
                    .load(Ordering::Relaxed),
                splice_byte_cap_exceeded_claw_to_guest: self
                    .inner
                    .splice_byte_cap_exceeded_claw_to_guest
                    .load(Ordering::Relaxed),
                pending_expired: self.inner.pending_expired.load(Ordering::Relaxed),
                source_buckets_pruned: self.inner.source_buckets_pruned.load(Ordering::Relaxed),
                bytes_guest_to_claw: self.inner.bytes_guest_to_claw.load(Ordering::Relaxed),
                bytes_claw_to_guest: self.inner.bytes_claw_to_guest.load(Ordering::Relaxed),
            },
            drops: self.inner.drops.snapshot(),
        }
    }

    pub(crate) fn record_connection_opened(&self) {
        self.inner
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .accepted_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_connection_closed(&self) {
        self.inner
            .active_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(1))
            })
            .ok();
    }

    pub(crate) fn set_pending_tokens(&self, pending_tokens: usize) {
        self.inner
            .pending_tokens
            .store(pending_tokens, Ordering::Relaxed);
    }

    pub(crate) fn set_source_buckets(&self, source_buckets: usize) {
        self.inner
            .source_buckets
            .store(source_buckets, Ordering::Relaxed);
    }

    pub(crate) fn record_pending_expired(&self, expired: usize) {
        self.inner
            .pending_expired
            .fetch_add(expired as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_source_buckets_pruned(&self, pruned: usize) {
        self.inner
            .source_buckets_pruned
            .fetch_add(pruned as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_parked(&self) {
        self.inner.parked_hellos.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_pair(&self) {
        self.inner.paired_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_splice_closed(&self, guest_to_claw: u64, claw_to_guest: u64) {
        self.inner.splice_closed.fetch_add(1, Ordering::Relaxed);
        self.inner
            .bytes_guest_to_claw
            .fetch_add(guest_to_claw, Ordering::Relaxed);
        self.inner
            .bytes_claw_to_guest
            .fetch_add(claw_to_guest, Ordering::Relaxed);
    }

    /// Bytes are the observational ledger's snapshot: this splice ended by
    /// cancellation, so they are what was forwarded before the timer fired.
    /// They land in the SAME cumulative byte counters as a normal close — a
    /// forwarded byte is a forwarded byte regardless of how the splice ended.
    pub(crate) fn record_splice_idle_timeout(&self, guest_to_claw: u64, claw_to_guest: u64) {
        self.inner
            .splice_idle_timeout
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .bytes_guest_to_claw
            .fetch_add(guest_to_claw, Ordering::Relaxed);
        self.inner
            .bytes_claw_to_guest
            .fetch_add(claw_to_guest, Ordering::Relaxed);
    }

    /// See [`Self::record_splice_idle_timeout`] — same cancellation shape.
    pub(crate) fn record_splice_lifetime_elapsed(&self, guest_to_claw: u64, claw_to_guest: u64) {
        self.inner
            .splice_lifetime_elapsed
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .bytes_guest_to_claw
            .fetch_add(guest_to_claw, Ordering::Relaxed);
        self.inner
            .bytes_claw_to_guest
            .fetch_add(claw_to_guest, Ordering::Relaxed);
    }

    pub(crate) fn record_splice_failed(&self) {
        self.inner.splice_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_splice_byte_cap_exceeded(
        &self,
        direction: crate::claw_share_rendezvous_stream_relay::SpliceByteCapDirection,
        guest_to_claw: u64,
        claw_to_guest: u64,
    ) {
        match direction {
            crate::claw_share_rendezvous_stream_relay::SpliceByteCapDirection::GuestToClaw => {
                self.inner
                    .splice_byte_cap_exceeded_guest_to_claw
                    .fetch_add(1, Ordering::Relaxed);
            }
            crate::claw_share_rendezvous_stream_relay::SpliceByteCapDirection::ClawToGuest => {
                self.inner
                    .splice_byte_cap_exceeded_claw_to_guest
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        self.inner
            .bytes_guest_to_claw
            .fetch_add(guest_to_claw, Ordering::Relaxed);
        self.inner
            .bytes_claw_to_guest
            .fetch_add(claw_to_guest, Ordering::Relaxed);
    }

    pub(crate) fn record_global_active_limit_drop(&self) {
        self.inner
            .drops
            .global_active_limit
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_abuse_gate_failure(&self, failure: RelayStatusAbuseGateFailure) {
        match failure {
            RelayStatusAbuseGateFailure::Rejected(reason) => match reason {
                RelayRejectReason::SourceBucketTableFull => {
                    self.inner
                        .drops
                        .source_bucket_table_full
                        .fetch_add(1, Ordering::Relaxed);
                }
                RelayRejectReason::UnpairedActiveLimit => {
                    self.inner
                        .drops
                        .source_unpaired_active_limit
                        .fetch_add(1, Ordering::Relaxed);
                }
                RelayRejectReason::PendingLimit => {
                    self.inner
                        .drops
                        .source_pending_limit
                        .fetch_add(1, Ordering::Relaxed);
                }
                RelayRejectReason::HelloAttemptRateLimited => {
                    self.inner
                        .drops
                        .hello_attempt_rate_limited
                        .fetch_add(1, Ordering::Relaxed);
                }
                RelayRejectReason::FailedHelloRateLimited => {
                    self.inner
                        .drops
                        .failed_hello_rate_limited
                        .fetch_add(1, Ordering::Relaxed);
                }
                RelayRejectReason::PairedSpliceLimit => {
                    self.inner
                        .drops
                        .source_paired_splice_limit
                        .fetch_add(1, Ordering::Relaxed);
                }
            },
            RelayStatusAbuseGateFailure::StateUnavailable => {
                self.inner
                    .drops
                    .abuse_state_unavailable
                    .fetch_add(1, Ordering::Relaxed);
            }
            RelayStatusAbuseGateFailure::UnexpectedPermit => {
                self.inner
                    .drops
                    .unexpected_abuse_permit
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn record_hello_error(&self, kind: RelayStatusHelloErrorKind) {
        match kind {
            RelayStatusHelloErrorKind::Timeout => {
                self.inner
                    .drops
                    .hello_timeout
                    .fetch_add(1, Ordering::Relaxed);
            }
            RelayStatusHelloErrorKind::Malformed => {
                self.inner
                    .drops
                    .malformed_hello
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(crate) fn record_offer_rejected(&self, reason: RendezvousRejectReason) {
        match reason {
            RendezvousRejectReason::TokenConsumed => {
                self.inner
                    .drops
                    .offer_token_consumed
                    .fetch_add(1, Ordering::Relaxed);
            }
            RendezvousRejectReason::DuplicateRole => {
                self.inner
                    .drops
                    .offer_duplicate_role
                    .fetch_add(1, Ordering::Relaxed);
            }
            RendezvousRejectReason::Expired => {
                self.inner
                    .drops
                    .offer_expired
                    .fetch_add(1, Ordering::Relaxed);
            }
            RendezvousRejectReason::CapacityExceeded => {
                self.inner
                    .drops
                    .offer_capacity_exceeded
                    .fetch_add(1, Ordering::Relaxed);
            }
            RendezvousRejectReason::ConsumedCapacityExceeded => {
                self.inner
                    .drops
                    .offer_consumed_capacity_exceeded
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayStatusAbuseGateFailure {
    Rejected(RelayRejectReason),
    StateUnavailable,
    UnexpectedPermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayStatusHelloErrorKind {
    Timeout,
    Malformed,
}

#[derive(Debug)]
struct RendezvousStreamRelayStatusInner {
    started_at: Instant,
    bind_addr: String,
    public_mode: bool,
    limits: RendezvousStreamRelayLimitSnapshot,
    active_connections: AtomicUsize,
    pending_tokens: AtomicUsize,
    source_buckets: AtomicUsize,
    accepted_connections: AtomicU64,
    parked_hellos: AtomicU64,
    paired_sessions: AtomicU64,
    splice_closed: AtomicU64,
    splice_idle_timeout: AtomicU64,
    splice_lifetime_elapsed: AtomicU64,
    splice_failed: AtomicU64,
    splice_byte_cap_exceeded_guest_to_claw: AtomicU64,
    splice_byte_cap_exceeded_claw_to_guest: AtomicU64,
    pending_expired: AtomicU64,
    source_buckets_pruned: AtomicU64,
    bytes_guest_to_claw: AtomicU64,
    bytes_claw_to_guest: AtomicU64,
    drops: RendezvousStreamRelayDropAtomicCounters,
}

/// Two measurement classes live in here, and confusing them produces wrong
/// alerts. The distinction is documented rather than encoded in the field
/// names because these names ARE the `/status` wire format (no
/// `#[serde(rename)]` anywhere), so renaming them would be a breaking change
/// for any operator scraping it.
///
/// - **LIVE GAUGES** — instantaneous, can go DOWN: [`Self::active_connections`],
///   [`Self::pending_tokens`], [`Self::source_buckets`]. Alert on their level.
/// - **CUMULATIVE COUNTERS** — monotonic for the life of the process, never
///   reset or decremented: everything nested under [`Self::counters`] and
///   [`Self::drops`]. Alert on their RATE; a raw level is just uptime.
/// - [`Self::uptime_secs`] is monotonic too, but derived from the clock rather
///   than counted, so it belongs to neither class.
///
/// The nesting is the only structural hint (gauges at top level, cumulative
/// under `counters`/`drops`) and it is NOT airtight — `uptime_secs` sits at
/// top level and is monotonic. Trust this doc, not the shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RendezvousStreamRelayStatusSnapshot {
    pub enabled: bool,
    pub bind_addr: String,
    pub public_mode: bool,
    pub external_reachability: &'static str,
    /// Monotonic, but clock-derived — neither a gauge nor a counted total.
    pub uptime_secs: u64,
    /// LIVE GAUGE: connections open right now. Incremented on accept and
    /// decremented on drop (RAII permit), so it falls back to 0 when idle.
    pub active_connections: usize,
    /// LIVE GAUGE: tokens currently awaiting their pair.
    pub pending_tokens: usize,
    /// LIVE GAUGE: per-source buckets currently held.
    pub source_buckets: usize,
    pub limits: RendezvousStreamRelayLimitSnapshot,
    pub counters: RendezvousStreamRelayAggregateCounters,
    pub drops: RendezvousStreamRelayDropCounters,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RendezvousStreamRelayLimitSnapshot {
    pub max_active_connections: usize,
    pub max_pending: usize,
    pub token_ttl_secs: u64,
    pub hello_timeout_secs: u64,
    pub splice_idle_timeout_secs: u64,
    pub splice_max_lifetime_secs: u64,
    pub splice_max_bytes_per_direction: Option<u64>,
    pub max_unpaired_active_per_source: usize,
    pub max_pending_per_source: usize,
    pub max_hello_attempts_per_source_per_window: u32,
    pub max_failed_hellos_per_source_per_window: u32,
    pub max_paired_splices_per_source: Option<usize>,
    pub hello_attempt_window_secs: u64,
    pub source_state_ttl_secs: u64,
    pub max_source_buckets: usize,
    pub ipv6_source_prefix_len: u8,
}

impl RendezvousStreamRelayLimitSnapshot {
    fn from_config(config: &RendezvousStreamRelayListenerConfig) -> Self {
        Self {
            max_active_connections: config.max_active_connections,
            max_pending: config.max_pending,
            token_ttl_secs: config.token_ttl.as_secs(),
            hello_timeout_secs: config.hello_timeout.as_secs(),
            splice_idle_timeout_secs: config.splice_idle_timeout.as_secs(),
            splice_max_lifetime_secs: config.splice_max_lifetime.as_secs(),
            splice_max_bytes_per_direction: config.splice_max_bytes_per_direction,
            max_unpaired_active_per_source: config.abuse.max_unpaired_active_per_source,
            max_pending_per_source: config.abuse.max_pending_per_source,
            max_hello_attempts_per_source_per_window: config
                .abuse
                .max_hello_attempts_per_source_per_window,
            max_failed_hellos_per_source_per_window: config
                .abuse
                .max_failed_hellos_per_source_per_window,
            max_paired_splices_per_source: config.abuse.max_paired_splices_per_source,
            hello_attempt_window_secs: config.abuse.hello_attempt_window.as_secs(),
            source_state_ttl_secs: config.abuse.source_state_ttl.as_secs(),
            max_source_buckets: config.abuse.max_source_buckets,
            ipv6_source_prefix_len: config.abuse.ipv6_source_prefix_len,
        }
    }
}

/// **Every field here is CUMULATIVE** — monotonic for the process lifetime,
/// never decremented and never reset. Alert on rate, not level.
///
/// In particular `paired_sessions` is a lifetime total, NOT a count of
/// currently-paired sessions; there is no live gauge for that. The
/// live-connection gauge is `RendezvousStreamRelayStatusSnapshot
/// ::active_connections`, one level up — note how close
/// `accepted_connections` (cumulative, here) and `active_connections`
/// (gauge, there) read, which is exactly why this is written down.
///
/// The two byte totals accumulate across ALL splice endings that can report
/// bytes — normal close, byte-cap, idle timeout and lifetime expiry alike.
/// They under-count only the I/O-error path, a documented debt (see the `Err`
/// arm in `claw_share_rendezvous_stream_relay_listener.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RendezvousStreamRelayAggregateCounters {
    pub accepted_connections: u64,
    pub parked_hellos: u64,
    /// Cumulative lifetime total of pairings — never a live gauge.
    pub paired_sessions: u64,
    pub splice_closed: u64,
    pub splice_idle_timeout: u64,
    pub splice_lifetime_elapsed: u64,
    pub splice_failed: u64,
    pub splice_byte_cap_exceeded_guest_to_claw: u64,
    pub splice_byte_cap_exceeded_claw_to_guest: u64,
    pub pending_expired: u64,
    pub source_buckets_pruned: u64,
    pub bytes_guest_to_claw: u64,
    pub bytes_claw_to_guest: u64,
}

#[derive(Debug, Default)]
struct RendezvousStreamRelayDropAtomicCounters {
    global_active_limit: AtomicU64,
    source_bucket_table_full: AtomicU64,
    source_unpaired_active_limit: AtomicU64,
    source_pending_limit: AtomicU64,
    source_paired_splice_limit: AtomicU64,
    hello_attempt_rate_limited: AtomicU64,
    failed_hello_rate_limited: AtomicU64,
    hello_timeout: AtomicU64,
    malformed_hello: AtomicU64,
    offer_token_consumed: AtomicU64,
    offer_duplicate_role: AtomicU64,
    offer_expired: AtomicU64,
    offer_capacity_exceeded: AtomicU64,
    offer_consumed_capacity_exceeded: AtomicU64,
    abuse_state_unavailable: AtomicU64,
    unexpected_abuse_permit: AtomicU64,
}

impl RendezvousStreamRelayDropAtomicCounters {
    fn snapshot(&self) -> RendezvousStreamRelayDropCounters {
        RendezvousStreamRelayDropCounters {
            global_active_limit: self.global_active_limit.load(Ordering::Relaxed),
            source_bucket_table_full: self.source_bucket_table_full.load(Ordering::Relaxed),
            source_unpaired_active_limit: self.source_unpaired_active_limit.load(Ordering::Relaxed),
            source_pending_limit: self.source_pending_limit.load(Ordering::Relaxed),
            source_paired_splice_limit: self.source_paired_splice_limit.load(Ordering::Relaxed),
            hello_attempt_rate_limited: self.hello_attempt_rate_limited.load(Ordering::Relaxed),
            failed_hello_rate_limited: self.failed_hello_rate_limited.load(Ordering::Relaxed),
            hello_timeout: self.hello_timeout.load(Ordering::Relaxed),
            malformed_hello: self.malformed_hello.load(Ordering::Relaxed),
            offer_token_consumed: self.offer_token_consumed.load(Ordering::Relaxed),
            offer_duplicate_role: self.offer_duplicate_role.load(Ordering::Relaxed),
            offer_expired: self.offer_expired.load(Ordering::Relaxed),
            offer_capacity_exceeded: self.offer_capacity_exceeded.load(Ordering::Relaxed),
            offer_consumed_capacity_exceeded: self
                .offer_consumed_capacity_exceeded
                .load(Ordering::Relaxed),
            abuse_state_unavailable: self.abuse_state_unavailable.load(Ordering::Relaxed),
            unexpected_abuse_permit: self.unexpected_abuse_permit.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RendezvousStreamRelayDropCounters {
    pub global_active_limit: u64,
    pub source_bucket_table_full: u64,
    pub source_unpaired_active_limit: u64,
    pub source_pending_limit: u64,
    pub source_paired_splice_limit: u64,
    pub hello_attempt_rate_limited: u64,
    pub failed_hello_rate_limited: u64,
    pub hello_timeout: u64,
    pub malformed_hello: u64,
    pub offer_token_consumed: u64,
    pub offer_duplicate_role: u64,
    pub offer_expired: u64,
    pub offer_capacity_exceeded: u64,
    pub offer_consumed_capacity_exceeded: u64,
    pub abuse_state_unavailable: u64,
    pub unexpected_abuse_permit: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_status_snapshot_is_aggregate_and_secret_free() {
        let config = RendezvousStreamRelayListenerConfig::default();
        let status = RendezvousStreamRelayStatusHandle::new("192.168.15.10:49152", true, &config);

        status.record_connection_opened();
        status.record_parked();
        status.record_pair();
        status.record_splice_closed(12, 34);
        status.record_abuse_gate_failure(RelayStatusAbuseGateFailure::Rejected(
            RelayRejectReason::SourceBucketTableFull,
        ));
        status.record_hello_error(RelayStatusHelloErrorKind::Malformed);
        status.record_offer_rejected(RendezvousRejectReason::DuplicateRole);
        status.set_pending_tokens(2);
        status.set_source_buckets(3);
        status.record_connection_closed();

        let snapshot = status.snapshot();
        assert!(snapshot.enabled);
        assert!(snapshot.public_mode);
        assert_eq!(snapshot.bind_addr, "192.168.15.10:49152");
        assert_eq!(snapshot.external_reachability, "not_checked");
        assert_eq!(snapshot.active_connections, 0);
        assert_eq!(snapshot.pending_tokens, 2);
        assert_eq!(snapshot.source_buckets, 3);
        assert_eq!(snapshot.counters.accepted_connections, 1);
        assert_eq!(snapshot.counters.parked_hellos, 1);
        assert_eq!(snapshot.counters.paired_sessions, 1);
        assert_eq!(snapshot.counters.bytes_guest_to_claw, 12);
        assert_eq!(snapshot.counters.bytes_claw_to_guest, 34);
        assert_eq!(snapshot.drops.source_bucket_table_full, 1);
        assert_eq!(snapshot.drops.malformed_hello, 1);
        assert_eq!(snapshot.drops.offer_duplicate_role, 1);

        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(!encoded.contains("rendezvous_token"));
        assert!(!encoded.contains("payload"));
        assert!(!encoded.contains("source_ip"));
        assert!(!encoded.contains("203.0.113."));
    }
}
