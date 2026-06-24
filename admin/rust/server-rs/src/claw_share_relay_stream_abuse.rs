//! Pure abuse policy model for public `relay_stream` rendezvous relays.
//!
//! This module is deliberately free of sockets, environment reads, spawned
//! tasks, and wall-clock time. It models only the local resource accounting that
//! a public blind relay will later enforce at the listener boundary.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

const DEFAULT_MAX_UNPAIRED_ACTIVE_PER_SOURCE: usize = 16;
const DEFAULT_MAX_PENDING_PER_SOURCE: usize = 16;
const DEFAULT_MAX_HELLO_ATTEMPTS_PER_WINDOW: u32 = 120;
const DEFAULT_MAX_FAILED_HELLOS_PER_WINDOW: u32 = 30;
const DEFAULT_MAX_PAIRED_SPLICES_PER_SOURCE: usize = 128;
const DEFAULT_MAX_SOURCE_BUCKETS: usize = 4096;
const DEFAULT_IPV6_SOURCE_PREFIX_LEN: u8 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelaySourceBucket {
    Ipv4(Ipv4Addr),
    Ipv6 { network: Ipv6Addr, prefix_len: u8 },
}

impl RelaySourceBucket {
    #[must_use]
    pub fn from_ip(ip: IpAddr, ipv6_prefix_len: u8) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::Ipv4(ip),
            IpAddr::V6(ip) => {
                let prefix_len = ipv6_prefix_len.min(128);
                Self::Ipv6 {
                    network: mask_ipv6(ip, prefix_len),
                    prefix_len,
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAbuseConfig {
    pub max_unpaired_active_per_source: usize,
    pub max_pending_per_source: usize,
    pub max_hello_attempts_per_source_per_window: u32,
    pub max_failed_hellos_per_source_per_window: u32,
    pub max_paired_splices_per_source: Option<usize>,
    pub hello_attempt_window: Duration,
    pub source_state_ttl: Duration,
    pub max_source_buckets: usize,
    pub max_splice_lifetime: Duration,
    pub ipv6_source_prefix_len: u8,
}

impl Default for RelayAbuseConfig {
    fn default() -> Self {
        Self {
            max_unpaired_active_per_source: DEFAULT_MAX_UNPAIRED_ACTIVE_PER_SOURCE,
            max_pending_per_source: DEFAULT_MAX_PENDING_PER_SOURCE,
            max_hello_attempts_per_source_per_window: DEFAULT_MAX_HELLO_ATTEMPTS_PER_WINDOW,
            max_failed_hellos_per_source_per_window: DEFAULT_MAX_FAILED_HELLOS_PER_WINDOW,
            max_paired_splices_per_source: Some(DEFAULT_MAX_PAIRED_SPLICES_PER_SOURCE),
            hello_attempt_window: Duration::from_secs(60),
            source_state_ttl: Duration::from_secs(300),
            max_source_buckets: DEFAULT_MAX_SOURCE_BUCKETS,
            max_splice_lifetime: Duration::from_secs(60 * 60),
            ipv6_source_prefix_len: DEFAULT_IPV6_SOURCE_PREFIX_LEN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRejectReason {
    SourceBucketTableFull,
    UnpairedActiveLimit,
    PendingLimit,
    HelloAttemptRateLimited,
    FailedHelloRateLimited,
    PairedSpliceLimit,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelayAdmissionOutcome {
    Accepted { permit: Option<RelayAbusePermit> },
    Rejected { reason: RelayRejectReason },
}

impl RelayAdmissionOutcome {
    #[must_use]
    pub fn accepted() -> Self {
        RelayAdmissionOutcome::Accepted { permit: None }
    }

    #[must_use]
    pub fn accepted_with_permit(permit: RelayAbusePermit) -> Self {
        RelayAdmissionOutcome::Accepted {
            permit: Some(permit),
        }
    }

    #[must_use]
    pub fn is_accepted(self) -> bool {
        matches!(self, RelayAdmissionOutcome::Accepted { .. })
    }

    #[must_use]
    pub fn accepted_permit(self) -> Option<RelayAbusePermit> {
        match self {
            RelayAdmissionOutcome::Accepted { permit } => permit,
            RelayAdmissionOutcome::Rejected { .. } => None,
        }
    }

    #[must_use]
    pub fn reject_reason(self) -> Option<RelayRejectReason> {
        match self {
            RelayAdmissionOutcome::Accepted { .. } => None,
            RelayAdmissionOutcome::Rejected { reason } => Some(reason),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RelayAbusePermit {
    bucket: RelaySourceBucket,
    kind: RelayAbusePermitKind,
}

impl RelayAbusePermit {
    #[must_use]
    pub fn bucket(&self) -> RelaySourceBucket {
        self.bucket
    }

    #[must_use]
    pub fn kind(&self) -> RelayAbusePermitKind {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAbusePermitKind {
    UnpairedActive,
    Pending,
    PairedSplice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelaySourceBucketSnapshot {
    pub unpaired_active: usize,
    pub pending: usize,
    pub paired_splices: usize,
}

#[derive(Debug)]
pub struct RelayAbuseState {
    config: RelayAbuseConfig,
    buckets: HashMap<RelaySourceBucket, RelaySourceState>,
}

impl RelayAbuseState {
    #[must_use]
    pub fn new(config: RelayAbuseConfig) -> Self {
        Self {
            config,
            buckets: HashMap::new(),
        }
    }

    #[must_use]
    pub fn config(&self) -> &RelayAbuseConfig {
        &self.config
    }

    #[must_use]
    pub fn source_bucket_for_ip(&self, ip: IpAddr) -> RelaySourceBucket {
        RelaySourceBucket::from_ip(ip, self.config.ipv6_source_prefix_len)
    }

    #[must_use]
    pub fn source_bucket_count(&self) -> usize {
        self.buckets.len()
    }

    pub fn source_snapshot(&self, bucket: RelaySourceBucket) -> Option<RelaySourceBucketSnapshot> {
        self.buckets.get(&bucket).map(RelaySourceState::snapshot)
    }

    pub fn prune_idle_buckets(&mut self, now: Instant) -> usize {
        let before = self.buckets.len();
        let ttl = self.config.source_state_ttl;
        self.buckets
            .retain(|_, source| !source.is_idle_expired(now, ttl));
        before.saturating_sub(self.buckets.len())
    }

    pub fn record_hello_attempt(
        &mut self,
        bucket: RelaySourceBucket,
        now: Instant,
    ) -> RelayAdmissionOutcome {
        let config = self.config.clone();
        let source = match self.ensure_source(bucket, now) {
            Ok(source) => source,
            Err(reason) => return RelayAdmissionOutcome::Rejected { reason },
        };
        if !source.hello_attempts.try_consume(
            now,
            config.max_hello_attempts_per_source_per_window,
            config.hello_attempt_window,
        ) {
            return RelayAdmissionOutcome::Rejected {
                reason: RelayRejectReason::HelloAttemptRateLimited,
            };
        }
        source.touch(now);
        RelayAdmissionOutcome::accepted()
    }

    pub fn record_hello_failure(
        &mut self,
        bucket: RelaySourceBucket,
        now: Instant,
    ) -> RelayAdmissionOutcome {
        let config = self.config.clone();
        let source = match self.ensure_source(bucket, now) {
            Ok(source) => source,
            Err(reason) => return RelayAdmissionOutcome::Rejected { reason },
        };
        if !source.failed_hellos.try_consume(
            now,
            config.max_failed_hellos_per_source_per_window,
            config.hello_attempt_window,
        ) {
            return RelayAdmissionOutcome::Rejected {
                reason: RelayRejectReason::FailedHelloRateLimited,
            };
        }
        source.touch(now);
        RelayAdmissionOutcome::accepted()
    }

    pub fn check_failed_hello_budget(
        &mut self,
        bucket: RelaySourceBucket,
        now: Instant,
    ) -> RelayAdmissionOutcome {
        let config = self.config.clone();
        let source = match self.ensure_source(bucket, now) {
            Ok(source) => source,
            Err(reason) => return RelayAdmissionOutcome::Rejected { reason },
        };
        if !source.failed_hellos.has_available(
            now,
            config.max_failed_hellos_per_source_per_window,
            config.hello_attempt_window,
        ) {
            return RelayAdmissionOutcome::Rejected {
                reason: RelayRejectReason::FailedHelloRateLimited,
            };
        }
        source.touch(now);
        RelayAdmissionOutcome::accepted()
    }

    pub fn record_successful_pair(&mut self, bucket: RelaySourceBucket, now: Instant) {
        let max_attempts = self.config.max_hello_attempts_per_source_per_window;
        if let Some(source) = self.buckets.get_mut(&bucket) {
            source.hello_attempts.refund(max_attempts);
            source.touch(now);
        }
    }

    pub fn try_acquire_unpaired_active(
        &mut self,
        bucket: RelaySourceBucket,
        now: Instant,
    ) -> RelayAdmissionOutcome {
        let max = self.config.max_unpaired_active_per_source;
        let source = match self.ensure_source(bucket, now) {
            Ok(source) => source,
            Err(reason) => return RelayAdmissionOutcome::Rejected { reason },
        };
        if source.unpaired_active >= max {
            return RelayAdmissionOutcome::Rejected {
                reason: RelayRejectReason::UnpairedActiveLimit,
            };
        }
        source.unpaired_active += 1;
        source.touch(now);
        RelayAdmissionOutcome::accepted_with_permit(RelayAbusePermit {
            bucket,
            kind: RelayAbusePermitKind::UnpairedActive,
        })
    }

    pub fn try_acquire_pending(
        &mut self,
        bucket: RelaySourceBucket,
        now: Instant,
    ) -> RelayAdmissionOutcome {
        let max = self.config.max_pending_per_source;
        let source = match self.ensure_source(bucket, now) {
            Ok(source) => source,
            Err(reason) => return RelayAdmissionOutcome::Rejected { reason },
        };
        if source.pending >= max {
            return RelayAdmissionOutcome::Rejected {
                reason: RelayRejectReason::PendingLimit,
            };
        }
        source.pending += 1;
        source.touch(now);
        RelayAdmissionOutcome::accepted_with_permit(RelayAbusePermit {
            bucket,
            kind: RelayAbusePermitKind::Pending,
        })
    }

    pub fn try_acquire_paired_splice(
        &mut self,
        bucket: RelaySourceBucket,
        now: Instant,
    ) -> RelayAdmissionOutcome {
        let max = self.config.max_paired_splices_per_source;
        let source = match self.ensure_source(bucket, now) {
            Ok(source) => source,
            Err(reason) => return RelayAdmissionOutcome::Rejected { reason },
        };
        if max.is_some_and(|max| source.paired_splices >= max) {
            return RelayAdmissionOutcome::Rejected {
                reason: RelayRejectReason::PairedSpliceLimit,
            };
        }
        source.paired_splices += 1;
        source.touch(now);
        RelayAdmissionOutcome::accepted_with_permit(RelayAbusePermit {
            bucket,
            kind: RelayAbusePermitKind::PairedSplice,
        })
    }

    // Take the permit by value: releasing it consumes (invalidates) the permit
    // so the caller cannot release the same permit twice. A `&` parameter would
    // re-permit double-release, which is exactly what this guard token prevents.
    #[allow(clippy::needless_pass_by_value)]
    pub fn release(&mut self, permit: RelayAbusePermit, now: Instant) {
        let Some(source) = self.buckets.get_mut(&permit.bucket) else {
            return;
        };
        match permit.kind {
            RelayAbusePermitKind::UnpairedActive => {
                source.unpaired_active = source.unpaired_active.saturating_sub(1);
            }
            RelayAbusePermitKind::Pending => {
                source.pending = source.pending.saturating_sub(1);
            }
            RelayAbusePermitKind::PairedSplice => {
                source.paired_splices = source.paired_splices.saturating_sub(1);
            }
        }
        source.touch(now);
    }

    fn ensure_source(
        &mut self,
        bucket: RelaySourceBucket,
        now: Instant,
    ) -> Result<&mut RelaySourceState, RelayRejectReason> {
        if self.buckets.contains_key(&bucket) {
            let source = self.buckets.get_mut(&bucket).expect("checked contains_key");
            source.touch(now);
            return Ok(source);
        }

        self.prune_idle_buckets(now);
        if self.buckets.len() >= self.config.max_source_buckets {
            return Err(RelayRejectReason::SourceBucketTableFull);
        }

        self.buckets.insert(bucket, RelaySourceState::new(now));
        self.buckets
            .get_mut(&bucket)
            .ok_or(RelayRejectReason::SourceBucketTableFull)
    }
}

impl Default for RelayAbuseState {
    fn default() -> Self {
        Self::new(RelayAbuseConfig::default())
    }
}

#[derive(Debug, Clone)]
struct RelaySourceState {
    unpaired_active: usize,
    pending: usize,
    paired_splices: usize,
    hello_attempts: TokenBucket,
    failed_hellos: TokenBucket,
    last_seen: Instant,
}

impl RelaySourceState {
    fn new(now: Instant) -> Self {
        Self {
            unpaired_active: 0,
            pending: 0,
            paired_splices: 0,
            hello_attempts: TokenBucket::new(),
            failed_hellos: TokenBucket::new(),
            last_seen: now,
        }
    }

    fn snapshot(&self) -> RelaySourceBucketSnapshot {
        RelaySourceBucketSnapshot {
            unpaired_active: self.unpaired_active,
            pending: self.pending,
            paired_splices: self.paired_splices,
        }
    }

    fn touch(&mut self, now: Instant) {
        self.last_seen = now;
    }

    fn is_active(&self) -> bool {
        self.unpaired_active > 0 || self.pending > 0 || self.paired_splices > 0
    }

    fn is_idle_expired(&self, now: Instant, ttl: Duration) -> bool {
        !self.is_active() && now.saturating_duration_since(self.last_seen) >= ttl
    }
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: u32,
    updated_at: Option<Instant>,
}

impl TokenBucket {
    fn new() -> Self {
        Self {
            tokens: 0,
            updated_at: None,
        }
    }

    fn try_consume(&mut self, now: Instant, capacity: u32, refill_window: Duration) -> bool {
        if capacity == 0 {
            return false;
        }
        self.refill(now, capacity, refill_window);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn has_available(&mut self, now: Instant, capacity: u32, refill_window: Duration) -> bool {
        if capacity == 0 {
            return false;
        }
        self.refill(now, capacity, refill_window);
        self.tokens > 0
    }

    fn refund(&mut self, capacity: u32) {
        self.tokens = self.tokens.saturating_add(1).min(capacity);
    }

    fn refill(&mut self, now: Instant, capacity: u32, refill_window: Duration) {
        let Some(updated_at) = self.updated_at else {
            self.updated_at = Some(now);
            self.tokens = capacity;
            return;
        };

        if refill_window.is_zero() {
            self.tokens = capacity;
            self.updated_at = Some(now);
            return;
        }

        let elapsed = now.saturating_duration_since(updated_at);
        if elapsed.is_zero() {
            return;
        }

        let elapsed_nanos = elapsed.as_nanos();
        let window_nanos = refill_window.as_nanos();
        if window_nanos == 0 {
            self.tokens = capacity;
            self.updated_at = Some(now);
            return;
        }

        // Saturate (rather than truncate) on overflow: a refill larger than
        // u32::MAX is clamped here and then bounded to `capacity` below, so the
        // final token count is identical to the in-range path.
        let refill =
            u32::try_from((elapsed_nanos.saturating_mul(u128::from(capacity))) / window_nanos)
                .unwrap_or(u32::MAX);
        if refill == 0 {
            return;
        }

        self.tokens = self.tokens.saturating_add(refill).min(capacity);
        let consumed_nanos = u128::from(refill).saturating_mul(window_nanos) / u128::from(capacity);
        // `consumed_nanos` is already clamped to u64::MAX, so the conversion is exact.
        let consumed = Duration::from_nanos(
            u64::try_from(consumed_nanos.min(u128::from(u64::MAX))).unwrap_or(u64::MAX),
        );
        self.updated_at = Some(updated_at + consumed);
    }
}

fn mask_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let prefix_len = prefix_len.min(128);
    let mut octets = addr.octets();
    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;

    if full_bytes < octets.len() {
        if remaining_bits == 0 {
            for octet in &mut octets[full_bytes..] {
                *octet = 0;
            }
        } else {
            let keep_mask = 0xffu8 << (8 - remaining_bits);
            octets[full_bytes] &= keep_mask;
            for octet in &mut octets[(full_bytes + 1)..] {
                *octet = 0;
            }
        }
    }

    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    fn ip4(last: u8) -> RelaySourceBucket {
        RelaySourceBucket::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), 64)
    }

    fn ip6(host: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2804, 0x18, 0x1146, 0xf43f, 0, 0, 0, host))
    }

    fn permit(outcome: RelayAdmissionOutcome) -> RelayAbusePermit {
        outcome.accepted_permit().expect("permit accepted")
    }

    fn config_for_caps() -> RelayAbuseConfig {
        RelayAbuseConfig {
            max_unpaired_active_per_source: 2,
            max_pending_per_source: 2,
            max_hello_attempts_per_source_per_window: 3,
            max_failed_hellos_per_source_per_window: 2,
            max_paired_splices_per_source: Some(4),
            source_state_ttl: Duration::from_secs(10),
            max_source_buckets: 4,
            ..RelayAbuseConfig::default()
        }
    }

    #[test]
    fn source_bucket_ipv4_is_exact_32() {
        assert_eq!(
            RelaySourceBucket::from_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 64),
            RelaySourceBucket::Ipv4(Ipv4Addr::new(198, 51, 100, 7))
        );
    }

    #[test]
    fn source_bucket_ipv6_defaults_to_64() {
        let bucket_a = RelaySourceBucket::from_ip(ip6(1), 64);
        let bucket_b = RelaySourceBucket::from_ip(ip6(2), 64);
        assert_eq!(bucket_a, bucket_b);
        assert_eq!(
            bucket_a,
            RelaySourceBucket::Ipv6 {
                network: Ipv6Addr::new(0x2804, 0x18, 0x1146, 0xf43f, 0, 0, 0, 0),
                prefix_len: 64,
            }
        );
    }

    #[test]
    fn source_bucket_ipv6_prefix_is_configurable() {
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1200, 0x0001, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1200, 0x00ff, 0, 0, 0, 1));
        assert_eq!(
            RelaySourceBucket::from_ip(a, 56),
            RelaySourceBucket::from_ip(b, 56)
        );
        assert_ne!(
            RelaySourceBucket::from_ip(a, 64),
            RelaySourceBucket::from_ip(b, 64)
        );
    }

    #[test]
    fn unpaired_active_cap_is_enforced_and_released() {
        let t0 = now();
        let bucket = ip4(10);
        let mut state = RelayAbuseState::new(config_for_caps());

        let first = permit(state.try_acquire_unpaired_active(bucket, t0));
        let second = permit(state.try_acquire_unpaired_active(bucket, t0));
        assert_eq!(
            state
                .try_acquire_unpaired_active(bucket, t0)
                .reject_reason(),
            Some(RelayRejectReason::UnpairedActiveLimit)
        );

        state.release(first, t0);
        let third = permit(state.try_acquire_unpaired_active(bucket, t0));
        assert_eq!(third.kind(), RelayAbusePermitKind::UnpairedActive);
        state.release(second, t0);
        state.release(third, t0);
        assert_eq!(
            state.source_snapshot(bucket),
            Some(RelaySourceBucketSnapshot::default())
        );
    }

    #[test]
    fn pending_cap_is_enforced_and_released() {
        let t0 = now();
        let bucket = ip4(11);
        let mut state = RelayAbuseState::new(config_for_caps());

        let first = permit(state.try_acquire_pending(bucket, t0));
        let second = permit(state.try_acquire_pending(bucket, t0));
        assert_eq!(
            state.try_acquire_pending(bucket, t0).reject_reason(),
            Some(RelayRejectReason::PendingLimit)
        );

        state.release(first, t0);
        assert!(
            state
                .try_acquire_pending(bucket, t0)
                .accepted_permit()
                .is_some()
        );
        state.release(second, t0);
    }

    #[test]
    fn failed_hello_token_bucket_trips_and_refills() {
        let t0 = now();
        let bucket = ip4(12);
        let mut state = RelayAbuseState::new(RelayAbuseConfig {
            max_failed_hellos_per_source_per_window: 2,
            hello_attempt_window: Duration::from_secs(10),
            ..config_for_caps()
        });

        assert!(state.record_hello_failure(bucket, t0).is_accepted());
        assert!(state.record_hello_failure(bucket, t0).is_accepted());
        assert_eq!(
            state.record_hello_failure(bucket, t0).reject_reason(),
            Some(RelayRejectReason::FailedHelloRateLimited)
        );
        assert_eq!(
            state
                .record_hello_failure(bucket, t0 + Duration::from_secs(4))
                .reject_reason(),
            Some(RelayRejectReason::FailedHelloRateLimited)
        );
        assert!(
            state
                .record_hello_failure(bucket, t0 + Duration::from_secs(5))
                .is_accepted()
        );
    }

    #[test]
    fn failed_hello_budget_check_blocks_until_refill_without_consuming() {
        let t0 = now();
        let bucket = ip4(22);
        let mut state = RelayAbuseState::new(RelayAbuseConfig {
            max_failed_hellos_per_source_per_window: 1,
            hello_attempt_window: Duration::from_secs(10),
            ..config_for_caps()
        });

        assert!(state.check_failed_hello_budget(bucket, t0).is_accepted());
        assert!(state.record_hello_failure(bucket, t0).is_accepted());
        assert_eq!(
            state.check_failed_hello_budget(bucket, t0).reject_reason(),
            Some(RelayRejectReason::FailedHelloRateLimited)
        );
        assert!(
            state
                .check_failed_hello_budget(bucket, t0 + Duration::from_secs(10))
                .is_accepted()
        );
    }

    #[test]
    fn successful_pair_does_not_escalate_failed_budget_and_refunds_attempt_backstop() {
        let t0 = now();
        let bucket = ip4(13);
        let mut state = RelayAbuseState::new(RelayAbuseConfig {
            max_hello_attempts_per_source_per_window: 2,
            max_failed_hellos_per_source_per_window: 1,
            hello_attempt_window: Duration::from_secs(60),
            ..config_for_caps()
        });

        assert!(state.record_hello_attempt(bucket, t0).is_accepted());
        state.record_successful_pair(bucket, t0);
        assert!(state.record_hello_attempt(bucket, t0).is_accepted());
        state.record_successful_pair(bucket, t0);
        assert!(state.record_hello_attempt(bucket, t0).is_accepted());

        assert!(state.record_hello_failure(bucket, t0).is_accepted());
        assert_eq!(
            state.record_hello_failure(bucket, t0).reject_reason(),
            Some(RelayRejectReason::FailedHelloRateLimited)
        );
    }

    #[test]
    fn paired_cgnat_sessions_do_not_hit_tight_unpaired_cap() {
        let t0 = now();
        let bucket = ip4(14);
        let mut state = RelayAbuseState::new(RelayAbuseConfig {
            max_unpaired_active_per_source: 1,
            max_paired_splices_per_source: Some(3),
            ..config_for_caps()
        });

        let unpaired = permit(state.try_acquire_unpaired_active(bucket, t0));
        assert_eq!(
            state
                .try_acquire_unpaired_active(bucket, t0)
                .reject_reason(),
            Some(RelayRejectReason::UnpairedActiveLimit)
        );

        let paired_a = permit(state.try_acquire_paired_splice(bucket, t0));
        let paired_b = permit(state.try_acquire_paired_splice(bucket, t0));
        let paired_c = permit(state.try_acquire_paired_splice(bucket, t0));
        assert_eq!(
            state.try_acquire_paired_splice(bucket, t0).reject_reason(),
            Some(RelayRejectReason::PairedSpliceLimit)
        );

        state.release(unpaired, t0);
        state.release(paired_a, t0);
        state.release(paired_b, t0);
        state.release(paired_c, t0);
    }

    #[test]
    fn source_bucket_table_full_fails_closed_for_new_active_sources() {
        let t0 = now();
        let mut state = RelayAbuseState::new(RelayAbuseConfig {
            max_source_buckets: 2,
            ..config_for_caps()
        });

        let _a = permit(state.try_acquire_unpaired_active(ip4(1), t0));
        let _b = permit(state.try_acquire_unpaired_active(ip4(2), t0));
        assert_eq!(state.source_bucket_count(), 2);
        assert_eq!(
            state
                .try_acquire_unpaired_active(ip4(3), t0)
                .reject_reason(),
            Some(RelayRejectReason::SourceBucketTableFull)
        );
    }

    #[test]
    fn zero_source_bucket_capacity_rejects_every_new_source() {
        let t0 = now();
        let mut state = RelayAbuseState::new(RelayAbuseConfig {
            max_source_buckets: 0,
            ..config_for_caps()
        });

        assert_eq!(
            state
                .try_acquire_unpaired_active(ip4(1), t0)
                .reject_reason(),
            Some(RelayRejectReason::SourceBucketTableFull)
        );
        assert_eq!(state.source_bucket_count(), 0);
    }

    #[test]
    fn source_bucket_table_prunes_only_idle_expired_buckets() {
        let t0 = now();
        let mut state = RelayAbuseState::new(RelayAbuseConfig {
            max_source_buckets: 2,
            source_state_ttl: Duration::from_secs(10),
            ..config_for_caps()
        });

        let active = permit(state.try_acquire_unpaired_active(ip4(1), t0));
        let idle = permit(state.try_acquire_unpaired_active(ip4(2), t0));
        state.release(idle, t0);

        assert_eq!(state.prune_idle_buckets(t0 + Duration::from_secs(9)), 0);
        assert_eq!(state.prune_idle_buckets(t0 + Duration::from_secs(10)), 1);
        assert_eq!(state.source_bucket_count(), 1);
        let third = permit(state.try_acquire_unpaired_active(ip4(3), t0 + Duration::from_secs(10)));
        state.release(active, t0);
        state.release(third, t0 + Duration::from_secs(10));
    }

    #[test]
    fn global_policy_is_independent_from_per_source_policy() {
        let t0 = now();
        let mut state = RelayAbuseState::new(config_for_caps());

        assert!(
            state
                .try_acquire_pending(ip4(20), t0)
                .accepted_permit()
                .is_some()
        );
        assert!(
            state
                .try_acquire_pending(ip4(20), t0)
                .accepted_permit()
                .is_some()
        );
        assert_eq!(
            state.try_acquire_pending(ip4(20), t0).reject_reason(),
            Some(RelayRejectReason::PendingLimit)
        );
        assert!(
            state
                .try_acquire_pending(ip4(21), t0)
                .accepted_permit()
                .is_some()
        );
    }

    #[test]
    fn configured_splice_lifetime_is_monotonic_duration() {
        let config = RelayAbuseConfig {
            max_splice_lifetime: Duration::from_secs(42),
            ..RelayAbuseConfig::default()
        };
        let state = RelayAbuseState::new(config);
        assert_eq!(state.config().max_splice_lifetime, Duration::from_secs(42));
    }
}
