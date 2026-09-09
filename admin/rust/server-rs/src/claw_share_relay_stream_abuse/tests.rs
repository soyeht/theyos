#![cfg(test)]

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
