//! Pair-code verify rate-limit adapter for
//! `POST /bootstrap/pair-device-uri/by-code`.
//!
//! Runtime foundation only: it defines the per-peer limiter action, the
//! durable subject key, the hourly ceiling, and the fail-closed mapping the
//! by-code handler must use. It intentionally does not expose a route, a
//! response type, or the code comparison itself.
//!
//! The six-word code carries 66 bits of entropy; that entropy is the
//! protection. This limiter is only an abuse ceiling per peer address, so a
//! single admitted peer cannot hammer the constant-time compare (or the
//! `SQLite` ledger behind it) without bound. There is deliberately no
//! household-wide bucket: one would let any peer deny service to every other
//! peer and adds nothing against 2^66.

use std::net::IpAddr;

use crate::ratelimit::{Limiter, RateLimitError};

/// Limiter action recorded once per code-verify attempt, keyed by peer.
pub const PAIR_CODE_PEER_ACTION: &str = "pair_code_verify_peer";

/// Hourly ceiling per peer address for [`PAIR_CODE_PEER_ACTION`].
pub const PAIR_CODE_PEER_LIMIT_PER_HOUR: i64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairCodeRateLimitDecision {
    Allowed,
    RejectOpaque,
}

impl PairCodeRateLimitDecision {
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Per-action overrides the production limiter must be built with, so the
/// pair-code bucket is capped at [`PAIR_CODE_PEER_LIMIT_PER_HOUR`] regardless
/// of the global `THEYOS_RATELIMIT_PER_HOUR` setting.
#[must_use]
pub fn pair_code_action_limits() -> [(&'static str, i64); 1] {
    [(PAIR_CODE_PEER_ACTION, PAIR_CODE_PEER_LIMIT_PER_HOUR)]
}

/// Durable subject key: one bucket per peer address, nothing else.
#[must_use]
pub fn pair_code_rate_limit_subject(peer: IpAddr) -> String {
    format!("peer:{peer}")
}

/// Record one pair-code verify attempt from `peer`.
///
/// Fail-closed: a limiter denial and a limiter error are the same
/// `RejectOpaque`. The handler must map `RejectOpaque` to the byte-identical
/// opaque response it uses for a wrong code, a missing window, or an expired
/// window, and must treat an absent limiter the same way. The returned
/// decision carries no status, header, or retry hint by design.
#[must_use]
pub fn check_pair_code_attempt(rate_limiter: &Limiter, peer: IpAddr) -> PairCodeRateLimitDecision {
    let subject = pair_code_rate_limit_subject(peer);
    // The action literal below is repeated on purpose: the rate-limit
    // coverage guard pins limiter sites by string literal, so the const only
    // keeps the two in lock-step.
    debug_assert_eq!(PAIR_CODE_PEER_ACTION, "pair_code_verify_peer");
    let result = rate_limiter.check(&subject, "pair_code_verify_peer");
    map_limiter_result(&result)
}

fn map_limiter_result(result: &Result<bool, RateLimitError>) -> PairCodeRateLimitDecision {
    match result {
        Ok(true) => PairCodeRateLimitDecision::Allowed,
        Ok(false) | Err(_) => PairCodeRateLimitDecision::RejectOpaque,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    fn tailnet_v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(100, 101, 102, 103))
    }

    fn tailnet_v6() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1))
    }

    #[test]
    fn limiter_denials_and_errors_are_the_same_opaque_reject() {
        assert_eq!(
            map_limiter_result(&Ok(true)),
            PairCodeRateLimitDecision::Allowed
        );
        assert_eq!(
            map_limiter_result(&Ok(false)),
            PairCodeRateLimitDecision::RejectOpaque
        );
        assert_eq!(
            map_limiter_result(&Err(RateLimitError::Internal("db unavailable".to_string()))),
            PairCodeRateLimitDecision::RejectOpaque
        );
        assert_eq!(
            map_limiter_result(&Err(RateLimitError::Lock)),
            PairCodeRateLimitDecision::RejectOpaque
        );
    }

    #[test]
    fn subject_is_the_peer_address_and_nothing_else() {
        assert_eq!(pair_code_rate_limit_subject(loopback()), "peer:127.0.0.1");
        assert_eq!(
            pair_code_rate_limit_subject(tailnet_v4()),
            "peer:100.101.102.103"
        );
        assert_eq!(
            pair_code_rate_limit_subject(tailnet_v6()),
            "peer:fd7a:115c:a1e0::1"
        );
    }

    #[test]
    fn attempts_are_durable_per_peer() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("pair-code-ratelimit.db");
        let db_path = db_path.to_str().unwrap();

        {
            let limiter = Limiter::new(db_path, 1).unwrap();
            assert!(
                check_pair_code_attempt(&limiter, tailnet_v4()).is_allowed(),
                "first attempt from a peer is allowed"
            );
            assert_eq!(
                check_pair_code_attempt(&limiter, tailnet_v4()),
                PairCodeRateLimitDecision::RejectOpaque,
                "second attempt in the same window is opaque-rejected"
            );
            assert!(
                check_pair_code_attempt(&limiter, tailnet_v6()).is_allowed(),
                "a different peer has an independent durable bucket"
            );
            assert!(
                check_pair_code_attempt(&limiter, loopback()).is_allowed(),
                "loopback has its own bucket too"
            );
        }

        let limiter = Limiter::new(db_path, 1).unwrap();
        assert_eq!(
            check_pair_code_attempt(&limiter, tailnet_v4()),
            PairCodeRateLimitDecision::RejectOpaque,
            "the attempt ledger survives limiter recreation"
        );
    }

    #[test]
    fn action_limit_caps_each_peer_at_sixty_per_hour() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("pair-code-ratelimit-cap.db");
        let mut limiter = Limiter::new(db_path.to_str().unwrap(), 1_000).unwrap();
        for (action, limit) in pair_code_action_limits() {
            limiter = limiter.with_action_limit(action, limit);
        }

        for attempt in 1..=PAIR_CODE_PEER_LIMIT_PER_HOUR {
            assert!(
                check_pair_code_attempt(&limiter, tailnet_v4()).is_allowed(),
                "attempt {attempt} is within the per-peer ceiling"
            );
        }
        assert_eq!(
            check_pair_code_attempt(&limiter, tailnet_v4()),
            PairCodeRateLimitDecision::RejectOpaque,
            "attempt {} is over the per-peer ceiling",
            PAIR_CODE_PEER_LIMIT_PER_HOUR + 1
        );
        assert!(
            check_pair_code_attempt(&limiter, tailnet_v6()).is_allowed(),
            "one saturated peer does not affect another (no shared bucket)"
        );
    }

    #[test]
    fn action_limits_name_exactly_the_peer_bucket() {
        assert_eq!(
            pair_code_action_limits(),
            [("pair_code_verify_peer", 60)],
            "one bucket only, per peer, 60/h"
        );
    }

    #[test]
    fn source_contract_stays_response_agnostic_and_secret_free() {
        let source = include_str!("bootstrap_pair_code_rate_limit.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let too_many_requests = ["StatusCode::TOO", "_MANY_REQUESTS"].concat();
        let retry_after = ["Retry", "-After"].concat();
        let rate_limit_header = ["X-Rate", "Limit"].concat();
        let pair_nonce = ["non", "ce"].concat();
        let pair_uri = ["pair_device", "_uri"].concat();
        assert!(!production.contains(&too_many_requests));
        assert!(!production.contains(&retry_after));
        assert!(!production.contains(&rate_limit_header));
        assert!(!production.contains(&pair_nonce));
        assert!(!production.contains(&pair_uri));
        assert!(
            !production.contains("HouseholdId") && !production.contains("hh_id"),
            "the subject can only ever be the peer address; no household-scoped bucket"
        );
    }
}
