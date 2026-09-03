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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::ratelimit::{Limiter, RateLimitError};
use crate::time_util;

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
/// The durable ledger plus the in-process gate that keeps a flood off it.
///
/// One per engine, held by `BootstrapHandlerState`. Deliberately not a
/// `static`: a process-global cache makes every test that touches this module
/// depend on the order the others ran in, and a per-engine value is also what
/// lets a second engine in the same process (the test harness does this) keep
/// its own budget.
pub struct PairCodeRateLimiter {
    ledger: Arc<Limiter>,
    /// Peers seen to be over the ceiling, and the hour window in which that
    /// was true. Lossy and bounded on purpose — see [`SHED_CACHE_CAPACITY`].
    shed: Mutex<HashMap<IpAddr, i64>>,
}

/// How many distinct peers the in-process gate remembers. A flood comes from
/// few addresses, so a small map is enough; when it is full the gate stops
/// accelerating and every call falls through to the durable ledger, which is
/// exactly the behaviour before the gate existed. Bounded on purpose: an
/// unbounded map keyed by peer address would be its own memory DoS.
const SHED_CACHE_CAPACITY: usize = 1024;

impl PairCodeRateLimiter {
    #[must_use]
    pub fn new(ledger: Arc<Limiter>) -> Self {
        Self {
            ledger,
            shed: Mutex::new(HashMap::new()),
        }
    }

    fn hour_window() -> i64 {
        let now = time_util::unix_now_secs_checked("pair_code_rate_limit.clock").unwrap_or(0);
        let now = i64::try_from(now).unwrap_or(0);
        now - now.rem_euclid(3600)
    }

    /// True when this peer was already refused by the ledger this hour, so the
    /// answer is known without a round-trip. Only ever says "no sooner": a
    /// peer it has not seen is always measured against the ledger.
    fn already_over_ceiling(&self, peer: IpAddr) -> bool {
        let Ok(mut shed) = self.shed.lock() else {
            return false;
        };
        let window = Self::hour_window();
        match shed.get(&peer) {
            Some(&seen) if seen == window => true,
            Some(_) => {
                // The hour turned over; the peer starts fresh against the ledger.
                shed.remove(&peer);
                false
            }
            None => false,
        }
    }

    fn remember_over_ceiling(&self, peer: IpAddr) {
        let Ok(mut shed) = self.shed.lock() else {
            return;
        };
        let window = Self::hour_window();
        if shed.len() >= SHED_CACHE_CAPACITY && !shed.contains_key(&peer) {
            shed.retain(|_, seen| *seen == window);
            if shed.len() >= SHED_CACHE_CAPACITY {
                return;
            }
        }
        shed.insert(peer, window);
    }
}

/// Record one pair-code verify attempt from `peer`.
///
/// Sheds before the ledger, not with it. `Limiter::check` charges the bucket
/// in order to learn the count: it takes the process-wide `Mutex<Connection>`
/// and runs a DELETE plus an upsert — two WAL commits — on *every* call, so
/// the ceiling never sheds the cost it exists to bound. A peer flooding this
/// route would keep occupying blocking-pool threads and contending for the
/// same mutex the claw and owner-recovery routes use, long after its 60
/// attempts were spent.
///
/// The in-process gate answers for a peer already known to be over the ceiling
/// this hour without touching SQLite. It is an accelerator, never the
/// authority: the durable bucket still decides admission, still survives a
/// restart, and is still what a first-time peer is measured against.
#[must_use]
pub fn check_pair_code_attempt(
    rate_limiter: &PairCodeRateLimiter,
    peer: IpAddr,
) -> PairCodeRateLimitDecision {
    if rate_limiter.already_over_ceiling(peer) {
        return PairCodeRateLimitDecision::RejectOpaque;
    }

    let subject = pair_code_rate_limit_subject(peer);
    // The action literal below is repeated on purpose: the rate-limit
    // coverage guard pins limiter sites by string literal, so the const only
    // keeps the two in lock-step.
    debug_assert_eq!(PAIR_CODE_PEER_ACTION, "pair_code_verify_peer");
    let result = rate_limiter.ledger.check(&subject, "pair_code_verify_peer");
    let decision = map_limiter_result(&result);
    if decision == PairCodeRateLimitDecision::RejectOpaque {
        rate_limiter.remember_over_ceiling(peer);
    }
    decision
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

    /// The 60/h ceiling is only real if the production limiter is actually
    /// built with the override. That happens in exactly one place — `main.rs`
    /// — and nothing tested it: deleting the loop left every test in this
    /// module green while the bucket silently fell back to the global
    /// `THEYOS_RATELIMIT_PER_HOUR`, which on a permissive host is no ceiling
    /// at all.
    #[test]
    fn production_wiring_applies_the_per_action_ceiling() {
        let main_rs = include_str!("main.rs");
        let wiring = main_rs
            .split_once("let mut rate_limiter =")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("let flow_config"))
            .map(|(head, _)| head)
            .expect("main.rs must still build the shared rate limiter");

        assert!(
            wiring.contains("bootstrap_pair_code_rate_limit::pair_code_action_limits()"),
            "main.rs must build the shared limiter from pair_code_action_limits()"
        );
        assert!(
            wiring.contains("with_action_limit(action, limit)"),
            "the overrides from pair_code_action_limits() must be applied, not just read"
        );
        assert_eq!(
            pair_code_action_limits(),
            [(PAIR_CODE_PEER_ACTION, 60)],
            "and the ceiling those overrides carry is 60/h per peer"
        );
    }

    #[test]
    fn shed_gate_answers_for_a_known_over_ceiling_peer_without_the_ledger() {
        // The point of the gate: once a peer is over, further attempts cost
        // no SQLite round-trip. The discriminator is the ledger's own count,
        // not the decision — an error is also RejectOpaque.
        let peer = IpAddr::V4(Ipv4Addr::new(100, 90, 4, 17));
        let ledger = Arc::new(Limiter::new(":memory:", 1).expect("in-memory limiter"));
        let limiter = PairCodeRateLimiter::new(Arc::clone(&ledger));

        assert_eq!(
            check_pair_code_attempt(&limiter, peer),
            PairCodeRateLimitDecision::Allowed,
            "the first attempt is inside the ceiling"
        );
        assert_eq!(
            check_pair_code_attempt(&limiter, peer),
            PairCodeRateLimitDecision::RejectOpaque,
            "the second is shed by the ledger, and remembered"
        );
        let subject = pair_code_rate_limit_subject(peer);
        let charged_after_two = ledger
            .get_remaining(&subject, PAIR_CODE_PEER_ACTION)
            .expect("remaining readable");

        for _ in 0..50 {
            assert_eq!(
                check_pair_code_attempt(&limiter, peer),
                PairCodeRateLimitDecision::RejectOpaque
            );
        }
        assert_eq!(
            ledger
                .get_remaining(&subject, PAIR_CODE_PEER_ACTION)
                .expect("remaining readable"),
            charged_after_two,
            "50 further attempts must not have touched the ledger at all"
        );
    }

    #[test]
    fn shed_gate_never_admits_a_peer_the_ledger_would_refuse() {
        // The accelerator may only ever say "no sooner", never "yes". A peer
        // whose durable bucket is already spent, but which this gate has
        // never seen, is still refused — the ledger is the authority.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("shed-gate-authority.db");
        let db_path = db_path.to_str().unwrap();
        let peer = IpAddr::V4(Ipv4Addr::new(100, 90, 4, 18));

        let spent = PairCodeRateLimiter::new(Arc::new(Limiter::new(db_path, 1).unwrap()));
        assert!(check_pair_code_attempt(&spent, peer).is_allowed());
        assert!(!check_pair_code_attempt(&spent, peer).is_allowed());
        drop(spent);

        // A new engine object: empty gate, same ledger on disk.
        let fresh = PairCodeRateLimiter::new(Arc::new(Limiter::new(db_path, 1).unwrap()));
        assert!(
            !fresh.already_over_ceiling(peer),
            "precondition: this gate has never seen the peer"
        );
        assert_eq!(
            check_pair_code_attempt(&fresh, peer),
            PairCodeRateLimitDecision::RejectOpaque,
            "an empty gate must not admit what the ledger already refused"
        );
    }

    #[test]
    fn shed_gate_keeps_peers_independent() {
        // One peer over its ceiling must never shed another's first attempt.
        let noisy = IpAddr::V4(Ipv4Addr::new(100, 90, 4, 19));
        let quiet = IpAddr::V4(Ipv4Addr::new(100, 90, 4, 20));
        let limiter = PairCodeRateLimiter::new(Arc::new(
            Limiter::new(":memory:", 1).expect("in-memory limiter"),
        ));
        assert!(check_pair_code_attempt(&limiter, noisy).is_allowed());
        for _ in 0..10 {
            assert!(!check_pair_code_attempt(&limiter, noisy).is_allowed());
        }
        assert!(
            check_pair_code_attempt(&limiter, quiet).is_allowed(),
            "a flooding neighbour must not spend this peer's budget"
        );
    }

    #[test]
    fn shed_gate_is_bounded_and_forgets_an_older_hour() {
        let limiter = PairCodeRateLimiter::new(Arc::new(
            Limiter::new(":memory:", 1).expect("in-memory limiter"),
        ));
        for third in 0..=5u8 {
            for last in 0..=255u8 {
                limiter.remember_over_ceiling(IpAddr::V4(Ipv4Addr::new(100, 90, third, last)));
            }
        }
        let len = limiter.shed.lock().expect("cache").len();
        assert!(
            len <= SHED_CACHE_CAPACITY,
            "the cache must never grow past its cap, got {len}"
        );

        // An entry stamped with a previous hour is not a shed reason.
        let stale = IpAddr::V4(Ipv4Addr::new(100, 91, 9, 9));
        limiter
            .shed
            .lock()
            .expect("cache")
            .insert(stale, PairCodeRateLimiter::hour_window() - 3600);
        assert!(
            !limiter.already_over_ceiling(stale),
            "a peer over the ceiling last hour starts this one fresh"
        );
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
            let limiter = PairCodeRateLimiter::new(Arc::new(Limiter::new(db_path, 1).unwrap()));
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

        // A fresh limiter means a fresh in-process gate too, so this really
        // does read the durable ledger.
        let limiter = PairCodeRateLimiter::new(Arc::new(Limiter::new(db_path, 1).unwrap()));
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
        let mut ledger = Limiter::new(db_path.to_str().unwrap(), 1_000).unwrap();
        for (action, limit) in pair_code_action_limits() {
            ledger = ledger.with_action_limit(action, limit);
        }
        let limiter = PairCodeRateLimiter::new(Arc::new(ledger));

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
