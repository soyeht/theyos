//! In-memory, single-use, TTL'd challenge table for the production relay-offer
//! request endpoints.
//!
//! A member/dialer first GETs a fresh server-issued challenge, then must echo it
//! (consumed exactly once) on the offer request. This binds each request to a
//! server nonce — replay-proof without client clock-skew tolerance, and a natural
//! per-request throttle (one challenge → at most one offer). Process-lifetime
//! only: a restart invalidates outstanding challenges (fail-closed — the client
//! simply re-fetches).

use std::collections::HashMap;
use std::sync::Mutex;

use rand::RngCore;
use rand::rngs::OsRng;

/// CSPRNG entropy per challenge (same posture as the rendezvous token).
pub const RELAY_OFFER_CHALLENGE_BYTES: usize = 32;

/// Default challenge lifetime — short, since the client fetches then immediately
/// makes the offer request.
pub const RELAY_OFFER_CHALLENGE_TTL_SECS: u64 = 60;

/// Fail-closed cap on outstanding (unconsumed, unexpired) challenges. Bounds the
/// table against an issuance flood; at the cap, `issue` returns `None`.
const MAX_OUTSTANDING_CHALLENGES: usize = 16_384;

/// Single-use, TTL'd server-issued challenges, keyed by the raw challenge bytes.
pub struct RelayOfferChallengeTable {
    inner: Mutex<HashMap<[u8; RELAY_OFFER_CHALLENGE_BYTES], u64>>,
}

impl Default for RelayOfferChallengeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayOfferChallengeTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a fresh single-use challenge valid until `now_unix + ttl_secs`.
    /// Prunes expired entries first; returns `None` (fail-closed) only if the
    /// table is still at its cap after pruning.
    pub fn issue(&self, now_unix: u64, ttl_secs: u64) -> Option<[u8; RELAY_OFFER_CHALLENGE_BYTES]> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|_, exp| *exp > now_unix);
        if guard.len() >= MAX_OUTSTANDING_CHALLENGES {
            return None;
        }
        let mut challenge = [0u8; RELAY_OFFER_CHALLENGE_BYTES];
        OsRng.fill_bytes(&mut challenge);
        guard.insert(challenge, now_unix.saturating_add(ttl_secs));
        Some(challenge)
    }

    /// Consume a challenge exactly once. Returns true iff it was present and
    /// unexpired; removes it so any replay fails. Wrong-length input is rejected.
    pub fn consume(&self, challenge: &[u8], now_unix: u64) -> bool {
        if challenge.len() != RELAY_OFFER_CHALLENGE_BYTES {
            return false;
        }
        let mut key = [0u8; RELAY_OFFER_CHALLENGE_BYTES];
        key.copy_from_slice(challenge);
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.retain(|_, exp| *exp > now_unix);
        guard.remove(&key).is_some()
    }

    #[cfg(test)]
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_then_consume_exactly_once() {
        let t = RelayOfferChallengeTable::new();
        let c = t.issue(1_000, 60).unwrap();
        assert_eq!(c.len(), RELAY_OFFER_CHALLENGE_BYTES);
        assert!(t.consume(&c, 1_010)); // present + unexpired
        assert!(!t.consume(&c, 1_011)); // single-use: replay fails
    }

    #[test]
    fn unknown_wrong_length_and_expired_are_rejected() {
        let t = RelayOfferChallengeTable::new();
        // never issued
        assert!(!t.consume(&[0u8; RELAY_OFFER_CHALLENGE_BYTES], 1_000));
        let c = t.issue(1_000, 60).unwrap();
        assert!(!t.consume(&c[..16], 1_010)); // wrong length
        assert!(!t.consume(&c, 1_000 + 61)); // expired before consume
        // and once expired-consume ran, the entry is pruned for good
        assert!(!t.consume(&c, 1_010));
    }

    #[test]
    fn issue_prunes_expired() {
        let t = RelayOfferChallengeTable::new();
        let c1 = t.issue(1_000, 10).unwrap();
        let _c2 = t.issue(1_000, 10).unwrap();
        assert_eq!(t.outstanding(), 2);
        // Issuing well after expiry prunes the stale ones first.
        let _c3 = t.issue(2_000, 10).unwrap();
        assert_eq!(t.outstanding(), 1);
        assert!(!t.consume(&c1, 2_000)); // c1 was pruned
    }
}
