//! Isolated rendezvous relay core for the future Product A `relay_stream` path.
//!
//! This module deliberately does not expose a public listener, does not alter
//! claim/ack wire schema, and does not implement Noise. It only owns the
//! relay-visible mechanics that are safe to unit-test in isolation: redacted
//! rendezvous tokens, a minimal hello shape, one-time guest/claw pairing, and
//! opaque byte splicing.

use std::collections::{HashMap, VecDeque};

use tokio::io::{self, AsyncRead, AsyncWrite};

// RendezvousToken/Role/Hello (+ their errors + length bounds + hello version)
// moved to household-rs (C7c-2a token leaf, C7c-2c-2a hello codec) so the guest
// can share them; re-exported here so this module's table/pairing/splicer and
// the types' external importers (e.g. the listener) keep the same path. Only the
// leaf codec moved - the relay mechanics stay in this module.
pub use household_rs::claw_share_rendezvous_hello::{
    RENDEZVOUS_HELLO_VERSION, RendezvousHello, RendezvousHelloError, RendezvousRole,
};
pub use household_rs::claw_share_rendezvous_token::{
    MAX_RENDEZVOUS_TOKEN_LEN, MIN_RENDEZVOUS_TOKEN_LEN, RendezvousToken, RendezvousTokenError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RendezvousTokenTableConfig {
    pub max_pending: usize,
    pub token_ttl_secs: u64,
    pub max_consumed: usize,
}

impl Default for RendezvousTokenTableConfig {
    fn default() -> Self {
        Self {
            max_pending: 1024,
            token_ttl_secs: 60,
            max_consumed: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendezvousRejectReason {
    TokenConsumed,
    DuplicateRole,
    Expired,
    CapacityExceeded,
}

pub enum RendezvousOfferOutcome<S> {
    Parked,
    Paired {
        guest: S,
        claw: S,
    },
    Rejected {
        reason: RendezvousRejectReason,
        stream: S,
    },
}

struct PendingRendezvous<S> {
    inserted_at: u64,
    guest: Option<S>,
    claw: Option<S>,
}

impl<S> PendingRendezvous<S> {
    fn new(inserted_at: u64, role: RendezvousRole, stream: S) -> Self {
        match role {
            RendezvousRole::Guest => Self {
                inserted_at,
                guest: Some(stream),
                claw: None,
            },
            RendezvousRole::Claw => Self {
                inserted_at,
                guest: None,
                claw: Some(stream),
            },
        }
    }

    fn is_expired(&self, now_secs: u64, ttl_secs: u64) -> bool {
        now_secs >= self.inserted_at.saturating_add(ttl_secs)
    }
}

/// In-memory one-time rendezvous token table.
pub struct RendezvousTokenTable<S> {
    config: RendezvousTokenTableConfig,
    pending: HashMap<RendezvousToken, PendingRendezvous<S>>,
    consumed: HashMap<RendezvousToken, u64>,
    consumed_order: VecDeque<RendezvousToken>,
}

impl<S> RendezvousTokenTable<S> {
    #[must_use]
    pub fn new(config: RendezvousTokenTableConfig) -> Self {
        let config = RendezvousTokenTableConfig {
            // Keep one-time replay protection enabled even with a zero override.
            max_consumed: config.max_consumed.max(1),
            ..config
        };
        Self {
            config,
            pending: HashMap::new(),
            consumed: HashMap::new(),
            consumed_order: VecDeque::new(),
        }
    }

    #[must_use]
    pub fn with_limits(max_pending: usize, token_ttl_secs: u64) -> Self {
        Self::new(RendezvousTokenTableConfig {
            max_pending,
            token_ttl_secs,
            max_consumed: RendezvousTokenTableConfig::default().max_consumed,
        })
    }

    #[must_use]
    pub fn with_consumed_limits(
        max_pending: usize,
        token_ttl_secs: u64,
        max_consumed: usize,
    ) -> Self {
        Self::new(RendezvousTokenTableConfig {
            max_pending,
            token_ttl_secs,
            max_consumed,
        })
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn consumed_len(&self) -> usize {
        self.consumed.len()
    }

    pub fn prune_expired(&mut self, now_secs: u64) -> usize {
        self.prune_expired_consumed(now_secs);
        let expired: Vec<RendezvousToken> = self
            .pending
            .iter()
            .filter(|&(_token, pending)| pending.is_expired(now_secs, self.config.token_ttl_secs))
            .map(|(token, _pending)| token.clone())
            .collect();
        let expired_count = expired.len();
        for token in expired {
            self.pending.remove(&token);
            self.mark_consumed(token, now_secs);
        }
        expired_count
    }

    fn prune_expired_consumed(&mut self, now_secs: u64) -> usize {
        let expired: Vec<RendezvousToken> = self
            .consumed
            .iter()
            .filter(|&(_token, consumed_until_secs)| now_secs >= *consumed_until_secs)
            .map(|(token, _consumed_until_secs)| token.clone())
            .collect();
        let expired_count = expired.len();
        for token in expired {
            self.consumed.remove(&token);
            self.consumed_order.retain(|queued| queued != &token);
        }
        expired_count
    }

    fn is_consumed(&mut self, token: &RendezvousToken, now_secs: u64) -> bool {
        self.prune_expired_consumed(now_secs);
        self.consumed
            .get(token)
            .is_some_and(|consumed_until_secs| now_secs < *consumed_until_secs)
    }

    fn mark_consumed(&mut self, token: RendezvousToken, now_secs: u64) {
        self.prune_expired_consumed(now_secs);

        let consumed_until_secs = now_secs.saturating_add(self.config.token_ttl_secs);
        if self
            .consumed
            .insert(token.clone(), consumed_until_secs)
            .is_none()
        {
            self.consumed_order.push_back(token);
        }

        while self.consumed.len() > self.config.max_consumed {
            let Some(oldest) = self.consumed_order.pop_front() else {
                break;
            };
            self.consumed.remove(&oldest);
        }
    }

    pub fn offer(
        &mut self,
        token: RendezvousToken,
        role: RendezvousRole,
        stream: S,
        now_secs: u64,
    ) -> RendezvousOfferOutcome<S> {
        if self.is_consumed(&token, now_secs) {
            return RendezvousOfferOutcome::Rejected {
                reason: RendezvousRejectReason::TokenConsumed,
                stream,
            };
        }

        if self
            .pending
            .get(&token)
            .is_some_and(|pending| pending.is_expired(now_secs, self.config.token_ttl_secs))
        {
            self.pending.remove(&token);
            self.mark_consumed(token, now_secs);
            return RendezvousOfferOutcome::Rejected {
                reason: RendezvousRejectReason::Expired,
                stream,
            };
        }

        self.prune_expired(now_secs);

        if self.is_consumed(&token, now_secs) {
            return RendezvousOfferOutcome::Rejected {
                reason: RendezvousRejectReason::TokenConsumed,
                stream,
            };
        }

        if let Some(mut pending) = self.pending.remove(&token) {
            if pending.is_expired(now_secs, self.config.token_ttl_secs) {
                self.mark_consumed(token, now_secs);
                return RendezvousOfferOutcome::Rejected {
                    reason: RendezvousRejectReason::Expired,
                    stream,
                };
            }

            match role {
                RendezvousRole::Guest if pending.guest.is_some() => {
                    self.pending.insert(token, pending);
                    return RendezvousOfferOutcome::Rejected {
                        reason: RendezvousRejectReason::DuplicateRole,
                        stream,
                    };
                }
                RendezvousRole::Claw if pending.claw.is_some() => {
                    self.pending.insert(token, pending);
                    return RendezvousOfferOutcome::Rejected {
                        reason: RendezvousRejectReason::DuplicateRole,
                        stream,
                    };
                }
                RendezvousRole::Guest => pending.guest = Some(stream),
                RendezvousRole::Claw => pending.claw = Some(stream),
            }

            if pending.guest.is_some() && pending.claw.is_some() {
                // Both sides are present (checked immediately above), so neither
                // take() can be None here; take both only once that holds, leaving
                // a half-filled pending untouched on the parked path below.
                if let (Some(guest), Some(claw)) = (pending.guest.take(), pending.claw.take()) {
                    self.mark_consumed(token, now_secs);
                    return RendezvousOfferOutcome::Paired { guest, claw };
                }
            }

            self.pending.insert(token, pending);
            return RendezvousOfferOutcome::Parked;
        }

        if self.pending.len() >= self.config.max_pending {
            return RendezvousOfferOutcome::Rejected {
                reason: RendezvousRejectReason::CapacityExceeded,
                stream,
            };
        }

        self.pending
            .insert(token, PendingRendezvous::new(now_secs, role, stream));
        RendezvousOfferOutcome::Parked
    }

    /// Return whether an offer would park a new stream rather than pair.
    ///
    /// This mirrors the preconditions in [`Self::offer`] while the caller still
    /// owns the stream, allowing the public listener to acquire a source pending
    /// permit only for streams that will actually be parked. The method may
    /// prune expired entries or mark an expired token as consumed, but it does
    /// not insert the caller's stream.
    pub fn offer_would_park(
        &mut self,
        token: &RendezvousToken,
        role: RendezvousRole,
        now_secs: u64,
    ) -> Result<bool, RendezvousRejectReason> {
        if self.is_consumed(token, now_secs) {
            return Err(RendezvousRejectReason::TokenConsumed);
        }

        if self
            .pending
            .get(token)
            .is_some_and(|pending| pending.is_expired(now_secs, self.config.token_ttl_secs))
        {
            self.pending.remove(token);
            self.mark_consumed(token.clone(), now_secs);
            return Err(RendezvousRejectReason::Expired);
        }

        self.prune_expired(now_secs);

        if self.is_consumed(token, now_secs) {
            return Err(RendezvousRejectReason::TokenConsumed);
        }

        if let Some(pending) = self.pending.get(token) {
            if pending.is_expired(now_secs, self.config.token_ttl_secs) {
                self.pending.remove(token);
                self.mark_consumed(token.clone(), now_secs);
                return Err(RendezvousRejectReason::Expired);
            }
            return match role {
                RendezvousRole::Guest if pending.guest.is_some() => {
                    Err(RendezvousRejectReason::DuplicateRole)
                }
                RendezvousRole::Claw if pending.claw.is_some() => {
                    Err(RendezvousRejectReason::DuplicateRole)
                }
                _ => Ok(false),
            };
        }

        if self.pending.len() >= self.config.max_pending {
            return Err(RendezvousRejectReason::CapacityExceeded);
        }

        Ok(true)
    }
}

impl<S> Default for RendezvousTokenTable<S> {
    fn default() -> Self {
        Self::new(RendezvousTokenTableConfig::default())
    }
}

/// Splice two already-protected opaque streams.
///
/// The relay must not parse or authorize the inner bytes. Public relay wiring
/// must add the Noise layer before feeding streams here.
pub async fn splice_opaque_streams<A, B>(mut guest: A, mut claw: B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut guest, &mut claw).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn token(label: u8) -> RendezvousToken {
        RendezvousToken::try_new(vec![label; 16]).unwrap()
    }

    fn pair_token(
        table: &mut RendezvousTokenTable<&'static str>,
        token: RendezvousToken,
        now: u64,
    ) {
        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Guest, "guest", now),
            RendezvousOfferOutcome::Parked
        ));
        assert!(matches!(
            table.offer(token, RendezvousRole::Claw, "claw", now + 1),
            RendezvousOfferOutcome::Paired { .. }
        ));
    }

    #[test]
    fn rendezvous_stream_token_empty_and_too_large_rejected() {
        assert_eq!(
            RendezvousToken::try_new([]).unwrap_err(),
            RendezvousTokenError::Empty
        );
        assert_eq!(
            RendezvousToken::try_new(vec![0x11; MIN_RENDEZVOUS_TOKEN_LEN - 1]).unwrap_err(),
            RendezvousTokenError::TooSmall {
                actual: MIN_RENDEZVOUS_TOKEN_LEN - 1,
                min: MIN_RENDEZVOUS_TOKEN_LEN,
            }
        );
        assert_eq!(
            RendezvousToken::try_new(vec![0x11; MAX_RENDEZVOUS_TOKEN_LEN + 1]).unwrap_err(),
            RendezvousTokenError::TooLarge {
                actual: MAX_RENDEZVOUS_TOKEN_LEN + 1,
                max: MAX_RENDEZVOUS_TOKEN_LEN,
            }
        );
    }

    #[test]
    fn rendezvous_stream_token_debug_and_display_are_redacted() {
        let raw = b"0123456789abcdef0123456789abcdef";
        let token = RendezvousToken::try_new(raw).unwrap();
        let debug = format!("{token:?}");
        let display = token.to_string();
        let raw_text = String::from_utf8_lossy(raw);

        assert!(!debug.contains(raw_text.as_ref()));
        assert!(!display.contains(raw_text.as_ref()));
        assert!(debug.contains("redacted"));
        assert!(display.contains("redacted"));
    }

    #[test]
    fn rendezvous_stream_guest_and_claw_same_token_pair() {
        let mut table = RendezvousTokenTable::with_limits(8, 60);
        let token = token(0x01);

        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Guest, "guest", 100),
            RendezvousOfferOutcome::Parked
        ));
        match table.offer(token, RendezvousRole::Claw, "claw", 101) {
            RendezvousOfferOutcome::Paired { guest, claw } => {
                assert_eq!(guest, "guest");
                assert_eq!(claw, "claw");
            }
            _ => panic!("guest and claw should pair"),
        }
        assert_eq!(table.pending_len(), 0);
        assert_eq!(table.consumed_len(), 1);
    }

    #[test]
    fn rendezvous_stream_duplicate_same_role_rejected_without_consuming_pending() {
        let mut table = RendezvousTokenTable::with_limits(8, 60);
        let token = token(0x02);

        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Claw, "claw-a", 100),
            RendezvousOfferOutcome::Parked
        ));
        match table.offer(token.clone(), RendezvousRole::Claw, "claw-b", 101) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::DuplicateRole);
                assert_eq!(stream, "claw-b");
            }
            _ => panic!("duplicate claw should reject"),
        }
        match table.offer(token, RendezvousRole::Guest, "guest", 102) {
            RendezvousOfferOutcome::Paired { guest, claw } => {
                assert_eq!(guest, "guest");
                assert_eq!(claw, "claw-a");
            }
            _ => panic!("pending original claw should still pair"),
        }
    }

    #[test]
    fn rendezvous_stream_token_expires_and_does_not_pair() {
        let mut table = RendezvousTokenTable::with_limits(8, 5);
        let token = token(0x03);

        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Claw, "claw", 100),
            RendezvousOfferOutcome::Parked
        ));
        match table.offer(token.clone(), RendezvousRole::Guest, "guest", 105) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::Expired);
                assert_eq!(stream, "guest");
            }
            _ => panic!("expired token must reject"),
        }
        match table.offer(token, RendezvousRole::Claw, "claw-reuse", 106) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::TokenConsumed);
                assert_eq!(stream, "claw-reuse");
            }
            _ => panic!("expired token must not be reusable"),
        }
    }

    #[test]
    fn rendezvous_stream_capacity_limit_is_enforced() {
        let mut table = RendezvousTokenTable::with_limits(1, 60);

        assert!(matches!(
            table.offer(token(0x04), RendezvousRole::Guest, "guest-a", 100),
            RendezvousOfferOutcome::Parked
        ));
        match table.offer(token(0x05), RendezvousRole::Guest, "guest-b", 101) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::CapacityExceeded);
                assert_eq!(stream, "guest-b");
            }
            _ => panic!("second pending token should exceed capacity"),
        }
    }

    #[test]
    fn rendezvous_stream_offer_would_park_matches_table_preconditions() {
        let mut table = RendezvousTokenTable::with_limits(1, 5);
        let parked = token(0x44);

        assert_eq!(
            table.offer_would_park(&parked, RendezvousRole::Guest, 100),
            Ok(true)
        );
        assert!(matches!(
            table.offer(parked.clone(), RendezvousRole::Guest, "guest-a", 100),
            RendezvousOfferOutcome::Parked
        ));
        assert_eq!(
            table.offer_would_park(&parked, RendezvousRole::Claw, 101),
            Ok(false)
        );
        assert_eq!(
            table.offer_would_park(&parked, RendezvousRole::Guest, 101),
            Err(RendezvousRejectReason::DuplicateRole)
        );
        assert_eq!(
            table.offer_would_park(&token(0x45), RendezvousRole::Guest, 101),
            Err(RendezvousRejectReason::CapacityExceeded)
        );
        assert_eq!(
            table.offer_would_park(&parked, RendezvousRole::Claw, 106),
            Err(RendezvousRejectReason::Expired)
        );
        assert_eq!(
            table.offer_would_park(&parked, RendezvousRole::Guest, 107),
            Err(RendezvousRejectReason::TokenConsumed)
        );
    }

    #[test]
    fn rendezvous_stream_paired_token_cannot_be_reused() {
        let mut table = RendezvousTokenTable::with_limits(8, 60);
        let token = token(0x06);

        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Guest, "guest", 100),
            RendezvousOfferOutcome::Parked
        ));
        assert!(matches!(
            table.offer(token.clone(), RendezvousRole::Claw, "claw", 101),
            RendezvousOfferOutcome::Paired { .. }
        ));
        match table.offer(token, RendezvousRole::Guest, "guest-reuse", 102) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::TokenConsumed);
                assert_eq!(stream, "guest-reuse");
            }
            _ => panic!("paired token must not be reusable"),
        }
    }

    #[test]
    fn rendezvous_stream_zero_max_consumed_still_rejects_replay() {
        let mut table = RendezvousTokenTable::with_consumed_limits(8, 60, 0);
        let token = token(0x07);

        pair_token(&mut table, token.clone(), 100);
        assert_eq!(table.consumed_len(), 1);

        match table.offer(token, RendezvousRole::Guest, "guest-reuse", 102) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::TokenConsumed);
                assert_eq!(stream, "guest-reuse");
            }
            _ => panic!("zero max_consumed override must not disable one-time replay protection"),
        }
    }

    #[test]
    fn rendezvous_stream_consumed_tokens_are_pruned_and_bounded() {
        let mut table = RendezvousTokenTable::with_consumed_limits(8, 5, 2);
        pair_token(&mut table, token(0x08), 100);
        assert_eq!(table.consumed_len(), 1);

        assert!(matches!(
            table.offer(token(0x09), RendezvousRole::Guest, "guest-new", 106),
            RendezvousOfferOutcome::Parked
        ));
        assert_eq!(table.consumed_len(), 0);

        let mut table = RendezvousTokenTable::with_consumed_limits(8, 60, 2);
        pair_token(&mut table, token(0x0a), 202);
        pair_token(&mut table, token(0x0b), 204);
        pair_token(&mut table, token(0x0c), 206);

        assert_eq!(table.consumed_len(), 2);
        match table.offer(token(0x0b), RendezvousRole::Guest, "guest-reuse", 208) {
            RendezvousOfferOutcome::Rejected { reason, stream } => {
                assert_eq!(reason, RendezvousRejectReason::TokenConsumed);
                assert_eq!(stream, "guest-reuse");
            }
            _ => panic!("non-evicted consumed token must still reject"),
        }
    }

    #[tokio::test]
    async fn rendezvous_stream_splice_passes_opaque_bytes_both_directions() {
        let (mut guest_client, guest_relay) = tokio::io::duplex(128);
        let (claw_relay, mut claw_client) = tokio::io::duplex(128);
        let splice = tokio::spawn(splice_opaque_streams(guest_relay, claw_relay));

        let guest_payload = b"\x00opaque-from-guest\xff";
        guest_client.write_all(guest_payload).await.unwrap();
        let mut from_guest = vec![0; guest_payload.len()];
        claw_client.read_exact(&mut from_guest).await.unwrap();
        assert_eq!(from_guest, guest_payload);

        let claw_payload = b"\xfeopaque-from-claw\x00";
        claw_client.write_all(claw_payload).await.unwrap();
        let mut from_claw = vec![0; claw_payload.len()];
        guest_client.read_exact(&mut from_claw).await.unwrap();
        assert_eq!(from_claw, claw_payload);

        guest_client.shutdown().await.unwrap();
        claw_client.shutdown().await.unwrap();
        let copied = tokio::time::timeout(std::time::Duration::from_secs(2), splice)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(copied.0 >= guest_payload.len() as u64);
        assert!(copied.1 >= claw_payload.len() as u64);
    }
}
