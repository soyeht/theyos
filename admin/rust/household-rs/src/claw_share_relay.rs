//! Relay store-and-forward transport for claw-share claims.
//!
//! The canonical claim path is *not* HTTP. From the architecture sketch:
//! before Alice accepts an invite she is not yet on the engine's mesh,
//! and the engine itself may be behind CGNAT or offline at the moment
//! she taps the link. Relying on direct HTTP from the friend to the
//! engine reintroduces the circular dependency the v2 sketch removed.
//!
//! Instead, the invite carries `owner_engine_npub` and a list of
//! `claim_relays` (WSS Nostr relays). The friend publishes an encrypted
//! `ClaimRequest` to one of the relays, addressed to the engine's
//! npub. The relay queues the event. The engine maintains an outbound
//! WSS subscription to its configured relays and consumes pending
//! claims when (re-)connected. It replies with an encrypted `ClaimAck`
//! via the same path.
//!
//! This module defines:
//!
//! - [`ClawShareRelayTransport`] — the trait the engine and the friend
//!   talk to. Real impl wraps `nostr-sdk` with NIP-44 encryption (slice
//!   9b — separate work).
//! - [`InMemoryRelay`] — a deterministic in-process implementation
//!   used by tests + the host-side harness. Mirrors the
//!   queue-then-deliver-on-subscribe semantics so the offline-at-tap
//!   scenario can be validated in unit tests today.
//!
//! HTTP `POST /api/v1/claw-share/claim` remains a fast-path that
//! engines accept when the friend can reach the engine directly. It is
//! NOT the contract: production deployments populate `claim_relays`
//! and degrade to HTTP only when both peers have direct connectivity.

#![allow(async_fn_in_trait)]

use std::collections::HashMap;
use std::sync::Mutex;

use crate::claw_share::ClawShareError;

/// Transport seam for the relay path. Real implementations wrap a
/// Nostr WSS client (nostr-sdk) with NIP-44 encryption keyed by the
/// `owner_engine_npub` ↔ guest device-npub pair.
pub trait ClawShareRelayTransport: Send + Sync {
    /// Publish an opaque `claim_bytes` payload to the named relays,
    /// addressed to `target_npub`. Returns Ok if at least one relay
    /// accepted the publish; per-relay failures are aggregated in
    /// tracing logs.
    ///
    /// The payload is whatever the caller already encrypted +
    /// serialized; this trait does not interpret it.
    async fn publish_claim(
        &self,
        relays: &[String],
        target_npub: &str,
        claim_bytes: Vec<u8>,
    ) -> Result<(), ClawShareError>;

    /// Drain one queued claim addressed to `subscriber_npub` from any
    /// of the named relays. Returns `Ok(None)` when no claim is
    /// currently queued — callers loop with backoff. Returns
    /// `Ok(Some(_))` when an event is available.
    ///
    /// Real impl keeps a long-lived WSS subscription and yields events
    /// as they arrive. The trait stays poll-shaped so callers can
    /// drive it from any event loop.
    async fn poll_claim_for(
        &self,
        relays: &[String],
        subscriber_npub: &str,
    ) -> Result<Option<Vec<u8>>, ClawShareError>;

    /// Symmetric to [`Self::publish_claim`] — engine → friend ack.
    async fn publish_ack(
        &self,
        relays: &[String],
        target_npub: &str,
        ack_bytes: Vec<u8>,
    ) -> Result<(), ClawShareError>;

    /// Symmetric to [`Self::poll_claim_for`] — friend polls for an
    /// engine ack on the relays it published to.
    async fn poll_ack_for(
        &self,
        relays: &[String],
        subscriber_npub: &str,
    ) -> Result<Option<Vec<u8>>, ClawShareError>;
}

// ─── In-memory implementation (tests + harness) ──────────────────────────────

/// Deterministic in-process relay used by host-side tests and the
/// development harness. Models the store-and-forward semantics: a
/// claim published before the engine subscribes still arrives when
/// the engine eventually polls.
///
/// Queues are keyed by `(direction, target_npub)`. The relay list
/// argument is ignored — every relay URL maps to the same in-process
/// queues. Production swaps this for a real WSS implementation.
#[derive(Default)]
pub struct InMemoryRelay {
    inner: Mutex<InMemoryRelayInner>,
}

#[derive(Default)]
struct InMemoryRelayInner {
    /// FIFO of claims pending delivery to each engine npub.
    inbox_claims: HashMap<String, Vec<Vec<u8>>>,
    /// FIFO of acks pending delivery to each friend npub.
    inbox_acks: HashMap<String, Vec<Vec<u8>>>,
}

impl InMemoryRelay {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ClawShareRelayTransport for InMemoryRelay {
    async fn publish_claim(
        &self,
        _relays: &[String],
        target_npub: &str,
        claim_bytes: Vec<u8>,
    ) -> Result<(), ClawShareError> {
        let mut guard = self.inner.lock().expect("in-memory relay mutex");
        guard
            .inbox_claims
            .entry(target_npub.to_string())
            .or_default()
            .push(claim_bytes);
        Ok(())
    }

    async fn poll_claim_for(
        &self,
        _relays: &[String],
        subscriber_npub: &str,
    ) -> Result<Option<Vec<u8>>, ClawShareError> {
        let mut guard = self.inner.lock().expect("in-memory relay mutex");
        Ok(guard.inbox_claims.get_mut(subscriber_npub).and_then(|q| {
            if q.is_empty() {
                None
            } else {
                Some(q.remove(0))
            }
        }))
    }

    async fn publish_ack(
        &self,
        _relays: &[String],
        target_npub: &str,
        ack_bytes: Vec<u8>,
    ) -> Result<(), ClawShareError> {
        let mut guard = self.inner.lock().expect("in-memory relay mutex");
        guard
            .inbox_acks
            .entry(target_npub.to_string())
            .or_default()
            .push(ack_bytes);
        Ok(())
    }

    async fn poll_ack_for(
        &self,
        _relays: &[String],
        subscriber_npub: &str,
    ) -> Result<Option<Vec<u8>>, ClawShareError> {
        let mut guard = self.inner.lock().expect("in-memory relay mutex");
        Ok(guard.inbox_acks.get_mut(subscriber_npub).and_then(|q| {
            if q.is_empty() {
                None
            } else {
                Some(q.remove(0))
            }
        }))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Acceptance scenario: friend publishes a claim before the engine
    /// subscribes (engine offline at tap). The relay queues the bytes.
    /// When the engine later polls, the claim is delivered. Engine
    /// publishes an ack; friend (still polling) eventually retrieves
    /// it. This proves the architecture works under the offline-at-tap
    /// + CGNAT-engine constraints — the in-process queue stands in for
    /// the real relay's store-and-forward.
    #[tokio::test]
    async fn offline_at_tap_claim_delivers_when_engine_subscribes() {
        let relay = InMemoryRelay::new();
        let relays = vec!["wss://relay.theyos.net".to_string()];
        let engine_npub = "npub1engine";
        let friend_npub = "npub1friend";

        // Engine offline: nothing to poll yet.
        assert!(
            relay
                .poll_claim_for(&relays, engine_npub)
                .await
                .expect("poll")
                .is_none()
        );

        // Friend taps invite, publishes claim. Engine still offline.
        let claim_payload = b"opaque-encrypted-claim-bytes".to_vec();
        relay
            .publish_claim(&relays, engine_npub, claim_payload.clone())
            .await
            .expect("publish claim");

        // Engine comes online and polls.
        let delivered = relay
            .poll_claim_for(&relays, engine_npub)
            .await
            .expect("poll after publish")
            .expect("payload available");
        assert_eq!(delivered, claim_payload);

        // Engine processes (out of scope for the transport layer) and
        // publishes an ack back. Friend was polling all along.
        let ack_payload = b"opaque-encrypted-ack-bytes".to_vec();
        relay
            .publish_ack(&relays, friend_npub, ack_payload.clone())
            .await
            .expect("publish ack");

        let delivered_ack = relay
            .poll_ack_for(&relays, friend_npub)
            .await
            .expect("poll ack")
            .expect("ack available");
        assert_eq!(delivered_ack, ack_payload);
    }

    /// Polling once delivers exactly one event; queues do not duplicate.
    #[tokio::test]
    async fn poll_drains_exactly_one_event() {
        let relay = InMemoryRelay::new();
        let relays = vec!["wss://r".to_string()];
        let target = "npub1x";
        relay
            .publish_claim(&relays, target, b"a".to_vec())
            .await
            .unwrap();
        relay
            .publish_claim(&relays, target, b"b".to_vec())
            .await
            .unwrap();

        let first = relay.poll_claim_for(&relays, target).await.unwrap();
        let second = relay.poll_claim_for(&relays, target).await.unwrap();
        let third = relay.poll_claim_for(&relays, target).await.unwrap();
        assert_eq!(first, Some(b"a".to_vec()));
        assert_eq!(second, Some(b"b".to_vec()));
        assert_eq!(third, None);
    }

    /// Queues are scoped by target npub; no cross-talk.
    #[tokio::test]
    async fn queues_are_isolated_by_target() {
        let relay = InMemoryRelay::new();
        let relays = vec![];
        relay
            .publish_claim(&relays, "npub1a", b"for-a".to_vec())
            .await
            .unwrap();
        relay
            .publish_claim(&relays, "npub1b", b"for-b".to_vec())
            .await
            .unwrap();

        assert_eq!(
            relay.poll_claim_for(&relays, "npub1a").await.unwrap(),
            Some(b"for-a".to_vec())
        );
        assert_eq!(
            relay.poll_claim_for(&relays, "npub1b").await.unwrap(),
            Some(b"for-b".to_vec())
        );
    }
}
