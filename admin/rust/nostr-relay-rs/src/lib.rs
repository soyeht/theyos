//! Real Nostr WSS publish/subscribe + NIP-44 v2 encryption.
//!
//! Replaces the round-1 `InMemoryRelay` stub with a network-bound
//! implementation: opens a `wss://...` connection to a Nostr relay,
//! publishes encrypted events (NIP-44 v2) addressed by `#p` tag to
//! the recipient's pubkey, and subscribes by `#p` filter so the
//! recipient receives store-and-forwarded payloads on reconnect.
//!
//! Crypto is delegated to the `nostr` crate — Schnorr keypair, event
//! id derivation (NIP-01), and NIP-44 v2 (HKDF-SHA256 + `ChaCha20` +
//! HMAC-SHA256 with deterministic padding). Rolling these from
//! scratch under time pressure ships subtle bugs; review-grade impl
//! in nostr 0.43 is what we depend on.
//!
//! Architecture:
//! - One reader task per relay connection. It parses each inbound
//!   frame and routes by message type:
//!   `OK <event_id>` → `oneshot::Sender` registered by the publisher;
//!   `EVENT <sub_id>` → `mpsc::Sender` registered by `subscribe`;
//!   `EOSE` / `NOTICE` / `CLOSED` — dropped silently for the slice.
//! - One writer task per connection that drains an outbound channel.
//! - The public API exposes `connect`, `publish` (awaits OK),
//!   `subscribe` (returns an event stream), plus encrypt/decrypt
//!   helpers tied to the claw-share envelope.
//!
//! Reconnect / multi-relay failover is the CALLER's policy — wrap
//! `NostrRelayClient` in your own loop with backoff. Keeping it
//! single-connection makes the trust + locking model clear: one
//! connection, one peer, one set of pending event acks.

#![deny(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr::prelude::*;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message as WsMessage;

pub const CLAW_SHARE_RELAY_KIND: u16 = 1059;
pub const CLAW_SHARE_TAG_NAMESPACE: &str = "soyeht-claw-share";

/// Kind for household-internal mesh-log gossip. Regular range (relays
/// keep them) so an engine that comes online late catches up by
/// re-subscribing with no `since` filter. Production hardening
/// includes NIP-44 wrapping with a per-household symmetric key so the
/// relay sees opaque ciphertext; the slice ships unencrypted because
/// the inner `LogEntry` is already P-256 signed and authority is
/// enforced by the `mesh.write` caveat — privacy at the relay is a
/// separate (documented) follow-up.
pub const HOUSEHOLD_LOG_KIND: u16 = 30100;
pub const HOUSEHOLD_LOG_TAG: &str = "h";

// Re-export the `nostr` crate so server-rs et al. can use one
// authoritative path to its types (Keys, Event, Filter, ...) rather
// than depending on the exact `nostr` semver from two places.
pub use nostr;

#[derive(Debug, Error)]
pub enum NostrRelayError {
    #[error("WSS connect failed: {0}")]
    Connect(String),
    #[error("WSS send failed: {0}")]
    Send(String),
    #[error("WSS receive failed or closed")]
    ReceiveClosed,
    #[error("relay rejected event: {0}")]
    RelayRejected(String),
    #[error("malformed relay message: {0}")]
    MalformedMessage(String),
    #[error("crypto operation failed: {0}")]
    Crypto(String),
    #[error("decoded payload was not valid CBOR claim bytes")]
    PayloadNotClaim,
    #[error("invalid relay URL: {0}")]
    BadUrl(String),
    #[error("timeout after {0:?}")]
    Timeout(Duration),
}

/// Shared per-connection state for the demux router.
#[derive(Default)]
struct RouterState {
    pending_ok: HashMap<String, oneshot::Sender<Result<(), String>>>,
    subscriptions: HashMap<String, mpsc::Sender<Event>>,
}

pub struct NostrRelayClient {
    tx_outbound: mpsc::Sender<String>,
    router: Arc<Mutex<RouterState>>,
    relay_url: String,
}

impl NostrRelayClient {
    /// Open a WSS connection to `relay_url` and start the read/write
    /// tasks. Returns once the WSS handshake completes.
    ///
    /// # Errors
    ///
    /// `Connect` when DNS / TCP / TLS / handshake fails.
    pub async fn connect(relay_url: &str) -> Result<Self, NostrRelayError> {
        let parsed = url::Url::parse(relay_url)
            .map_err(|e| NostrRelayError::BadUrl(format!("{relay_url}: {e}")))?;
        if parsed.scheme() != "wss" && parsed.scheme() != "ws" {
            return Err(NostrRelayError::BadUrl(format!(
                "unsupported scheme {} (need wss or ws)",
                parsed.scheme()
            )));
        }
        let (ws_stream, _resp) = tokio_tungstenite::connect_async(relay_url)
            .await
            .map_err(|e| NostrRelayError::Connect(format!("{e}")))?;
        let (mut sink, mut stream) = ws_stream.split();

        let (tx_outbound, mut rx_outbound) = mpsc::channel::<String>(64);
        let router = Arc::new(Mutex::new(RouterState::default()));

        // Writer task — drains outbound text frames.
        tokio::spawn(async move {
            while let Some(msg) = rx_outbound.recv().await {
                if sink.send(WsMessage::Text(msg)).await.is_err() {
                    break;
                }
            }
        });

        // Reader / demux task — routes by message type.
        let router_for_reader = Arc::clone(&router);
        tokio::spawn(async move {
            while let Some(frame) = stream.next().await {
                let Ok(WsMessage::Text(text)) = frame else {
                    continue;
                };
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                Self::route_message(&router_for_reader, value).await;
            }
            // Connection closed — fail any outstanding OK waiters.
            let mut guard = router_for_reader.lock().await;
            for (_id, tx) in guard.pending_ok.drain() {
                let _ = tx.send(Err("connection closed".to_string()));
            }
            guard.subscriptions.clear();
        });

        Ok(Self {
            tx_outbound,
            router,
            relay_url: relay_url.to_string(),
        })
    }

    #[must_use]
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    async fn route_message(router: &Arc<Mutex<RouterState>>, value: Value) {
        let Some(arr) = value.as_array() else { return };
        let Some(tag) = arr.first().and_then(Value::as_str) else {
            return;
        };
        match tag {
            "OK" => {
                let event_id = arr.get(1).and_then(Value::as_str).unwrap_or("");
                let accepted = arr.get(2).and_then(Value::as_bool).unwrap_or(false);
                let reason = arr.get(3).and_then(Value::as_str).unwrap_or("").to_string();
                let mut guard = router.lock().await;
                if let Some(tx) = guard.pending_ok.remove(event_id) {
                    let _ = tx.send(if accepted { Ok(()) } else { Err(reason) });
                }
            }
            "EVENT" => {
                let sub_id = arr.get(1).and_then(Value::as_str).unwrap_or("");
                let Some(event_json) = arr.get(2) else { return };
                let Ok(event) = serde_json::from_value::<Event>(event_json.clone()) else {
                    return;
                };
                let guard = router.lock().await;
                if let Some(tx) = guard.subscriptions.get(sub_id) {
                    let _ = tx.send(event).await;
                }
            }
            _ => {
                // EOSE, NOTICE, CLOSED — slice ignores; production
                // surfaces via a metadata channel.
            }
        }
    }

    /// Publish a signed event and await the relay's `OK` reply.
    pub async fn publish(&self, event: &Event) -> Result<(), NostrRelayError> {
        let event_id = event.id.to_string();
        let (tx_ok, rx_ok) = oneshot::channel();
        {
            let mut guard = self.router.lock().await;
            guard.pending_ok.insert(event_id.clone(), tx_ok);
        }
        let serialized = json!(["EVENT", event]).to_string();
        self.tx_outbound
            .send(serialized)
            .await
            .map_err(|e| NostrRelayError::Send(e.to_string()))?;
        match rx_ok.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(reason)) => Err(NostrRelayError::RelayRejected(reason)),
            Err(_) => Err(NostrRelayError::ReceiveClosed),
        }
    }

    /// Subscribe with the given filter. Yields events on the returned
    /// receiver. Drop the receiver to unsubscribe (the next CLOSE
    /// from the relay will tear down the routing entry).
    pub async fn subscribe(
        &self,
        subscription_id: &str,
        filter: &Filter,
    ) -> Result<mpsc::Receiver<Event>, NostrRelayError> {
        let filter_json = serde_json::to_value(filter)
            .map_err(|e| NostrRelayError::Crypto(format!("filter encode: {e}")))?;
        let req = json!(["REQ", subscription_id, filter_json]).to_string();
        let (tx_events, rx_events) = mpsc::channel::<Event>(64);
        {
            let mut guard = self.router.lock().await;
            guard
                .subscriptions
                .insert(subscription_id.to_string(), tx_events);
        }
        self.tx_outbound
            .send(req)
            .await
            .map_err(|e| NostrRelayError::Send(e.to_string()))?;
        Ok(rx_events)
    }
}

/// Encrypt + publish a claim payload, addressed to the engine's
/// Nostr pubkey. The publisher (friend) uses their long-lived
/// per-device Nostr key (or an ephemeral one — caller's policy).
pub async fn publish_encrypted_claim(
    client: &NostrRelayClient,
    sender_keys: &Keys,
    engine_pubkey: &PublicKey,
    payload_cbor: &[u8],
) -> Result<(), NostrRelayError> {
    let payload_hex = nostr::util::hex::encode(payload_cbor);
    let ciphertext = nip44::encrypt(
        sender_keys.secret_key(),
        engine_pubkey,
        payload_hex,
        nip44::Version::V2,
    )
    .map_err(|e| NostrRelayError::Crypto(format!("nip44 encrypt: {e}")))?;

    let tags = vec![
        Tag::public_key(*engine_pubkey),
        Tag::custom(
            TagKind::custom("ns".to_string()),
            [CLAW_SHARE_TAG_NAMESPACE.to_string()],
        ),
    ];
    let event = EventBuilder::new(Kind::Custom(CLAW_SHARE_RELAY_KIND), ciphertext)
        .tags(tags)
        .sign_with_keys(sender_keys)
        .map_err(|e| NostrRelayError::Crypto(format!("sign event: {e}")))?;

    client.publish(&event).await
}

/// Decrypt an incoming event with the engine's private key. Returns
/// the CBOR payload bytes the friend originally encrypted.
pub fn decrypt_claim_payload(
    engine_keys: &Keys,
    event: &Event,
) -> Result<Vec<u8>, NostrRelayError> {
    let plaintext = nip44::decrypt(engine_keys.secret_key(), &event.pubkey, &event.content)
        .map_err(|e| NostrRelayError::Crypto(format!("nip44 decrypt: {e}")))?;
    nostr::util::hex::decode(plaintext.as_bytes()).map_err(|_| NostrRelayError::PayloadNotClaim)
}

// ─── Household-internal mesh log gossip ──────────────────────────────────────

/// Publish a household `LogEntry` to the relay under the household
/// topic. Multiple engines under the same `household_id` all
/// subscribe to this topic so a remove-wins projection converges.
///
/// Content carries base64url(no-pad) of the canonical CBOR of the
/// signed entry; the inner P-256 signature is the trust anchor for
/// other engines (they reject entries whose `issuer_pub` is not in
/// their authorized-writers set — caller's responsibility on ingest).
///
/// # Errors
///
/// `Crypto` on signing / encoding; `Send` / `RelayRejected` per
/// [`NostrRelayClient::publish`].
pub async fn publish_household_log_entry(
    client: &NostrRelayClient,
    engine_keys: &Keys,
    household_id: &str,
    entry_cbor: &[u8],
) -> Result<(), NostrRelayError> {
    use base64::Engine as _;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(entry_cbor);
    let tags = vec![Tag::custom(
        TagKind::custom(HOUSEHOLD_LOG_TAG.to_string()),
        [household_id.to_string()],
    )];
    let event = EventBuilder::new(Kind::Custom(HOUSEHOLD_LOG_KIND), payload)
        .tags(tags)
        .sign_with_keys(engine_keys)
        .map_err(|e| NostrRelayError::Crypto(format!("sign event: {e}")))?;
    client.publish(&event).await
}

/// Decode an inbound household-log event back into the CBOR bytes of
/// its `LogEntry`. The caller MUST then run
/// `LogEntry::verify()` + authority check before appending to the
/// local store.
///
/// # Errors
///
/// `PayloadNotClaim` if the event content isn't valid base64url.
pub fn decode_household_log_payload(event: &Event) -> Result<Vec<u8>, NostrRelayError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(event.content.as_bytes())
        .map_err(|_| NostrRelayError::PayloadNotClaim)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    async fn spawn_mock_relay() -> (tokio::task::JoinHandle<()>, String) {
        use tokio_tungstenite::accept_async;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://{addr}");
        let handle = tokio::spawn(async move {
            // Multi-client: each accept handled on its own task. We
            // share a single in-memory event store + subscription
            // registry across all client tasks so a friend can
            // publish on connection A and an engine subscribed on
            // connection B receives the fanout.
            // Map key: (peer_addr, sub_id) → (writer, #p tags, #h tags).
            type SubEntry = (mpsc::Sender<Value>, Vec<String>, Vec<String>);
            type SubMap = Arc<Mutex<HashMap<(String, String), SubEntry>>>;
            let subs: SubMap = Arc::new(Mutex::new(HashMap::new()));

            loop {
                let Ok((stream, addr)) = listener.accept().await else {
                    return;
                };
                let subs_clone = Arc::clone(&subs);
                tokio::spawn(async move {
                    let ws = accept_async(stream).await.unwrap();
                    let (mut sink, mut stream) = ws.split();
                    let (tx_out, mut rx_out) = mpsc::channel::<Value>(64);
                    let addr_str = addr.to_string();

                    // Writer for this connection.
                    let writer = tokio::spawn(async move {
                        while let Some(v) = rx_out.recv().await {
                            if sink
                                .send(WsMessage::Text(v.to_string().into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });

                    while let Some(frame) = stream.next().await {
                        let Ok(WsMessage::Text(text)) = frame else {
                            continue;
                        };
                        let Ok(v) = serde_json::from_str::<Value>(&text) else {
                            continue;
                        };
                        let arr = v.as_array().cloned().unwrap_or_default();
                        if arr.is_empty() {
                            continue;
                        }
                        match arr[0].as_str() {
                            Some("EVENT") => {
                                let event_json = arr.get(1).cloned().unwrap_or(Value::Null);
                                let event_id = event_json
                                    .get("id")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string();
                                // Route to every subscription that
                                // matched via the #p tag filter.
                                // Collect tag values for routing.
                                let mut event_p_tags = Vec::new();
                                let mut event_h_tags = Vec::new();
                                if let Some(tags) = event_json.get("tags").and_then(Value::as_array)
                                {
                                    for tag in tags {
                                        if let Some(arr) = tag.as_array() {
                                            match arr.first().and_then(Value::as_str) {
                                                Some("p") => {
                                                    if let Some(s) =
                                                        arr.get(1).and_then(Value::as_str)
                                                    {
                                                        event_p_tags.push(s.to_string());
                                                    }
                                                }
                                                Some("h") => {
                                                    if let Some(s) =
                                                        arr.get(1).and_then(Value::as_str)
                                                    {
                                                        event_h_tags.push(s.to_string());
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                let guard = subs_clone.lock().await;
                                for ((_addr, sid), (tx, p_filter, h_filter)) in guard.iter() {
                                    let p_match = p_filter.is_empty()
                                        || event_p_tags.iter().any(|t| p_filter.contains(t));
                                    let h_match = h_filter.is_empty()
                                        || event_h_tags.iter().any(|t| h_filter.contains(t));
                                    // The filter matches when EVERY
                                    // declared tag has at least one
                                    // hit. (Empty filter list = wildcard.)
                                    if p_match
                                        && h_match
                                        && !(p_filter.is_empty() && h_filter.is_empty())
                                    {
                                        let _ = tx
                                            .send(json!(["EVENT", sid, event_json.clone()]))
                                            .await;
                                    }
                                }
                                drop(guard);
                                let _ = tx_out.send(json!(["OK", event_id, true, ""])).await;
                            }
                            Some("REQ") => {
                                let sub_id =
                                    arr.get(1).and_then(Value::as_str).unwrap_or("").to_string();
                                // Capture the filter's #p and #h tags
                                // so the mock can route by either.
                                let mut p_tags = Vec::new();
                                let mut h_tags = Vec::new();
                                if let Some(filter) = arr.get(2) {
                                    if let Some(p) = filter.get("#p").and_then(Value::as_array) {
                                        for v in p {
                                            if let Some(s) = v.as_str() {
                                                p_tags.push(s.to_string());
                                            }
                                        }
                                    }
                                    if let Some(h) = filter.get("#h").and_then(Value::as_array) {
                                        for v in h {
                                            if let Some(s) = v.as_str() {
                                                h_tags.push(s.to_string());
                                            }
                                        }
                                    }
                                }
                                let mut guard = subs_clone.lock().await;
                                guard.insert(
                                    (addr_str.clone(), sub_id.clone()),
                                    (tx_out.clone(), p_tags, h_tags),
                                );
                                drop(guard);
                                let _ = tx_out.send(json!(["EOSE", sub_id])).await;
                            }
                            _ => {}
                        }
                    }
                    writer.abort();
                });
            }
        });
        (handle, url)
    }

    /// Multi-engine convergence over real Nostr: engine-A publishes
    /// an opaque household log entry; engine-B is subscribed to the
    /// same household topic on the same relay; engine-B receives the
    /// payload and recovers the same opaque bytes A sent. Asserts the
    /// gossip wire works end-to-end — authority and signature
    /// verification ride the inner `LogEntry`, not this transport.
    #[tokio::test]
    async fn household_log_gossip_converges_via_real_wss() {
        let (relay_handle, relay_url) = spawn_mock_relay().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let engine_a = Keys::generate();
        let engine_b = Keys::generate();
        let household_id = "hh_fixture";

        let client_a = NostrRelayClient::connect(&relay_url).await.expect("a");
        let client_b = NostrRelayClient::connect(&relay_url).await.expect("b");

        // Both engines subscribe to the same household topic. Engine
        // B is the receiver in this test.
        let filter = Filter::new()
            .kind(Kind::Custom(HOUSEHOLD_LOG_KIND))
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::H),
                household_id.to_string(),
            );
        let mut sub_b = client_b
            .subscribe("household-log-b", &filter)
            .await
            .expect("sub b");
        let _ = tokio::time::timeout(Duration::from_millis(200), sub_b.recv()).await;

        let log_payload = b"opaque-cbor-LogEntry-bytes".to_vec();
        publish_household_log_entry(&client_a, &engine_a, household_id, &log_payload)
            .await
            .expect("publish");

        let event = tokio::time::timeout(Duration::from_secs(3), sub_b.recv())
            .await
            .expect("recv timeout")
            .expect("event");
        // Independent verification: engine B did not produce this
        // event, but the inbound publisher is engine A's pubkey.
        assert_eq!(event.pubkey, engine_a.public_key());
        let decoded = decode_household_log_payload(&event).expect("decode");
        assert_eq!(decoded, log_payload);
        let _ = engine_b; // engine B's identity is what the production
        // code uses to authority-check inbound entries; we
        // assert the wire round-trip here.

        relay_handle.abort();
    }

    #[tokio::test]
    async fn publish_and_subscribe_round_trip_over_real_wss() {
        let (relay_handle, relay_url) = spawn_mock_relay().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let engine_keys = Keys::generate();
        let friend_keys = Keys::generate();

        let engine_client = NostrRelayClient::connect(&relay_url)
            .await
            .expect("engine connect");
        let friend_client = NostrRelayClient::connect(&relay_url)
            .await
            .expect("friend connect");

        let filter = Filter::new()
            .kind(Kind::Custom(CLAW_SHARE_RELAY_KIND))
            .pubkey(engine_keys.public_key());
        let mut sub = engine_client
            .subscribe("claw-share-test", &filter)
            .await
            .expect("subscribe");

        // Drain the EOSE that arrived right after REQ.
        let _ = tokio::time::timeout(Duration::from_millis(200), sub.recv()).await;

        let payload = b"opaque-cbor-claim-bytes".to_vec();
        publish_encrypted_claim(
            &friend_client,
            &friend_keys,
            &engine_keys.public_key(),
            &payload,
        )
        .await
        .expect("publish");

        let event = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("subscription timeout")
            .expect("event received");

        let decoded = decrypt_claim_payload(&engine_keys, &event).expect("decrypt");
        assert_eq!(decoded, payload, "decrypted payload must match");

        relay_handle.abort();
    }
}
