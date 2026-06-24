//! Engine-side relay subscription loops for claw-share.
//!
//! When the engine is configured with `THEYOS_NOSTR_RELAY` (comma-
//! separated list of WSS URLs), one (claim consumer, gossip
//! consumer) pair is spawned per relay. Each pair runs independently
//! with its own reconnect backoff and its own client. Outbound
//! household-log gossip fan-outs via a single `broadcast::channel`:
//! every gossip loop publishes the same `LogEntry` to its relay, so
//! "success if any relay delivers" is achieved by symmetry — peer
//! engines accept the first arrival and dedupe the rest by
//! `entry_id` at `MeshLogStore::append`.
//!
//! Ack delivery (claim → friend) flows back through the same relay
//! the claim came in on — that's the only place where the friend
//! Nostr pubkey is listening.
//!
//! Authority: every inbound `LogEntry` is filtered by
//! `check_mesh_write_authority` BEFORE append. A valid Schnorr/ECDSA
//! signature alone is not sufficient — `issuer_pub` must match the
//! household's `hh_pub`. When `MachineCert::caveats` grows a
//! `MeshWrite` variant (Phase 5), the check expands to include any
//! machine cert carrying that caveat.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use household_rs::cbor;
use household_rs::claw_share::{ClawShareAck, ClawShareClaim, ClawShareSlotStore, TunnelHandle};
use household_rs::claw_share_flow::{EngineContext, engine_handle_claim};
use household_rs::household_mesh_log::{LogEntry, MeshEvent, MeshLogStore};
use nostr_relay_rs::nostr::prelude::*;
use nostr_relay_rs::{
    CLAW_SHARE_RELAY_KIND, HOUSEHOLD_LOG_KIND, NostrRelayClient, decode_household_log_payload,
    decrypt_claim_payload, publish_encrypted_claim, publish_household_log_entry,
};
use tokio::sync::broadcast;

use crate::household_state::HouseholdState;

const RECONNECT_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(60);
const GOSSIP_FANOUT_CAPACITY: usize = 64;

/// Persistent Nostr identity for the engine. Stored under
/// `<state_dir>/nostr_engine_key.hex` (32-byte raw secret key, hex).
/// Generated on first boot; subsequent boots reload so the engine's
/// npub stays stable across restarts.
pub fn load_or_create_nostr_key(state_dir: &std::path::Path) -> std::io::Result<Keys> {
    let path = state_dir.join("nostr_engine_key.hex");
    if let Ok(hex) = std::fs::read_to_string(&path) {
        if let Ok(bytes) = nostr_relay_rs::nostr::util::hex::decode(hex.trim()) {
            if let Ok(sk) = SecretKey::from_slice(&bytes) {
                return Ok(Keys::new(sk));
            }
        }
    }
    let keys = Keys::generate();
    let raw_hex = nostr_relay_rs::nostr::util::hex::encode(keys.secret_key().secret_bytes());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, raw_hex)?;
    Ok(keys)
}

/// Per-engine relay state. `relay_urls` is the ordered list of WSS
/// endpoints the engine connects to; each yields a claim consumer +
/// gossip consumer pair. `gossip_tx` is the broadcast handle that
/// `process_one` writes to after a successful local append; every
/// gossip loop has its own `Receiver` clone and republishes via its
/// relay.
pub struct EngineRelayState {
    pub household: HouseholdState,
    pub slot_store: Arc<ClawShareSlotStore>,
    pub mesh_log: Arc<MeshLogStore>,
    pub engine_keys: Keys,
    pub relay_urls: Vec<String>,
    /// Engine state directory root, used only by the default-off `relay_stream`
    /// claim provisioning. Read only when `THEYOS_RELAY_STREAM_LIVE` is set.
    pub state_dir: std::path::PathBuf,
}

struct SpawnedState {
    base: EngineRelayState,
    gossip_tx: broadcast::Sender<Vec<u8>>,
}

/// Parse a comma-separated `THEYOS_NOSTR_RELAY` value into a list of
/// non-empty WSS URLs. Empty / whitespace-only tokens are skipped.
#[must_use]
pub fn parse_relay_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn short_hex(value: &str) -> String {
    const KEEP: usize = 12;
    if value.len() <= KEEP {
        value.to_string()
    } else {
        format!("{}…", &value[..KEEP])
    }
}

fn p_tag_summary(event: &Event) -> (usize, Option<String>) {
    let mut count = 0usize;
    let mut first = None;
    for tag in event.tags.as_slice() {
        let parts = tag.as_slice();
        if parts.first().map(String::as_str) != Some("p") {
            continue;
        }
        count += 1;
        if first.is_none() {
            first = parts.get(1).map(|value| short_hex(value));
        }
    }
    (count, first)
}

/// Spawn the engine's relay loops on the current Tokio runtime.
/// Returns immediately; the loops live for the engine process
/// lifetime.
pub fn spawn(state: EngineRelayState) {
    if state.relay_urls.is_empty() {
        tracing::warn!(
            stage = "claw_share.relay.no_relays_configured",
            "EngineRelayState has empty relay_urls — no loops spawned",
        );
        return;
    }
    tracing::info!(
        stage = "claw_share.relay.spawn",
        relay_count = state.relay_urls.len(),
        relays = %state.relay_urls.join(","),
        engine_pub = %short_hex(&state.engine_keys.public_key().to_string()),
        "spawning claim/gossip relay loops",
    );
    let (gossip_tx, _) = broadcast::channel::<Vec<u8>>(GOSSIP_FANOUT_CAPACITY);
    let spawned = Arc::new(SpawnedState {
        base: state,
        gossip_tx: gossip_tx.clone(),
    });
    for relay_url in spawned.base.relay_urls.clone() {
        let url_for_claim = relay_url.clone();
        let url_for_gossip = relay_url.clone();
        let claim_state = Arc::clone(&spawned);
        let gossip_state = Arc::clone(&spawned);
        tokio::spawn(run_claim_loop(claim_state, url_for_claim));
        tokio::spawn(run_gossip_loop(gossip_state, url_for_gossip));
    }
}

// ─── claim consumer ──────────────────────────────────────────────────────────

async fn run_claim_loop(state: Arc<SpawnedState>, relay_url: String) {
    let mut backoff = RECONNECT_BACKOFF_INITIAL;
    loop {
        tracing::info!(
            stage = "claw_share.relay.claim.connect_start",
            relay = %relay_url,
        );
        match run_claim_session(&state, &relay_url).await {
            Ok(()) => {
                tracing::info!(
                    stage = "claw_share.relay.session_ended",
                    relay = %relay_url,
                    "claim session ended cleanly; reconnecting",
                );
                backoff = RECONNECT_BACKOFF_INITIAL;
            }
            Err(e) => {
                tracing::warn!(
                    stage = "claw_share.relay.session_error",
                    relay = %relay_url,
                    error = %e,
                    backoff_ms = backoff.as_millis(),
                    "claim session errored; backing off",
                );
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

async fn run_claim_session(
    state: &SpawnedState,
    relay_url: &str,
) -> Result<(), nostr_relay_rs::NostrRelayError> {
    let client = NostrRelayClient::connect(relay_url).await?;
    tracing::info!(
        stage = "claw_share.relay.claim.connect_ok",
        relay = %relay_url,
    );
    let filter = Filter::new()
        .kind(Kind::Custom(CLAW_SHARE_RELAY_KIND))
        .pubkey(state.base.engine_keys.public_key());
    tracing::info!(
        stage = "claw_share.relay.claim.subscribe_start",
        relay = %relay_url,
        sub_id = "engine-claims",
        kind = CLAW_SHARE_RELAY_KIND,
        p_tag = %short_hex(&state.base.engine_keys.public_key().to_string()),
    );
    let mut sub = client.subscribe("engine-claims", &filter).await?;
    tracing::info!(
        stage = "claw_share.relay.claim.subscribed",
        relay = %relay_url,
        sub_id = "engine-claims",
        kind = CLAW_SHARE_RELAY_KIND,
        p_tag = %short_hex(&state.base.engine_keys.public_key().to_string()),
    );

    while let Some(event) = sub.recv().await {
        let event_id = event.id.to_string();
        let event_kind = event.kind.as_u16();
        let event_pub = event.pubkey.to_string();
        let (p_tag_count, first_p_tag) = p_tag_summary(&event);
        tracing::info!(
            stage = "claw_share.relay.claim.event_received",
            relay = %relay_url,
            event_id = %short_hex(&event_id),
            kind = event_kind,
            author = %short_hex(&event_pub),
            p_tag_count,
            first_p_tag = %first_p_tag.as_deref().unwrap_or("-"),
            content_len = event.content.len(),
        );
        if let Err(e) = process_one(&client, state, relay_url, event).await {
            tracing::warn!(
                stage = "claw_share.relay.process_failed",
                relay = %relay_url,
                event_id = %short_hex(&event_id),
                kind = event_kind,
                error = %e,
            );
        } else {
            tracing::info!(
                stage = "claw_share.relay.claim.process_ok",
                relay = %relay_url,
                event_id = %short_hex(&event_id),
            );
        }
    }
    tracing::warn!(
        stage = "claw_share.relay.claim.receive_closed",
        relay = %relay_url,
    );
    Err(nostr_relay_rs::NostrRelayError::ReceiveClosed)
}

// ─── household-log gossip consumer ───────────────────────────────────────────

async fn run_gossip_loop(state: Arc<SpawnedState>, relay_url: String) {
    let mut backoff = RECONNECT_BACKOFF_INITIAL;
    loop {
        match run_gossip_session(&state, &relay_url).await {
            Ok(()) => {
                tracing::info!(
                    stage = "household_log.gossip.session_ended",
                    relay = %relay_url,
                );
                backoff = RECONNECT_BACKOFF_INITIAL;
            }
            Err(e) => {
                tracing::warn!(
                    stage = "household_log.gossip.session_error",
                    relay = %relay_url,
                    error = %e,
                );
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

async fn run_gossip_session(
    state: &SpawnedState,
    relay_url: &str,
) -> Result<(), nostr_relay_rs::NostrRelayError> {
    let identity = state.base.household.current().await;
    let Some(identity) = identity else {
        return Err(nostr_relay_rs::NostrRelayError::Crypto(
            "household identity not loaded".to_string(),
        ));
    };
    let hh_id = identity.record.hh_id.to_string();
    let authorized_pub = identity.record.hh_pub.clone();
    drop(identity);

    let client = NostrRelayClient::connect(relay_url).await?;
    let filter = Filter::new()
        .kind(Kind::Custom(HOUSEHOLD_LOG_KIND))
        .custom_tag(SingleLetterTag::lowercase(Alphabet::H), hh_id.clone());
    let mut sub = client.subscribe("engine-log-gossip", &filter).await?;
    let mut pub_rx = state.gossip_tx.subscribe();
    tracing::info!(
        stage = "household_log.gossip.subscribed",
        relay = %relay_url,
        hh_id = %hh_id,
    );

    loop {
        tokio::select! {
            event = sub.recv() => {
                match event {
                    Some(event) => {
                        if let Err(e) = ingest_log_event(state, &authorized_pub, &event) {
                            tracing::warn!(
                                stage = "household_log.gossip.ingest_failed",
                                relay = %relay_url,
                                error = %e,
                            );
                        }
                    }
                    None => return Err(nostr_relay_rs::NostrRelayError::ReceiveClosed),
                }
            }
            outbound = pub_rx.recv() => {
                match outbound {
                    Ok(cbor) => {
                        if let Err(e) = publish_household_log_entry(
                            &client,
                            &state.base.engine_keys,
                            &hh_id,
                            &cbor,
                        ).await {
                            tracing::warn!(
                                stage = "household_log.gossip.publish_failed",
                                relay = %relay_url,
                                error = %e,
                                "fanout will be attempted by sibling relays",
                            );
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            stage = "household_log.gossip.fanout_lagged",
                            relay = %relay_url,
                            skipped = %skipped,
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(nostr_relay_rs::NostrRelayError::ReceiveClosed);
                    }
                }
            }
        }
    }
}

// ─── authority + ingest helpers ──────────────────────────────────────────────

/// `mesh.write` authority check. Today: `entry.issuer_pub` must match
/// `hh_pub`. When `MachineCert::caveats` grows `MeshWrite` (Phase 5),
/// expand to OR-include any cert carrying it.
fn check_mesh_write_authority(
    authorized_pub: &household_rs::keys::P256PublicKey,
    entry: &LogEntry,
) -> Result<(), &'static str> {
    if entry.issuer_pub.as_bytes() != authorized_pub.as_bytes() {
        return Err("issuer_pub is not authorized for mesh.write in this household");
    }
    Ok(())
}

fn ingest_log_event(
    state: &SpawnedState,
    authorized_pub: &household_rs::keys::P256PublicKey,
    event: &Event,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cbor_bytes = decode_household_log_payload(event)?;
    let entry: LogEntry = cbor::from_canonical_slice(&cbor_bytes)?;
    check_mesh_write_authority(authorized_pub, &entry)?;
    match state.base.mesh_log.append(entry) {
        Ok(true) => {
            tracing::info!(stage = "household_log.gossip.ingested");
            Ok(())
        }
        Ok(false) => Ok(()),
        Err(e) => Err(Box::new(e)),
    }
}

// ─── claim consume + ack ─────────────────────────────────────────────────────

async fn process_one(
    client: &NostrRelayClient,
    state: &SpawnedState,
    relay_url: &str,
    event: Event,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Resolve the data-plane handle via the SAME pub(crate) helper `handle_claim`
    // uses (see `tunnel_factory` below), so the HTTP + relay paths can't drift.
    use crate::handlers_claw_share::public_data_tunnel_handle;

    let friend_pubkey = event.pubkey;
    let payload = decrypt_claim_payload(&state.base.engine_keys, &event)?;
    let claim: ClawShareClaim = cbor::from_canonical_slice(&payload)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let Some(identity) = state.base.household.current().await else {
        return Err("household identity not loaded".into());
    };
    let Some(owner_auth) = state.base.household.current_owner_auth().await else {
        return Err("owner auth not loaded".into());
    };

    let owner_key = identity.m_priv.as_ref();
    let owner_p_id = &owner_auth.owner_person_cert.p_id;
    let hh_id = &identity.record.hh_id;

    // This relay/membership subset uses no overlay: a public Direct address
    // (operator-configured) wins; else a Loopback channel for the single-host
    // harness. The L3 overlay handle is intentionally not part of this subset.
    let tunnel_factory = |claw_id: &str| {
        public_data_tunnel_handle().unwrap_or_else(|| TunnelHandle::Loopback {
            channel: format!("claw={claw_id}"),
        })
    };
    let credential_ttl_secs = std::env::var("THEYOS_CLAW_SHARE_CRED_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(7 * 24 * 60 * 60);

    let ctx = EngineContext {
        owner_key,
        owner_p_id,
        hh_id,
        slot_store: &state.base.slot_store,
        credential_ttl_secs,
        tunnel_factory: &tunnel_factory,
    };

    let mut ack: ClawShareAck = engine_handle_claim(&ctx, &claim, now)?;

    // Instrumentation: prove which TunnelHandle the WSS claim actually emits.
    // This relay/membership subset emits Direct/Loopback only (the L3 overlay
    // handle is not part of this subset). NO secrets.
    {
        let handle_kind = match &ack.tunnel {
            TunnelHandle::Direct { .. } => "direct",
            TunnelHandle::Loopback { .. } => "loopback",
        };
        tracing::info!(
            stage = "claw_share.relay.tunnel_emitted",
            handle = %handle_kind,
            claw_id = %ack.credential.claw_id,
        );
    }

    let consume_event = MeshEvent::ClawShareSlotConsumed {
        slot_id: ack.credential.slot_id.clone(),
        guest_device_pub: ack.credential.guest_device_pub.clone(),
        claw_id: ack.credential.claw_id.clone(),
        expires_at: ack.credential.expires_at,
        // Persist the SIGNED overlay npub (keystone) — same as the HTTP path so
        // the two cannot drift. Drives the share-derived roster.
        participant_npub: claim.participant_npub.clone(),
    };
    let log_entry = LogEntry::sign(now, owner_key.public(), consume_event, owner_key)?;
    let entry_cbor = cbor::to_canonical_vec(&log_entry)?;
    state.base.mesh_log.append(log_entry)?;

    // Relay/NIP-44 path: provision the relay_stream offer for this consumed slot
    // AND deliver it in the ack — this ack is end-to-end encrypted to the friend
    // (publish_encrypted_claim), so the offer's rendezvous token is confidential.
    // Best-effort: a provision or serialize failure leaves the offer absent and
    // never fails the claim/ack. (The HTTP claim path provisions too but leaves
    // the ack None, since HTTP is plaintext.)
    let provisioned =
        crate::claw_share_relay_stream_mount::try_provision_relay_stream_offer_for_claim(
            &state.base.state_dir,
            &state.base.household,
            &state.base.mesh_log,
            owner_key,
            &ack.credential,
            now,
        )
        .await;
    if let Some(offer) = provisioned {
        // Serialize the EXACT offer just provisioned (same mint, also persisted
        // for the pool) as opaque canonical CBOR for the guest to decode.
        match cbor::to_canonical_vec(&offer) {
            Ok(bytes) => ack.relay_stream_offer = Some(serde_bytes::ByteBuf::from(bytes)),
            Err(error) => tracing::warn!(
                stage = "claw_share.relay_stream.claim_offer_encode_failed",
                error = %error,
                "relay_stream offer encode failed; delivering ack without it",
            ),
        }
    }

    // Fanout: every gossip loop has a Receiver clone — each
    // republishes via its own relay. "Success if any relay delivers"
    // is achieved because peer engines dedupe by entry_id.
    let _ = state.gossip_tx.send(entry_cbor);

    let ack_cbor = cbor::to_canonical_vec(&ack)?;
    publish_encrypted_claim(client, &state.base.engine_keys, &friend_pubkey, &ack_cbor).await?;
    tracing::info!(
        stage = "claw_share.relay.claim_acked",
        claw_id = %ack.credential.claw_id,
        relay = %relay_url,
    );
    Ok(())
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::household_mesh_log::MeshEvent;
    use household_rs::keys::{IdentityKey, P256Keypair};

    fn fake_consume_event() -> MeshEvent {
        MeshEvent::ClawShareSlotConsumed {
            slot_id: household_rs::claw_share::SlotId([0u8; 16]),
            guest_device_pub: household_rs::keys::P256Keypair::from_secret_scalar(&[0x33u8; 32])
                .unwrap()
                .public(),
            claw_id: "claw_test".to_string(),
            expires_at: 1_800_000_000,
            participant_npub: None,
        }
    }

    #[test]
    fn parse_relay_list_handles_csv_and_whitespace() {
        assert_eq!(parse_relay_list(""), Vec::<String>::new());
        assert_eq!(
            parse_relay_list("wss://a, wss://b ,, wss://c"),
            vec!["wss://a", "wss://b", "wss://c"]
        );
        assert_eq!(parse_relay_list("wss://only"), vec!["wss://only"]);
    }

    #[test]
    fn mesh_write_rejects_entry_from_unauthorized_signer() {
        let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
        let intruder = P256Keypair::from_secret_scalar(&[0xAAu8; 32]).unwrap();
        let entry = LogEntry::sign(
            1_800_000_000,
            intruder.public(),
            fake_consume_event(),
            &intruder,
        )
        .unwrap();
        // Entry signature is cryptographically valid — verify() passes.
        assert!(entry.verify().is_ok());
        // But the authority check rejects it because intruder is not
        // the household owner.
        assert!(
            check_mesh_write_authority(&owner.public(), &entry).is_err(),
            "intruder-signed entry must be rejected even with valid signature"
        );
    }

    #[test]
    fn mesh_write_accepts_entry_from_household_owner() {
        let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
        let entry =
            LogEntry::sign(1_800_000_000, owner.public(), fake_consume_event(), &owner).unwrap();
        assert!(check_mesh_write_authority(&owner.public(), &entry).is_ok());
    }

    #[test]
    fn mesh_write_rejects_forged_group_claw_grant_from_non_owner() {
        // The replication CARRY (design risk #4) must close for the NEW Fase E
        // group/membership events, not only ClawShareSlotConsumed: a forged
        // GroupClawGranted from a valid-but-non-owner key has a cryptographically
        // valid signature yet must be rejected before the fold, because group
        // grants are owner-only. The gate is variant-agnostic (it checks
        // issuer_pub), so this locks the protection for the whole new event family.
        let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
        let intruder = P256Keypair::from_secret_scalar(&[0xAAu8; 32]).unwrap();

        let forged = LogEntry::sign(
            1_800_000_000,
            intruder.public(),
            MeshEvent::GroupClawGranted {
                group_id: "g".to_string(),
                claw_id: "claw_alpha".to_string(),
            },
            &intruder,
        )
        .unwrap();
        // The entry's own signature is self-consistent...
        assert!(forged.verify().is_ok());
        // ...but the household authority check rejects a non-owner issuer.
        assert!(
            check_mesh_write_authority(&owner.public(), &forged).is_err(),
            "a forged GroupClawGranted from a non-owner must be rejected at ingest"
        );

        // The same owner-signed group event IS authorized.
        let owner_signed = LogEntry::sign(
            1_800_000_000,
            owner.public(),
            MeshEvent::GroupClawGranted {
                group_id: "g".to_string(),
                claw_id: "claw_alpha".to_string(),
            },
            &owner,
        )
        .unwrap();
        assert!(check_mesh_write_authority(&owner.public(), &owner_signed).is_ok());
    }

    /// Multi-relay fanout: when a `LogEntry` is broadcast and one
    /// relay is "dead" (its receiver is dropped), the surviving relay
    /// still receives the entry. The dedupe contract at
    /// `MeshLogStore::append` ensures duplicate deliveries from
    /// healthy relays are silent no-ops, so "success if any relay
    /// delivers" is the operative invariant.
    #[tokio::test]
    async fn gossip_fanout_survives_dead_relay() {
        let (tx, _placeholder) = broadcast::channel::<Vec<u8>>(8);
        let mut relay_alive = tx.subscribe();
        let relay_dead = tx.subscribe();
        drop(relay_dead); // simulate the dead-relay loop having exited

        let payload = b"entry-cbor-bytes".to_vec();
        // The publish "succeeds" (broadcast returns the count of
        // active receivers, which includes the alive one).
        let count = tx.send(payload.clone()).expect("broadcast");
        assert!(count >= 1, "at least one live receiver must remain");

        let got = relay_alive
            .recv()
            .await
            .expect("alive receiver got payload");
        assert_eq!(got, payload, "alive relay receives the same payload");
    }
}
