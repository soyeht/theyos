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
use household_rs::claw_share::{
    CLAW_SHARE_GROUP_ACK_VERSION, CLAW_SHARE_GROUP_REQUEST_VERSION, ClawShareAck, ClawShareClaim,
    ClawShareGroupAck, ClawShareSlotStore, GroupClaimRequest, SLOT_ID_LEN, SlotId, TunnelHandle,
};
use household_rs::claw_share_flow::{EngineContext, engine_handle_claim};
use household_rs::household_mesh_log::{LogEntry, MeshEvent, MeshLogStore, ProjectedState};
use household_rs::keys::{IdentityKey, P256PublicKey};
use nostr_relay_rs::nostr::prelude::*;
use nostr_relay_rs::{
    CLAW_SHARE_RELAY_KIND, HOUSEHOLD_LOG_KIND, NostrRelayClient, decode_household_log_payload,
    decrypt_claim_payload, publish_encrypted_claim, publish_household_log_entry,
};
use tokio::sync::broadcast;

use crate::claw_share_relay_offer_challenge::{GROUP_CLAIM_NONCE_TTL_SECS, GroupClaimNonceTable};
use crate::claw_share_relay_stream_contract::check_relay_stream_group_membership;
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
    /// Shared single-use nonce guard for Path-A Group claims. One Arc is shared
    /// by all relay loops so replaying the same claim on another relay is still
    /// rejected.
    pub group_claim_nonces: Arc<GroupClaimNonceTable>,
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

/// Whether a claim must wait for the owner identity (`owner_auth`) to be loaded
/// before it can be processed.
///
/// Only the DEVICE credential flow needs it — to mint a `GuestCredential` bound to
/// the owner `p_id`. A credential-less GROUP claim authenticates end-to-end via
/// [`verify_group_claim`] (member-signed binding + device `PoP` + live membership)
/// and is served a machine-cert-signed offer, so it needs only the machine key
/// (`m_priv`) + the live projection — never `owner_auth`. Routing group claims
/// before the `owner_auth` guard is therefore owner-independent by construction.
///
/// Regression: a live hardware smoke hit `error="owner auth not loaded"` on a
/// headless dev engine (whose owner `PersonCert` lives only in the app keychain)
/// because the group branch used to sit BELOW the guard. This predicate pins the
/// invariant that the guard is Device-only.
fn claim_requires_owner_auth(claim: &ClawShareClaim) -> bool {
    claim.group_request.is_none()
}

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
    let owner_key = identity.m_priv.as_ref();

    // Credential-less GROUP claims authenticate end-to-end via the member-signed
    // binding + device PoP carried inside the claim, and the handler needs only
    // the machine key (`m_priv`) plus the live projection — NOT `owner_auth`.
    // Route them BEFORE the owner_auth guard so a group member reaches the claw
    // even when the owner identity is not loaded (owner-independent group access
    // is the whole point; a live smoke hit "owner auth not loaded" because the
    // branch used to sit below the guard).
    if let Some(group_req) = claim.group_request.clone() {
        return handle_group_claim(
            client,
            state,
            relay_url,
            &friend_pubkey,
            owner_key,
            &claim,
            &group_req,
            now,
        )
        .await;
    }

    // Past the group branch every remaining claim is a Device credential claim,
    // which DOES need the owner identity (`owner_p_id`) to mint the
    // `GuestCredential`. The owner_auth guard is Device-only — credential-less
    // group claims (returned above) are owner-independent. This holds by the early
    // return above; the assert pins it so a future change that routes a non-Device
    // claim here is caught instead of silently mis-gated.
    assert!(
        claim_requires_owner_auth(&claim),
        "owner_auth guard reached by a non-Device claim; group claims must route above it",
    );
    let Some(owner_auth) = state.base.household.current_owner_auth().await else {
        return Err("owner auth not loaded".into());
    };
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

// ─── Path-A Group claim handling ─────────────────────────────────────────────

const GROUP_OFFER_DEFAULT_TTL_SECS: u64 = 600;
const GROUP_OFFER_MAX_TTL_SECS: u64 = 600;

pub(crate) struct VerifiedGroupClaim {
    pub(crate) group_id: String,
    pub(crate) member_id: String,
    pub(crate) device_pub: P256PublicKey,
    pub(crate) claw_id: String,
    pub(crate) ttl_secs: Option<u64>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum GroupClaimReject {
    ClaimInvalid,
    RequestVersion,
    ChallengeNotNonce,
    DeviceMismatch,
    BindingInvalid,
    DevicePop,
    NonceReplay,
    NotAuthorized(&'static str),
    NonSentinelDeviceFields,
}

pub(crate) fn verify_group_claim(
    claim: &ClawShareClaim,
    group_req: &GroupClaimRequest,
    projection: &ProjectedState,
    nonce_table: &GroupClaimNonceTable,
    now: u64,
) -> Result<VerifiedGroupClaim, GroupClaimReject> {
    claim
        .verify(now)
        .map_err(|_| GroupClaimReject::ClaimInvalid)?;

    if group_req.v != CLAW_SHARE_GROUP_REQUEST_VERSION {
        return Err(GroupClaimReject::RequestVersion);
    }

    if group_req.challenge.as_slice() != &claim.nonce.0[..] {
        return Err(GroupClaimReject::ChallengeNotNonce);
    }

    if group_req.binding.device_pub != claim.guest_device_pub {
        return Err(GroupClaimReject::DeviceMismatch);
    }

    group_req
        .binding
        .verify()
        .map_err(|_| GroupClaimReject::BindingInvalid)?;

    group_req
        .verify_device_pop()
        .map_err(|_| GroupClaimReject::DevicePop)?;

    if !nonce_table.record_first_use(&claim.nonce.0, now, GROUP_CLAIM_NONCE_TTL_SECS) {
        return Err(GroupClaimReject::NonceReplay);
    }

    check_relay_stream_group_membership(
        projection,
        &group_req.group_id,
        &group_req.binding.member_id,
        &group_req.claw_id,
        &group_req.binding.device_pub,
    )
    .map_err(GroupClaimReject::NotAuthorized)?;

    if claim.slot_id != SlotId([0u8; SLOT_ID_LEN]) || claim.participant_npub.is_some() {
        return Err(GroupClaimReject::NonSentinelDeviceFields);
    }

    Ok(VerifiedGroupClaim {
        group_id: group_req.group_id.clone(),
        member_id: group_req.binding.member_id.clone(),
        device_pub: group_req.binding.device_pub.clone(),
        claw_id: group_req.claw_id.clone(),
        ttl_secs: group_req.ttl_secs,
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_group_claim(
    client: &NostrRelayClient,
    state: &SpawnedState,
    relay_url: &str,
    friend_pubkey: &PublicKey,
    owner_key: &dyn IdentityKey,
    claim: &ClawShareClaim,
    group_req: &GroupClaimRequest,
    now: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let projection = state.base.mesh_log.project();
    let verified = match verify_group_claim(
        claim,
        group_req,
        &projection,
        &state.base.group_claim_nonces,
        now,
    ) {
        Ok(value) => value,
        Err(reason) => {
            tracing::warn!(
                stage = "claw_share.relay.group_claim_rejected",
                reason = ?reason,
                relay = %relay_url,
                "group claim rejected; no ack emitted",
            );
            return Ok(());
        }
    };

    let ttl = verified
        .ttl_secs
        .unwrap_or(GROUP_OFFER_DEFAULT_TTL_SECS)
        .min(GROUP_OFFER_MAX_TTL_SECS);

    let Some(offer) = crate::claw_share_relay_stream_mount::try_provision_group_offer_for_claim(
        &state.base.state_dir,
        &state.base.household,
        &state.base.mesh_log,
        owner_key,
        verified.group_id,
        verified.member_id,
        verified.device_pub,
        verified.claw_id,
        now.saturating_add(ttl),
        now,
    )
    .await
    else {
        return Ok(());
    };

    let offer_bytes = cbor::to_canonical_vec(&offer)?;
    let ack = ClawShareGroupAck {
        v: CLAW_SHARE_GROUP_ACK_VERSION,
        relay_stream_offer: serde_bytes::ByteBuf::from(offer_bytes),
    };
    let ack_cbor = cbor::to_canonical_vec(&ack)?;
    publish_encrypted_claim(client, &state.base.engine_keys, friend_pubkey, &ack_cbor).await?;
    tracing::info!(
        stage = "claw_share.relay.group_claim_acked",
        relay = %relay_url,
        "group offer delivered in encrypted ack",
    );
    Ok(())
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::claw_share::{CLAIM_TIMESTAMP_TOLERANCE_SECS, ClaimNonce, ClawShareError};
    use household_rs::household_mesh_log::{
        MeshEvent, MeshMembership, ProjectedGroup, ProjectedMemberDevice,
    };
    use household_rs::ids::derive_household_id;
    use household_rs::keys::{IdentityKey, P256Keypair};
    use household_rs::member_identity::{MemberDeviceBinding, derive_member_id};
    use household_rs::person_cert::derive_person_id;

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
    fn claim_requires_owner_auth_group_false_device_true() {
        // Regression (live hardware smoke "owner auth not loaded"): a
        // credential-less GROUP claim is owner-independent and must NOT require
        // owner_auth — process_one routes it to handle_group_claim BEFORE the
        // guard. A Device credential claim DOES require it (to mint the
        // GuestCredential bound to the owner p_id). The bug was the group branch
        // sitting BELOW the unconditional owner_auth guard, which blocked group
        // members on a headless engine whose owner cert is not loaded.
        let device_key = P256Keypair::from_secret_scalar(&[0x33u8; 32]).unwrap();
        let member_key = P256Keypair::from_secret_scalar(&[0x55u8; 32]).unwrap();
        let now = 1_800_000_000u64;

        // Device claim → requires owner_auth (hits the guard).
        let device_claim = ClawShareClaim::sign(
            SlotId([7u8; 16]),
            device_key.public(),
            ClaimNonce::random(),
            now,
            &device_key as &dyn IdentityKey,
        )
        .unwrap();
        assert!(
            claim_requires_owner_auth(&device_claim),
            "device claim must require owner_auth",
        );

        // Group claim → owner-independent (routes above the guard).
        let nonce = ClaimNonce::random();
        let binding =
            MemberDeviceBinding::sign(&member_key, device_key.public(), "npub".into(), now)
                .unwrap();
        let group_req = GroupClaimRequest::sign(
            binding,
            "g".into(),
            "claw_a".into(),
            nonce.0.to_vec(),
            Some(600),
            &device_key as &dyn IdentityKey,
        )
        .unwrap();
        let group_claim = ClawShareClaim::sign_group(
            device_key.public(),
            nonce,
            now,
            group_req,
            &device_key as &dyn IdentityKey,
        )
        .unwrap();
        assert!(
            !claim_requires_owner_auth(&group_claim),
            "group claim must NOT require owner_auth",
        );
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

    const GC_GROUP: &str = "group_alpha";
    const GC_CLAW: &str = "claw_alpha";
    const GC_NPUB: &str = "npub_test";

    fn gc_keys() -> (P256Keypair, P256Keypair) {
        let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).unwrap();
        let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).unwrap();
        (member, device)
    }

    fn gc_claim(
        member: &P256Keypair,
        device: &P256Keypair,
        ts: u64,
    ) -> (ClawShareClaim, GroupClaimRequest) {
        let nonce = ClaimNonce([0x44u8; 32]);
        let binding = MemberDeviceBinding::sign(
            member as &dyn IdentityKey,
            device.public(),
            GC_NPUB.to_string(),
            1_800_000_000,
        )
        .unwrap();
        let group_req = GroupClaimRequest::sign(
            binding,
            GC_GROUP.to_string(),
            GC_CLAW.to_string(),
            nonce.0.to_vec(),
            Some(600),
            device as &dyn IdentityKey,
        )
        .unwrap();
        let claim = ClawShareClaim::sign_group(
            device.public(),
            nonce,
            ts,
            group_req.clone(),
            device as &dyn IdentityKey,
        )
        .unwrap();
        (claim, group_req)
    }

    fn gc_projection(member_id: &str, device: &P256Keypair) -> ProjectedState {
        let mut projection = ProjectedState::default();
        projection.groups.insert(
            GC_GROUP.to_string(),
            ProjectedGroup {
                group_id: GC_GROUP.to_string(),
                name: "Alpha".to_string(),
                members: [(member_id.to_string(), MeshMembership::Active)]
                    .into_iter()
                    .collect(),
                member_labels: Default::default(),
                granted_claws: [(GC_CLAW.to_string(), MeshMembership::Active)]
                    .into_iter()
                    .collect(),
                revision: 1,
            },
        );
        projection.member_devices.insert(
            member_id.to_string(),
            [(
                device.public().as_bytes()[..].to_vec(),
                ProjectedMemberDevice {
                    participant_npub: GC_NPUB.to_string(),
                    status: MeshMembership::Active,
                },
            )]
            .into_iter()
            .collect(),
        );
        projection
    }

    #[test]
    fn group_claim_valid_verifies() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, group_req) = gc_claim(&member, &device, ts);
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        let verified =
            verify_group_claim(&claim, &group_req, &projection, &nonces, ts).expect("valid");
        assert_eq!(verified.group_id, GC_GROUP);
        assert_eq!(verified.member_id, member_id);
        assert_eq!(verified.device_pub, device.public());
        assert_eq!(verified.claw_id, GC_CLAW);
        assert_eq!(verified.ttl_secs, Some(600));
    }

    #[test]
    fn group_claim_carries_zeroed_sentinel_slot() {
        let (member, device) = gc_keys();
        let (claim, _group_req) = gc_claim(&member, &device, 1_800_000_500);
        assert!(claim.group_request.is_some());
        assert_eq!(claim.slot_id, SlotId([0u8; SLOT_ID_LEN]));
        assert!(claim.participant_npub.is_none());
    }

    #[test]
    fn group_claim_replay_same_nonce_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, group_req) = gc_claim(&member, &device, ts);
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        assert!(verify_group_claim(&claim, &group_req, &projection, &nonces, ts).is_ok());
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, ts + 5),
            Err(GroupClaimReject::NonceReplay)
        ));
    }

    #[test]
    fn group_claim_window_boundary_replay_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, group_req) = gc_claim(&member, &device, ts);
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        let early = ts - CLAIM_TIMESTAMP_TOLERANCE_SECS;
        let late = ts + CLAIM_TIMESTAMP_TOLERANCE_SECS;
        assert!(verify_group_claim(&claim, &group_req, &projection, &nonces, early).is_ok());
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, late),
            Err(GroupClaimReject::NonceReplay)
        ));
    }

    #[test]
    fn group_claim_forged_binding_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, mut group_req) = gc_claim(&member, &device, ts);
        group_req.binding.member_id = "g_forged".to_string();
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
            Err(GroupClaimReject::BindingInvalid)
        ));
    }

    #[test]
    fn group_claim_bad_device_pop_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, mut group_req) = gc_claim(&member, &device, ts);
        group_req.device_pop = household_rs::keys::P256Signature([0u8; 64]);
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
            Err(GroupClaimReject::DevicePop)
        ));
    }

    #[test]
    fn group_claim_challenge_not_nonce_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, group_req) = gc_claim(&member, &device, ts);
        let rebound = GroupClaimRequest::sign(
            group_req.binding.clone(),
            GC_GROUP.to_string(),
            GC_CLAW.to_string(),
            vec![0x99u8; 32],
            Some(600),
            &device as &dyn IdentityKey,
        )
        .unwrap();
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        assert!(matches!(
            verify_group_claim(&claim, &rebound, &projection, &nonces, ts),
            Err(GroupClaimReject::ChallengeNotNonce)
        ));
    }

    #[test]
    fn group_claim_non_member_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, group_req) = gc_claim(&member, &device, ts);
        let projection = ProjectedState::default();
        let nonces = GroupClaimNonceTable::new();
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
            Err(GroupClaimReject::NotAuthorized(_))
        ));
    }

    #[test]
    fn group_claim_device_not_enrolled_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, group_req) = gc_claim(&member, &device, ts);
        let member_id = derive_member_id(&member.public());
        let other_device = P256Keypair::from_secret_scalar(&[0x66u8; 32]).unwrap();
        let projection = gc_projection(&member_id, &other_device);
        let nonces = GroupClaimNonceTable::new();
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
            Err(GroupClaimReject::NotAuthorized(_))
        ));
    }

    #[test]
    fn group_claim_stale_timestamp_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, group_req) = gc_claim(&member, &device, ts);
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        let stale = ts + CLAIM_TIMESTAMP_TOLERANCE_SECS + 10;
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, stale),
            Err(GroupClaimReject::ClaimInvalid)
        ));
    }

    #[test]
    fn group_claim_wrong_request_version_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, mut group_req) = gc_claim(&member, &device, ts);
        group_req.v = 2;
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
            Err(GroupClaimReject::RequestVersion)
        ));
    }

    #[test]
    fn group_claim_device_pub_mismatch_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, mut group_req) = gc_claim(&member, &device, ts);
        let other_device = P256Keypair::from_secret_scalar(&[0x66u8; 32]).unwrap();
        group_req.binding = MemberDeviceBinding::sign(
            &member as &dyn IdentityKey,
            other_device.public(),
            GC_NPUB.to_string(),
            1_800_000_000,
        )
        .unwrap();
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
            Err(GroupClaimReject::DeviceMismatch)
        ));
    }

    #[test]
    fn group_claim_non_sentinel_slot_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (_discard, group_req) = gc_claim(&member, &device, ts);
        let mut claim = ClawShareClaim::sign(
            SlotId([0x01u8; SLOT_ID_LEN]),
            device.public(),
            ClaimNonce([0x44u8; 32]),
            ts,
            &device as &dyn IdentityKey,
        )
        .unwrap();
        claim.group_request = Some(group_req.clone());
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
            Err(GroupClaimReject::NonSentinelDeviceFields)
        ));
    }

    #[test]
    fn group_claim_filled_participant_npub_rejected() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (_discard, group_req) = gc_claim(&member, &device, ts);
        let mut claim = ClawShareClaim::sign_with_participant(
            SlotId([0u8; SLOT_ID_LEN]),
            device.public(),
            ClaimNonce([0x44u8; 32]),
            ts,
            Some("npub_should_not_be_here".to_string()),
            &device as &dyn IdentityKey,
        )
        .unwrap();
        claim.group_request = Some(group_req.clone());
        let member_id = derive_member_id(&member.public());
        let projection = gc_projection(&member_id, &device);
        let nonces = GroupClaimNonceTable::new();
        assert!(matches!(
            verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
            Err(GroupClaimReject::NonSentinelDeviceFields)
        ));
    }

    #[test]
    fn engine_rejects_group_claim_in_device_flow() {
        let (member, device) = gc_keys();
        let ts = 1_800_000_500;
        let (claim, _group_req) = gc_claim(&member, &device, ts);
        let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
        let hh_id = derive_household_id(&owner.public());
        let owner_p_id = derive_person_id(&owner.public());
        let slots = ClawShareSlotStore::new();
        let tunnel_factory = |_claw_id: &str| TunnelHandle::Loopback {
            channel: "test".to_string(),
        };
        let ctx = EngineContext {
            owner_key: &owner,
            owner_p_id: &owner_p_id,
            hh_id: &hh_id,
            slot_store: &slots,
            credential_ttl_secs: 60,
            tunnel_factory: &tunnel_factory,
        };
        let err = engine_handle_claim(&ctx, &claim, ts).expect_err("group is not device flow");
        assert!(matches!(err, ClawShareError::SlotNotFound));
    }

    #[test]
    fn group_claim_route_precedes_device_path_source_guard() {
        let source = include_str!("claw_share_relay_loop.rs");
        let group_branch = source
            .find("if let Some(group_req) = claim.group_request.clone()")
            .expect("group branch marker");
        let engine_call = source
            .find("engine_handle_claim(&ctx, &claim, now)")
            .expect("device engine call marker");
        let slot_event_after_branch = source[group_branch..]
            .find("MeshEvent::ClawShareSlotConsumed")
            .expect("slot consume event after group branch")
            + group_branch;
        assert!(
            group_branch < engine_call,
            "Group claims must route before engine_handle_claim"
        );
        assert!(
            group_branch < slot_event_after_branch,
            "Group claims must route before slot-consume event append"
        );
    }
}
