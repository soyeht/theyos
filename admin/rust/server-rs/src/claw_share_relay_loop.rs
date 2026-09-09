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
use household_rs::claw_share::flow::{EngineContext, engine_handle_claim};
use household_rs::claw_share::{
    CLAW_SHARE_GROUP_ACK_VERSION, CLAW_SHARE_GROUP_REQUEST_VERSION, ClawShareAck, ClawShareClaim,
    ClawShareGroupAck, ClawShareSlotStore, GroupClaimRequest, SLOT_ID_LEN, SlotId, TunnelHandle,
};
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
        .map_or(0, |d| d.as_secs());

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
mod tests;
