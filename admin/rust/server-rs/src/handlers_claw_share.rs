//! HTTP wiring for the claw-share moment.
//!
//! Routes:
//!
//!   POST /api/v1/claw-share/claim     (anonymous; cryptographic auth via slot+sig)
//!   POST /api/v1/claw-share/invites   (owner; PoP-authed, mints invite URI)
//!   POST /api/v1/claw-share/revoke    (owner; PoP-authed, revokes a slot)
//!
//! Body shape on both sides is canonical CBOR (`application/cbor`); on
//! rejection the handler emits a typed CBOR error envelope so the iOS
//! `ClawShareCodec` can lift it into `ClawShareError`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use household_rs::caveats::Operation;
use household_rs::cbor;
use household_rs::claw_share::{
    ClawShareClaim, ClawShareError, ClawShareSlotStore, SlotId, TunnelHandle, owner_mint_invite,
};
use household_rs::claw_share_flow::{EngineContext, engine_handle_claim};
use household_rs::household_mesh_log::{
    LogEntry, MeshEvent, MeshLogStore, MeshMembership, ProjectedState,
};
use household_rs::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};
use household_rs::member_identity::MemberDeviceBinding;
use serde::{Deserialize, Serialize};

use crate::claw_share_relay_offer_challenge::{
    RELAY_OFFER_CHALLENGE_TTL_SECS, RelayOfferChallengeTable,
};
use crate::claw_share_relay_stream_abuse::{RelayAbuseState, RelayAdmissionOutcome};
use crate::claw_share_relay_stream_contract::{
    RelayStreamOfferContract, check_relay_stream_group_membership, check_relay_stream_public,
};
use crate::claw_share_relay_stream_mount::{
    RelayStreamClaimProvisionError, provision_group_offer_for_claw, provision_public_offer_for_claw,
};
use crate::household_auth;
use crate::household_state::HouseholdState;

// ConnectInfo gates the production relay-offer endpoints (loopback-or-mesh peer
// check), so it is always compiled. Query is only used by the dev mint fixture.
use axum::extract::ConnectInfo;
#[cfg(feature = "dev_claw_share_mint")]
use axum::extract::Query;

const CBOR_CONTENT_TYPE: &str = "application/cbor";

/// Per-engine claw-share state.
///
/// - `slot_store` is the live working state for slot CAS — populated at
///   engine startup by rehydrating `mesh_log`'s projection so a restart
///   never reopens a consumed/revoked invite.
/// - `mesh_log` is the durable, append-only signed source of truth.
///   Every mint / consume / revoke is appended to it before being
///   reflected in the slot store; on engine restart the bootstrap
///   reads the log, projects it, and seeds the slot store.
///
/// The data plane in this relay/membership subset uses no overlay: claim acks
/// carry a Direct/Loopback handle only (the overlay supervisor + the
/// confidential-transit stores are intentionally not part of this subset).
#[derive(Clone)]
pub struct ClawShareRouterState {
    pub household: HouseholdState,
    pub slot_store: Arc<ClawShareSlotStore>,
    pub mesh_log: Arc<MeshLogStore>,
    /// Single source of truth for the engine's Nostr relay *receive*
    /// identity: the x-only hex pubkey of the SAME keypair the relay
    /// claim loop (`claw_share_relay_loop`) subscribes/decrypts with
    /// (`<state_dir>/nostr_engine_key.hex`). The mint embeds exactly this
    /// as the invite's `owner_engine_npub`, so a friend's relay-published
    /// claim lands on the key the engine is actually listening on. This is
    /// the Nostr RECEIVE identity, NOT a mesh npub. `None` only when no
    /// Nostr identity could be loaded; the mint then fails closed (never
    /// emits an invite with an empty relay target).
    pub engine_relay_npub: Option<String>,
    /// Engine state directory root, used only by the default-off `relay_stream`
    /// claim provisioning (offer store + Noise keystore live under it). Read
    /// only when `THEYOS_RELAY_STREAM_LIVE` is set; otherwise unused.
    pub state_dir: std::path::PathBuf,
    /// Single-use, TTL'd server challenges for the production relay-offer request
    /// endpoints (replay-proofing). Process-lifetime, in-memory.
    pub relay_offer_challenges: Arc<RelayOfferChallengeTable>,
    /// Per-source admission / rate-limit for the relay-offer endpoints (reuses
    /// the D3 abuse model). Not `Sync`, so wrapped in a `std::sync::Mutex`.
    pub relay_offer_abuse: Arc<std::sync::Mutex<RelayAbuseState>>,
}

/// Build + sign a `MeshEvent` and append it to the durable log. Returns
/// without recording when the log append fails so the caller can map
/// to a typed HTTP error; logging plus tracing surfaces the issue.
fn log_event(
    mesh_log: &MeshLogStore,
    issuer_key: &dyn IdentityKey,
    now: u64,
    event: MeshEvent,
) -> Result<(), ClawShareError> {
    let entry = LogEntry::sign(now, issuer_key.public(), event, issuer_key).map_err(|e| {
        tracing::warn!(stage = "claw_share.log.sign_failed", error = %e);
        ClawShareError::Cbor(household_rs::error::HouseholdError::Cbor(format!("{e}")))
    })?;
    mesh_log.append(entry).map(|_| ()).map_err(|e| {
        tracing::warn!(stage = "claw_share.log.append_failed", error = %e);
        ClawShareError::Cbor(household_rs::error::HouseholdError::Cbor(format!("{e}")))
    })
}

#[derive(Serialize)]
struct MemberView {
    member_id: String,
    label: String,
    device_count: u64,
}

#[derive(Serialize)]
struct GroupView {
    group_id: String,
    name: String,
    members: Vec<MemberView>,
    granted_claws: Vec<String>,
}

#[derive(Serialize)]
struct GroupsListResponse {
    v: u8,
    groups: Vec<GroupView>,
    published_claws: Vec<String>,
}

fn build_groups_list_response(projection: &ProjectedState) -> GroupsListResponse {
    let groups = projection
        .groups
        .values()
        .map(|group| {
            let members = group
                .members
                .iter()
                .filter(|(_, status)| matches!(status, MeshMembership::Active))
                .map(|(member_id, _)| {
                    let device_count = projection.member_devices.get(member_id).map_or(0, |devs| {
                        devs.values()
                            .filter(|device| matches!(device.status, MeshMembership::Active))
                            .count() as u64
                    });
                    MemberView {
                        member_id: member_id.clone(),
                        label: group
                            .member_labels
                            .get(member_id)
                            .cloned()
                            .unwrap_or_default(),
                        device_count,
                    }
                })
                .collect();
            let granted_claws = group
                .granted_claws
                .iter()
                .filter(|(_, status)| matches!(status, MeshMembership::Active))
                .map(|(claw_id, _)| claw_id.clone())
                .collect();
            GroupView {
                group_id: group.group_id.clone(),
                name: group.name.clone(),
                members,
                granted_claws,
            }
        })
        .collect();
    let published_claws = projection
        .published_claws
        .iter()
        .filter(|(_, status)| matches!(status, MeshMembership::Active))
        .map(|(claw_id, _)| claw_id.clone())
        .collect();
    GroupsListResponse {
        v: 1,
        groups,
        published_claws,
    }
}

async fn handle_list_groups(
    State(state): State<ClawShareRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    if household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdInvite,
        now,
    )
    .await
    .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let projection = state.mesh_log.project();
    match cbor::to_canonical_vec(&build_groups_list_response(&projection)) {
        Ok(bytes) => cbor_response(StatusCode::OK, bytes),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Mount the claw-share routes on the `household_router`.
pub fn router(state: ClawShareRouterState) -> axum::Router {
    let router = axum::Router::new()
        .route("/api/v1/claw-share/claim", post(handle_claim))
        .route("/api/v1/claw-share/invites", post(handle_mint_invite))
        .route("/api/v1/claw-share/revoke", post(handle_revoke))
        .route("/api/v1/claw-share/group-op", post(handle_group_op))
        .route(
            "/api/v1/claw-share/invite-to-claw",
            post(handle_invite_to_claw),
        )
        .route("/api/v1/claw-share/groups", get(handle_list_groups))
        .route(
            "/api/v1/claw-share/relay-offer/challenge",
            post(handle_relay_offer_challenge),
        )
        .route(
            "/api/v1/claw-share/relay-offer/group",
            post(handle_relay_offer_group),
        )
        .route(
            "/api/v1/claw-share/relay-offer/public",
            post(handle_relay_offer_public),
        );
    // Dev-only fixture route (C7c-2c-e): absent entirely without the feature.
    #[cfg(feature = "dev_claw_share_mint")]
    let router = router.route(
        "/api/v1/claw-share/dev-mint-invite",
        post(handle_dev_mint_invite),
    );
    #[cfg(feature = "dev_claw_share_mint")]
    let router = router.route(
        "/api/v1/claw-share/dev-mint-relay-offer",
        post(handle_dev_mint_relay_offer),
    );
    #[cfg(feature = "dev_claw_share_mint")]
    let router = router.route(
        "/api/v1/claw-share/dev-publish-claw",
        post(handle_dev_publish_claw),
    );
    #[cfg(feature = "dev_claw_share_mint")]
    let router = router.route("/api/v1/claw-share/dev-group-op", post(handle_dev_group_op));
    router.with_state(state)
}

// ─── Production relay-offer request endpoints (Fase E2.5 / E3) ────────────────
//
// A member device (Group) or any dialer (Public) obtains a relay_stream offer
// for a claw it is entitled to. Two steps: GET a single-use server challenge,
// then POST the offer request echoing it. The dial-time gate
// (`validate_offer_target`) re-checks against a fresh projection and stays the
// SOLE authority — these checks are defense-in-depth + DoS hygiene, never the
// access boundary. All three endpoints refuse any peer outside the allowed
// rendezvous path (the offer body carries a confidential rendezvous token).

/// Default / max offer lifetime for a Group request; fixed (short) Public TTL.
const RELAY_OFFER_DEFAULT_TTL_SECS: u64 = 600;
const RELAY_OFFER_MAX_TTL_SECS: u64 = 600;
const RELAY_OFFER_PUBLIC_TTL_SECS: u64 = 300;

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Mirror the listener's bind policy as a CHECKED invariant: in this
/// relay/membership subset only a LOOPBACK peer may request an offer (the
/// response carries a confidential rendezvous token). The offer is
/// minted locally over loopback; any overlay-subnet branch is
/// intentionally not part of this subset. If a non-loopback requester policy is
/// later needed, add an explicit address allowlist.
fn relay_offer_peer_allowed(ip: std::net::IpAddr) -> bool {
    ip.is_loopback()
}

/// Per-source token-bucket admission; `true` = allowed. Reuses the D3 abuse model.
fn relay_offer_rate_ok(state: &ClawShareRouterState, ip: std::net::IpAddr) -> bool {
    let mut guard = state
        .relay_offer_abuse
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let bucket = guard.source_bucket_for_ip(ip);
    matches!(
        guard.record_hello_attempt(bucket, std::time::Instant::now()),
        RelayAdmissionOutcome::Accepted { .. }
    )
}

/// Front gate shared by all three endpoints: loopback-or-mesh peer (else 404,
/// shape-hiding) + per-source rate limit (else 429). Returns the unix `now`.
#[allow(clippy::result_large_err)] // the Err is a one-shot rejection Response
fn relay_offer_admit(state: &ClawShareRouterState, ip: std::net::IpAddr) -> Result<u64, Response> {
    if !relay_offer_peer_allowed(ip) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    if !relay_offer_rate_ok(state, ip) {
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "relay-offer-rate-limited",
            None,
        ));
    }
    unix_now().ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Encode a minted offer as canonical CBOR, or fail closed (never leak a token).
fn relay_offer_finish(
    offer: Result<RelayStreamOfferContract, RelayStreamClaimProvisionError>,
) -> Response {
    match offer {
        Ok(offer) => match cbor::to_canonical_vec(&offer) {
            Ok(bytes) => cbor_response(StatusCode::CREATED, bytes),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        Err(error) => {
            tracing::warn!(stage = "claw_share.relay_offer.provision_failed", error = %error);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "relay-offer-provision-failed",
                None,
            )
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RelayOfferChallengeReq {
    v: u8,
}

#[derive(Serialize, Deserialize)]
struct RelayOfferChallengeResp {
    v: u8,
    #[serde(with = "serde_bytes")]
    challenge: Vec<u8>,
    not_after: u64,
}

#[derive(Serialize, Deserialize)]
struct RelayOfferGroupReq {
    v: u8,
    #[serde(with = "serde_bytes")]
    challenge: Vec<u8>,
    binding: MemberDeviceBinding,
    group_id: String,
    claw_id: String,
    device_pop: P256Signature,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

/// Field-ordered view the device proof-of-possession signs over: binds the
/// request to the fresh challenge + the exact group/claw/ttl. Verified under
/// `binding.device_pub`.
#[derive(Serialize)]
struct RelayOfferGroupReqUnsigned<'a> {
    v: u8,
    #[serde(with = "serde_bytes")]
    challenge: &'a [u8],
    group_id: &'a str,
    claw_id: &'a str,
    ttl_secs: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct RelayOfferPublicReq {
    v: u8,
    #[serde(with = "serde_bytes")]
    challenge: Vec<u8>,
    dialer_device_pub: P256PublicKey,
    claw_id: String,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

/// `POST /api/v1/claw-share/relay-offer/challenge` — issue a single-use server
/// challenge. Peer-gated + rate-limited.
async fn handle_relay_offer_challenge(
    State(state): State<ClawShareRouterState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Response {
    let now = match relay_offer_admit(&state, peer.ip()) {
        Ok(now) => now,
        Err(resp) => return resp,
    };
    let Ok(req) = cbor::from_canonical_slice::<RelayOfferChallengeReq>(&body) else {
        return error_response(StatusCode::BAD_REQUEST, "relay-offer-malformed", None);
    };
    if req.v != 1 {
        return error_response(StatusCode::BAD_REQUEST, "relay-offer-version", None);
    }
    let Some(challenge) = state
        .relay_offer_challenges
        .issue(now, RELAY_OFFER_CHALLENGE_TTL_SECS)
    else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "relay-offer-challenge-unavailable",
            None,
        );
    };
    let resp = RelayOfferChallengeResp {
        v: 1,
        challenge: challenge.to_vec(),
        not_after: now.saturating_add(RELAY_OFFER_CHALLENGE_TTL_SECS),
    };
    match cbor::to_canonical_vec(&resp) {
        Ok(bytes) => cbor_response(StatusCode::CREATED, bytes),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// `POST /api/v1/claw-share/relay-offer/group` — member binding + device
/// proof-of-possession over a single-use challenge → live membership check →
/// mint+store+return the offer.
async fn handle_relay_offer_group(
    State(state): State<ClawShareRouterState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Response {
    let now = match relay_offer_admit(&state, peer.ip()) {
        Ok(now) => now,
        Err(resp) => return resp,
    };
    let Ok(req) = cbor::from_canonical_slice::<RelayOfferGroupReq>(&body) else {
        return error_response(StatusCode::BAD_REQUEST, "relay-offer-malformed", None);
    };
    if req.v != 1 {
        return error_response(StatusCode::BAD_REQUEST, "relay-offer-version", None);
    }

    // 1. Member-self-signed binding holds (member_id derives from member_pub).
    if req.binding.verify().is_err() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "relay-offer-binding-invalid",
            None,
        );
    }
    // 2. Device PoP over the request, verified under the bound device key —
    //    proves present possession + binds this request to the fresh challenge.
    let unsigned = RelayOfferGroupReqUnsigned {
        v: req.v,
        challenge: &req.challenge,
        group_id: &req.group_id,
        claw_id: &req.claw_id,
        ttl_secs: req.ttl_secs,
    };
    let Ok(pop_bytes) = cbor::to_canonical_vec(&unsigned) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if verify_signature(&req.binding.device_pub, &pop_bytes, &req.device_pop).is_err() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "relay-offer-device-pop-invalid",
            None,
        );
    }
    // 3. Single-use challenge (replay-proof). Consumed AFTER the PoP so a bad PoP
    //    cannot burn a victim's challenge.
    if !state.relay_offer_challenges.consume(&req.challenge, now) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "relay-offer-challenge-invalid",
            None,
        );
    }
    // 4. Authorization on the LIVE projection (defense-in-depth; the dial gate
    //    re-checks against a fresh projection and remains the sole authority).
    let projection = state.mesh_log.project();
    if check_relay_stream_group_membership(
        &projection,
        &req.group_id,
        &req.binding.member_id,
        &req.claw_id,
        &req.binding.device_pub,
    )
    .is_err()
    {
        return error_response(StatusCode::FORBIDDEN, "relay-offer-not-authorized", None);
    }
    // 5. Mint + store + deliver (the dialing device's key is the pinned audience).
    let Some(identity) = state.household.current().await else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "relay-offer-household-unavailable",
            None,
        );
    };
    let ttl = req
        .ttl_secs
        .unwrap_or(RELAY_OFFER_DEFAULT_TTL_SECS)
        .min(RELAY_OFFER_MAX_TTL_SECS);
    let offer = provision_group_offer_for_claw(
        &state.state_dir,
        &state.household,
        &state.mesh_log,
        identity.m_priv.as_ref(),
        req.group_id.clone(),
        req.binding.member_id.clone(),
        req.binding.device_pub.clone(),
        req.claw_id.clone(),
        now.saturating_add(ttl),
        now,
    )
    .await;
    relay_offer_finish(offer)
}

/// `POST /api/v1/claw-share/relay-offer/public` — single-use challenge → live
/// published check → mint+store+return. No identity (public), rate-limited.
async fn handle_relay_offer_public(
    State(state): State<ClawShareRouterState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Response {
    let now = match relay_offer_admit(&state, peer.ip()) {
        Ok(now) => now,
        Err(resp) => return resp,
    };
    let Ok(req) = cbor::from_canonical_slice::<RelayOfferPublicReq>(&body) else {
        return error_response(StatusCode::BAD_REQUEST, "relay-offer-malformed", None);
    };
    if req.v != 1 {
        return error_response(StatusCode::BAD_REQUEST, "relay-offer-version", None);
    }
    if !state.relay_offer_challenges.consume(&req.challenge, now) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "relay-offer-challenge-invalid",
            None,
        );
    }
    let projection = state.mesh_log.project();
    if check_relay_stream_public(&projection, &req.claw_id).is_err() {
        return error_response(StatusCode::NOT_FOUND, "relay-offer-not-published", None);
    }
    let Some(identity) = state.household.current().await else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "relay-offer-household-unavailable",
            None,
        );
    };
    let offer = provision_public_offer_for_claw(
        &state.state_dir,
        &state.household,
        &state.mesh_log,
        identity.m_priv.as_ref(),
        req.dialer_device_pub.clone(),
        req.claw_id.clone(),
        now.saturating_add(RELAY_OFFER_PUBLIC_TTL_SECS),
        now,
    )
    .await;
    relay_offer_finish(offer)
}

// ─── Mint invite (admin-PoP) ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct MintInviteRequest {
    /// Schema version.
    v: u8,
    claw_id: String,
    /// Optional TTL. Engine clamps to [`household_rs::claw_share::MAX_INVITE_TTL_SECS`].
    ttl_secs: Option<u64>,
    /// Optional transport hint. Defaults to a loopback channel; the
    /// owner-facing UI typically leaves this absent until a real mesh
    /// transport ships.
    transport_hint: Option<TunnelHandle>,
}

#[derive(Serialize)]
struct MintInviteResponse {
    v: u8,
    uri: String,
    slot_id: serde_bytes::ByteBuf,
    expires_at: u64,
}

/// Resolve the relay claim fields for a minted invite, or fail closed with a
/// stable error code.
///
/// SINGLE SOURCE OF TRUTH: `owner_engine_npub` is the engine's relay RECEIVE
/// identity (`engine_relay_npub` — the same key the relay claim loop
/// subscribes/decrypts with), NEVER the mesh npub. `claim_relays` is parsed
/// from the operator's `THEYOS_CLAIM_RELAYS`. Both must be present: an invite
/// with an empty relay target or an empty relay list is a silent dead end (a
/// friend's Nostr submitter would have no key to encrypt to and nowhere to
/// publish), so we refuse to mint it. Pure + env-free so it is unit-testable.
fn resolve_relay_claim_fields(
    engine_relay_npub: Option<&str>,
    claim_relays_env: Option<&str>,
) -> Result<(String, Vec<String>), &'static str> {
    let owner_engine_npub = match engine_relay_npub {
        Some(npub) if !npub.is_empty() => npub.to_string(),
        _ => return Err("relay_identity_unavailable"),
    };
    let claim_relays: Vec<String> = claim_relays_env
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if claim_relays.is_empty() {
        return Err("claim_relays_unconfigured");
    }
    Ok((owner_engine_npub, claim_relays))
}

/// If the operator configured a reachable public data-tunnel address
/// (`THEYOS_CLAW_DATA_TUNNEL_PUBLIC_ADDR`, e.g. `192.168.15.12:7423`), the
/// engine advertises it to friends as a `Direct` tunnel handle in the claim
/// ack — so a friend with no overlay and no prior pairing can dial the PTY
/// straight from the ack. Returns `None` when unset / empty / unparseable, so
/// the caller keeps its existing loopback fallback. Parses
/// `host:port` (IPv4 / DNS); IPv6 literals are a follow-up.
pub(crate) fn public_data_tunnel_handle() -> Option<TunnelHandle> {
    let raw = std::env::var("THEYOS_CLAW_DATA_TUNNEL_PUBLIC_ADDR").ok()?;
    parse_public_data_tunnel_addr(raw.trim())
}

/// Pure parse of a `host:port` public data-tunnel address into a `Direct`
/// handle. Split out for unit testing without touching the process env.
fn parse_public_data_tunnel_addr(raw: &str) -> Option<TunnelHandle> {
    if raw.is_empty() {
        return None;
    }
    let (host, port_str) = raw.rsplit_once(':')?;
    let host = host.trim();
    let port: u16 = port_str.trim().parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some(TunnelHandle::Direct {
        host: host.to_string(),
        port,
    })
}

/// Mint flow shared by the production `/api/v1/claw-share/invites` route and the
/// dev-only fixture: resolve the live dev household owner, mint the slot + invite
/// via `owner_mint_invite`, persist the `ClawShareSlotMinted` event (fail-closed),
/// record the per-claw mesh network, and build the response. The CALLER's
/// owner-PoP is verified by the production handler BEFORE calling this; this fn
/// performs NO authorization itself, so callers MUST gate it.
async fn mint_invite_inner(
    state: &ClawShareRouterState,
    req: MintInviteRequest,
    now: u64,
) -> Result<MintInviteResponse, Response> {
    let Some(identity) = state.household.current().await else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "household_unavailable",
            None,
        ));
    };
    let Some(owner_auth) = state.household.current_owner_auth().await else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "owner_auth_unavailable",
            None,
        ));
    };

    let owner_key = identity.m_priv.as_ref();
    let owner_p_id = &owner_auth.owner_person_cert.p_id;
    let hh_id = &identity.record.hh_id;

    let ttl_secs = req.ttl_secs.unwrap_or(900);
    // This relay/membership subset uses no overlay: the transport hint defaults
    // to a Loopback channel (the overlay data-tunnel hint is not part of this
    // subset). The caller may still pass an explicit `transport_hint`.
    let transport_hint = req
        .transport_hint
        .unwrap_or_else(|| TunnelHandle::Loopback {
            channel: format!("ch-{}", req.claw_id),
        });

    // Relay claim path — SINGLE SOURCE OF TRUTH + FAIL CLOSED. See
    // `resolve_relay_claim_fields`: `owner_engine_npub` MUST be the engine's
    // relay RECEIVE identity (the exact key the relay claim loop
    // subscribes/decrypts with), and `claim_relays` must be non-empty. Never
    // mint an invite with an empty relay target or relay list.
    let (owner_engine_npub, claim_relays) = match resolve_relay_claim_fields(
        state.engine_relay_npub.as_deref(),
        std::env::var("THEYOS_CLAIM_RELAYS").ok().as_deref(),
    ) {
        Ok(fields) => fields,
        Err(code) => return Err(error_response(StatusCode::SERVICE_UNAVAILABLE, code, None)),
    };

    let invite = match owner_mint_invite(
        owner_key,
        owner_p_id,
        hh_id,
        &req.claw_id,
        transport_hint,
        ttl_secs,
        now,
        owner_engine_npub,
        claim_relays,
        &state.slot_store,
    ) {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(stage = "claw_share.mint.failed", error = %e);
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "mint_failed",
                None,
            ));
        }
    };

    // Persist the mint event. Slot store + log diverging on a restart
    // would leave the engine in a state where an invite is "live" in
    // RAM but the log thinks it never happened (or vice versa); fail
    // closed if the log append fails.
    let mint_event = MeshEvent::ClawShareSlotMinted {
        slot_id: invite.slot_id.clone(),
        claw_id: invite.claw_id.clone(),
        expires_at: invite.expires_at,
    };
    if let Err(e) = log_event(&state.mesh_log, owner_key, now, mint_event) {
        tracing::warn!(stage = "claw_share.mint.log_failed", error = %e);
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "log_persist_failed",
            None,
        ));
    }

    let Ok(uri) = invite.to_uri() else {
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "uri_encode_failed",
            None,
        ));
    };

    Ok(MintInviteResponse {
        v: 1,
        uri,
        slot_id: serde_bytes::ByteBuf::from(invite.slot_id.as_bytes().to_vec()),
        expires_at: invite.expires_at,
    })
}

async fn handle_mint_invite(
    State(state): State<ClawShareRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());

    // Owner proof-of-possession is REQUIRED on the production route.
    if household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdInvite,
        now,
    )
    .await
    .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let req: MintInviteRequest = match cbor::from_canonical_slice(&body) {
        Ok(r) => r,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "request_malformed", None),
    };
    if req.v != 1 {
        return error_response(StatusCode::BAD_REQUEST, "version_unsupported", None);
    }

    match mint_invite_inner(&state, req, now).await {
        Ok(resp) => match cbor::to_canonical_vec(&resp) {
            Ok(bytes) => cbor_response(StatusCode::CREATED, bytes),
            Err(_) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response_encode_failed",
                None,
            ),
        },
        Err(resp) => resp,
    }
}

/// DEV-ONLY claw-share invite mint fixture (C7c-2c-e). NEVER ship; compiled out
/// of prod.
///
/// Present ONLY with `--features dev_claw_share_mint`; without the feature this
/// handler and its route do not exist. It mints a REAL PTY claw-share invite on
/// the LIVE engine — real `slot_store` + mesh log + the real dev household owner
/// via [`mint_invite_inner`] — so the `relay_stream` smoke has a pre-condition
/// invite, but it SKIPS the caller owner-PoP (`household_auth::authorize_request`)
/// that the production `/api/v1/claw-share/invites` route enforces. It is
/// therefore an owner-AUTHORIZATION BYPASS and must never be reachable in prod:
/// gated at compile time by the feature, and at runtime FAIL-CLOSED unless ALL
/// of `THEYOS_DEV_CLAW_SHARE_INVITE_MINT=1`, a loopback peer, and
/// `THEYOS_FORCE_SOFTWARE_KEYS=1` hold (any miss → 404, hiding the shape). It
/// returns only the invite URI (text). The resource is PTY by construction: the
/// `relay_stream` offer provisioned on claim is PTY; the invite is
/// resource-agnostic.
#[cfg(feature = "dev_claw_share_mint")]
async fn handle_dev_mint_invite(
    State(state): State<ClawShareRouterState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Query(query): Query<DevMintInviteQuery>,
) -> Response {
    if std::env::var("THEYOS_DEV_CLAW_SHARE_INVITE_MINT")
        .ok()
        .as_deref()
        != Some("1")
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !peer.ip().is_loopback() {
        tracing::warn!(stage = "claw_share.dev_mint.non_loopback_rejected", peer = %peer);
        return StatusCode::NOT_FOUND.into_response();
    }
    if std::env::var("THEYOS_FORCE_SOFTWARE_KEYS").ok().as_deref() != Some("1") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Owner-PoP is DELIBERATELY skipped here (the entire purpose of the
    // fixture). Everything downstream is the real path via `mint_invite_inner`.
    let claw_id = query
        .claw_id
        .unwrap_or_else(|| "claw_dev_smoke".to_string());
    let req = MintInviteRequest {
        v: 1,
        claw_id,
        ttl_secs: None,
        transport_hint: None,
    };

    match mint_invite_inner(&state, req, now).await {
        Ok(resp) => (StatusCode::CREATED, resp.uri).into_response(),
        Err(resp) => resp,
    }
}

/// Query for the dev-only mint fixture: optional `claw_id` (defaults to a fixed
/// dev value).
#[cfg(feature = "dev_claw_share_mint")]
#[derive(Deserialize)]
struct DevMintInviteQuery {
    claw_id: Option<String>,
}

/// Query for the dev-only GROUP/PUBLIC `relay_stream` offer mint fixture (Fase
/// E2.5/E3). `mode` = "group" | "public". `device_pub` is the dialing device's
/// 33-byte SEC1 P-256 key, hex. For "group", `group_id` + `member_id` are
/// required. Returns the minted offer as canonical CBOR.
#[cfg(feature = "dev_claw_share_mint")]
#[derive(Deserialize)]
struct DevMintRelayOfferQuery {
    mode: String,
    claw_id: String,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    member_id: Option<String>,
    device_pub: String,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

/// `POST /api/v1/claw-share/dev-mint-relay-offer` — DEV-ONLY (feature
/// `dev_claw_share_mint`). Mints + stores a GROUP or PUBLIC `relay_stream` offer
/// via the live-engine provisioning helpers and returns it as canonical CBOR, so
/// a loopback smoke can dial the group/public path. Same three fail-closed gates
/// as `handle_dev_mint_invite`; owner-PoP is skipped (that is the fixture's
/// point). The returned offer carries a rendezvous token, so this is loopback +
/// dev-keys + env-flag gated exactly like the invite fixture. The PRODUCTION
/// trigger (a member-PoP-authenticated request endpoint that delivers the offer
/// over an authenticated channel) is the remaining E2.5 wiring.
#[cfg(feature = "dev_claw_share_mint")]
async fn handle_dev_mint_relay_offer(
    State(state): State<ClawShareRouterState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Query(query): Query<DevMintRelayOfferQuery>,
) -> Response {
    if std::env::var("THEYOS_DEV_CLAW_SHARE_INVITE_MINT")
        .ok()
        .as_deref()
        != Some("1")
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !peer.ip().is_loopback() {
        tracing::warn!(stage = "claw_share.dev_mint_relay_offer.non_loopback_rejected", peer = %peer);
        return StatusCode::NOT_FOUND.into_response();
    }
    if std::env::var("THEYOS_FORCE_SOFTWARE_KEYS").ok().as_deref() != Some("1") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let Ok(device_bytes) = hex::decode(query.device_pub.trim()) else {
        return error_response(StatusCode::BAD_REQUEST, "device_pub_malformed", None);
    };
    let Ok(device_pub) = P256PublicKey::from_bytes(&device_bytes) else {
        return error_response(StatusCode::BAD_REQUEST, "device_pub_invalid", None);
    };
    let Some(identity) = state.household.current().await else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "household_unavailable",
            None,
        );
    };
    let owner_key = identity.m_priv.as_ref();
    let not_after = now.saturating_add(query.ttl_secs.unwrap_or(600));
    let mode = query.mode.clone();

    let offer = match mode.as_str() {
        "group" => {
            let (Some(group_id), Some(member_id)) = (query.group_id, query.member_id) else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "group_requires_group_id_and_member_id",
                    None,
                );
            };
            crate::claw_share_relay_stream_mount::provision_group_offer_for_claw(
                &state.state_dir,
                &state.household,
                &state.mesh_log,
                owner_key,
                group_id,
                member_id,
                device_pub,
                query.claw_id,
                not_after,
                now,
            )
            .await
        }
        "public" => {
            crate::claw_share_relay_stream_mount::provision_public_offer_for_claw(
                &state.state_dir,
                &state.household,
                &state.mesh_log,
                owner_key,
                device_pub,
                query.claw_id,
                not_after,
                now,
            )
            .await
        }
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "mode_must_be_group_or_public",
                None,
            );
        }
    };

    match offer {
        Ok(offer) => match cbor::to_canonical_vec(&offer) {
            Ok(bytes) => (
                StatusCode::CREATED,
                [(header::CONTENT_TYPE, CBOR_CONTENT_TYPE)],
                bytes,
            )
                .into_response(),
            Err(_) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "offer_encode_failed",
                None,
            ),
        },
        Err(error) => {
            tracing::warn!(stage = "claw_share.dev_mint_relay_offer.failed", error = %error);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "provision_failed", None)
        }
    }
}

/// Shared fail-closed gate for the DEV-ONLY claw-share endpoints (feature
/// `dev_claw_share_mint`): the peer is loopback AND
/// `THEYOS_DEV_CLAW_SHARE_INVITE_MINT=1` AND `THEYOS_FORCE_SOFTWARE_KEYS=1`. The env
/// VALUES are passed in (not read here) so the policy is unit-testable without
/// process-global env. ALL must hold; any miss ⇒ reject (404, shape-hiding).
#[cfg(feature = "dev_claw_share_mint")]
fn dev_endpoint_allowed(
    peer: std::net::IpAddr,
    mint_flag: Option<&str>,
    software_keys_flag: Option<&str>,
) -> bool {
    peer.is_loopback() && mint_flag == Some("1") && software_keys_flag == Some("1")
}

#[cfg(feature = "dev_claw_share_mint")]
#[derive(Deserialize)]
struct DevPublishClawQuery {
    claw_id: String,
}

/// `POST /api/v1/claw-share/dev-publish-claw?claw_id=…` — DEV-ONLY (feature
/// `dev_claw_share_mint`). Publishes a claw as a public `ClawSite` by emitting a
/// self-signed `ClawSitePublished` mesh event into the live op-log, WITHOUT the
/// owner `PersonCert` proof-of-possession that `/group-op` requires — behind the same three
/// fail-closed gates as the dev-mint endpoints (loopback +
/// `THEYOS_DEV_CLAW_SHARE_INVITE_MINT=1` + `THEYOS_FORCE_SOFTWARE_KEYS=1`). This is
/// an explicit owner-authority bypass for the loopback dev smoke ONLY (pure test
/// box; owner-approved); the production publish is the owner-PoP'd `/group-op`
/// `PublishClaw`. The event is signed by the engine key, so it folds into THIS
/// engine's live projection (the Public dial gate reads `published_claws`); it is
/// NOT authorized for replication to peer engines (the gossip-in CARRY rejects a
/// non-owner issuer).
#[cfg(feature = "dev_claw_share_mint")]
async fn handle_dev_publish_claw(
    State(state): State<ClawShareRouterState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Query(query): Query<DevPublishClawQuery>,
) -> Response {
    if !dev_endpoint_allowed(
        peer.ip(),
        std::env::var("THEYOS_DEV_CLAW_SHARE_INVITE_MINT")
            .ok()
            .as_deref(),
        std::env::var("THEYOS_FORCE_SOFTWARE_KEYS").ok().as_deref(),
    ) {
        tracing::warn!(stage = "claw_share.dev_publish_claw.gate_rejected", peer = %peer);
        return StatusCode::NOT_FOUND.into_response();
    }
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let Some(identity) = state.household.current().await else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "household_unavailable",
            None,
        );
    };
    let owner_key = identity.m_priv.as_ref();
    match log_event(
        &state.mesh_log,
        owner_key,
        now,
        MeshEvent::ClawSitePublished {
            claw_id: query.claw_id.clone(),
        },
    ) {
        Ok(()) => {
            tracing::info!(stage = "claw_share.dev_publish_claw.published", claw_id = %query.claw_id);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            tracing::warn!(stage = "claw_share.dev_publish_claw.failed", error = %e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "publish_failed", None)
        }
    }
}

// ─── Dev-only group seed (headless Group-claim smoke) ─────────────────────────

/// Request body for the DEV-ONLY `/dev-group-op` fixture. Carries the member +
/// device SECRET scalars (hex) so the engine can MINT the member-self-signed
/// binding locally (a `curl` client cannot sign P-256). The SAME two secrets fed
/// to `friend-cli group-claim-relay` reproduce the byte-identical `member_id` +
/// `device_pub` the live membership gate keys on. Secrets ride the BODY — never a
/// query string (`/group-op` logs `path_and_query`) — and are NEVER logged.
#[cfg(feature = "dev_claw_share_mint")]
#[derive(Deserialize)]
struct DevGroupOpRequest {
    /// 64-hex (32-byte) member secret scalar. Dev/smoke ONLY.
    member_secret: String,
    /// 64-hex (32-byte) device secret scalar. Dev/smoke ONLY.
    device_secret: String,
    /// Per-device relay rendezvous npub recorded in the binding.
    participant_npub: String,
    group_id: String,
    claw_id: String,
    /// Member display label recorded by `AddMember`.
    member_label: String,
    /// Optional group display name (`Create`); defaults to `group_id`.
    #[serde(default)]
    group_name: Option<String>,
    /// Optional binding `issued_at`; defaults to `now`. The membership gate
    /// ignores it (`binding.verify` has no freshness check); pin it only if you
    /// want byte-identical bindings across independent runs.
    #[serde(default)]
    issued_at: Option<u64>,
}

/// Response: the PUBLIC identifiers the smoke can echo/verify. No secret material.
#[cfg(feature = "dev_claw_share_mint")]
#[derive(Serialize)]
struct DevGroupOpResponse {
    member_id: String,
    /// SEC1-compressed (33-byte) device pubkey, hex.
    device_pub: String,
    group_id: String,
    claw_id: String,
}

/// Parse a 64-hex (32-byte) secret scalar into a software P-256 keypair, byte-for
/// -byte identical to friend-cli's `member_key_from_hex` (trim, len == 64, 2-char
/// `from_str_radix` windows, `from_secret_scalar`) so the engine-minted binding
/// and the friend-cli claim binding agree. Returns a static reason for a
/// shape-hiding 400. DEV-ONLY.
#[cfg(feature = "dev_claw_share_mint")]
fn dev_keypair_from_hex(hex: &str) -> Result<household_rs::keys::P256Keypair, &'static str> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err("secret_not_64_hex");
    }
    let mut scalar = [0u8; 32];
    for (i, byte) in scalar.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "secret_not_hex")?;
    }
    household_rs::keys::P256Keypair::from_secret_scalar(&scalar)
        .map_err(|_| "secret_invalid_scalar")
}

/// `POST /api/v1/claw-share/dev-group-op` — DEV-ONLY (feature
/// `dev_claw_share_mint`; route, handler, and types are absent entirely without
/// it). Seeds the live group projection for a headless Group-claim smoke by
/// applying `Create`, `AddMember`, `EnrollMemberDevice`, and `GrantClaw` WITHOUT
/// the owner `PersonCert` `PoP` that `/group-op` requires — behind the SAME three
/// fail-closed gates as the other dev fixtures (loopback, plus the env vars
/// `THEYOS_DEV_CLAW_SHARE_INVITE_MINT=1` and `THEYOS_FORCE_SOFTWARE_KEYS=1`); any
/// miss yields a bare 404, checked BEFORE the body is touched so a malformed or
/// forged request still leaks nothing. Each op flows through the SAME
/// [`apply_group_op`] the owner path uses (including the real `EnrollMemberDevice`
/// `binding.verify()`), so this is a generic apply, never a parallel seeder. An
/// explicit owner-authority bypass for the loopback dev smoke ONLY (pure test box;
/// owner-approved); the engine-signed events fold into THIS engine's live
/// projection but are NOT authorized for gossip replication (peer engines reject a
/// non-owner issuer).
#[cfg(feature = "dev_claw_share_mint")]
async fn handle_dev_group_op(
    State(state): State<ClawShareRouterState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Response {
    // Gate FIRST — before the body is parsed — so any miss is a bare 404 with zero
    // effect, hiding the endpoint shape even from a malformed/forged request.
    if !dev_endpoint_allowed(
        peer.ip(),
        std::env::var("THEYOS_DEV_CLAW_SHARE_INVITE_MINT")
            .ok()
            .as_deref(),
        std::env::var("THEYOS_FORCE_SOFTWARE_KEYS").ok().as_deref(),
    ) {
        tracing::warn!(stage = "claw_share.dev_group_op.gate_rejected", peer = %peer);
        return StatusCode::NOT_FOUND.into_response();
    }
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Loopback + dev-gated past this point. Secrets ride the body and are never
    // logged; parsing happens only after the gate.
    let req: DevGroupOpRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "request_malformed", None),
    };

    let member_key = match dev_keypair_from_hex(&req.member_secret) {
        Ok(k) => k,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, reason, None),
    };
    let device_key = match dev_keypair_from_hex(&req.device_secret) {
        Ok(k) => k,
        Err(reason) => return error_response(StatusCode::BAD_REQUEST, reason, None),
    };
    let device_pub = device_key.public();
    let issued_at = req.issued_at.unwrap_or(now);

    // Mint the member-self-signed binding server-side via the SAME canonical
    // builder friend-cli calls, so the enrolled binding and the F3 claim binding
    // agree on member_id (= derive_member_id(member_pub)) and device_pub bytes.
    let Ok(binding) = MemberDeviceBinding::sign(
        &member_key,
        device_pub.clone(),
        req.participant_npub.clone(),
        issued_at,
    ) else {
        return error_response(StatusCode::BAD_REQUEST, "member_binding_sign_failed", None);
    };
    let member_id = binding.member_id.clone();

    // The four ops the live membership gate requires, each applied through the
    // shared post-authorization path: Create → group exists; AddMember → member
    // Active; EnrollMemberDevice → device Active under member; GrantClaw → claw
    // granted to group. Short-circuit on the first failure.
    let ops = [
        GroupOp::Create {
            group_id: req.group_id.clone(),
            name: req
                .group_name
                .clone()
                .unwrap_or_else(|| req.group_id.clone()),
        },
        GroupOp::AddMember {
            group_id: req.group_id.clone(),
            member_id: member_id.clone(),
            label: req.member_label.clone(),
        },
        GroupOp::EnrollMemberDevice { binding },
        GroupOp::GrantClaw {
            group_id: req.group_id.clone(),
            claw_id: req.claw_id.clone(),
        },
    ];
    for op in ops {
        if let Err(resp) = apply_group_op(&state, &op, now).await {
            return resp;
        }
    }

    tracing::info!(
        stage = "claw_share.dev_group_op.applied",
        group_id = %req.group_id,
        claw_id = %req.claw_id,
        member_id = %member_id,
    );

    let resp = DevGroupOpResponse {
        member_id,
        device_pub: hex::encode(&device_pub.as_bytes()[..]),
        group_id: req.group_id,
        claw_id: req.claw_id,
    };
    match serde_json::to_vec(&resp) {
        Ok(bytes) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ─── Revoke slot (admin-PoP) ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct RevokeRequest {
    v: u8,
    /// 16-byte slot id of the slot to revoke. Guest-pubkey-scoped
    /// revocation lands when the mesh log replaces the slot store as
    /// the primary projection — slot id is sufficient today.
    #[serde(with = "serde_bytes")]
    slot_id: Vec<u8>,
}

async fn handle_revoke(
    State(state): State<ClawShareRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());

    if household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdRevoke,
        now,
    )
    .await
    .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let req: RevokeRequest = match cbor::from_canonical_slice(&body) {
        Ok(r) => r,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "request_malformed", None),
    };
    if req.v != 1 {
        return error_response(StatusCode::BAD_REQUEST, "version_unsupported", None);
    }
    let Ok(slot_id) = SlotId::from_bytes(&req.slot_id) else {
        return error_response(StatusCode::BAD_REQUEST, "slot_id_malformed", None);
    };
    // Resolve the issuer key now so we can persist the revoke
    // event. PoP already accepted; identity availability is the
    // engine-bootstrap invariant.
    let Some(identity) = state.household.current().await else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "household_unavailable",
            None,
        );
    };
    match state.slot_store.revoke(&slot_id, now) {
        Ok(()) => {
            // Persist the revoke. If the log write fails we surface the
            // failure to the caller — the in-memory revoke happened but
            // it WILL be reverted by the next restart's projection, so
            // we should not return 204.
            let revoke_event = MeshEvent::ClawShareSlotRevoked {
                slot_id: slot_id.clone(),
            };
            let owner_key = identity.m_priv.as_ref();
            if let Err(e) = log_event(&state.mesh_log, owner_key, now, revoke_event) {
                tracing::warn!(stage = "claw_share.revoke.log_failed", error = %e);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "log_persist_failed",
                    None,
                );
            }
            // The signed `ClawShareSlotRevoked` op-log entry above is the durable
            // revocation; the per-session credential gate is the authoritative
            // access boundary. The roster / deny-list re-publish + live
            // peer-removal are part of the L3 overlay subset and are
            // intentionally not wired in this relay/membership subset.
            let _ = owner_key;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(ClawShareError::SlotNotFound) => {
            error_response(StatusCode::NOT_FOUND, "slot_not_found", None)
        }
        Err(e) => {
            tracing::warn!(stage = "claw_share.revoke.failed", error = %e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "revoke_failed", None)
        }
    }
}

// ─── Fase E1: owner group-management endpoint ────────────────────────────────

/// One owner action against the first-class group model. Each variant maps to a
/// single signed `MeshEvent` appended to the durable log. Externally-tagged CBOR
/// (`snake_case` keys). `EnrollMemberDevice` additionally verifies the member's
/// self-signed `MemberDeviceBinding` before recording it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GroupOp {
    Create {
        group_id: String,
        name: String,
    },
    Rename {
        group_id: String,
        name: String,
    },
    AddMember {
        group_id: String,
        member_id: String,
        label: String,
    },
    RemoveMember {
        group_id: String,
        member_id: String,
    },
    GrantClaw {
        group_id: String,
        claw_id: String,
    },
    RevokeClaw {
        group_id: String,
        claw_id: String,
    },
    EnrollMemberDevice {
        binding: MemberDeviceBinding,
    },
    RetireMemberDevice {
        member_id: String,
        device_pub: P256PublicKey,
    },
    /// Fase E3: publish a claw's `ClawSite` as PUBLIC (anyone may dial it).
    PublishClaw {
        claw_id: String,
    },
    /// Fase E3: unpublish a claw — the public kill switch.
    UnpublishClaw {
        claw_id: String,
    },
}

#[derive(Debug, Deserialize)]
struct GroupOpRequest {
    v: u8,
    op: GroupOp,
}

/// Request body for `POST /api/v1/claw-share/invite-to-claw` — the ergonomic,
/// atomic "invite person X to claw Y" product primitive. Canonical CBOR,
/// `snake_case` keys. It composes the three already-tested owner-signed group
/// ops so the client makes ONE owner-authed call instead of three raw
/// `/group-op`s (Create + `AddMember` + `GrantClaw`).
#[derive(Debug, Deserialize)]
struct InviteToClawRequest {
    v: u8,
    /// The group the guest is invited into. Created with `group_name` when
    /// absent; an existing group is reused UNCHANGED (never renamed).
    group_id: String,
    /// Display name applied ONLY when the group is newly created.
    group_name: String,
    /// The guest's derived `member_id` (see `member_identity`). Membership is
    /// not trust by itself — the owner-signed `GroupMemberAdded` is what makes
    /// it authoritative.
    member_id: String,
    /// Owner-facing display label for the member (UX only, not an authority input).
    label: String,
    /// The claw the group is granted access to.
    claw_id: String,
}

/// Translate one [`GroupOp`] into the single signed `MeshEvent` it records.
/// `EnrollMemberDevice` fails closed (`BAD_REQUEST` / `member_binding_invalid`)
/// if the member's self-signed binding does not verify — `member_id` must derive
/// from `member_pub` and the member signature must hold. Pure (no I/O, no auth):
/// the SAME translation + validation is shared by the owner-PoP'd `/group-op` and
/// the dev-only `/dev-group-op` fixture, so the two paths can never diverge in
/// how an op maps to mesh state — only the authorization above them differs.
#[allow(clippy::result_large_err)] // the Err is a one-shot rejection Response
fn group_op_to_event(op: &GroupOp) -> Result<MeshEvent, Response> {
    Ok(match op {
        GroupOp::Create { group_id, name } => MeshEvent::GroupCreated {
            group_id: group_id.clone(),
            name: name.clone(),
        },
        GroupOp::Rename { group_id, name } => MeshEvent::GroupRenamed {
            group_id: group_id.clone(),
            name: name.clone(),
        },
        GroupOp::AddMember {
            group_id,
            member_id,
            label,
        } => MeshEvent::GroupMemberAdded {
            group_id: group_id.clone(),
            member_id: member_id.clone(),
            label: label.clone(),
        },
        GroupOp::RemoveMember {
            group_id,
            member_id,
        } => MeshEvent::GroupMemberRemoved {
            group_id: group_id.clone(),
            member_id: member_id.clone(),
        },
        GroupOp::GrantClaw { group_id, claw_id } => MeshEvent::GroupClawGranted {
            group_id: group_id.clone(),
            claw_id: claw_id.clone(),
        },
        GroupOp::RevokeClaw { group_id, claw_id } => MeshEvent::GroupClawRevoked {
            group_id: group_id.clone(),
            claw_id: claw_id.clone(),
        },
        GroupOp::EnrollMemberDevice { binding } => {
            if binding.verify().is_err() {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "member_binding_invalid",
                    None,
                ));
            }
            MeshEvent::MeshMemberDeviceEnrolled {
                member_id: binding.member_id.clone(),
                device_pub: binding.device_pub.clone(),
                participant_npub: binding.participant_npub.clone(),
            }
        }
        GroupOp::RetireMemberDevice {
            member_id,
            device_pub,
        } => MeshEvent::MeshMemberDeviceRetired {
            member_id: member_id.clone(),
            device_pub: device_pub.clone(),
        },
        GroupOp::PublishClaw { claw_id } => MeshEvent::ClawSitePublished {
            claw_id: claw_id.clone(),
        },
        GroupOp::UnpublishClaw { claw_id } => MeshEvent::ClawSiteUnpublished {
            claw_id: claw_id.clone(),
        },
    })
}

/// Apply one ALREADY-AUTHORIZED [`GroupOp`]: resolve the engine signing key,
/// translate via [`group_op_to_event`], and append the signed event to the
/// durable mesh log (the next `project()` folds it into the live state — there is
/// no cached projection to refresh). This is the post-authorization apply shared
/// by `/group-op` (owner-PoP'd above) and `/dev-group-op` (dev-gated above); it
/// performs NO authorization itself — the caller is the sole access boundary.
async fn apply_group_op(
    state: &ClawShareRouterState,
    op: &GroupOp,
    now: u64,
) -> Result<(), Response> {
    let Some(identity) = state.household.current().await else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "household_unavailable",
            None,
        ));
    };
    let owner_key = identity.m_priv.as_ref();
    let event = group_op_to_event(op)?;
    if let Err(e) = log_event(&state.mesh_log, owner_key, now, event) {
        tracing::warn!(stage = "claw_share.group_op.log_failed", error = %e);
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "log_persist_failed",
            None,
        ));
    }
    Ok(())
}

/// `POST /api/v1/claw-share/group-op` — OWNER-authed. Applies one [`GroupOp`] to
/// the first-class group model by appending one signed `MeshEvent` to the mesh
/// log, then republishes the affected claws' rosters so the change is live.
///
/// Auth reuses the owner share-management caveat (`HouseholdInvite`) — group
/// management is owner-only and adjacent to invite management, so this needs no
/// owner-cert migration; a dedicated `household.group` caveat is a follow-up.
async fn handle_group_op(
    State(state): State<ClawShareRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());

    if household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdInvite,
        now,
    )
    .await
    .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let req: GroupOpRequest = match cbor::from_canonical_slice(&body) {
        Ok(r) => r,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "request_malformed", None),
    };
    if req.v != 1 {
        return error_response(StatusCode::BAD_REQUEST, "version_unsupported", None);
    }

    // Post-authorization apply, shared with the dev-only `/dev-group-op` fixture.
    // The owner-PoP gate above is the SOLE authorization for this production
    // path. The signed membership op becomes durable in the op-log; the roster
    // re-publish of affected claws is part of the L3 overlay subset and is
    // intentionally not wired in this relay/membership subset.
    if let Err(resp) = apply_group_op(&state, &req.op, now).await {
        return resp;
    }

    StatusCode::NO_CONTENT.into_response()
}

/// Compose the owner-signed ops for an "invite person to claw" request against
/// the current projection. `GroupCreated` is included ONLY when the group is
/// absent (an existing group is reused unchanged, so a re-invite can never
/// rename or otherwise clobber it); `AddMember` and `GrantClaw` are always
/// included and are idempotent in the projection (re-adding an Active
/// member/claw is a no-op). Pure: no I/O, no auth — the handler applies the
/// result under the owner-PoP gate, so the ops carry no authority on their own.
fn invite_to_claw_ops(projection: &ProjectedState, req: &InviteToClawRequest) -> Vec<GroupOp> {
    let mut ops = Vec::with_capacity(3);
    if !projection.groups.contains_key(&req.group_id) {
        ops.push(GroupOp::Create {
            group_id: req.group_id.clone(),
            name: req.group_name.clone(),
        });
    }
    ops.push(GroupOp::AddMember {
        group_id: req.group_id.clone(),
        member_id: req.member_id.clone(),
        label: req.label.clone(),
    });
    ops.push(GroupOp::GrantClaw {
        group_id: req.group_id.clone(),
        claw_id: req.claw_id.clone(),
    });
    ops
}

/// `POST /api/v1/claw-share/invite-to-claw` — OWNER-authed. Atomically invites a
/// guest to one claw by appending the owner-signed events the dial-time gate
/// (`check_relay_stream_group_membership`) already enforces per request:
/// `GroupCreated` (only when absent), then `GroupMemberAdded`, then
/// `GroupClawGranted`.
///
/// This adds NO new authority: it is a thin, owner-only composition of the exact
/// tested `/group-op` primitives (`apply_group_op` -> `group_op_to_event` ->
/// signed `MeshEvent`), reusing the same `HouseholdInvite` caveat. It is
/// idempotent and fails CLOSED: a partial append (e.g. member added but the
/// grant not yet persisted) leaves the guest WITHOUT access, because the gate
/// requires BOTH an Active membership AND an Active claw grant; re-running the
/// invite simply completes it.
async fn handle_invite_to_claw(
    State(state): State<ClawShareRouterState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());

    if household_auth::authorize_request(
        &state.household,
        &headers,
        &method,
        &path_and_query,
        &body,
        Operation::HouseholdInvite,
        now,
    )
    .await
    .is_err()
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let req: InviteToClawRequest = match cbor::from_canonical_slice(&body) {
        Ok(r) => r,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "request_malformed", None),
    };
    if req.v != 1 {
        return error_response(StatusCode::BAD_REQUEST, "version_unsupported", None);
    }
    if req.group_id.is_empty() || req.member_id.is_empty() || req.claw_id.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "invite_field_empty", None);
    }

    // Read the projection once to decide whether the group must be created; the
    // owner-PoP gate above is the SOLE authorization for this production path.
    let ops = invite_to_claw_ops(&state.mesh_log.project(), &req);
    for op in &ops {
        if let Err(resp) = apply_group_op(&state, op, now).await {
            return resp;
        }
    }

    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod groups_list_tests {
    use super::*;
    use household_rs::household_mesh_log::{ProjectedGroup, ProjectedMemberDevice};

    #[test]
    fn build_groups_list_shows_active_state_with_labels_and_device_counts() {
        let mut projection = ProjectedState::default();
        projection.groups.insert(
            "g".to_string(),
            ProjectedGroup {
                group_id: "g".to_string(),
                name: "Family".to_string(),
                members: [
                    ("g_alice".to_string(), MeshMembership::Active),
                    ("g_removed".to_string(), MeshMembership::Removed),
                ]
                .into_iter()
                .collect(),
                member_labels: [("g_alice".to_string(), "Alice phone".to_string())]
                    .into_iter()
                    .collect(),
                granted_claws: [
                    ("claw_a".to_string(), MeshMembership::Active),
                    ("claw_revoked".to_string(), MeshMembership::Removed),
                ]
                .into_iter()
                .collect(),
                revision: 7,
            },
        );
        projection.member_devices.insert(
            "g_alice".to_string(),
            [
                (
                    vec![1u8; 33],
                    ProjectedMemberDevice {
                        participant_npub: "n1".to_string(),
                        status: MeshMembership::Active,
                    },
                ),
                (
                    vec![2u8; 33],
                    ProjectedMemberDevice {
                        participant_npub: "n2".to_string(),
                        status: MeshMembership::Active,
                    },
                ),
                (
                    vec![3u8; 33],
                    ProjectedMemberDevice {
                        participant_npub: "n3".to_string(),
                        status: MeshMembership::Removed,
                    },
                ),
            ]
            .into_iter()
            .collect(),
        );
        projection
            .published_claws
            .insert("claw_pub".to_string(), MeshMembership::Active);
        projection
            .published_claws
            .insert("claw_unpub".to_string(), MeshMembership::Removed);

        let response = build_groups_list_response(&projection);
        assert_eq!(response.v, 1);
        assert_eq!(response.groups.len(), 1);
        let group = &response.groups[0];
        assert_eq!(group.group_id, "g");
        assert_eq!(group.name, "Family");
        assert_eq!(group.members.len(), 1);
        assert_eq!(group.members[0].member_id, "g_alice");
        assert_eq!(group.members[0].label, "Alice phone");
        assert_eq!(group.members[0].device_count, 2);
        assert_eq!(group.granted_claws, vec!["claw_a".to_string()]);
        assert_eq!(response.published_claws, vec!["claw_pub".to_string()]);
    }

    #[test]
    fn build_groups_list_empty_projection_is_empty() {
        let response = build_groups_list_response(&ProjectedState::default());
        assert_eq!(response.v, 1);
        assert!(response.groups.is_empty());
        assert!(response.published_claws.is_empty());
    }

    #[test]
    fn groups_list_response_gold_hex() {
        let response = GroupsListResponse {
            v: 1,
            groups: vec![GroupView {
                group_id: "group_alpha".to_string(),
                name: "Alpha Group".to_string(),
                members: vec![MemberView {
                    member_id: "g_member_alpha".to_string(),
                    label: "Alice's phone".to_string(),
                    device_count: 1,
                }],
                granted_claws: vec!["claw_alpha".to_string()],
            }],
            published_claws: Vec::new(),
        };
        assert_eq!(
            hex::encode(cbor::to_canonical_vec(&response).unwrap()),
            "a36176016667726f75707381a4646e616d656b416c7068612047726f7570676d656d6265727381a3656c6162656c6d416c69636527732070686f6e65696d656d6265725f69646e675f6d656d6265725f616c7068616c6465766963655f636f756e74016867726f75705f69646b67726f75705f616c7068616d6772616e7465645f636c617773816a636c61775f616c7068616f7075626c69736865645f636c61777380"
        );
    }
}

/// `POST /api/v1/claw-share/claim` — anonymous endpoint. The friend's
/// device sends a signed `ClawShareClaim` (canonical CBOR). On success
/// the response is a CBOR `ClawShareAck` carrying the credential + tunnel
/// handle; on rejection the response is a typed CBOR error envelope.
async fn handle_claim(State(state): State<ClawShareRouterState>, body: Bytes) -> Response {
    let claim: ClawShareClaim = match cbor::from_canonical_slice(&body) {
        Ok(c) => c,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "claim_malformed", None),
    };

    let Some(identity) = state.household.current().await else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "household_unavailable",
            Some("engine has no loaded household identity"),
        );
    };
    let Some(owner_auth) = state.household.current_owner_auth().await else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "owner_auth_unavailable",
            Some("engine has no loaded owner cert"),
        );
    };

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "clock_before_epoch",
                None,
            );
        }
    };

    // For the slice, the engine signs the credential with its machine
    // key (`m_priv`) — semantically a stand-in for the owner key. The
    // trust chain refactor (machine_cert proves machine is authorized
    // to issue on owner's behalf) lands in a later slice. Field names
    // on the wire still read "owner_*" because they are what the friend
    // anchors against; the host-side rename to `issuer_*` is a known
    // follow-up and gated by the chain validation work.
    let owner_key = identity.m_priv.as_ref();
    let owner_p_id = &owner_auth.owner_person_cert.p_id;
    let hh_id = &identity.record.hh_id;

    // This relay/membership subset uses no overlay: the claim-ack carries a
    // Direct/Loopback data-plane handle only. A public Direct address
    // (operator-configured `THEYOS_CLAW_DATA_TUNNEL_PUBLIC_ADDR`) wins; else a
    // Loopback channel for the single-host harness. The L3 overlay handle
    // + roster add are intentionally not part of this subset.
    let tunnel_factory = |claw_id: &str| {
        public_data_tunnel_handle().unwrap_or_else(|| TunnelHandle::Loopback {
            channel: format!("ch-{claw_id}"),
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
        slot_store: &state.slot_store,
        credential_ttl_secs,
        tunnel_factory: &tunnel_factory,
    };

    match engine_handle_claim(&ctx, &claim, now) {
        Ok(ack) => {
            // Make the consume durable: append SlotConsumed to the
            // mesh log before sending the ack. If the append fails we
            // refuse the ack — the credential is already signed but
            // we shouldn't tell the friend "you're in" without the
            // engine being able to remember it across restart.
            let consume_event = MeshEvent::ClawShareSlotConsumed {
                slot_id: ack.credential.slot_id.clone(),
                guest_device_pub: ack.credential.guest_device_pub.clone(),
                claw_id: ack.credential.claw_id.clone(),
                expires_at: ack.credential.expires_at,
                // Persist the SIGNED overlay npub from the claim (keystone): the
                // share-derived roster is computed from consumed shares
                // that carry this. `None` for a ferry-only/legacy claim that
                // bound no overlay identity — such a share never enters the roster.
                participant_npub: claim.participant_npub.clone(),
            };
            if let Err(e) = log_event(&state.mesh_log, owner_key, now, consume_event) {
                tracing::warn!(stage = "claw_share.claim.log_failed", error = %e);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "log_persist_failed",
                    None,
                );
            }

            // Best-effort relay_stream offer provisioning for this consumed slot
            // (default-off; gated by THEYOS_RELAY_STREAM_LIVE). Never fails the
            // claim - errors are logged and swallowed inside the helper. The HTTP
            // claim path is plaintext, so the provisioned offer is DELIBERATELY
            // not delivered here: the ack stays None and the rendezvous token
            // never leaves on this path. The offer is still durable for the pool.
            let _ =
                crate::claw_share_relay_stream_mount::try_provision_relay_stream_offer_for_claim(
                    &state.state_dir,
                    &state.household,
                    &state.mesh_log,
                    owner_key,
                    &ack.credential,
                    now,
                )
                .await;

            match cbor::to_canonical_vec(&ack) {
                Ok(bytes) => cbor_response(StatusCode::OK, bytes),
                Err(_) => {
                    error_response(StatusCode::INTERNAL_SERVER_ERROR, "ack_encode_failed", None)
                }
            }
        }
        Err(e) => {
            let (status, code) = map_engine_error(&e);
            tracing::warn!(
                stage = "claw_share.claim.rejected",
                error.code = code,
                error.detail = %e,
            );
            error_response(status, code, Some(&format!("{e}")))
        }
    }
}

fn map_engine_error(err: &ClawShareError) -> (StatusCode, &'static str) {
    match err {
        ClawShareError::SlotNotFound => (StatusCode::NOT_FOUND, "slot_not_found"),
        ClawShareError::SlotAlreadyConsumed => (StatusCode::GONE, "slot_consumed"),
        ClawShareError::SlotRevoked => (StatusCode::GONE, "slot_revoked"),
        ClawShareError::InviteExpired => (StatusCode::GONE, "invite_expired"),
        ClawShareError::ClaimSignatureRejected
        | ClawShareError::InviteSignatureRejected
        | ClawShareError::CredentialSignatureRejected => {
            (StatusCode::UNAUTHORIZED, "signature_rejected")
        }
        ClawShareError::ClaimReplayWindow { .. } => (StatusCode::BAD_REQUEST, "claim_stale"),
        ClawShareError::VersionUnsupported(_) | ClawShareError::KindMismatch(_) => {
            (StatusCode::BAD_REQUEST, "wire_unsupported")
        }
        ClawShareError::SlotClawMismatch => (StatusCode::BAD_REQUEST, "slot_claw_mismatch"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    v: u8,
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
}

fn error_response(status: StatusCode, code: &str, message: Option<&str>) -> Response {
    let envelope = ErrorEnvelope {
        v: 1,
        code,
        message,
    };
    let bytes = cbor::to_canonical_vec(&envelope).unwrap_or_default();
    cbor_response(status, bytes)
}

fn cbor_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CBOR_CONTENT_TYPE),
    );
    resp
}

// HTTP integration test follow-up: constructing a synthetic
// `LoadedIdentity` (with valid `MachineCert` + chain) for this handler is
// non-trivial machinery that lives in `household-rs::bootstrap::tests`.
// The slice's correctness is already covered by:
//
//   - `household_rs::claw_share_flow::tests` for the engine handler
//     (pure function, no HTTP).
//   - `household_rs::claw_share::tests` for wire shapes, signing,
//     slot CAS, URI round-trip.
//
// The HTTP integration test belongs to the same slice that wires the
// handler into `household_bootstrap` and stands up the listeners in
// integration, so it can reuse the existing identity-bootstrap fixtures
// instead of rebuilding them from scratch here.

#[cfg(test)]
mod tests {
    use super::*;

    // ── Relay claim fields: single source of truth + fail closed ──

    #[test]
    fn relay_fields_resolve_from_identity_independent_of_mesh() {
        // `owner_engine_npub` comes straight from the relay receive identity
        // passed in — NOT from mesh. So an engine with mesh disabled still
        // mints a valid `owner_engine_npub` as long as a relay identity exists.
        let npub = "aa".repeat(32);
        let (owner_engine_npub, claim_relays) =
            resolve_relay_claim_fields(Some(&npub), Some("wss://relay.one, wss://relay.two ,,"))
                .expect("should resolve with identity + relays");
        assert_eq!(
            owner_engine_npub, npub,
            "owner_engine_npub passes through from the relay identity"
        );
        assert_eq!(claim_relays, vec!["wss://relay.one", "wss://relay.two"]);
    }

    #[test]
    fn relay_fields_fail_closed_without_relay_identity() {
        // No identity → refuse to mint (would advertise an empty target).
        assert_eq!(
            resolve_relay_claim_fields(None, Some("wss://relay.one")),
            Err("relay_identity_unavailable"),
        );
        // Empty-string identity is also rejected — no silent empty field.
        assert_eq!(
            resolve_relay_claim_fields(Some(""), Some("wss://relay.one")),
            Err("relay_identity_unavailable"),
        );
    }

    #[test]
    fn relay_fields_fail_closed_without_relays() {
        let npub = "bb".repeat(32);
        // No relay list configured at all.
        assert_eq!(
            resolve_relay_claim_fields(Some(&npub), None),
            Err("claim_relays_unconfigured"),
        );
        // Present but whitespace/empty-only → still fails closed (no silent
        // empty list slips through).
        assert_eq!(
            resolve_relay_claim_fields(Some(&npub), Some("   , ,")),
            Err("claim_relays_unconfigured"),
        );
    }

    // ── owner_engine_npub == relay-loop subscription key ──

    /// The invite's `owner_engine_npub` is the engine relay key's x-only hex
    /// (`public_key().to_hex()` — what bootstrap stores in `engine_relay_npub`
    /// and the mint advertises). The relay claim loop subscribes/decrypts on
    /// that SAME `public_key()`. A friend decoding the advertised npub MUST
    /// arrive at the exact key the engine listens on, else the claim lands on a
    /// pubkey nobody reads. This pins the single-source-of-truth invariant that
    /// the prior bug (mint advertised the mesh npub) violated.
    #[test]
    fn advertised_owner_engine_npub_decodes_to_relay_subscription_key() {
        use nostr_relay_rs::nostr::{Keys, PublicKey};
        let engine_keys = Keys::generate();
        let advertised = engine_keys.public_key().to_hex(); // bootstrap → engine_relay_npub → mint
        let subscribed = engine_keys.public_key(); // claw_share_relay_loop Filter::pubkey(...)
        let decoded = PublicKey::from_hex(&advertised).expect("advertised npub is valid hex");
        assert_eq!(
            decoded, subscribed,
            "owner_engine_npub must decode to the relay subscription key",
        );
    }

    // ── Direct public data-tunnel address parsing ──

    #[test]
    fn public_data_tunnel_addr_parses_host_port() {
        assert_eq!(
            parse_public_data_tunnel_addr("192.168.15.12:7423"),
            Some(TunnelHandle::Direct {
                host: "192.168.15.12".into(),
                port: 7423
            }),
        );
        // trims whitespace.
        assert_eq!(
            parse_public_data_tunnel_addr("  mac.local : 7423 "),
            Some(TunnelHandle::Direct {
                host: "mac.local".into(),
                port: 7423
            }),
        );
    }

    #[test]
    fn public_data_tunnel_addr_rejects_malformed() {
        // Never advertise a half-broken Direct handle.
        assert_eq!(parse_public_data_tunnel_addr(""), None);
        assert_eq!(parse_public_data_tunnel_addr("no-port"), None);
        assert_eq!(parse_public_data_tunnel_addr("host:notaport"), None);
        assert_eq!(parse_public_data_tunnel_addr("host:"), None);
        assert_eq!(parse_public_data_tunnel_addr(":7423"), None);
        assert_eq!(parse_public_data_tunnel_addr("host:99999"), None); // > u16::MAX
    }

    // ---- R134: public direct engine peer (CPE port-forward / WAN endpoint) ----

    // ── F1: shared GroupOp → MeshEvent translation (post-auth apply helper) ──

    #[test]
    fn group_op_to_event_maps_membership_variants() {
        // The four ops the group-claim membership gate depends on must map to the
        // exact mesh events `check_relay_stream_group_membership` reads.
        let ev = group_op_to_event(&GroupOp::Create {
            group_id: "g".into(),
            name: "G".into(),
        })
        .expect("create translates");
        assert!(matches!(ev, MeshEvent::GroupCreated { .. }));

        let ev = group_op_to_event(&GroupOp::AddMember {
            group_id: "g".into(),
            member_id: "g_m".into(),
            label: "phone".into(),
        })
        .expect("add_member translates");
        assert!(matches!(ev, MeshEvent::GroupMemberAdded { .. }));

        let ev = group_op_to_event(&GroupOp::GrantClaw {
            group_id: "g".into(),
            claw_id: "claw_a".into(),
        })
        .expect("grant_claw translates");
        assert!(matches!(ev, MeshEvent::GroupClawGranted { .. }));
    }

    #[test]
    fn group_op_to_event_enroll_verifies_binding_fail_closed() {
        use household_rs::keys::P256Keypair;
        use household_rs::member_identity::MemberDeviceBinding;

        let member = P256Keypair::generate();
        let device = P256Keypair::generate();
        let binding = MemberDeviceBinding::sign(
            &member,
            device.public(),
            "participant_npub_hex".into(),
            1_800_000_000,
        )
        .expect("sign member binding");

        // A valid self-signed binding records the enrol event.
        let ev = group_op_to_event(&GroupOp::EnrollMemberDevice {
            binding: binding.clone(),
        })
        .expect("valid binding accepted");
        assert!(matches!(ev, MeshEvent::MeshMemberDeviceEnrolled { .. }));

        // A forged member_id (no longer derives from member_pub) is rejected with
        // 400 — the SAME fail-closed validation the prod path enforced inline, now
        // shared verbatim by /group-op and the dev-only /dev-group-op fixture.
        let mut forged = binding;
        forged.member_id = "g_forged_member_id".into();
        let resp = group_op_to_event(&GroupOp::EnrollMemberDevice { binding: forged })
            .expect_err("forged member_id rejected");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── F2: the /dev-group-op seed satisfies the live group-claim gate ──

    #[test]
    fn dev_group_op_sequence_satisfies_live_membership_gate() {
        // The exact four ops /dev-group-op applies, run through the SAME
        // group_op_to_event + log_event the handler uses, must leave the live
        // projection in a state that PASSES check_relay_stream_group_membership
        // for the matching member+device — i.e. the live group claim will be
        // authorized. This is the F2↔F3 contract proven without a live engine.
        use crate::claw_share_relay_stream_contract::check_relay_stream_group_membership;
        use household_rs::household_mesh_log::MeshLogStore;
        use household_rs::keys::P256Keypair;
        use household_rs::member_identity::MemberDeviceBinding;

        let owner = P256Keypair::generate();
        // The SAME fixed secrets the smoke feeds to BOTH the dev seed and the
        // friend-cli claim → identical member_id + device_pub.
        let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).expect("member scalar");
        let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("device scalar");
        let device_pub = device.public();
        let binding = MemberDeviceBinding::sign(
            &member,
            device_pub.clone(),
            "participant_npub_hex".into(),
            1_800_000_000,
        )
        .expect("sign binding");
        let member_id = binding.member_id.clone();

        let mesh = MeshLogStore::new();
        let now = 1_800_000_100u64;
        let ops = [
            GroupOp::Create {
                group_id: "g".into(),
                name: "G".into(),
            },
            GroupOp::AddMember {
                group_id: "g".into(),
                member_id: member_id.clone(),
                label: "phone".into(),
            },
            GroupOp::EnrollMemberDevice { binding },
            GroupOp::GrantClaw {
                group_id: "g".into(),
                claw_id: "claw_a".into(),
            },
        ];
        for op in ops {
            let event = group_op_to_event(&op).expect("translate");
            log_event(&mesh, &owner as &dyn IdentityKey, now, event).expect("append");
        }

        let proj = mesh.project();
        check_relay_stream_group_membership(&proj, "g", &member_id, "claw_a", &device_pub)
            .expect("the dev-group-op sequence must satisfy the live membership gate");

        // Fail-closed negatives: a different device, claw, or group is rejected.
        let other_device = P256Keypair::from_secret_scalar(&[0x44u8; 32]).unwrap();
        assert!(
            check_relay_stream_group_membership(
                &proj,
                "g",
                &member_id,
                "claw_a",
                &other_device.public()
            )
            .is_err()
        );
        assert!(
            check_relay_stream_group_membership(&proj, "g", &member_id, "claw_other", &device_pub)
                .is_err()
        );
        assert!(
            check_relay_stream_group_membership(
                &proj,
                "other_g",
                &member_id,
                "claw_a",
                &device_pub
            )
            .is_err()
        );
    }

    #[cfg(feature = "dev_claw_share_mint")]
    #[test]
    fn dev_keypair_from_hex_matches_cross_language_fixture() {
        // Scalar [0x55;32] → the member_pub, and [0x33;32] → the device_pub,
        // pinned in docs/product-a-group-op-fixtures.md. Proves the server parse
        // == friend-cli's member_key_from_hex == the cross-language fixture, so
        // the same --member-secret/--device-secret yield identical keys on both.
        let m = dev_keypair_from_hex(&"55".repeat(32)).expect("valid member scalar");
        assert_eq!(
            hex::encode(&m.public().as_bytes()[..]),
            "0257e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34"
        );
        let d = dev_keypair_from_hex(&"33".repeat(32)).expect("valid device scalar");
        assert_eq!(
            hex::encode(&d.public().as_bytes()[..]),
            "0351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d"
        );
        // Shape-hiding 400 reasons (never panic, never leak).
        assert_eq!(
            dev_keypair_from_hex("abcd").err(),
            Some("secret_not_64_hex")
        );
        assert!(dev_keypair_from_hex(&"zz".repeat(32)).is_err());
    }

    // ── Ergonomic invite-to-claw endpoint (front half) ──

    #[test]
    fn invite_to_claw_ops_creates_group_only_when_absent() {
        use household_rs::keys::P256Keypair;

        let req = InviteToClawRequest {
            v: 1,
            group_id: "g".into(),
            group_name: "G".into(),
            member_id: "g_member".into(),
            label: "phone".into(),
            claw_id: "claw_a".into(),
        };

        // Absent group: Create is composed first, then AddMember + GrantClaw.
        let empty = MeshLogStore::new().project();
        let ops = invite_to_claw_ops(&empty, &req);
        assert_eq!(ops.len(), 3);
        assert!(matches!(ops[0], GroupOp::Create { .. }));
        assert!(matches!(ops[1], GroupOp::AddMember { .. }));
        assert!(matches!(ops[2], GroupOp::GrantClaw { .. }));

        // Existing group: Create is skipped (reused unchanged) — only AddMember + GrantClaw.
        let owner = P256Keypair::generate();
        let mesh = MeshLogStore::new();
        log_event(
            &mesh,
            &owner as &dyn IdentityKey,
            1_800_000_100,
            MeshEvent::GroupCreated {
                group_id: "g".into(),
                name: "G".into(),
            },
        )
        .expect("seed group");
        let ops = invite_to_claw_ops(&mesh.project(), &req);
        assert_eq!(ops.len(), 2);
        assert!(matches!(ops[0], GroupOp::AddMember { .. }));
        assert!(matches!(ops[1], GroupOp::GrantClaw { .. }));
    }

    #[test]
    fn invite_to_claw_ops_applied_satisfy_membership_gate() {
        use household_rs::keys::P256Keypair;

        let owner = P256Keypair::generate();
        let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).expect("member scalar");
        let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("device scalar");
        let device_pub = device.public();
        let binding = MemberDeviceBinding::sign(
            &member,
            device_pub.clone(),
            "participant_npub_hex".into(),
            1_800_000_000,
        )
        .expect("sign binding");
        let member_id = binding.member_id.clone();

        let mesh = MeshLogStore::new();
        let now = 1_800_000_100u64;
        let req = InviteToClawRequest {
            v: 1,
            group_id: "g".into(),
            group_name: "G".into(),
            member_id: member_id.clone(),
            label: "phone".into(),
            claw_id: "claw_a".into(),
        };

        // Apply the composed invite ops (Create + AddMember + GrantClaw)...
        for op in invite_to_claw_ops(&mesh.project(), &req) {
            let event = group_op_to_event(&op).expect("translate");
            log_event(&mesh, &owner as &dyn IdentityKey, now, event).expect("append");
        }
        // ...plus the guest's own self-signed device enrolment (a separate op the
        // invite does not — and must not — forge on the member's behalf).
        let enroll = group_op_to_event(&GroupOp::EnrollMemberDevice { binding }).expect("enroll");
        log_event(&mesh, &owner as &dyn IdentityKey, now, enroll).expect("append enroll");

        let proj = mesh.project();
        check_relay_stream_group_membership(&proj, "g", &member_id, "claw_a", &device_pub)
            .expect("invite must authorize the matching member + device + claw");

        // Fail-closed: the GrantClaw is load-bearing — a claw the invite did NOT
        // grant is rejected for the same member+device.
        assert!(
            check_relay_stream_group_membership(&proj, "g", &member_id, "claw_other", &device_pub)
                .is_err()
        );
    }

    #[test]
    fn reinvite_into_existing_group_preserves_name_and_members() {
        use household_rs::keys::P256Keypair;

        let owner = P256Keypair::generate();
        let mesh = MeshLogStore::new();
        let now = 1_800_000_100u64;

        // First invite creates group "g" (name "Family") with member m1.
        let first = InviteToClawRequest {
            v: 1,
            group_id: "g".into(),
            group_name: "Family".into(),
            member_id: "g_m1".into(),
            label: "m1".into(),
            claw_id: "claw_a".into(),
        };
        for op in invite_to_claw_ops(&mesh.project(), &first) {
            log_event(
                &mesh,
                &owner as &dyn IdentityKey,
                now,
                group_op_to_event(&op).unwrap(),
            )
            .unwrap();
        }

        // Second invite of m2 into the SAME group carries a DIFFERENT group_name;
        // because the group already exists, Create is not composed, so the name
        // is never touched and m1 is preserved.
        let second = InviteToClawRequest {
            v: 1,
            group_id: "g".into(),
            group_name: "ATTACKER_RENAME".into(),
            member_id: "g_m2".into(),
            label: "m2".into(),
            claw_id: "claw_a".into(),
        };
        let ops = invite_to_claw_ops(&mesh.project(), &second);
        assert!(
            !ops.iter().any(|op| matches!(op, GroupOp::Create { .. })),
            "an existing group must never be re-created by a re-invite"
        );
        for op in ops {
            log_event(
                &mesh,
                &owner as &dyn IdentityKey,
                now + 1,
                group_op_to_event(&op).unwrap(),
            )
            .unwrap();
        }

        let proj = mesh.project();
        let group = proj.groups.get("g").expect("group exists");
        assert_eq!(group.name, "Family", "re-invite must not rename the group");
        assert_eq!(
            group.members.get("g_m1"),
            Some(&MeshMembership::Active),
            "the original member must be preserved"
        );
        assert_eq!(
            group.members.get("g_m2"),
            Some(&MeshMembership::Active),
            "the newly invited member must be added"
        );
    }
}

#[cfg(test)]
mod relay_offer_tests {
    use super::*;

    use std::net::SocketAddr;

    use household_rs::household_mesh_log::{
        build_claw_site_published_event, build_group_claw_grant_event, build_group_created_event,
        build_group_member_add_event, build_member_device_enroll_event,
    };
    use household_rs::keys::P256Keypair;
    use household_rs::member_identity::derive_member_id;

    use crate::claw_share_relay_stream_contract::RelayStreamAudience;
    use crate::claw_share_relay_stream_test_support::{
        attacker_signer, data_tunnel_store, guest_pub, guest_signer, now_unix, owner_pub,
        owner_signer, relay_stream_household_state,
    };

    fn loopback() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 50_000))
    }

    fn relay_offer_state(
        mesh_log: Arc<MeshLogStore>,
        state_dir: std::path::PathBuf,
    ) -> ClawShareRouterState {
        ClawShareRouterState {
            household: relay_stream_household_state(),
            slot_store: data_tunnel_store(),
            mesh_log,
            engine_relay_npub: None,
            state_dir,
            relay_offer_challenges: Arc::new(RelayOfferChallengeTable::new()),
            relay_offer_abuse: Arc::new(std::sync::Mutex::new(RelayAbuseState::default())),
        }
    }

    async fn response_bytes(resp: Response) -> (StatusCode, Vec<u8>) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, bytes.to_vec())
    }

    #[cfg(feature = "dev_claw_share_mint")]
    #[test]
    fn dev_endpoint_gate_requires_loopback_and_both_flags() {
        let lo = "127.0.0.1".parse::<std::net::IpAddr>().unwrap();
        let public = "8.8.8.8".parse::<std::net::IpAddr>().unwrap();
        assert!(dev_endpoint_allowed(lo, Some("1"), Some("1")));
        assert!(!dev_endpoint_allowed(public, Some("1"), Some("1"))); // non-loopback
        assert!(!dev_endpoint_allowed(lo, None, Some("1"))); // mint flag unset
        assert!(!dev_endpoint_allowed(lo, Some("0"), Some("1"))); // mint flag != 1
        assert!(!dev_endpoint_allowed(lo, Some("1"), None)); // software-keys unset
        assert!(!dev_endpoint_allowed(lo, Some("1"), Some("0"))); // software-keys != 1
    }

    #[test]
    fn dev_publish_claw_event_marks_claw_published_for_the_public_dial_gate() {
        // The event handle_dev_publish_claw emits — a self-signed ClawSitePublished
        // via log_event — folds into the live projection so the Public dial gate
        // opens; an Unpublished reverses it (remove-wins).
        let mesh_log = MeshLogStore::new();
        let owner = owner_signer();
        log_event(
            &mesh_log,
            &owner as &dyn IdentityKey,
            now_unix(),
            MeshEvent::ClawSitePublished {
                claw_id: "claw_smoke".to_string(),
            },
        )
        .unwrap();
        let projection = mesh_log.project();
        assert!(projection.is_claw_published("claw_smoke"));
        check_relay_stream_public(&projection, "claw_smoke").expect("public dial gate opens");

        log_event(
            &mesh_log,
            &owner as &dyn IdentityKey,
            now_unix() + 1,
            MeshEvent::ClawSiteUnpublished {
                claw_id: "claw_smoke".to_string(),
            },
        )
        .unwrap();
        assert!(!mesh_log.project().is_claw_published("claw_smoke"));
    }

    #[tokio::test]
    async fn challenge_endpoint_issues_a_consumable_challenge() {
        let now = now_unix();
        let dir = tempfile::tempdir().unwrap();
        let state = relay_offer_state(Arc::new(MeshLogStore::new()), dir.path().to_path_buf());

        let req = RelayOfferChallengeReq { v: 1 };
        let body = Bytes::from(cbor::to_canonical_vec(&req).unwrap());
        let resp =
            handle_relay_offer_challenge(State(state.clone()), ConnectInfo(loopback()), body).await;
        let (status, bytes) = response_bytes(resp).await;
        assert_eq!(status, StatusCode::CREATED);
        let decoded: RelayOfferChallengeResp = cbor::from_canonical_slice(&bytes).unwrap();
        assert_eq!(decoded.challenge.len(), 32);
        // The issued challenge is consumable exactly once on the shared table.
        assert!(
            state
                .relay_offer_challenges
                .consume(&decoded.challenge, now)
        );
        assert!(
            !state
                .relay_offer_challenges
                .consume(&decoded.challenge, now)
        );
    }

    #[tokio::test]
    async fn public_offer_happy_path_and_unpublished_rejected() {
        let now = now_unix();
        let dir = tempfile::tempdir().unwrap();
        let mesh_log = Arc::new(MeshLogStore::new());
        mesh_log
            .append(
                build_claw_site_published_event(
                    "claw_pub".into(),
                    now,
                    owner_pub(),
                    &owner_signer(),
                )
                .unwrap(),
            )
            .unwrap();
        let state = relay_offer_state(Arc::clone(&mesh_log), dir.path().to_path_buf());

        // Happy path: published claw → minted Public offer.
        let challenge = state.relay_offer_challenges.issue(now, 60).unwrap();
        let req = RelayOfferPublicReq {
            v: 1,
            challenge: challenge.to_vec(),
            dialer_device_pub: guest_pub(),
            claw_id: "claw_pub".into(),
            ttl_secs: None,
        };
        let body = Bytes::from(cbor::to_canonical_vec(&req).unwrap());
        let resp =
            handle_relay_offer_public(State(state.clone()), ConnectInfo(loopback()), body).await;
        let (status, bytes) = response_bytes(resp).await;
        assert_eq!(status, StatusCode::CREATED);
        let offer: RelayStreamOfferContract = cbor::from_canonical_slice(&bytes).unwrap();
        assert_eq!(offer.payload.audience(), RelayStreamAudience::Public);
        assert_eq!(offer.payload.claw_id, "claw_pub");

        // Unpublished claw → 404 (fail-closed), nothing minted.
        let challenge2 = state.relay_offer_challenges.issue(now, 60).unwrap();
        let req2 = RelayOfferPublicReq {
            v: 1,
            challenge: challenge2.to_vec(),
            dialer_device_pub: guest_pub(),
            claw_id: "claw_unpub".into(),
            ttl_secs: None,
        };
        let body2 = Bytes::from(cbor::to_canonical_vec(&req2).unwrap());
        let resp2 =
            handle_relay_offer_public(State(state.clone()), ConnectInfo(loopback()), body2).await;
        let (status2, _) = response_bytes(resp2).await;
        assert_eq!(status2, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn group_offer_happy_path_and_bad_pop_rejected() {
        let now = now_unix();
        let dir = tempfile::tempdir().unwrap();
        let mesh_log = Arc::new(MeshLogStore::new());

        let member_key = P256Keypair::from_secret_scalar(&[0x71; 32]).unwrap();
        let member_id = derive_member_id(&member_key.public());
        let device_key = guest_signer();
        let device_pub = guest_pub();
        let npub = "npub_alice".to_string();
        let o = owner_signer();

        // Owner provisions the group: created → member added → claw granted →
        // device enrolled. All owner-signed.
        for entry in [
            build_group_created_event("g".into(), "Fam".into(), now, owner_pub(), &o).unwrap(),
            build_group_member_add_event(
                "g".into(),
                member_id.clone(),
                "alice".into(),
                now,
                owner_pub(),
                &o,
            )
            .unwrap(),
            build_group_claw_grant_event("g".into(), "claw_g".into(), now, owner_pub(), &o)
                .unwrap(),
            build_member_device_enroll_event(
                member_id.clone(),
                device_pub.clone(),
                npub.clone(),
                now,
                owner_pub(),
                &o,
            )
            .unwrap(),
        ] {
            mesh_log.append(entry).unwrap();
        }
        let state = relay_offer_state(Arc::clone(&mesh_log), dir.path().to_path_buf());

        // Member self-signs the device binding (member_id derives from member_pub).
        let binding =
            MemberDeviceBinding::sign(&member_key, device_pub.clone(), npub.clone(), now).unwrap();

        // Happy path: binding + device PoP over a fresh challenge → Group offer.
        let challenge = state.relay_offer_challenges.issue(now, 60).unwrap();
        let unsigned = RelayOfferGroupReqUnsigned {
            v: 1,
            challenge: &challenge,
            group_id: "g",
            claw_id: "claw_g",
            ttl_secs: None,
        };
        let pop = device_key
            .sign(&cbor::to_canonical_vec(&unsigned).unwrap())
            .unwrap();
        let req = RelayOfferGroupReq {
            v: 1,
            challenge: challenge.to_vec(),
            binding: binding.clone(),
            group_id: "g".into(),
            claw_id: "claw_g".into(),
            device_pop: pop,
            ttl_secs: None,
        };
        let body = Bytes::from(cbor::to_canonical_vec(&req).unwrap());
        let resp =
            handle_relay_offer_group(State(state.clone()), ConnectInfo(loopback()), body).await;
        let (status, bytes) = response_bytes(resp).await;
        assert_eq!(status, StatusCode::CREATED);
        let offer: RelayStreamOfferContract = cbor::from_canonical_slice(&bytes).unwrap();
        assert_eq!(
            offer.payload.audience(),
            RelayStreamAudience::Group {
                group_id: "g".into(),
                member_id: member_id.clone(),
            }
        );
        assert_eq!(offer.payload.guest_device_pub, device_pub);

        // Bad device PoP (signed by an attacker) → 401, nothing minted.
        let challenge2 = state.relay_offer_challenges.issue(now, 60).unwrap();
        let unsigned2 = RelayOfferGroupReqUnsigned {
            v: 1,
            challenge: &challenge2,
            group_id: "g",
            claw_id: "claw_g",
            ttl_secs: None,
        };
        let bad_pop = attacker_signer()
            .sign(&cbor::to_canonical_vec(&unsigned2).unwrap())
            .unwrap();
        let req2 = RelayOfferGroupReq {
            v: 1,
            challenge: challenge2.to_vec(),
            binding,
            group_id: "g".into(),
            claw_id: "claw_g".into(),
            device_pop: bad_pop,
            ttl_secs: None,
        };
        let body2 = Bytes::from(cbor::to_canonical_vec(&req2).unwrap());
        let resp2 =
            handle_relay_offer_group(State(state.clone()), ConnectInfo(loopback()), body2).await;
        let (status2, _) = response_bytes(resp2).await;
        assert_eq!(status2, StatusCode::UNAUTHORIZED);
    }
}
