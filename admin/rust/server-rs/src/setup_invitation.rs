//! In-memory cache for iPhone-first setup invitations (`_soyeht-setup._tcp.`).
//!
//! The Bonjour browser populates this cache when it discovers an iPhone
//! publishing `_soyeht-setup._tcp.`. The `POST /bootstrap/claim-setup-invitation`
//! handler reads from it to validate the token before persisting the invitation
//! and marking the engine as iPhone-initiated.
//!
//! Persistence path: `household/pending/setup_invitation.cbor` — written by the
//! claim handler, read by `POST /bootstrap/initialize` to enforce the Tailnet
//! IP-source guard per `contracts/setup-invitation.md`.

use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::sync::Mutex;

use crate::bonjour_trust::{DiscoverySource, classify_source};
use crate::pairing_addresses::PairingInstallation;

// ── Cache entry ───────────────────────────────────────────────────────────────

/// One `_soyeht-setup._tcp.` service discovered from the iPhone.
#[derive(Clone)]
pub struct SetupInvitationEntry {
    /// Raw 32-byte token from the Bonjour TXT `token` field (base64url-decoded).
    pub token: [u8; 32],
    /// `"<mDNS-hostname>:<port>"` — the callback endpoint the engine pings
    /// to verify the invitation is still valid on the iPhone side.
    pub iphone_endpoint: String,
    /// Resolved IP addresses of the iPhone's Bonjour service. The IP guard on
    /// `POST /bootstrap/initialize` checks that the request source matches one
    /// of these AND falls within Tailnet ranges.
    pub iphone_addrs: Vec<IpAddr>,
    pub owner_display_name: String,
    /// Non-empty when iPhone is helping a machine join an existing household.
    pub hh_id: Option<String>,
    pub expires_at: u64,
}

impl std::fmt::Debug for SetupInvitationEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: adding a field without updating this impl is a compile error.
        let Self {
            token: _,
            iphone_endpoint,
            iphone_addrs,
            owner_display_name,
            hh_id,
            expires_at,
        } = self;
        f.debug_struct("SetupInvitationEntry")
            .field("token", &"[REDACTED]")
            .field("iphone_endpoint", iphone_endpoint)
            .field("iphone_addrs", iphone_addrs)
            .field("owner_display_name", owner_display_name)
            .field("hh_id", hh_id)
            .field("expires_at", expires_at)
            .finish()
    }
}

impl SetupInvitationEntry {
    /// `true` if `src_ip` is a Tailnet address that matches this entry's `iphone_addrs`.
    #[must_use]
    pub fn source_ip_matches(&self, src_ip: IpAddr) -> bool {
        classify_source(src_ip) == DiscoverySource::Tailnet && self.iphone_addrs.contains(&src_ip)
    }
}

// ── Cache ─────────────────────────────────────────────────────────────────────

/// Thread-safe in-memory cache of setup invitations, keyed by token.
pub type SetupInvitationCache = Arc<Mutex<HashMap<[u8; 32], SetupInvitationEntry>>>;

#[must_use]
pub fn new_cache() -> SetupInvitationCache {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Insert or replace an entry. Called by the Bonjour browser task.
pub async fn cache_insert(cache: &SetupInvitationCache, entry: SetupInvitationEntry) {
    cache.lock().await.insert(entry.token, entry);
}

/// Remove all expired entries (called opportunistically before lookups).
pub async fn cache_purge_expired(cache: &SetupInvitationCache, now_unix: u64) {
    cache.lock().await.retain(|_, e| e.expires_at > now_unix);
}

/// Look up an entry by raw token bytes. Returns `None` if not found.
pub async fn cache_lookup(
    cache: &SetupInvitationCache,
    token: &[u8; 32],
) -> Option<SetupInvitationEntry> {
    cache.lock().await.get(token).cloned()
}

/// Atomically remove and return an entry. Concurrent callers with the same
/// token each hold the lock for the full remove; only the first gets `Some`.
/// Use instead of separate lookup + remove to close the concurrent-replay window.
pub async fn cache_take(
    cache: &SetupInvitationCache,
    token: &[u8; 32],
) -> Option<SetupInvitationEntry> {
    cache.lock().await.remove(token)
}

/// Re-insert `entry` on transient error paths, but only if the slot is still
/// vacant. Uses `entry(...).or_insert` so a fresher entry written by the
/// Bonjour browser (e.g. updated `expires_at` or `iphone_addrs`) is never
/// clobbered by the stale copy captured at `cache_take` time.
pub async fn cache_reinsert_if_absent(cache: &SetupInvitationCache, entry: SetupInvitationEntry) {
    cache.lock().await.entry(entry.token).or_insert(entry);
}

// ── TXT field parsing ─────────────────────────────────────────────────────────

/// Parse `_soyeht-setup._tcp.` TXT fields into a `SetupInvitationEntry`.
///
/// `txt` is a closure that returns the TXT field value for a given key.
/// Returns `None` if any required field is missing or malformed.
#[must_use]
pub fn parse_setup_txt(
    hostname: &str,
    port: u16,
    addrs: Vec<IpAddr>,
    txt: &impl Fn(&str) -> Option<String>,
) -> Option<SetupInvitationEntry> {
    let v: u8 = txt("v")?.parse().ok()?;
    if v != 1 {
        return None;
    }
    let token_b64 = txt("token")?;
    let token_bytes = B64URL.decode(token_b64).ok()?;
    let token: [u8; 32] = token_bytes.try_into().ok()?;
    let expires_at: u64 = txt("expires_at")?.parse().ok()?;
    let owner_display_name = txt("owner_display_name").unwrap_or_default();
    let hh_id = txt("hh_id").filter(|s| !s.is_empty());
    let iphone_endpoint = format!("{hostname}:{port}");
    Some(SetupInvitationEntry {
        token,
        iphone_endpoint,
        iphone_addrs: addrs,
        owner_display_name,
        hh_id,
        expires_at,
    })
}

/// Parse setup TXT fields and insert the invitation into `cache`.
///
/// Returns the inserted entry for logging/tests, or `None` when the TXT record
/// is not a valid iPhone setup invitation.
pub async fn cache_setup_txt(
    cache: &SetupInvitationCache,
    hostname: &str,
    port: u16,
    addrs: Vec<IpAddr>,
    txt: &impl Fn(&str) -> Option<String>,
) -> Option<SetupInvitationEntry> {
    let entry = parse_setup_txt(hostname, port, addrs, txt)?;
    cache_insert(cache, entry.clone()).await;
    Some(entry)
}

// ── Callback verify ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct VerifyReq<'a> {
    #[serde(rename = "v")]
    version: u8,
    token: &'a ByteBuf,
}

#[derive(Serialize, Deserialize)]
struct VerifyResp {
    #[serde(rename = "v")]
    version: u8,
    token: ByteBuf,
    installation: Option<PairingInstallation>,
    expires_at: u64,
    owner_display_name: Option<String>,
    iphone_apns_token: Option<ByteBuf>,
}

pub type InvitationVerifier =
    fn(&str, &[u8; 32], &PairingInstallation) -> Result<VerifiedInvitation, String>;

pub struct VerifiedInvitation {
    pub expires_at: u64,
    pub owner_display_name: String,
    pub iphone_apns_token: Option<[u8; 32]>,
    pub lan_address: Option<IpAddr>,
}

/// Limit callbacks to nearby addresses. In particular, do not follow redirects,
/// credentials, public DNS, alternate paths or queries supplied in an invitation.
/// LAN admission is bound to a literal address at which the token was verified.
fn callback_url(endpoint: &str) -> Result<(reqwest::Url, Option<IpAddr>), String> {
    let raw = if endpoint.contains("://") {
        endpoint.to_owned()
    } else {
        format!("http://{endpoint}")
    };
    let mut url = reqwest::Url::parse(&raw).map_err(|_| "invalid_callback_endpoint")?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.port().is_none()
    {
        return Err("invalid_callback_endpoint".into());
    }
    let host = url
        .host_str()
        .ok_or("invalid_callback_endpoint")?
        .trim_matches(['[', ']']);
    let ip = host.parse::<IpAddr>().ok();
    if let Some(ip) = ip {
        let local = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
        };
        if ip.is_loopback()
            || ip.is_unspecified()
            || !(local || crate::tailnet_address::is_tailnet_ip(ip))
        {
            return Err("invalid_callback_endpoint".into());
        }
    } else if !host.trim_end_matches('.').ends_with(".local") {
        return Err("invalid_callback_endpoint".into());
    }
    url.set_path("/setup/verify");
    Ok((
        url,
        ip.filter(|ip| !crate::tailnet_address::is_tailnet_ip(*ip)),
    ))
}

/// Confirm both token possession and installation at the iPhone before making
/// any claim persistent. Metadata comes from this response, not a Mac hint.
/// Runs synchronously; async callers must use spawn_blocking.
pub fn callback_verify_blocking(
    iphone_endpoint: &str,
    token: &[u8; 32],
    expected: &PairingInstallation,
) -> Result<VerifiedInvitation, String> {
    let (url, lan_address) = callback_url(iphone_endpoint)?;
    let token_buf = ByteBuf::from(token.to_vec());
    let req_body = household_rs::cbor::to_canonical_vec(&VerifyReq {
        version: 1,
        token: &token_buf,
    })
    .map_err(|_| "verify_encode_failed")?;
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(5))
        .build();
    let response = agent
        .post(url.as_str())
        .set("Content-Type", "application/cbor")
        .send_bytes(&req_body)
        .map_err(|_| "verify_request_failed")?;
    if response.status() != 200
        || response
            .header("Content-Type")
            .map(|h| h.split(';').next().unwrap_or("").trim())
            != Some("application/cbor")
    {
        return Err("invalid_verify_response".into());
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "verify_read_failed")?;
    if bytes.len() > 65_536 {
        return Err("verify_response_too_large".into());
    }
    decode_verified_invitation(&bytes, token, expected, lan_address)
}

pub fn decode_verified_invitation(
    bytes: &[u8],
    token: &[u8; 32],
    expected: &PairingInstallation,
    lan_address: Option<IpAddr>,
) -> Result<VerifiedInvitation, String> {
    let resp: VerifyResp =
        household_rs::cbor::from_canonical_slice(bytes).map_err(|_| "invalid_verify_response")?;
    if resp.version != 1 || resp.token.as_ref() != token.as_slice() {
        return Err("verify_token_mismatch".into());
    }
    if resp.installation.as_ref() != Some(expected) {
        return Err("profile_mismatch".into());
    }
    let now =
        crate::time_util::unix_now_secs_checked("claim.verify.clock").ok_or("clock_unavailable")?;
    if resp.expires_at <= now {
        return Err("invitation_expired".into());
    }
    let iphone_apns_token = resp
        .iphone_apns_token
        .map(|t| <[u8; 32]>::try_from(t.as_ref()))
        .transpose()
        .map_err(|_| "invalid_apns_token")?;
    Ok(VerifiedInvitation {
        expires_at: resp.expires_at,
        owner_display_name: resp.owner_display_name.unwrap_or_default(),
        iphone_apns_token,
        lan_address,
    })
}

// ── Persistence ───────────────────────────────────────────────────────────────

/// The persisted form of a claimed setup invitation.
///
/// Written atomically to `household/pending/setup_invitation.cbor` by the claim
/// handler. Read by `POST /bootstrap/initialize` to enforce the Tailnet IP guard.
#[derive(Serialize, Deserialize, Clone)]
pub struct PersistedSetupInvitation {
    #[serde(rename = "v")]
    pub version: u8,
    pub token: ByteBuf,
    pub iphone_endpoint: String,
    /// Serialized IP addresses (one per element, as strings).
    pub iphone_addrs: Vec<String>,
    pub owner_display_name: String,
    pub hh_id: Option<String>,
    pub expires_at: u64,
    /// Optional APNs device token (32 bytes). `None` → Bonjour-only flow.
    pub iphone_apns_token: Option<ByteBuf>,
    #[serde(default)]
    pub installation: Option<PairingInstallation>,
    #[serde(default)]
    pub accepted_at: Option<u64>,
    #[serde(default)]
    pub verified_lan_address: Option<IpAddr>,
}

impl std::fmt::Debug for PersistedSetupInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive destructure: adding a field without updating this impl is a compile error.
        let Self {
            version,
            token: _,
            iphone_endpoint,
            iphone_addrs,
            owner_display_name,
            hh_id,
            expires_at,
            iphone_apns_token,
            installation,
            accepted_at,
            verified_lan_address,
        } = self;
        f.debug_struct("PersistedSetupInvitation")
            .field("version", version)
            .field("installation", installation)
            .field("accepted_at", accepted_at)
            .field("verified_lan_address", verified_lan_address)
            .field("token", &"[REDACTED]")
            .field("iphone_endpoint", iphone_endpoint)
            .field("iphone_addrs", iphone_addrs)
            .field("owner_display_name", owner_display_name)
            .field("hh_id", hh_id)
            .field("expires_at", expires_at)
            .field(
                "iphone_apns_token",
                &iphone_apns_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[must_use]
pub fn pending_invitation_path(state_dir: &Path) -> PathBuf {
    state_dir
        .join("household")
        .join("pending")
        .join("setup_invitation.cbor")
}

/// Atomically write the claimed invitation to disk. Creates the parent directory
/// if needed.
pub fn persist_invitation(
    state_dir: &Path,
    entry: &SetupInvitationEntry,
    iphone_apns_token: Option<[u8; 32]>,
) -> Result<(), household_rs::StorageError> {
    persist_verified_invitation(state_dir, entry, iphone_apns_token, None, None, None)
}

pub fn persist_verified_invitation(
    state_dir: &Path,
    entry: &SetupInvitationEntry,
    iphone_apns_token: Option<[u8; 32]>,
    installation: Option<PairingInstallation>,
    accepted_at: Option<u64>,
    verified_lan_address: Option<IpAddr>,
) -> Result<(), household_rs::StorageError> {
    let path = pending_invitation_path(state_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| household_rs::StorageError::Io {
            path: parent.to_path_buf(),
            kind: e.kind().to_string(),
            hint: "creating household/pending".into(),
        })?;
    }
    let persisted = PersistedSetupInvitation {
        version: 1,
        token: ByteBuf::from(entry.token.to_vec()),
        iphone_endpoint: entry.iphone_endpoint.clone(),
        iphone_addrs: entry
            .iphone_addrs
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        owner_display_name: entry.owner_display_name.clone(),
        hh_id: entry.hh_id.clone(),
        expires_at: entry.expires_at,
        iphone_apns_token: iphone_apns_token.map(|t| ByteBuf::from(t.to_vec())),
        installation,
        accepted_at,
        verified_lan_address,
    };
    household_rs::storage::atomic_write_cbor(&path, &persisted)
}

/// Load the persisted invitation from disk, if present.
pub fn load_persisted_invitation(
    state_dir: &Path,
) -> Result<Option<PersistedSetupInvitation>, household_rs::StorageError> {
    let path = pending_invitation_path(state_dir);
    household_rs::storage::read_optional_cbor(&path)
}

/// Convert a claimed, persisted invitation back into the runtime entry shape
/// used by the accept-household path.
#[must_use]
pub fn persisted_invitation_entry(
    invitation: &PersistedSetupInvitation,
) -> Option<SetupInvitationEntry> {
    let token = <[u8; 32]>::try_from(invitation.token.as_ref()).ok()?;
    let iphone_addrs = invitation
        .iphone_addrs
        .iter()
        .filter_map(|addr| addr.parse::<IpAddr>().ok())
        .collect();
    Some(SetupInvitationEntry {
        token,
        iphone_endpoint: invitation.iphone_endpoint.clone(),
        iphone_addrs,
        owner_display_name: invitation.owner_display_name.clone(),
        hh_id: invitation.hh_id.clone(),
        expires_at: invitation.expires_at,
    })
}

/// Remove the persisted invitation (called after initialize completes or teardown).
pub fn clear_persisted_invitation(state_dir: &Path) {
    let path = pending_invitation_path(state_dir);
    let _ = std::fs::remove_file(path);
}

/// The local Mac may initialize manually without an invitation token. Remote
/// callers must prove the exact live invitation even if their source matches.
pub fn validate_initialize_claim(
    invitation: &PersistedSetupInvitation,
    source: Option<IpAddr>,
    token: Option<&[u8]>,
    now: u64,
) -> Result<(), &'static str> {
    if source.is_some_and(|ip| ip.is_loopback()) && token.is_none() {
        return Ok(());
    }
    if source.is_none() {
        return Err("missing_source");
    }
    if invitation.expires_at <= now {
        return Err("invitation_expired");
    }
    if token != Some(invitation.token.as_ref()) {
        return Err("claim_token_mismatch");
    }
    Ok(())
}

/// Validate that `src_ip` may run `POST /initialize` while an invitation is
/// pending: this Mac itself (loopback), or the invited iPhone's tailnet
/// address.
///
/// For `.local` mDNS hostnames, attempts a non-blocking live DNS resolution
/// (via `tokio::net::lookup_host`, 3 s timeout) first. Falls back to the
/// cached `iphone_addrs` from claim time if resolution fails or times out.
/// Non-.local hostnames skip live resolution entirely (rejects attacker-controlled
/// external hostnames that could trigger slow or hostile DNS).
pub async fn validate_initialize_source(
    invitation: &PersistedSetupInvitation,
    src_ip: IpAddr,
) -> Result<(), &'static str> {
    // Loopback is this Mac talking to its own engine, and it is always
    // allowed.
    //
    // MEASURED on the owner's Dev Mac 2026-09-05, with an iPhone nearby
    // looking for it:
    //
    //     WARN bootstrap.initialize.rejected reason="not_tailnet" src_ip="::1"
    //
    // The setup screen said "I could not create your home. Turn on Tailscale
    // to add machines to this home." — while the person was sitting at the Mac
    // naming their home, and the Mac's own Tailscale was up. Nothing they
    // could do would fix it: the guard wanted a TAILNET address from the
    // caller, and the caller was the Mac's own setup window on `::1`. With the
    // iPhone's Tailscale off, no address would ever have satisfied it, so
    // first setup was simply impossible.
    //
    // This guard exists to stop a STRANGER on the network from riding a
    // pending invitation to initialize the household. A process on this
    // machine is not that stranger: it already runs as the person who owns the
    // Mac, and the admin API it is talking to is bound to loopback.
    if src_ip.is_loopback() {
        return Ok(());
    }
    // Explicit LAN pairing policy: only the literal endpoint that answered
    // this profile's token challenge can initialize over LAN. The initialize
    // handler separately checks the claim token and invitation expiry.
    if invitation.installation.is_some() && invitation.verified_lan_address == Some(src_ip) {
        return Ok(());
    }
    if classify_source(src_ip) != DiscoverySource::Tailnet {
        return Err("not_tailnet");
    }

    // Only attempt live resolution for mDNS .local hostnames — never for
    // arbitrary external hosts that an attacker could embed in the endpoint field.
    let live_match = if let Some((host, port_str)) = invitation.iphone_endpoint.rsplit_once(':') {
        let host = host.trim_end_matches('.');
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        if host.ends_with(".local") {
            if let Ok(port) = port_str.parse::<u16>() {
                let endpoint = format!("{host}:{port}");
                let lookup = tokio::net::lookup_host(endpoint);
                match tokio::time::timeout(std::time::Duration::from_secs(3), lookup).await {
                    Ok(Ok(mut addrs)) => addrs.any(|sa| sa.ip() == src_ip),
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    if live_match {
        return Ok(());
    }

    // Fall back to cached addresses recorded at claim time.
    let cached_match = invitation
        .iphone_addrs
        .iter()
        .any(|addr_str| addr_str.parse::<IpAddr>().ok().as_ref() == Some(&src_ip));
    if !cached_match {
        return Err("source_ip_mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_candidates_cannot_target_other_services_or_redirects() {
        for endpoint in [
            "http://127.0.0.1:8091",
            "http://user:pass@192.168.1.20:8123",
            "http://192.168.1.20:8123/other",
            "http://192.168.1.20:8123?token=secret",
            "https://192.168.1.20:8123",
            "http://example.invalid:8123",
            "http://0.0.0.0:8123",
        ] {
            assert!(callback_url(endpoint).is_err(), "{endpoint}");
        }
        let (url, lan) = callback_url("http://192.168.1.20:8123").unwrap();
        assert_eq!(url.path(), "/setup/verify");
        assert_eq!(lan, Some("192.168.1.20".parse().unwrap()));
        assert!(callback_url("100.64.0.10:8123").unwrap().1.is_none());
    }

    #[test]
    fn callback_requires_token_profile_and_live_invitation_together() {
        let dev = PairingInstallation::new("dev".into(), 8101).unwrap();
        let release = PairingInstallation::new("release".into(), 8091).unwrap();
        let token = [42; 32];
        let mut response = VerifyResp {
            version: 1,
            token: ByteBuf::from(token.to_vec()),
            installation: Some(dev.clone()),
            expires_at: 2_524_608_000,
            owner_display_name: Some("Owner".into()),
            iphone_apns_token: None,
        };
        let encode =
            |response: &VerifyResp| household_rs::cbor::to_canonical_vec(response).unwrap();
        assert!(decode_verified_invitation(&encode(&response), &token, &dev, None).is_ok());
        assert!(decode_verified_invitation(&encode(&response), &[43; 32], &dev, None).is_err());
        assert!(decode_verified_invitation(&encode(&response), &token, &release, None).is_err());
        response.installation = None;
        assert!(decode_verified_invitation(&encode(&response), &token, &dev, None).is_err());
        response.installation = Some(dev.clone());
        response.expires_at = 1;
        assert!(decode_verified_invitation(&encode(&response), &token, &dev, None).is_err());
    }

    #[test]
    fn remote_initialize_requires_the_live_claim_token() {
        let invitation = pending_invitation(vec![]);
        let peer = Some("192.168.1.20".parse().unwrap());
        assert!(validate_initialize_claim(&invitation, peer, None, 1).is_err());
        assert!(validate_initialize_claim(&invitation, peer, Some(&[8; 32]), 1).is_err());
        assert!(validate_initialize_claim(&invitation, peer, Some(&[7; 32]), 1).is_ok());
        assert!(
            validate_initialize_claim(&invitation, peer, Some(&[7; 32]), invitation.expires_at)
                .is_err()
        );
        assert!(validate_initialize_claim(&invitation, None, Some(&[7; 32]), 1).is_err());
        assert!(
            validate_initialize_claim(&invitation, Some("::1".parse().unwrap()), None, 1).is_ok()
        );
    }

    #[tokio::test]
    async fn lan_admission_is_limited_to_the_profile_verified_callback_address() {
        let mut invitation = pending_invitation(vec!["192.168.1.20".into(), "192.168.1.21".into()]);
        let source = "192.168.1.20".parse().unwrap();
        assert!(
            validate_initialize_source(&invitation, source)
                .await
                .is_err()
        );
        invitation.installation = PairingInstallation::new("dev".into(), 8101);
        invitation.verified_lan_address = Some(source);
        assert!(
            validate_initialize_source(&invitation, source)
                .await
                .is_ok()
        );
        assert!(
            validate_initialize_source(&invitation, "192.168.1.21".parse().unwrap())
                .await
                .is_err()
        );
        invitation.installation = None;
        assert!(
            validate_initialize_source(&invitation, source)
                .await
                .is_err()
        );
    }

    fn setup_txt(token: [u8; 32]) -> HashMap<String, String> {
        HashMap::from([
            ("v".to_string(), "1".to_string()),
            ("token".to_string(), B64URL.encode(token)),
            ("owner_display_name".to_string(), "Owner".to_string()),
            ("hh_id".to_string(), String::new()),
            ("created_at".to_string(), "1746921600".to_string()),
            ("expires_at".to_string(), "2524608000".to_string()),
            ("port".to_string(), "8123".to_string()),
        ])
    }

    fn pending_invitation(iphone_addrs: Vec<String>) -> PersistedSetupInvitation {
        PersistedSetupInvitation {
            version: 1,
            token: ByteBuf::from(vec![7u8; 32]),
            // Deliberately not `.local`, so no live DNS resolution is attempted
            // and the test measures the guard rather than the network.
            iphone_endpoint: "iphone.example.invalid:8123".to_string(),
            iphone_addrs,
            owner_display_name: "Owner".to_string(),
            hh_id: None,
            expires_at: 2_524_608_000,
            iphone_apns_token: None,
            installation: None,
            accepted_at: None,
            verified_lan_address: None,
        }
    }

    /// First setup used to be impossible whenever an iPhone was nearby.
    ///
    /// MEASURED on the owner's Dev Mac 2026-09-05, with the phone looking for
    /// it: `bootstrap.initialize.rejected reason="not_tailnet" src_ip="::1"`,
    /// and the setup window said "I could not create your home. Turn on
    /// Tailscale". The caller was the Mac's OWN setup screen on loopback, and
    /// with the phone's Tailscale off no address could ever have satisfied the
    /// guard.
    #[tokio::test]
    async fn this_mac_can_always_initialize_its_own_household() {
        let invitation = pending_invitation(vec!["192.168.15.14".to_string()]);
        for loopback in ["127.0.0.1", "::1"] {
            validate_initialize_source(&invitation, loopback.parse().unwrap())
                .await
                .unwrap_or_else(|reason| {
                    panic!("{loopback} must be allowed to initialize, got {reason}")
                });
        }
    }

    /// The guard still does its job: a stranger on the Wi-Fi cannot ride a
    /// pending invitation to initialize the household.
    #[tokio::test]
    async fn a_local_network_peer_still_cannot_initialize() {
        let invitation = pending_invitation(vec!["192.168.15.14".to_string()]);
        assert_eq!(
            validate_initialize_source(&invitation, "192.168.15.99".parse().unwrap()).await,
            Err("not_tailnet")
        );
        // Not even the invited phone's own LAN address: this route is the
        // tailnet one, and loopback is the exception it now names.
        assert_eq!(
            validate_initialize_source(&invitation, "192.168.15.14".parse().unwrap()).await,
            Err("not_tailnet")
        );
    }

    /// And a tailnet address that is not the invited phone's is still refused.
    #[tokio::test]
    async fn another_tailnet_peer_is_still_refused() {
        let invitation = pending_invitation(vec!["100.64.10.5".to_string()]);
        assert_eq!(
            validate_initialize_source(&invitation, "100.64.10.9".parse().unwrap()).await,
            Err("source_ip_mismatch")
        );
        validate_initialize_source(&invitation, "100.64.10.5".parse().unwrap())
            .await
            .expect("the invited phone's tailnet address still passes");
    }

    #[tokio::test]
    async fn setup_txt_is_cached_by_token() {
        let cache = new_cache();
        let token = [7u8; 32];
        let txt = setup_txt(token);
        let addrs = vec!["100.64.10.5".parse().unwrap()];

        let inserted = cache_setup_txt(
            &cache,
            "iphone-soyeht-setup-a1b2c3.local.",
            8123,
            addrs.clone(),
            &|key| txt.get(key).cloned(),
        )
        .await
        .expect("valid setup TXT should cache");

        assert_eq!(inserted.token, token);
        assert_eq!(
            inserted.iphone_endpoint,
            "iphone-soyeht-setup-a1b2c3.local.:8123"
        );
        assert_eq!(inserted.iphone_addrs, addrs);
        assert_eq!(inserted.owner_display_name, "Owner");
        assert!(inserted.hh_id.is_none());

        let cached = cache_lookup(&cache, &token)
            .await
            .expect("entry should be keyed by token");
        assert_eq!(cached.iphone_endpoint, inserted.iphone_endpoint);
    }

    #[tokio::test]
    async fn malformed_setup_txt_is_not_cached() {
        let cache = new_cache();
        let mut txt = setup_txt([9u8; 32]);
        txt.remove("token");

        let inserted = cache_setup_txt(
            &cache,
            "iphone.local.",
            8123,
            vec!["100.64.10.5".parse().unwrap()],
            &|key| txt.get(key).cloned(),
        )
        .await;

        assert!(inserted.is_none());
        assert!(cache.lock().await.is_empty());
    }
}
