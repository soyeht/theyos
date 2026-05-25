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

#[derive(Deserialize)]
struct VerifyResp {
    #[serde(rename = "v")]
    #[allow(dead_code)]
    version: u8,
    token: ByteBuf,
}

/// POST to the iPhone's `/setup/verify` endpoint to confirm the token is still
/// valid. Returns `Ok(())` on success (iPhone echoes the same token back).
///
/// Runs synchronously — callers must use `spawn_blocking` if calling from async.
pub fn callback_verify_blocking(iphone_endpoint: &str, token: &[u8; 32]) -> Result<(), String> {
    let url = format!("http://{iphone_endpoint}/setup/verify");
    let token_buf = ByteBuf::from(token.to_vec());
    let req_body = household_rs::cbor::to_canonical_vec(&VerifyReq {
        version: 1,
        token: &token_buf,
    })
    .map_err(|e| format!("cbor encode: {e}"))?;

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build();
    let response = agent
        .post(&url)
        .set("Content-Type", "application/cbor")
        .send_bytes(&req_body)
        .map_err(|e| format!("POST {url}: {e}"))?;

    if response.status() != 200 {
        return Err(format!("iPhone verify returned HTTP {}", response.status()));
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read body: {e}"))?;
    let resp: VerifyResp = household_rs::cbor::from_canonical_slice(&bytes)
        .map_err(|e| format!("cbor decode: {e}"))?;
    if resp.token.as_ref() != token.as_slice() {
        return Err("token echoed by iPhone does not match".into());
    }
    Ok(())
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
        } = self;
        f.debug_struct("PersistedSetupInvitation")
            .field("version", version)
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

/// Validate that `src_ip` is a permitted Tailnet source for `POST /initialize`
/// given a persisted invitation.
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
