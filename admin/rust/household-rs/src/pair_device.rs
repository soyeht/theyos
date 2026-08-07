//! Owner-device pairing window state machine (FR-018).
//!
//! At install end (and on `--reissue-pair-qr`) the bootstrap mints a fresh
//! [`PairToken`] and parks it in a [`PairDeviceWindow`]. The HTTP layer
//! (`server-rs/src/handlers_pair_device.rs`) gates `/pair-device/*` routes on
//! window presence:
//!
//! - When the window is open, `/pair-device/initiate` and `/pair-device/confirm`
//!   are mounted and reachable.
//! - When the window is empty (no token, or the token's TTL elapsed, or the
//!   token was consumed), both routes MUST return **404 Not Found** —
//!   route-absent semantics, never `403`.
//!
//! Token consumption auto-closes the window. TTL expiry auto-closes the
//! window. The window also exposes a `subscribe()` channel so
//! `bonjour_publisher.rs` can flip Bonjour TXT records (`pairing=open` /
//! `pair_nonce=…`) in real time.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use subtle::ConstantTimeEq;
use tokio::sync::{RwLock, broadcast};

use crate::household_lifecycle::{HouseholdLifecycleGenerationV1, LifecycleWriteGuard};
use crate::keys::P256PublicKey;
use crate::machine_cert::PersonId;
use crate::pair_window_namespace::PairWindowNamespaceV2;

const PAIR_DEVICE_SNAPSHOT_VERSION: u8 = 2;

/// Hard ceiling on a single pair-window TTL. Prevents a tampered on-disk
/// snapshot from spawning an unbounded TTL cleanup task; callers passing a
/// larger TTL than this are clamped silently.
const MAX_PAIR_DEVICE_WINDOW_TTL_SECS: u64 = 600;

/// 32-byte random nonce; URL-safe base64 in the wire URI.
#[derive(Clone, Debug)]
pub struct PairNonce(pub [u8; 32]);

impl PairNonce {
    #[must_use]
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// URL-safe, no-padding base64 — pairs cleanly with the URI param.
    #[must_use]
    pub fn as_b64(&self) -> String {
        B64.encode(self.0)
    }

    /// Parse from URL-safe base64 (no padding) string.
    pub fn from_b64(s: &str) -> Result<Self, String> {
        let bytes = B64
            .decode(s)
            .map_err(|e| format!("nonce base64 decode: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("expected 32-byte nonce, got {}", bytes.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    /// Short-form (8 chars) base64 for Bonjour TXT records.
    #[must_use]
    pub fn as_short_b64(&self) -> String {
        let full = self.as_b64();
        full[..full.len().min(8)].to_string()
    }
}

/// Owner-device pairing token.
#[derive(Clone, Debug)]
pub struct PairToken {
    pub nonce: PairNonce,
    pub expires_at: Instant,
    pub expires_at_unix: u64,
    pub p_id_hint: Option<PersonId>,
}

impl PairToken {
    /// Mint a fresh token with the given TTL.
    pub fn mint(ttl: Duration, p_id_hint: Option<PersonId>) -> Result<Self, String> {
        let now = Instant::now();
        let now_unix = unix_now_secs()?;
        let expires_at = now
            .checked_add(ttl)
            .ok_or_else(|| "pair-window monotonic expiry overflow".to_string())?;
        let expires_at_unix = now_unix
            .checked_add(ttl.as_secs())
            .ok_or_else(|| "pair-window unix expiry overflow".to_string())?;
        Ok(Self {
            nonce: PairNonce::random(),
            expires_at,
            expires_at_unix,
            p_id_hint,
        })
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Persist the token to disk so the next process (e.g. the daemon
    /// started by launchd after `theyos install` exits) can pick it up.
    #[must_use]
    pub fn to_snapshot(
        &self,
        generation: HouseholdLifecycleGenerationV1,
    ) -> PairDeviceWindowSnapshot {
        PairDeviceWindowSnapshot {
            version: PAIR_DEVICE_SNAPSHOT_VERSION,
            nonce_b64: self.nonce.as_b64(),
            expires_at_unix: self.expires_at_unix,
            p_id_hint: self.p_id_hint.as_ref().map(|p| p.0.clone()),
            lifecycle_generation: ByteBuf::from(generation.token_bytes().to_vec()),
        }
    }

    /// Reconstruct a `PairToken` from a persisted snapshot. Returns `None` if
    /// the snapshot has already expired (per the unix timestamp), avoiding
    /// the cost of installing a stale token into a `PairDeviceWindow`.
    ///
    /// Remaining TTL is clamped to [`MAX_PAIR_DEVICE_WINDOW_TTL_SECS`] so that a
    /// tampered snapshot with a far-future `expires_at_unix` cannot spawn an
    /// unbounded sleep task.
    pub fn from_snapshot(snap: &PairDeviceWindowSnapshot) -> Result<Option<Self>, String> {
        if snap.version != PAIR_DEVICE_SNAPSHOT_VERSION || snap.lifecycle_generation.len() != 32 {
            return Err(format!(
                "unsupported pair window snapshot version: {}",
                snap.version
            ));
        }
        let nonce = PairNonce::from_b64(&snap.nonce_b64)?;
        let now_unix = unix_now_secs()?;
        if now_unix >= snap.expires_at_unix {
            return Ok(None);
        }
        let raw_remaining = snap.expires_at_unix - now_unix;
        let remaining_secs = raw_remaining.min(MAX_PAIR_DEVICE_WINDOW_TTL_SECS);
        let remaining = Duration::from_secs(remaining_secs);
        let expires_at = Instant::now()
            .checked_add(remaining)
            .ok_or_else(|| "pair-window monotonic expiry overflow".to_string())?;
        // If we clamped, also clamp the unix-seconds field so callers don't
        // see a contradiction between `expires_at` (Instant) and
        // `expires_at_unix` (wall-clock).
        let expires_at_unix = if raw_remaining == remaining_secs {
            snap.expires_at_unix
        } else {
            now_unix + remaining_secs
        };
        let p_id_hint = snap.p_id_hint.as_ref().map(|s| PersonId(s.clone()));
        Ok(Some(Self {
            nonce,
            expires_at,
            expires_at_unix,
            p_id_hint,
        }))
    }

    /// Render the canonical `soyeht://household/pair-device?…` URI.
    ///
    /// The install-time variant carries `hh_pub` (the household's 33-byte
    /// SEC1 public key, base64url-encoded) so the scanning device can verify
    /// the household identity before generating its own keypair and posting
    /// to `/pair-device/confirm`. `ttl` is the unix-seconds expiry timestamp.
    ///
    /// The optional `host` argument is included as `&host=<ip-or-hostname>:<port>`
    /// when the engine knows a reachable endpoint at QR-render time (the
    /// Tailnet IPv4 + bound port). This is a fallback for peers whose Bonjour
    /// implementation does not interoperate with macOS/iOS `NWBrowser`
    /// (observed on Linux's `mdns-sd` 0.10/0.13 crates which fail to emit
    /// announcement records). When `host` is present the scanning device
    /// MAY skip Bonjour browse and connect directly; when absent the device
    /// MUST discover via Bonjour as before. The field is non-critical so
    /// older scanners ignore it without error.
    /// `m_cert_fp` is the SHA-256 of the canonical CBOR encoding of **this
    /// machine's admitted `MachineCert`** — the same value the roster wire
    /// already carries as `machine_cert_fingerprint`, not a second definition.
    /// It is announced as critical (`crit=m_cert_fp`) so a scanner that does
    /// not understand it refuses the QR rather than pairing unpinned.
    ///
    /// It is a required argument on every entry point, so a producer that
    /// cannot name an admitted cert fails to compile rather than silently
    /// emitting an unpinned QR.
    #[must_use]
    pub fn to_uri(&self, hh_pub: &P256PublicKey, m_cert_fp: &[u8; 32]) -> String {
        self.to_uri_with_host(hh_pub, None, m_cert_fp)
    }

    /// As [`Self::to_uri`] but also includes a `host=<addr>:<port>` fallback
    /// query parameter when `host` is `Some`. See [`Self::to_uri`] for the
    /// rationale.
    #[must_use]
    pub fn to_uri_with_host(
        &self,
        hh_pub: &P256PublicKey,
        host: Option<&str>,
        m_cert_fp: &[u8; 32],
    ) -> String {
        self.to_uri_with_host_and_name(hh_pub, host, None, m_cert_fp)
    }

    /// As [`Self::to_uri_with_host`] but also includes the household display
    /// name for scanners that skip Bonjour and therefore cannot learn `hh_name`
    /// from service TXT records.
    #[must_use]
    pub fn to_uri_with_host_and_name(
        &self,
        hh_pub: &P256PublicKey,
        host: Option<&str>,
        household_name: Option<&str>,
        m_cert_fp: &[u8; 32],
    ) -> String {
        let mut uri = String::from("soyeht://household/pair-device");
        uri.push_str("?v=1");
        uri.push_str("&hh_pub=");
        uri.push_str(&B64.encode(hh_pub.as_bytes()));
        uri.push_str("&nonce=");
        uri.push_str(&self.nonce.as_b64());
        uri.push_str("&ttl=");
        uri.push_str(&self.expires_at_unix.to_string());
        // `B64` is URL_SAFE_NO_PAD, which is what the client re-encodes with;
        // a padded or otherwise non-canonical form still decodes to the right
        // 32 bytes but fails its `reencoded == fpValue` check.
        uri.push_str("&m_cert_fp=");
        uri.push_str(&B64.encode(m_cert_fp));
        // Exactly one `crit`, whose value is exactly this field name. The
        // client compares the whole value, so a comma list is not accepted.
        uri.push_str("&crit=m_cert_fp");
        if let Some(p) = &self.p_id_hint {
            uri.push_str("&p_id=");
            uri.push_str(&p.0);
        }
        if let Some(h) = host {
            uri.push_str("&host=");
            uri.push_str(&percent_encode_query_value(h));
        }
        if let Some(name) = household_name {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                uri.push_str("&house_name=");
                uri.push_str(&percent_encode_query_value(trimmed));
            }
        }
        uri
    }
}

fn percent_encode_query_value(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for b in value.as_bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b':' => {
                out.push(*b as char);
            }
            _ => {
                // write! into String is infallible, so swallowing the Result
                // matches the previous push_str(&format!(...)) semantics.
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn unix_now_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock before unix epoch: {e}"))
}

/// Snapshot of [`PairDeviceWindow`] state for the Bonjour publisher.
#[derive(Clone, Debug)]
pub enum PairDeviceWindowState {
    Closed,
    Open { short_nonce: String },
}

/// On-disk representation of an active pairing window. Written by
/// `theyos install` (and `--reissue-pair-qr`) so the long-running daemon
/// process picks up the token at startup. Removed on consume / expiry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairDeviceWindowSnapshot {
    pub version: u8,
    pub nonce_b64: String,
    pub expires_at_unix: u64,
    pub p_id_hint: Option<String>,
    /// Required fixed-width lifecycle witness. Version-1 snapshots lacked it
    /// and are deliberately never adopted.
    #[serde(with = "serde_bytes")]
    pub lifecycle_generation: ByteBuf,
}

/// Shared, mutable pair-receiving window.
///
/// Cloning a `PairDeviceWindow` shares state (it's an `Arc`-backed handle).
#[derive(Clone)]
pub struct PairDeviceWindow {
    inner: Arc<PairDeviceWindowInner>,
}

struct PairDeviceWindowInner {
    state: RwLock<Option<PairToken>>,
    notifier: broadcast::Sender<PairDeviceWindowState>,
    /// Retained generation capability used by every write/delete/TTL callback.
    namespace: Option<PairWindowNamespaceV2>,
}

impl PairDeviceWindow {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel::<PairDeviceWindowState>(8);
        Self {
            inner: Arc::new(PairDeviceWindowInner {
                state: RwLock::new(None),
                notifier: tx,
                namespace: None,
            }),
        }
    }

    /// Persistent variant for a standalone synchronous construction site.
    /// This may block up to the lifecycle lock deadline.
    pub fn with_persistence(
        state_dir: std::path::PathBuf,
    ) -> Result<Self, crate::error::StorageError> {
        let namespace = PairWindowNamespaceV2::current(state_dir)?;
        Ok(Self::with_namespace(namespace))
    }

    /// Construct without reacquiring a lifecycle lock already held by caller.
    pub fn with_persistence_under_lifecycle(
        state_dir: std::path::PathBuf,
        lifecycle: &LifecycleWriteGuard,
    ) -> Result<Self, crate::error::StorageError> {
        let namespace = PairWindowNamespaceV2::current_under_lifecycle(state_dir, lifecycle)?;
        Ok(Self::with_namespace(namespace))
    }

    /// Construct from an explicit generation capability.
    #[must_use]
    pub fn with_namespace(namespace: PairWindowNamespaceV2) -> Self {
        let (tx, _) = broadcast::channel::<PairDeviceWindowState>(8);
        Self {
            inner: Arc::new(PairDeviceWindowInner {
                state: RwLock::new(None),
                notifier: tx,
                namespace: Some(namespace),
            }),
        }
    }

    /// Subscribe to state changes (used by `bonjour_publisher.rs`).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<PairDeviceWindowState> {
        self.inner.notifier.subscribe()
    }

    /// Mint a fresh token and replace any existing token. Returns the new
    /// token (caller renders the URI via [`PairToken::to_uri`]).
    ///
    /// When `state_dir` is configured (see [`Self::with_persistence`]) the
    /// new token is also persisted in the current generation-scoped
    /// [`PairWindowNamespaceV2`] so a daemon restart picks up the live token
    /// without adopting an unscoped legacy snapshot.
    pub async fn mint_token(
        &self,
        ttl: Duration,
        p_id_hint: Option<PersonId>,
    ) -> Result<PairToken, String> {
        let token = PairToken::mint(ttl, p_id_hint)?;
        let mut guard = self.inner.state.write().await;
        let short = self.publish_locked(&mut guard, token.clone(), None)?;
        drop(guard);
        let _ = self
            .inner
            .notifier
            .send(PairDeviceWindowState::Open { short_nonce: short });
        self.spawn_ttl_cleanup(ttl);
        Ok(token)
    }

    /// Mint while reusing a lifecycle-exclusive guard held by the caller.
    pub async fn mint_token_under_lifecycle(
        &self,
        ttl: Duration,
        p_id_hint: Option<PersonId>,
        lifecycle: &LifecycleWriteGuard,
    ) -> Result<PairToken, String> {
        let token = PairToken::mint(ttl, p_id_hint)?;
        let mut guard = self.inner.state.write().await;
        let short = self.publish_locked(&mut guard, token.clone(), Some(lifecycle))?;
        drop(guard);
        let _ = self
            .inner
            .notifier
            .send(PairDeviceWindowState::Open { short_nonce: short });
        self.spawn_ttl_cleanup(ttl);
        Ok(token)
    }

    /// Publish `token` as the live window **and** persist its snapshot without
    /// releasing the caller's write guard in between. Returns the short nonce
    /// so the caller can broadcast after dropping the guard.
    ///
    /// Splitting these two writes is the bug this exists to prevent.
    /// [`Self::install_token_from_current_snapshot`] takes this same lock and
    /// then decides by re-reading the file, so any window in which memory has
    /// moved on while the file has not lets the snapshot watcher acquire the
    /// lock, find the file it expects, and reinstall the token that file
    /// names — leaving memory holding one nonce while the caller returns
    /// another. Under one guard the watcher can only ever re-read a file that
    /// already agrees with memory.
    ///
    /// Notify and TTL-cleanup deliberately stay *outside*: neither reads the
    /// snapshot, and `spawn_ttl_cleanup` takes the lock itself.
    fn publish_locked(
        &self,
        guard: &mut tokio::sync::RwLockWriteGuard<'_, Option<PairToken>>,
        token: PairToken,
        lifecycle: Option<&LifecycleWriteGuard>,
    ) -> Result<String, String> {
        let short = token.nonce.as_short_b64();
        if let Some(namespace) = &self.inner.namespace {
            let snapshot = token.to_snapshot(namespace.generation());
            let result = match lifecycle {
                Some(lifecycle) => {
                    namespace.write_pair_device_under_lifecycle(&snapshot, lifecycle)
                }
                None => namespace.write_pair_device(&snapshot),
            };
            result.map_err(|error| format!("persist pair-device window: {error}"))?;
        }
        **guard = Some(token);
        Ok(short)
    }

    /// Return the live token if one is open, otherwise mint one — atomically.
    ///
    /// [`Self::current_token`] followed by [`Self::mint_token`] is not the
    /// same operation: between the two calls a second caller can mint, and
    /// because `mint_token` *replaces* whatever is present, the first
    /// caller's response then carries a nonce that is already dead. The
    /// check and the mint therefore share a single write lock, exactly as
    /// [`Self::install_token_from_current_snapshot`] does.
    ///
    /// Returns `(token, minted)` so the caller can distinguish "served the
    /// window that was already open" from "opened a new one" in its logs.
    pub async fn get_or_mint(
        &self,
        ttl: Duration,
        p_id_hint: Option<PersonId>,
    ) -> Result<(PairToken, bool), String> {
        let mut guard = self.inner.state.write().await;
        if let Some(live) = guard.as_ref().filter(|t| !t.is_expired()) {
            return Ok((live.clone(), false));
        }
        let token = PairToken::mint(ttl, p_id_hint)?;
        let short = self.publish_locked(&mut guard, token.clone(), None)?;
        drop(guard);
        let _ = self
            .inner
            .notifier
            .send(PairDeviceWindowState::Open { short_nonce: short });
        self.spawn_ttl_cleanup(ttl);
        Ok((token, true))
    }

    /// Get or mint while reusing a lifecycle-exclusive guard.
    pub async fn get_or_mint_under_lifecycle(
        &self,
        ttl: Duration,
        p_id_hint: Option<PersonId>,
        lifecycle: &LifecycleWriteGuard,
    ) -> Result<(PairToken, bool), String> {
        let mut guard = self.inner.state.write().await;
        if let Some(live) = guard.as_ref().filter(|token| !token.is_expired()) {
            return Ok((live.clone(), false));
        }
        let token = PairToken::mint(ttl, p_id_hint)?;
        let short = self.publish_locked(&mut guard, token.clone(), Some(lifecycle))?;
        drop(guard);
        let _ = self
            .inner
            .notifier
            .send(PairDeviceWindowState::Open { short_nonce: short });
        self.spawn_ttl_cleanup(ttl);
        Ok((token, true))
    }

    /// Snapshot of the current open token, if any. Used by
    /// `/pair-device/initiate` (retrieve-only — no mint).
    pub async fn current_token(&self) -> Option<PairToken> {
        let guard = self.inner.state.read().await;
        match guard.as_ref() {
            Some(t) if !t.is_expired() => Some(t.clone()),
            _ => None,
        }
    }

    /// Read the snapshot belonging to this window's retained lifecycle
    /// generation. No raw path escapes to the caller and legacy unscoped
    /// snapshots are never considered.
    pub fn read_persisted_snapshot(&self) -> Result<Option<PairDeviceWindowSnapshot>, String> {
        self.read_persisted_snapshot_inner(None)
    }

    /// Read the generation-scoped snapshot without reacquiring a lifecycle
    /// lock already held exclusively by the caller.
    pub fn read_persisted_snapshot_under_lifecycle(
        &self,
        lifecycle: &LifecycleWriteGuard,
    ) -> Result<Option<PairDeviceWindowSnapshot>, String> {
        self.read_persisted_snapshot_inner(Some(lifecycle))
    }

    fn read_persisted_snapshot_inner(
        &self,
        lifecycle: Option<&LifecycleWriteGuard>,
    ) -> Result<Option<PairDeviceWindowSnapshot>, String> {
        let Some(namespace) = &self.inner.namespace else {
            return Ok(None);
        };
        let snapshot: Option<PairDeviceWindowSnapshot> = match lifecycle {
            Some(lifecycle) => namespace.read_pair_device_under_lifecycle(lifecycle),
            None => namespace.read_pair_device(),
        }
        .map_err(|error| format!("read pair-device window: {error}"))?;
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        if snapshot.version != PAIR_DEVICE_SNAPSHOT_VERSION
            || snapshot.lifecycle_generation.as_ref() != namespace.generation().token_bytes()
        {
            return Err(
                "pair-device snapshot does not match the retained lifecycle generation".to_string(),
            );
        }
        Ok(Some(snapshot))
    }

    /// Install a pre-existing token (e.g. one persisted by a sibling
    /// `theyos install` process). Replaces any existing token; spawns a TTL
    /// cleanup based on the token's remaining lifetime.
    pub async fn install_token(&self, token: PairToken) {
        let remaining = token.expires_at.saturating_duration_since(Instant::now());
        self.replace_with(token, remaining).await;
    }

    /// Install a token decoded from the persisted snapshot only if that exact
    /// snapshot is still on disk. The check runs while holding the same write
    /// lock used by [`Self::consume_token`], so the daemon cannot consume and
    /// delete a token while the snapshot watcher reinstalls it.
    pub async fn install_token_from_current_snapshot(
        &self,
        token: PairToken,
        snapshot: &PairDeviceWindowSnapshot,
    ) -> Result<bool, String> {
        self.install_token_from_snapshot_inner(token, snapshot, None)
            .await
    }

    /// Adopt while reusing a lifecycle-exclusive guard held by the watcher.
    pub async fn install_token_from_current_snapshot_under_lifecycle(
        &self,
        token: PairToken,
        snapshot: &PairDeviceWindowSnapshot,
        lifecycle: &LifecycleWriteGuard,
    ) -> Result<bool, String> {
        self.install_token_from_snapshot_inner(token, snapshot, Some(lifecycle))
            .await
    }

    async fn install_token_from_snapshot_inner(
        &self,
        token: PairToken,
        snapshot: &PairDeviceWindowSnapshot,
        lifecycle: Option<&LifecycleWriteGuard>,
    ) -> Result<bool, String> {
        let remaining = token.expires_at.saturating_duration_since(Instant::now());
        let short = token.nonce.as_short_b64();
        let mut guard = self.inner.state.write().await;
        if guard
            .as_ref()
            .is_some_and(|current| !current.is_expired() && current.nonce.0 == token.nonce.0)
        {
            return Ok(false);
        }
        if let Some(namespace) = &self.inner.namespace {
            if snapshot.lifecycle_generation.as_ref() != namespace.generation().token_bytes() {
                return Ok(false);
            }
            let latest: Option<PairDeviceWindowSnapshot> = match lifecycle {
                Some(lifecycle) => namespace.read_pair_device_under_lifecycle(lifecycle),
                None => namespace.read_pair_device(),
            }
            .map_err(|e| format!("read current pair-window snapshot: {e}"))?;
            if latest.as_ref() != Some(snapshot) {
                return Ok(false);
            }
        }
        *guard = Some(token);
        drop(guard);
        let _ = self
            .inner
            .notifier
            .send(PairDeviceWindowState::Open { short_nonce: short });
        self.spawn_ttl_cleanup(remaining);
        Ok(true)
    }

    async fn replace_with(&self, token: PairToken, ttl: Duration) {
        let short = token.nonce.as_short_b64();
        let mut guard = self.inner.state.write().await;
        *guard = Some(token);
        drop(guard);
        let _ = self
            .inner
            .notifier
            .send(PairDeviceWindowState::Open { short_nonce: short });
        self.spawn_ttl_cleanup(ttl);
    }

    /// Consume the active token if (a) a token is present and (b) the
    /// supplied nonce matches and (c) it has not expired. On success the
    /// window auto-closes (single-use invariant).
    ///
    /// # Panics
    ///
    /// Never panics in normal use. The internal `expect("present")` is
    /// reached only if the `Some(_)` branch's `as_ref()` returns `None`
    /// between match arms, which would indicate a tokio runtime bug.
    pub async fn consume_token(&self, nonce: &PairNonce) -> Result<PairToken, ConsumeError> {
        let mut guard = self.inner.state.write().await;
        match guard.as_ref() {
            None => Err(ConsumeError::NotOpen),
            Some(t) if t.is_expired() => {
                *guard = None;
                let delete = self.delete_persisted();
                drop(guard);
                let _ = self.inner.notifier.send(PairDeviceWindowState::Closed);
                delete.map_err(ConsumeError::Storage)?;
                Err(ConsumeError::Expired)
            }
            Some(t) if !bool::from(t.nonce.0.ct_eq(&nonce.0)) => Err(ConsumeError::WrongNonce),
            Some(_) => {
                let token = guard.take().expect("matched Some(_) above");
                // Authority is closed before the filesystem operation, but
                // the memory lock remains held so a new mint cannot publish a
                // replacement that this older consume would then delete.
                let delete = self.delete_persisted();
                drop(guard);
                let _ = self.inner.notifier.send(PairDeviceWindowState::Closed);
                delete.map_err(ConsumeError::Storage)?;
                Ok(token)
            }
        }
    }

    /// Consume the active token and run `f` while the window write lock is
    /// held. If `f` returns an error the token remains open; if it succeeds
    /// the window is closed and the returned value is yielded to the caller.
    pub async fn consume_token_with<T, E, F>(
        &self,
        nonce: &PairNonce,
        f: F,
    ) -> Result<T, ConsumeWithError<E>>
    where
        F: FnOnce(&PairToken) -> Result<T, E>,
    {
        self.consume_token_with_inner(nonce, f, None).await
    }

    /// Consume while reusing an already-held lifecycle-exclusive guard.
    pub async fn consume_token_with_under_lifecycle<T, E, F>(
        &self,
        nonce: &PairNonce,
        f: F,
        lifecycle: &LifecycleWriteGuard,
    ) -> Result<T, ConsumeWithError<E>>
    where
        F: FnOnce(&PairToken) -> Result<T, E>,
    {
        self.consume_token_with_inner(nonce, f, Some(lifecycle))
            .await
    }

    async fn consume_token_with_inner<T, E, F>(
        &self,
        nonce: &PairNonce,
        f: F,
        lifecycle: Option<&LifecycleWriteGuard>,
    ) -> Result<T, ConsumeWithError<E>>
    where
        F: FnOnce(&PairToken) -> Result<T, E>,
    {
        let mut guard = self.inner.state.write().await;
        let token = match guard.as_ref() {
            None => return Err(ConsumeWithError::Window(ConsumeError::NotOpen)),
            Some(t) if t.is_expired() => {
                *guard = None;
                let delete = self.delete_persisted_with(lifecycle);
                drop(guard);
                let _ = self.inner.notifier.send(PairDeviceWindowState::Closed);
                delete.map_err(|error| ConsumeWithError::Window(ConsumeError::Storage(error)))?;
                return Err(ConsumeWithError::Window(ConsumeError::Expired));
            }
            Some(t) if !bool::from(t.nonce.0.ct_eq(&nonce.0)) => {
                return Err(ConsumeWithError::Window(ConsumeError::WrongNonce));
            }
            Some(t) => t,
        };
        let output = f(token).map_err(ConsumeWithError::Callback)?;
        let _ = guard.take();
        let delete = self.delete_persisted_with(lifecycle);
        drop(guard);
        let _ = self.inner.notifier.send(PairDeviceWindowState::Closed);
        delete.map_err(|error| ConsumeWithError::Window(ConsumeError::Storage(error)))?;
        Ok(output)
    }

    /// Durably delete exactly this window's generation-scoped snapshot.
    fn delete_persisted(&self) -> Result<(), String> {
        self.delete_persisted_with(None)
    }

    fn delete_persisted_with(&self, lifecycle: Option<&LifecycleWriteGuard>) -> Result<(), String> {
        self.inner.namespace.as_ref().map_or(Ok(()), |namespace| {
            match lifecycle {
                Some(lifecycle) => namespace.delete_pair_device_under_lifecycle(lifecycle),
                None => namespace.delete_pair_device(),
            }
            .map_err(|error| error.to_string())
        })
    }

    /// Returns true if a non-expired token is currently parked.
    pub async fn is_open(&self) -> bool {
        let guard = self.inner.state.read().await;
        matches!(guard.as_ref(), Some(t) if !t.is_expired())
    }

    /// Forcibly close the window (for shutdown / `--reissue-pair-qr`).
    pub async fn close(&self) -> Result<(), String> {
        self.close_inner(None).await
    }

    /// Close while reusing an already-held lifecycle-exclusive guard.
    pub async fn close_under_lifecycle(
        &self,
        lifecycle: &LifecycleWriteGuard,
    ) -> Result<(), String> {
        self.close_inner(Some(lifecycle)).await
    }

    async fn close_inner(&self, lifecycle: Option<&LifecycleWriteGuard>) -> Result<(), String> {
        let mut guard = self.inner.state.write().await;
        // Close authority first. A stale generation capability may make the
        // exact-generation delete fail during teardown, but it must never
        // leave an in-memory token usable in that fail-stop window.
        *guard = None;
        let delete = self.delete_persisted_with(lifecycle);
        drop(guard);
        let _ = self.inner.notifier.send(PairDeviceWindowState::Closed);
        delete
    }

    fn spawn_ttl_cleanup(&self, ttl: Duration) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            tokio::time::sleep(ttl).await;
            let mut guard = inner.state.write().await;
            // Only clear if the token currently in the slot is the one whose
            // TTL we were waiting on (an earlier consume or reissue may have
            // already replaced it).
            if let Some(t) = guard.as_ref() {
                if t.is_expired() {
                    // Authority closes before delete. Keep the memory lock
                    // through the exact-generation delete so a concurrent
                    // mint cannot publish a replacement in between.
                    *guard = None;
                    let delete = inner.namespace.as_ref().map_or(Ok(()), |namespace| {
                        namespace
                            .delete_pair_device()
                            .map_err(|error| error.to_string())
                    });
                    drop(guard);
                    let _ = inner.notifier.send(PairDeviceWindowState::Closed);
                    if let Err(error) = delete {
                        tracing::warn!(
                            stage = "pair_device_window.ttl_delete_failed",
                            error = %error,
                        );
                    }
                }
            }
        });
    }
}

impl Default for PairDeviceWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConsumeError {
    #[error("pair window is not open")]
    NotOpen,
    #[error("pair token expired")]
    Expired,
    #[error("nonce does not match the active pair token")]
    WrongNonce,
    #[error("pair-window persistence failed: {0}")]
    Storage(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ConsumeWithError<E> {
    #[error("{0}")]
    Window(#[from] ConsumeError),
    #[error("pair token callback failed")]
    Callback(E),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKey;
    use crate::keys::P256Keypair;

    fn fake_hh_pub() -> P256PublicKey {
        P256Keypair::generate().public()
    }

    /// Stand-in for an admitted machine cert fingerprint in tests that are not
    /// about the fingerprint itself.
    const FAKE_M_CERT_FP: [u8; 32] = [7u8; 32];

    /// Every caller of a freshly-opened window must walk away with the same
    /// token. `current_token()` on a miss followed by `mint_token()` does not
    /// give that: the two calls are separate, `mint_token` replaces whatever
    /// is stored, and both callers then return — leaving one of them holding
    /// a nonce the window no longer has.
    ///
    /// The race is real, not theoretical. The same harness run against the
    /// two-step sequence observes divergence on the first round, every time
    /// (measured 2026-07-31, 5/5 runs); that control is not checked in
    /// because asserting *that a race happens* is inherently flaky. This
    /// direction is deterministic: `get_or_mint` holds one write lock across
    /// the check and the mint, so the answer is always one nonce.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn get_or_mint_hands_every_racing_caller_the_same_token() {
        const RACERS: usize = 64;
        for round in 0..40 {
            let w = PairDeviceWindow::new();
            let barrier = Arc::new(tokio::sync::Barrier::new(RACERS));
            let mut handles = Vec::with_capacity(RACERS);
            for _ in 0..RACERS {
                let w = w.clone();
                let b = Arc::clone(&barrier);
                handles.push(tokio::spawn(async move {
                    b.wait().await;
                    w.get_or_mint(Duration::from_secs(60), None)
                        .await
                        .unwrap()
                        .0
                        .nonce
                        .as_b64()
                }));
            }
            let mut nonces = std::collections::BTreeSet::new();
            for h in handles {
                nonces.insert(h.await.unwrap());
            }
            assert_eq!(
                nonces.len(),
                1,
                "round {round}: {RACERS} racing callers received {} distinct nonces; \
                 all but one of those pairing URIs is already dead",
                nonces.len()
            );
        }
    }

    /// The persistent path has a second racer the 64-caller test above cannot
    /// see, because that one uses a non-persistent window: the snapshot
    /// watcher. It calls [`PairDeviceWindow::install_token_from_current_snapshot`],
    /// which takes the same write lock and then decides by re-reading the
    /// file. So publishing the new token to memory and writing the file
    /// afterwards is not enough — the watcher can take the lock in that gap,
    /// still see the old file, and reinstall the old token, leaving memory and
    /// the URI this call returns naming different nonces.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn get_or_mint_never_returns_a_token_memory_does_not_hold() {
        for round in 0..50 {
            let td = tempfile::tempdir().unwrap();
            let w = PairDeviceWindow::with_persistence(td.path().to_path_buf()).unwrap();

            // A snapshot on disk with nothing in memory: the state a daemon
            // restart leaves behind for the watcher to pick up.
            let stale = PairToken::mint(Duration::from_secs(60), None).unwrap();
            let namespace = w.inner.namespace.as_ref().unwrap();
            let snap = stale.to_snapshot(namespace.generation());
            namespace.write_pair_device(&snap).unwrap();

            let watcher = {
                let w = w.clone();
                tokio::spawn(async move {
                    let _ = w.install_token_from_current_snapshot(stale, &snap).await;
                })
            };
            let (served, _) = w.get_or_mint(Duration::from_secs(60), None).await.unwrap();
            watcher.await.unwrap();

            // Whoever won, memory and the answer must name the same token: if
            // the watcher went first, `get_or_mint` reuses its token; if
            // `get_or_mint` went first, the watcher re-reads a file that
            // already moved on and declines. There is no third outcome.
            let held = w.current_token().await.expect("a window must be open");
            assert_eq!(
                held.nonce.as_b64(),
                served.nonce.as_b64(),
                "round {round}: returned a URI naming a nonce the window does not hold — \
                 the snapshot watcher won the gap between the memory write and the file write"
            );
        }
    }

    /// `mint_token` publishes through the same helper, so it inherits the same
    /// watcher race and is held to the same invariant. Keeping this test
    /// separate rather than parameterising the one above means the pre-existing
    /// caller (`post_pair_device_reissue`) keeps its own teeth.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mint_token_never_returns_a_token_memory_does_not_hold() {
        for round in 0..50 {
            let td = tempfile::tempdir().unwrap();
            let w = PairDeviceWindow::with_persistence(td.path().to_path_buf()).unwrap();
            let stale = PairToken::mint(Duration::from_secs(60), None).unwrap();
            let namespace = w.inner.namespace.as_ref().unwrap();
            let snap = stale.to_snapshot(namespace.generation());
            namespace.write_pair_device(&snap).unwrap();

            let watcher = {
                let w = w.clone();
                tokio::spawn(async move {
                    let _ = w.install_token_from_current_snapshot(stale, &snap).await;
                })
            };
            let minted = w.mint_token(Duration::from_secs(60), None).await.unwrap();
            watcher.await.unwrap();

            let held = w.current_token().await.expect("a window must be open");
            assert_eq!(
                held.nonce.as_b64(),
                minted.nonce.as_b64(),
                "round {round}: mint_token returned a nonce the window does not hold"
            );
        }
    }

    #[tokio::test]
    async fn get_or_mint_reports_whether_it_opened_the_window() {
        let w = PairDeviceWindow::new();
        let (first, minted) = w.get_or_mint(Duration::from_secs(60), None).await.unwrap();
        assert!(minted, "the first call opens the window");
        let (second, minted_again) = w.get_or_mint(Duration::from_secs(60), None).await.unwrap();
        assert!(!minted_again, "the second call must reuse, not re-mint");
        assert_eq!(first.nonce.as_b64(), second.nonce.as_b64());
    }

    #[tokio::test]
    async fn mint_then_consume() {
        let w = PairDeviceWindow::new();
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        let uri = token.to_uri(&fake_hh_pub(), &FAKE_M_CERT_FP);
        assert!(uri.starts_with("soyeht://household/pair-device?"));
        assert!(uri.contains("&hh_pub="));
        assert!(uri.contains("&ttl="));
        assert!(!uri.contains("&exp="));
        assert!(w.is_open().await);

        w.consume_token(&token.nonce).await.unwrap();
        assert!(!w.is_open().await);
    }

    #[tokio::test]
    async fn every_uri_variant_carries_the_critical_machine_cert_fingerprint() {
        // RFC 5737 documentation address — the same one `PairDeviceQR.swift`
        // uses in its frozen examples. No real or tailnet address in fixtures.
        const DOC_HOST: &str = "192.0.2.10:8091";

        let fp: [u8; 32] = [
            0x9a, 0x3f, 0x01, 0xff, 0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
            0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x0f, 0x1e, 0x2d, 0x3c,
        ];
        let w = PairDeviceWindow::new();
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        let hh = fake_hh_pub();

        // Every entry point, not just the widest one: `to_uri` and
        // `to_uri_with_host` delegate today, but a future edit could give one
        // of them its own body and silently drop the critical field.
        assert_ios_pair_device_qr_contract(&token.to_uri(&hh, &fp), &fp);
        assert_ios_pair_device_qr_contract(&token.to_uri_with_host(&hh, Some(DOC_HOST), &fp), &fp);
        assert_ios_pair_device_qr_contract(
            &token.to_uri_with_host_and_name(&hh, Some(DOC_HOST), Some("Home"), &fp),
            &fp,
        );
    }

    #[tokio::test]
    async fn uri_with_host_and_name_percent_encodes_household_name() {
        let w = PairDeviceWindow::new();
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        let uri = token.to_uri_with_host_and_name(
            &fake_hh_pub(),
            Some("100.82.47.115:8091"),
            Some("Sample Home"),
            &FAKE_M_CERT_FP,
        );
        assert!(uri.contains("&host=100.82.47.115:8091"));
        assert!(uri.contains("&house_name=Sample%20Home"));
    }

    /// Reject exactly what `PairDeviceQR.swift` on soyeht-ios rejects.
    ///
    /// Mirrored from the frozen client, not from our own intuition about what
    /// "carries a fingerprint" ought to mean:
    ///
    /// - `m_cert_fp` present exactly once (`duplicateField` otherwise);
    /// - `crit` present exactly once with value **exactly** `m_cert_fp` — the
    ///   client tests `critItems.count == 1 && critItems[0].value ==
    ///   "m_cert_fp"`, so a comma list that merely *contains* it is refused;
    /// - the value decodes as base64url to exactly 32 bytes;
    /// - re-encoding those bytes reproduces the query value byte for byte.
    ///
    /// That last one is the silent-failure class: a non-canonical encoding
    /// still decodes to the right 32 bytes, so every server-side assertion
    /// about "the fingerprint" passes while the device refuses the QR.
    fn assert_ios_pair_device_qr_contract(uri: &str, expected_fp: &[u8; 32]) {
        let query = uri.split_once('?').expect("uri has a query").1;
        let pairs: Vec<(&str, &str)> = query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .collect();

        let fps: Vec<&str> = pairs
            .iter()
            .filter(|(k, _)| *k == "m_cert_fp")
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(fps.len(), 1, "m_cert_fp must appear exactly once in {uri}");

        let crits: Vec<&str> = pairs
            .iter()
            .filter(|(k, _)| *k == "crit")
            .map(|(_, v)| *v)
            .collect();
        assert_eq!(crits.len(), 1, "crit must appear exactly once in {uri}");
        assert_eq!(
            crits[0], "m_cert_fp",
            "crit must be exactly `m_cert_fp`, not a list containing it"
        );

        let decoded = B64
            .decode(fps[0])
            .expect("m_cert_fp must be base64url-decodable");
        assert_eq!(decoded.len(), 32, "m_cert_fp must decode to 32 bytes");
        assert_eq!(
            decoded.as_slice(),
            expected_fp.as_slice(),
            "m_cert_fp must carry the admitted machine cert fingerprint"
        );
        assert_eq!(
            B64.encode(&decoded),
            fps[0],
            "m_cert_fp must be canonical base64url — the client re-encodes and compares"
        );
    }

    #[tokio::test]
    async fn second_consume_returns_not_open() {
        let w = PairDeviceWindow::new();
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        w.consume_token(&token.nonce).await.unwrap();
        match w.consume_token(&token.nonce).await {
            Err(ConsumeError::NotOpen) => {}
            other => panic!("expected NotOpen, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wrong_nonce_rejected() {
        let w = PairDeviceWindow::new();
        let _ = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        let bogus = PairNonce::random();
        match w.consume_token(&bogus).await {
            Err(ConsumeError::WrongNonce) => {}
            other => panic!("expected WrongNonce, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ttl_expiry_closes_window() {
        let w = PairDeviceWindow::new();
        let _ = w.mint_token(Duration::from_millis(50), None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(!w.is_open().await);
    }

    #[tokio::test]
    async fn current_token_returns_active_only() {
        let w = PairDeviceWindow::new();
        assert!(w.current_token().await.is_none());
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        let live = w.current_token().await.expect("active");
        assert_eq!(live.nonce.0, token.nonce.0);
    }

    #[tokio::test]
    async fn from_snapshot_caps_remaining_ttl() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let snap = PairDeviceWindowSnapshot {
            version: PAIR_DEVICE_SNAPSHOT_VERSION,
            nonce_b64: PairNonce::random().as_b64(),
            // Far-future expiry — would be unbounded sleep without clamping.
            expires_at_unix: now + 10_000_000,
            p_id_hint: None,
            lifecycle_generation: ByteBuf::from(vec![0_u8; 32]),
        };
        let token = PairToken::from_snapshot(&snap)
            .expect("decode")
            .expect("not expired");
        assert!(token.expires_at_unix - now <= MAX_PAIR_DEVICE_WINDOW_TTL_SECS);
    }

    #[tokio::test]
    async fn mint_persists_snapshot_when_state_dir_set() {
        let td = tempfile::tempdir().unwrap();
        let w = PairDeviceWindow::with_persistence(td.path().to_path_buf()).unwrap();
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();

        // Persisted snapshot should carry the same nonce.
        let namespace = w.inner.namespace.as_ref().unwrap();
        let path = namespace.pair_device_snapshot_path();
        let snap: PairDeviceWindowSnapshot = namespace.read_pair_device().unwrap().unwrap();
        assert_eq!(snap.nonce_b64, token.nonce.as_b64());

        // Consuming the token must wipe the persisted snapshot.
        w.consume_token(&token.nonce).await.unwrap();
        let stale: Option<PairDeviceWindowSnapshot> =
            crate::storage::read_optional_cbor(&path).unwrap();
        assert!(stale.is_none(), "persisted snapshot leaked after consume");
    }

    #[tokio::test]
    async fn stale_snapshot_token_is_not_reinstalled_after_consume() {
        let td = tempfile::tempdir().unwrap();
        let w = PairDeviceWindow::with_persistence(td.path().to_path_buf()).unwrap();
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        let snap = token.to_snapshot(w.inner.namespace.as_ref().unwrap().generation());

        w.consume_token(&token.nonce).await.unwrap();

        let decoded = PairToken::from_snapshot(&snap)
            .expect("decode")
            .expect("snapshot still unexpired");
        let installed = w
            .install_token_from_current_snapshot(decoded, &snap)
            .await
            .expect("install check");
        assert!(!installed);
        assert!(w.current_token().await.is_none());
    }

    #[tokio::test]
    async fn stale_generation_ttl_cannot_delete_current_generation_window() {
        let td = tempfile::tempdir().unwrap();
        let lifecycle =
            crate::household_lifecycle::HouseholdLifecycleLock::open_verified(td.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let old =
            PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
                .unwrap();
        old.mint_token_under_lifecycle(Duration::from_millis(20), None, &guard)
            .await
            .unwrap();
        guard.rotate_lifecycle_generation().unwrap();
        let current =
            PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
                .unwrap();
        let current_token = current
            .mint_token_under_lifecycle(Duration::from_secs(5), None, &guard)
            .await
            .unwrap();
        drop(guard);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            old.current_token().await.is_none(),
            "stale-generation TTL must close its in-memory authority even when deletion is refused"
        );
        assert_eq!(
            current.current_token().await.unwrap().nonce.0,
            current_token.nonce.0
        );
        assert!(
            current
                .inner
                .namespace
                .as_ref()
                .unwrap()
                .pair_device_snapshot_path()
                .exists()
        );
    }

    #[tokio::test]
    async fn identical_window_content_from_an_old_generation_is_not_adopted() {
        let td = tempfile::tempdir().unwrap();
        let lifecycle =
            crate::household_lifecycle::HouseholdLifecycleLock::open_verified(td.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let old =
            PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
                .unwrap();
        let token = old
            .mint_token_under_lifecycle(Duration::from_secs(30), None, &guard)
            .await
            .unwrap();
        let old_snapshot = old
            .read_persisted_snapshot_under_lifecycle(&guard)
            .unwrap()
            .unwrap();

        guard.rotate_lifecycle_generation().unwrap();
        let current =
            PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
                .unwrap();
        let mut same_content_current_generation = old_snapshot.clone();
        same_content_current_generation.lifecycle_generation = ByteBuf::from(
            current
                .inner
                .namespace
                .as_ref()
                .unwrap()
                .generation()
                .token_bytes()
                .to_vec(),
        );
        current
            .inner
            .namespace
            .as_ref()
            .unwrap()
            .write_pair_device_under_lifecycle(&same_content_current_generation, &guard)
            .unwrap();
        drop(guard);

        assert!(
            !current
                .install_token_from_current_snapshot(token, &old_snapshot)
                .await
                .unwrap()
        );
        assert!(current.current_token().await.is_none());
    }

    #[tokio::test]
    async fn stale_generation_consume_fails_closed_without_deleting_current_window() {
        let td = tempfile::tempdir().unwrap();
        let lifecycle =
            crate::household_lifecycle::HouseholdLifecycleLock::open_verified(td.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let old =
            PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
                .unwrap();
        let old_token = old
            .mint_token_under_lifecycle(Duration::from_secs(30), None, &guard)
            .await
            .unwrap();
        guard.rotate_lifecycle_generation().unwrap();
        let current =
            PairDeviceWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
                .unwrap();
        let current_token = current
            .mint_token_under_lifecycle(Duration::from_secs(30), None, &guard)
            .await
            .unwrap();
        drop(guard);

        assert!(matches!(
            old.consume_token(&old_token.nonce).await,
            Err(ConsumeError::Storage(_))
        ));
        assert!(old.current_token().await.is_none());
        assert_eq!(
            current.current_token().await.unwrap().nonce.0,
            current_token.nonce.0
        );
        assert!(
            current
                .inner
                .namespace
                .as_ref()
                .unwrap()
                .pair_device_snapshot_path()
                .exists()
        );
    }
}
