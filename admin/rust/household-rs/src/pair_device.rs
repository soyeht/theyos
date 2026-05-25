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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::{RwLock, broadcast};

use crate::keys::P256PublicKey;
use crate::machine_cert::PersonId;

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
    pub fn to_snapshot(&self) -> PairDeviceWindowSnapshot {
        PairDeviceWindowSnapshot {
            version: 1,
            nonce_b64: self.nonce.as_b64(),
            expires_at_unix: self.expires_at_unix,
            p_id_hint: self.p_id_hint.as_ref().map(|p| p.0.clone()),
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
        if snap.version != 1 {
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

    /// Render the canonical `soyeht://household/pair-device?…` URI per
    /// `docs/household-protocol.md` §11.
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
    #[must_use]
    pub fn to_uri(&self, hh_pub: &P256PublicKey) -> String {
        self.to_uri_with_host(hh_pub, None)
    }

    /// As [`Self::to_uri`] but also includes a `host=<addr>:<port>` fallback
    /// query parameter when `host` is `Some`. See [`Self::to_uri`] for the
    /// rationale.
    #[must_use]
    pub fn to_uri_with_host(&self, hh_pub: &P256PublicKey, host: Option<&str>) -> String {
        self.to_uri_with_host_and_name(hh_pub, host, None)
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
    ) -> String {
        let mut uri = String::from("soyeht://household/pair-device");
        uri.push_str("?v=1");
        uri.push_str("&hh_pub=");
        uri.push_str(&B64.encode(hh_pub.as_bytes()));
        uri.push_str("&nonce=");
        uri.push_str(&self.nonce.as_b64());
        uri.push_str("&ttl=");
        uri.push_str(&self.expires_at_unix.to_string());
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
    /// When `Some`, the window auto-deletes
    /// `<state_dir>/household/pair_device_window.cbor` on consume / expiry so the
    /// daemon (which reloads from disk on restart) cannot serve a stale
    /// token after success.
    state_dir: Option<PathBuf>,
}

impl PairDeviceWindow {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel::<PairDeviceWindowState>(8);
        Self {
            inner: Arc::new(PairDeviceWindowInner {
                state: RwLock::new(None),
                notifier: tx,
                state_dir: None,
            }),
        }
    }

    /// Persistent variant: synchronizes window state with
    /// `<state_dir>/household/pair_device_window.cbor`.
    #[must_use]
    pub fn with_persistence(state_dir: PathBuf) -> Self {
        let (tx, _) = broadcast::channel::<PairDeviceWindowState>(8);
        Self {
            inner: Arc::new(PairDeviceWindowInner {
                state: RwLock::new(None),
                notifier: tx,
                state_dir: Some(state_dir),
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
    /// new token is also persisted to `<state_dir>/household/pair_device_window.cbor`
    /// so a daemon restart picks up the live token instead of resurrecting
    /// the previous one.
    pub async fn mint_token(
        &self,
        ttl: Duration,
        p_id_hint: Option<PersonId>,
    ) -> Result<PairToken, String> {
        let token = PairToken::mint(ttl, p_id_hint)?;
        self.replace_with(token.clone(), ttl).await;
        if let Some(dir) = &self.inner.state_dir {
            if let Err(e) = crate::storage::atomic_write_cbor(
                &crate::storage::pair_device_window_path(dir),
                &token.to_snapshot(),
            ) {
                tracing::warn!(
                    stage = "pair_device_window.snapshot_write_failed",
                    error = %e,
                    "discarding persisted snapshot for safety"
                );
                let _ = crate::storage::delete_pair_device_window_snapshot(dir);
            }
        }
        Ok(token)
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
        let remaining = token.expires_at.saturating_duration_since(Instant::now());
        let short = token.nonce.as_short_b64();
        let mut guard = self.inner.state.write().await;
        if guard
            .as_ref()
            .is_some_and(|current| !current.is_expired() && current.nonce.0 == token.nonce.0)
        {
            return Ok(false);
        }
        if let Some(dir) = &self.inner.state_dir {
            let latest: Option<PairDeviceWindowSnapshot> =
                crate::storage::read_optional_cbor(&crate::storage::pair_device_window_path(dir))
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
                drop(guard);
                let _ = self.inner.notifier.send(PairDeviceWindowState::Closed);
                self.delete_persisted();
                Err(ConsumeError::Expired)
            }
            Some(t) if !bool::from(t.nonce.0.ct_eq(&nonce.0)) => Err(ConsumeError::WrongNonce),
            Some(_) => {
                let token = guard.take().expect("matched Some(_) above");
                drop(guard);
                let _ = self.inner.notifier.send(PairDeviceWindowState::Closed);
                self.delete_persisted();
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
        let mut guard = self.inner.state.write().await;
        let token = match guard.as_ref() {
            None => return Err(ConsumeWithError::Window(ConsumeError::NotOpen)),
            Some(t) if t.is_expired() => {
                *guard = None;
                drop(guard);
                let _ = self.inner.notifier.send(PairDeviceWindowState::Closed);
                self.delete_persisted();
                return Err(ConsumeWithError::Window(ConsumeError::Expired));
            }
            Some(t) if !bool::from(t.nonce.0.ct_eq(&nonce.0)) => {
                return Err(ConsumeWithError::Window(ConsumeError::WrongNonce));
            }
            Some(t) => t,
        };
        let output = f(token).map_err(ConsumeWithError::Callback)?;
        let _ = guard.take();
        drop(guard);
        let _ = self.inner.notifier.send(PairDeviceWindowState::Closed);
        self.delete_persisted();
        Ok(output)
    }

    /// Best-effort delete of the persisted pair window snapshot, if any.
    fn delete_persisted(&self) {
        if let Some(dir) = &self.inner.state_dir {
            if let Err(e) = crate::storage::delete_pair_device_window_snapshot(dir) {
                tracing::warn!(
                    stage = "pair_device_window.delete_snapshot_failed",
                    path = %dir.display(),
                    error = %e,
                );
            }
        }
    }

    /// Returns true if a non-expired token is currently parked.
    pub async fn is_open(&self) -> bool {
        let guard = self.inner.state.read().await;
        matches!(guard.as_ref(), Some(t) if !t.is_expired())
    }

    /// Forcibly close the window (for shutdown / `--reissue-pair-qr`).
    pub async fn close(&self) {
        let mut guard = self.inner.state.write().await;
        *guard = None;
        drop(guard);
        let _ = self.inner.notifier.send(PairDeviceWindowState::Closed);
        self.delete_persisted();
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
                    *guard = None;
                    drop(guard);
                    let _ = inner.notifier.send(PairDeviceWindowState::Closed);
                    if let Some(dir) = &inner.state_dir {
                        let _ = crate::storage::delete_pair_device_window_snapshot(dir);
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

    #[tokio::test]
    async fn mint_then_consume() {
        let w = PairDeviceWindow::new();
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        let uri = token.to_uri(&fake_hh_pub());
        assert!(uri.starts_with("soyeht://household/pair-device?"));
        assert!(uri.contains("&hh_pub="));
        assert!(uri.contains("&ttl="));
        assert!(!uri.contains("&exp="));
        assert!(w.is_open().await);

        w.consume_token(&token.nonce).await.unwrap();
        assert!(!w.is_open().await);
    }

    #[tokio::test]
    async fn uri_with_host_and_name_percent_encodes_household_name() {
        let w = PairDeviceWindow::new();
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        let uri = token.to_uri_with_host_and_name(
            &fake_hh_pub(),
            Some("100.82.47.115:8091"),
            Some("Sample Home"),
        );
        assert!(uri.contains("&host=100.82.47.115:8091"));
        assert!(uri.contains("&house_name=Sample%20Home"));
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
            version: 1,
            nonce_b64: PairNonce::random().as_b64(),
            // Far-future expiry — would be unbounded sleep without clamping.
            expires_at_unix: now + 10_000_000,
            p_id_hint: None,
        };
        let token = PairToken::from_snapshot(&snap)
            .expect("decode")
            .expect("not expired");
        assert!(token.expires_at_unix - now <= MAX_PAIR_DEVICE_WINDOW_TTL_SECS);
    }

    #[tokio::test]
    async fn mint_persists_snapshot_when_state_dir_set() {
        let td = tempfile::tempdir().unwrap();
        let w = PairDeviceWindow::with_persistence(td.path().to_path_buf());
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();

        // Persisted snapshot should carry the same nonce.
        let path = crate::storage::pair_device_window_path(td.path());
        let snap: PairDeviceWindowSnapshot =
            crate::storage::read_optional_cbor(&path).unwrap().unwrap();
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
        let w = PairDeviceWindow::with_persistence(td.path().to_path_buf());
        let token = w.mint_token(Duration::from_secs(60), None).await.unwrap();
        let snap = token.to_snapshot();

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
}
