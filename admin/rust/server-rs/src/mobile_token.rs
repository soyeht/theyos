//! Mobile token store — QR tokens (in-memory) + persistent sessions (`SQLite`).
//!
//! Two token types:
//! - **QR tokens**: short-lived (15 min), generated when admin clicks "QR" button.
//!   Encodes which instance the token grants access to, plus the generating admin's
//!   username.  In-memory only — no persistence needed for 15-min single-use tokens.
//! - **Session tokens**: long-lived (30 days, sliding window), issued when the mobile
//!   app exchanges a valid QR token via `POST /api/v1/mobile/auth`.  Persisted in
//!   `SQLite` so sessions survive deploys/restarts.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

// ─── Configuration ────────────────────────────────────────────────────────────

const QR_TOKEN_TTL: Duration = Duration::from_secs(15 * 60); // 15 minutes
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5 * 60); // 5 minutes

// ─── Types ────────────────────────────────────────────────────────────────────

/// Entry for a QR image link (maps `image_id` → `deep_link` for PNG rendering).
#[derive(Clone, Debug)]
struct ImageLinkEntry {
    deep_link: String,
    expires_at: Instant,
}

/// Metadata stored alongside a QR token.
#[derive(Clone, Debug)]
pub struct QrTokenEntry {
    /// Instance ID this QR token grants access to.
    pub instance_id: String,
    /// Admin username that generated this QR token.
    pub username: String,
    /// Workspace ID for "continue on iPhone" tokens — `Some` when the token was
    /// minted for a specific tmux session (device-to-device handoff), `None`
    /// for admin-minted QR that only grants instance access.
    pub workspace_id: Option<String>,
    /// When this token expires.
    pub expires_at: Instant,
    /// Wall-clock expiration (for JSON responses).
    pub expires_at_utc: SystemTime,
}

/// Capabilities describe what communication features a claw type supports.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ClawCapabilities {
    pub terminal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_auth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_ws: Option<String>,
}

// ─── QR Token Store (in-memory) ──────────────────────────────────────────────

/// Thread-safe in-memory store for short-lived QR tokens.
///
/// QR tokens are ephemeral (15 min, single-use) — no need for persistence.
/// All methods acquire the lock briefly and return.
pub struct MobileTokenStore {
    inner: Mutex<HashMap<String, QrTokenEntry>>,
    /// Maps image IDs to deep links for QR PNG rendering.
    image_links: Mutex<HashMap<String, ImageLinkEntry>>,
}

impl MobileTokenStore {
    /// Create a new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            image_links: Mutex::new(HashMap::new()),
        }
    }

    /// Generate a new QR token for the given instance and username (default 15-min TTL).
    /// Returns `(token, expires_at_rfc3339)`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn create_qr_token(&self, instance_id: &str, username: &str) -> (String, String) {
        self.create_qr_token_with_ttl(instance_id, username, QR_TOKEN_TTL)
    }

    /// Generate a new QR token with a custom TTL.
    /// Returns `(token, expires_at_rfc3339)`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn create_qr_token_with_ttl(
        &self,
        instance_id: &str,
        username: &str,
        ttl: Duration,
    ) -> (String, String) {
        self.insert_token(instance_id, username, None, ttl)
    }

    /// Generate a QR token for "continue on iPhone" flow — carries the specific
    /// tmux workspace the generating device is attached to, so that the scanning
    /// device lands on the same session without going through the instance picker.
    ///
    /// Returns `(token, expires_at_rfc3339)`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn create_continue_qr_token(
        &self,
        instance_id: &str,
        username: &str,
        workspace_id: &str,
        ttl: Duration,
    ) -> (String, String) {
        self.insert_token(instance_id, username, Some(workspace_id.to_string()), ttl)
    }

    fn insert_token(
        &self,
        instance_id: &str,
        username: &str,
        workspace_id: Option<String>,
        ttl: Duration,
    ) -> (String, String) {
        let token = generate_token();
        let now = Instant::now();
        let expires_at = now + ttl;
        let expires_at_utc = SystemTime::now() + ttl;

        let entry = QrTokenEntry {
            instance_id: instance_id.to_string(),
            username: username.to_string(),
            workspace_id,
            expires_at,
            expires_at_utc,
        };

        let mut inner = self.inner.lock().expect("mobile token store lock poisoned");
        inner.insert(token.clone(), entry);

        let expires_str = format_system_time(expires_at_utc);
        (token, expires_str)
    }

    /// Validate and consume a QR token. Returns `(instance_id, username, workspace_id)`
    /// if valid — `workspace_id` is `Some` only for continue-on-iPhone tokens.
    /// The token is removed on successful validation (single-use).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn redeem_qr_token(&self, token: &str) -> Option<(String, String, Option<String>)> {
        let mut inner = self.inner.lock().expect("mobile token store lock poisoned");
        let entry = inner.remove(token)?;
        if entry.expires_at < Instant::now() {
            return None; // expired
        }
        Some((entry.instance_id, entry.username, entry.workspace_id))
    }

    /// Look up a QR token without consuming it (for status checks).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn peek_qr_token(&self, token: &str) -> Option<QrTokenEntry> {
        let inner = self.inner.lock().expect("mobile token store lock poisoned");
        let entry = inner.get(token)?;
        if entry.expires_at < Instant::now() {
            return None;
        }
        Some(entry.clone())
    }

    /// Store a deep link for QR image rendering (default 15-min TTL). Returns the image ID.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn store_image_link(&self, deep_link: &str) -> String {
        self.store_image_link_with_ttl(deep_link, QR_TOKEN_TTL)
    }

    /// Store a deep link for QR image rendering with a custom TTL. Returns the image ID.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn store_image_link_with_ttl(&self, deep_link: &str, ttl: Duration) -> String {
        let id = generate_token();
        let entry = ImageLinkEntry {
            deep_link: deep_link.to_string(),
            expires_at: Instant::now() + ttl,
        };
        let mut links = self.image_links.lock().expect("image links lock poisoned");
        links.insert(id.clone(), entry);
        id
    }

    /// Retrieve a deep link by image ID (without consuming it).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get_image_link(&self, image_id: &str) -> Option<String> {
        let links = self.image_links.lock().expect("image links lock poisoned");
        let entry = links.get(image_id)?;
        if entry.expires_at < Instant::now() {
            return None;
        }
        Some(entry.deep_link.clone())
    }

    /// Remove expired QR tokens. Returns the number removed.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("mobile token store lock poisoned");
        let before = inner.len();
        inner.retain(|_, e| e.expires_at > now);
        let removed = before - inner.len();

        let mut links = self.image_links.lock().expect("image links lock poisoned");
        let before_links = links.len();
        links.retain(|_, e| e.expires_at > now);

        removed + (before_links - links.len())
    }

    /// Start a background task that periodically cleans up expired QR tokens.
    pub fn start_cleanup_task(self: &std::sync::Arc<Self>) {
        let store = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let removed = store.cleanup_expired();
                if removed > 0 {
                    tracing::info!(
                        "[mobile-tokens] cleanup: removed {removed} expired QR token(s)"
                    );
                }
            }
        });
    }
}

impl Default for MobileTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Mobile Session DB (SQLite-backed) ───────────────────────────────────────

/// Persistent mobile session store backed by `SQLite`.
///
/// Sessions use the same 30-day sliding-window TTL as web sessions
/// (`session_rs::get_ttl_secs()`).  Each `validate_session()` call extends
/// the expiry, matching the web `SessionStore` pattern.
pub struct MobileSessionDb {
    conn: Mutex<Connection>,
}

impl MobileSessionDb {
    /// Open (or create) the mobile sessions database.
    ///
    /// # Errors
    ///
    /// Returns a `rusqlite::Error` if the database cannot be opened or the
    /// schema cannot be initialized.
    pub fn open(db_path: &str) -> Result<Self, rusqlite::Error> {
        let conn = core_rs::db::open_wal(std::path::Path::new(db_path))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS mobile_sessions (
                token      TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mobile_sessions_expires
                ON mobile_sessions(expires_at);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create a new mobile session. Returns `(session_token, expires_at_rfc3339)`.
    ///
    /// # Errors
    ///
    /// Returns a `rusqlite::Error` if the INSERT fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn create_session(&self, username: &str) -> Result<(String, String), rusqlite::Error> {
        self.create_session_with_ttl(username, session_rs::get_ttl_secs())
    }

    /// Create a new mobile session with a custom TTL (in seconds).
    /// Returns `(session_token, expires_at_rfc3339)`.
    ///
    /// # Errors
    ///
    /// Returns a `rusqlite::Error` if the INSERT fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn create_session_with_ttl(
        &self,
        username: &str,
        ttl_secs: u64,
    ) -> Result<(String, String), rusqlite::Error> {
        let token = generate_token();
        let conn = self.conn.lock().expect("mobile session db lock poisoned");
        conn.execute(
            "INSERT INTO mobile_sessions (token, username, expires_at) \
             VALUES (?1, ?2, datetime(CURRENT_TIMESTAMP, ?3))",
            params![token, username, format!("+{ttl_secs} seconds")],
        )?;
        let expires_at_utc = SystemTime::now() + Duration::from_secs(ttl_secs);
        let expires_str = format_system_time(expires_at_utc);
        Ok((token, expires_str))
    }

    /// Validate a mobile session token. Returns the username if valid.
    ///
    /// On success, extends the session expiry (sliding window).
    #[must_use]
    pub fn validate_session(&self, token: &str) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        let username: Option<String> = conn
            .query_row(
                "SELECT username FROM mobile_sessions \
                 WHERE token = ?1 AND expires_at > CURRENT_TIMESTAMP",
                params![token],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or(None);
        // Sliding window renewal — extend on every successful validation.
        if username.is_some() {
            let ttl = session_rs::get_ttl_secs();
            let _ = conn.execute(
                "UPDATE mobile_sessions SET expires_at = datetime(CURRENT_TIMESTAMP, ?1) \
                 WHERE token = ?2",
                params![format!("+{ttl} seconds"), token],
            );
        }
        username
    }

    /// Delete a mobile session.
    ///
    /// # Errors
    ///
    /// Returns a `rusqlite::Error` if the DELETE fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn delete_session(&self, token: &str) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().expect("mobile session db lock poisoned");
        conn.execute(
            "DELETE FROM mobile_sessions WHERE token = ?1",
            params![token],
        )?;
        Ok(())
    }

    /// Remove all expired sessions. Returns the number deleted.
    ///
    /// # Errors
    ///
    /// Returns a `rusqlite::Error` if the DELETE fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn cleanup_expired(&self) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock().expect("mobile session db lock poisoned");
        conn.execute(
            "DELETE FROM mobile_sessions WHERE expires_at <= CURRENT_TIMESTAMP",
            [],
        )
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Derive claw capabilities from the claw type string.
#[must_use]
pub fn capabilities_for(claw_type: &str) -> ClawCapabilities {
    match claw_type {
        "zeroclaw" | "nullclaw" => ClawCapabilities {
            terminal: true,
            chat_endpoint: Some("/webhook".to_string()),
            chat_auth: Some("bearer".to_string()),
            chat_ws: None,
        },
        "ironclaw" => ClawCapabilities {
            terminal: true,
            chat_endpoint: Some("/api/chat/send".to_string()),
            chat_auth: Some("bearer".to_string()),
            chat_ws: Some("/api/chat/ws".to_string()),
        },
        // picoclaw, nanobot, openclaw — no generic HTTP chat endpoint
        _ => ClawCapabilities {
            terminal: true,
            chat_endpoint: None,
            chat_auth: None,
            chat_ws: None,
        },
    }
}

/// Generate a 32-byte random token encoded as base64url (no padding).
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Format a `SystemTime` as RFC 3339 (ISO 8601) string.
fn format_system_time(t: SystemTime) -> String {
    let dur = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    // Simple UTC formatting without pulling in chrono
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Calculate date from days since epoch (civil calendar)
    let (year, month, day) = days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
/// Algorithm from Howard Hinnant's `chrono`-compatible date library.
fn days_to_date(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_token_create_and_redeem() {
        let store = MobileTokenStore::new();
        let (token, _expires) = store.create_qr_token("inst-demo", "admin");

        // First redemption succeeds
        let result = store.redeem_qr_token(&token);
        assert_eq!(
            result,
            Some(("inst-demo".to_string(), "admin".to_string(), None))
        );

        // Second redemption fails (single-use)
        assert!(store.redeem_qr_token(&token).is_none());
    }

    #[test]
    fn qr_token_invalid() {
        let store = MobileTokenStore::new();
        assert!(store.redeem_qr_token("nonexistent").is_none());
    }

    #[test]
    fn qr_token_carries_username() {
        let store = MobileTokenStore::new();
        let (token, _) = store.create_qr_token("inst-1", "alice");
        let (_, username, _) = store.redeem_qr_token(&token).unwrap();
        assert_eq!(username, "alice");
    }

    #[test]
    fn legacy_qr_token_has_no_workspace_id() {
        let store = MobileTokenStore::new();
        let (token, _) = store.create_qr_token("inst-1", "alice");
        let (_, _, workspace_id) = store.redeem_qr_token(&token).unwrap();
        assert_eq!(workspace_id, None);
    }

    #[test]
    fn continue_qr_token_carries_workspace_id() {
        let store = MobileTokenStore::new();
        let (token, _) = store.create_continue_qr_token(
            "inst-1",
            "alice",
            "ws-xyz-123",
            Duration::from_secs(120),
        );
        let (instance_id, username, workspace_id) = store.redeem_qr_token(&token).unwrap();
        assert_eq!(instance_id, "inst-1");
        assert_eq!(username, "alice");
        assert_eq!(workspace_id, Some("ws-xyz-123".to_string()));
    }

    #[test]
    fn continue_qr_token_single_use() {
        let store = MobileTokenStore::new();
        let (token, _) = store.create_continue_qr_token(
            "inst-1",
            "alice",
            "ws-xyz-123",
            Duration::from_secs(120),
        );
        assert!(store.redeem_qr_token(&token).is_some());
        assert!(store.redeem_qr_token(&token).is_none()); // second attempt fails
    }

    #[test]
    fn session_db_create_with_custom_ttl() {
        let db = MobileSessionDb::open(":memory:").unwrap();
        let one_year = 365 * 24 * 3600;
        let (token, _expires) = db.create_session_with_ttl("admin", one_year).unwrap();

        // Check TTL before validate_session (which applies the default sliding window).
        {
            let conn = db.conn.lock().unwrap();
            let secs_remaining: f64 = conn
                .query_row(
                    "SELECT (julianday(expires_at) - julianday('now')) * 86400 \
                     FROM mobile_sessions WHERE token = ?1",
                    params![token],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                secs_remaining > f64::from(364 * 24 * 3600),
                "expected ~1 year TTL, got {secs_remaining}s"
            );
        }

        // Validate still works.
        let username = db.validate_session(&token);
        assert_eq!(username.as_deref(), Some("admin"));
    }

    #[test]
    fn session_db_create_and_validate() {
        let db = MobileSessionDb::open(":memory:").unwrap();
        let (token, _expires) = db.create_session("admin").unwrap();

        let username = db.validate_session(&token);
        assert_eq!(username.as_deref(), Some("admin"));

        // Session is reusable (not single-use)
        let username2 = db.validate_session(&token);
        assert_eq!(username2.as_deref(), Some("admin"));
    }

    #[test]
    fn session_db_invalid() {
        let db = MobileSessionDb::open(":memory:").unwrap();
        assert!(db.validate_session("nonexistent").is_none());
    }

    #[test]
    fn session_db_delete() {
        let db = MobileSessionDb::open(":memory:").unwrap();
        let (token, _) = db.create_session("admin").unwrap();
        db.delete_session(&token).unwrap();
        assert!(db.validate_session(&token).is_none());
    }

    #[test]
    fn session_db_cleanup_expired() {
        let db = MobileSessionDb::open(":memory:").unwrap();
        let (token, _) = db.create_session("admin").unwrap();
        // Manually expire the session.
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE mobile_sessions SET expires_at = datetime('now', '-1 hour') \
                 WHERE token = ?1",
                params![token],
            )
            .unwrap();
        }
        let removed = db.cleanup_expired().unwrap();
        assert_eq!(removed, 1);
        assert!(db.validate_session(&token).is_none());
    }

    #[test]
    fn session_db_sliding_window() {
        let db = MobileSessionDb::open(":memory:").unwrap();
        let (token, _) = db.create_session("admin").unwrap();
        // Expire the session to 1 minute from now (much less than the TTL).
        {
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "UPDATE mobile_sessions SET expires_at = datetime('now', '+60 seconds') \
                 WHERE token = ?1",
                params![token],
            )
            .unwrap();
        }
        // validate_session should renew it to the full TTL.
        assert!(db.validate_session(&token).is_some());
        // Check that expires_at was extended well beyond 60 seconds.
        {
            let conn = db.conn.lock().unwrap();
            let secs_remaining: f64 = conn
                .query_row(
                    "SELECT (julianday(expires_at) - julianday('now')) * 86400 \
                     FROM mobile_sessions WHERE token = ?1",
                    params![token],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                secs_remaining > 120.0,
                "sliding window should have extended expiry, got {secs_remaining}s"
            );
        }
    }

    #[test]
    fn cleanup_removes_nothing_when_fresh() {
        let store = MobileTokenStore::new();
        let (_token, _) = store.create_qr_token("inst-1", "admin");
        let removed = store.cleanup_expired();
        assert_eq!(removed, 0);
    }

    #[test]
    fn capabilities_zeroclaw() {
        let caps = capabilities_for("zeroclaw");
        assert!(caps.terminal);
        assert_eq!(caps.chat_endpoint.as_deref(), Some("/webhook"));
        assert!(caps.chat_ws.is_none());
    }

    #[test]
    fn capabilities_ironclaw() {
        let caps = capabilities_for("ironclaw");
        assert!(caps.terminal);
        assert_eq!(caps.chat_endpoint.as_deref(), Some("/api/chat/send"));
        assert_eq!(caps.chat_ws.as_deref(), Some("/api/chat/ws"));
    }

    #[test]
    fn capabilities_picoclaw() {
        let caps = capabilities_for("picoclaw");
        assert!(caps.terminal);
        assert!(caps.chat_endpoint.is_none());
        assert!(caps.chat_ws.is_none());
    }

    #[test]
    fn date_formatting() {
        // 2026-01-01T00:00:00Z = 20454 days since epoch
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(20454 * 86400);
        let s = format_system_time(t);
        assert_eq!(s, "2026-01-01T00:00:00Z");
    }
}
