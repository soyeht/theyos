//! session-rs — SQLite-backed session management for theyOS.
//!
//! # Design
//!
//!   - **WAL mode + `busy_timeout`**: concurrent reads while a writer is active.
//!   - **Username stored in session**: `ValidateSession` returns the username
//!     associated with the token.
//!   - **Pepper**: read from `THEYOS_SESSION_PEPPER` env var; falls back to
//!     the built-in default when the var is absent.
//!   - **Cleanup on demand**: `cleanup_expired()` removes stale sessions;
//!     callers may run it periodically or on every validate call.

use base64::Engine as _;
use core_rs::error::{AppError, ErrorCode};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("session not found or expired")]
    SessionNotFound,
    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError for SessionError {
    fn code(&self) -> ErrorCode {
        match self {
            SessionError::InvalidCredentials | SessionError::SessionNotFound => {
                ErrorCode::Unauthorized
            }
            _ => ErrorCode::Internal,
        }
    }
}

// ─── TTL ─────────────────────────────────────────────────────────────────────

/// Default session TTL: 30 days.
const DEFAULT_TTL_SECS: u64 = 2_592_000;

/// Return the session TTL in seconds.
///
/// Reads `THEYOS_SESSION_TTL_SECS` from the environment; falls back to 30 days.
#[must_use]
pub fn get_ttl_secs() -> u64 {
    std::env::var("THEYOS_SESSION_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_TTL_SECS)
}

// ─── Pepper ───────────────────────────────────────────────────────────────────

/// Return the pepper for password hashing.
///
/// Reads `THEYOS_SESSION_PEPPER` from the environment. Falls back to the
/// built-in default when the variable is not set. Set the env var in
/// production to rotate the pepper without a code change.
fn get_pepper() -> String {
    std::env::var("THEYOS_SESSION_PEPPER").unwrap_or_else(|_| {
        tracing::warn!("THEYOS_SESSION_PEPPER not set — using weak built-in default; set this env var in production");
        "theyos-default-pepper-change-me".to_string()
    })
}

// ─── SessionStore ─────────────────────────────────────────────────────────────

/// Session store backed by `SQLite`.
pub struct SessionStore {
    conn: Mutex<Connection>,
    admin_user: String,
    /// SHA-256(password + "::" + PEPPER) as a lowercase hex string.
    admin_password_hash: String,
}

impl SessionStore {
    /// Open (or create) the `SQLite` database and initialize the schema.
    ///
    /// Reads `SOYEHT_ADMIN_USER` (default: `"admin"`) and
    /// `SOYEHT_ADMIN_PASSWORD` (default: `""`) from the environment.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or the schema
    /// cannot be initialized.
    pub fn open(db_path: &str) -> Result<Self, SessionError> {
        let admin_user = std::env::var("SOYEHT_ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
        let admin_password = std::env::var("SOYEHT_ADMIN_PASSWORD").unwrap_or_default();
        let admin_password_hash = hash_password(&admin_password);

        let conn =
            core_rs::db::open_wal(std::path::Path::new(db_path)).map_err(SessionError::Db)?;
        Self::init_schema(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            admin_user,
            admin_password_hash,
        })
    }

    fn init_schema(conn: &Connection) -> Result<(), SessionError> {
        conn.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
            ",
        )
        .map_err(SessionError::Db)?;
        Ok(())
    }

    // ─── Auth ─────────────────────────────────────────────────────────────

    /// Validate username + password against the configured admin credentials.
    ///
    /// Returns `Ok(())` on success, `Err(SessionError::InvalidCredentials)` on
    /// failure.
    ///
    /// # Errors
    ///
    /// Returns `SessionError::InvalidCredentials` if the username or password
    /// does not match the configured admin credentials.
    pub fn validate_credentials(&self, username: &str, password: &str) -> Result<(), SessionError> {
        if username == self.admin_user && hash_password(password) == self.admin_password_hash {
            Ok(())
        } else {
            Err(SessionError::InvalidCredentials)
        }
    }

    // ─── Sessions ─────────────────────────────────────────────────────────

    /// Create a new session for `username`. Returns the session token.
    ///
    /// The session expires after `get_ttl_secs()` seconds (default: 30 days).
    /// Callers should use `Max-Age` (from `get_ttl_secs()`) in the `Set-Cookie`
    /// header rather than `Expires`, avoiding HTTP-date formatting issues.
    ///
    /// # Errors
    ///
    /// Returns an error if the mutex is poisoned or the database insert fails.
    pub fn create_session(&self, username: &str) -> Result<String, SessionError> {
        let token = generate_token();
        let ttl = get_ttl_secs();
        let conn = self
            .conn
            .lock()
            .map_err(|_| SessionError::Internal("mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at) \
             VALUES (?1, ?2, CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, ?3))",
            params![token, username, format!("+{ttl} seconds")],
        )
        .map_err(SessionError::Db)?;

        Ok(token)
    }

    /// Validate a session token (sliding window).
    ///
    /// Returns `Some(username)` if the token exists and has not expired.
    /// On success, extends `expires_at` by the configured TTL so that
    /// active sessions never expire while the user keeps using them.
    pub fn validate_session(&self, token: &str) -> Option<String> {
        let Ok(conn) = self.conn.lock() else {
            tracing::error!("[session] validate_session: mutex poisoned");
            return None;
        };
        let username: Option<String> = conn
            .query_row(
                "SELECT username FROM sessions \
                 WHERE token = ?1 AND expires_at > CURRENT_TIMESTAMP",
                params![token],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or(None);
        if username.is_some() {
            let ttl = get_ttl_secs();
            if let Err(e) = conn.execute(
                "UPDATE sessions SET expires_at = datetime(CURRENT_TIMESTAMP, ?1) WHERE token = ?2",
                params![format!("+{ttl} seconds"), token],
            ) {
                tracing::warn!("[session] sliding-window renewal failed: {e}");
            }
        }
        username
    }

    /// Delete a session by token. No-ops on unknown tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if the mutex is poisoned or the database delete fails.
    pub fn delete_session(&self, token: &str) -> Result<(), SessionError> {
        if token.is_empty() {
            return Ok(());
        }
        let conn = self
            .conn
            .lock()
            .map_err(|_| SessionError::Internal("mutex poisoned".into()))?;
        conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])
            .map_err(SessionError::Db)?;
        Ok(())
    }

    /// Delete all expired sessions and return the count removed.
    ///
    /// # Errors
    ///
    /// Returns an error if the mutex is poisoned or the database query fails.
    pub fn cleanup_expired(&self) -> Result<usize, SessionError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SessionError::Internal("mutex poisoned".into()))?;
        let n = conn
            .execute(
                "DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP",
                [],
            )
            .map_err(SessionError::Db)?;
        Ok(n)
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// SHA-256(password + "::" + pepper) as a lowercase hex string.
///
/// The pepper is read from the `THEYOS_SESSION_PEPPER` env var at call time.
#[must_use]
pub fn hash_password(password: &str) -> String {
    let pepper = get_pepper();
    let mut hasher = Sha256::new();
    hasher.update(format!("{password}::{pepper}"));
    hex::encode(hasher.finalize())
}

/// Generate a 32-byte random token encoded as base64url (no padding).
fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core_rs::env::set_test_env;

    fn open_temp() -> SessionStore {
        set_test_env("SOYEHT_ADMIN_USER", "testuser");
        set_test_env("SOYEHT_ADMIN_PASSWORD", "testpass");
        SessionStore::open(":memory:").expect("open :memory:")
    }

    #[test]
    fn test_validate_credentials_correct() {
        let store = open_temp();
        assert!(store.validate_credentials("testuser", "testpass").is_ok());
    }

    #[test]
    fn test_validate_credentials_wrong_password() {
        let store = open_temp();
        let err = store
            .validate_credentials("testuser", "wrongpass")
            .unwrap_err();
        assert!(matches!(err, SessionError::InvalidCredentials));
    }

    #[test]
    fn test_validate_credentials_wrong_user() {
        let store = open_temp();
        let err = store
            .validate_credentials("wronguser", "testpass")
            .unwrap_err();
        assert!(matches!(err, SessionError::InvalidCredentials));
    }

    #[test]
    fn test_create_and_validate_session() {
        let store = open_temp();
        let token = store.create_session("testuser").unwrap();
        assert!(!token.is_empty());
        let username = store.validate_session(&token);
        assert_eq!(username, Some("testuser".to_string()));
    }

    #[test]
    fn test_validate_nonexistent_session() {
        let store = open_temp();
        assert!(store.validate_session("nonexistent-token").is_none());
    }

    #[test]
    fn test_delete_session() {
        let store = open_temp();
        let token = store.create_session("testuser").unwrap();
        store.delete_session(&token).unwrap();
        assert!(store.validate_session(&token).is_none());
    }

    #[test]
    fn test_delete_session_empty_token() {
        let store = open_temp();
        // Should be a no-op, not an error.
        assert!(store.delete_session("").is_ok());
    }

    #[test]
    fn test_cleanup_expired() {
        let store = open_temp();
        let token = store.create_session("testuser").unwrap();
        // Manually expire the session.
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE sessions SET expires_at = datetime('now', '-1 hour') WHERE token = ?1",
                params![token],
            )
            .unwrap();
        }
        let n = store.cleanup_expired().unwrap();
        assert_eq!(n, 1);
        assert!(store.validate_session(&token).is_none());
    }

    #[test]
    fn test_cleanup_expired_leaves_valid_sessions() {
        let store = open_temp();
        let token = store.create_session("testuser").unwrap();
        let n = store.cleanup_expired().unwrap();
        assert_eq!(n, 0);
        // Valid session untouched.
        assert!(store.validate_session(&token).is_some());
    }

    #[test]
    fn test_hash_password_deterministic() {
        let h1 = hash_password("mypassword");
        let h2 = hash_password("mypassword");
        assert_eq!(h1, h2);
        assert_ne!(h1, hash_password("otherpassword"));
    }

    #[test]
    fn test_hash_password_pepper() {
        // Verify the pepper is included: same password with different pepper
        // would produce a different hash. We can't test that directly without
        // exposing the pepper, but we can verify the hash is stable across calls
        // and differs from a naive SHA-256 of just the password.
        let with_pepper = hash_password("secret");
        // SHA-256 of "secret" alone (no pepper) should differ.
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"secret");
        let without_pepper = hex::encode(hasher.finalize());
        assert_ne!(with_pepper, without_pepper);
    }

    #[test]
    fn test_token_length_and_format() {
        let token = generate_token();
        // 32 bytes base64url no-pad = ceil(32 * 4/3) = 43 chars
        assert_eq!(token.len(), 43);
        assert!(
            token
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn test_session_sliding_window() {
        let store = open_temp();
        let token = store.create_session("testuser").unwrap();
        // Manually set expires_at to 1 minute from now (short window).
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE sessions SET expires_at = datetime('now', '+1 minute') WHERE token = ?1",
                params![token],
            )
            .unwrap();
        }
        // Validate — should succeed and extend the expiry via sliding window.
        assert!(store.validate_session(&token).is_some());
        // Check that expires_at was extended beyond the 1-minute window.
        // The sliding window uses get_ttl_secs() which defaults to 30 days
        // but may be as low as 3600s if test_session_ttl_env_override runs
        // concurrently. Either way, the expiry should be > 60 seconds now.
        {
            let conn = store.conn.lock().unwrap();
            let secs_remaining: f64 = conn
                .query_row(
                    "SELECT (julianday(expires_at) - julianday('now')) * 86400 \
                     FROM sessions WHERE token = ?1",
                    params![token],
                    |row| row.get(0),
                )
                .unwrap();
            // Even with the minimum TTL (3600s from the env override test),
            // the sliding window should extend well beyond 60 seconds.
            assert!(
                secs_remaining > 60.0,
                "expected sliding window to extend expiry beyond 1 min, got {secs_remaining}s"
            );
        }
    }

    #[test]
    fn test_session_ttl_env_override() {
        set_test_env("THEYOS_SESSION_TTL_SECS", "3600");
        let store = open_temp();
        let token = store.create_session("testuser").unwrap();
        // Check that the session expires in ~1 hour, not 30 days.
        {
            let conn = store.conn.lock().unwrap();
            let secs_remaining: f64 = conn
                .query_row(
                    "SELECT (julianday(expires_at) - julianday('now')) * 86400 \
                     FROM sessions WHERE token = ?1",
                    params![token],
                    |row| row.get(0),
                )
                .unwrap();
            // Should be roughly 3600 seconds (±5 seconds for execution time).
            assert!(
                secs_remaining < 3610.0 && secs_remaining > 3500.0,
                "expected ~3600s expiry, got {secs_remaining}s"
            );
        }
        // Clean up env var to avoid poisoning other tests.
        core_rs::env::remove_test_env("THEYOS_SESSION_TTL_SECS");
    }

    #[test]
    fn test_touch_expired_noop() {
        let store = open_temp();
        let token = store.create_session("testuser").unwrap();
        // Manually expire the session.
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE sessions SET expires_at = datetime('now', '-1 hour') WHERE token = ?1",
                params![token],
            )
            .unwrap();
        }
        // Validate returns None for expired sessions.
        assert!(store.validate_session(&token).is_none());
        // The expired session should NOT have been extended.
        {
            let conn = store.conn.lock().unwrap();
            let secs_remaining: f64 = conn
                .query_row(
                    "SELECT (julianday(expires_at) - julianday('now')) * 86400 \
                     FROM sessions WHERE token = ?1",
                    params![token],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                secs_remaining < 0.0,
                "expired session should still be expired, got {secs_remaining}s"
            );
        }
    }

    #[test]
    fn test_multiple_sessions_per_user() {
        let store = open_temp();
        let t1 = store.create_session("testuser").unwrap();
        let t2 = store.create_session("testuser").unwrap();
        assert_ne!(t1, t2);
        assert!(store.validate_session(&t1).is_some());
        assert!(store.validate_session(&t2).is_some());
        store.delete_session(&t1).unwrap();
        assert!(store.validate_session(&t1).is_none());
        assert!(store.validate_session(&t2).is_some());
    }
}
