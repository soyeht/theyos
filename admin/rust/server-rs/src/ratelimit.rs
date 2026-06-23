//! Rate limiter — inlined from the former ratelimit-rs crate.
//!
//! # Design
//!
//!   - **Always UTC**: truncated to the hour, matching `SQLite`'s
//!     `datetime('now')` (UTC). This avoids stale-row cleanup issues on
//!     non-UTC machines.
//!
//!   - **Atomic upsert**: `INSERT … ON CONFLICT DO UPDATE SET count = count + 1
//!     RETURNING count` avoids SELECT→UPDATE race conditions under concurrent
//!     callers.
//!
//!   - **WAL mode + `busy_timeout`**: concurrent reads while a writer is active,
//!     no spurious `SQLITE_BUSY` errors.

use core_rs::time::civil_from_days;
use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("lock poisoned")]
    Lock,
    #[error("{0}")]
    Internal(String),
}

impl core_rs::error::AppError for RateLimitError {
    fn code(&self) -> core_rs::error::ErrorCode {
        core_rs::error::ErrorCode::Internal
    }
}

// ─── Public types ─────────────────────────────────────────────────────────────

/// Rate limiter backed by `SQLite`.
pub struct Limiter {
    conn: Mutex<Connection>,
    requests_per_hour: i64,
    /// Optional per-action hourly limit overrides. An action absent from this
    /// map uses the global `requests_per_hour`. Empty by default, so a limiter
    /// built with `new` alone behaves exactly as before this field existed.
    per_action: HashMap<String, i64>,
}

impl Limiter {
    /// Create a new limiter. If `requests_per_hour <= 0`, defaults to 30.
    ///
    /// The database at `db_path` is opened (or created) with WAL mode and a
    /// 5-second busy timeout. The `rate_limits` table is created if missing.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or the schema cannot
    /// be initialized.
    pub fn new(db_path: &str, requests_per_hour: i64) -> Result<Self, RateLimitError> {
        let conn =
            core_rs::db::open_wal(std::path::Path::new(db_path)).map_err(RateLimitError::Db)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                count INTEGER DEFAULT 1,
                window_start TEXT NOT NULL,
                UNIQUE(user_id, action, window_start)
            );
            CREATE INDEX IF NOT EXISTS idx_rate_limits_user_action
                ON rate_limits(user_id, action);",
        )
        .map_err(RateLimitError::Db)?;

        let rph = if requests_per_hour <= 0 {
            30
        } else {
            requests_per_hour
        };

        Ok(Limiter {
            conn: Mutex::new(conn),
            requests_per_hour: rph,
            per_action: HashMap::new(),
        })
    }

    /// Additively set a per-action hourly limit override (builder style).
    ///
    /// Actions without an override fall back to the global `requests_per_hour`
    /// passed to [`Limiter::new`]. A non-positive `limit` is ignored (the action
    /// keeps the global limit), mirroring `new`'s `<= 0` handling so an override
    /// can never silently make an action unlimited or always-denied.
    ///
    /// This is purely additive: a `Limiter` built with `new` alone (no calls to
    /// this method) has an empty override map and behaves identically to before
    /// per-action limits existed.
    #[must_use]
    pub fn with_action_limit(mut self, action: impl Into<String>, limit: i64) -> Self {
        if limit > 0 {
            self.per_action.insert(action.into(), limit);
        }
        self
    }

    /// The effective hourly limit for `action`: its override if one is set, else
    /// the global `requests_per_hour`.
    fn limit_for(&self, action: &str) -> i64 {
        self.per_action
            .get(action)
            .copied()
            .unwrap_or(self.requests_per_hour)
    }

    /// Check whether a request is allowed for the given user/action.
    ///
    /// Returns `Ok(true)` if under the limit, `Ok(false)` if the limit is
    /// exceeded.
    ///
    /// Uses an atomic `INSERT … ON CONFLICT DO UPDATE SET count = count + 1
    /// RETURNING count` to avoid the Go race condition.
    ///
    /// # Errors
    ///
    /// Returns an error if the mutex is poisoned or the database query fails.
    pub fn check(&self, user_id: &str, action: &str) -> Result<bool, RateLimitError> {
        let conn = self.conn.lock().map_err(|_| RateLimitError::Lock)?;
        let window = current_window_utc();

        // Clean up old entries (>1 hour old).
        conn.execute(
            "DELETE FROM rate_limits WHERE window_start < ?",
            params![one_hour_ago_utc()],
        )
        .map_err(RateLimitError::Db)?;

        // Atomic upsert: insert with count=1, or increment existing.
        // RETURNING gives us the post-increment count in one round-trip.
        let count: i64 = conn
            .query_row(
                "INSERT INTO rate_limits (user_id, action, count, window_start)
                 VALUES (?1, ?2, 1, ?3)
                 ON CONFLICT(user_id, action, window_start)
                 DO UPDATE SET count = count + 1
                 RETURNING count",
                params![user_id, action, window],
                |row| row.get(0),
            )
            .map_err(RateLimitError::Db)?;

        // count is the value *after* increment. If count > limit, deny.
        Ok(count <= self.limit_for(action))
    }

    /// Return remaining requests for the given user/action in the current window.
    ///
    /// # Errors
    ///
    /// Returns an error if the mutex is poisoned.
    pub fn get_remaining(&self, user_id: &str, action: &str) -> Result<i64, RateLimitError> {
        let conn = self.conn.lock().map_err(|_| RateLimitError::Lock)?;
        let window = current_window_utc();

        let count: i64 = conn
            .query_row(
                "SELECT count FROM rate_limits
                 WHERE user_id = ? AND action = ? AND window_start = ?",
                params![user_id, action, window],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let remaining = self.limit_for(action) - count;
        Ok(if remaining < 0 { 0 } else { remaining })
    }
}

// ─── Time helpers ─────────────────────────────────────────────────────────────

/// Current UTC hour as "YYYY-MM-DD HH:00:00" — the window key.
fn current_window_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_window(secs)
}

/// One hour ago in the same format, used for cleanup.
fn one_hour_ago_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_window(secs.saturating_sub(3600))
}

/// Format a unix timestamp (truncated to the hour) as "YYYY-MM-DD HH:00:00".
fn format_window(unix_secs: u64) -> String {
    // Truncate to the start of the hour.
    let truncated = unix_secs - (unix_secs % 3600);

    // Convert to calendar date/time (UTC).
    // NOTE: unix_secs / 86400 is always a non-negative value; safely fits i64 for
    // any date in the foreseeable future (max ~106 trillion days for u64::MAX)
    #[allow(clippy::cast_possible_wrap)]
    let days = (truncated / 86400) as i64;
    let time_of_day = truncated % 86400;
    let hour = time_of_day / 3600;

    // Days since 1970-01-01 → (year, month, day)
    let (y, m, d) = civil_from_days(days);

    format!("{y:04}-{m:02}-{d:02} {hour:02}:00:00")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_limiter(rph: i64) -> (Limiter, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let limiter = Limiter::new(db_path.to_str().unwrap(), rph).unwrap();
        (limiter, db_path)
    }

    fn tmp_limiter_built(rph: i64, overrides: &[(&str, i64)]) -> (Limiter, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let mut limiter = Limiter::new(db_path.to_str().unwrap(), rph).unwrap();
        for (action, limit) in overrides {
            limiter = limiter.with_action_limit(*action, *limit);
        }
        (limiter, db_path)
    }

    #[test]
    fn test_first_request_allowed() {
        let (limiter, _) = tmp_limiter(10);
        let allowed = limiter.check("user-a", "create").unwrap();
        assert!(allowed);
    }

    #[test]
    fn test_under_limit_all_allowed() {
        let (limiter, _) = tmp_limiter(5);
        for i in 0..5 {
            let allowed = limiter.check("user-b", "create").unwrap();
            assert!(allowed, "request {i} should be allowed");
        }
    }

    #[test]
    fn test_over_limit_denied() {
        let (limiter, _) = tmp_limiter(3);
        for _ in 0..3 {
            assert!(limiter.check("user-c", "create").unwrap());
        }
        // 4th should be denied
        assert!(!limiter.check("user-c", "create").unwrap());
    }

    #[test]
    fn test_different_users_independent() {
        let (limiter, _) = tmp_limiter(2);
        // Exhaust alice's quota
        assert!(limiter.check("alice", "create").unwrap());
        assert!(limiter.check("alice", "create").unwrap());
        assert!(!limiter.check("alice", "create").unwrap());
        // Bob should still be allowed
        assert!(limiter.check("bob", "create").unwrap());
    }

    #[test]
    fn test_different_actions_independent() {
        let (limiter, _) = tmp_limiter(2);
        assert!(limiter.check("user-d", "create").unwrap());
        assert!(limiter.check("user-d", "create").unwrap());
        assert!(!limiter.check("user-d", "create").unwrap());
        // Different action is independent
        assert!(limiter.check("user-d", "delete").unwrap());
    }

    #[test]
    fn test_remaining_fresh() {
        let (limiter, _) = tmp_limiter(10);
        let remaining = limiter.get_remaining("user-e", "create").unwrap();
        assert_eq!(remaining, 10);
    }

    #[test]
    fn test_remaining_after_requests() {
        let (limiter, _) = tmp_limiter(10);
        for _ in 0..3 {
            limiter.check("user-f", "create").unwrap();
        }
        let remaining = limiter.get_remaining("user-f", "create").unwrap();
        assert_eq!(remaining, 7);
    }

    #[test]
    fn test_remaining_at_zero() {
        let (limiter, _) = tmp_limiter(5);
        for _ in 0..5 {
            limiter.check("user-g", "create").unwrap();
        }
        let remaining = limiter.get_remaining("user-g", "create").unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_remaining_cannot_go_negative() {
        let (limiter, _) = tmp_limiter(2);
        for _ in 0..5 {
            limiter.check("user-h", "create").unwrap();
        }
        let remaining = limiter.get_remaining("user-h", "create").unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_default_requests_per_hour() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let limiter = Limiter::new(db_path.to_str().unwrap(), 0).unwrap();
        // Default is 30
        for i in 0..30 {
            assert!(
                limiter.check("user-i", "create").unwrap(),
                "request {i} should be allowed"
            );
        }
        assert!(!limiter.check("user-i", "create").unwrap());
    }

    #[test]
    fn test_negative_requests_per_hour_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let limiter = Limiter::new(db_path.to_str().unwrap(), -5).unwrap();
        // Default is 30
        let remaining = limiter.get_remaining("user-j", "create").unwrap();
        assert_eq!(remaining, 30);
    }

    #[test]
    fn test_window_format() {
        // Verify format_window produces correct format
        // 2025-01-15 12:30:00 UTC = 1736942400 + 30*60 = 1736944200
        // Truncated to hour: 2025-01-15 12:00:00
        let result = format_window(1_736_942_400 + 1800);
        assert_eq!(result, "2025-01-15 12:00:00");
    }

    #[test]
    fn test_civil_from_days() {
        // 1970-01-01 = day 0
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2025-01-15 = day 20103
        assert_eq!(civil_from_days(20103), (2025, 1, 15));
    }

    // ─── Per-action threshold overrides (P7-C PR-B, additive, behavior-neutral) ──

    #[test]
    fn no_override_uses_global_for_every_action() {
        // Behaviour-neutral: with no per-action override, distinct actions all
        // use the global limit — exactly as before the override map existed.
        let (limiter, _) = tmp_limiter(3);
        for _ in 0..3 {
            assert!(limiter.check("u", "alpha").unwrap());
            assert!(limiter.check("u", "beta").unwrap());
        }
        assert!(!limiter.check("u", "alpha").unwrap());
        assert!(!limiter.check("u", "beta").unwrap());
        assert_eq!(limiter.get_remaining("u", "alpha").unwrap(), 0);
    }

    #[test]
    fn action_override_is_stricter_than_global() {
        let (limiter, _) = tmp_limiter_built(30, &[("strict", 2)]);
        assert!(limiter.check("u", "strict").unwrap());
        assert!(limiter.check("u", "strict").unwrap());
        assert!(
            !limiter.check("u", "strict").unwrap(),
            "3rd request must be denied under override=2"
        );
    }

    #[test]
    fn action_without_override_falls_back_to_global() {
        let (limiter, _) = tmp_limiter_built(30, &[("strict", 2)]);
        for i in 0..30 {
            assert!(
                limiter.check("u", "other").unwrap(),
                "request {i} on the un-overridden action must use the global limit"
            );
        }
        assert!(!limiter.check("u", "other").unwrap());
    }

    #[test]
    fn overridden_and_global_actions_are_independent() {
        let (limiter, _) = tmp_limiter_built(30, &[("strict", 1)]);
        assert!(limiter.check("u", "strict").unwrap());
        assert!(!limiter.check("u", "strict").unwrap());
        // Exhausting the overridden action does not affect the global one.
        assert!(limiter.check("u", "other").unwrap());
    }

    #[test]
    fn action_override_can_be_more_lenient_than_global() {
        let (limiter, _) = tmp_limiter_built(2, &[("big", 5)]);
        for i in 0..5 {
            assert!(
                limiter.check("u", "big").unwrap(),
                "request {i} should be allowed under override=5"
            );
        }
        assert!(!limiter.check("u", "big").unwrap());
        // The global (2) still applies to un-overridden actions.
        assert!(limiter.check("u", "small").unwrap());
        assert!(limiter.check("u", "small").unwrap());
        assert!(!limiter.check("u", "small").unwrap());
    }

    #[test]
    fn get_remaining_respects_action_override() {
        let (limiter, _) = tmp_limiter_built(30, &[("strict", 3)]);
        assert_eq!(limiter.get_remaining("u", "strict").unwrap(), 3);
        limiter.check("u", "strict").unwrap();
        assert_eq!(limiter.get_remaining("u", "strict").unwrap(), 2);
        // The un-overridden action reports the global remaining.
        assert_eq!(limiter.get_remaining("u", "other").unwrap(), 30);
    }

    #[test]
    fn non_positive_override_is_ignored_and_keeps_global() {
        let (limiter, _) = tmp_limiter_built(4, &[("zero", 0), ("neg", -7)]);
        // Both ignored → both keep the global 4 (never always-denied or unlimited).
        for _ in 0..4 {
            assert!(limiter.check("u", "zero").unwrap());
            assert!(limiter.check("u", "neg").unwrap());
        }
        assert!(!limiter.check("u", "zero").unwrap());
        assert!(!limiter.check("u", "neg").unwrap());
    }

    #[test]
    fn global_default_still_applies_when_overrides_present() {
        // requests_per_hour <= 0 still defaults to 30 for un-overridden actions.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let limiter = Limiter::new(db_path.to_str().unwrap(), 0)
            .unwrap()
            .with_action_limit("strict", 2);
        assert_eq!(limiter.get_remaining("u", "other").unwrap(), 30);
        assert_eq!(limiter.get_remaining("u", "strict").unwrap(), 2);
    }
}
