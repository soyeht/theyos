//! backup-rs — `SQLite` backup management for theyOS.
//!
//! Uses `VACUUM INTO` to create point-in-time copies of the source database,
//! logs each backup attempt to a `backup_log` table in the source DB, and
//! prunes old backups beyond the configured retention count.

use core_rs::error::{AppError, ErrorCode};
use core_rs::time::unix_to_datetime;
use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("db error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("backup failed: {0}")]
    Failed(String),
}

impl AppError for BackupError {
    fn code(&self) -> ErrorCode {
        ErrorCode::Internal
    }
}

// ─── Wire type ────────────────────────────────────────────────────────────────

/// A row from the `backup_log` table.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BackupEntry {
    pub id: i64,
    pub backup_path: String,
    pub backup_size_bytes: Option<i64>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
}

// ─── Manager ──────────────────────────────────────────────────────────────────

/// Manages periodic `SQLite` backups via `VACUUM INTO`.
pub struct BackupManager {
    /// Path to the source `SQLite` database.
    db_path: String,
    /// Directory where backup files are written.
    backup_dir: PathBuf,
    /// How many completed backups to retain (older ones are pruned).
    retain_count: usize,
}

impl BackupManager {
    /// Create a new manager.  The backup directory is created if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the backup directory cannot be created.
    pub fn new(db_path: &str, backup_dir: &str, retain_count: usize) -> Result<Self, BackupError> {
        std::fs::create_dir_all(backup_dir)?;
        Ok(Self {
            db_path: db_path.to_string(),
            backup_dir: PathBuf::from(backup_dir),
            retain_count,
        })
    }

    /// Run a backup now.
    ///
    /// 1. Generates a timestamped filename.
    /// 2. Logs the start of the backup to `backup_log`.
    /// 3. Executes `VACUUM INTO '<path>'`.
    /// 4. Updates the log row with the outcome.
    /// 5. Prunes old backups beyond `retain_count`.
    ///
    /// Returns the absolute path to the backup file on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened, the `VACUUM INTO`
    /// command fails, or the backup log cannot be updated.
    pub fn backup(&self) -> Result<String, BackupError> {
        let now = chrono_now_str();
        let filename = format!("backup-{now}.db");
        let backup_path = self.backup_dir.join(&filename);
        let backup_path_str = backup_path
            .to_str()
            .ok_or_else(|| BackupError::Failed("backup path is not valid UTF-8".into()))?
            .to_string();

        let conn = core_rs::db::open_wal(std::path::Path::new(&self.db_path))?;

        // Insert start log row.
        conn.execute(
            "INSERT INTO backup_log (backup_path, status, started_at) \
             VALUES (?1, 'running', CURRENT_TIMESTAMP)",
            params![backup_path_str],
        )?;
        let log_id = conn.last_insert_rowid();

        // VACUUM INTO — escape single quotes in path (paranoia).
        let escaped = backup_path_str.replace('\'', "''");
        match conn.execute_batch(&format!("VACUUM INTO '{escaped}'")) {
            Ok(()) => {
                // NOTE: file sizes in practice are always < i64::MAX on Linux (8 EiB limit)
                #[allow(clippy::cast_possible_wrap)]
                let size = std::fs::metadata(&backup_path).map(|m| m.len() as i64).ok();
                conn.execute(
                    "UPDATE backup_log \
                     SET status='completed', completed_at=CURRENT_TIMESTAMP, \
                         backup_size_bytes=?1 \
                     WHERE id=?2",
                    params![size, log_id],
                )?;
                // Prune old backups.
                self.prune(&conn)?;
                Ok(backup_path_str)
            }
            Err(e) => {
                let _ = conn.execute(
                    "UPDATE backup_log \
                     SET status='failed', completed_at=CURRENT_TIMESTAMP, \
                         error_message=?1 \
                     WHERE id=?2",
                    params![e.to_string(), log_id],
                );
                Err(BackupError::Db(e))
            }
        }
    }

    /// List recent backup log entries, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or the query fails.
    pub fn list_backups(&self, limit: usize) -> Result<Vec<BackupEntry>, BackupError> {
        let conn = core_rs::db::open_wal(std::path::Path::new(&self.db_path))?;
        let mut stmt = conn.prepare(
            "SELECT id, backup_path, backup_size_bytes, started_at, completed_at, \
                    status, error_message \
             FROM backup_log \
             ORDER BY started_at DESC \
             LIMIT ?1",
        )?;
        // NOTE: limit is a UI-provided page size; values exceeding i64::MAX are not realistic
        #[allow(clippy::cast_possible_wrap)]
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(BackupEntry {
                id: row.get(0)?,
                backup_path: row.get(1)?,
                backup_size_bytes: row.get(2)?,
                started_at: row.get(3)?,
                completed_at: row.get(4)?,
                status: row.get(5)?,
                error_message: row.get(6)?,
            })
        })?;

        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Delete completed backups beyond `retain_count`, oldest first.
    fn prune(&self, conn: &Connection) -> Result<(), BackupError> {
        let mut stmt = conn.prepare(
            "SELECT id, backup_path FROM backup_log \
             WHERE status = 'completed' \
             ORDER BY started_at ASC",
        )?;
        let entries: Vec<(i64, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(std::result::Result::ok)
            .collect();

        if entries.len() <= self.retain_count {
            return Ok(());
        }

        let to_delete = &entries[..entries.len() - self.retain_count];
        for (id, path) in to_delete {
            let _ = std::fs::remove_file(path); // ignore missing files
            conn.execute("DELETE FROM backup_log WHERE id = ?1", params![id])?;
        }
        Ok(())
    }
}

// ─── Timestamp helpers ────────────────────────────────────────────────────────

/// Returns the current UTC time as a filename-safe string, e.g.
/// `"2026-01-15T14-30-00-123456789"` (hyphens instead of colons, nanoseconds
/// appended to guarantee uniqueness even when called multiple times per second).
#[must_use]
pub fn chrono_now_str() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let nanos = dur.subsec_nanos();
    let (y, mo, d, h, mi, s) = unix_to_datetime(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}-{mi:02}-{s:02}-{nanos:09}")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_db(dir: &TempDir) -> String {
        let db_path = dir.path().join("test.db").to_str().unwrap().to_string();
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r"
            CREATE TABLE IF NOT EXISTS backup_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                backup_path TEXT NOT NULL,
                backup_size_bytes INTEGER,
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME,
                status TEXT DEFAULT 'running',
                error_message TEXT
            );
            ",
        )
        .unwrap();
        db_path
    }

    #[test]
    fn test_backup_creates_file() {
        let dir = TempDir::new().unwrap();
        let db_path = setup_db(&dir);
        let backup_dir = dir.path().join("backups").to_str().unwrap().to_string();

        let mgr = BackupManager::new(&db_path, &backup_dir, 7).unwrap();
        let path = mgr.backup().unwrap();
        assert!(
            std::path::Path::new(&path).exists(),
            "backup file not found: {path}"
        );
    }

    #[test]
    fn test_backup_log_recorded() {
        let dir = TempDir::new().unwrap();
        let db_path = setup_db(&dir);
        let backup_dir = dir.path().join("backups").to_str().unwrap().to_string();

        let mgr = BackupManager::new(&db_path, &backup_dir, 7).unwrap();
        mgr.backup().unwrap();

        let entries = mgr.list_backups(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, "completed");
        assert!(entries[0].backup_size_bytes.is_some());
    }

    #[test]
    fn test_prune_keeps_retain_count() {
        let dir = TempDir::new().unwrap();
        let db_path = setup_db(&dir);
        let backup_dir = dir.path().join("backups").to_str().unwrap().to_string();

        let mgr = BackupManager::new(&db_path, &backup_dir, 2).unwrap();

        // Run 4 backups — only 2 should be retained.
        for _ in 0..4 {
            mgr.backup().unwrap();
            // Sleep briefly so timestamps differ.
            std::thread::sleep(std::time::Duration::from_millis(15));
        }

        let entries = mgr.list_backups(100).unwrap();
        assert_eq!(
            entries.len(),
            2,
            "expected 2 backups after pruning, got {}",
            entries.len()
        );
        for e in &entries {
            assert_eq!(e.status, "completed");
        }
    }

    #[test]
    fn test_list_backups_empty() {
        let dir = TempDir::new().unwrap();
        let db_path = setup_db(&dir);
        let backup_dir = dir.path().join("backups").to_str().unwrap().to_string();

        let mgr = BackupManager::new(&db_path, &backup_dir, 7).unwrap();
        let entries = mgr.list_backups(10).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_backup_dir_created() {
        let dir = TempDir::new().unwrap();
        let db_path = setup_db(&dir);
        let backup_dir = dir
            .path()
            .join("nested")
            .join("backup_dir")
            .to_str()
            .unwrap()
            .to_string();

        // Dir does not exist yet — BackupManager::new should create it.
        BackupManager::new(&db_path, &backup_dir, 3).unwrap();
        assert!(std::path::Path::new(&backup_dir).is_dir());
    }
}
