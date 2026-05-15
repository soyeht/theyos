//! schema.rs — DDL and migrations for the jobs `SQLite` store.
//!
//! Intentional improvements over the Go JSON+flock implementation:
//!   - `SQLite` WAL mode for concurrent readers + single writer
//!   - `busy_timeout(5000)` prevents instant `SQLITE_BUSY` errors under contention
//!   - `BEGIN IMMEDIATE` in `claim_next_pending` serialises concurrent claimers
//!     atomically without requiring a filesystem advisory lock

use rusqlite::{Connection, Result};

/// SQL to create the jobs table.
pub const CREATE_JOBS: &str = "
CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    instance_id  TEXT NOT NULL DEFAULT '',
    payload      TEXT NOT NULL DEFAULT '{}',
    result       TEXT,
    error        TEXT,
    message      TEXT,
    actor        TEXT,
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    completed_at TEXT,
    retries      INTEGER NOT NULL DEFAULT 0
)";

/// Apply DDL and migrations to an already-configured connection.
///
/// WAL mode and `busy_timeout` are set by `core_rs::db::open_wal()` at open
/// time.  Idempotent — safe to call on every `Store::new`.
pub fn apply(conn: &Connection) -> Result<()> {
    // NOTE: WAL mode + busy_timeout are set by `core_rs::db::open_wal()` at
    // connection open time.  This function only handles DDL and migrations.

    // Create table if not present.
    conn.execute_batch(CREATE_JOBS)?;
    // Migration: add actor column if missing (for existing databases).
    let _ = conn.execute_batch("ALTER TABLE jobs ADD COLUMN actor TEXT");
    Ok(())
}
