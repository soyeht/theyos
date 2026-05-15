//! `SQLite` helpers — consolidated WAL + `busy_timeout` boilerplate.
//!
//! Six crates independently opened connections with the same PRAGMA
//! sequence. This module provides a single `open_wal()` entry point.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

/// Open a `SQLite` database with WAL journal mode and 5-second busy timeout.
///
/// This is the standard configuration used across all theyOS crates.
///
/// # Errors
///
/// Returns a `rusqlite::Error` if the database cannot be opened or the
/// PRAGMAs cannot be applied.
pub fn open_wal(path: &Path) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
    Ok(conn)
}

/// Open a WAL-mode database and wrap it in a `Mutex` for thread-safe access.
///
/// # Errors
///
/// Returns a `rusqlite::Error` if the database cannot be opened.
pub fn open_wal_mutex(path: &Path) -> Result<Mutex<Connection>, rusqlite::Error> {
    open_wal(path).map(Mutex::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_wal_in_memory() {
        // Use a temp file to test WAL mode (in-memory doesn't support WAL)
        let dir = tempfile::tempdir().expect("create tempdir");
        let tmp = dir.path().join("test_wal.db");
        let conn = open_wal(&tmp).unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let timeout: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(timeout, 5000);
    }

    #[test]
    fn open_wal_mutex_works() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let tmp = dir.path().join("test_wal_mutex.db");
        let mtx = open_wal_mutex(&tmp).unwrap();
        let conn = mtx.lock().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    }
}
