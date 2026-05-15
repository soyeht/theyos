//! Destructive legacy-schema migration for Phase 1 household bootstrap.
//!
//! Pre-household dev/test installs carried user-affecting state in
//! `users`, `mobile_sessions`, and `invites`. Phase 1 intentionally wipes
//! those tables before the first household identity is created.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use tracing::info;

const LEGACY_TABLES: [&str; 3] = ["users", "mobile_sessions", "invites"];
const LEGACY_DROP_ORDER: [&str; 3] = ["invites", "mobile_sessions", "users"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyTable {
    pub name: String,
    pub row_count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacyDetection {
    pub tables: Vec<LegacyTable>,
}

impl LegacyDetection {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }

    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.tables.iter().map(|t| t.name.clone()).collect()
    }

    #[must_use]
    pub fn row_counts(&self) -> BTreeMap<String, u64> {
        self.tables
            .iter()
            .map(|t| (t.name.clone(), t.row_count))
            .collect()
    }
}

pub fn has_legacy_tables(conn: &Connection) -> rusqlite::Result<LegacyDetection> {
    let mut tables = Vec::new();
    for table in LEGACY_TABLES {
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            continue;
        }
        let row_count = count_rows(conn, table)?;
        tables.push(LegacyTable {
            name: table.to_string(),
            row_count,
        });
    }
    Ok(LegacyDetection { tables })
}

pub fn drop_legacy_atomic(
    conn: &mut Connection,
    detection: &LegacyDetection,
) -> rusqlite::Result<()> {
    drop_legacy_atomic_impl(conn, detection, None)
}

pub fn drop_legacy_at_path_if_present(db_path: &Path) -> rusqlite::Result<LegacyDetection> {
    if db_path != Path::new(":memory:") && !db_path.exists() {
        return Ok(LegacyDetection::default());
    }
    let mut conn = Connection::open(db_path)?;
    let detection = has_legacy_tables(&conn)?;
    if !detection.is_empty() {
        drop_legacy_atomic(&mut conn, &detection)?;
    }
    Ok(detection)
}

fn drop_legacy_atomic_impl(
    conn: &mut Connection,
    detection: &LegacyDetection,
    fail_after_drops: Option<usize>,
) -> rusqlite::Result<()> {
    if detection.is_empty() {
        return Ok(());
    }

    let tx = conn.transaction()?;
    let detected_names: std::collections::HashSet<&str> =
        detection.tables.iter().map(|t| t.name.as_str()).collect();
    for (idx, table) in LEGACY_DROP_ORDER
        .iter()
        .filter(|table| detected_names.contains(**table))
        .enumerate()
    {
        tx.execute(&format!("DROP TABLE IF EXISTS {table}"), [])?;
        if fail_after_drops == Some(idx + 1) {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    tx.commit()?;

    info!(
        stage = "migration.legacy_dropped",
        tables = ?detection.names(),
        row_counts = ?detection.row_counts(),
    );
    Ok(())
}

fn count_rows(conn: &Connection, table: &str) -> rusqlite::Result<u64> {
    let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    Ok(u64::try_from(count).unwrap_or(0))
}

/// Rollback test stays inline because it exercises `drop_legacy_atomic_impl`'s
/// `fail_after_drops` knob, which is module-private. Exposing it just to host
/// the test in `tests/` would weaken encapsulation of a fault-injection seam.
#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    fn create_table(conn: &Connection, table: &str, rows: usize) {
        conn.execute_batch(&format!(
            "CREATE TABLE {table} (id INTEGER PRIMARY KEY, value TEXT);"
        ))
        .unwrap();
        for i in 0..rows {
            conn.execute(
                &format!("INSERT INTO {table} (value) VALUES (?1)"),
                [format!("v{i}")],
            )
            .unwrap();
        }
    }

    fn table_exists(conn: &Connection, table: &str) -> bool {
        conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn rollback_restores_partial_drop_on_failure() {
        let mut conn = conn();
        create_table(&conn, "users", 1);
        create_table(&conn, "mobile_sessions", 1);
        let detection = has_legacy_tables(&conn).unwrap();

        let err = drop_legacy_atomic_impl(&mut conn, &detection, Some(1)).unwrap_err();
        assert!(matches!(err, rusqlite::Error::InvalidQuery));

        assert!(table_exists(&conn, "users"));
        assert!(table_exists(&conn, "mobile_sessions"));
    }
}
