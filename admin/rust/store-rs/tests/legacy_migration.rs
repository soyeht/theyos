use rusqlite::Connection;
use store_rs::{drop_legacy_at_path_if_present, drop_legacy_atomic, has_legacy_tables};

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
fn detects_no_legacy_tables() {
    let conn = conn();
    let detection = has_legacy_tables(&conn).unwrap();
    assert!(detection.is_empty());
}

#[test]
fn detects_each_legacy_table_with_row_count() {
    let conn = conn();
    create_table(&conn, "users", 2);
    create_table(&conn, "mobile_sessions", 3);
    create_table(&conn, "invites", 1);

    let detection = has_legacy_tables(&conn).unwrap();
    assert_eq!(
        detection.names(),
        vec!["users", "mobile_sessions", "invites"]
    );
    assert_eq!(detection.row_counts()["users"], 2);
    assert_eq!(detection.row_counts()["mobile_sessions"], 3);
    assert_eq!(detection.row_counts()["invites"], 1);
}

#[test]
fn drops_legacy_tables_atomically() {
    let mut conn = conn();
    create_table(&conn, "users", 1);
    create_table(&conn, "invites", 1);
    conn.execute_batch("CREATE TABLE instances (id TEXT PRIMARY KEY);")
        .unwrap();
    let detection = has_legacy_tables(&conn).unwrap();

    drop_legacy_atomic(&mut conn, &detection).unwrap();

    assert!(!table_exists(&conn, "users"));
    assert!(!table_exists(&conn, "invites"));
    assert!(table_exists(&conn, "instances"));
}

#[test]
fn path_helper_is_noop_when_db_absent() {
    let td = tempfile::tempdir().unwrap();
    let missing = td.path().join("missing.db");
    let detection = drop_legacy_at_path_if_present(&missing).unwrap();
    assert!(detection.is_empty());
    assert!(!missing.exists());
}
