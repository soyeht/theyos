use rusqlite::Connection;

fn table_exists(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
        [table],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn legacy_tables_are_dropped_before_identity_bootstrap_and_tokens_are_rejected() {
    let td = tempfile::tempdir().unwrap();
    let db_path = td.path().join("theyos.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT);
         CREATE TABLE mobile_sessions (token TEXT PRIMARY KEY, username TEXT);
         CREATE TABLE invites (id TEXT PRIMARY KEY, token TEXT);
         INSERT INTO users VALUES ('u1', 'legacy');
         INSERT INTO mobile_sessions VALUES ('legacy-token', 'legacy');
         INSERT INTO invites VALUES ('i1', 'invite-token');",
    )
    .unwrap();
    drop(conn);

    let detection = store_rs::drop_legacy_at_path_if_present(&db_path).unwrap();
    assert_eq!(
        detection.names(),
        vec!["users", "mobile_sessions", "invites"]
    );

    let conn = Connection::open(&db_path).unwrap();
    assert!(!table_exists(&conn, "users"));
    assert!(!table_exists(&conn, "mobile_sessions"));
    assert!(!table_exists(&conn, "invites"));
    drop(conn);

    let identity = household_rs::bootstrap_or_load(
        td.path(),
        household_rs::BootstrapOpts {
            household_name: "Sample Home".into(),
            hostname_label: Some("studio-mac".into()),
        },
        household_rs::KeyBackingPolicy::ForceSoftware,
    )
    .unwrap();
    assert!(identity.record.hh_id.as_str().starts_with("hh_"));

    let sessions = server_rs::mobile_token::MobileSessionDb::open(db_path.to_str().unwrap())
        .expect("recreate empty mobile session store");
    assert!(sessions.validate_session("legacy-token").is_none());
}
