#![cfg(test)]

use super::*;

fn open_temp() -> InstanceDb {
    InstanceDb::open(":memory:").expect("open :memory:")
}

fn instance_column_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('instances') WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn household_scope_migration_repairs_partial_columns() {
    for schema in [
        "CREATE TABLE instances (
                id TEXT PRIMARY KEY,
                created_at DATETIME,
                deleted_at DATETIME,
                household_id TEXT
            );",
        "CREATE TABLE instances (
                id TEXT PRIMARY KEY,
                created_at DATETIME,
                deleted_at DATETIME,
                household_machine_id TEXT
            );",
    ] {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(schema).unwrap();

        InstanceDb::migrate_household_scope(&conn).unwrap();

        assert!(instance_column_exists(&conn, "household_id"));
        assert!(instance_column_exists(&conn, "household_machine_id"));
        let index_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master \
                     WHERE type = 'index' AND name = 'idx_instances_household_scope'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(index_exists);
    }
}

fn foo_inst() -> NewInstance<'static> {
    NewInstance {
        id: "inst-foo",
        name: "foo",
        container: "picoclaw-foo",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    }
}

#[test]
fn test_insert_and_get() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    let row = db.get("inst-foo").unwrap().expect("row");
    assert_eq!(row.id, "inst-foo");
    assert_eq!(row.name, "foo");
    assert_eq!(row.status, InstanceStatus::Provisioning);
    assert_eq!(row.host_port, None);
}

#[test]
fn fresh_row_has_no_provisioning_failure_code() {
    // The migration ran (else the SELECT would fail); a fresh row is NULL.
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    assert_eq!(
        db.get("inst-foo")
            .unwrap()
            .unwrap()
            .provisioning_failure_code,
        None
    );
}

#[test]
fn set_and_clear_provisioning_failure_code() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.set_provisioning_failure_code("inst-foo", Some("host_vm_limit_reached"))
        .unwrap();
    assert_eq!(
        db.get("inst-foo")
            .unwrap()
            .unwrap()
            .provisioning_failure_code,
        Some("host_vm_limit_reached".to_string())
    );
    db.set_provisioning_failure_code("inst-foo", None).unwrap();
    assert_eq!(
        db.get("inst-foo")
            .unwrap()
            .unwrap()
            .provisioning_failure_code,
        None
    );
}

#[test]
fn update_status_clears_failure_code_then_restamp() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.set_provisioning_failure_code("inst-foo", Some("snapshot_failed"))
        .unwrap();
    // Any status transition clears the stale code.
    db.update_status(&StatusUpdate {
        id: "inst-foo",
        status: InstanceStatus::Active,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .unwrap();
    assert_eq!(
        db.get("inst-foo")
            .unwrap()
            .unwrap()
            .provisioning_failure_code,
        None
    );
    // The mark_failed order: update_status(Failed) clears, then re-stamp.
    db.update_status(&StatusUpdate {
        id: "inst-foo",
        status: InstanceStatus::Failed,
        message: "",
        error: "boom",
        job_id: "",
        phase: "",
    })
    .unwrap();
    db.set_provisioning_failure_code("inst-foo", Some("vm_start_failed"))
        .unwrap();
    let row = db.get("inst-foo").unwrap().unwrap();
    assert_eq!(
        row.provisioning_failure_code,
        Some("vm_start_failed".to_string())
    );
    assert_eq!(row.provisioning_error, Some("boom".to_string()));
}

#[test]
fn test_find_conflict() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    // Conflict by id
    assert!(db.find_conflict("inst-foo", "other").unwrap().is_some());
    // Conflict by name
    assert!(db.find_conflict("inst-other", "foo").unwrap().is_some());
    // No conflict
    assert!(db.find_conflict("inst-new", "new").unwrap().is_none());
}

#[test]
fn test_find_conflict_different_name_no_match() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    // A different id and name should NOT conflict
    assert!(db.find_conflict("inst-bar", "bar").unwrap().is_none());
    // But same name should still conflict
    assert!(db.find_conflict("inst-bar", "foo").unwrap().is_some());
}

#[test]
fn test_update_status() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.update_status(&StatusUpdate {
        id: "inst-foo",
        status: InstanceStatus::Active,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .unwrap();
    let row = db.get("inst-foo").unwrap().expect("row");
    assert_eq!(row.status, InstanceStatus::Active);
    assert_eq!(row.provisioning_message, None);
}

#[test]
fn test_update_port() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.update_port("inst-foo", 35000).unwrap();
    let port = db.get_host_port("inst-foo").unwrap();
    assert_eq!(port, 35000);
}

#[test]
fn test_clear_port() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.update_port("inst-foo", 35000).unwrap();
    db.clear_port("inst-foo").unwrap();
    let row = db.get("inst-foo").unwrap().expect("row");
    assert_eq!(row.host_port, None);
}

#[test]
fn test_list() {
    let db = open_temp();
    db.insert(&NewInstance {
        id: "inst-a",
        name: "alpha",
        container: "picoclaw-alpha",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-b",
        name: "beta",
        container: "picoclaw-beta",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();
    let rows = db.list().unwrap();
    assert_eq!(rows.len(), 2);
}

#[test]
fn household_list_includes_only_matching_active_household_rows() {
    let db = open_temp();
    db.insert(&NewInstance {
        id: "inst-household-alpha",
        name: "household-alpha",
        container: "picoclaw-household-alpha",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_alpha"),
        household_machine_id: Some("m_alpha"),
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-household-beta",
        name: "household-beta",
        container: "picoclaw-household-beta",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_beta"),
        household_machine_id: Some("m_beta"),
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-legacy",
        name: "legacy",
        container: "picoclaw-legacy",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-household-deleted",
        name: "household-deleted",
        container: "picoclaw-household-deleted",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_alpha"),
        household_machine_id: Some("m_alpha"),
    })
    .unwrap();
    db.soft_delete("inst-household-deleted").unwrap();

    let rows = db.list_for_household("hh_alpha").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, "inst-household-alpha");
    assert_eq!(rows[0].household_id.as_deref(), Some("hh_alpha"));
    assert_eq!(rows[0].household_machine_id.as_deref(), Some("m_alpha"));
}

#[test]
fn household_status_accepts_matching_household_independent_of_machine_metadata() {
    let db = open_temp();
    db.insert(&NewInstance {
        id: "inst-household-alpha",
        name: "household-alpha",
        container: "picoclaw-household-alpha",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_alpha"),
        household_machine_id: None,
    })
    .unwrap();

    let row = db
        .get_for_household_status("inst-household-alpha", "hh_alpha")
        .unwrap()
        .expect("matching household row");
    assert_eq!(row.id, "inst-household-alpha");
}

#[test]
fn household_status_rejects_unscoped_rows() {
    // INVERTED from `household_status_accepts_legacy_unscoped_rows` by the
    // 2026-08 security verdict (option (b), strict): a row without
    // household_id belongs to NO household. Status and listing must agree
    // by rule — unscoped rows are hidden from both until stamped via
    // `stamp_mac_host_household`. Kept (not deleted) so the rule
    // change is visible in review.
    let db = open_temp();
    db.insert(&NewInstance {
        id: "inst-legacy",
        name: "legacy",
        container: "picoclaw-legacy",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();

    assert!(
        db.get_for_household_status("inst-legacy", "hh_alpha")
            .unwrap()
            .is_none(),
        "unscoped rows must be hidden from household status under the strict rule"
    );
}

#[test]
fn household_status_and_list_agree_for_the_same_row() {
    // The two read paths must answer the SAME question for the SAME row —
    // the original bug was status accepting rows the listing excluded.
    let db = open_temp();
    let insert = |id: &str, hh: Option<&str>, m: Option<&str>| {
        db.insert(&NewInstance {
            id,
            name: id,
            container: &format!("c-{id}"),
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: hh,
            household_machine_id: m,
        })
        .unwrap();
    };
    insert("inst-scoped", Some("hh_alpha"), Some("m_alpha"));
    insert("inst-unscoped", None, None);
    insert("inst-machine-only", None, Some("m_alpha"));
    insert("inst-other-household", Some("hh_beta"), Some("m_beta"));
    insert("inst-deleted", Some("hh_alpha"), Some("m_alpha"));
    db.soft_delete("inst-deleted").unwrap();

    let listed: Vec<String> = db
        .list_for_household("hh_alpha")
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    for id in [
        "inst-scoped",
        "inst-unscoped",
        "inst-machine-only",
        "inst-other-household",
        "inst-deleted",
    ] {
        let in_status = db
            .get_for_household_status(id, "hh_alpha")
            .unwrap()
            .is_some();
        let in_list = listed.iter().any(|listed_id| listed_id == id);
        assert_eq!(
            in_status, in_list,
            "status and list disagree for row {id} (status={in_status}, list={in_list})"
        );
    }
    assert_eq!(listed, vec!["inst-scoped".to_string()]);
}

#[test]
fn stamp_mac_host_household_makes_seeded_mac_host_visible() {
    // Boot-order reproduction: the mac-host seed runs BEFORE the household
    // identity loads, so the row is born unscoped and invisible. Stamping
    // after bootstrap is what puts it in the sharing picker.
    let db = open_temp();
    let admin_id = db.seed_admin("admin").unwrap();
    db.seed_mac_host_instance(&admin_id).unwrap();

    let mac_host = db.get("inst-mac-host").unwrap().expect("seeded row");
    assert!(mac_host.household_id.is_none());
    assert!(mac_host.household_machine_id.is_none());
    assert!(db.list_for_household("hh_alpha").unwrap().is_empty());
    assert!(
        db.get_for_household_status("inst-mac-host", "hh_alpha")
            .unwrap()
            .is_none()
    );

    let stamped = db.stamp_mac_host_household("hh_alpha", "m_alpha").unwrap();
    assert!(stamped, "mac-host seed row must be stamped");

    let mac_host = db.get("inst-mac-host").unwrap().expect("seeded row");
    assert_eq!(mac_host.household_id.as_deref(), Some("hh_alpha"));
    assert_eq!(mac_host.household_machine_id.as_deref(), Some("m_alpha"));
    let listed: Vec<String> = db
        .list_for_household("hh_alpha")
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(listed, vec!["inst-mac-host".to_string()]);
    assert!(
        db.get_for_household_status("inst-mac-host", "hh_alpha")
            .unwrap()
            .is_some()
    );

    // Idempotent: a second stamp (next boot) touches nothing.
    assert!(!db.stamp_mac_host_household("hh_alpha", "m_alpha").unwrap());
}

#[test]
fn stamp_mac_host_household_fails_closed_on_ambiguous_or_foreign_rows() {
    // Narrow stamping (security verdict, 2026-08): ONLY the mac-host seed
    // row is eligible. A fully-unscoped NON-mac-host row — possibly a
    // leftover from a previous household — must NOT be adopted by the
    // current one. Partial scope (ambiguous provenance), another
    // household's rows, and soft-deleted rows are likewise untouched.
    let db = open_temp();
    let insert = |id: &str, container: &str, hh: Option<&str>, m: Option<&str>| {
        db.insert(&NewInstance {
            id,
            name: id,
            container,
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: hh,
            household_machine_id: m,
        })
        .unwrap();
    };
    insert("inst-legacy-unscoped", "picoclaw-legacy", None, None);
    insert(
        "inst-machine-only",
        "picoclaw-m-only",
        None,
        Some("m_unknown"),
    );
    insert(
        "inst-household-only",
        "picoclaw-h-only",
        Some("hh_alpha"),
        None,
    );
    insert(
        "inst-other-household",
        "picoclaw-other",
        Some("hh_beta"),
        Some("m_beta"),
    );
    insert("mac-host-lookalike", "mac-host-impostor", None, None);

    let stamped = db.stamp_mac_host_household("hh_alpha", "m_alpha").unwrap();
    assert!(!stamped, "no row here is eligible for stamping");

    let legacy = db.get("inst-legacy-unscoped").unwrap().unwrap();
    assert!(
        legacy.household_id.is_none() && legacy.household_machine_id.is_none(),
        "unscoped non-mac-host rows must NOT be adopted by the current household"
    );
    let machine_only = db.get("inst-machine-only").unwrap().unwrap();
    assert!(machine_only.household_id.is_none());
    assert_eq!(
        machine_only.household_machine_id.as_deref(),
        Some("m_unknown")
    );
    let household_only = db.get("inst-household-only").unwrap().unwrap();
    assert_eq!(household_only.household_id.as_deref(), Some("hh_alpha"));
    assert!(household_only.household_machine_id.is_none());
    let other = db.get("inst-other-household").unwrap().unwrap();
    assert_eq!(other.household_id.as_deref(), Some("hh_beta"));
    let lookalike = db.get("mac-host-lookalike").unwrap().unwrap();
    assert!(
        lookalike.household_id.is_none(),
        "only the exact mac-host container is eligible"
    );
}

#[test]
fn household_status_hides_machine_only_partial_scope() {
    let db = open_temp();
    db.insert(&NewInstance {
        id: "inst-machine-only",
        name: "machine-only",
        container: "picoclaw-machine-only",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: Some("m_alpha"),
    })
    .unwrap();

    assert!(
        db.get_for_household_status("inst-machine-only", "hh_alpha")
            .unwrap()
            .is_none()
    );
}

#[test]
fn household_status_hides_deleted_or_other_household_rows() {
    let db = open_temp();
    db.insert(&NewInstance {
        id: "inst-other-household",
        name: "other-household",
        container: "picoclaw-other-household",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_beta"),
        household_machine_id: Some("m_beta"),
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-deleted",
        name: "deleted",
        container: "picoclaw-deleted",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_alpha"),
        household_machine_id: Some("m_alpha"),
    })
    .unwrap();
    db.soft_delete("inst-deleted").unwrap();

    assert!(
        db.get_for_household_status("inst-other-household", "hh_alpha")
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_for_household_status("inst-deleted", "hh_alpha")
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_for_household_status("inst-missing", "hh_alpha")
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_delete() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.delete("inst-foo").unwrap();
    assert!(db.get("inst-foo").unwrap().is_none());
}

#[test]
fn test_delete_with_unredeemed_invite() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    let admin_id = db.seed_admin("admin").unwrap();
    db.create_invite("inst-foo", &admin_id, 3600).unwrap();

    db.delete("inst-foo").unwrap();
    assert!(db.get("inst-foo").unwrap().is_none());
    assert!(db.list_invites().unwrap().is_empty());
}

#[test]
fn test_delete_with_redeemed_invite() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    let admin_id = db.seed_admin("admin").unwrap();
    let invite = db.create_invite("inst-foo", &admin_id, 3600).unwrap();

    db.redeem_invite_atomic(&invite.token, "guest", &admin_id)
        .unwrap();

    db.delete("inst-foo").unwrap();
    assert!(db.get("inst-foo").unwrap().is_none());
    assert!(db.list_invites().unwrap().is_empty());
}

#[test]
fn test_set_job_id() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.set_job_id("inst-foo", "job-123").unwrap();
    let row = db.get("inst-foo").unwrap().expect("row");
    assert_eq!(row.job_id, Some("job-123".to_string()));
}

#[test]
fn test_set_custom_domain() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.set_custom_domain("inst-foo", "meunegocio.com.br", "cf-abc123")
        .unwrap();
    let row = db.get("inst-foo").unwrap().expect("row");
    assert_eq!(row.custom_domain, Some("meunegocio.com.br".to_string()));
    assert_eq!(row.cf_hostname_id, Some("cf-abc123".to_string()));
}

#[test]
fn test_clear_custom_domain() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.set_custom_domain("inst-foo", "app.example.com", "cf-xyz")
        .unwrap();
    db.clear_custom_domain("inst-foo").unwrap();
    let row = db.get("inst-foo").unwrap().expect("row");
    assert_eq!(row.custom_domain, None);
    assert_eq!(row.cf_hostname_id, None);
}

#[test]
fn test_lookup_custom_domain_port() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.update_status(&StatusUpdate {
        id: "inst-foo",
        status: InstanceStatus::Active,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .unwrap();
    db.update_port("inst-foo", 35002).unwrap();
    db.set_custom_domain("inst-foo", "app.example.com", "cf-id")
        .unwrap();
    let port = db.lookup_custom_domain_port("app.example.com").unwrap();
    assert_eq!(port, Some(35002));
}

#[test]
fn test_lookup_custom_domain_port_not_active() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.update_port("inst-foo", 35003).unwrap();
    db.set_custom_domain("inst-foo", "app.example.com", "cf-id")
        .unwrap();
    // Instance is "provisioning", not "active"
    let port = db.lookup_custom_domain_port("app.example.com").unwrap();
    assert_eq!(port, None);
}

#[test]
fn test_public_site_upsert_list_lookup_delete() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.update_status(&StatusUpdate {
        id: "inst-foo",
        status: InstanceStatus::Active,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .unwrap();

    let site = db
        .upsert_public_site(&NewPublicSite {
            domain: "app.example.com",
            instance_id: "inst-foo",
            guest_port: 3000,
            target_host: "127.0.0.1",
            target_port: 24001,
            enabled: true,
        })
        .unwrap();
    assert_eq!(site.domain, "app.example.com");
    assert_eq!(site.guest_port, 3000);
    assert_eq!(site.target_port, 24001);
    assert!(site.enabled);

    let list = db.list_public_sites_for_instance("inst-foo").unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].domain, "app.example.com");

    let target = db
        .lookup_public_site_target("app.example.com")
        .unwrap()
        .expect("active public site target");
    assert_eq!(target.instance_id, "inst-foo");
    assert_eq!(target.target_host, "127.0.0.1");

    let by_guest_port = db
        .find_public_site_for_instance_guest_port("inst-foo", 3000)
        .unwrap()
        .expect("site for guest port");
    assert_eq!(by_guest_port.target_port, 24001);

    let ports = db.list_public_site_target_ports().unwrap();
    assert_eq!(ports, vec![24001]);

    assert!(
        db.delete_public_site("inst-foo", "app.example.com")
            .unwrap()
            .is_some()
    );
    assert!(
        db.lookup_public_site_target("app.example.com")
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_lookup_public_site_target_not_active_or_disabled() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.upsert_public_site(&NewPublicSite {
        domain: "app.example.com",
        instance_id: "inst-foo",
        guest_port: 3000,
        target_host: "127.0.0.1",
        target_port: 24002,
        enabled: true,
    })
    .unwrap();

    assert!(
        db.lookup_public_site_target("app.example.com")
            .unwrap()
            .is_none()
    );

    db.update_status(&StatusUpdate {
        id: "inst-foo",
        status: InstanceStatus::Active,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .unwrap();
    db.upsert_public_site(&NewPublicSite {
        domain: "app.example.com",
        instance_id: "inst-foo",
        guest_port: 3000,
        target_host: "127.0.0.1",
        target_port: 24002,
        enabled: false,
    })
    .unwrap();

    assert!(
        db.lookup_public_site_target("app.example.com")
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_get_cf_hostname_id() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    assert_eq!(db.get_cf_hostname_id("inst-foo").unwrap(), None);
    db.set_custom_domain("inst-foo", "app.example.com", "cf-999")
        .unwrap();
    assert_eq!(
        db.get_cf_hostname_id("inst-foo").unwrap(),
        Some("cf-999".to_string())
    );
}

#[test]
fn test_custom_domain_unique_constraint() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    db.insert(&NewInstance {
        id: "inst-bar",
        name: "bar",
        container: "picoclaw-bar",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();
    db.set_custom_domain("inst-foo", "app.example.com", "cf-1")
        .unwrap();
    // Second instance trying to claim the same custom_domain should fail
    let err = db
        .set_custom_domain("inst-bar", "app.example.com", "cf-2")
        .unwrap_err();
    assert!(
        err.to_string().contains("UNIQUE"),
        "expected UNIQUE constraint error, got: {err}"
    );
}

#[test]
fn test_list_active_containers() {
    let db = open_temp();
    db.insert(&NewInstance {
        id: "inst-a",
        name: "alpha",
        container: "picoclaw-alpha",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-b",
        name: "beta",
        container: "picoclaw-beta",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();

    // Both start as "provisioning" — no active containers yet
    assert!(db.list_active_containers().unwrap().is_empty());

    // Activate alpha
    db.update_status(&StatusUpdate {
        id: "inst-a",
        status: InstanceStatus::Active,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .unwrap();
    let active = db.list_active_containers().unwrap();
    assert_eq!(active, vec!["picoclaw-alpha"]);

    // Activate beta too
    db.update_status(&StatusUpdate {
        id: "inst-b",
        status: InstanceStatus::Active,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .unwrap();
    let active = db.list_active_containers().unwrap();
    assert_eq!(active, vec!["picoclaw-alpha", "picoclaw-beta"]);

    // Stop alpha — only beta remains
    db.update_status(&StatusUpdate {
        id: "inst-a",
        status: InstanceStatus::Stopped,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .unwrap();
    let active = db.list_active_containers().unwrap();
    assert_eq!(active, vec!["picoclaw-beta"]);

    // Delete beta — empty again
    db.delete("inst-b").unwrap();
    assert!(db.list_active_containers().unwrap().is_empty());
}

#[test]
fn get_by_container_found_and_not_found() {
    let db = open_temp();
    db.insert(&foo_inst()).unwrap();
    let row = db.get_by_container("picoclaw-foo").unwrap().unwrap();
    assert_eq!(row.id, "inst-foo");
    assert_eq!(row.container, "picoclaw-foo");
    assert!(db.get_by_container("nonexistent").unwrap().is_none());
}

#[test]
fn get_for_household_by_container_filters_household_and_deleted_state() {
    let db = open_temp();
    db.insert(&NewInstance {
        id: "inst-household-alpha",
        name: "household-alpha",
        container: "picoclaw-household-alpha",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_alpha"),
        household_machine_id: Some("m_alpha"),
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-other-household",
        name: "other-household",
        container: "picoclaw-other-household",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_beta"),
        household_machine_id: Some("m_beta"),
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-legacy",
        name: "legacy",
        container: "picoclaw-legacy",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-deleted",
        name: "deleted",
        container: "picoclaw-deleted",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_alpha"),
        household_machine_id: Some("m_alpha"),
    })
    .unwrap();
    db.soft_delete("inst-deleted").unwrap();

    let row = db
        .get_for_household_by_container("picoclaw-household-alpha", "hh_alpha")
        .unwrap()
        .expect("matching household row");
    assert_eq!(row.id, "inst-household-alpha");
    assert!(
        db.get_for_household_by_container("picoclaw-other-household", "hh_alpha")
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_for_household_by_container("picoclaw-legacy", "hh_alpha")
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_for_household_by_container("picoclaw-deleted", "hh_alpha")
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_for_household_by_container("picoclaw-missing", "hh_alpha")
            .unwrap()
            .is_none()
    );
}

#[test]
fn get_for_household_by_id_filters_household_and_deleted_state() {
    let db = open_temp();
    db.insert(&NewInstance {
        id: "inst-household-alpha",
        name: "household-alpha",
        container: "picoclaw-household-alpha",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_alpha"),
        household_machine_id: Some("m_alpha"),
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-other-household",
        name: "other-household",
        container: "picoclaw-other-household",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_beta"),
        household_machine_id: Some("m_beta"),
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-legacy",
        name: "legacy",
        container: "picoclaw-legacy",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-deleted",
        name: "deleted",
        container: "picoclaw-deleted",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_alpha"),
        household_machine_id: Some("m_alpha"),
    })
    .unwrap();
    db.soft_delete("inst-deleted").unwrap();

    let row = db
        .get_for_household_by_id("inst-household-alpha", "hh_alpha")
        .unwrap()
        .expect("matching household row");
    assert_eq!(row.container, "picoclaw-household-alpha");
    assert!(
        db.get_for_household_by_id("inst-other-household", "hh_alpha")
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_for_household_by_id("inst-legacy", "hh_alpha")
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_for_household_by_id("inst-deleted", "hh_alpha")
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_for_household_by_id("inst-missing", "hh_alpha")
            .unwrap()
            .is_none()
    );
}

// ── Terminal workspace tests ─────────────────────────────────────────────

#[test]
fn workspace_create_and_resume() {
    let db = open_temp();
    let ws1 = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    assert_eq!(ws1.container, "picoclaw-foo");
    assert_eq!(ws1.username, "admin");
    assert_eq!(ws1.status, "active");
    assert!(!ws1.id.is_empty());

    // Resume returns the same workspace.
    let ws2 = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    assert_eq!(ws1.id, ws2.id);
}

#[test]
fn workspace_different_users_get_different_workspaces() {
    let db = open_temp();
    let ws1 = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    let ws2 = db
        .resume_or_create_conversation("picoclaw-foo", "mobile")
        .unwrap();
    assert_ne!(ws1.id, ws2.id);
    assert_ne!(ws1.id, ws2.id);
}

#[test]
fn workspace_unique_constraint() {
    let db = open_temp();
    db.resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    // Same user + container should resume, not create duplicate.
    let ws2 = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    // Verify only one row exists.
    let conn = db.conn.lock().unwrap();
    let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM terminal_conversations WHERE container='picoclaw-foo' AND username='admin'",
                [],
                |row| row.get(0),
            )
            .unwrap();
    assert_eq!(count, 1);
    drop(conn);
    assert_eq!(ws2.status, "active");
}

#[test]
fn workspace_cascade_delete() {
    let db = open_temp();
    db.resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    db.resume_or_create_conversation("picoclaw-foo", "mobile")
        .unwrap();
    let n = db
        .delete_conversations_for_container("picoclaw-foo")
        .unwrap();
    assert_eq!(n, 2);
    // Resume after delete creates a new workspace.
    let ws = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    assert_eq!(ws.status, "active");
}

#[test]
fn workspace_detach() {
    let db = open_temp();
    let ws = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    db.detach_conversation(&ws.id).unwrap();
    // Verify last_detach_at is set.
    let conn = db.conn.lock().unwrap();
    let detached: Option<String> = conn
        .query_row(
            "SELECT last_detach_at FROM terminal_conversations WHERE id = ?1",
            params![ws.id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(detached.is_some());
}

#[test]
fn workspace_cleanup_stale() {
    let db = open_temp();
    let ws = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    // Manually set last_attach_at to 100 days ago.
    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '-100 days') WHERE id = ?1",
                params![ws.id],
            )
            .unwrap();
    }
    let n = db.cleanup_stale_conversations(90).unwrap();
    assert_eq!(n, 1);
    // Verify it's expired now — resume creates a new one.
    let conn = db.conn.lock().unwrap();
    let status: String = conn
        .query_row(
            "SELECT status FROM terminal_conversations WHERE id = ?1",
            params![ws.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "expired");
}

#[test]
fn workspace_verify_owner_valid() {
    let db = open_temp();
    let ws = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    assert!(
        db.verify_conversation_owner(&ws.id, "picoclaw-foo", "admin")
            .unwrap()
    );
}

#[test]
fn workspace_verify_owner_wrong_user() {
    let db = open_temp();
    let ws = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    assert!(
        !db.verify_conversation_owner(&ws.id, "picoclaw-foo", "other")
            .unwrap()
    );
}

#[test]
fn workspace_verify_owner_wrong_container() {
    let db = open_temp();
    let ws = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    assert!(
        !db.verify_conversation_owner(&ws.id, "picoclaw-bar", "admin")
            .unwrap()
    );
}

#[test]
fn workspace_verify_owner_expired() {
    let db = open_temp();
    let ws = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    // Mark as expired.
    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
            "UPDATE terminal_conversations SET status = 'expired' WHERE id = ?1",
            params![ws.id],
        )
        .unwrap();
    }
    assert!(
        !db.verify_conversation_owner(&ws.id, "picoclaw-foo", "admin")
            .unwrap()
    );
}

// ── Multi-workspace tests (v2) ──────────────────────────────────────────

#[test]
fn workspace_create_multiple_same_user_container() {
    let db = open_temp();
    let ws1 = db
        .create_conversation("picoclaw-foo", "admin", "Dev Principal")
        .unwrap();
    let ws2 = db
        .create_conversation("picoclaw-foo", "admin", "Debug DB")
        .unwrap();
    assert_ne!(ws1.id, ws2.id);
    assert_ne!(ws1.id, ws2.id);
    assert_eq!(ws1.display_name, "Dev Principal");
    assert_eq!(ws2.display_name, "Debug DB");
}

#[test]
fn workspace_display_name_in_create() {
    let db = open_temp();
    let ws = db
        .create_conversation("picoclaw-foo", "admin", "Debug DB")
        .unwrap();
    assert_eq!(ws.display_name, "Debug DB");
    assert_eq!(ws.container, "picoclaw-foo");
    assert_eq!(ws.username, "admin");
    assert_eq!(ws.status, "active");
    assert!(!ws.id.is_empty());
}

#[test]
fn workspace_list_returns_only_users_workspaces() {
    let db = open_temp();
    db.create_conversation("picoclaw-foo", "admin", "WS 1")
        .unwrap();
    db.create_conversation("picoclaw-foo", "admin", "WS 2")
        .unwrap();
    db.create_conversation("picoclaw-foo", "other", "Other WS")
        .unwrap();
    let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
    assert_eq!(list.len(), 2);
    assert!(list.iter().all(|w| w.username == "admin"));
}

#[test]
fn workspace_list_includes_inactive_excludes_expired() {
    let db = open_temp();
    let ws_active = db
        .create_conversation("picoclaw-foo", "admin", "Active")
        .unwrap();
    let ws_inactive = db
        .create_conversation("picoclaw-foo", "admin", "Inactive")
        .unwrap();
    let ws_expired = db
        .create_conversation("picoclaw-foo", "admin", "Expired")
        .unwrap();
    // Mark statuses via raw SQL.
    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
            "UPDATE terminal_conversations SET status = 'inactive' WHERE id = ?1",
            params![ws_inactive.id],
        )
        .unwrap();
        conn.execute(
            "UPDATE terminal_conversations SET status = 'expired' WHERE id = ?1",
            params![ws_expired.id],
        )
        .unwrap();
    }
    let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
    assert_eq!(list.len(), 2);
    let ids: Vec<&str> = list.iter().map(|w| w.id.as_str()).collect();
    assert!(ids.contains(&ws_active.id.as_str()));
    assert!(ids.contains(&ws_inactive.id.as_str()));
    assert!(!ids.contains(&ws_expired.id.as_str()));
}

#[test]
fn workspace_list_empty_when_none() {
    let db = open_temp();
    let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
    assert!(list.is_empty());
}

#[test]
fn workspace_list_ordered_by_last_attach() {
    let db = open_temp();
    let ws1 = db
        .create_conversation("picoclaw-foo", "admin", "First")
        .unwrap();
    let ws2 = db
        .create_conversation("picoclaw-foo", "admin", "Second")
        .unwrap();
    let ws3 = db
        .create_conversation("picoclaw-foo", "admin", "Third")
        .unwrap();
    // Make ws2 the most recently attached.
    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '+1 minute') WHERE id = ?1",
                params![ws2.id],
            ).unwrap();
        conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '-10 minutes') WHERE id = ?1",
                params![ws1.id],
            ).unwrap();
    }
    let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
    assert_eq!(list.len(), 3);
    // Most recently attached first.
    assert_eq!(list[0].id, ws2.id);
    // ws3 was created after ws1 (with default CURRENT_TIMESTAMP), so ws3 > ws1.
    assert_eq!(list[1].id, ws3.id);
    assert_eq!(list[2].id, ws1.id);
}

#[test]
fn workspace_get_returns_workspace_with_display_name() {
    let db = open_temp();
    let ws = db
        .create_conversation("picoclaw-foo", "admin", "Dev Principal")
        .unwrap();
    let got = db
        .get_conversation(&ws.id)
        .unwrap()
        .expect("workspace exists");
    assert_eq!(got.id, ws.id);
    assert_eq!(got.container, "picoclaw-foo");
    assert_eq!(got.username, "admin");
    assert_eq!(got.display_name, "Dev Principal");
    assert_eq!(got.status, "active");
    assert!(!got.id.is_empty());
}

#[test]
fn workspace_get_nonexistent_returns_none() {
    let db = open_temp();
    assert!(db.get_conversation("nonexistent-id").unwrap().is_none());
}

#[test]
fn workspace_rename_updates_display_name() {
    let db = open_temp();
    let ws = db
        .create_conversation("picoclaw-foo", "admin", "Old Name")
        .unwrap();
    let updated = db.rename_conversation(&ws.id, "Dev Principal").unwrap();
    assert!(updated);
    let got = db.get_conversation(&ws.id).unwrap().unwrap();
    assert_eq!(got.display_name, "Dev Principal");
}

#[test]
fn workspace_rename_nonexistent_returns_false() {
    let db = open_temp();
    let updated = db.rename_conversation("nonexistent-id", "Name").unwrap();
    assert!(!updated);
}

#[test]
fn workspace_delete_removes_row() {
    let db = open_temp();
    let ws = db
        .create_conversation("picoclaw-foo", "admin", "To Delete")
        .unwrap();
    let deleted = db.delete_conversation(&ws.id).unwrap();
    assert!(deleted);
    let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
    assert!(list.is_empty());
}

#[test]
fn workspace_delete_nonexistent_returns_false() {
    let db = open_temp();
    let deleted = db.delete_conversation("nonexistent-id").unwrap();
    assert!(!deleted);
}

#[test]
fn workspace_resume_or_create_returns_most_recent() {
    let db = open_temp();
    let _ws1 = db
        .create_conversation("picoclaw-foo", "admin", "First")
        .unwrap();
    let ws2 = db
        .create_conversation("picoclaw-foo", "admin", "Second")
        .unwrap();
    // Make ws2 the most recently attached.
    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '+1 minute') WHERE id = ?1",
                params![ws2.id],
            ).unwrap();
    }
    // resume_or_create should return the most recently attached (ws2), not create a new one.
    let resumed = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    assert_eq!(resumed.id, ws2.id);
    // Verify no extra row was created.
    let list = db.list_conversations("picoclaw-foo", "admin").unwrap();
    assert_eq!(list.len(), 2);
}

#[test]
fn workspace_resume_or_create_creates_when_none() {
    let db = open_temp();
    let ws = db
        .resume_or_create_conversation("picoclaw-foo", "admin")
        .unwrap();
    assert_eq!(ws.container, "picoclaw-foo");
    assert_eq!(ws.username, "admin");
    assert_eq!(ws.status, "active");
    // display_name should default to empty string.
    assert_eq!(ws.display_name, "");
}

#[test]
fn workspace_cleanup_tiered_7d_marks_inactive() {
    let db = open_temp();
    let ws = db
        .create_conversation("picoclaw-foo", "admin", "Old")
        .unwrap();
    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '-10 days') WHERE id = ?1",
                params![ws.id],
            ).unwrap();
    }
    let (inactive, expired) = db.cleanup_stale_conversations_tiered(7, 30).unwrap();
    assert_eq!(inactive, 1);
    assert_eq!(expired, 0);
    let got = db.get_conversation(&ws.id).unwrap().unwrap();
    assert_eq!(got.status, "inactive");
}

#[test]
fn workspace_cleanup_tiered_30d_marks_expired() {
    let db = open_temp();
    let ws = db
        .create_conversation("picoclaw-foo", "admin", "Very Old")
        .unwrap();
    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '-35 days') WHERE id = ?1",
                params![ws.id],
            ).unwrap();
    }
    let (inactive, expired) = db.cleanup_stale_conversations_tiered(7, 30).unwrap();
    assert_eq!(inactive, 0);
    assert_eq!(expired, 1);
    let got = db.get_conversation(&ws.id).unwrap().unwrap();
    assert_eq!(got.status, "expired");
}

#[test]
fn workspace_cleanup_tiered_preserves_recent() {
    let db = open_temp();
    let ws = db
        .create_conversation("picoclaw-foo", "admin", "Recent")
        .unwrap();
    // last_attach_at is CURRENT_TIMESTAMP (just created), so 3 days ago is fine.
    // But let's set it explicitly to 3 days ago.
    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
                "UPDATE terminal_conversations SET last_attach_at = datetime('now', '-3 days') WHERE id = ?1",
                params![ws.id],
            ).unwrap();
    }
    let (inactive, expired) = db.cleanup_stale_conversations_tiered(7, 30).unwrap();
    assert_eq!(inactive, 0);
    assert_eq!(expired, 0);
    let got = db.get_conversation(&ws.id).unwrap().unwrap();
    assert_eq!(got.status, "active");
}

#[test]
fn workspace_cleanup_tiered_inactive_to_expired() {
    let db = open_temp();
    let ws = db
        .create_conversation("picoclaw-foo", "admin", "Will Expire")
        .unwrap();
    // Set as inactive with last_attach_at 35 days ago.
    {
        let conn = db.conn.lock().unwrap();
        conn.execute(
                "UPDATE terminal_conversations SET status = 'inactive', last_attach_at = datetime('now', '-35 days') WHERE id = ?1",
                params![ws.id],
            ).unwrap();
    }
    let (inactive, expired) = db.cleanup_stale_conversations_tiered(7, 30).unwrap();
    assert_eq!(inactive, 0);
    assert_eq!(expired, 1);
    let got = db.get_conversation(&ws.id).unwrap().unwrap();
    assert_eq!(got.status, "expired");
}

#[test]
fn workspace_migration_v2_idempotent() {
    // Opening the DB twice runs migrations twice — should not error.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let path_str = path.to_str().unwrap();
    {
        let _db1 = InstanceDb::open(path_str).unwrap();
    }
    {
        let db2 = InstanceDb::open(path_str).unwrap();
        // Verify we can still create multi-workspaces (v2 migration applied).
        let ws1 = db2
            .create_conversation("picoclaw-foo", "admin", "A")
            .unwrap();
        let ws2 = db2
            .create_conversation("picoclaw-foo", "admin", "B")
            .unwrap();
        assert_ne!(ws1.id, ws2.id);
    }
}

#[test]
fn terminal_conversations_survive_reopen() {
    // Regression for PR #16 follow-up: the migration must not wipe rows
    // across backend restarts. Insert a row, close the DB, re-open (which
    // re-runs migrations), and assert the row is still there.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let path_str = path.to_str().unwrap();

    let conv_id = {
        let db1 = InstanceDb::open(path_str).unwrap();
        let ws = db1
            .create_conversation("picoclaw-foo", "admin", "persistent")
            .unwrap();
        ws.id
    };

    let db2 = InstanceDb::open(path_str).unwrap();
    let got = db2
        .get_conversation(&conv_id)
        .unwrap()
        .expect("conversation row must survive DB reopen");
    assert_eq!(got.id, conv_id);
    assert_eq!(got.container, "picoclaw-foo");
    assert_eq!(got.username, "admin");
    assert_eq!(got.display_name, "persistent");
}

#[test]
fn test_count_by_claw_type() {
    let db = open_temp();
    // No instances yet
    assert_eq!(db.count_by_claw_type("picoclaw").unwrap(), 0);

    // Insert two picoclaw instances and one zeroclaw
    db.insert(&foo_inst()).unwrap(); // picoclaw-foo
    db.insert(&NewInstance {
        id: "inst-bar",
        name: "bar",
        container: "picoclaw-bar",
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();
    db.insert(&NewInstance {
        id: "inst-zc",
        name: "zc",
        container: "zeroclaw-zc",
        claw_type: "zeroclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();

    assert_eq!(db.count_by_claw_type("picoclaw").unwrap(), 2);
    assert_eq!(db.count_by_claw_type("zeroclaw").unwrap(), 1);
    assert_eq!(db.count_by_claw_type("nanobot").unwrap(), 0);
}

// ── User tests ───────────────────────────────────────────────────────────

#[test]
fn test_seed_admin_creates_user() {
    let db = open_temp();
    let id = db.seed_admin("admin").unwrap();
    assert!(id.starts_with("usr_"));

    let user = db.get_user_by_username("admin").unwrap().unwrap();
    assert_eq!(user.id, id);
    assert_eq!(user.role, UserRole::Admin);
    assert!(user.created_by.is_none());
}

#[test]
fn test_seed_admin_idempotent() {
    let db = open_temp();
    let id1 = db.seed_admin("admin").unwrap();
    let id2 = db.seed_admin("admin").unwrap();
    assert_eq!(id1, id2);

    // Even with a different username, seed_admin returns existing admin
    let id3 = db.seed_admin("otheradmin").unwrap();
    assert_eq!(id1, id3);

    // Only one admin exists
    let users = db.list_users().unwrap();
    assert_eq!(users.len(), 1);
}

#[test]
fn test_get_user_by_username_not_found() {
    let db = open_temp();
    assert!(db.get_user_by_username("nobody").unwrap().is_none());
}

#[test]
fn test_create_user() {
    let db = open_temp();
    let admin_id = db.seed_admin("admin").unwrap();

    let user = db
        .create_user("alice", UserRole::User, Some(&admin_id))
        .unwrap();
    assert!(user.id.starts_with("usr_"));
    assert_eq!(user.username, "alice");
    assert_eq!(user.role, UserRole::User);
    assert_eq!(user.created_by.as_deref(), Some(admin_id.as_str()));

    // Lookup by id
    let found = db.get_user(&user.id).unwrap().unwrap();
    assert_eq!(found.username, "alice");
}

#[test]
fn test_create_user_duplicate_username() {
    let db = open_temp();
    db.seed_admin("admin").unwrap();
    // "admin" already exists
    assert!(db.create_user("admin", UserRole::User, None).is_err());
}

// ── Ownership tests ────────────────────────────────────────────────────

#[test]
fn test_set_owner_and_list_for_user() {
    let db = open_temp();
    let admin_id = db.seed_admin("admin").unwrap();
    let alice = db
        .create_user("alice", UserRole::User, Some(&admin_id))
        .unwrap();

    db.insert(&foo_inst()).unwrap();

    // Initially unassigned
    assert!(db.get("inst-foo").unwrap().unwrap().owner_id.is_none());
    assert!(db.list_for_user(&alice.id).unwrap().is_empty());

    // Assign
    assert!(db.set_owner("inst-foo", Some(&alice.id)).unwrap());
    let rows = db.list_for_user(&alice.id).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].owner_id.as_deref(), Some(alice.id.as_str()));

    // Unassign
    assert!(db.set_owner("inst-foo", None).unwrap());
    assert!(db.list_for_user(&alice.id).unwrap().is_empty());
}

#[test]
fn test_get_owner_id_by_container() {
    let db = open_temp();
    let admin_id = db.seed_admin("admin").unwrap();
    let alice = db
        .create_user("alice", UserRole::User, Some(&admin_id))
        .unwrap();

    db.insert(&foo_inst()).unwrap();

    // Unassigned
    assert_eq!(
        db.get_owner_id_by_container("picoclaw-foo").unwrap(),
        Some(None)
    );

    // Assigned
    db.set_owner("inst-foo", Some(&alice.id)).unwrap();
    assert_eq!(
        db.get_owner_id_by_container("picoclaw-foo").unwrap(),
        Some(Some(alice.id.clone()))
    );

    // No such container
    assert!(
        db.get_owner_id_by_container("nonexistent")
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_list_accessible_containers() {
    let db = open_temp();
    let admin_id = db.seed_admin("admin").unwrap();
    let alice = db
        .create_user("alice", UserRole::User, Some(&admin_id))
        .unwrap();

    db.insert(&foo_inst()).unwrap();
    db.update_status(&StatusUpdate {
        id: "inst-foo",
        status: InstanceStatus::Active,
        message: "",
        error: "",
        job_id: "",
        phase: "",
    })
    .unwrap();

    // Admin sees unassigned
    let admin_ctrs = db
        .list_accessible_containers(&admin_id, UserRole::Admin)
        .unwrap();
    assert_eq!(admin_ctrs, vec!["picoclaw-foo"]);
    // User sees nothing (not owned)
    let alice_ctrs = db
        .list_accessible_containers(&alice.id, UserRole::User)
        .unwrap();
    assert!(alice_ctrs.is_empty());

    // Assign to alice
    db.set_owner("inst-foo", Some(&alice.id)).unwrap();
    // Admin no longer sees it
    let admin_ctrs = db
        .list_accessible_containers(&admin_id, UserRole::Admin)
        .unwrap();
    assert!(admin_ctrs.is_empty());
    // Alice sees it
    let alice_ctrs = db
        .list_accessible_containers(&alice.id, UserRole::User)
        .unwrap();
    assert_eq!(alice_ctrs, vec!["picoclaw-foo"]);
}

#[test]
fn test_list_users() {
    let db = open_temp();
    db.seed_admin("admin").unwrap();
    db.create_user("alice", UserRole::User, None).unwrap();
    db.create_user("bob", UserRole::User, None).unwrap();

    let users = db.list_users().unwrap();
    assert_eq!(users.len(), 3);
    assert_eq!(users[0].username, "admin");
}

// ── Resource Lease Tests ────────────────────────────────────────────────

#[test]
fn lease_create_and_query() {
    let db = open_temp();
    let id = db
        .create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "inst-1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
    assert!(id.starts_with("lease_"));

    let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
    assert_eq!(cpu, 2);
    assert_eq!(ram, 2048);
}

#[test]
fn lease_unique_index_prevents_duplicate_active() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();

    // Second active lease for same owner+kind should fail
    let result = db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 4,
        ram_mb: 4096,
        disk_gb: 0,
        expires_at: None,
    });
    assert!(result.is_err(), "duplicate active lease should fail");
}

#[test]
fn lease_release_idempotent() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();

    assert!(
        db.release_lease_str("instance", "inst-1", "runtime")
            .unwrap()
    );
    // Second release should return false (already released)
    assert!(
        !db.release_lease_str("instance", "inst-1", "runtime")
            .unwrap()
    );
}

#[test]
fn lease_released_excluded_from_sum() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();

    let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
    assert_eq!(cpu, 2);
    assert_eq!(ram, 2048);

    db.release_lease_str("instance", "inst-1", "runtime")
        .unwrap();

    let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
    assert_eq!(cpu, 0);
    assert_eq!(ram, 0);
}

#[test]
fn lease_after_release_can_create_new() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();
    db.release_lease_str("instance", "inst-1", "runtime")
        .unwrap();

    // After release, creating a new lease for the same owner+kind should work
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 4,
        ram_mb: 4096,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();

    let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
    assert_eq!(cpu, 4);
    assert_eq!(ram, 4096);
}

#[test]
fn lease_release_all() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Storage,
        cpu_cores: 0,
        ram_mb: 0,
        disk_gb: 10,
        expires_at: None,
    })
    .unwrap();

    let count = db.release_all_leases_str("instance", "inst-1").unwrap();
    assert_eq!(count, 2);

    let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
    assert_eq!(cpu, 0);
    assert_eq!(ram, 0);
    let disk = db.sum_active_storage_leases().unwrap();
    assert_eq!(disk, 0);
}

#[test]
fn lease_storage_sum() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Storage,
        cpu_cores: 0,
        ram_mb: 0,
        disk_gb: 10,
        expires_at: None,
    })
    .unwrap();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-2",
        lease_kind: LeaseKind::Storage,
        cpu_cores: 0,
        ram_mb: 0,
        disk_gb: 20,
        expires_at: None,
    })
    .unwrap();

    let disk = db.sum_active_storage_leases().unwrap();
    assert_eq!(disk, 30);
}

#[test]
fn lease_finalize_clears_expiry() {
    let db = open_temp();
    let now = now_unix();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: Some(now + 600),
    })
    .unwrap();

    assert!(db.finalize_lease("instance", "inst-1", "runtime").unwrap());

    let leases = db.active_leases_for_owner("instance", "inst-1").unwrap();
    assert_eq!(leases.len(), 1);
    assert!(leases[0].expires_at.is_none());
}

#[test]
fn lease_extend_updates_expiry() {
    let db = open_temp();
    let now = now_unix();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: Some(now + 600),
    })
    .unwrap();

    let new_expiry = now + 1200;
    assert!(
        db.extend_lease("instance", "inst-1", "runtime", new_expiry)
            .unwrap()
    );

    let leases = db.active_leases_for_owner("instance", "inst-1").unwrap();
    assert_eq!(leases[0].expires_at, Some(new_expiry));
}

#[test]
fn lease_has_active() {
    let db = open_temp();
    assert!(
        !db.has_active_lease_str("instance", "inst-1", "runtime")
            .unwrap()
    );

    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();

    assert!(
        db.has_active_lease_str("instance", "inst-1", "runtime")
            .unwrap()
    );

    db.release_lease_str("instance", "inst-1", "runtime")
        .unwrap();
    assert!(
        !db.has_active_lease_str("instance", "inst-1", "runtime")
            .unwrap()
    );
}

#[test]
fn lease_warm_pool_mixed_with_instance() {
    let db = open_temp();
    // Instance lease
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();
    // Warm pool lease
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::WarmPool,
        owner_id: "picoclaw:slot:0",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();

    // Sum includes both
    let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
    assert_eq!(cpu, 4);
    assert_eq!(ram, 4096);
}

#[test]
fn insert_with_leases_atomic() {
    let db = open_temp();
    let id = db.insert_with_leases(&foo_inst(), 600, None).unwrap();
    assert_eq!(id, "inst-foo");

    // Verify instance exists
    let row = db.get("inst-foo").unwrap().expect("instance");
    assert_eq!(row.status, InstanceStatus::Provisioning);

    // Verify 2 leases created
    let leases = db.active_leases_for_owner("instance", "inst-foo").unwrap();
    assert_eq!(leases.len(), 2);

    let runtime = leases.iter().find(|l| l.lease_kind == "runtime").unwrap();
    assert_eq!(runtime.cpu_cores, 2); // default from NewInstance
    assert_eq!(runtime.ram_mb, 2048);
    assert!(runtime.expires_at.is_some()); // TTL set

    let storage = leases.iter().find(|l| l.lease_kind == "storage").unwrap();
    assert_eq!(storage.disk_gb, 10); // default
    assert!(storage.expires_at.is_none()); // no TTL

    // Verify event recorded
    let events = db.list_instance_events("inst-foo", 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "create_started");
}

#[test]
fn insert_with_warm_pool_leases_transfers_runtime_atomically() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::WarmPool,
        owner_id: "picoclaw:slot:0",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();

    let id = db
        .insert_with_warm_pool_leases(&foo_inst(), 600, None)
        .unwrap();
    assert_eq!(id, "inst-foo");

    assert!(
        !db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
            .unwrap()
    );

    let leases = db.active_leases_for_owner("instance", "inst-foo").unwrap();
    assert_eq!(leases.len(), 2);
    let runtime = leases.iter().find(|l| l.lease_kind == "runtime").unwrap();
    assert_eq!(runtime.cpu_cores, 2);
    assert_eq!(runtime.ram_mb, 2048);
    assert!(runtime.expires_at.is_some());

    let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
    assert_eq!(cpu, 2);
    assert_eq!(ram, 2048);
}

#[test]
fn transfer_warm_pool_lease_works() {
    let db = open_temp();
    // Create a warm pool lease
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::WarmPool,
        owner_id: "picoclaw:slot:0",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();

    // Also need an instance row for the guest_os join
    db.insert(&foo_inst()).unwrap();

    // Transfer to instance
    let transferred = db
        .transfer_warm_pool_lease("picoclaw", "inst-foo", 2, 2048)
        .unwrap();
    assert!(transferred);

    // Warm pool lease should be released
    assert!(
        !db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
            .unwrap()
    );

    // Instance lease should exist
    assert!(
        db.has_active_lease_str("instance", "inst-foo", "runtime")
            .unwrap()
    );

    // Total runtime should still be 2 CPU / 2048 MB (ownership transfer, not addition)
    let (cpu, ram) = db.sum_active_runtime_leases().unwrap();
    assert_eq!(cpu, 2);
    assert_eq!(ram, 2048);
}

#[test]
fn transfer_warm_pool_lease_returns_false_when_no_lease() {
    let db = open_temp();
    let transferred = db
        .transfer_warm_pool_lease("picoclaw", "inst-foo", 2, 2048)
        .unwrap();
    assert!(!transferred);
}

#[test]
fn count_active_runtime_leases_by_guest_os_includes_macos_warm_pool() {
    let db = open_temp();
    db.insert(&NewInstance {
        id: "inst-mac",
        name: "inst-mac",
        container: "picoclaw-inst-mac",
        claw_type: "picoclaw",
        sunset_date: "",
        guest_os: Some("macos"),
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: None,
        household_machine_id: None,
    })
    .unwrap();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "inst-mac",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::WarmPool,
        owner_id: "picoclaw:slot:0",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();

    let count = db.count_active_runtime_leases_by_guest_os("macos").unwrap();
    assert_eq!(count, 2);
}

#[test]
fn instance_event_record_and_list() {
    let db = open_temp();
    db.record_instance_event(&NewInstanceEvent {
        instance_id: Some("inst-1"),
        event_type: "stopped",
        actor: "admin",
        detail: Some("user requested stop"),
        resource_snapshot: None,
    })
    .unwrap();
    db.record_instance_event(&NewInstanceEvent {
        instance_id: Some("inst-1"),
        event_type: "started",
        actor: "admin",
        detail: None,
        resource_snapshot: Some(r#"{"cpu":2}"#),
    })
    .unwrap();

    let events = db.list_instance_events("inst-1", 10).unwrap();
    assert_eq!(events.len(), 2);
    // Newest first
    assert_eq!(events[0].event_type, "started");
    assert_eq!(events[1].event_type, "stopped");
}

#[test]
fn migration_idempotent() {
    // Opening twice on same :memory: path simulates re-running migrations
    let db = open_temp();
    drop(db);
    let db2 = InstanceDb::open(":memory:").expect("second open");
    // Should succeed without errors
    let (cpu, ram) = db2.sum_active_runtime_leases().unwrap();
    assert_eq!(cpu, 0);
    assert_eq!(ram, 0);
}

/// B4b byte-identity: the typed lease API and the raw `_str` layer agree on
/// the exact wire bytes, both directions. A lease created with the typed
/// `LeaseOwnerType`/`LeaseKind` is found by a raw string query using the
/// historical literals, and a raw-string-created lease is found by a typed
/// query — proving the typed producers still write `warm_pool`/`instance`/
/// `runtime` unchanged.
#[test]
fn typed_lease_api_is_byte_identical_to_raw_str() {
    let db = open_temp();

    // Typed CREATE -> raw string query finds it with the old literals.
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::WarmPool,
        owner_id: "picoclaw:slot:0",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();
    assert!(
        db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
            .unwrap(),
        "typed create must write the literal wire bytes 'warm_pool'/'runtime'"
    );

    // Raw string CREATE -> typed query finds it.
    db.create_lease_str("instance", "inst-1", "runtime", 1, 512, 0, None)
        .unwrap();
    assert!(
        db.has_active_lease(LeaseOwnerType::Instance, "inst-1", LeaseKind::Runtime)
            .unwrap(),
        "typed query must read leases written with the literal wire bytes"
    );
}

// ── P3: lease ownership invariants ──────────────────────────────────────

/// `ux_active_lease_per_owner`: at most one ACTIVE lease per
/// `(owner_type, owner_id, lease_kind)`. A second active lease for the same
/// triple is rejected; after release a fresh one is allowed; a different
/// `lease_kind` for the same owner is a distinct triple (allowed).
#[test]
fn inv_at_most_one_active_lease_per_owner_kind() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "i1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();
    // Second ACTIVE runtime lease for the same owner triple → rejected.
    assert!(
        db.create_lease(&NewLease {
            owner_type: LeaseOwnerType::Instance,
            owner_id: "i1",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 1,
            ram_mb: 512,
            disk_gb: 0,
            expires_at: None,
        })
        .is_err(),
        "a second active runtime lease for the same owner must be rejected"
    );
    // A different kind (storage) for the same owner_id is a distinct triple.
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "i1",
        lease_kind: LeaseKind::Storage,
        cpu_cores: 0,
        ram_mb: 0,
        disk_gb: 10,
        expires_at: None,
    })
    .unwrap();
    // After releasing the runtime lease, a fresh one is allowed again.
    db.release_lease(LeaseOwnerType::Instance, "i1", LeaseKind::Runtime)
        .unwrap();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "i1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();
}

/// DB `CHECK` constraints reject invalid lease rows: non-negative resources
/// and `expires_at >= acquired_at`.
#[test]
fn inv_db_checks_reject_invalid_lease() {
    let db = open_temp();
    let mk = |cpu: i64, ram: i64, disk: i64, expires: Option<i64>| NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "i1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: cpu,
        ram_mb: ram,
        disk_gb: disk,
        expires_at: expires,
    };
    assert!(
        db.create_lease(&mk(-1, 0, 0, None)).is_err(),
        "cpu_cores >= 0"
    );
    assert!(db.create_lease(&mk(0, -1, 0, None)).is_err(), "ram_mb >= 0");
    assert!(
        db.create_lease(&mk(0, 0, -1, None)).is_err(),
        "disk_gb >= 0"
    );
    // expires_at in the past (< acquired_at = now) violates the temporal CHECK.
    assert!(
        db.create_lease(&mk(1, 1, 0, Some(1))).is_err(),
        "expires_at must be >= acquired_at"
    );
    // A valid lease still succeeds — the CHECKs don't reject good input.
    db.create_lease(&mk(1, 1, 0, None)).unwrap();
}

/// `transfer_warm_pool_lease` is atomic and conserves allocation: the warm
/// lease is released and an instance lease created in one transaction; the
/// total active runtime allocation is unchanged.
#[test]
fn inv_transfer_warm_pool_lease_is_atomic_and_conserves_allocation() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::WarmPool,
        owner_id: "picoclaw:slot:0",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();
    assert_eq!(db.sum_active_runtime_leases().unwrap(), (2, 2048));
    assert!(
        db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
            .unwrap()
    );

    assert!(
        db.transfer_warm_pool_lease("picoclaw", "i1", 2, 2048)
            .unwrap()
    );
    assert!(
        !db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
            .unwrap()
    );
    assert!(
        db.has_active_lease_str("instance", "i1", "runtime")
            .unwrap()
    );
    // Allocation conserved — still exactly one active runtime lease.
    assert_eq!(db.sum_active_runtime_leases().unwrap(), (2, 2048));

    // No warm-pool lease left → no-op transfer returns false.
    assert!(
        !db.transfer_warm_pool_lease("picoclaw", "i2", 2, 2048)
            .unwrap()
    );
}

/// `transfer_warm_pool_lease` rolls back fully when its internal instance
/// INSERT would violate `ux_active_lease_per_owner` — the warm lease is NOT
/// released and the pre-existing instance lease is untouched.
#[test]
fn inv_transfer_warm_pool_lease_rolls_back_on_conflict() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::WarmPool,
        owner_id: "picoclaw:slot:0",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();
    // The target instance ALREADY holds an active runtime lease.
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "i1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 1,
        ram_mb: 512,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();

    assert!(
        db.transfer_warm_pool_lease("picoclaw", "i1", 2, 2048)
            .is_err(),
        "transfer onto an instance that already holds a runtime lease must fail"
    );
    // Rollback: warm lease still active; i1's original lease intact.
    assert!(
        db.has_active_lease_str("warm_pool", "picoclaw:slot:0", "runtime")
            .unwrap()
    );
    assert!(
        db.has_active_lease_str("instance", "i1", "runtime")
            .unwrap()
    );
}

/// Releasing a runtime lease drops the allocation with no leak. This is the
/// mechanism the reaper (expired) and reconcile (dead instance) use; pure
/// clock-expiry is intentionally not fabricated (the DB `CHECK
/// (expires_at >= acquired_at)` forbids a past-expiry row via the API, and we
/// do not bypass schema).
#[test]
fn inv_release_drops_runtime_allocation_no_leak() {
    let db = open_temp();
    db.create_lease(&NewLease {
        owner_type: LeaseOwnerType::Instance,
        owner_id: "i1",
        lease_kind: LeaseKind::Runtime,
        cpu_cores: 2,
        ram_mb: 2048,
        disk_gb: 0,
        expires_at: None,
    })
    .unwrap();
    assert_eq!(db.sum_active_runtime_leases().unwrap(), (2, 2048));
    db.release_lease(LeaseOwnerType::Instance, "i1", LeaseKind::Runtime)
        .unwrap();
    assert_eq!(
        db.sum_active_runtime_leases().unwrap(),
        (0, 0),
        "released lease must not leak into allocation"
    );
}

// ── shareable_apps: the Share's own identity authority (D6) ────────────

fn scoped_inst<'a>(id: &'a str, name: &'a str, container: &'a str) -> NewInstance<'a> {
    NewInstance {
        id,
        name,
        container,
        claw_type: "picoclaw",
        sunset_date: "2026-12-31",
        guest_os: None,
        aux_storage_path: None,
        cpu_cores: None,
        ram_config_mb: None,
        disk_gb: None,
        household_id: Some("hh_alpha"),
        household_machine_id: Some("m_alpha"),
    }
}

#[test]
fn shareable_ensure_is_idempotent_and_never_resyncs_display_name() {
    let db = open_temp();
    db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
        .unwrap();
    let first = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();
    assert!(first.app_id.starts_with("app_"));
    assert_eq!(first.app_id.len(), 4 + 32);
    assert_eq!(first.display_name, "alpha");
    assert_eq!(first.resource, SHAREABLE_APP_RESOURCE_CLAWSITE);

    // Instance renamed in the catalog AFTER the binding exists.
    let conn = db.conn().unwrap();
    conn.execute(
        "UPDATE instances SET name = 'alpha-renamed' WHERE id = 'inst-alpha'",
        [],
    )
    .unwrap();
    drop(conn);

    let second = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();
    assert_eq!(
        second.app_id, first.app_id,
        "ensure must reuse the live binding"
    );
    assert_eq!(
        second.display_name, "alpha",
        "ensure must NEVER re-sync display_name from instances.name"
    );
}

#[test]
fn shareable_ensure_proves_instance_authority_before_any_binding() {
    let db = open_temp();
    // Unknown instance: no binding, uniform fail-closed.
    assert!(matches!(
        db.ensure_shareable_app("inst-ghost", "hh_alpha"),
        Err(StoreError::InstanceNotFound)
    ));
    // Unscoped instance (household NULL): same.
    db.insert(&NewInstance {
        household_id: None,
        household_machine_id: None,
        ..scoped_inst("inst-unscoped", "unscoped", "picoclaw-unscoped")
    })
    .unwrap();
    assert!(matches!(
        db.ensure_shareable_app("inst-unscoped", "hh_alpha"),
        Err(StoreError::InstanceNotFound)
    ));
    // Foreign-scoped instance: same, and nothing was ever written.
    db.insert(&NewInstance {
        household_id: Some("hh_other"),
        ..scoped_inst("inst-foreign", "foreign", "picoclaw-foreign")
    })
    .unwrap();
    assert!(matches!(
        db.ensure_shareable_app("inst-foreign", "hh_alpha"),
        Err(StoreError::InstanceNotFound)
    ));
    let conn = db.conn().unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM shareable_apps", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        count, 0,
        "failed authority proofs must never write bindings"
    );
}

#[test]
fn shareable_foreign_ensure_cannot_tombstone_another_households_binding() {
    let db = open_temp();
    db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
        .unwrap();
    let app = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

    // A caller naming a DIFFERENT household while the row is still
    // hh_alpha-scoped is rejected BEFORE touching the binding.
    assert!(matches!(
        db.ensure_shareable_app("inst-alpha", "hh_evil"),
        Err(StoreError::InstanceNotFound)
    ));
    let (binding, _) = db
        .resolve_live_shareable_app(&app.app_id, "hh_alpha")
        .unwrap()
        .expect("the live binding must survive the foreign attempt");
    assert_eq!(binding.app_id, app.app_id);
    assert!(binding.retired_at.is_none());
}

#[test]
fn shareable_same_display_name_bindings_resolve_independently() {
    let db = open_temp();
    db.insert(&scoped_inst("inst-one", "one", "picoclaw-one"))
        .unwrap();
    db.insert(&scoped_inst("inst-two", "two", "picoclaw-two"))
        .unwrap();
    let app_one = db.ensure_shareable_app("inst-one", "hh_alpha").unwrap();
    let app_two = db.ensure_shareable_app("inst-two", "hh_alpha").unwrap();
    assert_ne!(app_one.app_id, app_two.app_id);

    // BOTH renamed to the same display name: identity/routing never keys on it.
    db.rename_shareable_app(&app_one.app_id, "hh_alpha", "Study")
        .unwrap();
    db.rename_shareable_app(&app_two.app_id, "hh_alpha", "Study")
        .unwrap();
    db.update_port("inst-one", 8101).unwrap();
    db.update_port("inst-two", 8202).unwrap();

    let (binding_one, instance_one) = db
        .resolve_live_shareable_app(&app_one.app_id, "hh_alpha")
        .unwrap()
        .expect("app one resolves");
    let (binding_two, instance_two) = db
        .resolve_live_shareable_app(&app_two.app_id, "hh_alpha")
        .unwrap()
        .expect("app two resolves");
    assert_eq!(binding_one.display_name, binding_two.display_name);
    assert_eq!(instance_one.host_port, Some(8101));
    assert_eq!(instance_two.host_port, Some(8202));
    assert_ne!(instance_one.id, instance_two.id);
}

#[test]
fn shareable_rename_preserves_identity_and_is_scoped_fail_closed() {
    let db = open_temp();
    db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
        .unwrap();
    let app = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

    db.rename_shareable_app(&app.app_id, "hh_alpha", "French 101")
        .unwrap();
    let (binding, _) = db
        .resolve_live_shareable_app(&app.app_id, "hh_alpha")
        .unwrap()
        .unwrap();
    assert_eq!(binding.app_id, app.app_id);
    assert_eq!(binding.display_name, "French 101");

    // Foreign household and invalid names all fail closed.
    assert!(matches!(
        db.rename_shareable_app(&app.app_id, "hh_other", "nope"),
        Err(StoreError::InstanceNotFound)
    ));
    assert!(
        db.rename_shareable_app(&app.app_id, "hh_alpha", "")
            .is_err()
    );
    assert!(
        db.rename_shareable_app(&app.app_id, "hh_alpha", "   ")
            .is_err()
    );
    assert!(
        db.rename_shareable_app(&app.app_id, "hh_alpha", &"x".repeat(129))
            .is_err()
    );
}

#[test]
fn shareable_soft_delete_tombstones_and_recreate_mints_fresh_id() {
    let db = open_temp();
    db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
        .unwrap();
    let old = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

    db.soft_delete("inst-alpha").unwrap();
    assert!(
        db.resolve_live_shareable_app(&old.app_id, "hh_alpha")
            .unwrap()
            .is_none(),
        "deleted instance must fail closed"
    );
    {
        let conn = db.conn().unwrap();
        let retired: Option<i64> = conn
            .query_row(
                "SELECT retired_at FROM shareable_apps WHERE app_id = ?1",
                params![old.app_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            retired.is_some(),
            "soft delete must tombstone the binding in the SAME transaction"
        );
    }

    // Hard delete frees the name/id; recreate with the SAME technical slug.
    db.delete("inst-alpha").unwrap();
    db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
        .unwrap();
    let new = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();
    assert_ne!(
        old.app_id, new.app_id,
        "delete+recreate must yield a different app_id"
    );
    assert!(
        db.resolve_live_shareable_app(&old.app_id, "hh_alpha")
            .unwrap()
            .is_none(),
        "the old binding stays tombstoned forever"
    );
    assert!(
        db.resolve_live_shareable_app(&new.app_id, "hh_alpha")
            .unwrap()
            .is_some()
    );
}

#[test]
fn shareable_hard_delete_never_leaves_a_live_binding() {
    let db = open_temp();
    db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
        .unwrap();
    let app = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

    // The provisioning rollback path: succeeds AND leaves nothing resolvable.
    db.delete("inst-alpha").unwrap();
    assert!(
        db.resolve_live_shareable_app(&app.app_id, "hh_alpha")
            .unwrap()
            .is_none()
    );
    let conn = db.conn().unwrap();
    let retired: Option<i64> = conn
        .query_row(
            "SELECT retired_at FROM shareable_apps WHERE app_id = ?1",
            params![app.app_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        retired.is_some(),
        "hard delete must tombstone in the same tx"
    );
}

#[test]
fn shareable_resolve_is_household_scoped_and_readiness_is_not_terminal() {
    let db = open_temp();
    db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
        .unwrap();
    let app = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

    // Foreign household: indistinguishable fail-closed None.
    assert!(
        db.resolve_live_shareable_app(&app.app_id, "hh_other")
            .unwrap()
            .is_none()
    );
    // No host_port yet: identity VALID, readiness absent — Some, not terminal.
    let (_, instance) = db
        .resolve_live_shareable_app(&app.app_id, "hh_alpha")
        .unwrap()
        .expect("identity resolves even without host_port");
    assert_eq!(instance.host_port, None);
}

#[test]
fn shareable_repair_retires_stale_binding_only_after_row_rescope() {
    let db = open_temp();
    db.insert(&scoped_inst("inst-alpha", "alpha", "picoclaw-alpha"))
        .unwrap();
    let old = db.ensure_shareable_app("inst-alpha", "hh_alpha").unwrap();

    // While the row is still hh_alpha-scoped, an hh_beta ensure is rejected
    // and the live binding is untouched.
    assert!(matches!(
        db.ensure_shareable_app("inst-alpha", "hh_beta"),
        Err(StoreError::InstanceNotFound)
    ));
    assert!(
        db.resolve_live_shareable_app(&old.app_id, "hh_alpha")
            .unwrap()
            .is_some()
    );

    // Re-pair: the row itself is re-scoped to hh_beta. The JOIN pin makes
    // the old identity stop resolving IMMEDIATELY (scope moved), and only
    // NOW may ensure tombstone the stale binding and re-mint.
    let conn = db.conn().unwrap();
    conn.execute(
        "UPDATE instances SET household_id = 'hh_beta', household_machine_id = 'm_beta' \
             WHERE id = 'inst-alpha'",
        [],
    )
    .unwrap();
    drop(conn);
    assert!(
        db.resolve_live_shareable_app(&old.app_id, "hh_alpha")
            .unwrap()
            .is_none(),
        "re-scoped instance must strand the old identity at once"
    );
    let new = db.ensure_shareable_app("inst-alpha", "hh_beta").unwrap();
    assert_ne!(old.app_id, new.app_id);
    assert_eq!(new.household_id, "hh_beta");
    assert!(
        db.resolve_live_shareable_app(&old.app_id, "hh_beta")
            .unwrap()
            .is_none(),
        "the stale binding must not resolve under any household"
    );
    assert!(
        db.resolve_live_shareable_app(&new.app_id, "hh_beta")
            .unwrap()
            .is_some()
    );
}
