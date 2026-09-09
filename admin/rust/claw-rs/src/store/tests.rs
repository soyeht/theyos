#![cfg(test)]

use super::*;

fn temp_store() -> (tempfile::TempDir, ClawStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_file = dir.path().join("installed_claws.json");
    let store = ClawStore::new(&state_file).expect("ClawStore::new");
    (dir, store)
}

#[test]
fn clawstore_new_creates_state_on_first_mutation() {
    let (_dir, store) = temp_store();
    assert!(!store.state_file.exists());
    store.mark_ready("picoclaw").expect("mark_ready");
    assert!(store.state_file.exists());
}

/// Regression test for the fresh-install crash: when the state
/// file's *parent* directory does not exist yet, `persist()` must
/// create it instead of returning ENOENT. Reproduces the user-facing
/// "failed to mark installing: IO error: No such file or directory"
/// that fired on the very first Claw install attempt against a
/// brand-new theyos engine on macOS Sequoia.
#[test]
fn clawstore_persist_creates_missing_parent_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Path one level deeper than the tempdir — parent doesn't exist.
    let nested = dir.path().join(".run").join("installed_claws.json");
    assert!(!nested.parent().unwrap().exists());

    let store = ClawStore::new(&nested).expect("ClawStore::new tolerates missing path");
    store
        .mark_installing("picoclaw", "job_42")
        .expect("mark_installing must create the missing parent directory");

    assert!(nested.exists(), "state file written");
    assert!(nested.parent().unwrap().exists(), "parent dir created");

    // Round-trip: re-loading sees the persisted state.
    let store2 = ClawStore::new(&nested).expect("reload");
    assert_eq!(store2.get_status("picoclaw"), ClawStatus::Installing);
}

#[test]
fn clawstore_mark_installing_persists() {
    let (dir, store) = temp_store();
    store
        .mark_installing("picoclaw", "job_123")
        .expect("mark_installing");

    // Re-load from disk
    let store2 = ClawStore::new(&dir.path().join("installed_claws.json")).expect("reload");
    assert_eq!(store2.get_status("picoclaw"), ClawStatus::Installing);
    let state = store2.get_state("picoclaw").expect("state exists");
    assert_eq!(state.job_id.as_deref(), Some("job_123"));
}

/// Build a store whose state-file parent *component* is a regular file, so
/// every `persist()` fails with `NotADirectory`. Deterministic and root-safe
/// (you cannot `create_dir_all` under a file) — no production seam needed.
fn store_with_unwritable_parent() -> (tempfile::TempDir, ClawStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"x").expect("write blocker file");
    let state_file = blocker.join("installed_claws.json");
    let store = ClawStore::new(&state_file).expect("ClawStore::new is lazy");
    (dir, store)
}

#[test]
fn mark_installing_persist_failure_preserves_in_memory_state() {
    let (_dir, store) = store_with_unwritable_parent();
    assert_eq!(store.get_status("picoclaw"), ClawStatus::NotInstalled);
    let err = store
        .mark_installing("picoclaw", "job_x")
        .expect_err("persist must fail when a parent component is a file");
    assert!(
        matches!(err, StoreError::Io(_)),
        "expected IO error, got {err:?}"
    );
    assert_eq!(
        store.get_status("picoclaw"),
        ClawStatus::NotInstalled,
        "no drift to Installing on persist failure"
    );
}

#[test]
fn mark_uninstalling_persist_failure_preserves_ready_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sub = dir.path().join("run");
    std::fs::create_dir_all(&sub).expect("mkdir run");
    let state_file = sub.join("installed_claws.json");
    let store = ClawStore::new(&state_file).expect("ClawStore::new");
    store.mark_ready("picoclaw").expect("mark_ready");
    assert_eq!(store.get_status("picoclaw"), ClawStatus::Ready);

    // Swap the parent component `run` from a directory to a regular file so
    // the next persist() fails with NotADirectory.
    std::fs::remove_dir_all(&sub).expect("rm run");
    std::fs::write(&sub, b"x").expect("replace run dir with a file");

    store
        .mark_uninstalling("picoclaw")
        .expect_err("persist must fail when the parent component is a file");
    assert_eq!(
        store.get_status("picoclaw"),
        ClawStatus::Ready,
        "no drift to Uninstalling on persist failure"
    );
}

#[test]
fn mark_not_installed_persist_failure_preserves_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sub = dir.path().join("run");
    std::fs::create_dir_all(&sub).expect("mkdir run");
    let state_file = sub.join("installed_claws.json");
    let store = ClawStore::new(&state_file).expect("ClawStore::new");
    store.mark_ready("picoclaw").expect("mark_ready");

    std::fs::remove_dir_all(&sub).expect("rm run");
    std::fs::write(&sub, b"x").expect("replace run dir with a file");

    store
        .mark_not_installed("picoclaw")
        .expect_err("persist must fail when the parent component is a file");
    assert_eq!(
        store.get_status("picoclaw"),
        ClawStatus::Ready,
        "entry must be preserved (not removed) on persist failure"
    );
}

#[test]
fn clawstore_mark_ready_sets_timestamp() {
    let (_dir, store) = temp_store();
    store.mark_ready("picoclaw").expect("mark_ready");
    let state = store.get_state("picoclaw").expect("state");
    assert_eq!(state.status, ClawStatus::Ready);
    assert!(state.installed_at.is_some());
    assert!(state.error.is_none());
}

#[test]
fn clawstore_mark_failed_stores_error() {
    let (_dir, store) = temp_store();
    store
        .mark_failed("picoclaw", "golden build timed out")
        .expect("mark_failed");
    let state = store.get_state("picoclaw").expect("state");
    assert_eq!(state.status, ClawStatus::Failed);
    assert_eq!(state.error.as_deref(), Some("golden build timed out"));
}

#[test]
fn clawstore_installed_and_ready_filters() {
    let (_dir, store) = temp_store();
    store.mark_ready("picoclaw").unwrap();
    store.mark_installing("zeroclaw", "job_1").unwrap();
    store.mark_failed("nanobot", "oops").unwrap();

    let ready = store.installed_and_ready();
    assert_eq!(ready, vec!["picoclaw"]);
}

#[test]
fn clawstore_is_ready_true_for_ready() {
    let (_dir, store) = temp_store();
    store.mark_ready("picoclaw").unwrap();
    assert!(store.is_ready("picoclaw"));
}

#[test]
fn clawstore_is_ready_false_for_installing() {
    let (_dir, store) = temp_store();
    store.mark_installing("picoclaw", "job_1").unwrap();
    assert!(!store.is_ready("picoclaw"));
}

#[test]
fn clawstore_is_ready_false_for_unknown() {
    let (_dir, store) = temp_store();
    assert!(!store.is_ready("nonexistent"));
}

#[test]
fn clawstore_mark_not_installed_removes_entry() {
    let (_dir, store) = temp_store();
    store.mark_ready("picoclaw").unwrap();
    assert!(store.is_ready("picoclaw"));

    store.mark_not_installed("picoclaw").unwrap();
    assert!(!store.is_ready("picoclaw"));
    assert_eq!(store.get_status("picoclaw"), ClawStatus::NotInstalled);
}

#[test]
fn clawstore_seed_from_assets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let assets = dir.path().join("assets");

    // Create a consistent golden for picoclaw (symlink + matching metadata).
    // Snapshot is not needed; golden-only is sufficient for Ready.
    let fp = "a".repeat(64);
    build_golden(&assets, "picoclaw", &fp, &fp, "picoclaw", true, true, true);

    let state_file = dir.path().join("state.json");
    let store = ClawStore::new(&state_file).unwrap();
    store.seed_from_assets(&assets);

    assert!(store.is_ready("picoclaw"));
    // zeroclaw has no assets → still not installed
    assert!(!store.is_ready("zeroclaw"));
}

#[test]
fn clawstore_reset_stale_installing() {
    let (_dir, store) = temp_store();
    store.mark_installing("picoclaw", "job_1").unwrap();
    store.mark_ready("zeroclaw").unwrap();

    store.reset_stale_installing();

    assert_eq!(store.get_status("picoclaw"), ClawStatus::Failed);
    assert_eq!(store.get_status("zeroclaw"), ClawStatus::Ready); // unchanged
}

#[test]
fn clawstore_catalog_with_status_merges() {
    let (_dir, store) = temp_store();
    store.mark_ready("picoclaw").unwrap();

    let catalog = store.catalog_with_status();
    assert!(!catalog.is_empty());

    let pico = catalog
        .iter()
        .find(|c| c.name == "picoclaw")
        .expect("picoclaw");
    assert_eq!(pico.status, ClawStatus::Ready);
    assert!(pico.installed_at.is_some());
    // Without a verify-results path, verify fields are never populated.
    assert!(pico.verify_status.is_none());

    let zero = catalog
        .iter()
        .find(|c| c.name == "zeroclaw")
        .expect("zeroclaw");
    assert_eq!(zero.status, ClawStatus::NotInstalled);
}

#[test]
fn clawstore_catalog_with_status_merged_includes_verify_results() {
    let (dir, store) = temp_store();
    store.mark_ready("picoclaw").unwrap();

    let vr_path = dir.path().join("verify-results.json");
    let ok = verify_results::VerifyResult {
        verify_status: verify_results::VerifyStatus::Ok,
        verify_error: None,
        verify_log_path: None,
        verify_attempted_at: Some("2026-04-14T12:00:00Z".into()),
    };
    verify_results::record(&vr_path, "picoclaw", &ok).unwrap();
    let failed = verify_results::VerifyResult {
        verify_status: verify_results::VerifyStatus::Failed,
        verify_error: Some("boom".into()),
        verify_log_path: None,
        verify_attempted_at: Some("2026-04-14T12:00:00Z".into()),
    };
    verify_results::record(&vr_path, "zeroclaw", &failed).unwrap();

    let catalog = store.catalog_with_status_merged(Some(&vr_path));
    let pico = catalog.iter().find(|c| c.name == "picoclaw").unwrap();
    assert_eq!(pico.verify_status.as_deref(), Some("ok"));
    assert!(pico.verify_error.is_none());

    let zero = catalog.iter().find(|c| c.name == "zeroclaw").unwrap();
    assert_eq!(zero.verify_status.as_deref(), Some("failed"));
    assert_eq!(zero.verify_error.as_deref(), Some("boom"));
}

#[test]
fn clawstore_catalog_with_status_merged_tolerates_missing_file() {
    let (_dir, store) = temp_store();
    store.mark_ready("picoclaw").unwrap();
    let missing = std::path::PathBuf::from("/nonexistent/verify-results.json");
    let catalog = store.catalog_with_status_merged(Some(&missing));
    let pico = catalog.iter().find(|c| c.name == "picoclaw").unwrap();
    assert!(pico.verify_status.is_none());
}

#[test]
fn catalog_installable_matches_handler_installability_api() {
    // The catalog response and the install handler MUST agree —
    // both delegate to ManifestEntry::installability(). This test
    // sweeps every entry and asserts the two views agree, so future
    // catalog changes cannot reintroduce the iOS Claw Store bug where
    // the UI offered an Install button for entries the backend rejects.
    let (_dir, store) = temp_store();
    let catalog = store.catalog_with_status();
    for entry in manifest::catalog() {
        let row = catalog
            .iter()
            .find(|c| c.name == entry.name)
            .unwrap_or_else(|| panic!("catalog row missing for {}", entry.name));
        let expected_installable =
            matches!(entry.installability(), ClawInstallability::Installable);
        assert_eq!(
            row.installable, expected_installable,
            "{} disagrees with ManifestEntry::installability()",
            entry.name
        );
        if expected_installable {
            assert!(row.unavailable_reason_code.is_none());
            assert!(row.unavailable_reason.is_none());
        } else {
            let ClawInstallability::Unavailable { code, message } = entry.installability() else {
                unreachable!()
            };
            assert_eq!(row.unavailable_reason_code, Some(code));
            assert_eq!(row.unavailable_reason.as_deref(), Some(message.as_str()));
        }
    }
}

#[test]
fn catalog_claude_claw_is_unavailable_catalog_only_with_human_message() {
    let (_dir, store) = temp_store();
    let catalog = store.catalog_with_status();
    let claude = catalog
        .iter()
        .find(|c| c.name == "claude-claw")
        .expect("claude-claw must exist in catalog");
    assert!(!claude.installable);
    assert_eq!(
        claude.unavailable_reason_code,
        Some(UnavailableReasonCode::CatalogOnly)
    );
    let reason = claude.unavailable_reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("Claude Code plugin"),
        "expected manifest skip_install_reason in unavailable_reason, got: {reason}"
    );
}

#[test]
fn catalog_unavailable_reason_code_serialises_snake_case() {
    // Wire-format guarantee for the iPhone/Mac UI: the code is a
    // snake_case string, not a JSON object or upper-case enum name.
    let (_dir, store) = temp_store();
    let catalog = store.catalog_with_status();
    let claude = catalog
        .iter()
        .find(|c| c.name == "claude-claw")
        .expect("claude-claw must exist in catalog");
    let json = serde_json::to_value(claude).unwrap();
    assert_eq!(json["installable"], serde_json::Value::Bool(false));
    assert_eq!(
        json["unavailable_reason_code"],
        serde_json::Value::String("catalog_only".to_string()),
    );
}

// golden_ready_consistent / seed fingerprint check

/// Build a modern golden under `assets/goldens/<claw>/<dir_fp>/` with a
/// `current` symlink to `dir_fp`, writing metadata with `meta_fp` and
/// `meta_claw_type`. The `write_*`/`make_symlink` flags omit pieces to
/// exercise the missing-part cases.
#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
fn build_golden(
    assets: &Path,
    claw: &str,
    dir_fp: &str,
    meta_fp: &str,
    meta_claw_type: &str,
    write_rootfs: bool,
    write_meta_file: bool,
    make_symlink: bool,
) {
    use core_rs::artifact_meta::{self, Fingerprint, GoldenMeta};
    let fp = Fingerprint::new(dir_fp);
    let version_dir = artifact_meta::golden_version_dir(assets, claw, &fp);
    std::fs::create_dir_all(&version_dir).unwrap();
    if write_rootfs {
        std::fs::write(version_dir.join("rootfs.ext4"), b"rootfs").unwrap();
    }
    if write_meta_file {
        let meta = GoldenMeta {
            claw_type: meta_claw_type.to_string(),
            fingerprint: Fingerprint::new(meta_fp),
            base_rootfs_sha256: "b".repeat(64),
            installer_plan_sha256: "c".repeat(64),
            kernel_sha256: "d".repeat(64),
            builder_version: "test".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        artifact_meta::write_meta(&version_dir.join("golden.meta.json"), &meta).unwrap();
    }
    if make_symlink {
        let link = artifact_meta::golden_current_link(assets, claw);
        artifact_meta::update_current_link(&link, &fp).unwrap();
    }
}

fn first_supported_claw() -> Option<String> {
    manifest::catalog()
        .into_iter()
        .find(|e| e.tier == manifest::Tier::Supported)
        .map(|e| e.name.to_string())
}

#[test]
fn golden_consistent_matching_is_true() {
    let tmp = tempfile::tempdir().unwrap();
    let fp = "e".repeat(64);
    build_golden(
        tmp.path(),
        "picoclaw",
        &fp,
        &fp,
        "picoclaw",
        true,
        true,
        true,
    );
    assert!(golden_ready_consistent(tmp.path(), "picoclaw"));
}

#[test]
fn golden_consistent_missing_meta_is_false() {
    let tmp = tempfile::tempdir().unwrap();
    let fp = "e".repeat(64);
    // rootfs + symlink, but no golden.meta.json.
    build_golden(
        tmp.path(),
        "picoclaw",
        &fp,
        &fp,
        "picoclaw",
        true,
        false,
        true,
    );
    assert!(!golden_ready_consistent(tmp.path(), "picoclaw"));
}

#[test]
fn golden_consistent_mismatched_fingerprint_is_false() {
    let tmp = tempfile::tempdir().unwrap();
    // Install dir/symlink fingerprint != metadata fingerprint.
    build_golden(
        tmp.path(),
        "picoclaw",
        &"e".repeat(64),
        &"f".repeat(64),
        "picoclaw",
        true,
        true,
        true,
    );
    assert!(!golden_ready_consistent(tmp.path(), "picoclaw"));
}

#[test]
fn golden_consistent_wrong_claw_type_is_false() {
    let tmp = tempfile::tempdir().unwrap();
    let fp = "e".repeat(64);
    build_golden(
        tmp.path(),
        "picoclaw",
        &fp,
        &fp,
        "otherclaw",
        true,
        true,
        true,
    );
    assert!(!golden_ready_consistent(tmp.path(), "picoclaw"));
}

#[test]
fn golden_consistent_missing_symlink_or_rootfs_is_false() {
    let fp = "e".repeat(64);
    // No `current` symlink: version dir has meta+rootfs but nothing resolves.
    let tmp = tempfile::tempdir().unwrap();
    build_golden(
        tmp.path(),
        "picoclaw",
        &fp,
        &fp,
        "picoclaw",
        true,
        true,
        false,
    );
    assert!(!golden_ready_consistent(tmp.path(), "picoclaw"));

    // Symlink+meta present but rootfs.ext4 absent.
    let tmp2 = tempfile::tempdir().unwrap();
    build_golden(
        tmp2.path(),
        "picoclaw",
        &fp,
        &fp,
        "picoclaw",
        false,
        true,
        true,
    );
    assert!(!golden_ready_consistent(tmp2.path(), "picoclaw"));
}

#[test]
fn seed_marks_ready_on_consistent_golden() {
    let Some(claw) = first_supported_claw() else {
        return; // no Supported claw in catalog; nothing to seed
    };
    let (_sdir, store) = temp_store();
    let assets = tempfile::tempdir().unwrap();
    let fp = "a".repeat(64);
    build_golden(assets.path(), &claw, &fp, &fp, &claw, true, true, true);

    store.seed_from_assets(assets.path());
    assert!(store.is_ready(&claw), "consistent golden should seed Ready");
}

#[test]
fn seed_skips_inconsistent_golden() {
    let Some(claw) = first_supported_claw() else {
        return;
    };
    let (_sdir, store) = temp_store();
    let assets = tempfile::tempdir().unwrap();
    // Metadata fingerprint != install dir fingerprint.
    build_golden(
        assets.path(),
        &claw,
        &"a".repeat(64),
        &"b".repeat(64),
        &claw,
        true,
        true,
        true,
    );

    store.seed_from_assets(assets.path());
    assert!(
        !store.is_ready(&claw),
        "inconsistent golden must not seed Ready"
    );
}

#[test]
fn seed_marks_ready_on_legacy_golden() {
    let Some(claw) = first_supported_claw() else {
        return;
    };
    let (_sdir, store) = temp_store();
    let assets = tempfile::tempdir().unwrap();
    std::fs::write(
        assets.path().join(format!("ubuntu-24.04-{claw}.ext4")),
        b"legacy",
    )
    .unwrap();

    store.seed_from_assets(assets.path());
    assert!(
        store.is_ready(&claw),
        "legacy golden should still seed Ready"
    );
}
