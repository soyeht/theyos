#![cfg(test)]

use super::*;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn set_test_env_var(key: &str, value: &str) {
    // SAFETY: these test helpers are used in narrow, synchronous tests and
    // restore state immediately after the assertion window.
    unsafe { std::env::set_var(key, value) };
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn remove_test_env_var(key: &str) {
    // SAFETY: paired with `set_test_env_var` in test-only code.
    unsafe { std::env::remove_var(key) };
}

/// Create a fake root with release dir and populate it with dummy binaries.
fn setup_fake_root(tmpdir: &Path) -> PathBuf {
    let root = tmpdir.to_path_buf();
    let rel = release_dir(&root);
    fs::create_dir_all(&rel).expect("create release dir");

    // Create fake binaries with known content
    for (i, bin) in KEY_BINS.iter().enumerate() {
        let content = format!("binary-v1-{bin}-{i}");
        fs::write(rel.join(bin), content.as_bytes()).expect("write fake binary");
    }
    root
}

#[test]
fn snapshot_previous_copies_all_binaries() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());

    assert!(snapshot_previous(&root));

    let prev = previous_dir(&root);
    assert!(prev.is_dir());

    for bin in KEY_BINS {
        let snapped = prev.join(bin);
        assert!(snapped.is_file(), "previous should contain {bin}");
        let original = fs::read_to_string(release_dir(&root).join(bin)).unwrap();
        let copy = fs::read_to_string(&snapped).unwrap();
        assert_eq!(original, copy, "snapshot of {bin} should match original");
    }
}

#[test]
fn backup_copies_from_previous() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());

    // Snapshot v1 into .deploy-previous/
    assert!(snapshot_previous(&root));

    // Now backup reads from .deploy-previous/, not release_dir
    assert!(backup_binaries(&root));

    let bak = backup_dir(&root);
    assert!(bak.is_dir());

    for bin in KEY_BINS {
        let backed_up = bak.join(bin);
        assert!(backed_up.is_file(), "backup should contain {bin}");
        let prev_content = fs::read_to_string(previous_dir(&root).join(bin)).unwrap();
        let bak_content = fs::read_to_string(&backed_up).unwrap();
        assert_eq!(
            prev_content, bak_content,
            "backup of {bin} should match previous"
        );
    }
}

#[test]
fn backup_succeeds_without_previous_dir() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());

    // No .deploy-previous/ dir — first-ever deploy scenario
    // backup_binaries should succeed (return true) but not create a backup
    assert!(backup_binaries(&root));
    assert!(
        !backup_dir(&root).exists(),
        "no backup should be created without previous"
    );
}

#[test]
fn backup_partial_previous() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = tmpdir.path().to_path_buf();
    let rel = release_dir(&root);
    fs::create_dir_all(&rel).expect("create release dir");

    // Only create 3 out of the tracked runtime binaries
    for bin in &KEY_BINS[..3] {
        fs::write(rel.join(bin), b"data").expect("write");
    }

    // Snapshot the 3 binaries
    assert!(snapshot_previous(&root));

    // Backup from previous
    assert!(backup_binaries(&root));

    let bak = backup_dir(&root);
    let mut count = 0;
    for bin in KEY_BINS {
        if bak.join(bin).is_file() {
            count += 1;
        }
    }
    assert_eq!(
        count, 3,
        "should backup only existing binaries from previous"
    );
}

#[test]
fn restore_copies_from_backup() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());

    // Snapshot v1, then backup from snapshot
    assert!(snapshot_previous(&root));
    assert!(backup_binaries(&root));

    // Overwrite release dir with v2
    let rel = release_dir(&root);
    for bin in KEY_BINS {
        fs::write(rel.join(bin), b"binary-v2").expect("overwrite");
    }

    // Restore should bring back v1
    assert!(restore_binaries(&root));

    for (i, bin) in KEY_BINS.iter().enumerate() {
        let content = fs::read_to_string(rel.join(bin)).unwrap();
        let expected = format!("binary-v1-{bin}-{i}");
        assert_eq!(
            content, expected,
            "restored {bin} should be v1, got: {content}"
        );
    }
}

#[test]
fn restore_fails_when_no_backup() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());

    // No backup created -> restore should fail
    assert!(!restore_binaries(&root));
}

#[test]
fn cleanup_removes_backup_dir() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());

    assert!(snapshot_previous(&root));
    assert!(backup_binaries(&root));
    assert!(backup_dir(&root).is_dir());

    cleanup_backup(&root);
    assert!(!backup_dir(&root).exists());
}

#[test]
fn backup_overwrites_stale_backup() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());

    // Snapshot + backup v1
    assert!(snapshot_previous(&root));
    assert!(backup_binaries(&root));

    // Modify a binary in release and re-snapshot
    let rel = release_dir(&root);
    fs::write(rel.join(KEY_BINS[0]), b"modified-v2").expect("modify");
    assert!(snapshot_previous(&root));

    // Backup again — should overwrite with modified-v2
    assert!(backup_binaries(&root));

    let bak_content = fs::read_to_string(backup_dir(&root).join(KEY_BINS[0])).unwrap();
    assert_eq!(
        bak_content, "modified-v2",
        "stale backup should be overwritten"
    );
}

#[test]
fn full_cycle_snapshot_build_deploy_rollback() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());
    let rel = release_dir(&root);

    // 1. Snapshot v1 (simulates cmd_build saving production binaries)
    assert!(snapshot_previous(&root));

    // 2. Simulate cargo build overwriting release with v2
    for bin in KEY_BINS {
        fs::write(rel.join(bin), b"new-build-v2").expect("overwrite");
    }

    // 3. cmd_deploy: backup from .deploy-previous/ (the real v1)
    assert!(backup_binaries(&root));

    // 4. Simulate staging -> release promotion (v2 already in release)

    // 5. Smoke test fails — rollback restores v1 from backup
    assert!(restore_binaries(&root));

    // 6. Verify all binaries are the original v1 (not v2)
    for (i, bin) in KEY_BINS.iter().enumerate() {
        let content = fs::read_to_string(rel.join(bin)).unwrap();
        let expected = format!("binary-v1-{bin}-{i}");
        assert_eq!(content, expected, "{bin} should be restored to v1, not v2");
    }

    // 7. Cleanup
    cleanup_backup(&root);
    assert!(!backup_dir(&root).exists());
    cleanup_previous(&root);
    assert!(!previous_dir(&root).exists());
}

#[test]
fn key_bins_has_five_runtime_entries() {
    assert_eq!(KEY_BINS.len(), 5, "deploy tracks 5 runtime key binaries");
}

#[test]
#[cfg(not(target_os = "macos"))]
fn all_claws_has_eight_entries() {
    assert_eq!(all_claws().len(), 8, "should cover all 8 claw types");
}

#[test]
fn stage_copies_all_binaries() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());

    assert!(stage_binaries(&root));

    let stg = staging_dir(&root);
    assert!(stg.is_dir());

    for bin in KEY_BINS {
        let staged = stg.join(bin);
        assert!(staged.is_file(), "staging should contain {bin}");
        let original = fs::read_to_string(release_dir(&root).join(bin)).unwrap();
        let copy = fs::read_to_string(&staged).unwrap();
        assert_eq!(original, copy, "staged {bin} should match original");
    }
}

#[test]
fn promote_copies_staging_to_release() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());

    // Stage v1
    assert!(stage_binaries(&root));

    // Overwrite release with v2
    let rel = release_dir(&root);
    for bin in KEY_BINS {
        fs::write(rel.join(bin), b"binary-v2").expect("overwrite");
    }

    // Promote should restore staged v1
    assert!(promote_staging(&root));

    for (i, bin) in KEY_BINS.iter().enumerate() {
        let content = fs::read_to_string(rel.join(bin)).unwrap();
        let expected = format!("binary-v1-{bin}-{i}");
        assert_eq!(
            content, expected,
            "promoted {bin} should be v1 from staging"
        );
    }
}

#[test]
fn promote_fails_without_staging() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let root = setup_fake_root(tmpdir.path());

    // No staging dir -> promote should fail
    assert!(!promote_staging(&root));
}

// ── macOS-specific tests ──────────────────────────────────────────────────

#[cfg(target_os = "macos")]
#[test]
fn resolve_state_dir_uses_env() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let state = tmpdir.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(state.join(".env"), "FOO=bar\n").unwrap();

    // SAFETY: single-threaded test context
    set_test_env_var("THEYOS_DIR", state.to_str().unwrap());
    let result = resolve_state_dir();
    remove_test_env_var("THEYOS_DIR");

    assert_eq!(result, state);
}

#[cfg(target_os = "macos")]
#[test]
fn resolve_repo_dir_from_env() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let repo = tmpdir.path().join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    fs::create_dir_all(repo.join("admin")).unwrap();
    fs::write(repo.join("flake.nix"), "# test").unwrap();

    set_test_env_var("THEYOS_REPO_DIR", repo.to_str().unwrap());
    let result = resolve_repo_dir();
    remove_test_env_var("THEYOS_REPO_DIR");

    assert_eq!(result, repo);
}

#[cfg(target_os = "macos")]
#[test]
fn backup_restore_macos_roundtrip() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let bin_dir = tmpdir.path().join("libexec");
    fs::create_dir_all(&bin_dir).unwrap();

    // Create fake binaries
    for bin in KEY_BINS_MACOS {
        fs::write(bin_dir.join(bin), format!("original-{bin}")).unwrap();
    }

    // Backup
    assert!(backup_macos_binaries(&bin_dir));
    assert!(bin_dir.join(".deploy-backup").is_dir());

    // Modify originals
    for bin in KEY_BINS_MACOS {
        fs::write(bin_dir.join(bin), format!("modified-{bin}")).unwrap();
    }

    // Restore
    assert!(restore_macos_binaries(&bin_dir));

    // Verify originals restored
    for bin in KEY_BINS_MACOS {
        let content = fs::read_to_string(bin_dir.join(bin)).unwrap();
        assert_eq!(
            content,
            format!("original-{bin}"),
            "restore should bring back original {bin}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn backup_handles_first_install() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let bin_dir = tmpdir.path().join("libexec");
    fs::create_dir_all(&bin_dir).unwrap();

    // No binaries exist yet — should succeed gracefully
    assert!(backup_macos_binaries(&bin_dir));
}

#[cfg(target_os = "macos")]
#[test]
fn promote_macos_fails_missing_binary() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let repo = tmpdir.path().join("repo");
    let release = repo.join("admin/rust/target/release");
    fs::create_dir_all(&release).unwrap();
    let bin_dir = tmpdir.path().join("libexec");
    fs::create_dir_all(&bin_dir).unwrap();

    // Only create 1 binary — should fail because others are missing
    fs::write(release.join("soyeht"), "fake").unwrap();

    assert!(!promote_macos_binaries(&repo, &bin_dir));
}

#[cfg(target_os = "macos")]
#[test]
fn ensure_env_vars_idempotent() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let state = tmpdir.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(state.join(".env"), "EXISTING=value\n").unwrap();

    let bin = PathBuf::from("/opt/test/libexec");
    let web = PathBuf::from("/opt/test/libexec/web");

    // Call twice — should not duplicate entries
    // SAFETY: single-threaded test
    set_test_env_var("THEYOS_DIR", state.to_str().unwrap());
    ensure_env_vars(&state, &bin, &web);
    ensure_env_vars(&state, &bin, &web);
    remove_test_env_var("THEYOS_DIR");

    let content = fs::read_to_string(state.join(".env")).unwrap();
    let bin_dir_count = content
        .lines()
        .filter(|l| l.starts_with("THEYOS_BIN_DIR="))
        .count();
    assert_eq!(
        bin_dir_count, 1,
        "THEYOS_BIN_DIR should appear exactly once"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn ensure_env_vars_corrects_stale() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let state = tmpdir.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(
        state.join(".env"),
        "THEYOS_BIN_DIR=/old/path\nWEB_DIR=/old/web\n",
    )
    .unwrap();

    let bin = PathBuf::from("/new/path");
    let web = PathBuf::from("/new/web");

    set_test_env_var("THEYOS_DIR", state.to_str().unwrap());
    ensure_env_vars(&state, &bin, &web);
    remove_test_env_var("THEYOS_DIR");

    let content = fs::read_to_string(state.join(".env")).unwrap();
    assert!(
        content.contains("THEYOS_BIN_DIR=/new/path"),
        "should update stale value"
    );
    assert!(
        content.contains("WEB_DIR=/new/web"),
        "should update stale WEB_DIR"
    );
    assert!(!content.contains("/old/"), "stale values should be gone");
}

#[cfg(target_os = "macos")]
#[test]
fn ensure_wrapper_always_rewrites() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    // Simulate Homebrew layout: bin/ and libexec/ (parent of bin_dir is the
    // Homebrew prefix, bin/ is a sibling)
    let prefix = tmpdir.path().join("theyos");
    let bin_dir = prefix.join("libexec");
    let brew_bin = prefix.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&brew_bin).unwrap();

    // Write a raw binary (simulating overwritten wrapper)
    fs::write(brew_bin.join("soyeht"), b"\xCF\xFA\xED\xFE").unwrap();
    fs::write(brew_bin.join("theyos"), b"\xCF\xFA\xED\xFE").unwrap();
    fs::write(brew_bin.join("init_macos_guest"), b"\xCF\xFA\xED\xFE").unwrap();

    ensure_wrapper(&bin_dir);

    for name in ["soyeht", "theyos", "init_macos_guest"] {
        let content = fs::read_to_string(brew_bin.join(name)).unwrap();
        assert!(
            content.starts_with("#!/bin/sh"),
            "{name} should be a shell wrapper"
        );
        assert!(
            content.contains("THEYOS_BIN_DIR"),
            "{name} wrapper should set THEYOS_BIN_DIR"
        );
        assert!(
            content.contains("export THEYOS_VMRUNNER_RS_BIN="),
            "{name} wrapper should set canonical vmrunner env"
        );
        assert!(
            content.contains("export THEYOS_VMRUNNER_MACOS_RS_BIN=\"$THEYOS_VMRUNNER_RS_BIN\""),
            "{name} wrapper should alias legacy vmrunner env to canonical env"
        );
    }
}
