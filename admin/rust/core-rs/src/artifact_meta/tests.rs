#![cfg(test)]

use super::*;

// ── Fingerprint ─────────────────────────────────────────────────────

#[test]
fn fingerprint_new_and_display() {
    let fp = Fingerprint::new("abc123def456");
    assert_eq!(fp.as_str(), "abc123def456");
    assert_eq!(fp.to_string(), "abc123def456");
}

#[test]
fn fingerprint_short_truncates_to_12() {
    let fp = Fingerprint::new("abcdef012345678901234567890123456789");
    assert_eq!(fp.short(), "abcdef012345");
}

#[test]
fn fingerprint_short_on_short_string() {
    let fp = Fingerprint::new("abc");
    assert_eq!(fp.short(), "abc");
}

#[test]
fn fingerprint_equality() {
    let a = Fingerprint::new("aaa");
    let b = Fingerprint::new("aaa");
    let c = Fingerprint::new("bbb");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ── Golden fingerprint computation ──────────────────────────────────

#[test]
fn golden_fingerprint_deterministic() {
    let fp1 = golden_fingerprint("rootfs_hash", "plan_hash", "kernel_hash");
    let fp2 = golden_fingerprint("rootfs_hash", "plan_hash", "kernel_hash");
    assert_eq!(fp1, fp2, "same inputs must produce same fingerprint");
}

#[test]
fn golden_fingerprint_changes_with_rootfs() {
    let fp1 = golden_fingerprint("rootfs_a", "plan", "kernel");
    let fp2 = golden_fingerprint("rootfs_b", "plan", "kernel");
    assert_ne!(
        fp1, fp2,
        "different rootfs must produce different fingerprint"
    );
}

#[test]
fn golden_fingerprint_changes_with_plan() {
    let fp1 = golden_fingerprint("rootfs", "plan_a", "kernel");
    let fp2 = golden_fingerprint("rootfs", "plan_b", "kernel");
    assert_ne!(
        fp1, fp2,
        "different plan must produce different fingerprint"
    );
}

#[test]
fn golden_fingerprint_changes_with_kernel() {
    let fp1 = golden_fingerprint("rootfs", "plan", "kernel_a");
    let fp2 = golden_fingerprint("rootfs", "plan", "kernel_b");
    assert_ne!(
        fp1, fp2,
        "different kernel must produce different fingerprint"
    );
}

#[test]
fn golden_fingerprint_is_64_hex_chars() {
    let fp = golden_fingerprint("r", "p", "k");
    assert_eq!(fp.as_str().len(), 64, "SHA-256 hex digest is 64 chars");
    assert!(
        fp.as_str().chars().all(|c| c.is_ascii_hexdigit()),
        "must be hex"
    );
}

// ── Snapshot fingerprint computation ────────────────────────────────

#[test]
fn snapshot_fingerprint_deterministic() {
    let gfp = Fingerprint::new("golden123");
    let fp1 = snapshot_fingerprint(&gfp, "kernel_hash");
    let fp2 = snapshot_fingerprint(&gfp, "kernel_hash");
    assert_eq!(fp1, fp2);
}

#[test]
fn snapshot_fingerprint_changes_with_golden() {
    let fp1 = snapshot_fingerprint(&Fingerprint::new("golden_a"), "kernel");
    let fp2 = snapshot_fingerprint(&Fingerprint::new("golden_b"), "kernel");
    assert_ne!(fp1, fp2);
}

#[test]
fn snapshot_fingerprint_changes_with_kernel() {
    let gfp = Fingerprint::new("golden");
    let fp1 = snapshot_fingerprint(&gfp, "kernel_a");
    let fp2 = snapshot_fingerprint(&gfp, "kernel_b");
    assert_ne!(fp1, fp2);
}

// ── Staleness detection ─────────────────────────────────────────────

#[test]
fn golden_stale_when_missing() {
    let expected = Fingerprint::new("expected");
    let reason = golden_stale_reason(None, &expected);
    assert_eq!(reason, Some(StaleReason::Missing));
}

#[test]
fn golden_fresh_when_fingerprint_matches() {
    let fp = golden_fingerprint("r", "p", "k");
    let meta = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: fp.clone(),
        base_rootfs_sha256: "r".into(),
        installer_plan_sha256: "p".into(),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    assert_eq!(golden_stale_reason(Some(&meta), &fp), None);
}

#[test]
fn golden_stale_when_fingerprint_differs() {
    let fp = golden_fingerprint("r", "p", "k");
    let meta = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: Fingerprint::new("old_fingerprint"),
        base_rootfs_sha256: "r_old".into(),
        installer_plan_sha256: "p".into(),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    let reason = golden_stale_reason(Some(&meta), &fp);
    assert!(reason.is_some());
    assert!(matches!(reason, Some(StaleReason::InputChanged { .. })));
}

#[test]
fn golden_stale_detailed_identifies_rootfs_change() {
    let meta = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: golden_fingerprint("old_rootfs", "p", "k"),
        base_rootfs_sha256: "old_rootfs".into(),
        installer_plan_sha256: "p".into(),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    let reason = golden_stale_reason_detailed(Some(&meta), "new_rootfs", "p", "k");
    assert_eq!(
        reason,
        Some(StaleReason::InputChanged {
            field: "base_rootfs_sha256".into()
        })
    );
}

#[test]
fn golden_stale_detailed_identifies_plan_change() {
    let meta = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: golden_fingerprint("r", "old_plan", "k"),
        base_rootfs_sha256: "r".into(),
        installer_plan_sha256: "old_plan".into(),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    let reason = golden_stale_reason_detailed(Some(&meta), "r", "new_plan", "k");
    assert_eq!(
        reason,
        Some(StaleReason::InputChanged {
            field: "installer_plan_sha256".into()
        })
    );
}

#[test]
fn golden_stale_detailed_identifies_kernel_change() {
    let meta = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: golden_fingerprint("r", "p", "old_kernel"),
        base_rootfs_sha256: "r".into(),
        installer_plan_sha256: "p".into(),
        kernel_sha256: "old_kernel".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    let reason = golden_stale_reason_detailed(Some(&meta), "r", "p", "new_kernel");
    assert_eq!(
        reason,
        Some(StaleReason::InputChanged {
            field: "kernel_sha256".into()
        })
    );
}

#[test]
fn golden_stale_detailed_fresh_when_all_match() {
    let meta = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: golden_fingerprint("r", "p", "k"),
        base_rootfs_sha256: "r".into(),
        installer_plan_sha256: "p".into(),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    assert_eq!(
        golden_stale_reason_detailed(Some(&meta), "r", "p", "k"),
        None
    );
}

#[test]
fn snapshot_stale_when_missing() {
    let golden = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: Fingerprint::new("golden_fp"),
        base_rootfs_sha256: "r".into(),
        installer_plan_sha256: "p".into(),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    assert_eq!(
        snapshot_stale_reason(None, &golden),
        Some(StaleReason::Missing)
    );
}

#[test]
fn snapshot_fresh_when_golden_matches() {
    let golden = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: Fingerprint::new("golden_fp"),
        base_rootfs_sha256: "r".into(),
        installer_plan_sha256: "p".into(),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    let snap = SnapshotMeta {
        claw_type: "picoclaw".into(),
        fingerprint: Fingerprint::new("snap_fp"),
        golden_fingerprint: Fingerprint::new("golden_fp"),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    assert_eq!(snapshot_stale_reason(Some(&snap), &golden), None);
}

#[test]
fn snapshot_stale_when_golden_changed() {
    let golden = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: Fingerprint::new("new_golden_fp"),
        base_rootfs_sha256: "r".into(),
        installer_plan_sha256: "p".into(),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    let snap = SnapshotMeta {
        claw_type: "picoclaw".into(),
        fingerprint: Fingerprint::new("snap_fp"),
        golden_fingerprint: Fingerprint::new("old_golden_fp"),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    assert_eq!(
        snapshot_stale_reason(Some(&snap), &golden),
        Some(StaleReason::InputChanged {
            field: "golden_fingerprint".into()
        })
    );
}

#[test]
fn snapshot_stale_when_kernel_changed() {
    let golden = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: Fingerprint::new("golden_fp"),
        base_rootfs_sha256: "r".into(),
        installer_plan_sha256: "p".into(),
        kernel_sha256: "new_kernel".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    let snap = SnapshotMeta {
        claw_type: "picoclaw".into(),
        fingerprint: Fingerprint::new("snap_fp"),
        golden_fingerprint: Fingerprint::new("golden_fp"),
        kernel_sha256: "old_kernel".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    assert_eq!(
        snapshot_stale_reason(Some(&snap), &golden),
        Some(StaleReason::InputChanged {
            field: "kernel_sha256".into()
        })
    );
}

// ── sha256_bytes ────────────────────────────────────────────────────

#[test]
fn sha256_bytes_deterministic() {
    let h1 = sha256_bytes(b"hello world");
    let h2 = sha256_bytes(b"hello world");
    assert_eq!(h1, h2);
}

#[test]
fn sha256_bytes_is_64_hex_chars() {
    let h = sha256_bytes(b"test");
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn sha256_bytes_known_value() {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let h = sha256_bytes(b"");
    assert_eq!(
        h,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// ── sha256_file ─────────────────────────────────────────────────────

#[test]
fn sha256_file_works_on_real_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.bin");
    std::fs::write(&path, b"deterministic content").unwrap();

    let h1 = sha256_file(&path).unwrap();
    let h2 = sha256_file(&path).unwrap();
    assert_eq!(h1, h2, "same file must produce same hash");
    assert_eq!(h1.len(), 64);
}

#[test]
fn sha256_file_matches_sha256_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.bin");
    let content = b"cross check";
    std::fs::write(&path, content).unwrap();

    let file_hash = sha256_file(&path).unwrap();
    let bytes_hash = sha256_bytes(content);
    assert_eq!(
        file_hash, bytes_hash,
        "file hash must match in-process hash"
    );
}

#[test]
fn sha256_file_error_on_missing_file() {
    let result = sha256_file(Path::new("/nonexistent/file.bin"));
    assert!(result.is_err());
}

// ── Meta I/O ────────────────────────────────────────────────────────

#[test]
fn meta_round_trip_golden() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("golden.meta.json");
    let meta = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: Fingerprint::new("abc123"),
        base_rootfs_sha256: "rootfs_hash".into(),
        installer_plan_sha256: "plan_hash".into(),
        kernel_sha256: "kernel_hash".into(),
        builder_version: "v1.0.0".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };

    write_meta(&path, &meta).unwrap();
    let loaded: GoldenMeta = read_meta(&path).unwrap();
    assert_eq!(loaded.claw_type, "picoclaw");
    assert_eq!(loaded.fingerprint, Fingerprint::new("abc123"));
    assert_eq!(loaded.base_rootfs_sha256, "rootfs_hash");
    assert_eq!(loaded.installer_plan_sha256, "plan_hash");
    assert_eq!(loaded.kernel_sha256, "kernel_hash");
}

#[test]
fn meta_round_trip_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.meta.json");
    let meta = SnapshotMeta {
        claw_type: "picoclaw".into(),
        fingerprint: Fingerprint::new("snap_fp"),
        golden_fingerprint: Fingerprint::new("golden_fp"),
        kernel_sha256: "kernel_hash".into(),
        builder_version: "v1.0.0".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };

    write_meta(&path, &meta).unwrap();
    let loaded: SnapshotMeta = read_meta(&path).unwrap();
    assert_eq!(loaded.claw_type, "picoclaw");
    assert_eq!(loaded.golden_fingerprint, Fingerprint::new("golden_fp"));
}

#[test]
fn read_meta_returns_none_for_missing_file() {
    let result: Option<GoldenMeta> = read_meta(Path::new("/nonexistent/meta.json"));
    assert!(result.is_none());
}

#[test]
fn read_meta_returns_none_for_malformed_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.meta.json");
    std::fs::write(&path, "not json").unwrap();
    let result: Option<GoldenMeta> = read_meta(&path);
    assert!(result.is_none());
}

// ── Path helpers ────────────────────────────────────────────────────

#[test]
fn golden_claw_dir_format() {
    let p = golden_claw_dir(Path::new("/assets"), "picoclaw");
    assert_eq!(p, PathBuf::from("/assets/goldens/picoclaw"));
}

#[test]
fn golden_version_dir_format() {
    let fp = Fingerprint::new("abc123");
    let p = golden_version_dir(Path::new("/assets"), "picoclaw", &fp);
    assert_eq!(p, PathBuf::from("/assets/goldens/picoclaw/abc123"));
}

#[test]
fn golden_current_link_format() {
    let p = golden_current_link(Path::new("/assets"), "picoclaw");
    assert_eq!(p, PathBuf::from("/assets/goldens/picoclaw/current"));
}

#[test]
fn snapshot_claw_dir_format() {
    let p = snapshot_claw_dir(Path::new("/assets"), "picoclaw");
    assert_eq!(p, PathBuf::from("/assets/snapshots/picoclaw"));
}

#[test]
fn snapshot_current_link_format() {
    let p = snapshot_current_link(Path::new("/assets"), "picoclaw");
    assert_eq!(p, PathBuf::from("/assets/snapshots/picoclaw/current"));
}

// ── Symlink helpers ─────────────────────────────────────────────────

#[test]
fn update_current_link_creates_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("goldens").join("picoclaw").join("current");
    let fp = Fingerprint::new("abc123");

    update_current_link(&link, &fp).unwrap();

    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    let target = std::fs::read_link(&link).unwrap();
    assert_eq!(target.to_str().unwrap(), "abc123");
}

#[test]
fn update_current_link_replaces_existing() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("goldens").join("picoclaw").join("current");
    let fp1 = Fingerprint::new("old_fp");
    let fp2 = Fingerprint::new("new_fp");

    update_current_link(&link, &fp1).unwrap();
    update_current_link(&link, &fp2).unwrap();

    let target = std::fs::read_link(&link).unwrap();
    assert_eq!(target.to_str().unwrap(), "new_fp");
}

#[test]
fn golden_current_rootfs_resolves_through_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let assets = dir.path();

    // Set up: goldens/picoclaw/abc123/rootfs.ext4
    let fp = Fingerprint::new("abc123");
    let ver_dir = golden_version_dir(assets, "picoclaw", &fp);
    std::fs::create_dir_all(&ver_dir).unwrap();
    std::fs::write(ver_dir.join("rootfs.ext4"), b"fake rootfs").unwrap();

    // Create current -> abc123
    let link = golden_current_link(assets, "picoclaw");
    update_current_link(&link, &fp).unwrap();

    // Resolve
    let rootfs = golden_current_rootfs(assets, "picoclaw").unwrap();
    assert!(rootfs.ends_with("abc123/rootfs.ext4"));
    assert!(rootfs.exists());
}

#[test]
fn golden_current_rootfs_returns_none_without_symlink() {
    let dir = tempfile::tempdir().unwrap();
    assert!(golden_current_rootfs(dir.path(), "picoclaw").is_none());
}

#[test]
fn read_current_golden_meta_works() {
    let dir = tempfile::tempdir().unwrap();
    let assets = dir.path();

    let fp = Fingerprint::new("abc123");
    let ver_dir = golden_version_dir(assets, "picoclaw", &fp);
    std::fs::create_dir_all(&ver_dir).unwrap();

    let meta = GoldenMeta {
        claw_type: "picoclaw".into(),
        fingerprint: fp.clone(),
        base_rootfs_sha256: "r".into(),
        installer_plan_sha256: "p".into(),
        kernel_sha256: "k".into(),
        builder_version: "test".into(),
        created_at: "2026-03-09T00:00:00Z".into(),
    };
    write_meta(&ver_dir.join("golden.meta.json"), &meta).unwrap();

    let link = golden_current_link(assets, "picoclaw");
    update_current_link(&link, &fp).unwrap();

    let loaded = read_current_golden_meta(assets, "picoclaw").unwrap();
    assert_eq!(loaded.claw_type, "picoclaw");
    assert_eq!(loaded.fingerprint, fp);
}

// ── StaleReason Display ─────────────────────────────────────────────

#[test]
fn stale_reason_display() {
    assert_eq!(StaleReason::Missing.to_string(), "missing");
    assert_eq!(
        StaleReason::NoMetadata.to_string(),
        "no metadata (pre-migration artifact)"
    );
    assert_eq!(StaleReason::Forced.to_string(), "forced");
    assert_eq!(
        StaleReason::InputChanged {
            field: "base_rootfs_sha256".into()
        }
        .to_string(),
        "input changed: base_rootfs_sha256"
    );
}

// ── hex encoding ────────────────────────────────────────────────────

#[test]
fn hex_encode_empty() {
    assert_eq!(hex::encode(b""), "");
}

#[test]
fn hex_encode_known() {
    assert_eq!(hex::encode([0x00, 0xff, 0xab]), "00ffab");
}
