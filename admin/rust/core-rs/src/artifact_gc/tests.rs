#![cfg(test)]

use super::*;
use crate::artifact_meta::GoldenMeta;
use std::collections::HashSet;

/// Helper: create a fake golden version dir with a meta file.
fn make_golden(
    assets_dir: &Path,
    claw: &str,
    fp: &str,
    base_sha: &str,
    plan_sha: &str,
    kernel_sha: &str,
) {
    let dir = artifact_meta::golden_version_dir(assets_dir, claw, &Fingerprint::new(fp));
    fs::create_dir_all(&dir).unwrap();
    // Write a fake rootfs file so dir_size returns nonzero.
    fs::write(dir.join("rootfs.ext4"), vec![0u8; 1024]).unwrap();
    let meta = GoldenMeta {
        claw_type: claw.to_string(),
        fingerprint: Fingerprint::new(fp),
        base_rootfs_sha256: base_sha.to_string(),
        installer_plan_sha256: plan_sha.to_string(),
        kernel_sha256: kernel_sha.to_string(),
        builder_version: "test".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
    };
    artifact_meta::write_meta(&dir.join("golden.meta.json"), &meta).unwrap();
}

/// Helper: create a fake snapshot version dir with a meta file.
fn make_snapshot(assets_dir: &Path, claw: &str, fp: &str, golden_fp: &str, kernel_sha: &str) {
    let dir = artifact_meta::snapshot_version_dir(assets_dir, claw, &Fingerprint::new(fp));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("vmstate.snapshot"), vec![0u8; 2048]).unwrap();
    fs::write(dir.join("mem.snapshot"), vec![0u8; 4096]).unwrap();
    let meta = SnapshotMeta {
        claw_type: claw.to_string(),
        fingerprint: Fingerprint::new(fp),
        golden_fingerprint: Fingerprint::new(golden_fp),
        kernel_sha256: kernel_sha.to_string(),
        builder_version: "test".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
    };
    artifact_meta::write_meta(&dir.join("snapshot.meta.json"), &meta).unwrap();
}

/// Helper: set the `current` symlink for a claw.
fn set_current(assets_dir: &Path, kind: ArtifactKind, claw: &str, fp: &str) {
    let link = match kind {
        ArtifactKind::Golden => artifact_meta::golden_current_link(assets_dir, claw),
        ArtifactKind::Snapshot => artifact_meta::snapshot_current_link(assets_dir, claw),
    };
    artifact_meta::update_current_link(&link, &Fingerprint::new(fp)).unwrap();
}

// ── plan_gc tests ───────────────────────────────────────────────────

#[test]
fn empty_assets_dir_produces_empty_plan() {
    let tmp = tempfile::tempdir().unwrap();
    let plan = plan_gc(
        tmp.path(),
        &["picoclaw"],
        &GcConfig {
            rollback_window: 1,
            dry_run: true,
        },
    );
    assert!(plan.kept.is_empty());
    assert!(plan.garbage.is_empty());
    assert_eq!(plan.reclaimable_bytes, 0);
}

#[test]
fn current_golden_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();
    make_golden(assets, "picoclaw", "aaa111", "base1", "plan1", "kern1");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "aaa111");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );
    assert_eq!(plan.kept.len(), 1);
    assert_eq!(plan.garbage.len(), 0);
    assert_eq!(plan.kept[0].fingerprint.as_str(), "aaa111");
    assert!(plan.kept[0].keep_reasons.contains(&KeepReason::Current));
}

#[test]
fn non_current_golden_without_references_is_garbage() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();
    make_golden(assets, "picoclaw", "aaa111", "base1", "plan1", "kern1");
    make_golden(assets, "picoclaw", "bbb222", "base2", "plan2", "kern2");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "aaa111");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );
    assert_eq!(plan.kept.len(), 1, "only current should be kept");
    assert_eq!(plan.garbage.len(), 1, "old golden should be garbage");
    assert_eq!(plan.garbage[0].fingerprint.as_str(), "bbb222");
}

#[test]
fn golden_referenced_by_snapshot_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "aaa111", "base1", "plan1", "kern1");
    make_golden(assets, "picoclaw", "bbb222", "base2", "plan2", "kern2");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "bbb222");

    // Snapshot references old golden aaa111
    make_snapshot(assets, "picoclaw", "snap_old", "aaa111", "kern1");
    set_current(assets, ArtifactKind::Snapshot, "picoclaw", "snap_old");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );

    let kept_fps: HashSet<&str> = plan
        .kept
        .iter()
        .filter(|e| e.kind == ArtifactKind::Golden)
        .map(|e| e.fingerprint.as_str())
        .collect();
    assert!(
        kept_fps.contains("aaa111"),
        "old golden referenced by snapshot should be kept"
    );
    assert!(kept_fps.contains("bbb222"), "current golden should be kept");

    let garbage_goldens: Vec<_> = plan
        .garbage
        .iter()
        .filter(|e| e.kind == ArtifactKind::Golden)
        .collect();
    assert!(garbage_goldens.is_empty(), "no golden should be garbage");
}

#[test]
fn rollback_window_keeps_n_most_recent_non_current() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "old_fp1", "b1", "p1", "k1");
    std::thread::sleep(std::time::Duration::from_millis(50));
    make_golden(assets, "picoclaw", "med_fp2", "b2", "p2", "k2");
    std::thread::sleep(std::time::Duration::from_millis(50));
    make_golden(assets, "picoclaw", "new_fp3", "b3", "p3", "k3");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "new_fp3");

    // rollback_window = 1 → keep current + 1 most recent
    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 1,
            dry_run: true,
        },
    );

    let kept_fps: HashSet<&str> = plan
        .kept
        .iter()
        .filter(|e| e.kind == ArtifactKind::Golden)
        .map(|e| e.fingerprint.as_str())
        .collect();
    assert!(kept_fps.contains("new_fp3"), "current should be kept");
    assert!(
        kept_fps.contains("med_fp2"),
        "most recent non-current should be in rollback window"
    );

    let garbage_fps: HashSet<&str> = plan
        .garbage
        .iter()
        .filter(|e| e.kind == ArtifactKind::Golden)
        .map(|e| e.fingerprint.as_str())
        .collect();
    assert!(garbage_fps.contains("old_fp1"), "oldest should be garbage");
}

#[test]
fn rollback_window_zero_keeps_only_current() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "aaa111", "b1", "p1", "k1");
    std::thread::sleep(std::time::Duration::from_millis(50));
    make_golden(assets, "picoclaw", "bbb222", "b2", "p2", "k2");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "bbb222");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );
    assert_eq!(plan.kept.len(), 1);
    assert_eq!(plan.kept[0].fingerprint.as_str(), "bbb222");
    assert_eq!(plan.garbage.len(), 1);
    assert_eq!(plan.garbage[0].fingerprint.as_str(), "aaa111");
}

#[test]
fn snapshot_gc_works_independently() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "golden1", "b1", "p1", "k1");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "golden1");

    make_snapshot(assets, "picoclaw", "snap_old", "golden1", "k1");
    make_snapshot(assets, "picoclaw", "snap_new", "golden1", "k1");
    set_current(assets, ArtifactKind::Snapshot, "picoclaw", "snap_new");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );

    let garbage_snaps: Vec<_> = plan
        .garbage
        .iter()
        .filter(|e| e.kind == ArtifactKind::Snapshot)
        .collect();
    assert_eq!(garbage_snaps.len(), 1);
    assert_eq!(garbage_snaps[0].fingerprint.as_str(), "snap_old");

    let kept_snaps: Vec<_> = plan
        .kept
        .iter()
        .filter(|e| e.kind == ArtifactKind::Snapshot)
        .collect();
    assert_eq!(kept_snaps.len(), 1);
    assert_eq!(kept_snaps[0].fingerprint.as_str(), "snap_new");
}

#[test]
fn multiple_claws_scanned_independently() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "pico_cur", "b1", "p1", "k1");
    make_golden(assets, "picoclaw", "pico_old", "b2", "p2", "k2");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "pico_cur");

    make_golden(assets, "zeroclaw", "zero_cur", "b3", "p3", "k3");
    make_golden(assets, "zeroclaw", "zero_old", "b4", "p4", "k4");
    set_current(assets, ArtifactKind::Golden, "zeroclaw", "zero_cur");

    let plan = plan_gc(
        assets,
        &["picoclaw", "zeroclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );

    assert_eq!(plan.kept.len(), 2, "2 current goldens kept");
    assert_eq!(plan.garbage.len(), 2, "2 old goldens are garbage");

    let garbage_fps: HashSet<&str> = plan
        .garbage
        .iter()
        .map(|e| e.fingerprint.as_str())
        .collect();
    assert!(garbage_fps.contains("pico_old"));
    assert!(garbage_fps.contains("zero_old"));
}

#[test]
fn size_bytes_computed_for_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();
    make_golden(assets, "picoclaw", "aaa111", "b1", "p1", "k1");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "aaa111");

    let plan = plan_gc(assets, &["picoclaw"], &GcConfig::default());
    assert!(
        plan.kept[0].size_bytes > 0,
        "size should include rootfs.ext4 + meta"
    );
}

#[test]
fn reclaimable_bytes_sums_garbage_sizes() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "aaa111", "b1", "p1", "k1");
    make_golden(assets, "picoclaw", "bbb222", "b2", "p2", "k2");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "bbb222");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );
    assert_eq!(plan.garbage.len(), 1);
    assert_eq!(plan.reclaimable_bytes, plan.garbage[0].size_bytes);
    assert!(plan.reclaimable_bytes > 0);
}

// ── execute_gc tests ────────────────────────────────────────────────

#[test]
fn execute_gc_deletes_garbage_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "aaa111", "b1", "p1", "k1");
    make_golden(assets, "picoclaw", "bbb222", "b2", "p2", "k2");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "bbb222");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: false,
        },
    );
    let garbage_path = plan.garbage[0].path.clone();
    assert!(garbage_path.exists(), "garbage dir should exist before GC");

    let result = execute_gc(plan, false);
    assert_eq!(result.deleted_count, 1);
    assert!(result.freed_bytes > 0);
    assert!(result.errors.is_empty());
    assert!(
        !garbage_path.exists(),
        "garbage dir should be deleted after GC"
    );

    // Current should still exist
    let current_dir =
        artifact_meta::golden_version_dir(assets, "picoclaw", &Fingerprint::new("bbb222"));
    assert!(current_dir.exists(), "current dir should NOT be deleted");
}

#[test]
fn execute_gc_dry_run_does_not_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "aaa111", "b1", "p1", "k1");
    make_golden(assets, "picoclaw", "bbb222", "b2", "p2", "k2");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "bbb222");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );
    let garbage_path = plan.garbage[0].path.clone();

    let result = execute_gc(plan, true);
    assert_eq!(result.deleted_count, 0);
    assert_eq!(result.freed_bytes, 0);
    assert!(garbage_path.exists(), "dry run should NOT delete anything");
}

#[test]
fn run_gc_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "aaa111", "b1", "p1", "k1");
    make_golden(assets, "picoclaw", "bbb222", "b2", "p2", "k2");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "bbb222");

    make_snapshot(assets, "picoclaw", "snap_old", "aaa111", "k1");
    make_snapshot(assets, "picoclaw", "snap_new", "bbb222", "k2");
    set_current(assets, ArtifactKind::Snapshot, "picoclaw", "snap_new");

    let result = run_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: false,
        },
    );

    // GC plan is computed BEFORE deletion. snap_old references aaa111,
    // so aaa111 is KEPT in this run (conservative: no cascade in one pass).
    assert!(
        result.deleted_count >= 1,
        "at least snap_old should be deleted"
    );
    assert!(result.errors.is_empty());

    // Key invariant: current versions are NEVER deleted.
    let current_golden =
        artifact_meta::golden_version_dir(assets, "picoclaw", &Fingerprint::new("bbb222"));
    assert!(current_golden.exists(), "current golden must survive GC");

    let current_snap =
        artifact_meta::snapshot_version_dir(assets, "picoclaw", &Fingerprint::new("snap_new"));
    assert!(current_snap.exists(), "current snapshot must survive GC");
}

#[test]
fn no_current_symlink_means_all_are_garbage() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "aaa111", "b1", "p1", "k1");
    make_golden(assets, "picoclaw", "bbb222", "b2", "p2", "k2");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );
    assert_eq!(plan.garbage.len(), 2);
    assert_eq!(plan.kept.len(), 0);
}

#[test]
fn keep_reasons_multiple_reasons_per_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    // aaa111 is current AND referenced by a snapshot → two keep reasons
    make_golden(assets, "picoclaw", "aaa111", "b1", "p1", "k1");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "aaa111");
    make_snapshot(assets, "picoclaw", "snap1", "aaa111", "k1");
    set_current(assets, ArtifactKind::Snapshot, "picoclaw", "snap1");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );
    let golden_entries: Vec<_> = plan
        .kept
        .iter()
        .filter(|e| e.kind == ArtifactKind::Golden)
        .collect();
    assert_eq!(golden_entries.len(), 1);
    assert!(
        golden_entries[0].keep_reasons.len() >= 2,
        "should have at least Current + ReferencedBySnapshot: {:?}",
        golden_entries[0].keep_reasons
    );
}

#[test]
fn artifact_kind_display() {
    assert_eq!(ArtifactKind::Golden.to_string(), "golden");
    assert_eq!(ArtifactKind::Snapshot.to_string(), "snapshot");
}

#[test]
fn keep_reason_display() {
    assert_eq!(KeepReason::Current.to_string(), "current");
    assert_eq!(
        KeepReason::ReferencedBySnapshot {
            snapshot_claw: "picoclaw".to_string(),
            snapshot_fingerprint: "abc123".to_string(),
        }
        .to_string(),
        "referenced by snapshot picoclaw/abc123"
    );
    assert_eq!(
        KeepReason::RollbackWindow { position: 0 }.to_string(),
        "rollback window (position 0)"
    );
}

#[test]
fn gc_config_default() {
    let config = GcConfig::default();
    assert_eq!(config.rollback_window, 1);
    assert!(!config.dry_run);
}

#[test]
fn dirs_without_meta_are_still_scanned() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    // Create a golden dir manually WITHOUT meta
    let dir = artifact_meta::golden_version_dir(assets, "picoclaw", &Fingerprint::new("orphan_fp"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("rootfs.ext4"), vec![0u8; 512]).unwrap();

    make_golden(assets, "picoclaw", "current_fp", "b1", "p1", "k1");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "current_fp");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: true,
        },
    );
    let garbage_fps: Vec<&str> = plan
        .garbage
        .iter()
        .map(|e| e.fingerprint.as_str())
        .collect();
    assert!(
        garbage_fps.contains(&"orphan_fp"),
        "orphan dir should be garbage"
    );
}

#[test]
fn execute_gc_handles_already_deleted_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let assets = tmp.path();

    make_golden(assets, "picoclaw", "aaa111", "b1", "p1", "k1");
    make_golden(assets, "picoclaw", "bbb222", "b2", "p2", "k2");
    set_current(assets, ArtifactKind::Golden, "picoclaw", "bbb222");

    let plan = plan_gc(
        assets,
        &["picoclaw"],
        &GcConfig {
            rollback_window: 0,
            dry_run: false,
        },
    );
    // Pre-delete the garbage
    fs::remove_dir_all(&plan.garbage[0].path).unwrap();

    let result = execute_gc(plan, false);
    assert_eq!(result.deleted_count, 0);
    assert_eq!(result.errors.len(), 1);
}
