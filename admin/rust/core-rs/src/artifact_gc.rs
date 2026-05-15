//! Reference-based garbage collection for versionated artifacts.
//!
//! # GC model
//!
//! A fingerprinted artifact directory is "referenced" if any of these hold:
//!
//! 1. **`current` symlink** — the claw's `current` symlink points to it.
//! 2. **Snapshot back-reference** — a snapshot's `snapshot.meta.json` records
//!    `golden_fingerprint` matching this golden's fingerprint.
//! 3. **Rollback window** — configurable retention count (default: keep 1 extra
//!    beyond `current`) preserving the N most recent versions.
//!
//! Everything else is garbage and can be safely deleted.
//!
//! # Safety rules
//!
//! - **Never** delete based on validation success alone.
//! - **Never** delete the `current` symlink target.
//! - **Never** delete a golden that any snapshot's metadata references.
//! - Only delete fingerprint directories, never the claw-level directory.
//! - GC requires the artifact lock to be held (caller responsibility).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::artifact_meta::{self, Fingerprint, SnapshotMeta};

// ── Types ───────────────────────────────────────────────────────────────────

/// Result of a GC scan: what to keep, what to delete, and why.
#[derive(Debug, Clone)]
pub struct GcPlan {
    /// Fingerprint directories that are referenced and will be kept.
    pub kept: Vec<GcEntry>,
    /// Fingerprint directories that are unreferenced and eligible for deletion.
    pub garbage: Vec<GcEntry>,
    /// Total bytes that would be freed by deleting all garbage entries.
    pub reclaimable_bytes: u64,
}

/// A single artifact entry in the GC plan.
#[derive(Debug, Clone)]
pub struct GcEntry {
    /// The artifact kind (golden or snapshot).
    pub kind: ArtifactKind,
    /// Claw type (e.g. `"picoclaw"`).
    pub claw_type: String,
    /// The fingerprint of this version.
    pub fingerprint: Fingerprint,
    /// Full path to the fingerprint directory on disk.
    pub path: PathBuf,
    /// Size in bytes of this directory (sum of all files).
    pub size_bytes: u64,
    /// Why this entry is being kept (empty for garbage).
    pub keep_reasons: Vec<KeepReason>,
}

/// Kind of versionated artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    Golden,
    Snapshot,
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Golden => write!(f, "golden"),
            Self::Snapshot => write!(f, "snapshot"),
        }
    }
}

/// Reason why an artifact is being retained (not garbage collected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepReason {
    /// Target of the `current` symlink.
    Current,
    /// Referenced by a snapshot's `snapshot.meta.json`.
    ReferencedBySnapshot {
        /// The snapshot claw type that references this golden.
        snapshot_claw: String,
        /// The snapshot fingerprint that references this golden.
        snapshot_fingerprint: String,
    },
    /// Within the rollback retention window.
    RollbackWindow {
        /// Position in the retention window (0 = most recent, 1 = previous, ...).
        position: usize,
    },
}

impl std::fmt::Display for KeepReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Current => write!(f, "current"),
            Self::ReferencedBySnapshot {
                snapshot_claw,
                snapshot_fingerprint,
            } => write!(
                f,
                "referenced by snapshot {snapshot_claw}/{snapshot_fingerprint}"
            ),
            Self::RollbackWindow { position } => {
                write!(f, "rollback window (position {position})")
            }
        }
    }
}

/// GC configuration.
#[derive(Debug, Clone)]
pub struct GcConfig {
    /// Number of extra versions to keep beyond `current` (default: 1).
    /// Set to 0 to only keep `current`.
    pub rollback_window: usize,
    /// If true, produce a plan without deleting anything (dry run).
    pub dry_run: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            rollback_window: 1,
            dry_run: false,
        }
    }
}

/// Result of running GC.
#[derive(Debug, Clone)]
pub struct GcResult {
    /// The plan that was executed (or would be executed in dry-run mode).
    pub plan: GcPlan,
    /// Number of directories actually deleted (0 in dry-run mode).
    pub deleted_count: usize,
    /// Total bytes actually freed (0 in dry-run mode).
    pub freed_bytes: u64,
    /// Errors encountered during deletion (non-fatal: GC continues on error).
    pub errors: Vec<String>,
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Scan the assets directory and produce a GC plan without deleting anything.
///
/// This is the analysis step: it identifies referenced vs unreferenced
/// fingerprint directories for all claw types.
///
/// # Arguments
///
/// * `assets_dir` — base directory containing `goldens/` and `snapshots/`
/// * `claws` — claw types to scan (pass `manifest::all_names()` for all)
/// * `config` — GC configuration (rollback window size)
#[must_use]
pub fn plan_gc(assets_dir: &Path, claws: &[&str], config: &GcConfig) -> GcPlan {
    // 1. Collect all snapshot metadata (needed for golden back-references).
    let snapshot_metas = collect_all_snapshot_metas(assets_dir, claws);

    // 2. Build a set of golden fingerprints referenced by snapshots.
    let golden_refs_from_snapshots = build_golden_refs_from_snapshots(&snapshot_metas);

    let mut kept = Vec::new();
    let mut garbage = Vec::new();
    let mut reclaimable_bytes: u64 = 0;

    // 3. Scan goldens.
    for claw in claws {
        scan_artifact_dirs(
            assets_dir,
            claw,
            ArtifactKind::Golden,
            &golden_refs_from_snapshots,
            config,
            &mut kept,
            &mut garbage,
        );
    }

    // 4. Scan snapshots.
    for claw in claws {
        scan_artifact_dirs(
            assets_dir,
            claw,
            ArtifactKind::Snapshot,
            &golden_refs_from_snapshots,
            config,
            &mut kept,
            &mut garbage,
        );
    }

    for entry in &garbage {
        reclaimable_bytes = reclaimable_bytes.saturating_add(entry.size_bytes);
    }

    GcPlan {
        kept,
        garbage,
        reclaimable_bytes,
    }
}

/// Execute a GC plan: delete all garbage entries.
///
/// Requires the artifact lock to be held (caller responsibility).
/// Errors are collected but do not abort the sweep — GC is best-effort.
#[must_use]
pub fn execute_gc(plan: GcPlan, dry_run: bool) -> GcResult {
    let mut deleted_count = 0;
    let mut freed_bytes: u64 = 0;
    let mut errors = Vec::new();

    if !dry_run {
        for entry in &plan.garbage {
            match fs::remove_dir_all(&entry.path) {
                Ok(()) => {
                    deleted_count += 1;
                    freed_bytes = freed_bytes.saturating_add(entry.size_bytes);
                }
                Err(e) => {
                    errors.push(format!(
                        "failed to delete {} {}/{}: {e}",
                        entry.kind,
                        entry.claw_type,
                        entry.fingerprint.short()
                    ));
                }
            }
        }
    }

    GcResult {
        plan,
        deleted_count,
        freed_bytes,
        errors,
    }
}

/// Convenience: plan + execute in one call.
#[must_use]
pub fn run_gc(assets_dir: &Path, claws: &[&str], config: &GcConfig) -> GcResult {
    let plan = plan_gc(assets_dir, claws, config);
    execute_gc(plan, config.dry_run)
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Collect all snapshot metadata across all claws.
fn collect_all_snapshot_metas(
    assets_dir: &Path,
    claws: &[&str],
) -> Vec<(String, Fingerprint, SnapshotMeta)> {
    let mut metas = Vec::new();
    for claw in claws {
        let snap_claw_dir = artifact_meta::snapshot_claw_dir(assets_dir, claw);
        if !snap_claw_dir.is_dir() {
            continue;
        }
        for fp_dir in list_fingerprint_dirs(&snap_claw_dir) {
            let fp = fp_dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let meta_path = fp_dir.join("snapshot.meta.json");
            if let Some(meta) = artifact_meta::read_meta::<SnapshotMeta>(&meta_path) {
                metas.push((claw.to_string(), Fingerprint::new(&fp), meta));
            }
        }
    }
    metas
}

/// Build a set of golden fingerprints that are referenced by snapshot metadata.
///
/// Returns a map: `(claw_type, golden_fingerprint) → Vec<(snapshot_claw, snapshot_fp)>`.
fn build_golden_refs_from_snapshots(
    snapshot_metas: &[(String, Fingerprint, SnapshotMeta)],
) -> HashMap<(String, String), Vec<(String, String)>> {
    let mut refs: HashMap<(String, String), Vec<(String, String)>> = HashMap::new();
    for (snap_claw, snap_fp, meta) in snapshot_metas {
        let key = (
            meta.claw_type.clone(),
            meta.golden_fingerprint.as_str().to_string(),
        );
        refs.entry(key)
            .or_default()
            .push((snap_claw.clone(), snap_fp.as_str().to_string()));
    }
    refs
}

/// List all fingerprint directories under a claw directory.
///
/// A "fingerprint directory" is any subdirectory whose name is NOT `current`
/// (the symlink).
fn list_fingerprint_dirs(claw_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let Ok(entries) = fs::read_dir(claw_dir) else {
        return dirs;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // Skip `current` symlink and any non-directory entries.
        if name == "current" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            dirs.push(path);
        }
    }
    // Sort by name for deterministic output.
    dirs.sort();
    dirs
}

/// Read the `current` symlink target as a fingerprint string.
fn read_current_fingerprint(claw_dir: &Path) -> Option<String> {
    let link = claw_dir.join("current");
    fs::read_link(&link)
        .ok()
        .map(|target| target.to_string_lossy().to_string())
}

/// Compute the total size of a directory (sum of all file sizes, recursive
/// into subdirectories but not following symlinks).
fn dir_size(path: &Path) -> u64 {
    let mut total: u64 = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_file() {
                    total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                } else if ft.is_dir() {
                    total += dir_size(&entry.path());
                }
            }
        }
    }
    total
}

/// Scan all fingerprint dirs for one claw + artifact kind, classify as kept/garbage.
#[allow(clippy::too_many_arguments)]
fn scan_artifact_dirs(
    assets_dir: &Path,
    claw: &str,
    kind: ArtifactKind,
    golden_refs: &HashMap<(String, String), Vec<(String, String)>>,
    config: &GcConfig,
    kept: &mut Vec<GcEntry>,
    garbage: &mut Vec<GcEntry>,
) {
    let claw_dir = match kind {
        ArtifactKind::Golden => artifact_meta::golden_claw_dir(assets_dir, claw),
        ArtifactKind::Snapshot => artifact_meta::snapshot_claw_dir(assets_dir, claw),
    };

    if !claw_dir.is_dir() {
        return;
    }

    let current_fp = read_current_fingerprint(&claw_dir);
    let fp_dirs = list_fingerprint_dirs(&claw_dir);

    // Sort fingerprint dirs by modification time (newest first) for rollback
    // window ordering.
    let mut dirs_with_time: Vec<(PathBuf, std::time::SystemTime)> = fp_dirs
        .into_iter()
        .map(|p| {
            let mtime = fs::metadata(&p)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            (p, mtime)
        })
        .collect();
    dirs_with_time.sort_by(|a, b| b.1.cmp(&a.1)); // newest first

    // Build a set of fingerprints within the rollback window.
    // The rollback window includes the N most recent non-current versions.
    let mut rollback_positions: HashMap<String, usize> = HashMap::new();
    let mut position = 0;
    for (dir_path, _) in &dirs_with_time {
        let fp_str = dir_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // Skip the current version — it's already retained by `Current` reason.
        if Some(&fp_str) == current_fp.as_ref() {
            continue;
        }
        if position < config.rollback_window {
            rollback_positions.insert(fp_str, position);
            position += 1;
        }
    }

    // Classify each fingerprint directory.
    for (dir_path, _) in &dirs_with_time {
        let fp_str = dir_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let fp = Fingerprint::new(&fp_str);
        let size = dir_size(dir_path);
        let mut reasons: Vec<KeepReason> = Vec::new();

        // Check 1: is this the current version?
        if Some(&fp_str) == current_fp.as_ref() {
            reasons.push(KeepReason::Current);
        }

        // Check 2: is this golden referenced by any snapshot?
        if kind == ArtifactKind::Golden {
            let key = (claw.to_string(), fp_str.clone());
            if let Some(referrers) = golden_refs.get(&key) {
                for (snap_claw, snap_fp) in referrers {
                    reasons.push(KeepReason::ReferencedBySnapshot {
                        snapshot_claw: snap_claw.clone(),
                        snapshot_fingerprint: snap_fp.clone(),
                    });
                }
            }
        }

        // Check 3: rollback window?
        if let Some(&pos) = rollback_positions.get(&fp_str) {
            reasons.push(KeepReason::RollbackWindow { position: pos });
        }

        let entry = GcEntry {
            kind,
            claw_type: claw.to_string(),
            fingerprint: fp,
            path: dir_path.clone(),
            size_bytes: size,
            keep_reasons: reasons.clone(),
        };

        if reasons.is_empty() {
            garbage.push(entry);
        } else {
            kept.push(entry);
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
        let dir =
            artifact_meta::golden_version_dir(assets, "picoclaw", &Fingerprint::new("orphan_fp"));
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
}
