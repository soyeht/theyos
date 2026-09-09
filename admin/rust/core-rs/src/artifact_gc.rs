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
                    total += entry.metadata().map_or(0, |m| m.len());
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
    dirs_with_time.sort_by_key(|(_, mtime)| std::cmp::Reverse(*mtime)); // newest first

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
mod tests;
