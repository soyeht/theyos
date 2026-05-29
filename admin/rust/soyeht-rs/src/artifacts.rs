//! `artifacts sync` — DAG-based artifact reconciliation.
//!
//! Flow:
//!   1. Acquire artifact lock
//!   2. Enter maintenance mode (draining → active)
//!   3. Query imagebuilder for golden staleness (DAG-based)
//!   4. Rebuild stale goldens via imagebuilder
//!   5. Check snapshot staleness (golden fingerprint vs snapshot metadata)
//!   6. Rebuild stale snapshots via e2e-runner
//!   7. Exit maintenance mode
//!
//! Golden staleness is determined by shelling out to `imagebuilder dag-check`,
//! which computes content-addressed fingerprints from build inputs (base rootfs,
//! `InstallerPlan`, kernel).  This avoids pulling in the heavy vmrunner-rs crate.
//!
//! Snapshot staleness is checked directly via core-rs metadata functions.

use std::path::{Path, PathBuf};
use std::process::Command;

use core_rs::artifact_meta;

use crate::util::e2e_runner_bin;

/// Supported claw types from the manifest — the only tier that has
/// golden artifacts and snapshots to sync/GC. Detected/catalog entries
/// don't have artifacts yet (Phase C bakes them on-demand via `install_worker`).
fn all_claws() -> Vec<&'static str> {
    core_rs::manifest::supported_names()
}

/// Default rollback window size (keep 1 extra beyond `current`).
const GC_DEFAULT_ROLLBACK_WINDOW: usize = 1;

/// Entry point for `soyeht artifacts-sync [claw...]`.
#[allow(clippy::too_many_lines)]
pub fn cmd_artifacts_sync(root: &Path, force: bool, gc_after: bool, claw_types: &[String]) {
    let known = all_claws();
    let claws: Vec<&str> = if claw_types.is_empty() {
        // Default to installed claws only (not all 6 from manifest)
        let installed = crate::util::ready_claws_from_server(root);
        if installed.is_empty() {
            println!("[artifacts] no claws installed — install via claw store (/claws)");
            return;
        }
        installed
            .iter()
            .filter_map(|ct| known.iter().find(|&&c| c == ct.as_str()).copied())
            .collect()
    } else {
        claw_types
            .iter()
            .filter_map(|ct| known.iter().find(|&&c| c == ct.as_str()).copied())
            .collect()
    };

    if claws.is_empty() {
        eprintln!("[artifacts] no valid claw types specified");
        std::process::exit(1);
    }

    let home = core_rs::env::theyos_home(root);
    let fc_home = PathBuf::from(&home).join("firecracker");
    let assets_dir = fc_home.join("assets");
    let locks_dir = fc_home.join("locks");

    println!("[artifacts] ===== DAG-based artifact sync =====");
    println!(
        "[artifacts] scope: {} claw(s): {}",
        claws.len(),
        claws.join(", ")
    );

    // 1. Acquire artifact lock
    let _lock = match core_rs::artifact_lock::ArtifactLock::try_acquire(&locks_dir) {
        Ok(Some(lock)) => {
            println!("[artifacts] artifact lock acquired");
            lock
        }
        Ok(None) => {
            eprintln!("[artifacts] ERROR: another sync is already running (lock held)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[artifacts] ERROR: could not acquire artifact lock: {e}");
            std::process::exit(1);
        }
    };

    // 2. Enter maintenance mode
    if let Err(e) = core_rs::maintenance::enter_maintenance(
        &locks_dir,
        core_rs::maintenance::MaintenanceState::Active,
        "artifact sync in progress",
        60,
    ) {
        eprintln!("[artifacts] WARNING: could not enter maintenance mode: {e}");
        // Non-fatal: continue sync even without maintenance mode
    } else {
        println!("[artifacts] maintenance mode: active");
    }

    // 3. Query imagebuilder for golden staleness (DAG-based)
    let dag_report = if force {
        // Force mode: mark all as stale without querying
        None
    } else {
        query_golden_staleness(root, &claws)
    };

    let mut stale_goldens: Vec<&str> = Vec::new();
    let mut fresh_goldens: Vec<&str> = Vec::new();

    for &claw in &claws {
        let is_stale = if force {
            println!("[artifacts]   {claw}: STALE (forced)");
            true
        } else if let Some(ref report) = dag_report {
            if let Some(entry) = report.get(claw) {
                let stale = entry["stale"].as_bool().unwrap_or(true);
                if stale {
                    let reason = entry["reason"].as_str().unwrap_or("unknown");
                    println!("[artifacts]   {claw}: STALE ({reason})");
                } else {
                    let fp = entry["fingerprint"].as_str().unwrap_or("?");
                    let short = &fp[..fp.len().min(12)];
                    println!("[artifacts]   {claw}: fresh (fp={short})");
                }
                stale
            } else {
                println!("[artifacts]   {claw}: STALE (not in dag-check output)");
                true
            }
        } else {
            // dag-check failed entirely — treat all as stale
            println!("[artifacts]   {claw}: STALE (dag-check unavailable)");
            true
        };

        if is_stale {
            stale_goldens.push(claw);
        } else {
            fresh_goldens.push(claw);
        }
    }

    // 4. Rebuild stale goldens
    if stale_goldens.is_empty() {
        println!("[artifacts] all goldens are fresh — no rebuilds needed");
    } else {
        println!(
            "[artifacts] rebuilding {} stale golden(s): {}",
            stale_goldens.len(),
            stale_goldens.join(", ")
        );

        let imagebuilder = imagebuilder_bin(root);
        if !imagebuilder.is_file() {
            eprintln!(
                "[artifacts] ERROR: imagebuilder binary not found: {}",
                imagebuilder.display()
            );
            exit_maintenance(&locks_dir);
            std::process::exit(1);
        }

        for &claw in &stale_goldens {
            println!("[artifacts] rebuilding golden for {claw}...");
            let status = Command::new(&imagebuilder)
                .arg("rebuild")
                .arg("--force")
                .arg(claw)
                .current_dir(root)
                .status()
                .unwrap_or_else(|e| {
                    eprintln!("[artifacts] imagebuilder spawn: {e}");
                    exit_maintenance(&locks_dir);
                    std::process::exit(1)
                });
            if !status.success() {
                eprintln!("[artifacts] golden rebuild FAILED for {claw}");
                exit_maintenance(&locks_dir);
                std::process::exit(1);
            }
            println!("[artifacts] golden rebuilt for {claw}");
        }
    }

    // 5. Check each snapshot for staleness (depends on golden being fresh)
    let mut stale_snapshots: Vec<&str> = Vec::new();

    for &claw in &claws {
        let golden_meta = artifact_meta::read_current_golden_meta(&assets_dir, claw);
        let snap_meta = artifact_meta::read_current_snapshot_meta(&assets_dir, claw);

        let stale = if force {
            true
        } else if let Some(gmeta) = &golden_meta {
            artifact_meta::snapshot_stale_reason(snap_meta.as_ref(), gmeta).is_some()
        } else {
            // No golden metadata — snapshot must be stale
            true
        };

        if stale {
            println!("[artifacts]   {claw}: snapshot STALE");
            stale_snapshots.push(claw);
        } else {
            println!("[artifacts]   {claw}: snapshot fresh");
        }
    }

    // 6. Rebuild stale snapshots
    if stale_snapshots.is_empty() {
        println!("[artifacts] all snapshots are fresh — no rebuilds needed");
    } else {
        println!(
            "[artifacts] rebuilding {} stale snapshot(s): {}",
            stale_snapshots.len(),
            stale_snapshots.join(", ")
        );

        let runner = e2e_runner_bin(root);
        if !runner.is_file() {
            eprintln!(
                "[artifacts] ERROR: e2e-runner binary not found: {}",
                runner.display()
            );
            exit_maintenance(&locks_dir);
            std::process::exit(1);
        }

        let mut args: Vec<&str> = vec!["snapshot", "--force"];
        for claw in &stale_snapshots {
            args.push(claw);
        }
        let status = Command::new(&runner)
            .args(&args)
            .current_dir(root)
            .status()
            .unwrap_or_else(|e| {
                eprintln!("[artifacts] e2e-runner spawn: {e}");
                exit_maintenance(&locks_dir);
                std::process::exit(1)
            });
        if !status.success() {
            eprintln!("[artifacts] snapshot rebuild FAILED");
            exit_maintenance(&locks_dir);
            std::process::exit(1);
        }
        println!("[artifacts] all stale snapshots rebuilt");
    }

    // 7. Exit maintenance mode
    exit_maintenance(&locks_dir);

    println!("[artifacts] ===== artifact sync complete =====");
    println!(
        "[artifacts]   goldens:   {} fresh, {} rebuilt",
        fresh_goldens.len(),
        stale_goldens.len()
    );
    println!(
        "[artifacts]   snapshots: {} fresh, {} rebuilt",
        claws.len() - stale_snapshots.len(),
        stale_snapshots.len()
    );

    // Optional: run GC after sync to clean up unreferenced versions.
    if gc_after {
        println!("[artifacts] running post-sync GC...");
        run_gc_impl(&assets_dir, &claws, false, GC_DEFAULT_ROLLBACK_WINDOW);
    }
}

/// Entry point for `soyeht artifacts gc [--dry-run] [--rollback-window N] [claw...]`.
pub fn cmd_artifacts_gc(root: &Path, dry_run: bool, rollback_window: usize, claw_types: &[String]) {
    let known = all_claws();
    let claws: Vec<&str> = if claw_types.is_empty() {
        known
    } else {
        claw_types
            .iter()
            .filter_map(|ct| known.iter().find(|&&c| c == ct.as_str()).copied())
            .collect()
    };

    if claws.is_empty() {
        eprintln!("[gc] no valid claw types specified");
        std::process::exit(1);
    }

    let home = core_rs::env::theyos_home(root);
    let assets_dir = PathBuf::from(&home).join("firecracker/assets");

    run_gc_impl(&assets_dir, &claws, dry_run, rollback_window);
}

/// Shared GC implementation used by both standalone `artifacts gc` and post-sync GC.
fn run_gc_impl(assets_dir: &Path, claws: &[&str], dry_run: bool, rollback_window: usize) {
    let config = core_rs::artifact_gc::GcConfig {
        rollback_window,
        dry_run,
    };

    let mode_str = if dry_run { " (dry run)" } else { "" };
    println!(
        "[gc] scanning {} claw(s) for unreferenced artifacts{mode_str}...",
        claws.len()
    );

    let result = core_rs::artifact_gc::run_gc(assets_dir, claws, &config);

    // Print kept entries summary
    if !result.plan.kept.is_empty() {
        println!("[gc] kept: {} version(s)", result.plan.kept.len());
        for entry in &result.plan.kept {
            let reasons: Vec<String> = entry.keep_reasons.iter().map(ToString::to_string).collect();
            println!(
                "[gc]   {} {}/{}: {} ({})",
                entry.kind,
                entry.claw_type,
                entry.fingerprint.short(),
                format_bytes(entry.size_bytes),
                reasons.join(", ")
            );
        }
    }

    // Print garbage entries
    if result.plan.garbage.is_empty() {
        println!("[gc] no unreferenced artifacts found — nothing to clean up");
    } else {
        let verb = if dry_run { "would delete" } else { "deleted" };
        println!(
            "[gc] {verb}: {} version(s), {} reclaimable",
            result.plan.garbage.len(),
            format_bytes(result.plan.reclaimable_bytes)
        );
        for entry in &result.plan.garbage {
            let action = if dry_run { "would delete" } else { "deleted" };
            println!(
                "[gc]   {action} {} {}/{}: {}",
                entry.kind,
                entry.claw_type,
                entry.fingerprint.short(),
                format_bytes(entry.size_bytes)
            );
        }
    }

    // Print actual deletion results (non-dry-run)
    if !dry_run && result.deleted_count > 0 {
        println!(
            "[gc] freed {} across {} artifact(s)",
            format_bytes(result.freed_bytes),
            result.deleted_count
        );
    }

    // Print any errors
    for err in &result.errors {
        eprintln!("[gc] WARNING: {err}");
    }
}

/// Format bytes as human-readable string (e.g. "1.5 MiB", "256 KiB", "42 B").
#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;

    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Exit maintenance mode, logging any error.
fn exit_maintenance(locks_dir: &Path) {
    if let Err(e) = core_rs::maintenance::exit_maintenance(locks_dir) {
        eprintln!("[artifacts] WARNING: could not exit maintenance mode: {e}");
    } else {
        println!("[artifacts] maintenance mode: off");
    }
}

/// Query imagebuilder for DAG-based golden staleness via `imagebuilder dag-check`.
///
/// Returns a JSON object keyed by claw type, or `None` if the subprocess fails.
fn query_golden_staleness(
    root: &Path,
    claws: &[&str],
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let imagebuilder = imagebuilder_bin(root);
    if !imagebuilder.is_file() {
        eprintln!(
            "[artifacts] WARNING: imagebuilder not found for dag-check: {}",
            imagebuilder.display()
        );
        return None;
    }

    let mut cmd = Command::new(&imagebuilder);
    cmd.arg("dag-check");
    cmd.current_dir(root);
    for claw in claws {
        cmd.arg(claw);
    }

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("[artifacts] WARNING: imagebuilder dag-check spawn failed: {e}");
            return None;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!(
            "[artifacts] WARNING: imagebuilder dag-check failed (exit={}):\n{}",
            output.status,
            stderr.trim()
        );
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    match serde_json::from_str::<serde_json::Value>(&stdout) {
        Ok(serde_json::Value::Object(map)) => Some(map),
        Ok(_) => {
            eprintln!("[artifacts] WARNING: dag-check returned non-object JSON");
            None
        }
        Err(e) => {
            eprintln!("[artifacts] WARNING: dag-check output parse error: {e}");
            None
        }
    }
}

/// Resolve the imagebuilder binary (delegates to shared resolver).
fn imagebuilder_bin(root: &Path) -> PathBuf {
    crate::util::imagebuilder_bin(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ────────────────────────────────────────────────────────

    #[test]
    fn all_claws_has_eight_entries() {
        assert_eq!(all_claws().len(), 8);
    }

    #[test]
    fn all_claws_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for claw in all_claws() {
            assert!(seen.insert(claw), "duplicate claw: {claw}");
        }
    }

    // ── imagebuilder_bin resolution ──────────────────────────────────────

    #[test]
    fn imagebuilder_bin_prefers_release() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let release = root.join("admin/rust/target/release");
        let debug = root.join("admin/rust/target/debug");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::create_dir_all(&debug).unwrap();
        std::fs::write(release.join("imagebuilder"), b"release").unwrap();
        std::fs::write(debug.join("imagebuilder"), b"debug").unwrap();

        let result = imagebuilder_bin(root);
        assert!(result.to_string_lossy().contains("release"));
    }

    #[test]
    fn imagebuilder_bin_falls_back_to_debug() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let debug = root.join("admin/rust/target/debug");
        std::fs::create_dir_all(&debug).unwrap();
        std::fs::write(debug.join("imagebuilder"), b"debug").unwrap();

        let result = imagebuilder_bin(root);
        assert!(result.to_string_lossy().contains("debug"));
    }

    #[test]
    fn imagebuilder_bin_returns_debug_path_when_neither_exists() {
        let dir = tempfile::tempdir().unwrap();
        let result = imagebuilder_bin(dir.path());
        // Should return the debug path (even though it doesn't exist)
        assert!(result.to_string_lossy().contains("debug"));
    }

    // ── query_golden_staleness ──────────────────────────────────────────

    #[test]
    fn query_golden_staleness_returns_none_for_missing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let result = query_golden_staleness(dir.path(), &["picoclaw"]);
        assert!(result.is_none());
    }

    // ── dag-check JSON parsing contract ─────────────────────────────────

    /// Verify we can parse the exact JSON format that `imagebuilder dag-check` emits.
    #[test]
    fn parse_dag_check_json_fresh() {
        let json = r#"{
            "picoclaw": {"stale": false, "reason": null, "fingerprint": "abc123def456789012345678901234567890123456789012345678901234"},
            "nullclaw": {"stale": false, "reason": null, "fingerprint": "def456"}
        }"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        let serde_json::Value::Object(map) = parsed else {
            panic!("expected object");
        };

        let pico = &map["picoclaw"];
        assert!(!pico["stale"].as_bool().unwrap());
        assert!(pico["reason"].is_null());
        assert_eq!(pico["fingerprint"].as_str().unwrap().len(), 60);
    }

    #[test]
    fn parse_dag_check_json_stale() {
        let json = r#"{
            "picoclaw": {"stale": true, "reason": "input changed: base_rootfs_sha256", "fingerprint": "abc123"}
        }"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        let serde_json::Value::Object(map) = parsed else {
            panic!("expected object");
        };

        let pico = &map["picoclaw"];
        assert!(pico["stale"].as_bool().unwrap());
        assert_eq!(
            pico["reason"].as_str().unwrap(),
            "input changed: base_rootfs_sha256"
        );
    }

    #[test]
    fn parse_dag_check_json_missing() {
        let json = r#"{
            "picoclaw": {"stale": true, "reason": "missing", "fingerprint": null}
        }"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        let serde_json::Value::Object(map) = parsed else {
            panic!("expected object");
        };

        let pico = &map["picoclaw"];
        assert!(pico["stale"].as_bool().unwrap());
        assert!(pico["fingerprint"].is_null());
    }

    // ── exit_maintenance ────────────────────────────────────────────────

    #[test]
    fn exit_maintenance_succeeds_when_no_maintenance_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        // Should not panic — logs a warning but doesn't fail
        exit_maintenance(dir.path());
    }

    #[test]
    fn exit_maintenance_clears_active_maintenance() {
        let dir = tempfile::tempdir().unwrap();
        let locks = dir.path();
        std::fs::create_dir_all(locks).unwrap();

        // Enter maintenance
        core_rs::maintenance::enter_maintenance(
            locks,
            core_rs::maintenance::MaintenanceState::Active,
            "test",
            30,
        )
        .unwrap();
        assert!(core_rs::maintenance::is_maintenance(locks));

        // Exit
        exit_maintenance(locks);
        assert!(!core_rs::maintenance::is_maintenance(locks));
    }

    // ── Claw filtering ──────────────────────────────────────────────────

    #[test]
    fn claw_filter_ignores_unknown_types() {
        let known = all_claws();
        let input = ["picoclaw".to_string(), "fakeclaw".to_string()];
        let filtered: Vec<&str> = input
            .iter()
            .filter_map(|ct| known.iter().find(|&&c| c == ct.as_str()).copied())
            .collect();
        assert_eq!(filtered, vec!["picoclaw"]);
    }

    #[test]
    fn claw_filter_empty_input_gives_all() {
        let known = all_claws();
        let input: Vec<String> = vec![];
        let result: Vec<&str> = if input.is_empty() {
            known
        } else {
            input
                .iter()
                .filter_map(|ct| known.iter().find(|&&c| c == ct.as_str()).copied())
                .collect()
        };
        assert_eq!(result.len(), 8);
    }

    // ── GC constant ─────────────────────────────────────────────────────

    #[test]
    fn gc_default_rollback_window_is_one() {
        assert_eq!(GC_DEFAULT_ROLLBACK_WINDOW, 1);
    }

    // ── format_bytes ────────────────────────────────────────────────────

    #[test]
    fn format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn format_bytes_small() {
        assert_eq!(format_bytes(42), "42 B");
    }

    #[test]
    fn format_bytes_kib() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
    }

    #[test]
    fn format_bytes_mib() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 + 512 * 1024), "1.5 MiB");
    }

    #[test]
    fn format_bytes_gib() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    // ── run_gc_impl integration ─────────────────────────────────────────

    #[test]
    fn run_gc_impl_on_empty_dir_does_not_panic() {
        let tmp = tempfile::tempdir().unwrap();
        // Should not panic on empty assets dir
        run_gc_impl(tmp.path(), &["picoclaw"], false, 1);
    }

    #[test]
    fn run_gc_impl_dry_run_preserves_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let assets = tmp.path();

        // Create a golden with current + one old version
        let fp = core_rs::artifact_meta::Fingerprint::new("current_fp");
        let dir = core_rs::artifact_meta::golden_version_dir(assets, "picoclaw", &fp);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"data").unwrap();
        let meta = core_rs::artifact_meta::GoldenMeta {
            claw_type: "picoclaw".to_string(),
            fingerprint: fp.clone(),
            base_rootfs_sha256: "b1".to_string(),
            installer_plan_sha256: "p1".to_string(),
            kernel_sha256: "k1".to_string(),
            builder_version: "test".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        core_rs::artifact_meta::write_meta(&dir.join("golden.meta.json"), &meta).unwrap();

        let old_fp = core_rs::artifact_meta::Fingerprint::new("old_fp");
        let old_dir = core_rs::artifact_meta::golden_version_dir(assets, "picoclaw", &old_fp);
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join("rootfs.ext4"), b"old_data").unwrap();

        let link = core_rs::artifact_meta::golden_current_link(assets, "picoclaw");
        core_rs::artifact_meta::update_current_link(&link, &fp).unwrap();

        // dry_run=true, rollback_window=0 → old_fp would be garbage but not deleted
        run_gc_impl(assets, &["picoclaw"], true, 0);
        assert!(old_dir.exists(), "dry run should not delete old dir");
    }

    #[test]
    fn run_gc_impl_deletes_garbage_when_not_dry() {
        let tmp = tempfile::tempdir().unwrap();
        let assets = tmp.path();

        // Create current + old golden
        let fp = core_rs::artifact_meta::Fingerprint::new("current_fp");
        let dir = core_rs::artifact_meta::golden_version_dir(assets, "picoclaw", &fp);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"data").unwrap();
        let meta = core_rs::artifact_meta::GoldenMeta {
            claw_type: "picoclaw".to_string(),
            fingerprint: fp.clone(),
            base_rootfs_sha256: "b1".to_string(),
            installer_plan_sha256: "p1".to_string(),
            kernel_sha256: "k1".to_string(),
            builder_version: "test".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        core_rs::artifact_meta::write_meta(&dir.join("golden.meta.json"), &meta).unwrap();

        let old_fp = core_rs::artifact_meta::Fingerprint::new("old_fp");
        let old_dir = core_rs::artifact_meta::golden_version_dir(assets, "picoclaw", &old_fp);
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::write(old_dir.join("rootfs.ext4"), b"old_data").unwrap();

        let link = core_rs::artifact_meta::golden_current_link(assets, "picoclaw");
        core_rs::artifact_meta::update_current_link(&link, &fp).unwrap();

        // dry_run=false, rollback_window=0 → old_fp deleted
        run_gc_impl(assets, &["picoclaw"], false, 0);
        assert!(!old_dir.exists(), "old dir should be deleted");
        assert!(dir.exists(), "current dir should survive");
    }
}
