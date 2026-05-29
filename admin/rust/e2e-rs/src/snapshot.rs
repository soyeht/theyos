use std::path::{Path, PathBuf};
use std::time::Duration;

use core_rs::ipc::client::IpcClient;

use crate::client::AdminClient;
use crate::error::E2eError;
use crate::runner::all_claw_types;

pub struct SnapshotConfig {
    pub vmrunner_bin: PathBuf,
    pub home: PathBuf,
    pub state_dir: PathBuf,
    pub assets_dir: PathBuf,
    pub kernel_image: PathBuf,
    pub ssh_key: PathBuf,
    pub force: bool,
    pub settle: Duration,
    pub timeout: Duration,
    pub poll_interval: Duration,
}

/// # Panics
///
/// Panics if `claw_types` is non-empty and `claw_types.last()` is `None`
/// (which is impossible for a non-empty slice, but the `.unwrap()` is present).
#[must_use]
pub fn run_snapshots(client: &AdminClient, claw_types: &[&str], config: &SnapshotConfig) -> bool {
    eprintln!(
        "[snapshot] Building base snapshots for {} claw type(s)",
        claw_types.len()
    );

    // Preflight
    if !config.vmrunner_bin.exists() {
        eprintln!(
            "[snapshot] ERROR: vmrunner binary not found: {}",
            config.vmrunner_bin.display()
        );
        return false;
    }
    if !config.ssh_key.exists() {
        eprintln!(
            "[snapshot] ERROR: SSH key not found: {}",
            config.ssh_key.display()
        );
        return false;
    }

    // Clean up stale snapshot-seed instances from previous failed deploys.
    // These are VMs that were created for snapshot building but never deleted.
    cleanup_stale_seeds(client);

    // Drain the warm pool so that seed instances are cold-booted (not claimed
    // from the pool). Warm pool VMs carry a baked rootfs path from the PREVIOUS
    // snapshot; if used as a snapshot seed, the new vmstate would still reference
    // the old path, causing a path mismatch on the next restore.
    eprintln!("[snapshot] Draining warm pool before snapshot build...");
    if let Err(e) = client.drain_warm_pool() {
        eprintln!("[snapshot] WARNING: failed to drain warm pool: {e} (continuing)");
    }

    let snapshots_dir = config.assets_dir.join("snapshots");
    let _ = std::fs::create_dir_all(&snapshots_dir);
    let _ = std::fs::create_dir_all(&config.state_dir);

    let mut succeeded = Vec::new();
    let mut failed = Vec::new();

    for ct in claw_types {
        match snapshot_one(client, ct, config, &snapshots_dir) {
            Ok(cached) => {
                if cached {
                    succeeded.push(format!("{ct} (cached)"));
                } else {
                    succeeded.push(ct.to_string());
                }
            }
            Err(e) => {
                eprintln!("[snapshot] ERROR: {ct}: {e}");
                failed.push(ct.to_string());
            }
        }

        if ct != claw_types.last().unwrap() {
            eprintln!("[snapshot] Settling {}s...", config.settle.as_secs());
            std::thread::sleep(config.settle);
        }
    }

    eprintln!();
    eprintln!("[snapshot] === Snapshot Build Summary ===");
    if !succeeded.is_empty() {
        eprintln!("[snapshot]   Succeeded: {}", succeeded.join(", "));
    }
    if !failed.is_empty() {
        eprintln!("[snapshot]   Failed:    {}", failed.join(", "));
    }

    if failed.is_empty() {
        eprintln!("[snapshot] All snapshots ready. Next create will use snapshot restore path.");
        true
    } else {
        false
    }
}

/// Delete any leftover `*-snapshot-seed-*` instances from previous deploys.
/// These are orphaned VMs that consume resources and can cause SSH port
/// contention during the next snapshot build.
fn cleanup_stale_seeds(client: &AdminClient) {
    let instances = match client.list_instances() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[snapshot] WARNING: could not list instances for stale seed cleanup: {e}");
            return;
        }
    };

    let stale: Vec<_> = instances
        .iter()
        .filter(|i| i.name.contains("-snapshot-seed-"))
        .collect();

    if stale.is_empty() {
        return;
    }

    eprintln!(
        "[snapshot] Cleaning up {} stale snapshot-seed instance(s)...",
        stale.len()
    );
    for inst in &stale {
        eprintln!(
            "[snapshot]   deleting stale seed: {} ({})",
            inst.name, inst.id
        );
        delete_seed_instance(client, &inst.id);
    }
    // Let teardown settle before proceeding
    if !stale.is_empty() {
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

/// Best-effort cleanup of a seed instance.  Logs a warning if the delete fails
/// instead of silently discarding the error (which would leave orphan VMs).
fn delete_seed_instance(client: &AdminClient, instance_id: &str) {
    if let Err(e) = client.delete_instance(instance_id) {
        eprintln!(
            "[snapshot]   WARNING: failed to delete seed instance {instance_id}: {e} \
             — VM processes may be orphaned"
        );
    }
}

#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
// NOTE: file size display in MB; u64→f64 precision loss is acceptable for human-readable output
fn snapshot_one(
    client: &AdminClient,
    claw_type: &str,
    config: &SnapshotConfig,
    snapshots_dir: &Path,
) -> Result<bool, E2eError> {
    eprintln!("[snapshot] === Processing {claw_type} ===");

    // Check golden image — try versionated layout first, then legacy flat path.
    let golden_exists =
        core_rs::artifact_meta::golden_current_rootfs(&config.assets_dir, claw_type).is_some()
            || config
                .assets_dir
                .join(format!("ubuntu-24.04-{claw_type}.ext4"))
                .exists();
    if !golden_exists {
        return Err(E2eError::BenchmarkFailed(format!(
            "golden image not found for {claw_type} — install via claw store or run: sudo soyeht artifacts-sync"
        )));
    }

    // Check staleness — try versionated layout first, then legacy flat.
    let snap_dir = resolve_snapshot_dir(&config.assets_dir, claw_type, snapshots_dir);
    let snap_marker = snap_dir.join("snapshot.ready");
    let snap_vmstate = snap_dir.join("vmstate.snapshot");
    let snap_mem = snap_dir.join("mem.snapshot");

    if !config.force && snap_marker.exists() && snap_vmstate.exists() && snap_mem.exists() {
        // If we have DAG metadata, check staleness by golden fingerprint match
        // instead of age. If metadata exists and golden matches, it's fresh.
        let snap_meta: Option<core_rs::artifact_meta::SnapshotMeta> =
            core_rs::artifact_meta::read_meta(&snap_dir.join("snapshot.meta.json"));
        let golden_meta =
            core_rs::artifact_meta::read_current_golden_meta(&config.assets_dir, claw_type);

        if let (Some(sm), Some(gm)) = (&snap_meta, &golden_meta) {
            if core_rs::artifact_meta::snapshot_stale_reason(Some(sm), gm).is_none() {
                eprintln!(
                    "[snapshot]   Snapshot for {claw_type} is DAG-fresh (fp={}) — skipping",
                    sm.fingerprint.short()
                );
                return Ok(true); // cached, DAG-fresh
            }
            eprintln!("[snapshot]   Snapshot for {claw_type} is DAG-stale — rebuilding");
        } else {
            // Fallback to age-based staleness (legacy layout)
            if let Ok(meta) = std::fs::metadata(&snap_marker) {
                if let Ok(modified) = meta.modified() {
                    let age = modified.elapsed().unwrap_or_default();
                    let age_days = age.as_secs() / 86400;
                    if age_days < 7 {
                        eprintln!(
                            "[snapshot]   Snapshot for {claw_type} is {age_days} days old — skipping (use --force to rebuild)"
                        );
                        return Ok(true); // cached
                    }
                    eprintln!(
                        "[snapshot]   Snapshot for {claw_type} is {age_days} days old — rebuilding"
                    );
                }
            }
        }
    }

    let _ = std::fs::create_dir_all(&snap_dir);

    // Remove marker to force full boot
    let _ = std::fs::remove_file(&snap_marker);

    // Create seed instance via admin API
    let pid = std::process::id();
    let temp_name = format!("snapshot-seed-{pid}");

    eprintln!("[snapshot]   Creating seed instance {claw_type}-{temp_name}...");

    let cr = client.create_instance(&temp_name, claw_type).map_err(|e| {
        E2eError::BenchmarkFailed(format!("create seed instance for {claw_type}: {e}"))
    })?;

    let instance_id = cr
        .instance
        .as_ref()
        .map(|i| i.id.clone())
        .unwrap_or_default();
    let job_id = cr.job_id;

    eprintln!("[snapshot]   Instance: {instance_id}, job: {job_id}");
    eprintln!("[snapshot]   Waiting for instance to become ready...");

    // Poll job — always clean up on error
    let poll_result = client.poll_job_interval(
        &job_id,
        config.timeout,
        &format!("snapshot-{claw_type}"),
        config.poll_interval,
    );

    if let Err(e) = &poll_result {
        eprintln!("[snapshot]   Job failed: {e}");
        delete_seed_instance(client, &instance_id);
        return Err(E2eError::BenchmarkFailed(format!(
            "seed instance job failed for {claw_type}: {e}"
        )));
    }

    let container = format!("{claw_type}-{temp_name}");
    eprintln!("[snapshot]   Delegating quiesce + snapshot to vmrunner...");
    let vmrunner_bin = config.vmrunner_bin.to_str().unwrap_or("vmrunner_ipc");
    let ipc = match IpcClient::start(vmrunner_bin, &[]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[snapshot]   Failed to start vmrunner IPC: {e}");
            delete_seed_instance(client, &instance_id);
            return Err(E2eError::BenchmarkFailed(format!(
                "start vmrunner IPC for {claw_type}: {e}"
            )));
        }
    };

    let snap_result = ipc.call(
        "TakeBaseSnapshot",
        serde_json::json!({
            "container": container,
            "claw_type": claw_type,
            "home": config.home.to_str().unwrap_or(""),
            "state_dir": config.state_dir.to_str().unwrap_or(""),
            "kernel_image": config.kernel_image.to_str().unwrap_or(""),
            "ssh_key": config.ssh_key.to_str().unwrap_or("")
        }),
    );

    match snap_result {
        Ok(_) => {
            eprintln!("[snapshot]   Snapshot taken successfully for {claw_type}");
            if let Ok(meta) = std::fs::metadata(&snap_vmstate) {
                let size_mb = meta.len() as f64 / (1024.0 * 1024.0);
                eprintln!("[snapshot]     vmstate: {size_mb:.1}M");
            }
            if let Ok(meta) = std::fs::metadata(&snap_mem) {
                let size_mb = meta.len() as f64 / (1024.0 * 1024.0);
                eprintln!("[snapshot]     mem:     {size_mb:.1}M");
            }
        }
        Err(e) => {
            eprintln!("[snapshot]   Snapshot FAILED for {claw_type}: {e}");
            delete_seed_instance(client, &instance_id);
            return Err(E2eError::BenchmarkFailed(format!(
                "take snapshot for {claw_type}: {e}"
            )));
        }
    }

    // Delete seed instance
    eprintln!("[snapshot]   Deleting seed instance {instance_id}...");
    delete_seed_instance(client, &instance_id);

    Ok(false) // not cached
}

/// Resolve the snapshot directory for a claw type.
///
/// Tries the versionated layout (via `current` symlink) first, then falls
/// back to the legacy flat layout `<snapshots_dir>/<claw>/`.
fn resolve_snapshot_dir(assets_dir: &Path, claw_type: &str, snapshots_dir: &Path) -> PathBuf {
    let current_link = core_rs::artifact_meta::snapshot_current_link(assets_dir, claw_type);
    if let Ok(target) = std::fs::read_link(&current_link) {
        let resolved = if target.is_relative() {
            current_link
                .parent()
                .unwrap_or(Path::new("."))
                .join(&target)
        } else {
            target
        };
        if resolved.is_dir() {
            return resolved;
        }
    }
    snapshots_dir.join(claw_type)
}

/// Validate claw types, defaulting to all 6 if empty.
///
/// # Errors
///
/// Returns an error string if any provided claw type is unknown.
pub fn resolve_claw_types(types: &[String]) -> Result<Vec<&'static str>, String> {
    let known = all_claw_types();
    if types.is_empty() {
        return Ok(known);
    }
    let mut out = Vec::new();
    for ct in types {
        match known.iter().find(|&&s| s == ct.as_str()) {
            Some(s) => out.push(*s),
            None => {
                return Err(format!(
                    "unknown claw type '{}'. Valid: {}",
                    ct,
                    known.join(", ")
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_claw_types_defaults_to_all_eight() {
        let result = resolve_claw_types(&[]).unwrap();
        assert_eq!(result.len(), 8, "should return all 8 claw types");
        assert!(result.contains(&"picoclaw"));
        assert!(result.contains(&"nanobot"));
        assert!(result.contains(&"zeroclaw"));
        assert!(result.contains(&"openclaw"));
        assert!(result.contains(&"nullclaw"));
        assert!(result.contains(&"ironclaw"));
        assert!(result.contains(&"hermes-agent"));
        assert!(result.contains(&"noclaw"));
    }

    #[test]
    fn resolve_claw_types_rejects_unknown() {
        let types = vec!["picoclaw".to_string(), "fakeclaw".to_string()];
        let result = resolve_claw_types(&types);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("fakeclaw"),
            "error should name the unknown type, got: {err}"
        );
    }

    #[test]
    fn resolve_claw_types_filters_valid_subset() {
        let types = vec!["nanobot".to_string(), "picoclaw".to_string()];
        let result = resolve_claw_types(&types).unwrap();
        assert_eq!(result, vec!["nanobot", "picoclaw"]);
    }
}
