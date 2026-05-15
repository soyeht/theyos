//! Post-reboot instance reconciliation.
//!
//! After a power outage or crash, Firecracker VMs die but the database still marks
//! them as "Active". This module detects dead instances and marks them as
//! "Stopped" so the UI is honest and Caddy doesn't get routes to dead ports.

use std::path::Path;

use store_rs::{InstanceDb, InstanceStatus, StatusUpdate};
use vmrunner_rs::SweepReport;

/// Reconcile database state after `sweep_orphans`.
///
/// Two phases:
/// - **Phase A**: containers that sweep explicitly cleaned (dead FC PID).
/// - **Phase B**: catch-all — any Active instance whose state directory is missing.
///
/// Returns the number of instances marked as Stopped.
pub fn reconcile_after_sweep(db: &InstanceDb, state_dir: &Path, report: &SweepReport) -> u32 {
    let mut reconciled = 0u32;

    // Phase A: containers that sweep explicitly cleaned
    for container in &report.cleaned_containers {
        match db.get_by_container(container) {
            Ok(Some(row)) if row.status == InstanceStatus::Active => {
                let update = StatusUpdate {
                    id: &row.id,
                    status: InstanceStatus::Stopped,
                    message: "VM stopped (detected dead after reboot)",
                    error: "",
                    job_id: "",
                    phase: "",
                };
                if let Err(e) = db.update_status(&update) {
                    tracing::warn!("[reconcile] failed to update {container}: {e}");
                } else {
                    // Release runtime lease — VM is dead, CPU/RAM are free
                    if let Err(e) = db.release_lease("instance", &row.id, "runtime") {
                        tracing::warn!(
                            "[reconcile] failed to release runtime lease for {container}: {e}"
                        );
                    }
                    reconciled += 1;
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("[reconcile] DB lookup failed for {container}: {e}"),
        }
    }

    // Phase B: catch-all — any Active instance without a state directory on disk.
    // Skip mac-host: it has no VM directory and is always available (local shell via tmux).
    match db.list() {
        Ok(rows) => {
            for row in &rows {
                if row.status != InstanceStatus::Active {
                    continue;
                }
                if row.claw_type == "mac-host" {
                    continue; // no VM state dir expected; always treated as running
                }
                if report
                    .cleaned_containers
                    .iter()
                    .any(|c| c == &row.container)
                {
                    continue; // already reconciled in phase A
                }
                let env_exists = state_dir.join(&row.container).join("instance.env").exists();
                if !env_exists {
                    let update = StatusUpdate {
                        id: &row.id,
                        status: InstanceStatus::Stopped,
                        message: "VM stopped (no state directory after reboot)",
                        error: "",
                        job_id: "",
                        phase: "",
                    };
                    if let Err(e) = db.update_status(&update) {
                        tracing::warn!("[reconcile] failed to update {}: {e}", row.container);
                    } else {
                        // Release runtime lease — VM is dead, CPU/RAM are free
                        if let Err(e) = db.release_lease("instance", &row.id, "runtime") {
                            tracing::warn!(
                                "[reconcile] failed to release runtime lease for {}: {e}",
                                row.container
                            );
                        }
                        reconciled += 1;
                    }
                }
            }
        }
        Err(e) => tracing::warn!("[reconcile] failed to list instances: {e}"),
    }

    if reconciled > 0 {
        tracing::warn!("[reconcile] marked {reconciled} instance(s) as Stopped");
        let _ = db.record_audit_event(
            None,
            "system",
            "reconcile",
            Some(&format!(
                "Marked {reconciled} dead instance(s) as Stopped after reboot"
            )),
        );
    }
    reconciled
}

#[cfg(test)]
mod tests {
    use super::*;
    use store_rs::NewInstance;
    use tempfile::TempDir;

    fn make_active(db: &InstanceDb, id: &str, container: &str) {
        db.insert(&NewInstance {
            id,
            name: id,
            container,
            claw_type: "picoclaw",
            sunset_date: "",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
        })
        .unwrap();
        db.update_status(&StatusUpdate {
            id,
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        })
        .unwrap();
    }

    #[test]
    fn phase_a_marks_swept_containers_as_stopped() {
        let db = InstanceDb::open(":memory:").unwrap();
        make_active(&db, "i1", "pico-dead");
        make_active(&db, "i2", "pico-alive");

        let report = SweepReport {
            instances_cleaned: 1,
            dirs_removed: 0,
            cleaned_containers: vec!["pico-dead".to_string()],
        };

        let tmp = TempDir::new().unwrap();
        // Create state dir for pico-alive so phase B doesn't touch it
        let alive_dir = tmp.path().join("pico-alive");
        std::fs::create_dir_all(&alive_dir).unwrap();
        std::fs::write(alive_dir.join("instance.env"), "").unwrap();

        let n = reconcile_after_sweep(&db, tmp.path(), &report);
        assert_eq!(n, 1);

        let row = db.get("i1").unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Stopped);

        let row2 = db.get("i2").unwrap().unwrap();
        assert_eq!(row2.status, InstanceStatus::Active);
    }

    #[test]
    fn phase_b_catches_missing_state_dirs() {
        let db = InstanceDb::open(":memory:").unwrap();
        make_active(&db, "i1", "pico-vanished");
        make_active(&db, "i2", "pico-present");

        let report = SweepReport::default(); // nothing swept

        let tmp = TempDir::new().unwrap();
        // Only create state dir for pico-present
        let present_dir = tmp.path().join("pico-present");
        std::fs::create_dir_all(&present_dir).unwrap();
        std::fs::write(present_dir.join("instance.env"), "").unwrap();

        let n = reconcile_after_sweep(&db, tmp.path(), &report);
        assert_eq!(n, 1);

        let row = db.get("i1").unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Stopped);

        let row2 = db.get("i2").unwrap().unwrap();
        assert_eq!(row2.status, InstanceStatus::Active);
    }

    #[test]
    fn skips_non_active_instances() {
        let db = InstanceDb::open(":memory:").unwrap();
        // Insert but don't set to Active — stays Provisioning
        db.insert(&NewInstance {
            id: "i1",
            name: "i1",
            container: "pico-prov",
            claw_type: "picoclaw",
            sunset_date: "",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
        })
        .unwrap();

        let report = SweepReport {
            instances_cleaned: 1,
            dirs_removed: 0,
            cleaned_containers: vec!["pico-prov".to_string()],
        };

        let tmp = TempDir::new().unwrap();
        let n = reconcile_after_sweep(&db, tmp.path(), &report);
        assert_eq!(n, 0);

        let row = db.get("i1").unwrap().unwrap();
        assert_eq!(row.status, InstanceStatus::Provisioning);
    }

    #[test]
    fn both_phases_combined() {
        let db = InstanceDb::open(":memory:").unwrap();
        make_active(&db, "i1", "pico-swept");
        make_active(&db, "i2", "pico-missing");
        make_active(&db, "i3", "pico-ok");

        let report = SweepReport {
            instances_cleaned: 1,
            dirs_removed: 0,
            cleaned_containers: vec!["pico-swept".to_string()],
        };

        let tmp = TempDir::new().unwrap();
        let ok_dir = tmp.path().join("pico-ok");
        std::fs::create_dir_all(&ok_dir).unwrap();
        std::fs::write(ok_dir.join("instance.env"), "").unwrap();

        let n = reconcile_after_sweep(&db, tmp.path(), &report);
        assert_eq!(n, 2); // pico-swept (phase A) + pico-missing (phase B)

        assert_eq!(
            db.get("i1").unwrap().unwrap().status,
            InstanceStatus::Stopped
        );
        assert_eq!(
            db.get("i2").unwrap().unwrap().status,
            InstanceStatus::Stopped
        );
        assert_eq!(
            db.get("i3").unwrap().unwrap().status,
            InstanceStatus::Active
        );
    }
}
