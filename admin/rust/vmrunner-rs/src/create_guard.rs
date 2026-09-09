//! `create_guard.rs` — RAII rollback guard for VM creation.
//!
//! `CreateGuard` tracks all resources allocated during a VM create flow and
//! automatically cleans them up if the create does not complete successfully.
//!
//! # Usage
//!
//! ```ignore
//! let mut guard = CreateGuard::new(instance_dir.clone());
//! // ... create directory ...
//! guard.set_rootfs(rootfs_path.clone());
//! // ... copy rootfs ...
//! guard.set_pids(fc_pid, slirp_pid);
//! // ... start VM ...
//! guard.commit(); // Disarms the guard — cleanup will NOT run on drop.
//! ```
//!
//! If the function returns early (via `?`) before `commit()` is called, the
//! `Drop` impl will:
//! 1. Kill the FC process group and slirp process (if PIDs are set)
//! 2. Remove socket files
//! 3. Remove the entire instance directory (including rootfs)
//!
//! **Important for diagnostics (PR4):** Call `capture_diagnostic_logs()` on
//! the guard BEFORE returning the error. The guard's `Drop` deletes the entire
//! instance directory, which includes `serial.log` and `slirp.log`. If you
//! capture the tails first you can attach them to the `ErrorContext` and they
//! will survive the cleanup.
//!
//! For `claim_from_pool`, a separate `ClaimGuard` handles the case where a
//! pool directory has been renamed to the real container name and needs to be
//! cleaned up on failure.

use std::path::{Path, PathBuf};

use crate::error::DiagnosticLogs;
use crate::instance_env::{InstanceEnv, persist_hostfwd_uncertain_marker};
use crate::network::{
    is_pid_running, kill_pgrp, kill_pgrp_force, kill_pid, kill_pid_force, reap_pid,
};

// ── CreateGuard ────────────────────────────────────────────────────────────

/// RAII guard for the full (cold) VM create path.
///
/// Tracks all resources created during `VmRunner::create()` and tears them
/// down automatically if `commit()` is never called.
pub struct CreateGuard {
    /// The instance directory to remove on rollback.
    instance_dir: PathBuf,
    /// Firecracker process PID (process group leader). Set after FC is spawned.
    pub fc_pid: Option<u32>,
    /// slirp4netns process PID. Set after slirp is spawned.
    pub slirp_pid: Option<u32>,
    /// Whether the create completed successfully. Set by `commit()`.
    committed: bool,
}

impl CreateGuard {
    /// Create a new guard tracking `instance_dir`.
    #[must_use]
    pub fn new(instance_dir: PathBuf) -> Self {
        Self {
            instance_dir,
            fc_pid: None,
            slirp_pid: None,
            committed: false,
        }
    }

    /// Register the Firecracker PID so it can be killed on rollback.
    pub fn set_fc_pid(&mut self, pid: u32) {
        self.fc_pid = Some(pid);
    }

    /// Register the slirp4netns PID so it can be killed on rollback.
    pub fn set_slirp_pid(&mut self, pid: u32) {
        self.slirp_pid = Some(pid);
    }

    /// Disarm the guard — `Drop` will NOT perform cleanup.
    ///
    /// Call this as the very last step of a successful create, immediately
    /// before returning `Ok(...)`.
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Capture `serial.log` and `slirp.log` tails from the instance directory
    /// **before** calling rollback or dropping the guard.
    ///
    /// The guard's `Drop` deletes the entire instance directory (including
    /// those logs). Call this method at the error site, then attach the
    /// returned `DiagnosticLogs` to your `ErrorContext`.
    #[must_use]
    pub fn capture_diagnostic_logs(&self) -> DiagnosticLogs {
        DiagnosticLogs::capture(&self.instance_dir)
    }
}

impl Drop for CreateGuard {
    fn drop(&mut self) {
        if !self.committed {
            tracing::warn!(
                "[vmrunner-guard] Rolling back failed create: {}",
                self.instance_dir.display()
            );
            if !do_cleanup(&self.instance_dir, self.fc_pid, self.slirp_pid) {
                tracing::error!(
                    "[vmrunner-guard] failed to verify cleanup for {}; quarantine preserved",
                    self.instance_dir.display()
                );
            }
        }
    }
}

// ── ClaimGuard ────────────────────────────────────────────────────────────

/// RAII guard for the pool claim path (`claim_from_pool`).
///
/// After a pool directory is renamed to the real container name, any failure
/// must either:
///   a) Delete the VM entirely (processes + directory), OR
///   b) Rename the directory back and attempt to restore the pool entry
///      (not attempted here — we always delete on failure to avoid a corrupt
///      warm pool state).
///
/// The running FC+slirp processes are known from the `WarmEntry` that was
/// taken from the pool before the rename.
pub struct ClaimGuard {
    /// The new (real) instance directory after rename.
    instance_dir: PathBuf,
    /// Firecracker PID from the warm pool entry.
    pub fc_pid: Option<u32>,
    /// slirp PID from the warm pool entry.
    pub slirp_pid: Option<u32>,
    /// Whether the claim completed successfully.
    committed: bool,
}

impl ClaimGuard {
    /// Create a new claim guard.
    ///
    /// `instance_dir` is the renamed directory (real container name, not pool name).
    #[must_use]
    pub fn new(instance_dir: PathBuf, fc_pid: Option<u32>, slirp_pid: Option<u32>) -> Self {
        Self {
            instance_dir,
            fc_pid,
            slirp_pid,
            committed: false,
        }
    }

    /// Disarm the guard.
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Capture diagnostic logs before the guard drops and deletes the directory.
    #[must_use]
    pub fn capture_diagnostic_logs(&self) -> DiagnosticLogs {
        DiagnosticLogs::capture(&self.instance_dir)
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        if !self.committed {
            tracing::warn!(
                "[vmrunner-guard] Rolling back failed pool claim: {}",
                self.instance_dir.display()
            );
            if !do_cleanup(&self.instance_dir, self.fc_pid, self.slirp_pid) {
                tracing::error!(
                    "[vmrunner-guard] failed to verify cleanup for {}; quarantine preserved",
                    self.instance_dir.display()
                );
            }
        }
    }
}

// ── PoolFillGuard ─────────────────────────────────────────────────────────

/// RAII guard for `fill_pool_slot_impl`.
///
/// Cleans up a partially-created warm pool VM if the fill fails after the
/// directory and/or processes have been created.
pub struct PoolFillGuard {
    /// The pool instance directory (e.g. `_warm-picoclaw-0`).
    pool_dir: PathBuf,
    /// FC PID once spawned.
    pub fc_pid: Option<u32>,
    /// slirp PID once spawned.
    pub slirp_pid: Option<u32>,
    /// Whether the fill completed successfully.
    committed: bool,
}

impl PoolFillGuard {
    #[must_use]
    pub fn new(pool_dir: PathBuf) -> Self {
        Self {
            pool_dir,
            fc_pid: None,
            slirp_pid: None,
            committed: false,
        }
    }

    pub fn set_fc_pid(&mut self, pid: u32) {
        self.fc_pid = Some(pid);
    }

    pub fn set_slirp_pid(&mut self, pid: u32) {
        self.slirp_pid = Some(pid);
    }

    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Capture diagnostic logs before the guard drops and deletes the directory.
    #[must_use]
    pub fn capture_diagnostic_logs(&self) -> DiagnosticLogs {
        DiagnosticLogs::capture(&self.pool_dir)
    }
}

impl Drop for PoolFillGuard {
    fn drop(&mut self) {
        if !self.committed {
            tracing::warn!(
                "[vmrunner-guard] Rolling back failed pool fill: {}",
                self.pool_dir.display()
            );
            if !do_cleanup(&self.pool_dir, self.fc_pid, self.slirp_pid) {
                tracing::error!(
                    "[vmrunner-guard] failed to verify warm-pool cleanup for {}; quarantine preserved",
                    self.pool_dir.display()
                );
            }
        }
    }
}

// ── Shared cleanup logic ──────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct CleanupOps {
    is_pid_running: fn(u32) -> bool,
    persist_marker: fn(&Path, &str) -> Result<(), crate::error::VmError>,
    kill_pid: fn(u32),
    kill_pgrp: fn(u32),
    kill_pid_force: fn(u32),
    kill_pgrp_force: fn(u32),
    reap_pid: fn(u32),
    sleep: fn(std::time::Duration),
}

fn real_cleanup_ops() -> CleanupOps {
    CleanupOps {
        is_pid_running,
        persist_marker: persist_hostfwd_uncertain_marker,
        kill_pid,
        kill_pgrp,
        kill_pid_force,
        kill_pgrp_force,
        reap_pid,
        sleep: std::thread::sleep,
    }
}

/// Kill a VM and remove its directory only after all tracked processes are
/// observed dead. Returns `true` only when the directory was removed.
#[must_use]
pub fn do_cleanup(instance_dir: &Path, fc_pid: Option<u32>, slirp_pid: Option<u32>) -> bool {
    do_cleanup_with_ops(instance_dir, fc_pid, slirp_pid, real_cleanup_ops())
}

fn do_cleanup_with_ops(
    instance_dir: &Path,
    requested_fc_pid: Option<u32>,
    requested_slirp_pid: Option<u32>,
    ops: CleanupOps,
) -> bool {
    // The caller may not have received the PIDs yet when an async start path
    // fails. Recover the durable values before touching the directory so an
    // outer guard cannot erase a live VM with `None, None`.
    let env_path = instance_dir.join("instance.env");
    let (fc_pid, slirp_pid, state_error) = match InstanceEnv::load_unchecked(instance_dir) {
        Ok(inst) => (
            requested_fc_pid.or(inst.firecracker_pid()),
            requested_slirp_pid.or(inst.slirp_pid()),
            None,
        ),
        Err(error) if env_path.exists() => {
            // A present but malformed state file is evidence that ownership is
            // not fully recoverable. Kill only caller-supplied PIDs, then keep
            // the directory for a process-level/startup recovery path instead
            // of treating malformed fields as `None` and deleting evidence.
            tracing::error!(
                "[vmrunner-guard] cannot parse {}: {error}; preserving state until ownership is recovered",
                env_path.display()
            );
            (requested_fc_pid, requested_slirp_pid, Some(error))
        }
        Err(_) => (requested_fc_pid, requested_slirp_pid, None),
    };

    // The marker is the first persistent side effect. If the backend dies
    // after this point, startup cleanup will preserve the directory and use
    // the unchecked loader to prove teardown before deleting it.
    let quarantine_error = if instance_dir.exists() {
        (ops.persist_marker)(instance_dir, "cleanup in progress").err()
    } else {
        None
    };
    if let Some(error) = &quarantine_error {
        tracing::error!(
            "[vmrunner-guard] cannot persist quarantine marker for {}: {error}; continuing teardown and preserving any survivor evidence",
            instance_dir.display()
        );
    }

    // 1. Kill slirp first (it depends on FC's network namespace)
    if let Some(pid) = slirp_pid {
        (ops.kill_pid)(pid);
    }

    // 2. Kill FC process group (SIGTERM, then SIGKILL if needed)
    if let Some(pid) = fc_pid {
        (ops.kill_pgrp)(pid);
        (ops.kill_pid)(pid);
        (ops.sleep)(std::time::Duration::from_millis(200));
        (ops.kill_pgrp_force)(pid);
        (ops.kill_pid_force)(pid);
    }

    // Also SIGKILL slirp if still alive
    if let Some(pid) = slirp_pid {
        (ops.kill_pid_force)(pid);
    }

    (ops.sleep)(std::time::Duration::from_millis(100));

    // 2b. Reap zombie children so they don't linger as <defunct> processes.
    // The original Child handle was dropped after spawn (only the PID was kept),
    // so these processes become zombies when they exit. waitpid(WNOHANG)
    // collects the exit status without blocking. No-op if not our child.
    if let Some(pid) = fc_pid {
        (ops.reap_pid)(pid);
    }
    if let Some(pid) = slirp_pid {
        (ops.reap_pid)(pid);
    }

    let fc_survives = fc_pid.is_some_and(ops.is_pid_running);
    let slirp_survives = slirp_pid.is_some_and(ops.is_pid_running);
    if fc_survives || slirp_survives {
        let persistence_detail = quarantine_error
            .map(|error| format!("; quarantine persistence also failed: {error}"))
            .unwrap_or_default();
        tracing::error!(
            "[vmrunner-guard] preserving {} because teardown is unverified (firecracker_survives={fc_survives}, slirp_survives={slirp_survives}){persistence_detail}",
            instance_dir.display(),
        );
        return false;
    }

    if let Some(error) = state_error {
        let persistence_detail = quarantine_error
            .map(|marker_error| format!("; quarantine persistence also failed: {marker_error}"))
            .unwrap_or_default();
        tracing::error!(
            "[vmrunner-guard] preserving {} because instance state was not parseable: {error}{persistence_detail}",
            instance_dir.display()
        );
        return false;
    }

    if let Some(error) = quarantine_error {
        tracing::warn!(
            "[vmrunner-guard] teardown verified for {} despite quarantine persistence failure: {error}",
            instance_dir.display()
        );
    }

    // 3. Remove socket files (best-effort — they're inside instance_dir anyway)
    for sock in &["firecracker.sock", "slirp-api.sock"] {
        let _ = std::fs::remove_file(instance_dir.join(sock));
    }

    // 4. Remove entire instance directory (rootfs, logs, instance.env, etc.)
    if instance_dir.exists() {
        match std::fs::remove_dir_all(instance_dir) {
            Ok(()) => {
                tracing::info!(
                    "[vmrunner-guard] Cleaned up instance dir: {}",
                    instance_dir.display()
                );
                true
            }
            Err(e) => {
                tracing::error!(
                    "[vmrunner-guard] Failed to remove instance dir {}: {e}",
                    instance_dir.display()
                );
                false
            }
        }
    } else {
        true
    }
}

#[cfg(test)]
mod tests;
