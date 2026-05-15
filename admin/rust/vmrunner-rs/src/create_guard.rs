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
use crate::network::{kill_pgrp, kill_pgrp_force, kill_pid, kill_pid_force, reap_pid};

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
            do_cleanup(&self.instance_dir, self.fc_pid, self.slirp_pid);
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
            do_cleanup(&self.instance_dir, self.fc_pid, self.slirp_pid);
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
            do_cleanup(&self.pool_dir, self.fc_pid, self.slirp_pid);
        }
    }
}

// ── Shared cleanup logic ──────────────────────────────────────────────────

pub fn do_cleanup(instance_dir: &Path, fc_pid: Option<u32>, slirp_pid: Option<u32>) {
    // 1. Kill slirp first (it depends on FC's network namespace)
    if let Some(pid) = slirp_pid {
        kill_pid(pid);
    }

    // 2. Kill FC process group (SIGTERM, then SIGKILL if needed)
    if let Some(pid) = fc_pid {
        kill_pgrp(pid);
        kill_pid(pid);
        std::thread::sleep(std::time::Duration::from_millis(200));
        kill_pgrp_force(pid);
        kill_pid_force(pid);
    }

    // Also SIGKILL slirp if still alive
    if let Some(pid) = slirp_pid {
        kill_pid_force(pid);
    }

    // 2b. Reap zombie children so they don't linger as <defunct> processes.
    // The original Child handle was dropped after spawn (only the PID was kept),
    // so these processes become zombies when they exit. waitpid(WNOHANG)
    // collects the exit status without blocking. No-op if not our child.
    if let Some(pid) = fc_pid {
        reap_pid(pid);
    }
    if let Some(pid) = slirp_pid {
        reap_pid(pid);
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
            }
            Err(e) => {
                tracing::error!(
                    "[vmrunner-guard] Failed to remove instance dir {}: {e}",
                    instance_dir.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ── CreateGuard ────────────────────────────────────────────────────────

    #[test]
    fn create_guard_without_commit_removes_directory() {
        let dir = tempfile::tempdir().unwrap();
        let instance_dir = dir.path().join("test-instance");
        fs::create_dir(&instance_dir).unwrap();
        assert!(instance_dir.exists());

        {
            let _guard = CreateGuard::new(instance_dir.clone());
            // Drop without commit
        }

        assert!(
            !instance_dir.exists(),
            "instance dir should be removed after drop without commit"
        );
    }

    #[test]
    fn create_guard_with_commit_preserves_directory() {
        let dir = tempfile::tempdir().unwrap();
        let instance_dir = dir.path().join("test-instance");
        fs::create_dir(&instance_dir).unwrap();

        {
            let mut guard = CreateGuard::new(instance_dir.clone());
            guard.commit();
        }

        assert!(
            instance_dir.exists(),
            "instance dir should survive drop after commit"
        );
    }

    #[test]
    fn create_guard_removes_socket_files_on_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let instance_dir = dir.path().join("test-instance");
        fs::create_dir(&instance_dir).unwrap();

        let fc_sock = instance_dir.join("firecracker.sock");
        let slirp_sock = instance_dir.join("slirp-api.sock");
        fs::write(&fc_sock, "").unwrap();
        fs::write(&slirp_sock, "").unwrap();
        assert!(fc_sock.exists());
        assert!(slirp_sock.exists());

        {
            let _guard = CreateGuard::new(instance_dir.clone());
        }

        // Both sockets and the directory should be gone
        assert!(!fc_sock.exists());
        assert!(!slirp_sock.exists());
        assert!(!instance_dir.exists());
    }

    #[test]
    fn create_guard_with_bogus_pids_still_cleans_up_directory() {
        // PIDs 999_999_999 won't exist — kill calls are best-effort.
        // The important thing is the directory still gets removed.
        let dir = tempfile::tempdir().unwrap();
        let instance_dir = dir.path().join("test-instance");
        fs::create_dir(&instance_dir).unwrap();
        fs::write(instance_dir.join("rootfs.ext4"), "fake").unwrap();

        {
            let mut guard = CreateGuard::new(instance_dir.clone());
            guard.set_fc_pid(999_999_999);
            guard.set_slirp_pid(999_999_998);
            // Drop without commit — cleanup runs with nonexistent PIDs
        }

        assert!(
            !instance_dir.exists(),
            "directory should be removed even with bogus PIDs"
        );
    }

    #[test]
    fn create_guard_capture_diagnostic_logs_before_drop() {
        let dir = tempfile::tempdir().unwrap();
        let instance_dir = dir.path().join("test-instance");
        fs::create_dir(&instance_dir).unwrap();
        fs::write(instance_dir.join("serial.log"), "kernel: boot ok\n").unwrap();
        fs::write(instance_dir.join("slirp.log"), "slirp: started\n").unwrap();

        let logs;
        {
            let guard = CreateGuard::new(instance_dir.clone());
            logs = guard.capture_diagnostic_logs();
            // Guard drops here — directory is deleted
        }

        assert!(!instance_dir.exists(), "directory should be removed");
        assert!(
            logs.serial_log_tail.as_deref().unwrap().contains("boot ok"),
            "serial log should have been captured before deletion"
        );
        assert!(
            logs.slirp_log_tail
                .as_deref()
                .unwrap()
                .contains("slirp: started"),
            "slirp log should have been captured before deletion"
        );
    }

    // ── ClaimGuard ─────────────────────────────────────────────────────────

    #[test]
    fn claim_guard_without_commit_removes_directory() {
        let dir = tempfile::tempdir().unwrap();
        let instance_dir = dir.path().join("claimed-instance");
        fs::create_dir(&instance_dir).unwrap();

        {
            let _guard = ClaimGuard::new(instance_dir.clone(), None, None);
        }

        assert!(
            !instance_dir.exists(),
            "claimed dir should be removed after rollback"
        );
    }

    #[test]
    fn claim_guard_with_commit_preserves_directory() {
        let dir = tempfile::tempdir().unwrap();
        let instance_dir = dir.path().join("claimed-instance");
        fs::create_dir(&instance_dir).unwrap();

        {
            let mut guard = ClaimGuard::new(instance_dir.clone(), None, None);
            guard.commit();
        }

        assert!(
            instance_dir.exists(),
            "claimed dir should survive after commit"
        );
    }

    // ── PoolFillGuard ──────────────────────────────────────────────────────

    #[test]
    fn pool_fill_guard_without_commit_removes_directory() {
        let dir = tempfile::tempdir().unwrap();
        let pool_dir = dir.path().join("_warm-picoclaw-0");
        fs::create_dir(&pool_dir).unwrap();

        {
            let _guard = PoolFillGuard::new(pool_dir.clone());
        }

        assert!(
            !pool_dir.exists(),
            "pool dir should be removed after fill rollback"
        );
    }

    #[test]
    fn pool_fill_guard_with_commit_preserves_directory() {
        let dir = tempfile::tempdir().unwrap();
        let pool_dir = dir.path().join("_warm-picoclaw-0");
        fs::create_dir(&pool_dir).unwrap();

        {
            let mut guard = PoolFillGuard::new(pool_dir.clone());
            guard.commit();
        }

        assert!(
            pool_dir.exists(),
            "pool dir should survive after successful fill"
        );
    }

    #[test]
    fn pool_fill_guard_with_bogus_pids_cleans_up_directory() {
        let dir = tempfile::tempdir().unwrap();
        let pool_dir = dir.path().join("_warm-picoclaw-0");
        fs::create_dir(&pool_dir).unwrap();
        fs::write(pool_dir.join("firecracker.sock"), "").unwrap();

        {
            let mut guard = PoolFillGuard::new(pool_dir.clone());
            guard.set_fc_pid(999_999_997);
            guard.set_slirp_pid(999_999_996);
        }

        assert!(
            !pool_dir.exists(),
            "pool dir should be removed even with bogus PIDs"
        );
    }
}
