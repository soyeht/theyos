//! Snapshot management for VZ VMs.
//!
//! Handles VZ snapshot lifecycle for warm pool functionality.
//!
//! Two distinct snapshot kinds:
//! - **Regular snapshots**: TTL-based, discovered by scanning `snapshots_dir`.
//! - **Base snapshots**: Registered by name via [`SnapshotManager::register`], never
//!   expired by TTL (only invalidated when the file is deleted). Used for the macOS
//!   guest base image (`"macos-base"` → `base.vzsnapshot`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::VZError;

/// Snapshot state for warm pool management.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotState {
    /// Snapshot is ready to use
    Ready,
    /// Snapshot is being created
    Warming,
    /// Snapshot has expired (TTL exceeded)
    Expired,
}

impl SnapshotState {
    /// Create from string.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ready" => Some(Self::Ready),
            "warming" => Some(Self::Warming),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }

    /// Convert to string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Warming => "warming",
            Self::Expired => "expired",
        }
    }
}

/// Snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VMSnapshot {
    /// Snapshot ID (unique)
    pub id: String,
    /// Claw type this snapshot serves
    pub claw_type: String,
    /// Path to .vzsnapshot file
    pub path: PathBuf,
    /// Current state
    pub state: SnapshotState,
    /// When the snapshot was created
    pub created_at: SystemTime,
    /// When the snapshot was last used
    pub last_used: Option<SystemTime>,
    /// Size in bytes
    pub size_bytes: u64,
}

impl VMSnapshot {
    /// Create a new snapshot metadata.
    #[must_use]
    pub fn new(claw_type: String, path: PathBuf) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            claw_type,
            path,
            state: SnapshotState::Warming,
            created_at: SystemTime::now(),
            last_used: None,
            size_bytes: 0,
        }
    }

    /// Check if snapshot has expired based on TTL.
    #[must_use]
    pub fn is_expired(&self, ttl_hours: u64) -> bool {
        let ttl_duration = std::time::Duration::from_secs(ttl_hours * 3600);

        if let Ok(elapsed) = self.created_at.elapsed() {
            elapsed > ttl_duration
        } else {
            // SystemTime was before Unix epoch - treat as expired
            true
        }
    }

    /// Update the last used time and mark as ready.
    pub fn mark_used(&mut self) {
        self.last_used = Some(SystemTime::now());
        self.state = SnapshotState::Ready;
    }

    /// Mark as expired.
    pub fn mark_expired(&mut self) {
        self.state = SnapshotState::Expired;
    }

    /// Calculate the path for a snapshot of the given claw type.
    #[must_use]
    pub fn path_for(base_dir: &Path, claw_type: &str) -> PathBuf {
        base_dir.join(format!("{claw_type}-snapshot.vzsnapshot"))
    }

    /// Get the file size if the snapshot file exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the filesystem metadata cannot be read.
    pub fn update_size(&mut self) -> Result<(), VZError> {
        self.size_bytes = std::fs::metadata(&self.path).map_or(0, |m| m.len());
        Ok(())
    }
}

/// Snapshot manager for warm pool operations.
#[derive(Clone)]
pub struct SnapshotManager {
    /// Base directory for regular (TTL-managed) snapshots.
    snapshots_dir: PathBuf,
    /// Default TTL in hours for regular snapshots.
    ttl_hours: u64,
    /// Named base snapshots that are exempt from TTL expiry.
    ///
    /// Populated via [`Self::register`] at `vmrunner_macos_ipc` startup.
    /// Key: name (e.g. `"macos-base"`), Value: path to `.vzsnapshot` file.
    base_snapshots: HashMap<String, PathBuf>,
}

impl SnapshotManager {
    /// Create a new snapshot manager.
    #[must_use]
    pub fn new(snapshots_dir: PathBuf, ttl_hours: u64) -> Self {
        Self {
            snapshots_dir,
            ttl_hours,
            base_snapshots: HashMap::new(),
        }
    }

    /// Register a named base snapshot that is exempt from TTL expiry.
    ///
    /// Called at `vmrunner_macos_ipc` startup with `"macos-base"` pointing to
    /// `$THEYOS_VM_ASSETS_DIR/macos-base/base.vzsnapshot`. Registered snapshots
    /// are never expired automatically — invalidation happens only when the file
    /// is deleted (e.g. by `theyos init-macos-guest --force-provision`).
    ///
    /// Re-registering the same `name` with a new path replaces the old entry.
    pub fn register(&mut self, name: &str, path: PathBuf) {
        self.base_snapshots.insert(name.to_string(), path);
    }

    /// Return the path for a registered base snapshot if the file exists on disk.
    ///
    /// Returns `None` if the name was never registered or the file has been deleted.
    #[must_use]
    pub fn base_snapshot_path(&self, name: &str) -> Option<&PathBuf> {
        let path = self.base_snapshots.get(name)?;
        if path.exists() { Some(path) } else { None }
    }

    /// Restore a warm-pool VM from a registered base snapshot and boot it.
    ///
    /// The caller must have already CoW-cloned `disk.img` and `aux.auxstorage` from
    /// `macos-base/` into `dest_dir`. This function:
    ///   1. Looks up `name` in the registered base snapshot registry.
    ///   2. Builds a [`crate::vz::VZMacOSVmConfigurationBuilder`] from the files in `dest_dir`.
    ///   3. Creates a [`crate::vz::VZVirtualMachine`].
    ///   4. Calls `restoreMachineStateFromURL:` + `resumeWithCompletionHandler:`
    ///      (via `vm.restore_snapshot`) to transition the VM from Paused → Running.
    ///
    /// The returned `VZVirtualMachine` is in the **Running** state and ready for
    /// warm-pool assignment.
    ///
    /// # Errors
    ///
    /// Returns `VZError::SnapshotError` if `name` is not registered or the file is
    /// missing; `VZError::InvalidConfig` if `dest_dir` is missing required files;
    /// or any VZ error from the restore/resume operation.
    pub async fn restore_from_base_snapshot(
        &self,
        name: &str,
        container: &str,
        dest_dir: &Path,
        hardware_model_data: &[u8],
        cpus: u32,
        memory_mb: u32,
    ) -> Result<crate::vz::VZVirtualMachine, VZError> {
        let snapshot_path = self.base_snapshot_path(name).ok_or_else(|| {
            VZError::SnapshotError(format!(
                "base snapshot '{name}' not registered or not found on disk — \
                 run 'theyos init-macos-guest' to create it"
            ))
        })?;

        let disk_path = dest_dir.join("disk.img");
        let aux_path = dest_dir.join("aux.auxstorage");

        tracing::info!(
            container,
            snapshot = %snapshot_path.display(),
            disk = %disk_path.display(),
            "Restoring warm-pool VM from base snapshot"
        );

        let config = crate::vz::VZMacOSVmConfigurationBuilder::new()
            .cpus(cpus)
            .memory_mb(memory_mb)
            .disk_path(disk_path)
            .aux_storage_path(aux_path)
            .hardware_model_data(hardware_model_data.to_vec())
            .build()?;

        let vm = crate::vz::VZVirtualMachine::new(&config, container)?;
        vm.restore_snapshot(snapshot_path).await?;

        tracing::info!(
            container,
            "Warm-pool VM is running after base snapshot restore"
        );

        Ok(vm)
    }

    /// Ensure snapshots directory exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn ensure_dir(&self) -> Result<(), VZError> {
        let dir = self.snapshots_dir.display();
        std::fs::create_dir_all(&self.snapshots_dir).map_err(|e| {
            VZError::InvalidConfig(format!("Failed to create snapshots directory {dir}: {e}"))
        })
    }

    /// Get snapshot path for a claw type.
    #[must_use]
    pub fn snapshot_path(&self, claw_type: &str) -> PathBuf {
        VMSnapshot::path_for(&self.snapshots_dir, claw_type)
    }

    /// List all snapshots in the directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshots directory cannot be read.
    pub fn list_snapshots(&self) -> Result<Vec<VMSnapshot>, VZError> {
        let mut snapshots = Vec::new();

        let dir = self.snapshots_dir.display();
        let entries = std::fs::read_dir(&self.snapshots_dir).map_err(|e| {
            VZError::InvalidConfig(format!("Failed to read snapshots directory {dir}: {e}"))
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("vzsnapshot") {
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                // Extract claw type from "picoclaw-snapshot.vzsnapshot"
                let claw_type = stem.strip_suffix("-snapshot").unwrap_or(stem).to_string();

                let mut snapshot = VMSnapshot::new(claw_type.clone(), path);
                snapshot.state = SnapshotState::Ready;
                snapshot.update_size()?;

                if snapshot.is_expired(self.ttl_hours) {
                    snapshot.mark_expired();
                }

                snapshots.push(snapshot);
            }
        }

        Ok(snapshots)
    }

    /// Find a ready snapshot for the given claw type.
    #[must_use]
    pub fn find_ready(&self, claw_type: &str) -> Option<VMSnapshot> {
        let path = self.snapshot_path(claw_type);
        if !path.exists() {
            return None;
        }

        let mut snapshot = VMSnapshot::new(claw_type.to_string(), path);
        snapshot.state = SnapshotState::Ready;
        snapshot.update_size().ok()?;

        if snapshot.is_expired(self.ttl_hours) {
            return None;
        }

        Some(snapshot)
    }

    /// Delete a snapshot file.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot file cannot be removed.
    pub fn delete(&self, snapshot: &VMSnapshot) -> Result<(), VZError> {
        if snapshot.path.exists() {
            let path = snapshot.path.display();
            std::fs::remove_file(&snapshot.path)
                .map_err(|e| VZError::Other(format!("Failed to delete snapshot {path}: {e}")))?;
        }
        Ok(())
    }

    /// Clean up expired snapshots.
    ///
    /// # Errors
    ///
    /// Returns an error if snapshots cannot be listed or deleted.
    pub fn cleanup_expired(&self) -> Result<Vec<PathBuf>, VZError> {
        let snapshots = self.list_snapshots()?;
        let mut removed = Vec::new();

        for snapshot in snapshots {
            if snapshot.is_expired(self.ttl_hours) {
                let path = snapshot.path.clone();
                self.delete(&snapshot)?;
                removed.push(path);
            }
        }

        Ok(removed)
    }

    /// Get total disk usage of all snapshots.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshots directory cannot be read.
    pub fn total_size(&self) -> Result<u64, VZError> {
        let snapshots = self.list_snapshots()?;
        Ok(snapshots.iter().map(|s| s.size_bytes).sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_snapshot_state_from_str() {
        assert_eq!(SnapshotState::from_str("ready"), Some(SnapshotState::Ready));
        assert_eq!(
            SnapshotState::from_str("WARMING"),
            Some(SnapshotState::Warming)
        );
        assert_eq!(
            SnapshotState::from_str("expired"),
            Some(SnapshotState::Expired)
        );
        assert_eq!(SnapshotState::from_str("unknown"), None);
    }

    #[test]
    fn test_snapshot_state_as_str() {
        assert_eq!(SnapshotState::Ready.as_str(), "ready");
        assert_eq!(SnapshotState::Warming.as_str(), "warming");
        assert_eq!(SnapshotState::Expired.as_str(), "expired");
    }

    #[test]
    fn test_vm_snapshot_new() {
        let snapshot = VMSnapshot::new(
            "picoclaw".to_string(),
            PathBuf::from("/tmp/test.vzsnapshot"),
        );

        assert_eq!(snapshot.claw_type, "picoclaw");
        assert_eq!(snapshot.state, SnapshotState::Warming);
        assert_eq!(snapshot.last_used, None);
        assert_eq!(snapshot.size_bytes, 0);
    }

    #[test]
    fn test_vm_snapshot_mark_used() {
        let mut snapshot = VMSnapshot::new(
            "picoclaw".to_string(),
            PathBuf::from("/tmp/test.vzsnapshot"),
        );
        assert_eq!(snapshot.state, SnapshotState::Warming);

        snapshot.mark_used();
        assert_eq!(snapshot.state, SnapshotState::Ready);
        assert!(snapshot.last_used.is_some());
    }

    #[test]
    fn test_vm_snapshot_path_for() {
        let base = PathBuf::from("/snapshots");
        let path = VMSnapshot::path_for(&base, "picoclaw");
        assert_eq!(
            path,
            PathBuf::from("/snapshots/picoclaw-snapshot.vzsnapshot")
        );
    }

    #[test]
    fn test_snapshot_manager() {
        let temp_dir = TempDir::new().unwrap();
        let manager = SnapshotManager::new(temp_dir.path().to_path_buf(), 24);

        // Ensure directory exists
        manager.ensure_dir().unwrap();
        assert!(temp_dir.path().exists());

        // No snapshots initially
        let snapshots = manager.list_snapshots().unwrap();
        assert!(snapshots.is_empty());

        // Find non-existent snapshot returns None
        assert!(manager.find_ready("picoclaw").is_none());
    }

    #[test]
    fn test_register_base_snapshot() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = SnapshotManager::new(temp_dir.path().to_path_buf(), 24);

        // Not registered yet
        assert!(manager.base_snapshot_path("macos-base").is_none());

        // Create a fake snapshot file and register it
        let snap_path = temp_dir.path().join("base.vzsnapshot");
        std::fs::write(&snap_path, b"fake snapshot data").unwrap();
        manager.register("macos-base", snap_path.clone());

        // Now accessible
        assert_eq!(manager.base_snapshot_path("macos-base"), Some(&snap_path));
    }

    #[test]
    fn test_base_snapshot_missing_on_disk_returns_none() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = SnapshotManager::new(temp_dir.path().to_path_buf(), 24);

        // Register a path that does NOT exist on disk
        let nonexistent = temp_dir.path().join("missing.vzsnapshot");
        manager.register("missing", nonexistent);

        // Should return None since the file doesn't exist
        assert!(manager.base_snapshot_path("missing").is_none());
    }

    #[test]
    fn test_base_snapshot_not_subject_to_ttl() {
        // Regular snapshots expire with TTL. Base snapshots registered via register()
        // are only invalidated when the file is deleted — TTL=0 does NOT expire them.
        let temp_dir = TempDir::new().unwrap();
        let mut manager = SnapshotManager::new(temp_dir.path().to_path_buf(), 0); // TTL = 0

        let snap_path = temp_dir.path().join("base.vzsnapshot");
        std::fs::write(&snap_path, b"fake snapshot data").unwrap();
        manager.register("macos-base", snap_path.clone());

        // Even with TTL=0, base snapshots are returned as long as the file exists
        assert_eq!(manager.base_snapshot_path("macos-base"), Some(&snap_path));
    }

    #[test]
    fn test_register_multiple_base_snapshots() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = SnapshotManager::new(temp_dir.path().to_path_buf(), 24);

        let snap1 = temp_dir.path().join("base1.vzsnapshot");
        let snap2 = temp_dir.path().join("base2.vzsnapshot");
        std::fs::write(&snap1, b"snap1").unwrap();
        std::fs::write(&snap2, b"snap2").unwrap();

        manager.register("snapshot-v1", snap1.clone());
        manager.register("snapshot-v2", snap2.clone());

        assert_eq!(manager.base_snapshot_path("snapshot-v1"), Some(&snap1));
        assert_eq!(manager.base_snapshot_path("snapshot-v2"), Some(&snap2));
        assert!(manager.base_snapshot_path("snapshot-v3").is_none());
    }

    #[test]
    fn test_register_overwrites_existing_entry() {
        let temp_dir = TempDir::new().unwrap();
        let mut manager = SnapshotManager::new(temp_dir.path().to_path_buf(), 24);

        let snap1 = temp_dir.path().join("v1.vzsnapshot");
        let snap2 = temp_dir.path().join("v2.vzsnapshot");
        std::fs::write(&snap1, b"old").unwrap();
        std::fs::write(&snap2, b"new").unwrap();

        manager.register("macos-base", snap1.clone());
        assert_eq!(manager.base_snapshot_path("macos-base"), Some(&snap1));

        // Re-register with a new path (e.g. after --force-provision rebuilds the snapshot)
        manager.register("macos-base", snap2.clone());
        assert_eq!(manager.base_snapshot_path("macos-base"), Some(&snap2));
    }

    #[test]
    fn test_vm_snapshot_is_expired() {
        let mut snapshot = VMSnapshot::new(
            "picoclaw".to_string(),
            PathBuf::from("/tmp/test.vzsnapshot"),
        );

        // Fresh snapshot should not be expired
        assert!(!snapshot.is_expired(24));

        // Modify created_at to simulate old snapshot
        let one_day_ago = SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(25 * 3600))
            .unwrap();
        snapshot.created_at = one_day_ago;

        // Should be expired with 24 hour TTL
        assert!(snapshot.is_expired(24));

        // Should not be expired with 48 hour TTL
        assert!(!snapshot.is_expired(48));
    }
}
