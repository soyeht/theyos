//! Warm pool management for macOS VMs.
//!
//! Maintains a pool of pre-booted VMs for instant (<1s) instance creation.
//! Uses snapshots to preserve VM state and enables fast cloning.

#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid;

use crate::{
    build_cidata_iso, clone_base_image,
    config::MacOSConfig,
    ensure_ssh_key,
    error::VZError,
    snapshot::SnapshotManager,
    vz::{VZVirtualMachine, VZVirtualMachineConfigurationBuilder, VmState},
};

/// Default warm pool size (number of pre-warmed VMs per claw type).
const DEFAULT_POOL_SIZE: usize = 2;

/// Default snapshot TTL (24 hours).
const DEFAULT_TTL_HOURS: u64 = 24;

/// Entry in the warm pool representing a single pre-warmed VM.
#[derive(Debug, Clone)]
pub struct WarmPoolEntry {
    /// Unique identifier for this pool entry.
    pub id: String,
    /// Claw type (e.g., "picoclaw", "zeroclaw").
    pub claw_type: String,
    /// Path to the snapshot file.
    pub snapshot_path: PathBuf,
    /// Current state of this entry.
    pub state: PoolEntryState,
    /// When this snapshot was created.
    pub created_at: SystemTime,
    /// When this snapshot was last used.
    pub last_used: SystemTime,
    /// Size of the snapshot in bytes.
    pub size_bytes: u64,
}

/// State of a warm pool entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolEntryState {
    /// Snapshot is ready for use.
    Ready,
    /// Snapshot is being created/updated.
    Filling,
    /// Snapshot has expired and should be refreshed.
    Expired,
}

/// Warm pool manager for macOS VMs.
///
/// Maintains a pool of pre-booted VM snapshots for fast instance creation.
/// Pool size and TTL are configurable via [`MacOSConfig`].
///
/// `Clone` is cheap: the entries map is behind `Arc<RwLock<...>>`.
#[derive(Clone)]
pub struct WarmPoolManager {
    /// Snapshots directory.
    pub(crate) snapshots_dir: PathBuf,
    /// Warm pool configuration.
    config: WarmPoolConfig,
    /// Pool entries by claw type.
    entries: Arc<RwLock<HashMap<String, Vec<WarmPoolEntry>>>>,
    /// Snapshot manager for save/load operations.
    _snapshot_manager: SnapshotManager,
}

/// Warm pool configuration.
#[derive(Debug, Clone)]
pub struct WarmPoolConfig {
    /// Target pool size (entries per claw type).
    pub pool_size: usize,
    /// Snapshot TTL in hours.
    pub ttl_hours: u64,
}

impl Default for WarmPoolConfig {
    fn default() -> Self {
        Self {
            pool_size: DEFAULT_POOL_SIZE,
            ttl_hours: DEFAULT_TTL_HOURS,
        }
    }
}

impl WarmPoolManager {
    /// Create a new warm pool manager.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshots directory cannot be accessed.
    pub fn new(snapshots_dir: PathBuf, config: WarmPoolConfig) -> Result<Self, VZError> {
        // Ensure snapshots directory exists
        std::fs::create_dir_all(&snapshots_dir).map_err(|e| {
            VZError::InvalidConfig(format!(
                "Failed to create snapshots directory {}: {e}",
                snapshots_dir.display()
            ))
        })?;

        let snapshot_manager = SnapshotManager::new(snapshots_dir.clone(), config.ttl_hours);

        info!(
            "Warm pool initialized: size={}, TTL={}h, dir={}",
            config.pool_size,
            config.ttl_hours,
            snapshots_dir.display()
        );

        Ok(Self {
            snapshots_dir,
            config,
            entries: Arc::new(RwLock::new(HashMap::new())),
            _snapshot_manager: snapshot_manager,
        })
    }

    /// Create from `MacOSConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if config is invalid or directory creation fails.
    pub fn from_config(config: &MacOSConfig) -> Result<Self, VZError>
    where
        Self: Sized,
    {
        let snapshots_dir = match std::env::var("THEYOS_SNAPSHOTS_DIR") {
            Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => {
                if let Some(ref macos_cfg) = config.vm_backend.macos {
                    PathBuf::from(&macos_cfg.snapshots_path)
                } else {
                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                    PathBuf::from(home).join("Library/Application Support/theyos/snapshots")
                }
            }
        };

        let pool_config = WarmPoolConfig {
            pool_size: config.warm_pool.size,
            ttl_hours: config.warm_pool.ttl_hours,
        };

        Self::new(snapshots_dir, pool_config)
    }

    /// Take a ready snapshot from the pool for the given claw type.
    ///
    /// Returns `Some(entry)` if a ready snapshot is available, `None` otherwise.
    /// This is an atomic operation - only one caller gets each entry.
    pub async fn take(&self, claw_type: &str) -> Option<WarmPoolEntry> {
        let mut entries = self.entries.write().await;
        let pool = entries.get_mut(claw_type)?;

        // Find first ready entry
        let idx = pool.iter().position(|e| e.state == PoolEntryState::Ready)?;

        let entry = pool.remove(idx);
        debug!(
            "Warm pool: took entry {} for {} ({} remaining)",
            entry.id,
            claw_type,
            pool.len()
        );

        Some(entry)
    }

    /// Return a snapshot to the pool (e.g., after VM stop).
    ///
    /// Marks the entry as ready for reuse.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be added to the pool.
    pub async fn store(&self, entry: WarmPoolEntry) -> Result<(), VZError> {
        let mut entries = self.entries.write().await;
        let pool = entries.entry(entry.claw_type.clone()).or_default();

        // Check if snapshot is expired
        let ttl = Duration::from_secs(self.config.ttl_hours * 3600);
        let age = entry.created_at.elapsed().unwrap_or(Duration::ZERO);

        let entry_id = entry.id.clone();
        let entry_claw_type = entry.claw_type.clone();

        let mut entry = entry;
        if age > ttl {
            warn!(
                "Warm pool: entry {} expired (age={:?} > TTL={:?})",
                entry_id, age, ttl
            );
            entry.state = PoolEntryState::Expired;
        } else {
            entry.state = PoolEntryState::Ready;
        }

        pool.push(entry);
        debug!(
            "Warm pool: stored entry {} for {} ({} total)",
            entry_id,
            entry_claw_type,
            pool.len()
        );

        Ok(())
    }

    /// Mark an entry as being filled (snapshot creation in progress).
    ///
    /// This prevents multiple concurrent refills of the same slot.
    ///
    /// # Errors
    ///
    /// Returns an error if the pool is full or entry already exists.
    pub async fn mark_filling(&self, claw_type: &str, id: String) -> Result<(), VZError> {
        let mut entries = self.entries.write().await;
        let pool = entries.entry(claw_type.to_string()).or_default();

        // Check pool size limit
        if pool.len() >= self.config.pool_size {
            let pool_len = pool.len();
            return Err(VZError::ResourceExhausted(format!(
                "Warm pool full for {claw_type}: {pool_len} entries"
            )));
        }

        // Check for duplicate ID
        if pool.iter().any(|e| e.id == id) {
            return Err(VZError::AlreadyExists(format!(
                "Warm pool entry {id} already exists"
            )));
        }

        // Create filling entry
        let snapshot_path = self.snapshots_dir.join(format!("{claw_type}-{id}.snap"));
        let entry = WarmPoolEntry {
            id: id.clone(),
            claw_type: claw_type.to_string(),
            snapshot_path,
            state: PoolEntryState::Filling,
            created_at: SystemTime::now(),
            last_used: SystemTime::now(),
            size_bytes: 0,
        };

        pool.push(entry);
        debug!("Warm pool: marked {} for {} as filling", id, claw_type);

        Ok(())
    }

    /// Update entry state after snapshot creation completes.
    ///
    /// # Errors
    ///
    /// Returns an error if entry not found.
    pub async fn update_entry(
        &self,
        claw_type: &str,
        id: &str,
        state: PoolEntryState,
        size_bytes: u64,
    ) -> Result<(), VZError> {
        let mut entries = self.entries.write().await;
        let pool = entries
            .get_mut(claw_type)
            .ok_or_else(|| VZError::NotFound(format!("No pool for {claw_type}")))?;

        let entry = pool.iter_mut().find(|e| e.id == id).ok_or_else(|| {
            VZError::NotFound(format!("Entry {id} not found in pool {claw_type}"))
        })?;

        entry.state = state;
        entry.size_bytes = size_bytes;
        entry.last_used = SystemTime::now();

        debug!(
            "Warm pool: updated entry {} for {} to {:?}",
            id, claw_type, state
        );

        Ok(())
    }

    /// Get current pool status for all claw types (async version).
    #[must_use]
    pub async fn status_full(&self) -> HashMap<String, PoolStatus> {
        self.status_inner().await
    }

    /// Remove expired entries from all pools.
    ///
    /// Returns the number of entries removed.
    #[must_use]
    pub async fn cleanup_expired(&self) -> usize {
        let ttl = Duration::from_secs(self.config.ttl_hours * 3600);
        let mut removed = 0;

        let mut entries = self.entries.write().await;

        for pool in entries.values_mut() {
            let before = pool.len();
            pool.retain(|entry| {
                let age = entry.created_at.elapsed().unwrap_or(Duration::ZERO);
                if age > ttl && entry.state == PoolEntryState::Expired {
                    // Try to delete the snapshot file
                    if let Err(e) = std::fs::remove_file(&entry.snapshot_path) {
                        warn!(
                            "Failed to delete expired snapshot {}: {}",
                            entry.snapshot_path.display(),
                            e
                        );
                    }
                    false
                } else {
                    true
                }
            });
            removed += before - pool.len();
        }

        if removed > 0 {
            info!("Warm pool: cleaned up {} expired entries", removed);
        }

        removed
    }

    /// Check if pool needs refilling for the given claw type.
    #[must_use]
    pub async fn needs_refill(&self, claw_type: &str) -> bool {
        let entries = self.entries.read().await;
        let pool = entries.get(claw_type);

        match pool {
            None => true, // No pool yet, needs refill
            Some(p) => {
                let ready_count = p
                    .iter()
                    .filter(|e| e.state == PoolEntryState::Ready)
                    .count();
                ready_count < self.config.pool_size
            }
        }
    }

    /// Get snapshot path for a new pool entry.
    #[must_use]
    pub fn snapshot_path(&self, claw_type: &str, id: &str) -> PathBuf {
        self.snapshots_dir.join(format!("{claw_type}-{id}.snap"))
    }

    /// Get canonical snapshot path for a claw type (used by warm pool).
    #[must_use]
    pub fn snapshot_path_for(&self, claw_type: &str) -> PathBuf {
        self.snapshots_dir
            .join(format!("{claw_type}-snapshot.vzsnapshot"))
    }

    /// Mark a slot as ready with a given snapshot path.
    ///
    /// # Panics
    ///
    /// Panics if the Tokio runtime cannot be built (system resource exhaustion).
    pub fn mark_ready(&self, claw_type: &str, path: PathBuf) {
        let entry = WarmPoolEntry {
            id: uuid::Uuid::new_v4().to_string(),
            claw_type: claw_type.to_string(),
            snapshot_path: path,
            state: PoolEntryState::Ready,
            created_at: SystemTime::now(),
            last_used: SystemTime::now(),
            size_bytes: 0,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let _ = rt.block_on(self.store(entry));
    }

    /// Drain all pool entries (stop + clear).
    ///
    /// # Panics
    ///
    /// Panics if the Tokio runtime cannot be built (system resource exhaustion).
    pub fn drain_all(&self) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async {
            let mut entries = self.entries.write().await;
            entries.clear();
        });
        info!("Warm pool: drained all entries");
    }

    /// Get synchronous pool status (blocks briefly on the `RwLock`).
    ///
    /// # Panics
    ///
    /// Panics if the Tokio runtime cannot be built (system resource exhaustion).
    #[must_use]
    pub fn status(&self) -> HashMap<String, PoolStatus> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(self.status_async())
    }

    /// Async pool status.
    async fn status_async(&self) -> HashMap<String, PoolStatus> {
        self.status_inner().await
    }

    async fn status_inner(&self) -> HashMap<String, PoolStatus> {
        let entries = self.entries.read().await;
        let mut status = HashMap::new();
        for (claw_type, pool) in entries.iter() {
            let ready = pool
                .iter()
                .filter(|e| e.state == PoolEntryState::Ready)
                .count();
            let filling = pool
                .iter()
                .filter(|e| e.state == PoolEntryState::Filling)
                .count();
            let expired = pool
                .iter()
                .filter(|e| e.state == PoolEntryState::Expired)
                .count();
            let snap = pool
                .iter()
                .find(|e| e.state == PoolEntryState::Ready)
                .map(|e| PoolEntrySnapshot {
                    path: e.snapshot_path.clone(),
                    created_at: e.created_at,
                });
            status.insert(
                claw_type.clone(),
                PoolStatus {
                    total: pool.len(),
                    ready,
                    filling,
                    expired,
                    target_size: self.config.pool_size,
                    state: if ready > 0 {
                        PoolEntryState::Ready
                    } else if filling > 0 {
                        PoolEntryState::Filling
                    } else {
                        PoolEntryState::Expired
                    },
                    snapshot: snap,
                },
            );
        }
        status
    }

    /// Boot a VM, pause it, and save a snapshot into the warm pool.
    ///
    /// This is the background refill operation. On completion, marks the slot `Ready`.
    ///
    /// # Errors
    ///
    /// Returns an error if any step (clone, boot, pause, snapshot) fails.
    pub async fn refill(&self, claw_type: &str) -> Result<(), VZError> {
        info!(claw_type, "Warm pool: starting refill");

        let refill_id = uuid::Uuid::new_v4().to_string();
        let container = format!("warmpool-{claw_type}-{}", &refill_id[..8]);
        let snapshot_path = self.snapshot_path_for(claw_type);

        // Mark slot as filling to prevent duplicate fills.
        self.mark_filling(claw_type, refill_id.clone()).await?;

        let result = self.do_refill(claw_type, &container, &snapshot_path).await;

        match result {
            Ok(()) => {
                self.update_entry(claw_type, &refill_id, PoolEntryState::Ready, 0)
                    .await?;
                // Replace entry with the correct snapshot path.
                {
                    let mut entries = self.entries.write().await;
                    if let Some(pool) = entries.get_mut(claw_type) {
                        if let Some(e) = pool.iter_mut().find(|e| e.id == refill_id) {
                            e.snapshot_path.clone_from(&snapshot_path);
                        }
                    }
                }
                info!(claw_type, "Warm pool: refill complete");
                Ok(())
            }
            Err(e) => {
                // Remove the filling entry on failure.
                let mut entries = self.entries.write().await;
                if let Some(pool) = entries.get_mut(claw_type) {
                    pool.retain(|e| e.id != refill_id);
                }
                Err(e)
            }
        }
    }

    async fn do_refill(
        &self,
        claw_type: &str,
        container: &str,
        snapshot_path: &std::path::Path,
    ) -> Result<(), VZError> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let inst_dir = std::path::PathBuf::from(&home)
            .join("Library/Application Support/theyos/vms")
            .join(container);

        // 1. Get SSH key.
        let pubkey = ensure_ssh_key().await?;

        // 2. Clone base disk.
        let (disk_path, efi_path, cidata_path) =
            clone_base_image(claw_type, container, &inst_dir).await?;

        // 3. Build cidata ISO.
        build_cidata_iso(container, &pubkey, &cidata_path).await?;

        // 4. Build VM config.
        let config = VZVirtualMachineConfigurationBuilder::new()
            .cpus(2)
            .memory_mb(2048)
            .disk_path(disk_path)
            .efi_store_path(efi_path)
            .cidata_iso_path(cidata_path)
            .build()?;

        // 5. Create and start VM.
        let vm = VZVirtualMachine::new(&config, container)?;
        vm.start().await?;

        // 6. Wait for running state.
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Ok(VmState::Running) = vm.get_state() {
                break;
            }
        }

        // 7. Pause and save snapshot.
        vm.pause().await?;
        vm.save_snapshot(snapshot_path).await?;

        // 8. Clean up the temporary VM instance.
        let _ = std::fs::remove_dir_all(&inst_dir);

        Ok(())
    }

    /// Take a slot for a new instance, restoring from snapshot.
    ///
    /// Returns the restored VM and its snapshot path, or `None` if no slot is ready.
    pub async fn take_and_restore(
        &self,
        claw_type: &str,
        container: &str,
    ) -> Option<Result<VZVirtualMachine, VZError>> {
        let entry = self.take(claw_type).await?;

        // Check TTL.
        let ttl = Duration::from_secs(self.config.ttl_hours * 3600);
        if entry.created_at.elapsed().unwrap_or(Duration::ZERO) > ttl {
            warn!(
                claw_type,
                "Warm pool snapshot expired, falling back to cold boot"
            );
            return None;
        }

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let inst_dir = std::path::PathBuf::from(&home)
            .join("Library/Application Support/theyos/vms")
            .join(container);

        // Clone the snapshot disk for the new instance.
        // For warm restore we need a fresh disk clone.
        Some(
            self.restore_entry(claw_type, container, &inst_dir, &entry)
                .await,
        )
    }

    async fn restore_entry(
        &self,
        claw_type: &str,
        container: &str,
        inst_dir: &std::path::Path,
        _entry: &WarmPoolEntry,
    ) -> Result<VZVirtualMachine, VZError> {
        let pubkey = ensure_ssh_key().await?;
        let (disk_path, efi_path, cidata_path) =
            clone_base_image(claw_type, container, inst_dir).await?;
        build_cidata_iso(container, &pubkey, &cidata_path).await?;

        let snapshot_path = self.snapshot_path_for(claw_type);
        let config = VZVirtualMachineConfigurationBuilder::new()
            .cpus(2)
            .memory_mb(2048)
            .disk_path(disk_path)
            .efi_store_path(efi_path)
            .cidata_iso_path(cidata_path)
            .build()?;

        let vm = VZVirtualMachine::new(&config, container)?;
        vm.restore_snapshot(&snapshot_path).await?;
        Ok(vm)
    }
}

/// Snapshot reference for display in pool status.
#[derive(Debug, Clone)]
pub struct PoolEntrySnapshot {
    pub path: PathBuf,
    pub created_at: SystemTime,
}

/// Pool status for a single claw type.
#[derive(Debug, Clone)]
pub struct PoolStatus {
    /// Total entries in pool.
    pub total: usize,
    /// Ready-to-use entries.
    pub ready: usize,
    /// Entries being created.
    pub filling: usize,
    /// Expired entries.
    pub expired: usize,
    /// Target pool size.
    pub target_size: usize,
    /// Current slot state (summary).
    pub state: PoolEntryState,
    /// Snapshot reference if Ready.
    pub snapshot: Option<PoolEntrySnapshot>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> WarmPoolConfig {
        WarmPoolConfig {
            pool_size: 2,
            ttl_hours: 24,
        }
    }

    #[tokio::test]
    async fn test_warm_pool_take_empty() {
        let temp = tempfile::tempdir().unwrap();
        let snap_dir = temp.path().join("snapshots");

        let pool = WarmPoolManager::new(snap_dir, test_config()).unwrap();

        // Taking from empty pool returns None
        assert!(pool.take("picoclaw").await.is_none());
    }

    #[tokio::test]
    async fn test_warm_pool_mark_filling() {
        let temp = tempfile::tempdir().unwrap();
        let snap_dir = temp.path().join("snapshots");

        let pool = WarmPoolManager::new(snap_dir, test_config()).unwrap();

        // Mark entry as filling
        pool.mark_filling("picoclaw", "test-1".to_string())
            .await
            .unwrap();

        // Status should show 1 filling
        let status = pool.status_full().await;
        assert_eq!(status.get("picoclaw").unwrap().filling, 1);
        assert_eq!(status.get("picoclaw").unwrap().ready, 0);
    }

    #[tokio::test]
    async fn test_warm_pool_store_and_take() {
        let temp = tempfile::tempdir().unwrap();
        let snap_dir = temp.path().join("snapshots");

        let pool = WarmPoolManager::new(snap_dir, test_config()).unwrap();

        // Create and store an entry
        let entry = WarmPoolEntry {
            id: "test-1".to_string(),
            claw_type: "picoclaw".to_string(),
            snapshot_path: PathBuf::from("/tmp/test.snap"),
            state: PoolEntryState::Ready,
            created_at: SystemTime::now(),
            last_used: SystemTime::now(),
            size_bytes: 1024,
        };

        pool.store(entry.clone()).await.unwrap();

        // Take should return the entry
        let taken = pool.take("picoclaw").await.unwrap();
        assert_eq!(taken.id, "test-1");

        // Second take should return None (pool empty)
        assert!(pool.take("picoclaw").await.is_none());
    }

    #[tokio::test]
    async fn test_warm_pool_needs_refill() {
        let temp = tempfile::tempdir().unwrap();
        let snap_dir = temp.path().join("snapshots");

        let pool = WarmPoolManager::new(snap_dir, test_config()).unwrap();

        // Empty pool needs refill
        assert!(pool.needs_refill("picoclaw").await);

        // Add one ready entry
        pool.mark_filling("picoclaw", "test-1".to_string())
            .await
            .unwrap();
        pool.update_entry("picoclaw", "test-1", PoolEntryState::Ready, 1024)
            .await
            .unwrap();

        // Still needs refill (target is 2)
        assert!(pool.needs_refill("picoclaw").await);

        // Add second entry
        pool.mark_filling("picoclaw", "test-2".to_string())
            .await
            .unwrap();
        pool.update_entry("picoclaw", "test-2", PoolEntryState::Ready, 1024)
            .await
            .unwrap();

        // No longer needs refill
        assert!(!pool.needs_refill("picoclaw").await);
    }

    #[tokio::test]
    async fn test_warm_pool_cleanup_expired() {
        let temp = tempfile::tempdir().unwrap();
        let snap_dir = temp.path().join("snapshots");

        // Create a pool with very short TTL
        let config = WarmPoolConfig {
            pool_size: 2,
            ttl_hours: 0, // Immediate expiry
        };
        let pool = WarmPoolManager::new(snap_dir, config).unwrap();

        // Add an entry and mark as expired
        pool.mark_filling("picoclaw", "test-1".to_string())
            .await
            .unwrap();
        pool.update_entry("picoclaw", "test-1", PoolEntryState::Expired, 1024)
            .await
            .unwrap();

        // Cleanup should remove expired entries
        let removed = pool.cleanup_expired().await;
        assert_eq!(removed, 1);

        // Status should show 0 entries
        let status = pool.status_full().await;
        assert_eq!(status.get("picoclaw").map_or(0, |s| s.total), 0);
    }
}
