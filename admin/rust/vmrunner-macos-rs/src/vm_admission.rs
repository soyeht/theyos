#![cfg(target_os = "macos")]
//! `VmAdmission` — the single admission authority for **every** macOS VM that
//! theyOS starts (install, snapshot, warm pool, user claw, restart).
//!
//! # Why this exists
//!
//! Apple's Virtualization framework enforces a host-wide limit on concurrently
//! active macOS guests (`MACOS_VM_LIMIT`). That limit is owned by
//! `AppleVirtualPlatformSystemService`, an OS daemon that **outlives** the
//! `vmrunner_macos_ipc` process. Apple exposes **no** public API to query the
//! current active-VM count. A `VZVirtualMachine` that is dropped while still
//! running (process crash, `SIGKILL` from an IPC respawn, or a `Drop` that
//! releases but never `stop`s) leaks an OS-level session that keeps counting
//! against the limit until the host reboots.
//!
//! A process-local [`MacOSVmSlotManager`] semaphore cannot see those leaks: the
//! prepare IPC is a *fresh* process each run, so its semaphore always starts
//! full. We therefore keep a **persisted lease registry** that records what
//! *theyOS itself* started.
//!
//! # Invariants
//!
//! - **I-1 (single authority).** No macOS `VZVirtualMachine` may be started
//!   without a [`VmLease`] obtained from [`VmAdmission::reserve`]. Every entry
//!   point — install, snapshot, warm pool, user claw, restart — goes through it.
//! - **I-2 (explicit stop before release).** A running VM is stopped by an
//!   explicit [`ManagedMacOSVm::stop_then_release`] / [`VmLease::release_clean`]
//!   call. [`VmLease::drop`] is *only* a last-best-effort telemetry hook: it
//!   never silently frees capacity, it retains the registry record (fail-closed).
//! - **I-3 (boot-scoped orphan accounting).** A lease whose `owner_pid` is dead
//!   **in the same boot** is a `suspected_orphan` and still counts against
//!   capacity — that is exactly when the OS may still be holding the slot. It is
//!   never silently removed. A lease from a **different boot** is reconciled
//!   away, because a reboot clears leaked VZ sessions.
//! - **I-4 (reactive backstop).** If the registry shows free capacity but VZ
//!   still returns the limit error (`Code=6`), the caller maps it to a typed
//!   [`VZError::HostVmLimitReached`], calls [`VmAdmission::mark_host_blocked`]
//!   (a boot-scoped flag), and stops retrying.
//!
//! The registry is guarded by an advisory `flock` so concurrent IPC processes
//! coordinate. It is the source of truth for *theyOS-started* VMs — not a
//! pretend query of macOS internals.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::OwnedSemaphorePermit;

use crate::slot_manager::{MACOS_VM_LIMIT, MacOSVmSlotManager};
use crate::vz::VZVirtualMachine;

/// Default registry filename under the VM state directory.
const REGISTRY_FILENAME: &str = "active-vm-leases.json";

/// What kind of macOS VM a lease protects. Serialized into the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmKind {
    /// `VZMacOSInstaller` install VM (guest-image prepare, step 1).
    Install,
    /// Base-snapshot boot VM (guest-image prepare, step 2).
    Snapshot,
    /// Pre-booted warm-pool VM.
    WarmPool,
    /// User claw instance VM.
    UserClaw,
}

/// Lifecycle state of a lease, for telemetry/observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    /// VM is being created/started.
    Starting,
    /// VM is running.
    Running,
    /// VM stop has been requested.
    Stopping,
}

/// Why a reservation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitReason {
    /// Live + suspected-orphan leases already fill the host limit.
    CapacityFull,
    /// The host was flagged blocked this boot after a reactive VZ limit error.
    HostBlocked,
}

/// Error returned by [`VmAdmission::reserve`].
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// The macOS host active-VM limit is (believed to be) reached.
    #[error(
        "host macOS VM limit reached ({reason:?}): {live} running, {suspected_orphans} \
         suspected orphan(s) this boot (limit {MACOS_VM_LIMIT})"
    )]
    HostVmLimitReached {
        /// Leases whose owner process is alive this boot.
        live: usize,
        /// Same-boot leases whose owner process is dead (slot may still be held by the OS).
        suspected_orphans: usize,
        /// Whether the refusal is a reactive host-blocked flag vs. plain capacity.
        reason: LimitReason,
    },
    /// Registry I/O / locking failure.
    #[error("vm admission registry error: {0}")]
    Registry(String),
}

impl AdmissionError {
    /// True when this error is the host VM limit (used to set the typed
    /// `host_vm_limit_reached` failure code upstream).
    #[must_use]
    pub fn is_host_vm_limit(&self) -> bool {
        matches!(self, Self::HostVmLimitReached { .. })
    }
}

/// A single persisted lease record — the source of truth for one theyOS-started VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VmLeaseRecord {
    /// Unique lease id (uuid v4).
    lease_id: String,
    /// PID of the process that started (and owns the stop of) the VM.
    owner_pid: i32,
    /// Boot identity (`kern.boottime` seconds). Changes on reboot.
    boot_id: String,
    /// What the VM is for.
    kind: VmKind,
    /// Instance/container id when applicable (user claw, warm pool slot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,
    /// Unix seconds when the lease was created.
    started_at: u64,
    /// Lifecycle state.
    state: LeaseState,
}

/// On-disk registry document.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Registry {
    /// Schema version.
    #[serde(default = "default_version")]
    version: u32,
    /// Set to the current boot id when a reactive VZ limit error is observed.
    /// Cleared automatically once the boot id changes (reboot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocked_boot_id: Option<String>,
    /// Active leases.
    #[serde(default)]
    leases: Vec<VmLeaseRecord>,
}

fn default_version() -> u32 {
    1
}

/// A live snapshot of admission capacity (for status endpoints/telemetry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacitySnapshot {
    /// Leases whose owner process is alive this boot.
    pub live: usize,
    /// Same-boot dead-owner leases (slot likely still held by the OS).
    pub suspected_orphans: usize,
    /// Free slots (`limit - live - orphans`, floored at 0).
    pub available: usize,
    /// Whether the host is flagged blocked this boot.
    pub host_blocked: bool,
}

type Liveness = Arc<dyn Fn(i32) -> bool + Send + Sync>;

/// The single admission authority. Cheap to clone-by-reference via `Arc`.
pub struct VmAdmission {
    /// Process-local RAII semaphore (defense-in-depth; the registry is truth).
    slots: MacOSVmSlotManager,
    /// Path to the lease registry JSON.
    registry_path: PathBuf,
    /// This process's boot id.
    boot_id: String,
    /// PID-liveness probe (injectable for tests).
    liveness: Liveness,
}

impl VmAdmission {
    /// Construct for production: registry under `state_dir`, real boot id, real
    /// PID liveness via `kill(pid, 0)`.
    #[must_use]
    pub fn new(state_dir: &Path) -> Self {
        Self {
            slots: MacOSVmSlotManager::new(),
            registry_path: state_dir.join(REGISTRY_FILENAME),
            boot_id: core_rs::boot_id::current_boot_id(),
            liveness: Arc::new(pid_alive_real),
        }
    }

    /// Number of in-process semaphore permits currently free (diagnostic only;
    /// the registry capacity is authoritative across processes).
    #[must_use]
    pub fn semaphore_available(&self) -> usize {
        self.slots.available()
    }

    /// Reserve a slot for a new macOS VM.
    ///
    /// On success the returned [`VmLease`] holds the in-process permit and a
    /// persisted registry record; the caller must release it via
    /// [`VmLease::release_clean`] (or wrap the VM in [`ManagedMacOSVm`] and call
    /// [`ManagedMacOSVm::stop_then_release`]).
    ///
    /// On [`AdmissionError::HostVmLimitReached`] **no VM was started** and the
    /// caller must not attempt one.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::HostVmLimitReached`] when capacity is full or
    /// the host is flagged blocked this boot, or [`AdmissionError::Registry`]
    /// on I/O failure.
    pub fn reserve(
        &self,
        kind: VmKind,
        instance_id: Option<String>,
    ) -> Result<VmLease, AdmissionError> {
        let guard = FileGuard::lock_exclusive(&self.registry_path)?;
        let mut reg = guard.read_registry()?;

        let changed = reconcile(&mut reg, &self.boot_id, &self.liveness);

        // Reactive host-block flag: refuse without touching VZ.
        if reg.blocked_boot_id.as_deref() == Some(self.boot_id.as_str()) {
            if changed {
                guard.write_registry(&reg)?;
            }
            let (live, orphans) = count(&reg, &self.boot_id, &self.liveness);
            return Err(AdmissionError::HostVmLimitReached {
                live,
                suspected_orphans: orphans,
                reason: LimitReason::HostBlocked,
            });
        }

        let (live, orphans) = count(&reg, &self.boot_id, &self.liveness);
        if live + orphans >= MACOS_VM_LIMIT {
            if changed {
                guard.write_registry(&reg)?;
            }
            return Err(AdmissionError::HostVmLimitReached {
                live,
                suspected_orphans: orphans,
                reason: LimitReason::CapacityFull,
            });
        }

        // Process-local permit (defense-in-depth). The registry already gated
        // cross-process capacity, so this should succeed; a failure means our
        // own process already holds every permit — also a limit condition.
        let permit =
            self.slots
                .try_acquire_owned()
                .map_err(|_| AdmissionError::HostVmLimitReached {
                    live,
                    suspected_orphans: orphans,
                    reason: LimitReason::CapacityFull,
                })?;

        let lease_id = new_lease_id();
        reg.leases.push(VmLeaseRecord {
            lease_id: lease_id.clone(),
            owner_pid: current_pid(),
            boot_id: self.boot_id.clone(),
            kind,
            instance_id,
            started_at: now_secs(),
            state: LeaseState::Starting,
        });
        guard.write_registry(&reg)?;

        Ok(VmLease {
            registry_path: self.registry_path.clone(),
            lease_id,
            kind,
            permit: Some(permit),
            released: false,
        })
    }

    /// Flag the host as blocked for the current boot after a reactive VZ limit
    /// error. Subsequent [`reserve`](Self::reserve) calls refuse immediately —
    /// without attempting a VM — until the host reboots (boot id changes) or
    /// [`clear_host_blocked`](Self::clear_host_blocked) is called.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Registry`] on I/O failure.
    pub fn mark_host_blocked(&self) -> Result<(), AdmissionError> {
        let guard = FileGuard::lock_exclusive(&self.registry_path)?;
        let mut reg = guard.read_registry()?;
        reconcile(&mut reg, &self.boot_id, &self.liveness);
        reg.blocked_boot_id = Some(self.boot_id.clone());
        guard.write_registry(&reg)?;
        tracing::warn!(
            boot_id = %self.boot_id,
            "host flagged blocked for this boot after VZ active-VM limit error"
        );
        Ok(())
    }

    /// Clear the host-blocked flag (e.g. operator `--force`). Does not touch
    /// leases; capacity gating still applies.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Registry`] on I/O failure.
    pub fn clear_host_blocked(&self) -> Result<(), AdmissionError> {
        let guard = FileGuard::lock_exclusive(&self.registry_path)?;
        let mut reg = guard.read_registry()?;
        reconcile(&mut reg, &self.boot_id, &self.liveness);
        reg.blocked_boot_id = None;
        guard.write_registry(&reg)?;
        Ok(())
    }

    /// Reconcile the registry now (drop other-boot leases, persist), returning
    /// the current capacity snapshot. Call at process startup for telemetry and
    /// to surface stale state.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Registry`] on I/O failure.
    pub fn reconcile_now(&self) -> Result<CapacitySnapshot, AdmissionError> {
        let guard = FileGuard::lock_exclusive(&self.registry_path)?;
        let mut reg = guard.read_registry()?;
        reconcile(&mut reg, &self.boot_id, &self.liveness);
        guard.write_registry(&reg)?;
        Ok(snapshot(&reg, &self.boot_id, &self.liveness))
    }

    /// Read the current capacity snapshot without mutating the registry.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::Registry`] on I/O failure.
    pub fn capacity(&self) -> Result<CapacitySnapshot, AdmissionError> {
        let guard = FileGuard::lock_exclusive(&self.registry_path)?;
        let reg = guard.read_registry()?;
        Ok(snapshot(&reg, &self.boot_id, &self.liveness))
    }
}

/// A held reservation. Holds the in-process permit and a persisted record.
///
/// **Release discipline (Invariant I-2):** call [`release_clean`](Self::release_clean)
/// after the VM is confirmed stopped, or wrap the VM in [`ManagedMacOSVm`] and
/// call [`ManagedMacOSVm::stop_then_release`]. Dropping a lease without an
/// explicit release retains the registry record (fail-closed) and only logs.
#[derive(Debug)]
pub struct VmLease {
    registry_path: PathBuf,
    lease_id: String,
    kind: VmKind,
    permit: Option<OwnedSemaphorePermit>,
    released: bool,
}

impl VmLease {
    /// The lease's kind.
    #[must_use]
    pub fn kind(&self) -> VmKind {
        self.kind
    }

    /// The lease id.
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    /// Mark the lease `Running` in the registry (post-start, optional).
    pub fn mark_running(&self) {
        if let Err(e) = set_lease_state(&self.registry_path, &self.lease_id, LeaseState::Running) {
            tracing::debug!(lease = %self.lease_id, error = %e, "mark_running failed");
        }
    }

    /// Mark the lease `Stopping` in the registry (pre-stop, optional).
    pub fn mark_stopping(&self) {
        if let Err(e) = set_lease_state(&self.registry_path, &self.lease_id, LeaseState::Stopping) {
            tracing::debug!(lease = %self.lease_id, error = %e, "mark_stopping failed");
        }
    }

    /// Remove the registry record and release the in-process permit. Call only
    /// after the VM is confirmed stopped (or was never started).
    pub fn release_clean(mut self) {
        if let Err(e) = remove_lease(&self.registry_path, &self.lease_id) {
            tracing::warn!(
                lease = %self.lease_id,
                error = %e,
                "release_clean: failed to remove lease record"
            );
        }
        drop(self.permit.take()); // return the semaphore permit
        self.released = true;
    }

    /// Retain the lease as a suspected orphan: keep the registry record AND keep
    /// the in-process permit consumed (slot stays held until reboot). Use when a
    /// VM could not be confirmed stopped.
    pub fn retain_as_orphan(mut self) {
        tracing::error!(
            lease = %self.lease_id,
            kind = ?self.kind,
            "lease retained as suspected orphan (VM stop failed/unverified) — slot held until reboot"
        );
        // Forget the permit so the semaphore stays decremented for this process.
        std::mem::forget(self.permit.take());
        self.released = true; // prevent Drop's duplicate handling
    }
}

impl Drop for VmLease {
    fn drop(&mut self) {
        if !self.released {
            // Last-best-effort telemetry only — never the primary stop path.
            // Retain the registry record (fail-closed): an un-released lease means
            // the VM stop was not confirmed, so it must keep counting until the
            // owner dies and reboot clears it.
            tracing::warn!(
                lease = %self.lease_id,
                kind = ?self.kind,
                "VmLease dropped without release_clean/stop_then_release — \
                 retaining registry record as suspected orphan (fail-closed)"
            );
            // The permit drops here, freeing the in-process slot; the persisted
            // record remains so cross-process accounting stays conservative.
        }
    }
}

/// A `VZVirtualMachine` paired with its [`VmLease`], enforcing stop-before-release.
///
/// This is the **required** wrapper for the snapshot / warm-pool / user-claw /
/// restart paths that use the [`VZVirtualMachine`] wrapper (whose own `Drop`
/// releases but does not stop).
pub struct ManagedMacOSVm {
    vm: Arc<VZVirtualMachine>,
    lease: Option<VmLease>,
}

impl ManagedMacOSVm {
    /// Pair a VM with its lease.
    #[must_use]
    pub fn new(vm: Arc<VZVirtualMachine>, lease: VmLease) -> Self {
        Self {
            vm,
            lease: Some(lease),
        }
    }

    /// Borrow the underlying VM.
    #[must_use]
    pub fn vm(&self) -> &Arc<VZVirtualMachine> {
        &self.vm
    }

    /// Clone the `Arc` to the underlying VM.
    #[must_use]
    pub fn clone_vm(&self) -> Arc<VZVirtualMachine> {
        Arc::clone(&self.vm)
    }

    /// Mark the held lease `Running` after the VM has successfully started.
    pub fn mark_running(&self) {
        if let Some(l) = &self.lease {
            l.mark_running();
        }
    }

    /// Consume the wrapper, returning the VM and its still-held lease — for a
    /// long-lived VM that will be stored (e.g. a warm-pool entry) and stopped
    /// later via `VmEntry::stop_and_release`.
    ///
    /// # Panics
    ///
    /// Panics if the lease was already taken (e.g. after `stop_then_release`).
    #[must_use]
    pub fn into_parts(mut self) -> (Arc<VZVirtualMachine>, VmLease) {
        let lease = self
            .lease
            .take()
            .expect("ManagedMacOSVm::into_parts called after the lease was released");
        (Arc::clone(&self.vm), lease)
    }

    /// Stop the VM, then release the lease. On stop failure the lease is retained
    /// as a suspected orphan (Invariant I-2: never free capacity for a VM we
    /// could not confirm stopped).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`VZError`](crate::error::VZError) if the stop fails.
    pub async fn stop_then_release(mut self, graceful: bool) -> Result<(), crate::error::VZError> {
        let lease = self.lease.take();
        if let Some(l) = &lease {
            l.mark_stopping();
        }
        let result = self.vm.stop(graceful).await;
        match (result, lease) {
            (Ok(()), Some(l)) => {
                l.release_clean();
                Ok(())
            }
            (Ok(()), None) => Ok(()),
            (Err(e), Some(l)) => {
                tracing::error!(error = %e, "stop_then_release: VM stop failed — retaining lease");
                l.retain_as_orphan();
                Err(e)
            }
            (Err(e), None) => Err(e),
        }
    }
}

// ── pure registry logic (unit-testable) ───────────────────────────────────────

/// Reconcile leases against the current boot. Drops leases from **other** boots
/// (reboot cleared the VZ session). Same-boot leases are kept — including
/// dead-owner ones (suspected orphans). Clears `blocked_boot_id` if it belongs
/// to a previous boot. Returns `true` if the registry changed.
fn reconcile(reg: &mut Registry, boot_id: &str, _liveness: &Liveness) -> bool {
    let before = reg.leases.len();
    reg.leases.retain(|l| l.boot_id == boot_id);
    let leases_changed = reg.leases.len() != before;

    let block_changed = match &reg.blocked_boot_id {
        Some(b) if b != boot_id => {
            reg.blocked_boot_id = None;
            true
        }
        _ => false,
    };

    leases_changed || block_changed
}

/// Count `(live, suspected_orphans)` among same-boot leases.
fn count(reg: &Registry, boot_id: &str, liveness: &Liveness) -> (usize, usize) {
    let mut live = 0;
    let mut orphans = 0;
    for l in &reg.leases {
        if l.boot_id != boot_id {
            continue;
        }
        if liveness(l.owner_pid) {
            live += 1;
        } else {
            orphans += 1;
        }
    }
    (live, orphans)
}

fn snapshot(reg: &Registry, boot_id: &str, liveness: &Liveness) -> CapacitySnapshot {
    let (live, orphans) = count(reg, boot_id, liveness);
    let occupied = live + orphans;
    CapacitySnapshot {
        live,
        suspected_orphans: orphans,
        available: MACOS_VM_LIMIT.saturating_sub(occupied),
        host_blocked: reg.blocked_boot_id.as_deref() == Some(boot_id),
    }
}

// ── registry persistence helpers (own their own lock) ──────────────────────────

fn set_lease_state(path: &Path, lease_id: &str, state: LeaseState) -> Result<(), AdmissionError> {
    let guard = FileGuard::lock_exclusive(path)?;
    let mut reg = guard.read_registry()?;
    let mut found = false;
    for l in &mut reg.leases {
        if l.lease_id == lease_id {
            l.state = state;
            found = true;
            break;
        }
    }
    if found {
        guard.write_registry(&reg)?;
    }
    Ok(())
}

fn remove_lease(path: &Path, lease_id: &str) -> Result<(), AdmissionError> {
    let guard = FileGuard::lock_exclusive(path)?;
    let mut reg = guard.read_registry()?;
    let before = reg.leases.len();
    reg.leases.retain(|l| l.lease_id != lease_id);
    if reg.leases.len() != before {
        guard.write_registry(&reg)?;
    }
    Ok(())
}

// ── file lock + (de)serialization ──────────────────────────────────────────────

/// RAII advisory exclusive lock on the registry file (`flock`).
///
/// The lock is held on a **stable sidecar** file (`<registry>.lock`), never on the
/// registry file itself — so the data file can be replaced via atomic temp+rename
/// without invalidating the lock (rename swaps the registry inode; the lock inode
/// is unaffected). The lock releases when the sidecar `File` is closed (on drop).
/// Never hold two `FileGuard`s for the same path in one thread — `flock(LOCK_EX)`
/// on a second open file description would self-deadlock.
struct FileGuard {
    data_path: PathBuf,
    /// Held open for the lifetime of the guard; closing it releases the flock.
    _lock: File,
}

impl FileGuard {
    fn lock_exclusive(data_path: &Path) -> Result<Self, AdmissionError> {
        if let Some(parent) = data_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AdmissionError::Registry(format!("create {}: {e}", parent.display()))
            })?;
        }
        let lock_path = data_path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| AdmissionError::Registry(format!("open {}: {e}", lock_path.display())))?;
        // SAFETY: flock on a valid fd; LOCK_EX blocks until the lock is granted.
        let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(AdmissionError::Registry(format!(
                "flock {}: {}",
                lock_path.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self {
            data_path: data_path.to_path_buf(),
            _lock: lock,
        })
    }

    fn read_registry(&self) -> Result<Registry, AdmissionError> {
        let s = match std::fs::read_to_string(&self.data_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Registry::default()),
            Err(e) => return Err(AdmissionError::Registry(format!("read: {e}"))),
        };
        if s.trim().is_empty() {
            return Ok(Registry::default());
        }
        match serde_json::from_str::<Registry>(&s) {
            Ok(reg) => Ok(reg),
            Err(e) => {
                // A corrupt registry must not be silently reset (that would drop real
                // leases / suspected orphans). Fail-closed: surface it.
                tracing::error!(error = %e, "vm lease registry is corrupt — refusing to proceed");
                Err(AdmissionError::Registry(format!("corrupt registry: {e}")))
            }
        }
    }

    /// Persist atomically: write a unique temp sibling, fsync, then rename over the
    /// registry path. The rename is atomic on the same filesystem, so a crash mid-write
    /// never leaves a partially-written registry.
    fn write_registry(&self, reg: &Registry) -> Result<(), AdmissionError> {
        let s = serde_json::to_string_pretty(reg)
            .map_err(|e| AdmissionError::Registry(format!("serialize: {e}")))?;
        let tmp_path = PathBuf::from(format!(
            "{}.tmp.{}",
            self.data_path.display(),
            current_pid()
        ));
        {
            let mut tmp = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| {
                    AdmissionError::Registry(format!("open tmp {}: {e}", tmp_path.display()))
                })?;
            tmp.write_all(s.as_bytes())
                .map_err(|e| AdmissionError::Registry(format!("write tmp: {e}")))?;
            tmp.sync_all()
                .map_err(|e| AdmissionError::Registry(format!("fsync tmp: {e}")))?;
        }
        std::fs::rename(&tmp_path, &self.data_path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            AdmissionError::Registry(format!("rename {}: {e}", self.data_path.display()))
        })?;
        Ok(())
    }
}

// ── environment / OS probes ────────────────────────────────────────────────────

fn current_pid() -> i32 {
    // SAFETY: getpid is always safe.
    unsafe { libc::getpid() }
}

fn pid_alive_real(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // kill(pid, 0): 0 => alive; EPERM => alive (exists, no permission); ESRCH => dead.
    // SAFETY: signal 0 performs error checking without sending a signal.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_lease_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// Boot identity is owned by `core_rs::boot_id::current_boot_id()` — the single
// source of truth shared with the guest-image status reader, so a
// `failure_boot_id` stamped there compares byte-for-byte with `blocked_boot_id`
// / per-lease `boot_id` here.

// ── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// Build an admission instance with an injected boot id and a fake liveness
    /// set, backed by a temp registry file.
    fn test_admission(dir: &Path, boot_id: &str, alive: HashSet<i32>) -> VmAdmission {
        let alive = Arc::new(Mutex::new(alive));
        let alive2 = Arc::clone(&alive);
        VmAdmission {
            slots: MacOSVmSlotManager::new(),
            registry_path: dir.join(REGISTRY_FILENAME),
            boot_id: boot_id.to_string(),
            liveness: Arc::new(move |pid| alive2.lock().unwrap().contains(&pid)),
        }
    }

    fn read_raw(dir: &Path) -> Registry {
        let s = std::fs::read_to_string(dir.join(REGISTRY_FILENAME)).unwrap_or_default();
        if s.trim().is_empty() {
            Registry::default()
        } else {
            serde_json::from_str(&s).unwrap()
        }
    }

    #[test]
    fn reserve_succeeds_until_limit_then_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let mut alive = HashSet::new();
        alive.insert(current_pid());
        let adm = test_admission(tmp.path(), "boot-A", alive);

        let l1 = adm.reserve(VmKind::Install, None).expect("first reserve");
        let l2 = adm.reserve(VmKind::WarmPool, None).expect("second reserve");

        // Third must be refused with CapacityFull (limit is 2), no VM started.
        let err = adm.reserve(VmKind::UserClaw, None).unwrap_err();
        match err {
            AdmissionError::HostVmLimitReached {
                live,
                suspected_orphans,
                reason,
            } => {
                assert_eq!(live, 2);
                assert_eq!(suspected_orphans, 0);
                assert_eq!(reason, LimitReason::CapacityFull);
            }
            AdmissionError::Registry(e) => panic!("expected HostVmLimitReached, got Registry({e})"),
        }

        // Releasing one frees a slot.
        l1.release_clean();
        let _l3 = adm
            .reserve(VmKind::UserClaw, None)
            .expect("reserve after release");
        drop(l2);
    }

    #[test]
    fn same_boot_dead_pid_is_suspected_orphan_and_counts() {
        let tmp = tempfile::tempdir().unwrap();
        // Seed a registry with two leases from a DEAD pid on the SAME boot.
        let dead_pid = 999_999; // not in alive set
        let reg = Registry {
            version: 1,
            blocked_boot_id: None,
            leases: vec![
                VmLeaseRecord {
                    lease_id: "a".into(),
                    owner_pid: dead_pid,
                    boot_id: "boot-A".into(),
                    kind: VmKind::Install,
                    instance_id: None,
                    started_at: 1,
                    state: LeaseState::Running,
                },
                VmLeaseRecord {
                    lease_id: "b".into(),
                    owner_pid: dead_pid,
                    boot_id: "boot-A".into(),
                    kind: VmKind::Snapshot,
                    instance_id: None,
                    started_at: 2,
                    state: LeaseState::Running,
                },
            ],
        };
        std::fs::write(
            tmp.path().join(REGISTRY_FILENAME),
            serde_json::to_string_pretty(&reg).unwrap(),
        )
        .unwrap();

        let mut alive = HashSet::new();
        alive.insert(current_pid()); // dead_pid is NOT alive
        let adm = test_admission(tmp.path(), "boot-A", alive);

        // Both dead-pid leases are suspected orphans on this boot → limit reached,
        // refuse WITHOUT removing them.
        let err = adm.reserve(VmKind::Install, None).unwrap_err();
        match err {
            AdmissionError::HostVmLimitReached {
                live,
                suspected_orphans,
                reason,
            } => {
                assert_eq!(live, 0);
                assert_eq!(suspected_orphans, 2);
                assert_eq!(reason, LimitReason::CapacityFull);
            }
            AdmissionError::Registry(e) => panic!("expected HostVmLimitReached, got Registry({e})"),
        }
        // Orphans must NOT be silently removed.
        assert_eq!(read_raw(tmp.path()).leases.len(), 2);
    }

    #[test]
    fn different_boot_leases_are_reclaimed() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = Registry {
            version: 1,
            blocked_boot_id: Some("boot-OLD".into()),
            leases: vec![VmLeaseRecord {
                lease_id: "old".into(),
                owner_pid: 12345,
                boot_id: "boot-OLD".into(),
                kind: VmKind::Install,
                instance_id: None,
                started_at: 1,
                state: LeaseState::Running,
            }],
        };
        std::fs::write(
            tmp.path().join(REGISTRY_FILENAME),
            serde_json::to_string_pretty(&reg).unwrap(),
        )
        .unwrap();

        let mut alive = HashSet::new();
        alive.insert(current_pid());
        let adm = test_admission(tmp.path(), "boot-NEW", alive);

        // New boot: old lease reconciled away, blocked flag cleared, reserve OK.
        let snap = adm.reconcile_now().unwrap();
        assert_eq!(snap.live, 0);
        assert_eq!(snap.suspected_orphans, 0);
        assert!(!snap.host_blocked);
        assert_eq!(read_raw(tmp.path()).leases.len(), 0);

        let _l = adm
            .reserve(VmKind::Install, None)
            .expect("reserve on new boot");
    }

    #[test]
    fn host_blocked_flag_refuses_without_capacity() {
        let tmp = tempfile::tempdir().unwrap();
        let mut alive = HashSet::new();
        alive.insert(current_pid());
        let adm = test_admission(tmp.path(), "boot-A", alive);

        // No leases yet, but the host was reactively flagged blocked.
        adm.mark_host_blocked().unwrap();

        let err = adm.reserve(VmKind::Install, None).unwrap_err();
        match err {
            AdmissionError::HostVmLimitReached { reason, live, .. } => {
                assert_eq!(reason, LimitReason::HostBlocked);
                assert_eq!(live, 0);
            }
            AdmissionError::Registry(e) => panic!("expected HostBlocked, got Registry({e})"),
        }

        // Clearing the flag re-enables reservations.
        adm.clear_host_blocked().unwrap();
        let _l = adm
            .reserve(VmKind::Install, None)
            .expect("reserve after clear");
    }

    #[test]
    fn dropped_lease_without_release_is_retained_failclosed() {
        let tmp = tempfile::tempdir().unwrap();
        let mut alive = HashSet::new();
        alive.insert(current_pid());
        let adm = test_admission(tmp.path(), "boot-A", alive);

        {
            let _l = adm.reserve(VmKind::Install, None).expect("reserve");
            // dropped here WITHOUT release_clean
        }
        // Record retained (fail-closed): the lease still counts.
        assert_eq!(read_raw(tmp.path()).leases.len(), 1);
    }

    #[test]
    fn corrupt_registry_is_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        // Write a non-JSON blob into the registry.
        std::fs::write(
            tmp.path().join(REGISTRY_FILENAME),
            b"{ this is not valid json ]]",
        )
        .unwrap();

        let mut alive = HashSet::new();
        alive.insert(current_pid());
        let adm = test_admission(tmp.path(), "boot-A", alive);

        // A corrupt registry must NOT be silently reset — reserve fails closed.
        let err = adm.reserve(VmKind::Install, None).unwrap_err();
        match err {
            AdmissionError::Registry(msg) => assert!(msg.contains("corrupt"), "unexpected: {msg}"),
            AdmissionError::HostVmLimitReached { .. } => {
                panic!("corrupt registry must not be treated as free capacity")
            }
        }
        // The corrupt file is left intact (not silently overwritten).
        let raw = std::fs::read_to_string(tmp.path().join(REGISTRY_FILENAME)).unwrap();
        assert!(raw.contains("not valid json"));
    }

    #[test]
    fn writes_are_atomic_via_rename() {
        // A successful reserve leaves a well-formed registry and no leftover temp file.
        let tmp = tempfile::tempdir().unwrap();
        let mut alive = HashSet::new();
        alive.insert(current_pid());
        let adm = test_admission(tmp.path(), "boot-A", alive);

        let lease = adm.reserve(VmKind::Install, None).expect("reserve");
        // Registry parses cleanly.
        let _ = read_raw(tmp.path());
        // No stray temp files remain in the directory.
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp file left behind: {leftovers:?}");
        lease.release_clean();
    }

    #[test]
    fn release_clean_removes_record() {
        let tmp = tempfile::tempdir().unwrap();
        let mut alive = HashSet::new();
        alive.insert(current_pid());
        let adm = test_admission(tmp.path(), "boot-A", alive);

        let l = adm.reserve(VmKind::Install, None).expect("reserve");
        assert_eq!(read_raw(tmp.path()).leases.len(), 1);
        l.release_clean();
        assert_eq!(read_raw(tmp.path()).leases.len(), 0);
    }

    #[test]
    fn mark_running_updates_record_state() {
        let tmp = tempfile::tempdir().unwrap();
        let mut alive = HashSet::new();
        alive.insert(current_pid());
        let adm = test_admission(tmp.path(), "boot-A", alive);

        let l = adm
            .reserve(VmKind::UserClaw, Some("inst-a".into()))
            .unwrap();
        assert_eq!(read_raw(tmp.path()).leases[0].state, LeaseState::Starting);
        l.mark_running();
        assert_eq!(read_raw(tmp.path()).leases[0].state, LeaseState::Running);
        l.release_clean();
    }

    // ── helpers for the pure-logic / persistence tests below ──────────────────

    fn liveness_from(alive: &[i32]) -> Liveness {
        let set: HashSet<i32> = alive.iter().copied().collect();
        Arc::new(move |pid| set.contains(&pid))
    }

    fn rec(lease_id: &str, owner_pid: i32, boot_id: &str) -> VmLeaseRecord {
        VmLeaseRecord {
            lease_id: lease_id.into(),
            owner_pid,
            boot_id: boot_id.into(),
            kind: VmKind::Install,
            instance_id: None,
            started_at: 1,
            state: LeaseState::Running,
        }
    }

    fn write_registry_file(dir: &Path, reg: &Registry) {
        std::fs::write(
            dir.join(REGISTRY_FILENAME),
            serde_json::to_string_pretty(reg).unwrap(),
        )
        .unwrap();
    }

    // ── FileGuard read/write I/O paths ────────────────────────────────────────

    #[test]
    fn file_guard_read_missing_registry_is_default() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REGISTRY_FILENAME);
        let guard = FileGuard::lock_exclusive(&path).expect("lock");
        let reg = guard.read_registry().expect("read missing");
        assert!(reg.leases.is_empty());
        assert!(reg.blocked_boot_id.is_none());
    }

    #[test]
    fn file_guard_read_empty_and_whitespace_are_default() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REGISTRY_FILENAME);
        for blob in ["", "   \n\t  "] {
            std::fs::write(&path, blob).unwrap();
            let guard = FileGuard::lock_exclusive(&path).expect("lock");
            let reg = guard.read_registry().expect("read blank");
            assert!(
                reg.leases.is_empty(),
                "blob {blob:?} should decode to default"
            );
        }
    }

    #[test]
    fn file_guard_read_invalid_json_is_corrupt_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REGISTRY_FILENAME);
        std::fs::write(&path, b"{ not json ]]").unwrap();
        let guard = FileGuard::lock_exclusive(&path).expect("lock");
        let err = guard.read_registry().unwrap_err();
        match err {
            AdmissionError::Registry(msg) => assert!(msg.contains("corrupt"), "got {msg}"),
            AdmissionError::HostVmLimitReached { .. } => {
                panic!("a corrupt registry must surface as a Registry error, not a limit error")
            }
        }
    }

    #[test]
    fn file_guard_write_then_read_roundtrips_under_one_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REGISTRY_FILENAME);
        let reg = Registry {
            version: 1,
            blocked_boot_id: Some("boot-A".into()),
            leases: vec![rec("a", 10, "boot-A"), rec("b", 11, "boot-A")],
        };
        let guard = FileGuard::lock_exclusive(&path).expect("lock");
        guard.write_registry(&reg).expect("write");
        let back = guard.read_registry().expect("read back");
        assert_eq!(back.blocked_boot_id.as_deref(), Some("boot-A"));
        let ids: Vec<_> = back.leases.iter().map(|l| l.lease_id.clone()).collect();
        assert_eq!(ids, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn file_guard_write_is_atomic_and_locks_a_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REGISTRY_FILENAME);
        {
            let guard = FileGuard::lock_exclusive(&path).expect("lock");
            guard.write_registry(&Registry::default()).expect("write");
        }
        // The advisory lock lives on a `.lock` sidecar, not the data file.
        assert!(
            path.with_extension("lock").exists(),
            "sidecar lock must exist"
        );
        // No leftover temp files from the atomic temp+rename.
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp left behind: {leftovers:?}");
    }

    // ── reconcile / count / snapshot pure helpers ─────────────────────────────

    #[test]
    fn reconcile_drops_other_boot_keeps_same_boot_and_reports_change() {
        let liveness = liveness_from(&[10]);
        let mut reg = Registry {
            version: 1,
            blocked_boot_id: None,
            leases: vec![rec("keep", 10, "boot-A"), rec("drop", 10, "boot-OLD")],
        };
        assert!(reconcile(&mut reg, "boot-A", &liveness));
        let ids: Vec<_> = reg.leases.iter().map(|l| l.lease_id.clone()).collect();
        assert_eq!(ids, vec!["keep".to_string()]);
        // Second pass: nothing left to change → not changed (idempotent).
        assert!(!reconcile(&mut reg, "boot-A", &liveness));
    }

    #[test]
    fn reconcile_clears_blocked_flag_from_other_boot_only() {
        let liveness = liveness_from(&[]);
        let mut reg = Registry {
            version: 1,
            blocked_boot_id: Some("boot-OLD".into()),
            leases: vec![],
        };
        assert!(reconcile(&mut reg, "boot-A", &liveness));
        assert!(reg.blocked_boot_id.is_none());
        // A current-boot block is preserved (no change).
        reg.blocked_boot_id = Some("boot-A".into());
        assert!(!reconcile(&mut reg, "boot-A", &liveness));
        assert_eq!(reg.blocked_boot_id.as_deref(), Some("boot-A"));
    }

    #[test]
    fn count_splits_live_and_orphans_ignoring_other_boots() {
        let liveness = liveness_from(&[10]); // pid 10 alive, 11 dead
        let reg = Registry {
            version: 1,
            blocked_boot_id: None,
            leases: vec![
                rec("live", 10, "boot-A"),
                rec("orphan", 11, "boot-A"),
                rec("elsewhere", 10, "boot-OLD"),
            ],
        };
        assert_eq!(count(&reg, "boot-A", &liveness), (1, 1));
    }

    #[test]
    fn snapshot_available_saturates_at_zero_when_overcapacity() {
        let liveness = liveness_from(&[10]);
        // One more live lease than the host limit allows.
        let leases = (0..=MACOS_VM_LIMIT)
            .map(|i| rec(&format!("l{i}"), 10, "boot-A"))
            .collect();
        let reg = Registry {
            version: 1,
            blocked_boot_id: None,
            leases,
        };
        let snap = snapshot(&reg, "boot-A", &liveness);
        assert_eq!(snap.live, MACOS_VM_LIMIT + 1);
        assert_eq!(
            snap.available, 0,
            "available must floor at 0, never underflow"
        );
        assert!(!snap.host_blocked);
    }

    #[test]
    fn snapshot_reports_host_blocked_only_for_current_boot() {
        let liveness = liveness_from(&[]);
        let mut reg = Registry {
            version: 1,
            blocked_boot_id: Some("boot-A".into()),
            leases: vec![],
        };
        assert!(snapshot(&reg, "boot-A", &liveness).host_blocked);
        reg.blocked_boot_id = Some("boot-OTHER".into());
        assert!(!snapshot(&reg, "boot-A", &liveness).host_blocked);
    }

    // ── set_lease_state / remove_lease persistence helpers ────────────────────

    #[test]
    fn set_lease_state_updates_known_and_noops_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REGISTRY_FILENAME);
        write_registry_file(
            tmp.path(),
            &Registry {
                version: 1,
                blocked_boot_id: None,
                leases: vec![rec("known", 10, "boot-A")],
            },
        );
        // Unknown id: Ok, no mutation.
        set_lease_state(&path, "nope", LeaseState::Stopping).expect("noop ok");
        assert_eq!(read_raw(tmp.path()).leases[0].state, LeaseState::Running);
        // Known id: state updated and persisted.
        set_lease_state(&path, "known", LeaseState::Stopping).expect("update ok");
        assert_eq!(read_raw(tmp.path()).leases[0].state, LeaseState::Stopping);
    }

    #[test]
    fn remove_lease_removes_known_and_noops_unknown() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(REGISTRY_FILENAME);
        write_registry_file(
            tmp.path(),
            &Registry {
                version: 1,
                blocked_boot_id: None,
                leases: vec![rec("a", 10, "boot-A"), rec("b", 11, "boot-A")],
            },
        );
        remove_lease(&path, "missing").expect("noop ok");
        assert_eq!(read_raw(tmp.path()).leases.len(), 2);
        remove_lease(&path, "a").expect("remove ok");
        let ids: Vec<_> = read_raw(tmp.path())
            .leases
            .iter()
            .map(|l| l.lease_id.clone())
            .collect();
        assert_eq!(ids, vec!["b".to_string()]);
    }

    // ── pid_alive_real errno edges ────────────────────────────────────────────

    #[test]
    fn pid_alive_real_handles_nonpositive_self_and_dead() {
        assert!(!pid_alive_real(0), "pid 0 is not a real process to probe");
        assert!(!pid_alive_real(-1), "negative pid is rejected");
        assert!(pid_alive_real(current_pid()), "this test process is alive");
        // launchd (pid 1) always exists; kill(1, 0) returns 0 (root) or EPERM
        // (non-root) — both map to alive.
        assert!(pid_alive_real(1), "pid 1 (launchd) must read as alive");
        // Above macOS PID_MAX (~99998), so reliably absent → ESRCH → dead.
        assert!(!pid_alive_real(999_999), "an impossible pid reads as dead");
    }
}
