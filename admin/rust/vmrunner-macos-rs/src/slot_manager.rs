//! `MacOSVmSlotManager` — enforces Apple's 2-concurrent-macOS-VM license limit.
//!
//! Decision 6 from research.md: Apple's virtualization license permits at most
//! 2 simultaneous macOS guest VMs per host. Enforced via a `Semaphore(2)`.
//! The warm pool pre-acquires one permit on startup, leaving 1 slot for user VMs.
//!
//! The IPC VM-limit error code is owned by `core_rs::guest_image_failure`
//! and re-exported here as `MACOS_VM_LIMIT_REACHED` for compatibility.

use std::sync::{Arc, OnceLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit, TryAcquireError};

/// Maximum simultaneous macOS guest VMs allowed by Apple's virtualization license.
pub const MACOS_VM_LIMIT: usize = 2;

/// Error code returned when the macOS VM limit is reached.
pub use core_rs::guest_image_failure::IPC_CODE_MACOS_VM_LIMIT_REACHED as MACOS_VM_LIMIT_REACHED;

/// Manages the 2-VM concurrent macOS guest limit via a Tokio semaphore.
///
/// # Concurrency
///
/// `try_acquire` is atomic — no TOCTOU race between checking availability
/// and acquiring the permit.
#[derive(Clone)]
pub struct MacOSVmSlotManager {
    semaphore: Arc<Semaphore>,
}

impl MacOSVmSlotManager {
    /// Create a new manager with capacity `MACOS_VM_LIMIT` (2).
    #[must_use]
    pub fn new() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(MACOS_VM_LIMIT)),
        }
    }

    /// Return the process-wide singleton instance.
    ///
    /// The warm pool startup code calls `try_acquire()` once after obtaining the
    /// singleton, leaving 1 permit available for user VM creation.
    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<MacOSVmSlotManager> = OnceLock::new();
        INSTANCE.get_or_init(Self::new)
    }

    /// Attempt to acquire a slot without blocking.
    ///
    /// Returns `Ok(permit)` if a slot is available. The permit releases the slot
    /// automatically when dropped (RAII).
    ///
    /// Returns `Err(TryAcquireError::NoPermits)` when both slots are occupied
    /// (i.e., the Apple 2-VM limit is reached).
    ///
    /// # Errors
    ///
    /// Returns `TryAcquireError` if no permits are available or the semaphore
    /// is closed.
    pub fn try_acquire(&self) -> Result<SemaphorePermit<'_>, TryAcquireError> {
        self.semaphore.try_acquire()
    }

    /// Attempt to acquire an owned slot permit without blocking.
    ///
    /// Unlike [`try_acquire`], the returned `OwnedSemaphorePermit` has no
    /// lifetime tied to `&self`, so it can be stored in a `HashMap` alongside
    /// the VM it protects. The permit releases the slot when dropped (RAII).
    ///
    /// # Errors
    ///
    /// Returns `TryAcquireError` if no permits are available or the semaphore
    /// is closed.
    pub fn try_acquire_owned(&self) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        Arc::clone(&self.semaphore).try_acquire_owned()
    }

    /// Return the number of currently available VM slots (0, 1, or 2).
    #[must_use]
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }
}

impl Default for MacOSVmSlotManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_capacity_is_two() {
        let mgr = MacOSVmSlotManager::new();
        assert_eq!(mgr.available(), MACOS_VM_LIMIT);
    }

    #[test]
    fn test_two_acquires_succeed() {
        let mgr = MacOSVmSlotManager::new();
        let p1 = mgr.try_acquire();
        let p2 = mgr.try_acquire();
        assert!(p1.is_ok());
        assert!(p2.is_ok());
        assert_eq!(mgr.available(), 0);
    }

    #[test]
    fn test_third_acquire_fails() {
        let mgr = MacOSVmSlotManager::new();
        let _p1 = mgr.try_acquire().unwrap();
        let _p2 = mgr.try_acquire().unwrap();
        assert!(mgr.try_acquire().is_err());
    }

    #[test]
    fn test_drop_permit_restores_slot() {
        let mgr = MacOSVmSlotManager::new();
        {
            let _p = mgr.try_acquire().unwrap();
            assert_eq!(mgr.available(), 1);
        }
        assert_eq!(mgr.available(), MACOS_VM_LIMIT);
    }

    #[test]
    fn test_warm_pool_leaves_one_user_slot() {
        let mgr = MacOSVmSlotManager::new();
        // Warm pool pre-acquires one permit
        let _warm_pool_permit = mgr.try_acquire().unwrap();
        assert_eq!(mgr.available(), 1);
        // User can still create 1 VM
        let user_permit = mgr.try_acquire();
        assert!(user_permit.is_ok());
        // No more slots
        assert!(mgr.try_acquire().is_err());
    }

    #[test]
    fn test_limit_constant() {
        assert_eq!(MACOS_VM_LIMIT, 2);
        assert_eq!(
            MACOS_VM_LIMIT_REACHED,
            core_rs::guest_image_failure::IPC_CODE_MACOS_VM_LIMIT_REACHED
        );
    }

    #[test]
    fn test_owned_permit_stores_without_lifetime() {
        let mgr = MacOSVmSlotManager::new();
        let p1 = mgr.try_acquire_owned().unwrap();
        let p2 = mgr.try_acquire_owned().unwrap();
        assert_eq!(mgr.available(), 0);
        // Both permits can be stored in a HashMap-like collection (no lifetime)
        let permits: Vec<OwnedSemaphorePermit> = vec![p1, p2];
        assert_eq!(permits.len(), 2);
        // Dropping the vec releases both permits
        drop(permits);
        assert_eq!(mgr.available(), MACOS_VM_LIMIT);
    }

    #[test]
    fn test_concurrent_simultaneous_limit() {
        // Exhaust both slots in the main thread, then verify concurrent contenders all fail.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mgr = Arc::new(MacOSVmSlotManager::new());
        // Pre-acquire both slots
        let _p1 = mgr.try_acquire().unwrap();
        let _p2 = mgr.try_acquire().unwrap();
        assert_eq!(mgr.available(), 0);

        let failures = Arc::new(AtomicUsize::new(0));

        let threads: Vec<_> = (0..8)
            .map(|_| {
                let mgr = Arc::clone(&mgr);
                let failures = Arc::clone(&failures);
                std::thread::spawn(move || {
                    if mgr.try_acquire().is_err() {
                        failures.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }

        // All 8 contenders must have failed — both slots were held throughout
        assert_eq!(
            failures.load(Ordering::SeqCst),
            8,
            "all concurrent acquires must fail when both slots are held"
        );
    }
}
