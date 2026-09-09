//! `warm_pool.rs` — In-process warm pool of pre-restored Firecracker VMs.
//!
//! # Concept
//!
//! The biggest bottleneck in VM creation is `load_snapshot`, which takes ~13-15s
//! inside Firecracker regardless of I/O speed (it's CPU/device restore time).
//!
//! The warm pool pre-creates one VM per claw type ahead of time. When a user
//! requests a new instance, we claim a warm VM instead of restoring a new one:
//!
//! ```text
//! Normal path (no pool):  prepare_rootfs(2s) + start_vm(15s) + wait_ssh(2s) + install(1s) = ~20s
//! Warm pool claim:        rename(1ms) + add_hostfwd(100ms) + wait_ssh(1s) + install(1s)   = ~2s
//! ```
//!
//! # Pool VM lifecycle
//!
//! ```text
//! [empty] → fill_slot() → [warm: FC running, no hostfwds, SSH unreachable from host]
//!         → claim()     → [claimed: real container name, ports added, SSH reachable]
//!         → (refill)    → [warm] again
//! ```
//!
//! # Port strategy
//!
//! Pool VMs are started via `start_vm(pool_mode=true)`: Firecracker is running and
//! the VM is fully booted (or restored from snapshot), but no slirp port-forwards
//! are registered. At claim time we add the real SSH and app ports.
//!
//! # Naming convention
//!
//! Pool VMs live in `<state_dir>/_warm-<claw_type>-0/`. The `_` prefix and
//! `_warm-` substring ensure they are never confused with real customer instances
//! and are excluded from the instance listing queries.
//!
//! # Thread safety
//!
//! The pool is stored as a process-wide `OnceLock<Mutex<WarmPool>>`. The IPC
//! binary is single-threaded for dispatch, but the refill is spawned as a
//! background thread, so all accesses go through the mutex.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::instance_env::InstanceEnv;

// ── Types ──────────────────────────────────────────────────────────────────

/// A warm pool entry: a running VM ready to be claimed.
#[derive(Debug, Clone)]
pub struct WarmEntry {
    /// The warm container name, e.g. `_warm-picoclaw-0`
    pub container: String,
    /// Claw type, e.g. `picoclaw`
    pub claw_type: String,
    /// Instance state (PIDs, paths, etc.)
    pub inst: InstanceEnv,
    /// Whether the claw binary was confirmed present during fill (via SSH check).
    /// If true, the install step can be skipped at claim time without re-checking.
    pub binary_present: bool,
}

/// The warm pool: one slot per claw type.
#[derive(Debug, Default)]
pub struct WarmPool {
    /// `claw_type` → warm entry (None = slot is empty / being filled)
    pub(crate) slots: HashMap<String, Option<WarmEntry>>,
}

impl WarmPool {
    /// All supported claw types from the manifest (single source of truth).
    ///
    /// Returns only `Tier::Supported` claws — warm pool only preheats claws
    /// that have builtin plans and golden images. Detected/Available/Catalog
    /// tier claws are outside the warm pool domain.
    ///
    /// This is a backward-compat bridge. Callers should eventually pass the
    /// list via params instead of querying it here (D3 IPC change).
    #[must_use]
    pub fn all_claw_types() -> Vec<&'static str> {
        core_rs::manifest::supported_names()
    }

    /// Build the pool container name for a claw type and slot index.
    #[must_use]
    pub fn container_name(claw_type: &str, slot: usize) -> String {
        format!("_warm-{claw_type}-{slot}")
    }

    /// Check if a container name is a pool VM (used to filter from listings).
    #[must_use]
    pub fn is_pool_container(name: &str) -> bool {
        name.starts_with("_warm-")
    }

    /// Return the status string for a given claw type slot:
    /// `"empty"` (no slot), `"filling"` (slot reserved but no entry), or `"warm"`.
    #[must_use]
    pub fn slot_state(&self, claw_type: &str) -> &'static str {
        match self.slots.get(claw_type) {
            None => "empty",
            Some(None) => "filling",
            Some(Some(_)) => "warm",
        }
    }

    /// Return true if the slot for the given claw type is currently being filled
    /// (reserved but not yet warm).
    #[must_use]
    pub fn is_filling(&self, claw_type: &str) -> bool {
        matches!(self.slots.get(claw_type), Some(None))
    }

    /// Take a warm entry for the given claw type, if available.
    /// Returns `None` if the slot is empty or currently being filled.
    pub fn take(&mut self, claw_type: &str) -> Option<WarmEntry> {
        let entry = match self.slots.get_mut(claw_type) {
            Some(slot) => slot.take(),
            None => return None,
        };
        // Distinguish "empty" from "filling":
        // - empty slot      => remove key entirely (None in map)
        // - filling in prog => keep Some(None)
        if entry.is_some() {
            self.slots.remove(claw_type);
        }
        entry
    }

    /// Mark a slot as being refilled (None = in progress).
    /// Returns `true` if the slot was successfully marked as filling, or
    /// `false` if it was already filling.
    pub fn mark_filling(&mut self, claw_type: &str) -> bool {
        if let Some(None) = self.slots.get(claw_type) {
            // Already filling
            return false;
        }
        self.slots.insert(claw_type.to_string(), None);
        true
    }

    /// Clear the filling state if a refill operation fails, allowing future
    /// requests to attempt refilling again. Does nothing if not currently filling.
    pub fn unmark_filling(&mut self, claw_type: &str) {
        if let Some(None) = self.slots.get(claw_type) {
            self.slots.remove(claw_type);
        }
    }

    /// Store a newly-warm entry in the pool.
    pub fn store(&mut self, entry: WarmEntry) {
        self.slots.insert(entry.claw_type.clone(), Some(entry));
    }

    /// Is the slot for this claw type empty (None or not present)?
    #[must_use]
    pub fn slot_is_empty(&self, claw_type: &str) -> bool {
        match self.slots.get(claw_type) {
            None | Some(None) => true,
            Some(Some(_)) => false,
        }
    }

    /// Drain all slots from the pool, returning both warm entries and
    /// clearing filling reservations.
    ///
    /// Unlike `take()` which skips `Some(None)` (filling) slots, this method
    /// removes **all** entries — warm and filling — so the pool is completely
    /// empty afterward. Returns warm entries that need cleanup (processes + dirs).
    ///
    /// Filling slots (`Some(None)`) have no `WarmEntry` to return — the
    /// background task that was filling them should be cancelled separately
    /// (via the shutdown flag). The slot reservation is simply cleared here.
    pub fn drain_all(&mut self) -> Vec<WarmEntry> {
        let mut entries = Vec::new();
        // drain() empties the HashMap completely.
        for (_claw_type, slot) in self.slots.drain() {
            if let Some(entry) = slot {
                entries.push(entry);
            }
            // Some(None) = filling — just cleared, no entry to return.
        }
        entries
    }

    /// Verify the health of a `warm` slot by checking its Firecracker PID.
    ///
    /// Returns the actual slot state after health check:
    ///   - `"warm"` — PID alive, slot is healthy
    ///   - `"stale"` — PID dead or missing, slot was removed (caller should clean up)
    ///   - `"filling"` / `"empty"` — slot wasn't warm, returned as-is
    ///
    /// If the slot is `warm` but the FC PID is dead, the entry is removed from
    /// the pool and the stale `WarmEntry` is returned via `stale_out` so the
    /// caller can clean up processes/directories.
    pub fn health_check(
        &mut self,
        claw_type: &str,
        stale_out: &mut Option<WarmEntry>,
    ) -> &'static str {
        match self.slots.get(claw_type) {
            None => "empty",
            Some(None) => "filling",
            Some(Some(entry)) => {
                let alive = entry
                    .inst
                    .firecracker_pid
                    .is_some_and(core_rs::os::is_pid_running);
                if alive {
                    "warm"
                } else {
                    // FC is dead — remove the stale entry so it can be cleaned up.
                    *stale_out = self.slots.remove(claw_type).flatten();
                    "stale"
                }
            }
        }
    }
}

// ── Enabled flag ──────────────────────────────────────────────────────────

static ENABLED: OnceLock<bool> = OnceLock::new();

/// Read `THEYOS_WARM_POOL_SIZE` once at startup. Cached in `OnceLock`.
/// Returns `false` if value is `"0"` or `"disabled"`; `true` otherwise (including unset).
#[must_use]
pub fn warm_pool_enabled() -> bool {
    *ENABLED.get_or_init(|| {
        !matches!(
            std::env::var("THEYOS_WARM_POOL_SIZE").as_deref(),
            Ok("0" | "disabled")
        )
    })
}

// ── Global instance ────────────────────────────────────────────────────────

static POOL: OnceLock<Mutex<WarmPool>> = OnceLock::new();

/// Access the global warm pool (initializes on first call).
pub fn global_pool() -> &'static Mutex<WarmPool> {
    POOL.get_or_init(|| Mutex::new(WarmPool::default()))
}

// ── Shutdown flag ──────────────────────────────────────────────────────────

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Signal all in-flight pool fill tasks to abort.
///
/// Once set, `is_shutting_down()` returns `true` and `fill_pool_slot_impl`
/// bails out at the next checkpoint. The flag is reset by `clear_shutdown()`
/// after a drain + re-init cycle.
pub fn signal_shutdown() {
    SHUTDOWN.store(true, Ordering::Release);
}

/// Check whether a shutdown/drain has been requested.
#[must_use]
pub fn is_shutting_down() -> bool {
    SHUTDOWN.load(Ordering::Acquire)
}

/// Reset the shutdown flag (called after drain completes, before re-init).
pub fn clear_shutdown() {
    SHUTDOWN.store(false, Ordering::Release);
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
