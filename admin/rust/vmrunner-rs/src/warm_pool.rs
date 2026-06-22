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
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Builds a dummy `WarmEntry` with no real VM behind it.
    fn dummy_entry(claw_type: &str) -> WarmEntry {
        let container = WarmPool::container_name(claw_type, 0);
        WarmEntry {
            container: container.clone(),
            claw_type: claw_type.to_string(),
            inst: crate::instance_env::InstanceEnv {
                container: container.clone(),
                customer: container.clone(),
                claw_type: claw_type.to_string(),
                host_port: 0,
                ssh_port: core_rs::guest_net::SSH_HOST_PORT_RANGE_START,
                firecracker_pid: Some(99999),
                slirp_pid: Some(99998),
                instance_dir: PathBuf::from("/tmp/fake"),
                rootfs_path: PathBuf::from("/tmp/fake/rootfs.ext4"),
                firecracker_sock: PathBuf::from("/tmp/fake/firecracker.sock"),
                slirp_api_sock: PathBuf::from("/tmp/fake/slirp-api.sock"),
                serial_log: PathBuf::from("/tmp/fake/serial.log"),
                slirp_log: PathBuf::from("/tmp/fake/slirp.log"),
                customer_dir: String::new(),
            },
            binary_present: true,
        }
    }

    // ── take / store ───────────────────────────────────────────────────────

    #[test]
    fn take_returns_none_on_empty_pool() {
        let mut pool = WarmPool::default();
        assert!(pool.take("picoclaw").is_none());
    }

    #[test]
    fn store_then_take_roundtrip() {
        let mut pool = WarmPool::default();
        pool.store(dummy_entry("picoclaw"));

        let taken = pool.take("picoclaw").expect("should return stored entry");
        assert_eq!(taken.claw_type, "picoclaw");
        assert_eq!(taken.container, "_warm-picoclaw-0");
        assert_eq!(
            taken.inst.ssh_port,
            core_rs::guest_net::SSH_HOST_PORT_RANGE_START
        );
    }

    #[test]
    fn take_drains_slot() {
        // Second take on the same slot must return None (slot is empty after first take).
        let mut pool = WarmPool::default();
        pool.store(dummy_entry("picoclaw"));

        assert!(pool.take("picoclaw").is_some());
        assert!(
            pool.take("picoclaw").is_none(),
            "second take should return None"
        );
    }

    // ── mark_filling ───────────────────────────────────────────────────────

    #[test]
    fn mark_filling_makes_slot_empty() {
        let mut pool = WarmPool::default();
        let was_empty = pool.mark_filling("zeroclaw");
        assert!(was_empty);
        assert!(pool.slot_is_empty("zeroclaw"));

        let was_empty_second = pool.mark_filling("zeroclaw");
        assert!(!was_empty_second);
    }

    #[test]
    fn mark_filling_blocks_take() {
        let mut pool = WarmPool::default();
        assert!(pool.mark_filling("zeroclaw"));
        assert!(
            pool.take("zeroclaw").is_none(),
            "take on a filling slot must return None"
        );
    }

    #[test]
    fn store_after_mark_filling_works() {
        let mut pool = WarmPool::default();
        assert!(pool.mark_filling("nanobot"));
        assert!(pool.slot_is_empty("nanobot"));

        pool.store(dummy_entry("nanobot"));
        assert!(!pool.slot_is_empty("nanobot"));

        let taken = pool.take("nanobot").expect("should be warm after store");
        assert_eq!(taken.claw_type, "nanobot");
    }

    // ── container_name / is_pool_container ────────────────────────────────

    #[test]
    fn container_name_format() {
        assert_eq!(WarmPool::container_name("picoclaw", 0), "_warm-picoclaw-0");
        assert_eq!(WarmPool::container_name("zeroclaw", 1), "_warm-zeroclaw-1");
        assert_eq!(WarmPool::container_name("nanobot", 42), "_warm-nanobot-42");
    }

    #[test]
    fn is_pool_container_detects_warm_names() {
        assert!(WarmPool::is_pool_container("_warm-picoclaw-0"));
        assert!(WarmPool::is_pool_container("_warm-zeroclaw-1"));
        assert!(WarmPool::is_pool_container("_warm-anything"));

        assert!(!WarmPool::is_pool_container("picoclaw-myinst"));
        assert!(!WarmPool::is_pool_container("warm-picoclaw-0")); // missing underscore prefix
        assert!(!WarmPool::is_pool_container(""));
    }

    // ── all_claw_types ─────────────────────────────────────────────────────

    #[test]
    fn all_claw_types_has_eight() {
        let types = WarmPool::all_claw_types();
        assert_eq!(types.len(), 8, "expected exactly 8 claw types");
        for ct in &[
            "picoclaw",
            "zeroclaw",
            "nanobot",
            "openclaw",
            "nullclaw",
            "ironclaw",
            "hermes-agent",
            "noclaw",
        ] {
            assert!(types.contains(ct), "missing claw type: {ct}");
        }
    }

    // ── binary_present ─────────────────────────────────────────────────────

    #[test]
    fn binary_present_preserved_through_store_take() {
        let mut pool = WarmPool::default();

        let mut entry = dummy_entry("picoclaw");
        entry.binary_present = true;
        pool.store(entry);
        assert!(pool.take("picoclaw").unwrap().binary_present);

        let mut entry = dummy_entry("picoclaw");
        entry.binary_present = false;
        pool.store(entry);
        assert!(!pool.take("picoclaw").unwrap().binary_present);
    }

    // ── shutdown flag ───────────────────────────────────────────────────────

    // NOTE: These tests use the process-wide SHUTDOWN AtomicBool.
    // They are safe with cargo test's default parallel execution because
    // each test does a deterministic set → assert → clear cycle.

    #[test]
    fn shutdown_flag_lifecycle() {
        use super::{clear_shutdown, is_shutting_down, signal_shutdown};

        // Initially clear (or cleared by a previous test).
        clear_shutdown();
        assert!(!is_shutting_down());

        signal_shutdown();
        assert!(is_shutting_down());

        clear_shutdown();
        assert!(!is_shutting_down());
    }

    // ── drain_all ───────────────────────────────────────────────────────────

    #[test]
    fn drain_all_empty_pool() {
        let mut pool = WarmPool::default();
        let entries = pool.drain_all();
        assert!(entries.is_empty());
    }

    #[test]
    fn drain_all_returns_warm_entries() {
        let mut pool = WarmPool::default();
        pool.store(dummy_entry("picoclaw"));
        pool.store(dummy_entry("zeroclaw"));

        let entries = pool.drain_all();
        assert_eq!(entries.len(), 2);
        // Pool should be completely empty.
        assert_eq!(pool.slot_state("picoclaw"), "empty");
        assert_eq!(pool.slot_state("zeroclaw"), "empty");
    }

    #[test]
    fn drain_all_clears_filling_slots() {
        let mut pool = WarmPool::default();
        pool.mark_filling("picoclaw");
        pool.store(dummy_entry("zeroclaw"));

        let entries = pool.drain_all();
        // Only zeroclaw has a WarmEntry; picoclaw was filling (None).
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].claw_type, "zeroclaw");
        // Both slots should be empty.
        assert_eq!(pool.slot_state("picoclaw"), "empty");
        assert_eq!(pool.slot_state("zeroclaw"), "empty");
    }

    #[test]
    fn drain_all_allows_refill_after() {
        let mut pool = WarmPool::default();
        pool.store(dummy_entry("picoclaw"));
        pool.drain_all();

        // Should be able to fill again.
        assert!(pool.mark_filling("picoclaw"));
        pool.store(dummy_entry("picoclaw"));
        assert_eq!(pool.slot_state("picoclaw"), "warm");
    }

    // ── health_check ────────────────────────────────────────────────────────

    #[test]
    fn health_check_empty_slot() {
        let mut pool = WarmPool::default();
        let mut stale = None;
        assert_eq!(pool.health_check("picoclaw", &mut stale), "empty");
        assert!(stale.is_none());
    }

    #[test]
    fn health_check_filling_slot() {
        let mut pool = WarmPool::default();
        pool.mark_filling("picoclaw");
        let mut stale = None;
        assert_eq!(pool.health_check("picoclaw", &mut stale), "filling");
        assert!(stale.is_none());
    }

    #[test]
    fn health_check_stale_slot_returns_stale_and_removes_entry() {
        // Use a bogus PID that is definitely not running.
        let mut pool = WarmPool::default();
        let mut entry = dummy_entry("picoclaw");
        entry.inst.firecracker_pid = Some(4_294_967); // non-existent PID
        pool.store(entry);

        let mut stale = None;
        assert_eq!(pool.health_check("picoclaw", &mut stale), "stale");
        assert!(stale.is_some(), "stale entry should be returned");
        assert_eq!(stale.as_ref().unwrap().claw_type, "picoclaw");
        // Slot should now be empty.
        assert_eq!(pool.slot_state("picoclaw"), "empty");
    }

    #[test]
    fn health_check_warm_slot_with_live_pid() {
        // Use current process PID — it's definitely alive.
        let mut pool = WarmPool::default();
        let mut entry = dummy_entry("picoclaw");
        entry.inst.firecracker_pid = Some(std::process::id());
        pool.store(entry);

        let mut stale = None;
        assert_eq!(pool.health_check("picoclaw", &mut stale), "warm");
        assert!(stale.is_none());
        // Slot should still be warm.
        assert_eq!(pool.slot_state("picoclaw"), "warm");
    }

    // ── Concurrency tests ─────────────────────────────────────────────────

    #[test]
    fn concurrent_take_only_one_wins() {
        // 10 threads race to take from the same pool slot.
        // Exactly 1 should get Some, the other 9 must get None.
        use std::sync::{Arc, Barrier, Mutex};

        let pool = Arc::new(Mutex::new(WarmPool::default()));
        pool.lock().unwrap().store(dummy_entry("picoclaw"));

        let barrier = Arc::new(Barrier::new(10));
        let winners = Arc::new(Mutex::new(0u32));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let pool = Arc::clone(&pool);
                let barrier = Arc::clone(&barrier);
                let winners = Arc::clone(&winners);
                std::thread::spawn(move || {
                    barrier.wait(); // All threads start at the same time
                    let got = pool.lock().unwrap().take("picoclaw");
                    if got.is_some() {
                        *winners.lock().unwrap() += 1;
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            *winners.lock().unwrap(),
            1,
            "exactly 1 thread should win the take"
        );
        // Pool should be empty now
        assert!(pool.lock().unwrap().take("picoclaw").is_none());
    }

    #[test]
    fn concurrent_mark_filling_only_one_wins() {
        // 10 threads race to mark_filling on the same claw type.
        // Exactly 1 should get true, the other 9 must get false.
        use std::sync::{Arc, Barrier, Mutex};

        let pool = Arc::new(Mutex::new(WarmPool::default()));
        let barrier = Arc::new(Barrier::new(10));
        let true_count = Arc::new(Mutex::new(0u32));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let pool = Arc::clone(&pool);
                let barrier = Arc::clone(&barrier);
                let true_count = Arc::clone(&true_count);
                std::thread::spawn(move || {
                    barrier.wait();
                    let got = pool.lock().unwrap().mark_filling("zeroclaw");
                    if got {
                        *true_count.lock().unwrap() += 1;
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            *true_count.lock().unwrap(),
            1,
            "exactly 1 thread should succeed at mark_filling"
        );
        assert!(
            pool.lock().unwrap().is_filling("zeroclaw"),
            "slot should be in filling state"
        );
    }
}
