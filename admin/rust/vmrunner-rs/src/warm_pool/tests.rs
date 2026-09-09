#![cfg(test)]

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
