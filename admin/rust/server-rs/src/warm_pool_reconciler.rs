//! `warm_pool_reconciler.rs` — Budget-aware warm pool refill loop.
//!
//! The reconciler is the **only** component that dispatches `WarmPoolRefill`
//! IPC calls. It replaces the old per-create `tokio::spawn` auto-refill in
//! `vmrunner-rs/src/lib.rs` and the startup `warm_pool_init` in `main.rs`.
//!
//! Loop: every `RECONCILE_INTERVAL` seconds, probe slot states + host
//! resources, decide which empty slots to fill within CPU/RAM budget,
//! then dispatch refills. Skips cycles while maintenance mode is active.

use core_rs::ipc::protocol::{LeaseKind, LeaseOwnerType};
use std::collections::HashMap;
use std::time::Duration;
use store_rs::WarmPoolSlotId;

use crate::capacity::{
    SLOT_CPU, SLOT_RAM, SlotState, compute_capacity_projection, warm_pool_slot_states,
};
use crate::state::SharedState;

/// Interval between reconciler ticks.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);

// ── warm_pool_enabled (local helper, duplicated from vmrunner-rs) ────────────

/// Check if the warm pool is enabled via `THEYOS_WARM_POOL_SIZE`.
/// Returns `false` if the value is `"0"` or `"disabled"`; `true` otherwise.
fn warm_pool_enabled() -> bool {
    if cfg!(target_os = "macos") && std::env::var("THEYOS_WARM_POOL_SIZE").is_err() {
        return false;
    }
    !matches!(
        std::env::var("THEYOS_WARM_POOL_SIZE").as_deref(),
        Ok("0" | "disabled")
    )
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Start the warm pool reconciler loop as a background tokio task.
///
/// Returns immediately. The task runs until the tokio runtime shuts down.
pub fn start_warm_pool_reconciler(state: SharedState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if !warm_pool_enabled() {
            tracing::info!("[warm-pool-reconciler] disabled via THEYOS_WARM_POOL_SIZE");
            return;
        }

        tracing::info!("[warm-pool-reconciler] started (interval={RECONCILE_INTERVAL:?})");

        loop {
            tokio::time::sleep(RECONCILE_INTERVAL).await;

            // Skip while maintenance mode is active.
            if core_rs::maintenance::creates_blocked(&state.locks_dir) {
                continue;
            }

            // Acquire capacity lock — serializes with create handlers.
            let _cap_guard = state.capacity_lock.lock().await;

            // Probe VM slot states (for knowing which need refill — not for capacity math).
            let slot_states = warm_pool_slot_states(&state);

            let installed_claws: Vec<String> = state
                .claw_store
                .catalog_with_status()
                .into_iter()
                .filter(|c| c.status == claw_rs::ClawStatus::Ready)
                .map(|c| c.name)
                .collect();

            release_orphaned_warm_pool_leases(&state, &installed_claws);

            // Get capacity projection from leases (includes warm pool in allocated total).
            let disk_path = core_rs::host_resources::resolve_instance_disk_path();
            let host = match core_rs::host_resources::detect_all(&disk_path) {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!("[warm-pool-reconciler] host detect failed: {e}");
                    continue;
                }
            };

            let projection = match compute_capacity_projection(&state.instance_db, &host) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("[warm-pool-reconciler] projection failed: {}", e.message);
                    continue;
                }
            };

            let input = RefillDecisionInput {
                slot_states: &slot_states,
                installed_claws: &installed_claws,
                projection_available_cpu: projection.available_cpu,
                projection_available_ram: projection.available_ram,
                per_slot_cost: (SLOT_CPU, SLOT_RAM),
                instance_db: &state.instance_db,
            };

            let targets = decide_refill_targets(&input);

            for ct in &targets {
                match state.executor.lock() {
                    Ok(exec) => {
                        // Create warm pool lease BEFORE dispatching the refill.
                        // This ensures capacity is reserved even if the refill takes time.
                        if let Err(e) = state.instance_db.create_lease(&store_rs::NewLease {
                            owner_type: LeaseOwnerType::WarmPool,
                            owner_id: &WarmPoolSlotId::new(ct).owner_id(),
                            lease_kind: LeaseKind::Runtime,
                            cpu_cores: SLOT_CPU,
                            ram_mb: SLOT_RAM,
                            disk_gb: 0,
                            expires_at: None,
                        }) {
                            tracing::warn!("[warm-pool-reconciler] create lease for {ct}: {e}");
                            continue;
                        }

                        match exec.warm_pool_refill(ct) {
                            Ok(v) => {
                                tracing::info!(
                                    "[warm-pool-reconciler] dispatched refill: {ct} → {v}"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "[warm-pool-reconciler] refill IPC failed for {ct}: {e}"
                                );
                                // Refill failed — release the lease we just created.
                                if let Err(e2) = state.instance_db.release_lease(
                                    LeaseOwnerType::WarmPool,
                                    &WarmPoolSlotId::new(ct).owner_id(),
                                    LeaseKind::Runtime,
                                ) {
                                    tracing::warn!(
                                        "[warm-pool-reconciler] release failed lease for {ct}: {e2}"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[warm-pool-reconciler] executor lock poisoned: {e}");
                        break;
                    }
                }
            }

            // capacity_lock guard dropped here (end of loop iteration).
        }
    })
}

// ── Orphaned lease cleanup ─────────────────────────────────────────────────

/// Release warm pool leases whose claw type is no longer installed.
///
/// Safety net — primary cleanup happens in `install_worker::run_uninstall_claw`.
fn release_orphaned_warm_pool_leases(state: &SharedState, installed_claws: &[String]) {
    let Ok(owners) = state.instance_db.active_warm_pool_lease_owners() else {
        return;
    };
    for owner_id in owners {
        if let Some(ct) = owner_id.split(':').next() {
            if !installed_claws.iter().any(|ic| ic == ct) {
                let _ = state.instance_db.release_lease(
                    LeaseOwnerType::WarmPool,
                    &owner_id,
                    LeaseKind::Runtime,
                );
                tracing::info!("[warm-pool-reconciler] released orphaned lease: {owner_id}");
            }
        }
    }
}

// ── Pure decision helper ────────────────────────────────────────────────────

/// Input for the refill decision helper.
pub struct RefillDecisionInput<'a> {
    pub slot_states: &'a HashMap<String, SlotState>,
    pub installed_claws: &'a [String],
    pub projection_available_cpu: i64,
    pub projection_available_ram: i64,
    /// `(cpu, ram)` cost per warm pool slot.
    pub per_slot_cost: (i64, i64),
    /// DB access to check existing warm pool leases.
    pub instance_db: &'a store_rs::InstanceDb,
}

/// Decide which claw types need a warm pool refill, respecting budget.
///
/// Returns a sorted list of claw types to refill. Deterministic (alphabetical).
#[must_use]
pub fn decide_refill_targets(input: &RefillDecisionInput<'_>) -> Vec<String> {
    // 1. Find candidates: installed claws whose slot is Empty AND has no active lease.
    let mut candidates: Vec<&String> = input
        .installed_claws
        .iter()
        .filter(|ct| {
            let state = input
                .slot_states
                .get(ct.as_str())
                .copied()
                .unwrap_or(SlotState::Empty);
            if state != SlotState::Empty {
                return false;
            }
            // Also check that no active warm pool lease exists (may be left from a
            // previous cycle if the slot was drained but lease wasn't released).
            !input
                .instance_db
                .has_active_lease(
                    LeaseOwnerType::WarmPool,
                    &WarmPoolSlotId::new(ct).owner_id(),
                    LeaseKind::Runtime,
                )
                .unwrap_or(true)
        })
        .collect();

    // 2. Sort for determinism.
    candidates.sort();

    // 3. Simulate sequential admission within remaining budget.
    let mut accepted = Vec::new();
    let mut remaining_cpu = input.projection_available_cpu;
    let mut remaining_ram = input.projection_available_ram;

    for ct in candidates {
        if remaining_cpu >= input.per_slot_cost.0 && remaining_ram >= input.per_slot_cost.1 {
            accepted.push(ct.clone());
            remaining_cpu -= input.per_slot_cost.0;
            remaining_ram -= input.per_slot_cost.1;
        }
    }

    accepted
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_slot_states(entries: &[(&str, SlotState)]) -> HashMap<String, SlotState> {
        entries.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn installed(names: &[&str]) -> Vec<String> {
        names.iter().copied().map(String::from).collect()
    }

    #[test]
    fn fills_empty_slots_within_budget() {
        let db = store_rs::InstanceDb::open(":memory:").unwrap();
        let slot_states = make_slot_states(&[
            ("picoclaw", SlotState::Empty),
            ("ironclaw", SlotState::Empty),
        ]);
        let input = RefillDecisionInput {
            slot_states: &slot_states,
            installed_claws: &installed(&["picoclaw", "ironclaw"]),
            projection_available_cpu: 6,
            projection_available_ram: 6144,
            per_slot_cost: (2, 2048),
            instance_db: &db,
        };
        let result = decide_refill_targets(&input);
        assert_eq!(result, vec!["ironclaw", "picoclaw"]);
    }

    #[test]
    fn stops_when_budget_exhausted() {
        let db = store_rs::InstanceDb::open(":memory:").unwrap();
        let slot_states = make_slot_states(&[("picoclaw", SlotState::Empty)]);
        let input = RefillDecisionInput {
            slot_states: &slot_states,
            installed_claws: &installed(&["picoclaw"]),
            projection_available_cpu: 0,
            projection_available_ram: 0,
            per_slot_cost: (2, 2048),
            instance_db: &db,
        };
        let result = decide_refill_targets(&input);
        assert!(result.is_empty(), "budget full — no refills: {result:?}");
    }

    #[test]
    fn skips_filling_slots() {
        let db = store_rs::InstanceDb::open(":memory:").unwrap();
        let slot_states = make_slot_states(&[
            ("picoclaw", SlotState::Filling),
            ("ironclaw", SlotState::Empty),
        ]);
        let input = RefillDecisionInput {
            slot_states: &slot_states,
            installed_claws: &installed(&["picoclaw", "ironclaw"]),
            projection_available_cpu: 4,
            projection_available_ram: 4096,
            per_slot_cost: (2, 2048),
            instance_db: &db,
        };
        let result = decide_refill_targets(&input);
        assert_eq!(result, vec!["ironclaw"]);
    }

    #[test]
    fn skips_warm_slots() {
        let db = store_rs::InstanceDb::open(":memory:").unwrap();
        let slot_states = make_slot_states(&[
            ("picoclaw", SlotState::Warm),
            ("ironclaw", SlotState::Empty),
        ]);
        let input = RefillDecisionInput {
            slot_states: &slot_states,
            installed_claws: &installed(&["picoclaw", "ironclaw"]),
            projection_available_cpu: 4,
            projection_available_ram: 4096,
            per_slot_cost: (2, 2048),
            instance_db: &db,
        };
        let result = decide_refill_targets(&input);
        assert_eq!(result, vec!["ironclaw"]);
    }

    #[test]
    fn skips_uninstalled_claws() {
        let db = store_rs::InstanceDb::open(":memory:").unwrap();
        let slot_states = make_slot_states(&[
            ("picoclaw", SlotState::Empty),
            ("ironclaw", SlotState::Empty),
        ]);
        let input = RefillDecisionInput {
            slot_states: &slot_states,
            installed_claws: &installed(&["picoclaw"]),
            projection_available_cpu: 6,
            projection_available_ram: 6144,
            per_slot_cost: (2, 2048),
            instance_db: &db,
        };
        let result = decide_refill_targets(&input);
        assert_eq!(result, vec!["picoclaw"]);
    }

    #[test]
    fn sequential_admission_stops_mid_list() {
        let db = store_rs::InstanceDb::open(":memory:").unwrap();
        let slot_states = make_slot_states(&[
            ("picoclaw", SlotState::Empty),
            ("ironclaw", SlotState::Empty),
            ("zeroclaw", SlotState::Empty),
        ]);
        // Budget fits 2 slots (4 CPU / 4096 MB), not 3.
        let input = RefillDecisionInput {
            slot_states: &slot_states,
            installed_claws: &installed(&["picoclaw", "ironclaw", "zeroclaw"]),
            projection_available_cpu: 4,
            projection_available_ram: 4096,
            per_slot_cost: (2, 2048),
            instance_db: &db,
        };
        let result = decide_refill_targets(&input);
        assert_eq!(
            result,
            vec!["ironclaw", "picoclaw"],
            "should accept first 2 alphabetically, reject zeroclaw"
        );
    }

    #[test]
    fn skips_slot_with_existing_lease() {
        let db = store_rs::InstanceDb::open(":memory:").unwrap();
        // picoclaw has an existing warm pool lease (e.g. from a previous fill)
        db.create_lease(&store_rs::NewLease {
            owner_type: LeaseOwnerType::WarmPool,
            owner_id: "picoclaw:slot:0",
            lease_kind: LeaseKind::Runtime,
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        let slot_states = make_slot_states(&[
            ("picoclaw", SlotState::Empty), // VM empty but lease exists
            ("ironclaw", SlotState::Empty),
        ]);
        let input = RefillDecisionInput {
            slot_states: &slot_states,
            installed_claws: &installed(&["picoclaw", "ironclaw"]),
            projection_available_cpu: 4,
            projection_available_ram: 4096,
            per_slot_cost: (2, 2048),
            instance_db: &db,
        };
        let result = decide_refill_targets(&input);
        // picoclaw should be skipped because it already has a lease
        assert_eq!(result, vec!["ironclaw"]);
    }
}
