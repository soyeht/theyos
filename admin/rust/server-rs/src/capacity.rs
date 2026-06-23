//! Capacity guard: lease-based resource accounting.
//!
//! All capacity checks use `compute_capacity_projection()` which reads from
//! `resource_leases` instead of inferring allocation from `instances.status`.
//!
//! Called while holding `state.capacity_lock` to serialize concurrent creates.
//! Host detection I/O must happen BEFORE acquiring the lock.

use core_rs::host_resources::HostResources;
use core_rs::ipc::protocol::{LeaseKind, LeaseOwnerType};
use store_rs::InstanceDb;
use vmrunner_common_rs::{DEFAULT_CREATE_CPU_CORES, DEFAULT_CREATE_RAM_MB, WarmPoolStatusWire};

use crate::state::SharedState;

// ── Constants ────────────────────────────────────────────────────────────────

/// Warm-pool slot size.
///
/// A warm slot is prefilled with the default Create CPU/RAM shape, so capacity
/// matching aliases the shared vmrunner Create defaults instead of owning local
/// resource literals. Disk is handled separately by storage leases.
pub const SLOT_CPU: i64 = DEFAULT_CREATE_CPU_CORES as i64;
pub const SLOT_RAM: i64 = DEFAULT_CREATE_RAM_MB as i64;

/// Disk margin in GB — always keep this much free (default: 5 GB).
const DISK_MARGIN_GB: u64 = 5;

/// Apple license limit: max 2 concurrent macOS VMs per host.
#[cfg(target_os = "macos")]
const MACOS_SLOTS_TOTAL: i64 = 2;

// ── Public types ─────────────────────────────────────────────────────────────

/// Error returned by [`check_capacity`] with retry metadata.
#[derive(Debug)]
pub struct CapacityError {
    pub message: String,
    pub retry_after_secs: u32,
}

/// Unified capacity projection — single source of truth for all endpoints.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapacityProjection {
    // Host
    pub host_cpu: u32,
    pub host_ram_mb: u64,
    pub host_disk_gb: u64,
    // Budget
    pub cpu_budget: i64,
    pub ram_budget: i64,
    // Allocated (from leases — includes instances + warm pool)
    pub allocated_cpu: i64,
    pub allocated_ram: i64,
    pub allocated_disk: i64,
    // Available
    pub available_cpu: i64,
    pub available_ram: i64,
    pub available_disk: i64,
    // macOS slots (Apple 2-VM limit)
    pub macos_slots_used: i64,
    pub macos_slots_total: i64,
}

/// Slot state for a single claw type (used by the reconciler).
pub use vmrunner_common_rs::WarmPoolSlotState as SlotState;

/// Request parameters for a capacity check.
pub struct CapacityRequest<'a> {
    pub cpu_cores: u32,
    pub ram_mb: u32,
    pub disk_gb: u32,
    pub guest_os: &'a str,
    /// `None` = legacy call sites treat as cold (delta = full request).
    pub claw_type: Option<&'a str>,
}

#[must_use]
pub fn request_matches_warm_pool_lease(
    db: &InstanceDb,
    claw_type: Option<&str>,
    cpu_cores: u32,
    ram_mb: u32,
) -> bool {
    claw_type.is_some_and(|ct| {
        i64::from(cpu_cores) == SLOT_CPU
            && i64::from(ram_mb) == SLOT_RAM
            && db
                .has_active_lease(
                    LeaseOwnerType::WarmPool.as_str(),
                    &format!("{ct}:slot:0"),
                    LeaseKind::Runtime.as_str(),
                )
                .unwrap_or(false)
    })
}

// ── Env helpers ──────────────────────────────────────────────────────────────

/// Read CPU reserve from `THEYOS_CPU_RESERVE` env var (default: 1 core for host OS).
#[must_use]
pub fn cpu_reserve() -> u32 {
    std::env::var("THEYOS_CPU_RESERVE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

/// Read RAM budget percentage from `THEYOS_RAM_BUDGET_PERCENT` env var (default: 80%).
#[must_use]
pub fn ram_budget_percent() -> u64 {
    std::env::var("THEYOS_RAM_BUDGET_PERCENT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80)
}

// ── Warm pool slot probes (for reconciler — VM state, not capacity) ─────────

/// Query the warm pool and return per-claw slot states (used by the reconciler).
///
/// This probes the vmrunner IPC for actual VM state (Empty/Filling/Warm).
/// It is NOT used for capacity math — leases handle that.
pub fn warm_pool_slot_states(state: &SharedState) -> std::collections::HashMap<String, SlotState> {
    let status = state
        .executor
        .lock()
        .ok()
        .and_then(|exec| exec.warm_pool_status().ok())
        .unwrap_or_default();
    parse_warm_pool_json(&status)
}

/// Parse the JSON returned by `warm_pool_status()` into per-claw slot states.
fn parse_warm_pool_json(
    status: &serde_json::Value,
) -> std::collections::HashMap<String, SlotState> {
    serde_json::from_value::<WarmPoolStatusWire>(status.clone())
        .map(WarmPoolStatusWire::into_slot_states)
        .unwrap_or_default()
        .into_iter()
        .map(|(claw_type, state)| (claw_type, capacity_slot_state(state)))
        .collect()
}

const fn capacity_slot_state(state: SlotState) -> SlotState {
    match state {
        SlotState::Stale | SlotState::Expired => SlotState::Empty,
        state => state,
    }
}

// ── Capacity projection ─────────────────────────────────────────────────────

/// Compute the unified capacity projection from resource leases.
///
/// This is the **single source of truth** for capacity. All endpoints
/// (`/admin/resources`, `/resource-options`, `check_capacity`) use this.
///
/// # Errors
///
/// Returns [`CapacityError`] if database queries fail.
pub fn compute_capacity_projection(
    db: &InstanceDb,
    host: &HostResources,
) -> Result<CapacityProjection, CapacityError> {
    let reserve = cpu_reserve();
    let pct = ram_budget_percent();

    let cpu_budget = i64::from(host.cpu_cores.saturating_sub(reserve));
    #[allow(clippy::cast_possible_wrap)]
    let ram_budget = ((host.total_ram_mb * pct) / 100) as i64;

    let (alloc_cpu, alloc_ram) = db.sum_active_runtime_leases().map_err(|e| CapacityError {
        message: format!("failed to query runtime leases: {e}"),
        retry_after_secs: 5,
    })?;

    let alloc_disk = db.sum_active_storage_leases().map_err(|e| CapacityError {
        message: format!("failed to query storage leases: {e}"),
        retry_after_secs: 5,
    })?;

    let available_cpu = (cpu_budget - alloc_cpu).max(0);
    let available_ram = (ram_budget - alloc_ram).max(0);
    #[allow(clippy::cast_possible_wrap)]
    let available_disk =
        (host.available_disk_gb as i64 - alloc_disk - DISK_MARGIN_GB as i64).max(0);

    // macOS slot tracking
    #[cfg(target_os = "macos")]
    let (macos_slots_used, macos_slots_total) = {
        let used = db
            .count_active_runtime_leases_by_guest_os("macos")
            .unwrap_or(0);
        (used, MACOS_SLOTS_TOTAL)
    };
    #[cfg(not(target_os = "macos"))]
    let (macos_slots_used, macos_slots_total) = (0i64, 0i64);

    Ok(CapacityProjection {
        host_cpu: host.cpu_cores,
        host_ram_mb: host.total_ram_mb,
        host_disk_gb: host.total_disk_gb,
        cpu_budget,
        ram_budget,
        allocated_cpu: alloc_cpu,
        allocated_ram: alloc_ram,
        allocated_disk: alloc_disk,
        available_cpu,
        available_ram,
        available_disk,
        macos_slots_used,
        macos_slots_total,
    })
}

/// Capture the current capacity projection as a JSON string for audit events.
///
/// # Errors
///
/// Returns [`CapacityError`] if host detection, projection, or JSON
/// serialization fails.
pub fn capacity_snapshot_json(db: &InstanceDb) -> Result<String, CapacityError> {
    let disk_path = core_rs::host_resources::resolve_instance_disk_path();
    let host = core_rs::host_resources::detect_all(&disk_path).map_err(|e| CapacityError {
        message: format!("failed to detect host resources: {e}"),
        retry_after_secs: 5,
    })?;
    let projection = compute_capacity_projection(db, &host)?;
    serde_json::to_string(&projection).map_err(|e| CapacityError {
        message: format!("failed to serialize capacity projection: {e}"),
        retry_after_secs: 5,
    })
}

#[must_use]
pub fn project_after_request(
    projection: &CapacityProjection,
    req: &CapacityRequest<'_>,
    warm_match: bool,
) -> CapacityProjection {
    let mut projected = projection.clone();
    let cpu_delta = if warm_match {
        0
    } else {
        i64::from(req.cpu_cores)
    };
    let ram_delta = if warm_match { 0 } else { i64::from(req.ram_mb) };
    let disk_delta = i64::from(req.disk_gb);
    projected.allocated_cpu += cpu_delta;
    projected.allocated_ram += ram_delta;
    projected.allocated_disk += disk_delta;
    projected.available_cpu = (projected.available_cpu - cpu_delta).max(0);
    projected.available_ram = (projected.available_ram - ram_delta).max(0);
    projected.available_disk = (projected.available_disk - disk_delta).max(0);
    #[cfg(target_os = "macos")]
    if req.guest_os == "macos" && !warm_match {
        projected.macos_slots_used += 1;
    }
    projected
}

// ── Capacity check ──────────────────────────────────────────────────────────

/// Check host capacity before instance creation.
///
/// `host` must be detected BEFORE acquiring the lock (I/O outside lock scope).
/// Called while holding `state.capacity_lock`.
///
/// When `req.claw_type` matches a warm pool lease (same claw type AND request
/// asks for exactly slot size), the request is treated as a warm-pool claim:
/// delta=0 for the request (ownership transfer, not new allocation).
///
/// # Errors
///
/// Returns [`CapacityError`] if any resource limit is exceeded (CPU, RAM, disk,
/// or macOS slot limit).
pub fn check_capacity(
    state: &SharedState,
    host: &HostResources,
    req: &CapacityRequest<'_>,
) -> Result<CapacityProjection, CapacityError> {
    let projection = compute_capacity_projection(&state.instance_db, host)?;

    // ── Warm match detection ────────────────────────────────────────────
    // If the request matches a warm slot (same claw type, same slot size),
    // delta=0 because the warm pool lease will be transferred, not added.
    let warm_match = request_matches_warm_pool_lease(
        &state.instance_db,
        req.claw_type,
        req.cpu_cores,
        req.ram_mb,
    );

    let request_cpu_delta = if warm_match {
        0
    } else {
        i64::from(req.cpu_cores)
    };
    let request_ram_delta = if warm_match { 0 } else { i64::from(req.ram_mb) };

    // ── CPU check ───────────────────────────────────────────────────────
    if projection.allocated_cpu + request_cpu_delta > projection.cpu_budget {
        return Err(CapacityError {
            message: format!(
                "insufficient CPU: requesting {} cores, \
                 but only {} of {} available (allocated: {})",
                req.cpu_cores,
                projection.available_cpu,
                projection.cpu_budget,
                projection.allocated_cpu,
            ),
            retry_after_secs: 30,
        });
    }

    // ── RAM check ───────────────────────────────────────────────────────
    if projection.allocated_ram + request_ram_delta > projection.ram_budget {
        return Err(CapacityError {
            message: format!(
                "insufficient RAM: requesting {} MB, \
                 but only {} MB of {} MB budget available (allocated: {} MB)",
                req.ram_mb,
                projection.available_ram,
                projection.ram_budget,
                projection.allocated_ram,
            ),
            retry_after_secs: 30,
        });
    }

    // ── Disk check ──────────────────────────────────────────────────────
    if i64::from(req.disk_gb) > projection.available_disk {
        return Err(CapacityError {
            message: format!(
                "insufficient disk: requesting {} GB, \
                 but only {} GB available after reserved storage and {} GB margin",
                req.disk_gb, projection.available_disk, DISK_MARGIN_GB
            ),
            retry_after_secs: 60,
        });
    }

    // ── macOS VM slot check ─────────────────────────────────────────────
    #[cfg(target_os = "macos")]
    let macos_slot_delta = i64::from(!warm_match);
    #[cfg(target_os = "macos")]
    if req.guest_os == "macos"
        && projection.macos_slots_used + macos_slot_delta > projection.macos_slots_total
    {
        return Err(CapacityError {
            message: format!(
                "macOS VM slot limit reached ({}/{} slots used)",
                projection.macos_slots_used, projection.macos_slots_total
            ),
            retry_after_secs: 60,
        });
    }

    #[cfg(not(target_os = "macos"))]
    let _ = req.guest_os; // suppress unused warning on Linux

    Ok(projection)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_host(cpu: u32, ram_mb: u64, disk_gb: u64) -> HostResources {
        HostResources {
            cpu_cores: cpu,
            total_ram_mb: ram_mb,
            available_ram_mb: ram_mb / 2,
            available_disk_gb: disk_gb,
            total_disk_gb: disk_gb * 2,
        }
    }

    #[test]
    fn migrated_create_default_sites_use_common_owner() {
        let migrated_sources = [
            (
                "server-rs/src/handlers_instances.rs",
                include_str!("handlers_instances.rs"),
                &["unwrap_or(2)", "unwrap_or(2048)", "unwrap_or(10)"][..],
            ),
            (
                "server-rs/src/handlers_mobile.rs",
                include_str!("handlers_mobile.rs"),
                &["unwrap_or(2)", "unwrap_or(2048)", "unwrap_or(10)"][..],
            ),
            (
                "server-rs/src/main.rs",
                include_str!("main.rs"),
                &["unwrap_or(2)", "unwrap_or(2048)"][..],
            ),
            (
                "vmrunner-rs/src/lib.rs",
                include_str!("../../vmrunner-rs/src/lib.rs"),
                &[
                    "prepare_rootfs(&inst, 10)",
                    "start_vm(&mut inst, false, true, 2, 2048)",
                    "start_vm(&mut inst, false, false, 2, 2048)",
                    "start_vm(&mut inst, true, false, 2, 2048)",
                ][..],
            ),
            (
                "vmrunner-macos-rs/src/bin/vmrunner_macos_ipc_macos.rs",
                include_str!("../../vmrunner-macos-rs/src/bin/vmrunner_macos_ipc_macos.rs"),
                &["parse_resource_params(params, 2, 2048)"][..],
            ),
        ];

        for (path, source, forbidden_patterns) in migrated_sources {
            for forbidden in forbidden_patterns {
                assert!(
                    !source.contains(forbidden),
                    "{path} reintroduced create-default literal fallback `{forbidden}`"
                );
            }
        }
    }

    #[test]
    fn projection_empty_db() {
        let db = InstanceDb::open(":memory:").unwrap();
        let host = make_host(8, 16384, 100);
        let proj = compute_capacity_projection(&db, &host).unwrap();

        // CPU budget: 8 - 1 (default reserve) = 7
        assert_eq!(proj.cpu_budget, 7);
        // RAM budget: 16384 * 80% = 13107
        assert_eq!(proj.ram_budget, 13107);
        assert_eq!(proj.allocated_cpu, 0);
        assert_eq!(proj.allocated_ram, 0);
        assert_eq!(proj.allocated_disk, 0);
        assert_eq!(proj.available_cpu, 7);
        assert_eq!(proj.available_ram, 13107);
    }

    #[test]
    fn projection_with_leases() {
        let db = InstanceDb::open(":memory:").unwrap();
        db.create_lease(&store_rs::NewLease {
            owner_type: "instance",
            owner_id: "inst-1",
            lease_kind: "runtime",
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        db.create_lease(&store_rs::NewLease {
            owner_type: "instance",
            owner_id: "inst-1",
            lease_kind: "storage",
            cpu_cores: 0,
            ram_mb: 0,
            disk_gb: 10,
            expires_at: None,
        })
        .unwrap();

        let host = make_host(8, 16384, 100);
        let proj = compute_capacity_projection(&db, &host).unwrap();

        assert_eq!(proj.allocated_cpu, 2);
        assert_eq!(proj.allocated_ram, 2048);
        assert_eq!(proj.allocated_disk, 10);
        assert_eq!(proj.available_cpu, 5); // 7 - 2
        assert_eq!(proj.available_ram, 11059); // 13107 - 2048
    }

    #[test]
    fn projection_includes_warm_pool() {
        let db = InstanceDb::open(":memory:").unwrap();
        // Instance lease
        db.create_lease(&store_rs::NewLease {
            owner_type: "instance",
            owner_id: "inst-1",
            lease_kind: "runtime",
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        // Warm pool lease
        db.create_lease(&store_rs::NewLease {
            owner_type: "warm_pool",
            owner_id: "picoclaw:slot:0",
            lease_kind: "runtime",
            cpu_cores: 2,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        let host = make_host(8, 16384, 100);
        let proj = compute_capacity_projection(&db, &host).unwrap();

        // Both included
        assert_eq!(proj.allocated_cpu, 4);
        assert_eq!(proj.allocated_ram, 4096);
        assert_eq!(proj.available_cpu, 3); // 7 - 4
    }

    #[test]
    fn projection_released_leases_excluded() {
        let db = InstanceDb::open(":memory:").unwrap();
        db.create_lease(&store_rs::NewLease {
            owner_type: "instance",
            owner_id: "inst-1",
            lease_kind: "runtime",
            cpu_cores: 4,
            ram_mb: 4096,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();
        db.release_lease("instance", "inst-1", "runtime").unwrap();

        let host = make_host(8, 16384, 100);
        let proj = compute_capacity_projection(&db, &host).unwrap();

        assert_eq!(proj.allocated_cpu, 0);
        assert_eq!(proj.available_cpu, 7);
    }

    #[test]
    fn projection_cpu_would_exceed() {
        let db = InstanceDb::open(":memory:").unwrap();
        // Allocate 6 cores (budget is 7 with default reserve=1 on 8-core host)
        db.create_lease(&store_rs::NewLease {
            owner_type: "instance",
            owner_id: "inst-1",
            lease_kind: "runtime",
            cpu_cores: 6,
            ram_mb: 2048,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        let host = make_host(8, 16384, 100);
        let proj = compute_capacity_projection(&db, &host).unwrap();

        // Only 1 CPU available, so a 4-CPU request would fail
        assert_eq!(proj.available_cpu, 1);
        assert!(proj.allocated_cpu + 4 > proj.cpu_budget);
    }

    #[test]
    fn projection_ram_would_exceed() {
        let db = InstanceDb::open(":memory:").unwrap();
        // RAM budget: 16384 * 80% = 13107. Allocate 12000.
        db.create_lease(&store_rs::NewLease {
            owner_type: "instance",
            owner_id: "inst-1",
            lease_kind: "runtime",
            cpu_cores: 1,
            ram_mb: 12000,
            disk_gb: 0,
            expires_at: None,
        })
        .unwrap();

        let host = make_host(8, 16384, 100);
        let proj = compute_capacity_projection(&db, &host).unwrap();

        // Only 1107 MB available, so a 4096 MB request would fail
        assert_eq!(proj.available_ram, 1107);
        assert!(proj.allocated_ram + 4096 > proj.ram_budget);
    }
}
