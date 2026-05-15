//! Admin handlers — warm pool operations, maintenance status, and resource metrics.
//!
//!   GET  /api/v1/admin/warm-pool-status   → `handle_warm_pool_status`
//!   POST /api/v1/admin/warm-pool-refill   → `handle_warm_pool_refill`
//!   POST /api/v1/admin/warm-pool-init     → `handle_warm_pool_init`
//!   POST /api/v1/admin/drain-warm-pool    → `handle_drain_warm_pool`
//!   GET  /api/v1/admin/maintenance        → `handle_maintenance_status`
//!   GET  /api/v1/admin/resources          → `handle_resources`

use crate::state::SharedState;
use axum::{Json, extract::State};
use core_rs::error::ApiError;
use serde_json::{Value, json};

// ─── Admin: warm-pool operations ──────────────────────────────────────────────
//
// All warm-pool endpoints proxy through the Executor's vmrunner IPC connection
// so they operate on the REAL warm pool (inside the vmrunner_ipc subprocess),
// not the server-rs process-local VmRunner instance (which has an empty pool).

/// `GET /api/v1/admin/warm-pool-status`
///
/// Returns the warm-pool slot state for all 6 claw types.
/// Each slot is `"empty"`, `"filling"`, or `"warm"`.
///
/// # Errors
///
/// Returns `ApiError` if the IPC call fails.
#[allow(clippy::unused_async)]
pub async fn handle_warm_pool_status(
    State(state): State<SharedState>,
) -> Result<Json<Value>, ApiError> {
    let exec = state
        .executor
        .lock()
        .map_err(|e| ApiError::internal(format!("executor lock poisoned: {e}")))?;
    let status = exec
        .warm_pool_status()
        .map_err(|e| ApiError::internal(format!("warm_pool_status failed: {e}")))?;
    Ok(Json(status))
}

/// `POST /api/v1/admin/warm-pool-refill`
///
/// Trigger a refill for a single claw type.  Body: `{"claw_type": "picoclaw"}`.
/// Returns immediately; the fill runs asynchronously.
///
/// # Errors
///
/// Returns `ApiError` if the IPC call fails or `claw_type` is missing.
#[allow(clippy::unused_async)]
pub async fn handle_warm_pool_refill(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    // Block warm pool refill during maintenance — pool VMs would be built from
    // potentially stale snapshots while artifacts are being reconciled.
    if core_rs::maintenance::creates_blocked(&state.locks_dir) {
        let status = core_rs::maintenance::read_status(&state.locks_dir);
        return Ok(Json(json!({
            "error": "warm pool refill blocked — maintenance in progress",
            "reason": status.reason,
            "retry_after_secs": status.retry_after_secs,
        })));
    }

    let claw_type = body["claw_type"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::bad_request("claw_type is required"))?;
    let exec = state
        .executor
        .lock()
        .map_err(|e| ApiError::internal(format!("executor lock poisoned: {e}")))?;
    let result = exec
        .warm_pool_refill(claw_type)
        .map_err(|e| ApiError::internal(format!("warm_pool_refill failed: {e}")))?;
    Ok(Json(result))
}

/// `POST /api/v1/admin/warm-pool-init`
///
/// Re-initialize the warm pool: marks all 6 slots as `filling` and spawns
/// background tasks to fill them (concurrency=2).  Returns immediately.
///
/// # Errors
///
/// Returns `ApiError` if the IPC call fails.
#[allow(clippy::unused_async)]
pub async fn handle_warm_pool_init(
    State(state): State<SharedState>,
) -> Result<Json<Value>, ApiError> {
    // Block warm pool init during maintenance — filling 6 pool slots from
    // potentially stale snapshots would waste resources and interfere with
    // the ongoing artifact reconciliation.
    if core_rs::maintenance::creates_blocked(&state.locks_dir) {
        let status = core_rs::maintenance::read_status(&state.locks_dir);
        return Ok(Json(json!({
            "error": "warm pool init blocked — maintenance in progress",
            "reason": status.reason,
            "retry_after_secs": status.retry_after_secs,
        })));
    }

    let exec = state
        .executor
        .lock()
        .map_err(|e| ApiError::internal(format!("executor lock poisoned: {e}")))?;
    let result = exec
        .warm_pool_init()
        .map_err(|e| ApiError::internal(format!("warm_pool_init failed: {e}")))?;
    Ok(Json(result))
}

// ── Maintenance mode ────────────────────────────────────────────────────────

/// `GET /api/v1/admin/maintenance`
///
/// Returns the current maintenance mode status.  Used by the frontend to
/// display a maintenance banner and by monitoring tools.
///
/// Response:
/// ```json
/// {
///   "maintenance": false,
///   "state": "off",
///   "reason": "",
///   "retry_after_secs": 0
/// }
/// ```
///
/// During active maintenance:
/// ```json
/// {
///   "maintenance": true,
///   "state": "active",
///   "reason": "artifact sync in progress",
///   "retry_after_secs": 60
/// }
/// ```
#[allow(clippy::unused_async)]
pub async fn handle_maintenance_status(State(state): State<SharedState>) -> Json<Value> {
    let status = core_rs::maintenance::read_status(&state.locks_dir);
    Json(json!({
        "maintenance": status.state != core_rs::maintenance::MaintenanceState::Off,
        "state": status.state.to_string(),
        "reason": status.reason,
        "started_at": status.started_at,
        "retry_after_secs": status.retry_after_secs,
    }))
}

/// `POST /api/v1/admin/drain-warm-pool`
///
/// Kills all pre-warmed VMs and clears their warm-pool slots.
/// Called by `soyeht deploy` before restarting the backend so that
/// warm-pool VMs don't survive as orphan processes.
///
/// # Errors
///
/// Returns `ApiError` if the IPC call fails.
#[allow(clippy::unused_async)]
pub async fn handle_drain_warm_pool(
    State(state): State<SharedState>,
) -> Result<Json<Value>, ApiError> {
    let exec = state
        .executor
        .lock()
        .map_err(|e| ApiError::internal(format!("executor lock poisoned: {e}")))?;
    let result = exec
        .warm_pool_drain()
        .map_err(|e| ApiError::internal(format!("warm_pool_drain failed: {e}")))?;
    Ok(Json(result))
}

// ── Resource metrics ────────────────────────────────────────────────────────

/// `GET /api/v1/admin/resources`
///
/// Returns host resources, current allocation, and budget via
/// `compute_capacity_projection()` — the single source of truth for capacity.
/// Admin-only — requires authentication.
///
/// # Errors
///
/// Returns [`ApiError`] if host resource detection or any database query fails.
#[allow(clippy::unused_async)]
pub async fn handle_resources(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let disk_path = core_rs::host_resources::resolve_instance_disk_path();
    let host = core_rs::host_resources::detect_all(&disk_path)
        .map_err(|e| ApiError::internal(format!("detect host resources: {e}")))?;

    let proj = crate::capacity::compute_capacity_projection(&state.instance_db, &host)
        .map_err(|e| ApiError::internal(e.message))?;

    let active_count = state
        .instance_db
        .count_active_instances()
        .map_err(|e| ApiError::internal(format!("count_active_instances: {e}")))?;

    Ok(Json(json!({
        "host": {
            "cpu_cores": proj.host_cpu,
            "total_ram_mb": proj.host_ram_mb,
            "available_ram_mb": host.available_ram_mb,
            "total_disk_gb": proj.host_disk_gb,
            "available_disk_gb": host.available_disk_gb,
        },
        "allocated": {
            "cpu_cores": proj.allocated_cpu,
            "ram_mb": proj.allocated_ram,
            "disk_gb": proj.allocated_disk,
            "instance_count": active_count,
        },
        "budget": {
            "cpu_cores": proj.cpu_budget,
            "ram_mb": proj.ram_budget,
            "cpu_reserve": crate::capacity::cpu_reserve(),
            "ram_budget_percent": crate::capacity::ram_budget_percent(),
        },
        "available": {
            "cpu_cores": proj.available_cpu,
            "ram_mb": proj.available_ram,
            "disk_gb": proj.available_disk,
        },
        "macos_slots": {
            "used": proj.macos_slots_used,
            "total": proj.macos_slots_total,
        },
    })))
}
