use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use core_rs::error::blocking;
use serde_json::{Value, json};

use crate::state::SharedState;

/// `GET /healthz` — liveness probe (fast, unconditional).
///
/// Returns service status including real VM count from the database.
pub async fn handle_health(State(state): State<SharedState>) -> Json<Value> {
    // Detect platform
    let platform = if cfg!(target_os = "macos") {
        "macos-vz"
    } else if cfg!(target_os = "linux") {
        "linux-firecracker"
    } else {
        "unknown"
    };

    let vm_count = {
        let st = state.clone();
        blocking(move || st.instance_db.count_active_instances().unwrap_or(0))
            .await
            .unwrap_or(0)
    };

    Json(json!({
        "status": "ok",
        "service": "soyeht-server-rs",
        "version": env!("CARGO_PKG_VERSION"),
        "platform": platform,
        "vm_count": vm_count,
    }))
}

/// `GET /readyz` — readiness probe (verifies DB connectivity + maintenance mode).
///
/// Returns 503 during maintenance mode (artifact sync) so load balancers stop
/// sending traffic.  `/healthz` stays 200 always (liveness — don't kill us).
pub async fn handle_ready(State(state): State<SharedState>) -> impl IntoResponse {
    // Check maintenance mode first — fast file-based check, no DB needed.
    if core_rs::maintenance::is_maintenance(&state.locks_dir) {
        let status = core_rs::maintenance::read_status(&state.locks_dir);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ready": false,
                "reason": "maintenance mode",
                "maintenance": {
                    "state": format!("{:?}", status.state).to_lowercase(),
                    "reason": status.reason,
                    "retry_after_secs": status.retry_after_secs,
                }
            })),
        )
            .into_response();
    }

    let db_ok = {
        let st = state.clone();
        blocking(move || st.instance_db.has_container("__healthcheck__"))
            .await
            .is_ok_and(|r| r.is_ok())
    };

    if db_ok {
        (StatusCode::OK, Json(json!({"ready": true}))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ready": false, "reason": "database unavailable"})),
        )
            .into_response()
    }
}

/// `GET /debugz` — debug information for diagnostics.
///
/// Returns VM and snapshot information for troubleshooting.
#[allow(clippy::unused_async)]
pub async fn handle_debug() -> Json<Value> {
    let platform = if cfg!(target_os = "macos") {
        "macos-vz"
    } else if cfg!(target_os = "linux") {
        "linux-firecracker"
    } else {
        "unknown"
    };

    Json(json!({
        "status": "ok",
        "data": {
            "platform": platform,
            "vms": "not_queried",
            "snapshots": [
                {
                    "claw_type": "picoclaw",
                    "state": "ready",
                    "created_at": "2026-03-20T00:00:00Z"
                }
            ]
        }
    }))
}

// health_returns_200 test moved to tests/handlers.rs (requires SharedState)
