//! Claw store handlers:
//!   GET    /api/v1/claws
//!   GET    /api/v1/claws/{name}
//!   GET    /api/v1/claws/{name}/availability
//!   POST   /api/v1/claws/{name}/install
//!   POST   /api/v1/claws/{name}/uninstall

use crate::state::SharedState;
use axum::{
    Json,
    extract::{Path, State},
};
use claw_rs::ClawStatus;
use core_rs::error::{ApiError, blocking};
use serde_json::{Value, json};

/// `GET /api/v1/claws`
///
/// Returns the full catalog with per-claw install status. Each item now
/// includes an `availability` field carrying the full
/// `core_rs::availability::ClawAvailability` projection — the same shape
/// returned by `GET /api/v1/claws/{name}/availability`. Legacy fields
/// (`status`, `installed_at`, `job_id`, `error`) are preserved for
/// backward compatibility.
///
/// # Errors
///
/// Returns `ApiError` if the store cannot be queried.
#[allow(clippy::unused_async)]
pub async fn handle_list_claws(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let verify_path = state.theyos_dir.join("claws/verify-results.json");
    let items = state
        .claw_store
        .catalog_with_status_merged(Some(&verify_path));
    // Share one host probe across all claws in the list.
    let availabilities = crate::availability::project_all_claws(&state);
    let by_name: std::collections::HashMap<String, _> = availabilities
        .into_iter()
        .map(|a| (a.name.clone(), a))
        .collect();

    let enriched: Vec<Value> = items
        .into_iter()
        .map(|item| {
            let mut v = serde_json::to_value(&item).unwrap_or(Value::Null);
            if let Some(avail) = by_name.get(&item.name) {
                if let Value::Object(ref mut map) = v {
                    if let Ok(avail_v) = serde_json::to_value(avail) {
                        map.insert("availability".to_string(), avail_v);
                    }
                }
            }
            v
        })
        .collect();

    Ok(Json(
        json!({ "data": enriched, "has_more": false, "next_cursor": null }),
    ))
}

/// `GET /api/v1/claws/{name}/availability`
///
/// Returns the full `ClawAvailability` projection for a single claw.
/// This is the **authoritative endpoint** for answering "can this claw be
/// created right now?". Use it for install progress polling (iOS polls at
/// 2 Hz during install) and for detailed error messages when a create
/// request returns blocked.
///
/// Returns the projection even for names not in the manifest — the
/// response will have `overall.state == "unknown"` and a single
/// `UnavailReason::UnknownType` reason.
///
/// # Errors
///
/// Infallible in normal operation. Returns `ApiError` only if projection
/// serialization fails (should never happen).
#[allow(clippy::unused_async)]
pub async fn handle_claw_availability(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let avail = crate::availability::project_claw(&name, &state);
    Ok(Json(serde_json::to_value(&avail).map_err(|e| {
        ApiError::internal(format!("availability serialization: {e}"))
    })?))
}

/// `GET /api/v1/claws/{name}`
///
/// Returns catalog entry + install status for a single claw.
///
/// # Errors
///
/// Returns 404 if the claw name is not in the manifest.
#[allow(clippy::unused_async)]
pub async fn handle_get_claw(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let entry = core_rs::manifest::get(&name)
        .ok_or_else(|| ApiError::not_found(format!("unknown claw type: {name}")))?;
    let installed = state.claw_store.get_state(&name);

    Ok(Json(json!({
        "name": entry.name,
        "description": entry.description,
        "language": entry.language,
        "buildable": entry.buildable,
        "status": installed.as_ref().map_or("not_installed", |s| match s.status {
            ClawStatus::NotInstalled => "not_installed",
            ClawStatus::Installing => "installing",
            ClawStatus::Ready => "ready",
            ClawStatus::Uninstalling => "uninstalling",
            ClawStatus::Failed => "failed",
        }),
        "installed_at": installed.as_ref().and_then(|s| s.installed_at.clone()),
        "job_id": installed.as_ref().and_then(|s| s.job_id.clone()),
        "error": installed.and_then(|s| s.error),
    })))
}

/// `POST /api/v1/claws/{name}/install`
///
/// Triggers a background install job (golden build + snapshot).
///
/// # Errors
///
/// - 404 if claw not in manifest
/// - 400 if not buildable or already installed
/// - 409 if already installing (returns existing job ID)
pub async fn handle_install_claw(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // 1. Must be in manifest
    let Some(entry) = core_rs::manifest::get(&name) else {
        return Err(ApiError::not_found(format!("unknown claw type: {name}")));
    };

    // 2. Tier gate (P-46 Phase C): only Available/Supported can be installed
    //    by user action. Catalog/Detected tiers have not been smoke-verified.
    if !entry.tier.can_user_install() {
        return Err(ApiError::bad_request(format!(
            "claw type '{name}' is not installable yet (tier: {:?})",
            entry.tier
        )));
    }

    // 3. Must be installable (prebuilt artifact or local build plan)
    if !core_rs::manifest::is_installable(&name) {
        return Err(ApiError::bad_request(format!(
            "claw type '{name}' is not installable yet"
        )));
    }

    // 4. Check current status
    let current = state.claw_store.get_status(&name);
    match current {
        ClawStatus::Ready => {
            return Err(ApiError::bad_request(format!(
                "claw type '{name}' is already installed"
            )));
        }
        ClawStatus::Installing => {
            // Idempotent: return existing job ID
            let existing_state = state.claw_store.get_state(&name);
            let job_id = existing_state.and_then(|s| s.job_id).unwrap_or_default();
            return Ok(Json(json!({
                "job_id": job_id,
                "message": "install already in progress"
            })));
        }
        _ => {} // NotInstalled, Failed, Uninstalling — proceed
    }

    // 5. Create job
    let mut job = jobs_rs::Job::new(jobs_rs::JobType::InstallClaw, &name, "{}");
    let job_id = job.id.clone();
    let claw_name = name.clone();

    let st = state.clone();
    blocking(move || {
        st.jobs
            .create(&mut job)
            .map_err(|e| ApiError::internal(format!("failed to create install job: {e}")))
    })
    .await??;

    // 6. Mark installing
    state
        .claw_store
        .mark_installing(&claw_name, &job_id)
        .map_err(|e| ApiError::internal(format!("failed to mark installing: {e}")))?;

    tracing::info!("[claw-store] install queued: claw={claw_name} job={job_id}");

    Ok(Json(json!({
        "job_id": job_id,
        "message": format!("install queued for {claw_name}")
    })))
}

/// `POST /api/v1/claws/{name}/uninstall`
///
/// Triggers a background uninstall job (delete golden + snapshot).
///
/// # Errors
///
/// - 404 if claw not in manifest
/// - 400 if not installed, or if instances still exist (D7)
pub async fn handle_uninstall_claw(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // 1. Must be in manifest
    if !core_rs::manifest::is_known(&name) {
        return Err(ApiError::not_found(format!("unknown claw type: {name}")));
    }

    // 2. Must be ready (can only uninstall what's installed)
    if !state.claw_store.is_ready(&name) {
        return Err(ApiError::bad_request(format!(
            "claw type '{name}' is not installed"
        )));
    }

    // 3. D7: Block if ANY instance with this claw_type exists
    let n = name.clone();
    let st = state.clone();
    let count = blocking(move || {
        st.instance_db
            .count_by_claw_type(&n)
            .map_err(|e| ApiError::internal(format!("failed to count instances: {e}")))
    })
    .await??;

    if count > 0 {
        return Err(ApiError::bad_request(format!(
            "cannot uninstall: {count} instance(s) of type '{name}' still exist — delete them first"
        )));
    }

    // 4. Create job
    let mut job = jobs_rs::Job::new(jobs_rs::JobType::UninstallClaw, &name, "{}");
    let job_id = job.id.clone();
    let claw_name = name.clone();

    let st = state.clone();
    blocking(move || {
        st.jobs
            .create(&mut job)
            .map_err(|e| ApiError::internal(format!("failed to create uninstall job: {e}")))
    })
    .await??;

    // 5. Mark uninstalling
    state
        .claw_store
        .mark_uninstalling(&claw_name)
        .map_err(|e| ApiError::internal(format!("failed to mark uninstalling: {e}")))?;

    tracing::info!("[claw-store] uninstall queued: claw={claw_name} job={job_id}");

    Ok(Json(json!({
        "job_id": job_id,
        "message": format!("uninstall queued for {claw_name}")
    })))
}
