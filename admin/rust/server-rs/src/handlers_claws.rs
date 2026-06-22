//! Claw store handlers:
//!   GET    /api/v1/claws
//!   GET    /api/v1/claws/{name}
//!   GET    /api/v1/claws/{name}/availability
//!   POST   /api/v1/claws/{name}/install
//!   POST   /api/v1/claws/{name}/uninstall

use crate::claw_store_service;
use crate::responses::{
    ClawDetailResponse, ClawJobResponse, ClawListItemResponse, ListResponse, claw_list_response,
};
use crate::state::SharedState;
use axum::{
    Json,
    extract::{Path, State},
};
use claw_rs::ClawStatus;
use core_rs::error::ApiError;

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
pub async fn handle_list_claws(
    State(state): State<SharedState>,
) -> Result<Json<ListResponse<ClawListItemResponse>>, ApiError> {
    let verify_path = state.theyos_dir.join("claws/verify-results.json");
    let items = state
        .claw_store
        .catalog_with_status_merged(Some(&verify_path));
    // Share one host probe across all claws in the list.
    let availabilities = crate::availability::project_all_claws(&state);
    Ok(Json(claw_list_response(items, availabilities, None)))
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
) -> Result<Json<core_rs::availability::ClawAvailability>, ApiError> {
    let avail = crate::availability::project_claw(&name, &state);
    Ok(Json(avail))
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
) -> Result<Json<ClawDetailResponse>, ApiError> {
    let entry = core_rs::manifest::get(&name)
        .ok_or_else(|| ApiError::not_found(format!("unknown claw type: {name}")))?;
    let installed = state.claw_store.get_state(&name);

    Ok(Json(ClawDetailResponse {
        name: entry.name.to_string(),
        description: entry.description.to_string(),
        language: entry.language.to_string(),
        buildable: entry.buildable,
        status: installed
            .as_ref()
            .map_or("not_installed", |state| claw_status_wire(state.status))
            .to_string(),
        installed_at: installed
            .as_ref()
            .and_then(|state| state.installed_at.clone()),
        job_id: installed.as_ref().and_then(|state| state.job_id.clone()),
        error: installed.and_then(|state| state.error),
    }))
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
) -> Result<Json<ClawJobResponse>, ApiError> {
    Ok(Json(
        claw_store_service::install_claw(&state, name)
            .await?
            .into_job_response(),
    ))
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
) -> Result<Json<ClawJobResponse>, ApiError> {
    Ok(Json(
        claw_store_service::uninstall_claw(&state, name)
            .await?
            .into_job_response(),
    ))
}

fn claw_status_wire(status: ClawStatus) -> &'static str {
    match status {
        ClawStatus::NotInstalled => "not_installed",
        ClawStatus::Installing => "installing",
        ClawStatus::Ready => "ready",
        ClawStatus::Uninstalling => "uninstalling",
        ClawStatus::Failed => "failed",
    }
}
