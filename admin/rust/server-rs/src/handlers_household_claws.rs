//! Household-namespaced Claw Store handlers (`/api/v1/household/claws*`).
//!
//! Wraps the underlying `handlers_claws::*` logic with a per-handler PoP
//! authorization gate matching the pattern in `handlers_pair_machine.rs`
//! (`founder_join_request_handler`) and `handlers_household.rs`
//! (`snapshot`). The shared `handlers_claws` handlers themselves cannot
//! enforce PoP auth — they're also mounted on the Bearer-authenticated
//! admin router (`api_rest` in `main.rs`) and must stay shape-compatible
//! with that surface.
//!
//! Operation mapping (every household route MUST gate on a specific
//! `Operation::Claws*` so the founder's caveats can restrict which
//! delegated devices may perform which action):
//!
//!   GET    /api/v1/household/claws                       → Operation::ClawsList
//!   GET    /api/v1/household/claws/{name}/availability   → Operation::ClawsList
//!   POST   /api/v1/household/claws/{name}/install        → Operation::ClawsCreate
//!   POST   /api/v1/household/claws/{name}/uninstall      → Operation::ClawsDelete
//!
//! Failure mode is `401 Unauthorized` with a deterministic empty body —
//! no oracle that distinguishes "missing header" from "bad signature".
//! Matches the reject shape used elsewhere on the household listener.

use crate::handlers_claws;
use crate::household_auth;
use crate::household_state::HouseholdState;
use crate::state::SharedState;
use crate::time_util;
use axum::{
    body::Bytes,
    extract::{FromRef, Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use household_rs::caveats::Operation;

/// Combined state for the household Claws router. Holds both the engine's
/// main `SharedState` (forwarded to the underlying `handlers_claws::*`
/// logic) and the `HouseholdState` needed for PoP authorization.
#[derive(Clone)]
pub struct HouseholdClawsState {
    pub shared: SharedState,
    pub household: HouseholdState,
}

impl FromRef<HouseholdClawsState> for SharedState {
    fn from_ref(state: &HouseholdClawsState) -> Self {
        state.shared.clone()
    }
}

impl FromRef<HouseholdClawsState> for HouseholdState {
    fn from_ref(state: &HouseholdClawsState) -> Self {
        state.household.clone()
    }
}

/// PoP-gates the request and forwards to `handlers_claws::handle_list_claws`.
pub async fn handle_household_list_claws(
    State(state): State<HouseholdClawsState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(reject) = authorize(&state, &method, &uri, &headers, &body, Operation::ClawsList, "list").await {
        return reject;
    }
    forward(handlers_claws::handle_list_claws(State(state.shared.clone())).await)
}

/// PoP-gates the request and forwards to `handlers_claws::handle_claw_availability`.
pub async fn handle_household_claw_availability(
    State(state): State<HouseholdClawsState>,
    Path(name): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(reject) = authorize(&state, &method, &uri, &headers, &body, Operation::ClawsList, "availability").await {
        return reject;
    }
    forward(handlers_claws::handle_claw_availability(State(state.shared.clone()), Path(name)).await)
}

/// PoP-gates the request and forwards to `handlers_claws::handle_install_claw`.
pub async fn handle_household_install_claw(
    State(state): State<HouseholdClawsState>,
    Path(name): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(reject) = authorize(&state, &method, &uri, &headers, &body, Operation::ClawsCreate, "install").await {
        return reject;
    }
    forward(handlers_claws::handle_install_claw(State(state.shared.clone()), Path(name)).await)
}

/// PoP-gates the request and forwards to `handlers_claws::handle_uninstall_claw`.
pub async fn handle_household_uninstall_claw(
    State(state): State<HouseholdClawsState>,
    Path(name): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(reject) = authorize(&state, &method, &uri, &headers, &body, Operation::ClawsDelete, "uninstall").await {
        return reject;
    }
    forward(handlers_claws::handle_uninstall_claw(State(state.shared.clone()), Path(name)).await)
}

// ── Internals ─────────────────────────────────────────────────────────

/// Runs `household_auth::authorize_request` with the supplied `Operation`
/// and folds every failure into `401 Unauthorized` (empty body) plus a
/// `tracing::warn` line that names the reject reason for operator triage.
async fn authorize(
    state: &HouseholdClawsState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Bytes,
    operation: Operation,
    stage_suffix: &str,
) -> Result<(), Response> {
    let Some(now) = time_util::unix_now_secs_checked("household_claws.clock") else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());

    if let Err(e) = household_auth::authorize_request(
        &state.household,
        headers,
        method,
        &path_and_query,
        body,
        operation,
        now,
    )
    .await
    {
        tracing::warn!(
            stage = "household_claws.rejected",
            op = stage_suffix,
            reason = "pop_auth_failed",
            error = %e,
        );
        return Err(StatusCode::UNAUTHORIZED.into_response());
    }
    Ok(())
}

/// Converts the inner `Result<Json<Value>, ApiError>` returned by the
/// shared handlers into an axum `Response`. Both arms already implement
/// `IntoResponse`; this helper keeps the wrappers concise.
fn forward<T: IntoResponse, E: IntoResponse>(result: Result<T, E>) -> Response {
    match result {
        Ok(value) => value.into_response(),
        Err(error) => error.into_response(),
    }
}
