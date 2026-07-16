//! Household-namespaced Claw Store handlers (`/api/v1/household/claws*`).
//!
//! Wraps the underlying `handlers_claws::*` logic with a per-handler `PoP`
//! authorization gate matching the pattern in `handlers_pair_machine.rs`
//! (`founder_join_request_handler`) and `handlers_household.rs`
//! (`snapshot`). The shared `handlers_claws` handlers themselves cannot
//! enforce `PoP` auth — they're also mounted on the Bearer-authenticated
//! admin router (`api_rest` in `main.rs`) and must stay shape-compatible
//! with that surface.
//!
//! Operation mapping (every household route MUST gate on a specific
//! `Operation::Claws*` so the founder's caveats can restrict which
//! delegated devices may perform which action):
//!
//!   GET    /api/v1/household/claws                       → `Operation::ClawsList`
//!   GET    /api/v1/household/claws/{name}/availability   → `Operation::ClawsList`
//!   POST   /api/v1/household/claws/{name}/install        → `Operation::ClawsCreate`
//!   POST   /api/v1/household/claws/{name}/uninstall      → `Operation::ClawsDelete`
//!   GET    /api/v1/household/instances                   → `Operation::ClawsList`
//!   POST   /api/v1/household/instances                   → `Operation::ClawsCreate`
//!   GET    /api/v1/household/instances/{id}/status       → `Operation::ClawsList`
//!   GET    /api/v1/household/terminals/{container}/workspaces      → `Operation::ClawsList`
//!   POST   /api/v1/household/terminals/{container}/workspaces      → `Operation::ClawsUse`
//!   PATCH  /api/v1/household/terminals/{container}/workspaces/{id} → `Operation::ClawsUse`
//!   DELETE /api/v1/household/terminals/{container}/workspaces/{id} → `Operation::ClawsUse`
//!   POST   /api/v1/household/terminals/{container}/attach-token    → peer + `Operation::ClawsUse`
//!   GET    /api/v1/household/terminals/{container}/pty             → peer + attach-token gated
//!   POST   /api/v1/household/instances/{id}/stop       → `Operation::ClawsUse`
//!   POST   /api/v1/household/instances/{id}/restart    → `Operation::ClawsUse`
//!   POST   /api/v1/household/instances/{id}/rebuild    → `Operation::ClawsUse`
//!   DELETE /api/v1/household/instances/{id}            → `Operation::ClawsDelete`
//!
//! Failure mode is `401 Unauthorized` with a deterministic empty body —
//! no oracle that distinguishes "missing header" from "bad signature".
//! Matches the reject shape used elsewhere on the household listener.

use crate::household_attach_token::{HouseholdAttachScope, HouseholdAttachTokenStore};
use crate::household_auth;
use crate::household_state::HouseholdState;
use crate::responses::{InstanceResponse, ListResponse};
use crate::state::SharedState;
use crate::time_util;
use crate::{handlers_claws, handlers_instances, handlers_mobile, handlers_terminal};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{ConnectInfo, FromRef, Path, Query, State, WebSocketUpgrade},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use core_rs::error::{ApiError, blocking};
use household_rs::caveats::Operation;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

const HOUSEHOLD_ATTACH_TOKEN_HEADER: &str = "x-soyeht-household-attach-token";

/// Combined state for the household Claws router. Holds both the engine's
/// main `SharedState` (forwarded to the underlying `handlers_claws::*`
/// logic) and the `HouseholdState` needed for `PoP` authorization.
#[derive(Clone)]
pub struct HouseholdClawsState {
    pub shared: SharedState,
    pub household: HouseholdState,
    pub attach_tokens: Arc<HouseholdAttachTokenStore>,
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

/// `PoP`-gates the request and forwards to `handlers_claws::handle_list_claws`.
pub async fn handle_household_list_claws(
    State(state): State<HouseholdClawsState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(reject) = authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsList,
        "list",
    )
    .await
    {
        return reject;
    }
    forward(handlers_claws::handle_list_claws(State(state.shared.clone())).await)
}

/// `PoP`-gates the request and forwards to `handlers_claws::handle_claw_availability`.
pub async fn handle_household_claw_availability(
    State(state): State<HouseholdClawsState>,
    Path(name): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(reject) = authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsList,
        "availability",
    )
    .await
    {
        return reject;
    }
    forward(handlers_claws::handle_claw_availability(State(state.shared.clone()), Path(name)).await)
}

/// P7-C: the standard "rate limit exceeded" 429 response, matching the shape
/// emitted by the `create_instance` limiter in `handlers_instances` /
/// `handlers_mobile`. No new response/body shape is introduced.
fn rate_limited_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"error": "rate limit exceeded", "code": "RATE_LIMITED"})),
    )
        .into_response()
}

/// P7-C: per-actor rate-limit gate for a household Claw action, keyed by the
/// PoP-authenticated `actor_person_id`. Returns `true` when the request is
/// allowed. Fail-open: any limiter/db error allows the request, so a limiter
/// outage never blocks legitimate Claw operations (matching the existing
/// `create_instance` behaviour). Uses the global hourly limit unless an explicit
/// per-action override is configured.
async fn actor_action_allowed(
    shared: &SharedState,
    actor_person_id: &str,
    action: &'static str,
) -> bool {
    let shared = shared.clone();
    let actor = actor_person_id.to_string();
    blocking(move || shared.rate_limiter.check(&actor, action).unwrap_or(true))
        .await
        .unwrap_or(true)
}

/// `PoP`-gates the request and forwards to `handlers_claws::handle_install_claw`.
pub async fn handle_household_install_claw(
    State(state): State<HouseholdClawsState>,
    Path(name): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsCreate,
        "install",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };
    // P7-C: rate-limit Claw installs per authenticated person (`claw_install`),
    // checked AFTER PoP authorization and BEFORE any install work.
    if !actor_action_allowed(&state.shared, &authorized.actor_person_id, "claw_install").await {
        return rate_limited_response();
    }
    forward(handlers_claws::handle_install_claw(State(state.shared.clone()), Path(name)).await)
}

/// `PoP`-gates the request and forwards to `handlers_claws::handle_uninstall_claw`.
pub async fn handle_household_uninstall_claw(
    State(state): State<HouseholdClawsState>,
    Path(name): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsDelete,
        "uninstall",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };
    // P7-C: rate-limit Claw uninstalls per authenticated person (`claw_uninstall`),
    // checked AFTER PoP authorization and BEFORE any uninstall work.
    if !actor_action_allowed(&state.shared, &authorized.actor_person_id, "claw_uninstall").await {
        return rate_limited_response();
    }
    forward(handlers_claws::handle_uninstall_claw(State(state.shared.clone()), Path(name)).await)
}

/// `PoP`-gates listing instances created for the local engine's household.
pub async fn handle_household_list_instances(
    State(state): State<HouseholdClawsState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(reject) = authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsList,
        "list_instances",
    )
    .await
    {
        return reject;
    }

    let Some(scope) = household_scope(&state).await else {
        return ApiError::not_found("household not found").into_response();
    };

    forward(household_list_instances(&state.shared, &scope.household_id).await)
}

/// `PoP`-gates instance creation for a selected Mac household endpoint.
///
/// The endpoint itself is the target Mac. The body matches
/// `/api/v1/mobile/instances`, and the response keeps the same flat
/// `snake_case` shape expected by the iOS client.
pub async fn handle_household_create_instance(
    State(state): State<HouseholdClawsState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsCreate,
        "create_instance",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };

    let req = match serde_json::from_slice::<handlers_mobile::MobileCreateInstanceReq>(&body) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(
                stage = "household_claws.create_instance.bad_request",
                error = %e,
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid create instance request",
                    "code": "BAD_REQUEST",
                })),
            )
                .into_response();
        }
    };

    let Some(household_scope) = household_scope(&state).await else {
        return ApiError::not_found("household not found").into_response();
    };

    forward(
        handlers_mobile::create_mobile_instance_for_actor(
            state.shared.clone(),
            authorized.actor_person_id,
            req,
            Some(household_scope),
        )
        .await,
    )
}

/// `PoP`-gates status polling for a household-created instance.
pub async fn handle_household_instance_status(
    State(state): State<HouseholdClawsState>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(reject) = authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsList,
        "instance_status",
    )
    .await
    {
        return reject;
    }

    let Some(scope) = household_scope(&state).await else {
        return ApiError::not_found("household not found").into_response();
    };

    forward(household_instance_status(&state.shared, &id, &scope.household_id).await)
}

/// `PoP`-gates workspace listing for a household-scoped terminal container.
pub async fn handle_household_list_workspaces(
    State(state): State<HouseholdClawsState>,
    Path(container): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsList,
        "list_workspaces",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };

    let Some(scope) = household_scope(&state).await else {
        return ApiError::not_found("household not found").into_response();
    };
    let username = workspace_username(&authorized);

    forward(
        household_list_workspaces(&state.shared, &container, &scope.household_id, &username).await,
    )
}

/// `PoP`-gates workspace creation for a household-scoped terminal container.
pub async fn handle_household_create_workspace(
    State(state): State<HouseholdClawsState>,
    Path(container): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsUse,
        "create_workspace",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };

    let req = match serde_json::from_slice::<handlers_terminal::CreateWorkspaceBody>(&body) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(
                stage = "household_claws.create_workspace.bad_request",
                error = %e,
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid create workspace request",
                    "code": "BAD_REQUEST",
                })),
            )
                .into_response();
        }
    };

    let Some(scope) = household_scope(&state).await else {
        return ApiError::not_found("household not found").into_response();
    };
    let username = workspace_username(&authorized);

    forward(
        household_create_workspace(
            &state.shared,
            &container,
            &scope.household_id,
            &username,
            req.display_name,
        )
        .await,
    )
}

/// `PoP`-gates workspace rename for a household-scoped terminal container.
pub async fn handle_household_rename_workspace(
    State(state): State<HouseholdClawsState>,
    Path((container, id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsUse,
        "rename_workspace",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };

    let req = match serde_json::from_slice::<handlers_terminal::RenameWorkspaceBody>(&body) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(
                stage = "household_claws.rename_workspace.bad_request",
                error = %e,
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid rename workspace request",
                    "code": "BAD_REQUEST",
                })),
            )
                .into_response();
        }
    };

    let Some(scope) = household_scope(&state).await else {
        return ApiError::not_found("household not found").into_response();
    };
    let username = workspace_username(&authorized);

    forward(
        household_rename_workspace(
            &state.shared,
            &container,
            &id,
            &scope.household_id,
            &username,
            req.display_name,
        )
        .await,
    )
}

/// `PoP`-gates workspace deletion for a household-scoped terminal container.
pub async fn handle_household_delete_workspace(
    State(state): State<HouseholdClawsState>,
    Path((container, id)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsUse,
        "delete_workspace",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };

    let Some(scope) = household_scope(&state).await else {
        return ApiError::not_found("household not found").into_response();
    };
    let username = workspace_username(&authorized);

    forward(
        household_delete_workspace(
            &state.shared,
            &container,
            &id,
            &scope.household_id,
            &username,
        )
        .await,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HouseholdAttachTokenRequest {
    pub workspace_id: String,
}

/// `PoP`-gates minting a short-lived household terminal attach token.
pub async fn handle_household_mint_attach_token(
    State(state): State<HouseholdClawsState>,
    Path(container): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_terminal_attach_peer_allowed(peer_addr(peer), "mint_attach_token") {
        return StatusCode::FORBIDDEN.into_response();
    }

    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsUse,
        "mint_attach_token",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };

    let req = match serde_json::from_slice::<HouseholdAttachTokenRequest>(&body) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(
                stage = "household_claws.attach_token.bad_request",
                error = %e,
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid attach token request",
                    "code": "BAD_REQUEST",
                })),
            )
                .into_response();
        }
    };

    let Some(scope) = household_scope(&state).await else {
        return ApiError::not_found("household not found").into_response();
    };
    let username = workspace_username(&authorized);

    forward(
        household_mint_attach_token(
            &state,
            &container,
            &req.workspace_id,
            &scope.household_id,
            &username,
        )
        .await,
    )
}

/// Upgrades a household terminal WebSocket using a single-use attach token.
pub async fn handle_household_terminal_pty(
    State(state): State<HouseholdClawsState>,
    Path(container): Path<String>,
    Query(q): Query<handlers_terminal::PtyQuery>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !is_terminal_attach_peer_allowed(peer_addr(peer), "terminal_pty") {
        return StatusCode::FORBIDDEN.into_response();
    }

    forward(household_terminal_pty(&state, &container, q, &headers, ws).await)
}

/// `PoP`-gates stopping a household-scoped instance.
pub async fn handle_household_stop_instance(
    State(state): State<HouseholdClawsState>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsUse,
        "stop_instance",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };

    forward(household_stop_instance(&state, &authorized, &id).await)
}

/// `PoP`-gates restarting a household-scoped instance.
pub async fn handle_household_restart_instance(
    State(state): State<HouseholdClawsState>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsUse,
        "restart_instance",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };

    forward(household_restart_instance(&state, &authorized, &id).await)
}

/// `PoP`-gates rebuilding a household-scoped instance.
pub async fn handle_household_rebuild_instance(
    State(state): State<HouseholdClawsState>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsUse,
        "rebuild_instance",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };

    forward(household_rebuild_instance(&state, &authorized, &id).await)
}

/// `PoP`-gates deleting a household-scoped instance.
pub async fn handle_household_delete_instance(
    State(state): State<HouseholdClawsState>,
    Path(id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let authorized = match authorize(
        &state,
        &method,
        &uri,
        &headers,
        &body,
        Operation::ClawsDelete,
        "delete_instance",
    )
    .await
    {
        Ok(authorized) => authorized,
        Err(reject) => return reject,
    };

    forward(household_delete_instance(&state, &authorized, &id).await)
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
) -> Result<household_auth::AuthorizedRequest, Response> {
    let Some(now) = time_util::unix_now_secs_checked("household_claws.clock") else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());

    match household_auth::authorize_request_with_actor(
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
        Ok(authorized) => Ok(authorized),
        Err(e) => {
            tracing::warn!(
                stage = "household_claws.rejected",
                op = stage_suffix,
                reason = "pop_auth_failed",
                error = %e,
            );
            Err(StatusCode::UNAUTHORIZED.into_response())
        }
    }
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

async fn household_scope(
    state: &HouseholdClawsState,
) -> Option<crate::instance_create::HouseholdInstanceScope> {
    household_scope_from_state(&state.household).await
}

async fn household_scope_from_state(
    state: &HouseholdState,
) -> Option<crate::instance_create::HouseholdInstanceScope> {
    let identity = state.current().await?;
    Some(crate::instance_create::HouseholdInstanceScope {
        household_id: identity.record.hh_id.to_string(),
        household_machine_id: identity.cert.m_id.to_string(),
    })
}

async fn household_list_instances(
    state: &SharedState,
    household_id: &str,
) -> Result<Json<ListResponse<InstanceResponse>>, ApiError> {
    let st = state.clone();
    let household_id = household_id.to_string();
    let rows = blocking(move || {
        st.instance_db
            .list_for_household(&household_id)
            .map_err(ApiError::from)
    })
    .await??;
    let items = rows.into_iter().map(InstanceResponse::from_row).collect();
    Ok(Json(ListResponse::all(items)))
}

async fn household_instance_status(
    state: &SharedState,
    id: &str,
    household_id: &str,
) -> Result<Response, ApiError> {
    let st = state.clone();
    let iid = id.to_string();
    let household_id = household_id.to_string();
    let row = blocking(move || {
        st.instance_db
            .get_for_household_status(&iid, &household_id)
            .map_err(ApiError::from)
    })
    .await??;
    let row = row.ok_or_else(|| ApiError::not_found("instance not found"))?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": row.status.to_string(),
            "provisioning_message": row.provisioning_message,
            "provisioning_error": row.provisioning_error,
            "provisioning_failure_code": row.provisioning_failure_code,
            "provisioning_phase": row.provisioning_phase,
        })),
    )
        .into_response())
}

fn workspace_username(authorized: &household_auth::AuthorizedRequest) -> String {
    // `terminal_conversations.username` is text, not a local users FK. The
    // household v1 namespace is per actor person after container access has
    // already been constrained by `household_id == self`.
    authorized.actor_person_id.clone()
}

async fn require_household_container(
    state: &SharedState,
    container: &str,
    household_id: &str,
) -> Result<store_rs::InstanceRow, ApiError> {
    let container = handlers_terminal::validate_container(container)?;
    let st = state.clone();
    let household_id = household_id.to_string();
    let row = blocking(move || {
        st.instance_db
            .get_for_household_by_container(&container, &household_id)
            .map_err(ApiError::from)
    })
    .await??;
    row.ok_or_else(|| ApiError::not_found("container not found"))
}

async fn require_household_instance_by_id(
    state: &SharedState,
    id: &str,
    household_id: &str,
) -> Result<store_rs::InstanceRow, ApiError> {
    let st = state.clone();
    let id = id.to_string();
    let household_id = household_id.to_string();
    let row = blocking(move || {
        st.instance_db
            .get_for_household_by_id(&id, &household_id)
            .map_err(ApiError::from)
    })
    .await??;
    row.ok_or_else(|| ApiError::not_found("instance not found"))
}

async fn household_action_row(
    state: &HouseholdClawsState,
    id: &str,
) -> Result<store_rs::InstanceRow, ApiError> {
    let Some(scope) = household_scope(state).await else {
        return Err(ApiError::not_found("household not found"));
    };
    require_household_instance_by_id(&state.shared, id, &scope.household_id).await
}

async fn household_stop_instance(
    state: &HouseholdClawsState,
    authorized: &household_auth::AuthorizedRequest,
    id: &str,
) -> Result<StatusCode, ApiError> {
    let row = household_action_row(state, id).await?;
    handlers_instances::stop_instance_for_row(&state.shared, &authorized.actor_person_id, id, row)
        .await
}

async fn household_restart_instance(
    state: &HouseholdClawsState,
    authorized: &household_auth::AuthorizedRequest,
    id: &str,
) -> Result<StatusCode, ApiError> {
    let row = household_action_row(state, id).await?;
    handlers_instances::restart_instance_for_row(
        &state.shared,
        &authorized.actor_person_id,
        id,
        row,
    )
    .await
}

async fn household_rebuild_instance(
    state: &HouseholdClawsState,
    authorized: &household_auth::AuthorizedRequest,
    id: &str,
) -> Result<StatusCode, ApiError> {
    let row = household_action_row(state, id).await?;
    handlers_instances::rebuild_instance_for_row(
        &state.shared,
        &authorized.actor_person_id,
        id,
        row,
    )
    .await
}

async fn household_delete_instance(
    state: &HouseholdClawsState,
    authorized: &household_auth::AuthorizedRequest,
    id: &str,
) -> Result<StatusCode, ApiError> {
    let row = household_action_row(state, id).await?;
    handlers_instances::delete_instance_for_row(&state.shared, &authorized.actor_person_id, id, row)
        .await
}

async fn household_mint_attach_token(
    state: &HouseholdClawsState,
    container: &str,
    workspace_id: &str,
    household_id: &str,
    username: &str,
) -> Result<Json<serde_json::Value>, ApiError> {
    let container = handlers_terminal::validate_container(container)?;
    require_household_container(&state.shared, &container, household_id).await?;
    let session_id = handlers_terminal::sanitize_session_id(workspace_id)?;
    handlers_terminal::verify_session_owner(&state.shared, &session_id, &container, username)
        .await?;

    let minted = state.attach_tokens.mint(HouseholdAttachScope {
        household_id: household_id.to_string(),
        container,
        session_id,
        actor_person_id: username.to_string(),
    });

    Ok(Json(json!({
        "token": minted.token,
        "expires_at": minted.expires_at
    })))
}

async fn household_terminal_pty(
    state: &HouseholdClawsState,
    container: &str,
    q: handlers_terminal::PtyQuery,
    headers: &HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, Response> {
    let token = attach_token_from_headers(headers)
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;
    let scope = state
        .attach_tokens
        .consume(token)
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

    let Some(current_scope) = household_scope(state).await else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    if scope.household_id != current_scope.household_id {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    }

    let container =
        handlers_terminal::validate_container(container).map_err(IntoResponse::into_response)?;
    if scope.container != container {
        return Err(ApiError::not_found("container not found").into_response());
    }

    let session_id =
        handlers_terminal::sanitize_session_id(&q.session).map_err(IntoResponse::into_response)?;
    if scope.session_id != session_id {
        return Err(ApiError::not_found("session not found").into_response());
    }

    require_household_container(&state.shared, &container, &current_scope.household_id)
        .await
        .map_err(IntoResponse::into_response)?;
    handlers_terminal::verify_session_owner(
        &state.shared,
        &session_id,
        &container,
        &scope.actor_person_id,
    )
    .await
    .map_err(IntoResponse::into_response)?;

    Ok(
        handlers_terminal::serve_authorized_terminal_pty(state.shared.clone(), container, q, ws)
            .await,
    )
}

fn attach_token_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(HOUSEHOLD_ATTACH_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn peer_addr(peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> Option<SocketAddr> {
    peer.map(|Extension(ConnectInfo(addr))| addr)
}

fn is_terminal_attach_peer_allowed(peer: Option<SocketAddr>, stage_suffix: &str) -> bool {
    if peer.is_some_and(is_terminal_attach_peer_addr_allowed) {
        return true;
    }

    tracing::warn!(
        stage = format!("household_claws.{stage_suffix}.peer_rejected"),
        peer = ?peer,
        "household terminal attach route rejected non-loopback/non-tailnet/non-configured-mesh peer"
    );
    false
}

fn is_terminal_attach_peer_addr_allowed(peer: SocketAddr) -> bool {
    crate::household_listener::is_post_trust_household_peer_allowed(peer.ip())
}

async fn household_list_workspaces(
    state: &SharedState,
    container: &str,
    household_id: &str,
    username: &str,
) -> Result<Json<serde_json::Value>, ApiError> {
    let container = handlers_terminal::validate_container(container)?;
    require_household_container(state, &container, household_id).await?;

    let st = state.clone();
    let c = container.clone();
    let u = username.to_string();
    let workspaces = blocking(move || {
        st.instance_db
            .list_conversations(&c, &u)
            .map_err(ApiError::from)
    })
    .await??;

    let items: Vec<serde_json::Value> = workspaces
        .iter()
        .map(|ws| {
            let is_connected = state
                .pty_mgr
                .get(&container, &ws.id)
                .is_some_and(|s| !s.is_closed());
            json!({
                "id": ws.id,
                "session_id": ws.id,
                "container": ws.container,
                "display_name": ws.display_name,
                "status": ws.status,
                "is_connected": is_connected,
                "created_at": ws.created_at,
                "last_attach_at": ws.last_attach_at,
                "last_activity_at": ws.last_activity_at
            })
        })
        .collect();

    let warning_threshold = 8;
    let mut result = json!({"data": &items, "has_more": false, "next_cursor": null});
    if items.len() > warning_threshold {
        result["warning"] = json!(format!(
            "You have {} sessions. Consider closing unused ones.",
            items.len()
        ));
    }

    Ok(Json(result))
}

async fn household_create_workspace(
    state: &SharedState,
    container: &str,
    household_id: &str,
    username: &str,
    display_name: String,
) -> Result<Json<serde_json::Value>, ApiError> {
    let container = handlers_terminal::validate_container(container)?;
    let row = require_household_container(state, &container, household_id).await?;
    if row.status != store_rs::InstanceStatus::Active {
        return Err(ApiError::bad_request(format!("vm_{}", row.status)));
    }

    let st = state.clone();
    let c = container.clone();
    let u = username.to_string();
    let dn = display_name.clone();
    let ws = blocking(move || {
        st.instance_db
            .create_conversation(&c, &u, &dn)
            .map_err(ApiError::from)
    })
    .await??;

    tracing::info!(
        "household workspace created: {} ({}) for actor {} on {}",
        ws.id,
        display_name,
        username,
        container
    );

    Ok(Json(json!({
        "workspace": {
            "id": ws.id,
            "session_id": ws.id,
            "container": ws.container,
            "display_name": ws.display_name,
            "status": ws.status
        }
    })))
}

async fn household_rename_workspace(
    state: &SharedState,
    container: &str,
    id: &str,
    household_id: &str,
    username: &str,
    display_name: String,
) -> Result<StatusCode, ApiError> {
    let container = handlers_terminal::validate_container(container)?;
    require_household_container(state, &container, household_id).await?;
    let session_id = handlers_terminal::sanitize_session_id(id)?;
    handlers_terminal::verify_session_owner(state, &session_id, &container, username).await?;

    let st = state.clone();
    let sid = session_id.clone();
    let updated = blocking(move || {
        st.instance_db
            .rename_conversation(&sid, &display_name)
            .map_err(ApiError::from)
    })
    .await??;

    if !updated {
        return Err(ApiError::not_found("workspace not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn household_delete_workspace(
    state: &SharedState,
    container: &str,
    id: &str,
    household_id: &str,
    username: &str,
) -> Result<StatusCode, ApiError> {
    let container = handlers_terminal::validate_container(container)?;
    require_household_container(state, &container, household_id).await?;
    let session_id = handlers_terminal::sanitize_session_id(id)?;
    handlers_terminal::verify_session_owner(state, &session_id, &container, username).await?;

    let st = state.clone();
    let sid = session_id.clone();
    let deleted = blocking(move || {
        st.instance_db
            .delete_conversation(&sid)
            .map_err(ApiError::from)
    })
    .await??;

    if !deleted {
        return Err(ApiError::not_found("workspace not found"));
    }

    if let Err(e) = state.pty_mgr.close(&container, &session_id) {
        tracing::warn!("[household_claws] delete workspace pty close: {e}");
    }

    tracing::info!(
        "household workspace deleted: {} for actor {} on {}",
        session_id,
        username,
        container
    );

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use household_rs::keys::{IdentityKey, P256Keypair};
    use household_rs::{BootstrapOpts, KeyBackingPolicy};
    use std::sync::Arc;

    #[tokio::test]
    async fn household_scope_uses_loaded_engine_identity_not_caller_identity() {
        let state_dir = tempfile::tempdir().expect("state dir");
        let identity = household_rs::bootstrap_or_load(
            state_dir.path(),
            BootstrapOpts {
                household_name: "Sample Home".into(),
                hostname_label: Some("mac-alpha".into()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();
        let expected_household_id = identity.record.hh_id.to_string();
        let expected_machine_id = identity.cert.m_id.to_string();
        let caller = P256Keypair::generate();
        let caller_person_id = household_rs::derive_person_id(&caller.public()).0;

        let state = HouseholdState::loaded(Arc::new(identity));
        let scope = household_scope_from_state(&state)
            .await
            .expect("loaded household scope");

        assert_eq!(scope.household_id, expected_household_id);
        assert_eq!(scope.household_machine_id, expected_machine_id);
        assert_ne!(scope.household_machine_id, caller_person_id);
    }
}
