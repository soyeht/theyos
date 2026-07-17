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
//!   POST   /api/v1/household/claws/{name}/owner-site/preflight     → peer + injected pre-effect capability only
//!   GET    /api/v1/household/claws/{name}/owner-site/ake           → peer + injected A2 provider only
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
use crate::owner_site_ake::{OWNER_SITE_AKE_MAX_RECORD_ENVELOPE_BYTES, OwnerSiteAkeProvider};
use crate::owner_site_capability::{OwnerSiteCapabilityStore, OwnerSiteResource};
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

/// Admits only the inert PR1 owner-site wire shape.
///
/// The production household router never injects an owner-site capability
/// store in this slice, so this endpoint is fail-closed. No owner-site `PoP`,
/// challenge, backend connection, or browser byte exists yet.
pub(crate) async fn handle_household_owner_site_preflight(
    Path(name): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    provider: Option<Extension<Arc<OwnerSiteCapabilityStore>>>,
) -> Response {
    if let Some(reject) = owner_site_pre_effect_peer_rejection(peer_addr(peer)).await {
        return reject;
    }

    // A terminal attach token is never an owner-site presentation. Reject it
    // explicitly rather than silently accepting an unrelated bearer header.
    if headers.contains_key(HOUSEHOLD_ATTACH_TOKEN_HEADER) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let Some(Extension(store)) = provider else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Ok(resource) = OwnerSiteResource::from_route_claw(&name) else {
        return StatusCode::FORBIDDEN.into_response();
    };

    match store.pre_effect_admission(&resource) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::FORBIDDEN.into_response(),
    }
}

/// Upgrades the one-WebSocket owner-site A2 M1/M2/M3 handshake and S2/C3 record confirmation.
///
/// A missing provider is deliberately a quiet default deny.  The handler
/// applies the same live Ready + verified-local-Mesh peer gate before looking
/// at the provider, parsing a resource, or accepting the WebSocket.  Neither
/// an address nor `ConnectInfo` is an owner-site principal.
pub(crate) async fn handle_household_owner_site_ake(
    Path(name): Path<String>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    provider: Option<Extension<Arc<OwnerSiteAkeProvider>>>,
    upgrade: WebSocketUpgrade,
) -> Response {
    if let Some(reject) = owner_site_ake_peer_rejection(peer_addr(peer)).await {
        return reject;
    }

    // A terminal attach token is never an owner-site A2 credential.
    if headers.contains_key(HOUSEHOLD_ATTACH_TOKEN_HEADER) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let Some(Extension(provider)) = provider else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Ok(resource) = OwnerSiteResource::from_route_claw(&name) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !provider.admits_resource(&resource) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let peer = peer_addr(peer);
    upgrade
        .max_message_size(OWNER_SITE_AKE_MAX_RECORD_ENVELOPE_BYTES)
        .max_frame_size(OWNER_SITE_AKE_MAX_RECORD_ENVELOPE_BYTES)
        .on_upgrade(move |socket| async move {
            provider.serve(socket, resource, peer).await;
        })
        .into_response()
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
    if let Some(reject) = terminal_attach_peer_rejection(peer_addr(peer), "mint_attach_token").await
    {
        return reject;
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
    if let Some(reject) = terminal_attach_peer_rejection(peer_addr(peer), "terminal_pty").await {
        return reject;
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

async fn terminal_attach_peer_rejection(
    peer: Option<SocketAddr>,
    stage_suffix: &str,
) -> Option<Response> {
    match crate::household_listener::post_trust_household_peer_gate(peer).await {
        Ok(()) => None,
        Err(status) => {
            tracing::warn!(
                stage = format!("household_claws.{stage_suffix}.peer_rejected"),
                peer = ?peer,
                "household terminal attach route rejected non-loopback/non-tailnet/non-verified-mesh peer"
            );
            Some(status.into_response())
        }
    }
}

async fn owner_site_pre_effect_peer_rejection(peer: Option<SocketAddr>) -> Option<Response> {
    match crate::household_listener::post_trust_household_peer_gate(peer).await {
        Ok(()) => None,
        Err(status) => {
            tracing::warn!(
                stage = "household_claws.owner_site_pre_effect.peer_rejected",
                peer = ?peer,
                "household owner-site pre-effect route rejected source before capability admission"
            );
            Some(status.into_response())
        }
    }
}

async fn owner_site_ake_peer_rejection(peer: Option<SocketAddr>) -> Option<Response> {
    match crate::household_listener::post_trust_household_peer_gate(peer).await {
        Ok(()) => None,
        Err(status) => {
            tracing::warn!(
                stage = "household_claws.owner_site_ake.peer_rejected",
                peer = ?peer,
                "household owner-site A2 route rejected source before provider or WebSocket upgrade"
            );
            Some(status.into_response())
        }
    }
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
    use crate::claw_store_routes;
    use crate::owner_site_ake::{
        OwnerSiteAkeEffectSnapshot, OwnerSiteAkeFixture, OwnerSiteAkeHarness,
    };
    use crate::owner_site_authority::{OwnerSiteAuthoritySnapshot, active_authority_fixture};
    use crate::owner_site_capability::{
        OwnerSiteBackend, OwnerSiteCapability, OwnerSiteCapabilityScope, OwnerSiteCapabilityStore,
        OwnerSiteEffectCounters, OwnerSiteEffectSnapshot, OwnerSiteIntent, OwnerSiteResource,
    };
    use axum::{
        Extension, Router,
        body::Body,
        extract::ConnectInfo,
        http::Request,
        routing::{get, post},
    };
    use axum_test::{TestServer, WsMessage};
    use household_rs::keys::{IdentityKey, P256Keypair};
    use household_rs::{BootstrapOpts, KeyBackingPolicy};
    use std::sync::Arc;
    use tokio::time::{Duration, timeout};
    use tower::ServiceExt;

    fn owner_site_store(
        claw_name: &str,
        actor_id: &str,
        authority: OwnerSiteAuthoritySnapshot,
    ) -> (Arc<OwnerSiteCapabilityStore>, Arc<OwnerSiteEffectCounters>) {
        let resource = OwnerSiteResource::from_route_claw(claw_name).expect("owner-site resource");
        let intent = OwnerSiteIntent::injected_for_harness("household-alpha", actor_id, resource)
            .expect("owner-site intent");
        let backend = OwnerSiteBackend::numeric_loopback(
            "127.0.0.1:7411".parse().expect("numeric loopback backend"),
        )
        .expect("loopback backend");
        let scope = OwnerSiteCapabilityScope::new(intent, authority, backend);
        let (store, effects) = OwnerSiteCapabilityStore::injected_for_harness(
            OwnerSiteCapability::injected_for_harness(scope),
        );
        (Arc::new(store), effects)
    }

    fn owner_site_route(provider: Option<Arc<OwnerSiteCapabilityStore>>) -> Router {
        let app = Router::new().route(
            claw_store_routes::household::OWNER_SITE_PREFLIGHT,
            post(handle_household_owner_site_preflight),
        );
        match provider {
            Some(store) => app.layer(Extension(store)),
            None => app,
        }
    }

    fn owner_site_ake_route(provider: Option<Arc<OwnerSiteAkeProvider>>) -> Router {
        let app = Router::new().route(
            claw_store_routes::household::OWNER_SITE_AKE,
            get(handle_household_owner_site_ake),
        );
        match provider {
            Some(provider) => app.layer(Extension(provider)),
            None => app,
        }
    }

    fn assert_ake_never_effected(snapshot: &OwnerSiteAkeEffectSnapshot) {
        assert_eq!(snapshot.verified_peers, 0);
        assert_eq!(snapshot.dial_permits_issued, 0);
        assert_eq!(snapshot.mints, 0);
        assert_eq!(snapshot.consumes, 0);
        assert_eq!(snapshot.proxy_dials, 0);
        assert_eq!(snapshot.site_bytes, 0);
    }

    async fn owner_site_preflight_request(
        app: Router,
        claw_name: &str,
        peer: Option<SocketAddr>,
        attach_token: Option<&str>,
    ) -> StatusCode {
        let path = format!("/api/v1/household/claws/{claw_name}/owner-site/preflight");
        let mut builder = Request::builder().method(Method::POST).uri(path);
        if let Some(peer) = peer {
            builder = builder.extension(ConnectInfo(peer));
        }
        if let Some(attach_token) = attach_token {
            builder = builder.header(HOUSEHOLD_ATTACH_TOKEN_HEADER, attach_token);
        }
        owner_site_route_response(app, builder).await.status()
    }

    async fn owner_site_route_response(
        app: Router,
        builder: axum::http::request::Builder,
    ) -> Response {
        app.oneshot(builder.body(Body::empty()).expect("owner-site request"))
            .await
            .expect("owner-site response")
    }

    fn assert_owner_site_zero_effects(
        effects: &OwnerSiteEffectCounters,
        pre_effect_admissions: usize,
    ) {
        assert_eq!(
            effects.snapshot(),
            OwnerSiteEffectSnapshot {
                listener_binds: 0,
                mints: 0,
                consumes: 0,
                proxy_dials: 0,
                site_bytes: 0,
                challenge_issues: 0,
                challenge_claims: 0,
                pre_effect_admissions,
            },
            "pre-effect owner-site route must not bind, mint, issue/claim a challenge, dial, or expose bytes"
        );
    }

    #[tokio::test]
    async fn owner_site_ake_default_denies_and_unverified_mesh_stops_before_provider() {
        let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
        let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
        let default_server = TestServer::builder()
            .http_transport()
            .build(owner_site_ake_route(None).layer(Extension(ConnectInfo(loopback))))
            .expect("default-deny A2 test server");
        let response = default_server.get_websocket(path).await;
        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);

        let OwnerSiteAkeFixture {
            provider, effects, ..
        } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
        let unverified = SocketAddr::from(([10, 44, 0, 2], 41001));
        let server = TestServer::builder()
            .http_transport()
            .build(
                owner_site_ake_route(Some(Arc::new(provider)))
                    .layer(Extension(ConnectInfo(unverified))),
            )
            .expect("unverified A2 test server");
        let response = server.get_websocket(path).await;
        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(effects.snapshot().sessions_started, 0);
        assert_eq!(effects.snapshot().challenge_issues, 0);
        assert_eq!(effects.snapshot().challenge_claims, 0);
        assert_ake_never_effected(&effects.snapshot());
    }

    #[tokio::test]
    async fn owner_site_ake_uses_one_binary_ws_for_s2_c3_then_closes_pre_effect() {
        let OwnerSiteAkeFixture {
            provider,
            client,
            effects,
        } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
        let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
        let app =
            owner_site_ake_route(Some(Arc::new(provider))).layer(Extension(ConnectInfo(loopback)));
        let server = TestServer::builder()
            .http_transport()
            .build(app)
            .expect("A2 WS test server");
        let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
        let response = server.get_websocket(path).await;
        assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
        let mut websocket = response.into_websocket().await;

        let (mut client_session, m1) = client.start().expect("M1");
        websocket.send_message(WsMessage::Binary(m1.into())).await;
        let m2 = websocket.receive_bytes().await;
        let m3 = client_session
            .accept_m2_and_make_m3(&m2)
            .expect("M3 after authenticated M2");
        websocket.send_message(WsMessage::Binary(m3.into())).await;

        let s2 = websocket.receive_bytes().await;
        assert!(!s2.is_empty(), "S2 must be an encrypted A2 record");
        let c3 = client_session
            .accept_s2_and_make_c3(&s2)
            .expect("C3 only after authenticating the exact S2");
        websocket.send_message(WsMessage::Binary(c3.into())).await;

        for _ in 0..128 {
            if effects.snapshot().c3_records_accepted == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let snapshot = effects.snapshot();
        assert_eq!(snapshot.sessions_started, 1);
        assert_eq!(snapshot.challenge_issues, 1);
        assert_eq!(snapshot.challenge_claims, 1);
        assert_eq!(snapshot.validated_pending_finished, 1);
        assert_eq!(snapshot.post_claim_recheck_rejections, 0);
        assert_eq!(snapshot.s2_records_emitted, 1);
        assert_eq!(snapshot.c3_records_accepted, 1);
        assert_eq!(snapshot.post_c3_recheck_rejections, 0);
        assert_eq!(snapshot.completed_m3_closures, 1);
        assert_ake_never_effected(&snapshot);
        assert_eq!(client.action_pop_signature_count(), 1);
        // The same WS closes after authenticated C3. There is still no raw
        // stream, second WebSocket, resumable credential, peer, or site byte.
        let close = timeout(Duration::from_secs(1), websocket.receive_bytes())
            .await
            .expect("post-C3 pre-effect state must close the same WebSocket");
        assert!(
            close.is_empty(),
            "the record-confirmed pre-effect state must emit zero raw bytes"
        );
    }

    #[tokio::test]
    async fn owner_site_ake_route_real_rejects_raw_c3_and_closes_without_effects() {
        let OwnerSiteAkeFixture {
            provider,
            client,
            effects,
        } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
        let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
        let app =
            owner_site_ake_route(Some(Arc::new(provider))).layer(Extension(ConnectInfo(loopback)));
        let server = TestServer::builder()
            .http_transport()
            .build(app)
            .expect("A2 WS test server");
        let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
        let response = server.get_websocket(path).await;
        assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
        let mut websocket = response.into_websocket().await;

        let (mut client_session, m1) = client.start().expect("M1");
        websocket.send_message(WsMessage::Binary(m1.into())).await;
        let m2 = websocket.receive_bytes().await;
        let m3 = client_session
            .accept_m2_and_make_m3(&m2)
            .expect("M3 after authenticated M2");
        websocket.send_message(WsMessage::Binary(m3.into())).await;
        let s2 = websocket.receive_bytes().await;
        assert!(
            !s2.is_empty(),
            "server reaches the encrypted S2 state first"
        );

        // A text application message is plaintext, never an A2 record. The
        // A2 state machine must close rather than parse or downgrade it.
        websocket
            .send_message(WsMessage::Text("not-an-a2-record".into()))
            .await;

        let close = timeout(Duration::from_secs(1), websocket.receive_bytes())
            .await
            .expect("malformed C3 must close the same WebSocket");
        assert!(
            close.is_empty(),
            "malformed C3 cannot reveal raw response bytes"
        );
        let snapshot = effects.snapshot();
        assert_eq!(snapshot.sessions_started, 1);
        assert_eq!(snapshot.challenge_claims, 1);
        assert_eq!(snapshot.validated_pending_finished, 1);
        assert_eq!(snapshot.s2_records_emitted, 1);
        assert_eq!(snapshot.c3_records_accepted, 0);
        assert_eq!(snapshot.post_c3_recheck_rejections, 0);
        assert_eq!(snapshot.completed_m3_closures, 1);
        assert_ake_never_effected(&snapshot);
    }

    #[tokio::test]
    async fn owner_site_ake_route_real_c3_timeout_closes_without_effects() {
        let OwnerSiteAkeFixture {
            provider,
            client,
            effects,
        } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
        let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
        let app =
            owner_site_ake_route(Some(Arc::new(provider))).layer(Extension(ConnectInfo(loopback)));
        let server = TestServer::builder()
            .http_transport()
            .build(app)
            .expect("A2 WS test server");
        let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
        let response = server.get_websocket(path).await;
        assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
        let mut websocket = response.into_websocket().await;

        let (mut client_session, m1) = client.start().expect("M1");
        websocket.send_message(WsMessage::Binary(m1.into())).await;
        let m2 = websocket.receive_bytes().await;
        let m3 = client_session
            .accept_m2_and_make_m3(&m2)
            .expect("M3 after authenticated M2");
        websocket.send_message(WsMessage::Binary(m3.into())).await;
        let s2 = websocket.receive_bytes().await;
        assert!(
            !s2.is_empty(),
            "server reaches PendingFinished before the timeout"
        );

        let close = timeout(Duration::from_secs(2), websocket.receive_bytes())
            .await
            .expect("withheld C3 must expire and close the same WebSocket");
        assert!(close.is_empty(), "timeout cannot reveal raw response bytes");
        let snapshot = effects.snapshot();
        assert_eq!(snapshot.sessions_started, 1);
        assert_eq!(snapshot.challenge_claims, 1);
        assert_eq!(snapshot.validated_pending_finished, 1);
        assert_eq!(snapshot.s2_records_emitted, 1);
        assert_eq!(snapshot.c3_records_accepted, 0);
        assert_eq!(snapshot.post_c3_recheck_rejections, 0);
        assert_eq!(snapshot.completed_m3_closures, 1);
        assert_ake_never_effected(&snapshot);
    }

    #[tokio::test]
    async fn owner_site_ake_route_real_revoke_after_consume_closes_without_effects() {
        let OwnerSiteAkeFixture {
            provider,
            client,
            effects,
        } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
        let harness = provider
            .harness_for_test()
            .expect("test-only A2 harness provider");
        let pause = harness.pause_after_claim_for_harness();
        let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
        let app =
            owner_site_ake_route(Some(Arc::new(provider))).layer(Extension(ConnectInfo(loopback)));
        let server = TestServer::builder()
            .http_transport()
            .build(app)
            .expect("A2 WS test server");
        let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
        let response = server.get_websocket(path).await;
        assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
        let mut websocket = response.into_websocket().await;

        let (mut client_session, m1) = client.start().expect("M1");
        websocket.send_message(WsMessage::Binary(m1.into())).await;
        let m2 = websocket.receive_bytes().await;
        let m3 = client_session
            .accept_m2_and_make_m3(&m2)
            .expect("M3 after authenticated M2");
        websocket.send_message(WsMessage::Binary(m3.into())).await;

        timeout(Duration::from_secs(1), pause.wait_until_reached())
            .await
            .expect("one-shot challenge must be claimed before the re-read");
        harness.revoke_before_recheck_for_harness();
        pause.resume();

        for _ in 0..128 {
            if effects.snapshot().post_claim_recheck_rejections == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let snapshot = effects.snapshot();
        assert_eq!(snapshot.sessions_started, 1);
        assert_eq!(snapshot.challenge_issues, 1);
        assert_eq!(snapshot.challenge_claims, 1);
        assert_eq!(snapshot.validated_pending_finished, 0);
        assert_eq!(snapshot.post_claim_recheck_rejections, 1);
        assert_eq!(snapshot.s2_records_emitted, 0);
        assert_eq!(snapshot.c3_records_accepted, 0);
        assert_eq!(snapshot.post_c3_recheck_rejections, 0);
        assert_eq!(snapshot.completed_m3_closures, 1);
        assert_ake_never_effected(&snapshot);
        assert_eq!(client.action_pop_signature_count(), 1);

        let close = timeout(Duration::from_secs(1), websocket.receive_bytes())
            .await
            .expect("revocation must close the same WebSocket");
        assert!(close.is_empty(), "revocation must emit zero raw bytes");
    }

    #[tokio::test]
    async fn owner_site_ake_route_real_revoke_between_s2_and_c3_closes_without_effects() {
        let OwnerSiteAkeFixture {
            provider,
            client,
            effects,
        } = OwnerSiteAkeHarness::fixture_for_harness("picoclaw").expect("A2 fixture");
        let harness = provider
            .harness_for_test()
            .expect("test-only A2 harness provider");
        let pause = harness.pause_after_s2_for_harness();
        let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
        let app =
            owner_site_ake_route(Some(Arc::new(provider))).layer(Extension(ConnectInfo(loopback)));
        let server = TestServer::builder()
            .http_transport()
            .build(app)
            .expect("A2 WS test server");
        let path = "/api/v1/household/claws/picoclaw/owner-site/ake";
        let response = server.get_websocket(path).await;
        assert_eq!(response.status_code(), StatusCode::SWITCHING_PROTOCOLS);
        let mut websocket = response.into_websocket().await;

        let (mut client_session, m1) = client.start().expect("M1");
        websocket.send_message(WsMessage::Binary(m1.into())).await;
        let m2 = websocket.receive_bytes().await;
        let m3 = client_session
            .accept_m2_and_make_m3(&m2)
            .expect("M3 after authenticated M2");
        websocket.send_message(WsMessage::Binary(m3.into())).await;
        let s2 = websocket.receive_bytes().await;
        assert!(!s2.is_empty(), "S2 must be encrypted before the pause");

        timeout(Duration::from_secs(1), pause.wait_until_reached())
            .await
            .expect("S2 pause must be reached before C3 finalization");
        let before_c3 = effects.snapshot();
        assert_eq!(before_c3.validated_pending_finished, 1);
        assert_eq!(before_c3.s2_records_emitted, 1);
        assert_eq!(before_c3.c3_records_accepted, 0);
        assert_eq!(before_c3.verified_peers, 0);
        assert_eq!(before_c3.mints, 0);
        assert_eq!(before_c3.consumes, 0);
        assert_eq!(before_c3.proxy_dials, 0);
        assert_eq!(before_c3.site_bytes, 0);
        harness.revoke_before_recheck_for_harness();
        let c3 = client_session
            .accept_s2_and_make_c3(&s2)
            .expect("the device can only acknowledge the received S2");
        websocket.send_message(WsMessage::Binary(c3.into())).await;
        pause.resume();

        for _ in 0..128 {
            if effects.snapshot().post_c3_recheck_rejections == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let snapshot = effects.snapshot();
        assert_eq!(snapshot.sessions_started, 1);
        assert_eq!(snapshot.challenge_issues, 1);
        assert_eq!(snapshot.challenge_claims, 1);
        assert_eq!(snapshot.validated_pending_finished, 1);
        assert_eq!(snapshot.post_claim_recheck_rejections, 0);
        assert_eq!(snapshot.s2_records_emitted, 1);
        assert_eq!(snapshot.c3_records_accepted, 0);
        assert_eq!(snapshot.post_c3_recheck_rejections, 1);
        assert_eq!(snapshot.completed_m3_closures, 1);
        assert_ake_never_effected(&snapshot);
        assert_eq!(client.action_pop_signature_count(), 1);

        let close = timeout(Duration::from_secs(1), websocket.receive_bytes())
            .await
            .expect("revoked pending channel must close the same WebSocket");
        assert!(close.is_empty(), "revoke must expose no raw site bytes");
    }

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

    #[tokio::test]
    async fn owner_site_pre_effect_route_is_typed_fail_closed_and_zero_effect() {
        let path_resource = "picoclaw";
        let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");

        // The production router has no owner-site provider in PR1. A valid
        // source alone therefore cannot produce a pre-effect admission.
        let status = owner_site_preflight_request(
            owner_site_route(None),
            path_resource,
            Some(loopback),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // The production no-extension path above is the real default. This
        // empty test provider additionally makes its zero-effect observation
        // explicit without granting a capability.
        let (absent, absent_effects) = OwnerSiteCapabilityStore::unavailable_for_harness();
        let absent = Arc::new(absent);
        let absent_pending = absent.pending_count();
        let status = owner_site_preflight_request(
            owner_site_route(Some(Arc::clone(&absent))),
            path_resource,
            Some(loopback),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(absent.pending_count(), absent_pending);
        assert_owner_site_zero_effects(&absent_effects, 1);

        let (stale, stale_effects) = owner_site_store(
            path_resource,
            "owner-alpha",
            OwnerSiteAuthoritySnapshot::Stale,
        );
        let stale_pending = stale.pending_count();
        let status = owner_site_preflight_request(
            owner_site_route(Some(Arc::clone(&stale))),
            path_resource,
            Some(loopback),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(stale.pending_count(), stale_pending);
        assert_owner_site_zero_effects(&stale_effects, 1);

        let (mismatch, mismatch_effects) = owner_site_store(
            path_resource,
            "owner-alpha",
            OwnerSiteAuthoritySnapshot::Mismatch,
        );
        let mismatch_pending = mismatch.pending_count();
        let status = owner_site_preflight_request(
            owner_site_route(Some(Arc::clone(&mismatch))),
            path_resource,
            Some(loopback),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(mismatch.pending_count(), mismatch_pending);
        assert_owner_site_zero_effects(&mismatch_effects, 1);

        let (revoked, revoked_effects) = owner_site_store(
            path_resource,
            "owner-alpha",
            OwnerSiteAuthoritySnapshot::Revoked,
        );
        let revoked_pending = revoked.pending_count();
        let status = owner_site_preflight_request(
            owner_site_route(Some(Arc::clone(&revoked))),
            path_resource,
            Some(loopback),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(revoked.pending_count(), revoked_pending);
        assert_owner_site_zero_effects(&revoked_effects, 1);

        let resource =
            OwnerSiteResource::from_route_claw(path_resource).expect("owner-site resource");
        let (actor_id, authority) =
            active_authority_fixture("household-alpha", resource).expect("typed authority fixture");
        let (admitted, effects) = owner_site_store(path_resource, &actor_id, authority);
        let admitted_pending = admitted.pending_count();

        // An exact typed capability is the only positive path in PR1. This
        // loopback case exercises the wire harness only; a Mesh success stays
        // deferred until the reviewed VerifiedMesh provider exists. The route
        // still invokes the shared live peer gate before this provider.
        let status = owner_site_preflight_request(
            owner_site_route(Some(Arc::clone(&admitted))),
            path_resource,
            Some(loopback),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(admitted.pending_count(), admitted_pending);
        assert_owner_site_zero_effects(&effects, 1);

        // A different resource cannot use the injected capability.
        let status = owner_site_preflight_request(
            owner_site_route(Some(Arc::clone(&admitted))),
            "otherclaw",
            Some(loopback),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(admitted.pending_count(), admitted_pending);
        assert_owner_site_zero_effects(&effects, 2);

        // The shared live gate still wins over the injected capability: neither
        // an unverified Mesh source nor a missing peer reaches the provider.
        let unverified = SocketAddr::from(([10, 44, 0, 2], 41001));
        for peer in [Some(unverified), None] {
            let status = owner_site_preflight_request(
                owner_site_route(Some(Arc::clone(&admitted))),
                path_resource,
                peer,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "peer={peer:?}");
            assert_eq!(admitted.pending_count(), admitted_pending);
            assert_owner_site_zero_effects(&effects, 2);
        }

        // A terminal attach bearer cannot be presented at this route and the
        // terminal token remains untouched after the rejection.
        let attach_tokens = HouseholdAttachTokenStore::new();
        let attach = attach_tokens.mint(HouseholdAttachScope {
            household_id: "household-alpha".to_string(),
            container: path_resource.to_string(),
            session_id: "workspace-alpha".to_string(),
            actor_person_id: "owner-alpha".to_string(),
        });
        let attach_pending = attach_tokens.pending_count();
        let status = owner_site_preflight_request(
            owner_site_route(Some(Arc::clone(&admitted))),
            path_resource,
            Some(loopback),
            Some(&attach.token),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(attach_tokens.pending_count(), attach_pending);
        assert_eq!(admitted.pending_count(), admitted_pending);
        assert_owner_site_zero_effects(&effects, 2);
    }

    #[tokio::test]
    async fn owner_site_pre_effect_rejections_have_zero_body_and_no_challenge_delta() {
        let path_resource = "picoclaw";
        let loopback: SocketAddr = "127.0.0.1:41001".parse().expect("loopback peer");
        let (store, effects) = OwnerSiteCapabilityStore::unavailable_for_harness();
        let app = owner_site_route(Some(Arc::new(store)));
        let path = format!("/api/v1/household/claws/{path_resource}/owner-site/preflight");
        let response = owner_site_route_response(
            app,
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .extension(ConnectInfo(loopback)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), 1_024)
            .await
            .expect("forbidden body");
        assert!(body.is_empty(), "pre-effect denial must expose zero bytes");
        assert_owner_site_zero_effects(&effects, 1);
    }
}
