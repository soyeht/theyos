//! Terminal handlers.
//!
//!   GET  /api/v1/terminals/containers                  → `handle_containers`
//!   GET  /api/v1/terminals/{container}/pty             → `handle_terminal_pty`     (WebSocket)
//!   GET  /api/v1/terminals/{container}/tmux/panes      → `handle_tmux_list_panes`
//!   POST /api/v1/terminals/{container}/tmux/rename-window → `handle_tmux_rename_window`

use axum::http::StatusCode;
use axum::{
    Json,
    extract::ws::{Message, WebSocket},
    extract::{Path, Query, State, WebSocketUpgrade},
    response::{IntoResponse, Response},
};
use core_rs::error::ApiError;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::auth::AuthUser;
use crate::state::SharedState;

const MAX_CONTAINER_LEN: usize = 128;

/// Validate and normalize a raw container path parameter.
pub(crate) fn validate_container(raw: &str) -> Result<String, ApiError> {
    let container = raw.trim().to_string();
    if container.is_empty() {
        return Err(ApiError::bad_request("invalid container"));
    }
    if container.len() > MAX_CONTAINER_LEN {
        return Err(ApiError::bad_request("container name too long"));
    }
    Ok(container)
}

/// Verify that `session_id` belongs to an active workspace owned by `username`
/// for `container`.  Returns `Err(404)` on mismatch (not 403, to avoid leaking
/// that the workspace exists for another user).
pub(crate) async fn verify_session_owner(
    state: &SharedState,
    session_id: &str,
    container: &str,
    username: &str,
) -> Result<(), ApiError> {
    let db_state = state.clone();
    let sid = session_id.to_string();
    let ctr = container.to_string();
    let usr = username.to_string();
    let owns = core_rs::error::blocking(move || {
        db_state
            .instance_db
            .verify_conversation_owner(&sid, &ctr, &usr)
            .map_err(ApiError::from)
    })
    .await
    .map_err(|e| ApiError::internal(format!("spawn_blocking: {e}")))??;

    if owns {
        Ok(())
    } else {
        Err(ApiError::not_found("session not found"))
    }
}

/// Check if the authenticated user can access the given container's terminal.
///
/// - Unassigned instance (`owner_id`=NULL): admin-only
/// - Assigned instance: owner-only (even admins are denied)
/// - Missing container: 404
///
/// Returns `Err(404)` on denial (not 403, to avoid leaking instance existence).
pub(crate) async fn require_terminal_access(
    state: &SharedState,
    auth: &AuthUser,
    container: &str,
) -> Result<(), ApiError> {
    let st = state.clone();
    let c = container.to_string();
    let owner_result = core_rs::error::blocking(move || {
        st.instance_db
            .get_owner_id_by_container(&c)
            .map_err(ApiError::from)
    })
    .await??;

    match owner_result {
        // Container doesn't exist
        None => Err(ApiError::not_found("container not found")),
        // Unassigned: admin-only
        Some(None) => {
            if auth.role == store_rs::UserRole::Admin {
                Ok(())
            } else {
                Err(ApiError::not_found("container not found"))
            }
        }
        // Assigned: owner-only (even admins denied)
        Some(Some(owner_id)) => {
            if auth.user_id == owner_id {
                Ok(())
            } else {
                Err(ApiError::not_found("container not found"))
            }
        }
    }
}

// ── GET /api/v1/terminals/containers ────────────────────────────────────────

/// Lists containers from active instances (queried from the instance DB).
///
/// # Errors
///
/// Returns `ApiError` if the database query or blocking task fails.
pub async fn handle_containers(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let items = core_rs::error::blocking(move || {
        state
            .instance_db
            .list_accessible_containers(&auth.user_id, auth.role)
            .map_err(ApiError::from)
    })
    .await??;
    Ok(Json(
        json!({"data": items, "has_more": false, "next_cursor": null}),
    ))
}

// ── POST /api/v1/terminals/{container}/reconnect ────────────────────────────

#[derive(Deserialize)]
pub struct ReconnectQuery {
    #[serde(default)]
    pub session: String,
}

/// Reconnects a terminal workspace by killing **all** SSH/PTY sessions for the
/// given workspace, WITHOUT restarting the VM. The base tmux session and its
/// shared windows/panes survive inside the VM, so the next WebSocket connection
/// with the same `session_id` creates a fresh grouped session that reattaches
/// to the same terminal content.
///
/// ## Scope
///
/// This is a workspace-level operation: it disconnects **every** client
/// currently attached to the workspace (browser, mobile, etc.). This matches
/// the pre-grouped-sessions behavior where a single shared `PtySession` was
/// killed, affecting all clients. The endpoint is designed as a recovery
/// action ("force reconnect"), not a per-client operation.
///
/// # Errors
///
/// Returns `ApiError` on invalid container name or blocking-task errors.
#[tracing::instrument(skip(state, q), fields(container = %container))]
pub async fn handle_terminal_reconnect(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(container): Path<String>,
    Query(q): Query<ReconnectQuery>,
) -> Result<Response, ApiError> {
    let container = validate_container(&container)?;
    require_terminal_access(&state, &auth, &container).await?;
    if q.session.is_empty() {
        return Err(ApiError::bad_request("session id required"));
    }
    verify_session_owner(&state, &q.session, &container, &auth.username).await?;

    // v2: no more grouped sessions. Close the single PTY for this conversation.
    // The conversation log on disk is also unlinked by `close`.
    if let Err(e) = state.pty_mgr.close(&container, &q.session) {
        tracing::warn!("[terminal] reconnect close: {e}");
    }

    tracing::info!("terminal reconnect requested: {}", container);
    state.spawn_audit(
        None,
        auth.username,
        "reconnect",
        Some(format!("container={container}")),
    );

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ── POST /api/v1/terminals/{container}/workspace ────────────────────────────

/// Returns a server-owned terminal workspace for the authenticated user
/// and given container. Resumes an existing workspace or creates a new one.
///
/// The `workspace.id` is used as the `sessionId` for the WebSocket PTY
/// connection, ensuring cross-device session continuity.
///
/// # Errors
///
/// Returns `ApiError` on invalid container, missing instance, or DB failure.
#[tracing::instrument(skip(state), fields(container = %container))]
pub async fn handle_terminal_workspace(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(container): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let container = validate_container(&container)?;
    require_terminal_access(&state, &auth, &container).await?;

    // Verify instance exists and is Active.
    let st = state.clone();
    let c = container.clone();
    let row = core_rs::error::blocking(move || {
        st.instance_db.get_by_container(&c).map_err(ApiError::from)
    })
    .await??;

    match row {
        None => return Err(ApiError::not_found("container not found")),
        Some(r) if r.status != store_rs::InstanceStatus::Active => {
            return Err(ApiError::bad_request(format!("vm_{}", r.status)));
        }
        _ => {}
    }

    let st = state.clone();
    let c = container.clone();
    let u = auth.username.clone();
    let ws = core_rs::error::blocking(move || {
        st.instance_db
            .resume_or_create_conversation(&c, &u)
            .map_err(ApiError::from)
    })
    .await??;

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

// ── GET /api/v1/terminals/{container}/workspaces ────────────────────────────

/// Lists all active and inactive workspaces for the authenticated user on
/// the given container. Returns workspaces ordered by most recently attached.
///
/// Includes `isConnected` (true if PTY session is alive) and a `warning`
/// string when the user has 8+ workspaces.
///
/// # Errors
///
/// Returns `ApiError` on invalid container or DB failure.
#[tracing::instrument(skip(state), fields(container = %container))]
pub async fn handle_list_conversations(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(container): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let container = validate_container(&container)?;
    require_terminal_access(&state, &auth, &container).await?;

    let st = state.clone();
    let c = container.clone();
    let u = auth.username.clone();
    let workspaces = core_rs::error::blocking(move || {
        st.instance_db
            .list_conversations(&c, &u)
            .map_err(ApiError::from)
    })
    .await??;

    let pty_mgr = &state.pty_mgr;
    let items: Vec<serde_json::Value> = workspaces
        .iter()
        .map(|ws| {
            let is_connected = pty_mgr
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

    const WARNING_THRESHOLD: usize = 8;
    let mut result = json!({"data": &items, "has_more": false, "next_cursor": null});
    if items.len() > WARNING_THRESHOLD {
        result["warning"] = json!(format!(
            "You have {} sessions. Consider closing unused ones.",
            items.len()
        ));
    }

    Ok(Json(result))
}

// ── POST /api/v1/terminals/{container}/workspaces ───────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreateWorkspaceBody {
    #[serde(default)]
    pub display_name: String,
}

/// Creates a new workspace for the authenticated user on the given container.
/// Unlike `handle_terminal_workspace` (which resumes), this always creates.
///
/// # Errors
///
/// Returns `ApiError` on invalid container, missing instance, or DB failure.
#[tracing::instrument(skip(state, body), fields(container = %container))]
pub async fn handle_create_conversation(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(container): Path<String>,
    Json(body): Json<CreateWorkspaceBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let container = validate_container(&container)?;
    require_terminal_access(&state, &auth, &container).await?;

    // Verify instance exists and is Active.
    let st = state.clone();
    let c = container.clone();
    let row = core_rs::error::blocking(move || {
        st.instance_db.get_by_container(&c).map_err(ApiError::from)
    })
    .await??;

    match row {
        None => return Err(ApiError::not_found("container not found")),
        Some(r) if r.status != store_rs::InstanceStatus::Active => {
            return Err(ApiError::bad_request(format!("vm_{}", r.status)));
        }
        _ => {}
    }

    let display_name = body.display_name;
    let st = state.clone();
    let c = container.clone();
    let u = auth.username.clone();
    let dn = display_name.clone();
    let ws = core_rs::error::blocking(move || {
        st.instance_db
            .create_conversation(&c, &u, &dn)
            .map_err(ApiError::from)
    })
    .await??;

    tracing::info!(
        "workspace created: {} ({}) for {} on {}",
        ws.id,
        display_name,
        auth.username,
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

// ── PATCH /api/v1/terminals/{container}/workspaces/{id} ─────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RenameWorkspaceBody {
    pub display_name: String,
}

/// Renames a workspace's display name.
///
/// # Errors
///
/// Returns `ApiError` on invalid container, ownership mismatch, or DB failure.
#[tracing::instrument(skip(state, body), fields(container = %container, id = %id))]
pub async fn handle_rename_conversation(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path((container, id)): Path<(String, String)>,
    Json(body): Json<RenameWorkspaceBody>,
) -> Result<StatusCode, ApiError> {
    let container = validate_container(&container)?;
    require_terminal_access(&state, &auth, &container).await?;
    let session_id = sanitize_session_id(&id)?;
    verify_session_owner(&state, &session_id, &container, &auth.username).await?;

    let st = state.clone();
    let sid = session_id.clone();
    let dn = body.display_name.clone();
    let updated = core_rs::error::blocking(move || {
        st.instance_db
            .rename_conversation(&sid, &dn)
            .map_err(ApiError::from)
    })
    .await??;

    if !updated {
        return Err(ApiError::not_found("workspace not found"));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── DELETE /api/v1/terminals/{container}/workspaces/{id} ────────────────────

/// Deletes a workspace: kills the tmux session inside the VM, closes the
/// PTY session, and hard-deletes the workspace row.
///
/// # Errors
///
/// Returns `ApiError` on invalid container, ownership mismatch, or DB failure.
#[tracing::instrument(skip(state), fields(container = %container, id = %id))]
pub async fn handle_delete_conversation(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path((container, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let container = validate_container(&container)?;
    require_terminal_access(&state, &auth, &container).await?;
    let session_id = sanitize_session_id(&id)?;
    verify_session_owner(&state, &session_id, &container, &auth.username).await?;

    // v2 canonical delete order: (1) DB row → (2) PTY close → (3) log unlink.
    // Doing DB first ensures new attaches fail immediately with "not found".
    // `pty_mgr.close` handles the log unlink too.

    // 3. Hard-delete the conversation from the DB.
    let st = state.clone();
    let sid = session_id.clone();
    let deleted = core_rs::error::blocking(move || {
        st.instance_db
            .delete_conversation(&sid)
            .map_err(ApiError::from)
    })
    .await??;

    if !deleted {
        return Err(ApiError::not_found("conversation not found"));
    }

    // 4. Close the PTY session (SIGHUP subprocess, unlink log file).
    if let Err(e) = state.pty_mgr.close(&container, &session_id) {
        tracing::warn!("[terminal] delete conversation pty close: {e}");
    }

    tracing::info!(
        "workspace deleted: {} for {} on {}",
        session_id,
        auth.username,
        container
    );
    state.spawn_audit(
        None,
        auth.username,
        "delete_workspace",
        Some(format!("container={container}, workspace={session_id}")),
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── GET /api/v1/terminals/{container}/pty ────────────────────────────────────
// WebSocket PTY: upgrades to WS then pipes input/output to a real PTY session.

/// Maximum length for the raw session ID (before `soyeht_` prefix).
///
/// With grouped sessions, the tmux session name format is:
/// `soyeht_{session_id}_c{client_id}` = 7 + `session_id` + 2 + 8 = `session_id` + 17.
/// The tmux limit is 64 chars → `session_id` ≤ 47. We use 46 for safety margin.
///
/// Existing workspace IDs are 16-char hex strings, well within this limit.
const MAX_SESSION_ID_LEN: usize = 46;

#[derive(Deserialize)]
pub struct PtyQuery {
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub cols: u16,
    #[serde(default)]
    pub rows: u16,
    /// Opt-in to replaying the entire conversation log on attach instead of
    /// just the tail (`TAIL_REPLAY_BYTES`). Defaults to `false`.
    #[serde(default)]
    pub full_replay: bool,
}

/// Validate and normalize a raw session query parameter.
///
/// - Empty → generate a random session ID (no fallback to `"main"` to avoid
///   collisions between tabs/panels/clients).
/// - Non-empty → must be 1-46 chars, `[a-zA-Z0-9_-]` only.
///
/// The validated ID is later prefixed with `soyeht_` by `PtyManager` to form
/// the tmux session name (max 64 chars total).
pub(crate) fn sanitize_session_id(raw: &str) -> Result<String, ApiError> {
    if raw.is_empty() {
        return Err(ApiError::bad_request("session id required"));
    }
    if raw.len() > MAX_SESSION_ID_LEN {
        return Err(ApiError::bad_request("session id too long"));
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::bad_request("invalid session id"));
    }
    Ok(raw.to_string())
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum PtyMessageType {
    Input,
    Resize,
    Init,
}

#[derive(Deserialize)]
struct PtyClientMessage {
    #[serde(rename = "type")]
    msg_type: PtyMessageType,
    #[serde(default)]
    data: String,
    #[serde(default)]
    cols: u16,
    #[serde(default)]
    rows: u16,
}

#[allow(clippy::too_many_lines)]
pub async fn handle_terminal_pty(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(container): Path<String>,
    Query(q): Query<PtyQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let container = match validate_container(&container) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    if let Err(e) = require_terminal_access(&state, &auth, &container).await {
        return e.into_response();
    }

    // Validate and normalize session ID.
    let session_id = match sanitize_session_id(&q.session) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    // Verify the session belongs to this user's workspace.
    if let Err(e) = verify_session_owner(&state, &session_id, &container, &auth.username).await {
        return e.into_response();
    }

    serve_authorized_terminal_pty(state, container, q, ws).await
}

pub(crate) async fn serve_authorized_terminal_pty(
    state: SharedState,
    container: String,
    q: PtyQuery,
    ws: WebSocketUpgrade,
) -> Response {
    let session_id = match sanitize_session_id(&q.session) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    // Lazy-open a PTY session for this conversation. The first WS attach
    // spawns the subprocess + creates the log file; subsequent attaches
    // reuse the same PtySession. Multiple WebSockets on the same
    // conversation coexist — no commander role, no close-4000 dance.
    let pty_mgr = Arc::clone(&state.pty_mgr);

    let cols = if q.cols > 0 { q.cols } else { 80 };
    let rows = if q.rows > 0 { q.rows } else { 24 };

    let sess = {
        let pm = Arc::clone(&pty_mgr);
        let c = container.clone();
        let s = session_id.clone();
        match tokio::task::spawn_blocking(move || pm.start(&c, &s, cols, rows)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return ApiError::from(e).into_response(),
            Err(e) => return ApiError::internal(e.to_string()).into_response(),
        }
    };

    // v2: persist log_path in DB on first lazy-open so diagnostics can find it.
    {
        let sid = session_id.clone();
        let log_path = sess.log().path().to_string_lossy().into_owned();
        let st = Arc::clone(&state);
        tokio::task::spawn_blocking(move || {
            let _ = st.instance_db.set_conversation_log_path(&sid, &log_path);
        });
    }

    let ctx = PtyWsContext {
        state: Arc::clone(&state),
        workspace_id: session_id,
    };
    let full_replay = q.full_replay;
    ws.on_upgrade(move |socket| serve_pty_websocket(socket, sess, cols, rows, full_replay, ctx))
}

// ── Local (broker-owned) terminals — persistent panes ─────────────────────
//
// The Soyeht macOS app routes local pane PTYs through the engine so agent
// processes survive app restarts/updates. The app resolves argv/cwd/env and
// the engine only executes. Spawning a local command is host code execution
// by design: these endpoints are loopback-only and require the same
// authentication as every other terminal endpoint.

#[derive(Deserialize)]
pub struct LocalTerminalCreateRequest {
    pub conversation_id: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub cols: u16,
    #[serde(default)]
    pub rows: u16,
}

/// `POST /api/v1/terminals/local` — create (or reattach to) a broker-owned
/// local PTY session. Idempotent per `conversation_id`: an existing live
/// session is returned as-is, so app relaunch can blindly re-issue creates.
/// The response's `reconnected` field tells the two cases apart (`true` =
/// returned an existing live session; `false` = spawned a new process), so
/// the caller can say "conversation restored" only when it's actually true.
pub async fn handle_local_terminal_create(
    State(state): State<SharedState>,
    _auth: AuthUser,
    Json(req): Json<LocalTerminalCreateRequest>,
) -> Response {
    if req.argv.is_empty() {
        return ApiError::bad_request("argv must not be empty").into_response();
    }
    let spec = terminal_rs::pty::LocalSpawnSpec {
        argv: req.argv,
        cwd: req.cwd.map(std::path::PathBuf::from),
        env: req.env,
    };
    let cols = if req.cols > 0 { req.cols } else { 80 };
    let rows = if req.rows > 0 { req.rows } else { 24 };

    let pm = Arc::clone(&state.pty_mgr);
    let conv_id = req.conversation_id.clone();
    match tokio::task::spawn_blocking(move || pm.start_local(&conv_id, &spec, cols, rows)).await {
        Ok(Ok((sess, reconnected))) => (
            StatusCode::OK,
            Json(json!({
                "conversation_id": req.conversation_id,
                "ws_path": format!("/api/v1/terminals/local/{}/pty", req.conversation_id),
                "slave_tty_path": sess.slave_tty_path(),
                // True when an existing live session was returned as-is;
                // false when a new process had to be spawned. Lets the
                // client say "conversation restored" only when it's true.
                "reconnected": reconnected,
            })),
        )
            .into_response(),
        Ok(Err(e)) => ApiError::from(e).into_response(),
        Err(e) => ApiError::internal(e.to_string()).into_response(),
    }
}

/// `GET /api/v1/terminals/local` — lists every broker-owned local session
/// (live or not-yet-reaped), with the metadata `soyeht-mcp` needs to map a
/// TTY back to the pane that owns it.
pub async fn handle_local_terminal_list(State(state): State<SharedState>, _auth: AuthUser) -> Response {
    let pm = Arc::clone(&state.pty_mgr);
    match tokio::task::spawn_blocking(move || pm.list_local()).await {
        Ok(sessions) => {
            let items: Vec<serde_json::Value> = sessions
                .iter()
                .map(|s| {
                    json!({
                        "conversation_id": s.conversation_id,
                        "slave_tty_path": s.slave_tty_path,
                        "pgid": s.pgid,
                        "cwd": s.cwd.to_string_lossy(),
                        "is_connected": s.is_connected,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({"data": items, "has_more": false, "next_cursor": null})),
            )
                .into_response()
        }
        Err(e) => ApiError::internal(e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct LocalPtyQuery {
    #[serde(default)]
    cols: u16,
    #[serde(default)]
    rows: u16,
    /// Opt-in to replaying the entire conversation log on attach instead of
    /// just the tail (`TAIL_REPLAY_BYTES`). Defaults to `false`.
    #[serde(default)]
    full_replay: bool,
}

/// `GET /api/v1/terminals/local/{conversation_id}/pty` — attach a WebSocket
/// to an existing broker-owned local session (404 if it is not running; the
/// client must create it first so the spawn spec is always explicit).
pub async fn handle_local_terminal_pty(
    State(state): State<SharedState>,
    _auth: AuthUser,
    Path(conversation_id): Path<String>,
    Query(q): Query<LocalPtyQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(sess) = state.pty_mgr.get_local(&conversation_id) else {
        return ApiError::not_found("local session not found").into_response();
    };
    if sess.is_closed() {
        return ApiError::not_found("local session has exited").into_response();
    }

    let cols = if q.cols > 0 { q.cols } else { 80 };
    let rows = if q.rows > 0 { q.rows } else { 24 };
    let ctx = PtyWsContext {
        state: Arc::clone(&state),
        workspace_id: conversation_id,
    };
    let full_replay = q.full_replay;
    ws.on_upgrade(move |socket| serve_pty_websocket(socket, sess, cols, rows, full_replay, ctx))
}

/// `DELETE /api/v1/terminals/local/{conversation_id}` — close a broker-owned
/// session (kills the child, removes the conversation log).
pub async fn handle_local_terminal_delete(
    State(state): State<SharedState>,
    _auth: AuthUser,
    Path(conversation_id): Path<String>,
) -> Response {
    let pm = Arc::clone(&state.pty_mgr);
    match tokio::task::spawn_blocking(move || pm.close_local(&conversation_id)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(e)) => ApiError::from(e).into_response(),
        Err(e) => ApiError::internal(e.to_string()).into_response(),
    }
}

/// Run a shell command inside a VM via `<ctl> exec <container> <cmd>`.
/// Used by the file browser to execute Python snippets in the guest.
async fn ssh_exec(state: &SharedState, container: &str, cmd: &str) -> Result<String, ApiError> {
    let ctl_path = state.pty_mgr.ctl_path().to_string();
    let ctr = container.to_string();
    let command = cmd.to_string();
    let result = tokio::task::spawn_blocking(move || {
        std::process::Command::new(&ctl_path)
            .args(["exec", &ctr, &command])
            .output()
    })
    .await
    .map_err(|e| ApiError::internal(format!("ssh_exec join: {e}")))?
    .map_err(|e| ApiError::internal(format!("ssh_exec spawn: {e}")))?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(ApiError::internal(format!(
            "ssh_exec failed: {}",
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}

/// Bundled context for `serve_pty_websocket` to stay under the clippy arg limit.
struct PtyWsContext {
    state: SharedState,
    workspace_id: String,
}

/// Prefix for in-band control markers embedded in Binary frames. iOS/macOS
/// clients recognize this sentinel and treat the rest of the frame as a
/// metadata control signal (never fed to the terminal parser). The web UI
/// currently treats ALL Binary as control, so markers are ignored there too.
const CTL_PREFIX: &[u8] = b"\x00\x01CTL:";

/// Replay file chunk size streamed over WS.
const REPLAY_CHUNK: usize = 64 * 1024;

/// Default replay window on reattach: only the last `TAIL_REPLAY_BYTES` of
/// the conversation log are streamed, instead of the entire file. A long-
/// running session's log can reach hundreds of MB; replaying all of it on
/// every reattach is slow and risks the live-broadcast subscriber (capacity
/// `BROADCAST_CAP` in `terminal-rs::pty`) lagging before the replay catches
/// up. Callers that need the full history can opt in with `full_replay=true`.
const TAIL_REPLAY_BYTES: u64 = 2 * 1024 * 1024;

/// Bound on a single WS frame send (replay or live forward). A stalled or
/// frozen peer — TCP send buffer never draining — would otherwise block
/// `socket.send(...).await` indefinitely, holding this task and the PTY log
/// file descriptor it keeps open for the rest of the session's lifetime.
const WS_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Sends `msg` on `socket`, bounded by `WS_SEND_TIMEOUT`. Returns `true` on
/// success; `false` on a send error OR a timeout — callers treat both the
/// same way a plain `.is_err()` would: the connection is presumed dead.
async fn send_with_timeout(socket: &mut WebSocket, msg: Message) -> bool {
    matches!(
        tokio::time::timeout(WS_SEND_TIMEOUT, socket.send(msg)).await,
        Ok(Ok(()))
    )
}

/// Computes the (possibly clamped) replay window `[replay_from, cursor]`
/// for a WS reattach. Returns `(replay_from, clamped_cursor)` — the caller
/// re-binds its `cursor` variable to the second value.
///
/// `cursor` is clamped up to `base_offset` FIRST. `cursor` is snapshotted
/// well before this is called (before a real WS send and a
/// `replay_guard()` acquire, both genuine await points), so a rotation can
/// land in that gap and advance `base_offset` past a now-stale `cursor` —
/// the entire range up to that old snapshot was rotated off disk before it
/// was ever read. Clamping `cursor` up first keeps every downstream
/// computation (`replay_from`, the physical seek offset, the remaining
/// byte count) safe against underflow: clamping `replay_from` alone cannot
/// simultaneously satisfy `replay_from <= cursor` and
/// `replay_from >= base_offset` when `cursor < base_offset`, but clamping
/// `cursor` first collapses both sides to `base_offset` in that case,
/// yielding a correct (empty) window instead of an inverted one.
fn compute_replay_window(cursor: u64, base_offset: u64, full_replay: bool) -> (u64, u64) {
    let cursor = cursor.max(base_offset);
    let replay_from = if full_replay {
        base_offset
    } else {
        cursor.saturating_sub(TAIL_REPLAY_BYTES).max(base_offset)
    };
    (replay_from, cursor)
}

/// v2 WebSocket event loop: stream a bounded tail of the conversation log
/// from disk as replay, then forward live broadcast (de-duplicated by
/// end-offset cursor).
///
/// Flow:
/// 1. Subscribe to broadcast FIRST (captures live bytes arriving during replay).
/// 2. Read `cursor = log.size` AFTER subscribing (source of truth).
/// 3. Send Binary `CTL:replay_start`.
/// 4. Compute the initial replay window under a brief `log.replay_guard()`
///    acquire: `replay_from` is `base_offset` when `full_replay` is set or
///    the log fits within `TAIL_REPLAY_BYTES`; otherwise
///    `max(cursor - TAIL_REPLAY_BYTES, base_offset)` — history the log has
///    rotated away is gone even under `full_replay`. When `replay_from > 0`,
///    send Binary `CTL:replay_truncated` — the client knows history before
///    that marker was dropped.
/// 5. Stream log file asynchronously from `replay_from` to `cursor`, one
///    bounded `REPLAY_CHUNK` at a time (translating to a physical seek
///    position by subtracting `base_offset`), as Binary raw frames.
///    `replay_guard()` is re-acquired per chunk (seek+read only) and never
///    held across the network send, so a slow/frozen peer stalls only its
///    own reattach, never a concurrent rotation.
/// 6. Send Binary `CTL:replay_done`.
/// 7. Re-sync: keep streaming from the log if it grew during replay.
/// 8. Enter live forward loop: drop chunks with `end_offset <= cursor`.
///
/// Every WS send (replay, live forward, control markers, ping) goes through
/// [`send_with_timeout`], so a stalled/frozen peer cannot hold this task —
/// and the PTY log file descriptor it keeps open — indefinitely.
///
/// Input handling: JSON Text frames (`input` / `resize` / `init`) processed
/// concurrently. Writes to the PTY are serialized by `PtySession::write`'s
/// internal `write_lock`.
#[allow(clippy::too_many_lines)]
async fn serve_pty_websocket(
    mut socket: WebSocket,
    sess: Arc<terminal_rs::pty::PtySession>,
    initial_cols: u16,
    initial_rows: u16,
    full_replay: bool,
    ctx: PtyWsContext,
) {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    use tokio::time::{Duration, interval};

    let state = ctx.state;
    let workspace_id = ctx.workspace_id;

    // Apply initial resize if the client supplied dimensions that differ from
    // the current PTY size. v2: no buffer clear — the log keeps growing.
    let pty_size = sess.current_size();
    if (initial_cols, initial_rows) != (0, 0) && pty_size != (initial_cols, initial_rows) {
        if let Err(e) = sess.resize(initial_cols.max(1), initial_rows.max(1)) {
            tracing::debug!("[pty-ws] initial resize: {e}");
        }
    }

    // ── Step 1: subscribe BEFORE reading cursor to avoid losing bytes ──
    let mut rx = sess.subscribe();

    // ── Step 2: snapshot cursor from atomic size counter ──
    let log = sess.log();
    let mut cursor = log.current_size();

    // ── Step 3: replay_start marker ──
    let mut marker = Vec::with_capacity(CTL_PREFIX.len() + 12);
    marker.extend_from_slice(CTL_PREFIX);
    marker.extend_from_slice(b"replay_start");
    if !send_with_timeout(&mut socket, Message::Binary(marker.into())).await {
        return;
    }

    // ── Step 4: compute the initial replay window and flag truncation ──
    // Bytes beyond `cursor` are forwarded live via the broadcast channel in
    // step 8, which drops messages with `end_offset <= cursor` to avoid
    // duplicates. Previously this streamed the entire log (`0..cursor`) on
    // every reattach — for a long-running session that means replaying
    // hundreds of MB of history the client already has, and it risks the
    // broadcast subscriber lagging (fixed capacity) before replay catches up.
    let (mut pos, replay_to) = {
        let _guard = log.replay_guard().await;
        compute_replay_window(cursor, log.base_offset(), full_replay)
    };
    cursor = replay_to;
    if pos > 0 {
        let mut marker = Vec::with_capacity(CTL_PREFIX.len() + 17);
        marker.extend_from_slice(CTL_PREFIX);
        marker.extend_from_slice(b"replay_truncated");
        if !send_with_timeout(&mut socket, Message::Binary(marker.into())).await {
            return;
        }
    }

    // ── Step 5: stream log file pos..replay_to, one bounded chunk at a time ──
    // `replay_guard()` is acquired fresh for each chunk's seek+read, never
    // held across the network send: a slow/frozen peer can stall
    // `socket.send` for up to `WS_SEND_TIMEOUT`, and holding the guard
    // across that would block `ConversationLog::append`'s rotation for the
    // same span — one stalled reattach could stall every writer of the
    // session's live output. `base_offset` is re-read on every iteration
    // because a rotation can land in the gap between chunks (guard
    // released for the send) and shift it forward past `pos`; when it
    // does, `[pos, base_offset)` was dropped by rotation before this loop
    // reached it — the same tolerated history loss `compute_replay_window`
    // already accepts up front, just discovered one chunk later. The
    // reader stays open across iterations: rotation mutates the log file
    // in place via the same path/inode (see `rotate_file`), so an
    // already-open fd sees rotated content correctly once re-seeked — only
    // the guard's scope shrinks to a single seek+read pair.
    let mut reader = match tokio::fs::File::open(log.path()).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("[pty-ws] open log for replay: {e}");
            return;
        }
    };
    while pos < replay_to {
        let chunk = {
            let _guard = log.replay_guard().await;
            let base_offset = log.base_offset();
            pos = pos.max(base_offset);
            if pos >= replay_to {
                None
            } else {
                // Physical file position 0 == logical offset `base_offset`.
                let phys_from = pos - base_offset;
                if let Err(e) = reader.seek(std::io::SeekFrom::Start(phys_from)).await {
                    tracing::error!("[pty-ws] seek log for replay: {e}");
                    return;
                }
                let take = usize::try_from(replay_to - pos)
                    .unwrap_or(usize::MAX)
                    .min(REPLAY_CHUNK);
                let mut buf = vec![0u8; take];
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => None,
                    Ok(n) => {
                        buf.truncate(n);
                        Some(buf)
                    }
                }
            }
        };
        let Some(buf) = chunk else {
            // Nothing left in the window, or a short read/error — let the
            // live loop catch up.
            break;
        };
        pos += u64::try_from(buf.len()).unwrap_or(u64::MAX);
        if !send_with_timeout(&mut socket, Message::Binary(buf.into())).await {
            return;
        }
    }

    // ── Step 6: replay_done marker ──
    let mut marker = Vec::with_capacity(CTL_PREFIX.len() + 11);
    marker.extend_from_slice(CTL_PREFIX);
    marker.extend_from_slice(b"replay_done");
    let _ = send_with_timeout(&mut socket, Message::Binary(marker.into())).await;

    // ── Step 8: live forward loop + input handling ──
    let mut ping_ticker = interval(Duration::from_secs(30));
    ping_ticker.tick().await;
    let mut last_pong = tokio::time::Instant::now();
    let mut activity_ticker = interval(Duration::from_secs(60));
    activity_ticker.tick().await;
    let mut activity_dirty = false;

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok((end_offset, bytes)) => {
                        if bytes.is_empty() { continue; }
                        let start_offset = end_offset.saturating_sub(bytes.len() as u64);
                        let to_send: &[u8] = if end_offset <= cursor {
                            // Already in replay — drop.
                            continue;
                        } else if start_offset < cursor {
                            // Chunk straddles the cursor — send the tail.
                            let skip = usize::try_from(cursor - start_offset).unwrap_or(0);
                            &bytes[skip..]
                        } else {
                            &bytes[..]
                        };
                        if !send_with_timeout(&mut socket, Message::Binary(to_send.to_vec().into())).await {
                            break;
                        }
                        cursor = end_offset;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("[pty-ws] subscriber lagged by {n} chunks, closing");
                        let mut m = Vec::with_capacity(CTL_PREFIX.len() + 17);
                        m.extend_from_slice(CTL_PREFIX);
                        m.extend_from_slice(b"subscriber_lagged");
                        let _ = send_with_timeout(&mut socket, Message::Binary(m.into())).await;
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        let mut m = Vec::with_capacity(CTL_PREFIX.len() + 13);
                        m.extend_from_slice(CTL_PREFIX);
                        m.extend_from_slice(b"session_ended");
                        let _ = send_with_timeout(&mut socket, Message::Binary(m.into())).await;
                        break;
                    }
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<PtyClientMessage>(&text) {
                            Ok(client_msg) => match client_msg.msg_type {
                                PtyMessageType::Input if !client_msg.data.is_empty() => {
                                    if sess.write(client_msg.data.as_bytes()).await.is_err() {
                                        break;
                                    }
                                    activity_dirty = true;
                                }
                                PtyMessageType::Input => {}
                                PtyMessageType::Resize | PtyMessageType::Init => {
                                    let (nc, nr) = (client_msg.cols.max(1), client_msg.rows.max(1));
                                    if let Err(e) = sess.resize(nc, nr) {
                                        tracing::debug!("[pty-ws] resize: {e}");
                                    }
                                }
                            },
                            Err(e) => tracing::debug!("[pty-ws] unknown client message: {e}"),
                        }
                    }
                    Some(Ok(Message::Pong(_))) => { last_pong = tokio::time::Instant::now(); }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    _ => {}
                }
            }
            _ = ping_ticker.tick() => {
                if last_pong.elapsed() > Duration::from_secs(90) {
                    tracing::warn!("[pty-ws] pong timeout (>90s), closing stale connection");
                    break;
                }
                if !send_with_timeout(&mut socket, Message::Ping(vec![].into())).await {
                    break;
                }
            }
            _ = activity_ticker.tick() => {
                if activity_dirty {
                    activity_dirty = false;
                    let st = Arc::clone(&state);
                    let wid = workspace_id.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = st.instance_db.touch_activity(&wid);
                    }).await;
                }
            }
        }
    }

    // ── Cleanup: detach this subscriber. PTY session itself keeps running
    // (conversation lifetime is controlled by DELETE, not WS close).
    drop(rx);

    // Final touch on disconnect if there was pending activity.
    if activity_dirty {
        let st = Arc::clone(&state);
        let wid = workspace_id.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = st.instance_db.touch_activity(&wid);
        })
        .await;
    }
}

// ── File browser ────────────────────────────────────────────────────────────

/// Maximum length for a user-supplied absolute/relative filesystem path.
const MAX_FS_PATH_LEN: usize = 4096;
/// Maximum bytes returned by `GET /files/read` (cap enforced server-side).
const MAX_FILE_READ_BYTES: usize = 512 * 1024;
/// Default read size when the client omits `max_bytes`.
const DEFAULT_FILE_READ_BYTES: usize = 64 * 1024;

const fn default_max_bytes() -> usize {
    DEFAULT_FILE_READ_BYTES
}

fn default_path() -> String {
    "~".to_string()
}

const PYTHON_STDIN_HEREDOC: &str = "__THEYOS_PY__";

/// Build a shell command that executes Python from stdin via a quoted heredoc.
///
/// Arguments are passed as regular argv items after `python3 -`. Callers must
/// sanitize any user-controlled arguments before passing them here.
fn build_python_stdin_command(script: &str, args: &[&str]) -> String {
    let trimmed = script.trim_matches('\n');
    let tag = PYTHON_STDIN_HEREDOC;
    let mut cmd = String::from("python3 -");
    for arg in args {
        cmd.push(' ');
        cmd.push('\'');
        cmd.push_str(arg);
        cmd.push('\'');
    }
    cmd.push_str(" <<'");
    cmd.push_str(tag);
    cmd.push_str("'\n");
    cmd.push_str(trimmed);
    cmd.push('\n');
    cmd.push_str(tag);
    cmd
}

/// Validate a user-supplied filesystem path string. Rejects shell-metacharacter
/// patterns and control characters. The path is *not* resolved — it is passed
/// verbatim to a Python program inside the VM that uses `os.path.expanduser`.
fn sanitize_fs_path(raw: &str) -> Result<String, ApiError> {
    if raw.is_empty() {
        return Err(ApiError::bad_request("path required"));
    }
    if raw.len() > MAX_FS_PATH_LEN {
        return Err(ApiError::bad_request("path too long"));
    }
    // Reject shell metacharacters so the path can be safely embedded as a
    // Python string literal. Python receives the path as a argv argument, but
    // we also block NUL and the quote chars that would break literal quoting.
    for c in raw.chars() {
        if c == '\0' || c == '\n' || c == '\r' || c == '\'' || c == '"' || c == '\\' {
            return Err(ApiError::bad_request("invalid path characters"));
        }
    }
    // Reject path-traversal-ish patterns that have no legitimate use in the
    // browser context. `..` on its own or as a component is blocked.
    for comp in raw.split('/') {
        if comp == ".." {
            return Err(ApiError::bad_request("path traversal not allowed"));
        }
    }
    Ok(raw.to_string())
}

#[derive(Deserialize)]
pub struct FilesQuery {
    #[serde(default)]
    pub session: String,
    #[serde(default = "default_path")]
    pub path: String,
}

/// `GET /api/v1/terminals/{container}/files?session=X&path=~/foo`
///
/// Lists directory entries at `path` inside the VM. Returns structured JSON
/// generated by a Python one-liner running via `fc-ssh exec` — never by
/// parsing `ls` output (which is fragile across locales and filenames).
///
/// # Errors
///
/// Returns `ApiError` on invalid input, ownership mismatch, or filesystem
/// failure (path not found, not a directory, permission denied).
pub async fn handle_files_list(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(container): Path<String>,
    Query(q): Query<FilesQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let container = validate_container(&container)?;
    require_terminal_access(&state, &auth, &container).await?;
    let session_id = sanitize_session_id(&q.session)?;
    verify_session_owner(&state, &session_id, &container, &auth.username).await?;
    let path = sanitize_fs_path(&q.path)?;

    // Python program that prints a JSON document. We feed it via stdin using
    // a quoted heredoc so the script preserves real newlines.
    let py = r#"
import os, sys, json, stat, time
p = os.path.expanduser(sys.argv[1])
if not os.path.isdir(p):
    print(json.dumps({"error": "not_a_directory"}))
    sys.exit(0)
entries = []
try:
    for name in sorted(os.listdir(p)):
        full = os.path.join(p, name)
        try:
            st = os.lstat(full)
        except OSError:
            continue
        mode = st.st_mode
        if stat.S_ISDIR(mode): kind = "dir"
        elif stat.S_ISLNK(mode): kind = "symlink"
        elif stat.S_ISREG(mode): kind = "file"
        else: kind = "other"
        perms = stat.filemode(mode)[1:10]
        entries.append({
            "name": name,
            "kind": kind,
            "size": int(st.st_size),
            "modified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)),
            "permissions": perms,
        })
    print(json.dumps({"path": p, "entries": entries}))
except PermissionError:
    print(json.dumps({"error": "permission_denied"}))
"#;

    let cmd = build_python_stdin_command(py, &[&path]);
    let output = ssh_exec(&state, &container, &cmd).await?;

    let parsed: serde_json::Value = serde_json::from_str(output.trim())
        .map_err(|e| ApiError::internal(format!("files_list parse: {e}")))?;

    if let Some(err) = parsed.get("error").and_then(|v| v.as_str()) {
        return match err {
            "not_a_directory" => Err(ApiError::bad_request("not a directory")),
            "permission_denied" => Err(ApiError::not_found("path not found")),
            other => Err(ApiError::internal(format!("files_list: {other}"))),
        };
    }

    let resolved_path = parsed
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or(&path)
        .to_string();
    let entries = parsed
        .get("entries")
        .cloned()
        .unwrap_or_else(|| serde_json::Value::Array(vec![]));

    Ok(Json(json!({
        "path": resolved_path,
        "entries": entries,
        "has_more": false,
        "next_cursor": null
    })))
}

#[derive(Deserialize)]
pub struct FileReadQuery {
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub path: String,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
}

#[derive(Deserialize)]
pub struct FileDownloadQuery {
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub path: String,
}

/// `GET /api/v1/terminals/{container}/files/read?session=X&path=~/foo.txt&max_bytes=65536`
///
/// Returns the first `max_bytes` bytes of the file. `max_bytes` is capped at
/// 512 KB server-side. The response body is sent as `text/plain; charset=utf-8`
/// when the content is valid UTF-8; otherwise `application/octet-stream`.
///
/// # Errors
///
/// Returns `ApiError` on invalid input, ownership mismatch, or filesystem
/// failure (path not found, is a directory, permission denied).
pub async fn handle_files_read(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(container): Path<String>,
    Query(q): Query<FileReadQuery>,
) -> Result<Response, ApiError> {
    let container = validate_container(&container)?;
    require_terminal_access(&state, &auth, &container).await?;
    let session_id = sanitize_session_id(&q.session)?;
    verify_session_owner(&state, &session_id, &container, &auth.username).await?;
    let path = sanitize_fs_path(&q.path)?;

    let capped = q.max_bytes.clamp(1, MAX_FILE_READ_BYTES);

    // Python wrapper: resolve ~, reject directories, emit at most `max_bytes`.
    let py = r#"
import os, sys
p = os.path.expanduser(sys.argv[1])
n = int(sys.argv[2])
if os.path.isdir(p):
    sys.stderr.write("is_a_directory")
    sys.exit(2)
try:
    fd = os.open(p, os.O_RDONLY)
except FileNotFoundError:
    sys.stderr.write("not_found")
    sys.exit(3)
except PermissionError:
    sys.stderr.write("permission_denied")
    sys.exit(4)
try:
    data = os.read(fd, n)
finally:
    os.close(fd)
sys.stdout.buffer.write(data)
"#;

    let capped_str = capped.to_string();
    let cmd = build_python_stdin_command(py, &[&path, &capped_str]);
    let ctl_path = state.pty_mgr.ctl_path().to_string();
    let ctr = container.clone();
    let bytes = core_rs::error::blocking(move || -> Result<Vec<u8>, ApiError> {
        let output = std::process::Command::new(&ctl_path)
            .args(["exec", &ctr, &cmd])
            .output()
            .map_err(|e| ApiError::internal(format!("fc-ssh exec: {e}")))?;
        if output.status.success() {
            return Ok(output.stdout);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = stderr.trim();
        Err(match msg {
            m if m.contains("not_found") => ApiError::not_found("file not found"),
            m if m.contains("is_a_directory") => ApiError::bad_request("is a directory"),
            m if m.contains("permission_denied") => ApiError::not_found("file not found"),
            other => ApiError::internal(format!("files_read: {other}")),
        })
    })
    .await??;

    let is_utf8 = std::str::from_utf8(&bytes).is_ok();
    let content_type = if is_utf8 {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    };

    // Derive a safe filename for Content-Disposition. Strip path, drop any
    // quote-like characters (already blocked by sanitize_fs_path, but keep
    // it defensive).
    let filename: String = path
        .rsplit('/')
        .next()
        .unwrap_or("file")
        .chars()
        .filter(|c| *c != '"' && *c != '\\' && *c != '\n' && *c != '\r')
        .collect();
    let disposition = format!("inline; filename=\"{filename}\"");

    Ok(axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("content-type", content_type)
        .header("content-disposition", disposition)
        .body(axum::body::Body::from(bytes))
        .unwrap_or_else(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

/// `GET /api/v1/terminals/{container}/files/download?session=X&path=~/foo.pdf`
///
/// Returns the full file contents so the iOS client can persist the file
/// locally and hand it to Quick Look / share sheets. Uses the same auth and
/// path sanitization as `/files/read`.
///
/// # Errors
///
/// Returns an error if auth, container validation, or the remote file read fails.
pub async fn handle_files_download(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(container): Path<String>,
    Query(q): Query<FileDownloadQuery>,
) -> Result<Response, ApiError> {
    let container = validate_container(&container)?;
    require_terminal_access(&state, &auth, &container).await?;
    let session_id = sanitize_session_id(&q.session)?;
    verify_session_owner(&state, &session_id, &container, &auth.username).await?;
    let path = sanitize_fs_path(&q.path)?;

    let py = r#"
import os, sys
p = os.path.expanduser(sys.argv[1])
if os.path.isdir(p):
    sys.stderr.write("is_a_directory")
    sys.exit(2)
try:
    fd = os.open(p, os.O_RDONLY)
except FileNotFoundError:
    sys.stderr.write("not_found")
    sys.exit(3)
except PermissionError:
    sys.stderr.write("permission_denied")
    sys.exit(4)
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        sys.stdout.buffer.write(chunk)
finally:
    os.close(fd)
"#;

    let cmd = build_python_stdin_command(py, &[&path]);
    let ctl_path = state.pty_mgr.ctl_path().to_string();
    let ctr = container.clone();
    let bytes = core_rs::error::blocking(move || -> Result<Vec<u8>, ApiError> {
        let output = std::process::Command::new(&ctl_path)
            .args(["exec", &ctr, &cmd])
            .output()
            .map_err(|e| ApiError::internal(format!("fc-ssh exec: {e}")))?;
        if output.status.success() {
            return Ok(output.stdout);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = stderr.trim();
        Err(match msg {
            m if m.contains("not_found") => ApiError::not_found("file not found"),
            m if m.contains("is_a_directory") => ApiError::bad_request("is a directory"),
            m if m.contains("permission_denied") => ApiError::not_found("file not found"),
            other => ApiError::internal(format!("files_download: {other}")),
        })
    })
    .await??;

    let filename: String = path
        .rsplit('/')
        .next()
        .unwrap_or("file")
        .chars()
        .filter(|c| *c != '"' && *c != '\\' && *c != '\n' && *c != '\r')
        .collect();
    let disposition = format!("attachment; filename=\"{filename}\"");

    Ok(axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("content-disposition", disposition)
        .header("content-length", bytes.len().to_string())
        .body(axum::body::Body::from(bytes))
        .unwrap_or_else(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_replay_window_normal_case_unaffected() {
        // No rotation raced us: base_offset is well behind cursor, ordinary
        // tail-replay math applies unchanged.
        let (replay_from, cursor) = compute_replay_window(10_000_000, 0, false);
        assert_eq!(cursor, 10_000_000);
        assert_eq!(replay_from, 10_000_000 - TAIL_REPLAY_BYTES);
    }

    #[test]
    fn compute_replay_window_full_replay_starts_at_base_offset() {
        let (replay_from, cursor) = compute_replay_window(10_000_000, 500, true);
        assert_eq!(cursor, 10_000_000);
        assert_eq!(replay_from, 500);
    }

    #[test]
    fn compute_replay_window_clamps_stale_cursor_forward_no_underflow() {
        // Regression (jovian review, fix B): a rotation raced the awaits
        // between snapshotting `cursor` and acquiring the replay guard,
        // advancing `base_offset` PAST the stale `cursor`. Naively computing
        // `cursor.saturating_sub(TAIL).max(base_offset)` would then exceed
        // `cursor`, underflowing `cursor - replay_from` downstream (panic in
        // debug, wraparound/duplicate-or-garbage bytes in release).
        let stale_cursor = 100;
        let base_offset = 500; // rotated past the stale cursor while we awaited
        let (replay_from, cursor) = compute_replay_window(stale_cursor, base_offset, false);
        assert_eq!(cursor, base_offset, "cursor must be clamped forward, never left stale");
        assert_eq!(replay_from, base_offset);
        assert!(replay_from <= cursor, "must never underflow cursor - replay_from downstream");
        assert!(replay_from >= base_offset, "must never underflow replay_from - base_offset (phys_from) downstream");
    }

    #[test]
    fn compute_replay_window_clamps_stale_cursor_forward_even_under_full_replay() {
        let stale_cursor = 100;
        let base_offset = 500;
        let (replay_from, cursor) = compute_replay_window(stale_cursor, base_offset, true);
        assert_eq!(cursor, base_offset);
        assert_eq!(replay_from, base_offset);
    }

    #[test]
    fn compute_replay_window_never_produces_inverted_range() {
        // Property check across a spread of values: replay_from must always
        // fall within [base_offset, cursor] — never outside it in either
        // direction, regardless of how `cursor` and `base_offset` relate.
        for cursor in [0u64, 1, 500, 999, 1_000, 1_001, 5_000_000] {
            for base_offset in [0u64, 1, 500, 1_000, 2_000_000] {
                for full_replay in [false, true] {
                    let (replay_from, clamped_cursor) =
                        compute_replay_window(cursor, base_offset, full_replay);
                    assert!(
                        clamped_cursor >= base_offset,
                        "cursor={cursor} base_offset={base_offset} full_replay={full_replay}"
                    );
                    assert!(
                        replay_from <= clamped_cursor,
                        "cursor={cursor} base_offset={base_offset} full_replay={full_replay}"
                    );
                    assert!(
                        replay_from >= base_offset,
                        "cursor={cursor} base_offset={base_offset} full_replay={full_replay}"
                    );
                }
            }
        }
    }
}
