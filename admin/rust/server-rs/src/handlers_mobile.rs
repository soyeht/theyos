//! Mobile API handlers — QR-based authentication for the Flutter app.
//!
//! Routes:
//!   POST /api/v1/instances/{id}/qr-token   (admin-authed — generates QR token)
//!   POST /api/v1/mobile/auth               (public — exchanges QR token for session)
//!   GET  /api/v1/mobile/status             (mobile-authed — validates session)
//!   GET  /api/v1/mobile/instances          (mobile-authed — lists instances)
//!   POST /api/v1/mobile/logout             (mobile-authed — revokes session)

use crate::auth::{AdminUser, AuthUser};
use crate::handlers_instances::require_instance;
use crate::instance_create::rollback_inserted_instance;
use crate::mobile_token::capabilities_for;
use crate::state::SharedState;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use core_rs::error::{ApiError, blocking};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEEP_LINK_QUERY_VALUE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'`');
const PROVISIONING_TTL_SECS: i64 = 1200;

#[must_use]
pub fn mobile_deep_link(action: &str, query_items: &[(&str, &str)]) -> String {
    let query = query_items
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                key,
                utf8_percent_encode(value, DEEP_LINK_QUERY_VALUE_SET)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("theyos://{action}?{query}")
}

// ─── Request / response types ─────────────────────────────────────────────────

/// Optional query-string filter for `GET /api/v1/mobile/claws`.
///
/// `tier` — if present, only entries at the matching tier variant are returned.
/// Values: `catalog` / `detected` / `available` / `supported`. Unknown values
/// are silently ignored (returns the full catalog) so newer clients don't
/// break older servers. Absent = every tier.
#[derive(Deserialize, Debug, Default)]
pub struct ClawsQuery {
    #[serde(default)]
    pub tier: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MobileAuthRequest {
    /// The QR token scanned by the mobile app.
    pub qr_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct MobileAuthResponse {
    session_token: String,
    expires_at: String,
    instances: Vec<MobileInstanceInfo>,
    /// Set when the QR token was a "continue on iPhone" handoff.
    /// Client uses this to skip the instance picker and land directly on the
    /// pre-existing tmux workspace. `None` on regular pair/auth flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    target_instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_conversation_id: Option<String>,
    /// Pre-built WebSocket URL including session + bearer token as query params.
    /// Present iff the other two `target_*` are present. The server builds it
    /// here (rather than on the client) so the host/scheme detection matches
    /// what the generating device saw — no risk of drift between `best_qr_host`
    /// at generation time vs. client-side URL assembly.
    #[serde(skip_serializing_if = "Option::is_none")]
    target_ws_url: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct MobileInstanceInfo {
    id: String,
    name: String,
    container: String,
    claw_type: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    capabilities: crate::mobile_token::ClawCapabilities,
    /// Present while `status == "provisioning"`. Mirrors the single-instance
    /// status endpoint so the mobile app can render in-progress deploys in
    /// the list without maintaining local-only state. `None` for terminal
    /// statuses (active, stopped, failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning_phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioning_error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct QrTokenResponse {
    token: String,
    expires_at: String,
    /// Best host for the mobile app to connect to (auto-detected from channels).
    qr_host: String,
    /// Which channel is being used (e.g., "cloudflare", "tailscale", "lan", "local").
    qr_channel: String,
    /// Ready-to-use deep link for the mobile app: `theyos://connect?token=X&host=Y`.
    deep_link: String,
    /// Image ID for the QR code PNG endpoint (`GET /qr/{image_id}`).
    image_id: String,
    instance: QrInstanceInfo,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct QrInstanceInfo {
    id: String,
    name: String,
    container: String,
    claw_type: String,
}

const RESOURCE_OPTIONS_RETRY_AFTER_SECS: u32 = 30;

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ResourceOptionRange {
    min: u32,
    max: u32,
    default: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled: Option<bool>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ResourceOptionsResponse {
    cpu_cores: ResourceOptionRange,
    ram_mb: ResourceOptionRange,
    disk_gb: ResourceOptionRange,
}

fn build_resource_option_range(
    label: &'static str,
    min: u32,
    max: u32,
    preferred_default: u32,
    disabled: Option<bool>,
) -> Result<ResourceOptionRange, crate::capacity::CapacityError> {
    if max < min {
        return Err(crate::capacity::CapacityError {
            message: format!(
                "insufficient {label}: minimum supported is {min}, but only {max} available"
            ),
            retry_after_secs: RESOURCE_OPTIONS_RETRY_AFTER_SECS,
        });
    }

    Ok(ResourceOptionRange {
        min,
        max,
        default: preferred_default.clamp(min, max),
        disabled,
    })
}

fn build_resource_options_response(
    cpu_max: u32,
    ram_max: u32,
    disk_max: u32,
    is_macos: bool,
) -> Result<ResourceOptionsResponse, crate::capacity::CapacityError> {
    Ok(ResourceOptionsResponse {
        cpu_cores: build_resource_option_range("CPU", 1, cpu_max, 2, None)?,
        ram_mb: build_resource_option_range("RAM", 512, ram_max, 2048, None)?,
        disk_gb: build_resource_option_range("disk", 5, disk_max, 10, Some(is_macos))?,
    })
}

fn resource_options_capacity_response(cap_err: &crate::capacity::CapacityError) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": cap_err.message,
            "code": "SERVICE_UNAVAILABLE",
            "retry_after_secs": cap_err.retry_after_secs,
        })),
    )
        .into_response()
}

/// Detect the best host for the QR code based on available network channels.
///
/// Priority: Cloudflare (public) > Tailscale (private) > LAN > localhost.
#[must_use]
pub fn best_qr_host() -> (String, String) {
    let status = core_rs::network_detect::detect_network_status();
    best_qr_host_from_status(&status)
}

/// Platform metadata exposed to mobile clients.
#[must_use]
pub fn server_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Testable inner function — selects the best host from a pre-built [`NetworkStatus`].
fn best_qr_host_from_status(status: &core_rs::network_detect::NetworkStatus) -> (String, String) {
    let admin_port = status
        .channels
        .iter()
        .find(|c| c.channel_type == "local")
        .and_then(|c| c.urls.first())
        .and_then(|u| u.rsplit(':').next())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8892);

    // Priority 1: Cloudflare (public, works from anywhere)
    for ch in &status.channels {
        if ch.channel_type == "cloudflare" && ch.detected {
            if let Some(ref hostname) = ch.hostname {
                return (hostname.clone(), "cloudflare".into());
            }
        }
    }

    // Priority 2: Tailscale (private, works on tailnet)
    // has_https is the effective per-node HTTPS availability computed by
    // network detection after considering tailscale serve and local Caddy.
    for ch in &status.channels {
        if ch.channel_type == "tailscale" && ch.detected {
            let has_https = ch.has_https == Some(true);
            if has_https {
                if let Some(ref hostname) = ch.hostname {
                    return (format!("https://{hostname}"), "tailscale".into());
                }
            }
            if let Some(ref ip) = ch.ip {
                return (format!("http://{ip}:{admin_port}"), "tailscale".into());
            }
            if let Some(ref hostname) = ch.hostname {
                return (
                    format!("http://{hostname}:{admin_port}"),
                    "tailscale".into(),
                );
            }
        }
    }

    // Priority 3: LAN IP
    for ch in &status.channels {
        if ch.channel_type == "lan" && ch.detected {
            if let Some(ref ip) = ch.ip {
                return (format!("{ip}:{admin_port}"), "lan".into());
            }
        }
    }

    // Fallback: localhost
    (format!("localhost:{admin_port}"), "local".into())
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// `POST /api/v1/instances/{id}/qr-token`
///
/// Admin-authenticated. Generates a short-lived QR token for the given instance.
/// The frontend renders this token as a QR code for the mobile app to scan.
///
/// # Errors
///
/// Returns `ApiError` if the instance doesn't exist or the DB query fails.
#[tracing::instrument(skip(state))]
pub async fn handle_generate_qr_token(
    State(state): State<SharedState>,
    AdminUser(AuthUser { username, .. }): AdminUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    // Look up the instance in the database.
    let st = state.clone();
    let iid = id.clone();
    let row = blocking(move || st.instance_db.get(&iid).map_err(ApiError::from)).await??;
    let row = row.ok_or_else(|| ApiError::not_found("instance not found"))?;

    // Generate QR token (carries the generating admin's username)
    let (token, expires_at) = state.mobile_tokens.create_qr_token(&id, &username);

    let (qr_host, qr_channel) = best_qr_host();
    let deep_link = mobile_deep_link("connect", &[("token", &token), ("host", &qr_host)]);
    let image_id = state.mobile_tokens.store_image_link(&deep_link);

    tracing::info!(
        "[mobile] user={username} generated QR token for instance={id} container={} qr_host={qr_host} channel={qr_channel}",
        row.container
    );

    Ok((
        StatusCode::OK,
        Json(QrTokenResponse {
            token,
            expires_at,
            qr_host,
            qr_channel,
            deep_link,
            image_id,
            instance: QrInstanceInfo {
                id: row.id,
                name: row.name,
                container: row.container,
                claw_type: row.claw_type,
            },
        }),
    )
        .into_response())
}

/// `POST /api/v1/mobile/auth`
///
/// Public (no auth required). Exchanges a QR token for a mobile session token.
/// The QR token is single-use and consumed on successful exchange.
///
/// # Errors
///
/// Returns 401 if the QR token is invalid or expired.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_auth(
    State(state): State<SharedState>,
    Json(req): Json<MobileAuthRequest>,
) -> Result<Response, ApiError> {
    if req.qr_token.is_empty() {
        return Err(ApiError::bad_request("qr_token is required"));
    }

    // Validate and consume the QR token (single-use).
    // `workspace_id_opt` is `Some` for "continue on iPhone" tokens — handled below.
    let (instance_id, qr_username, workspace_id_opt) = state
        .mobile_tokens
        .redeem_qr_token(&req.qr_token)
        .ok_or_else(|| ApiError::unauthorized("invalid or expired QR token"))?;

    // Look up the instance to confirm it still exists.
    let st = state.clone();
    let iid = instance_id.clone();
    let target_row = blocking(move || st.instance_db.get(&iid).map_err(ApiError::from)).await??;
    let target_row = target_row.ok_or_else(|| ApiError::not_found("instance no longer exists"))?;

    // Create a persistent mobile session with the real admin username from the
    // QR token — workspace (container, username) matches between web and mobile,
    // so both devices get the same tmux session.
    let (session_token, expires_at) = state
        .mobile_sessions
        .create_session(&qr_username)
        .map_err(|e| ApiError::internal(format!("create session: {e}")))?;

    let instances = build_instance_list(&state, &qr_username).await?;

    // Continue-on-iPhone handoff: the QR was minted for a specific tmux workspace.
    // Re-validate ownership + instance status at redeem time (not trust-on-mint)
    // so that workspace deletions / instance stops between generation and scan
    // gracefully degrade to the instance-picker fallback on iOS.
    let (target_instance_id, target_conversation_id, target_ws_url) = match workspace_id_opt {
        Some(workspace_id) if target_row.status == store_rs::InstanceStatus::Active => {
            let st = state.clone();
            let ws_id = workspace_id.clone();
            let container = target_row.container.clone();
            let username = qr_username.clone();
            let is_owner = blocking(move || {
                st.instance_db
                    .verify_conversation_owner(&ws_id, &container, &username)
                    .map_err(ApiError::from)
            })
            .await??;

            if is_owner {
                // Touch last_attach_at so `list_conversations` ordering reflects this
                // new attach (mirrors what `resume_or_create_conversation` does).
                let st = state.clone();
                let ws_id = workspace_id.clone();
                let _ = blocking(move || {
                    st.instance_db
                        .touch_conversation_attached(&ws_id)
                        .map_err(ApiError::from)
                })
                .await?;

                let ws_url = build_pty_ws_url(&target_row.container, &workspace_id, &session_token);
                (
                    Some(target_row.id.clone()),
                    Some(workspace_id),
                    Some(ws_url),
                )
            } else {
                tracing::warn!(
                    "[mobile] continue QR workspace ownership check failed: \
                     workspace={workspace_id} container={} user={qr_username}",
                    target_row.container
                );
                (None, None, None)
            }
        }
        Some(workspace_id) => {
            tracing::info!(
                "[mobile] continue QR redeemed but instance is {} (not Active) — \
                 falling back to instance list: container={} workspace={workspace_id}",
                target_row.status,
                target_row.container
            );
            (None, None, None)
        }
        None => (None, None, None),
    };

    tracing::info!(
        "[mobile] QR auth success: instance={} container={} continue={}",
        target_row.id,
        target_row.container,
        target_ws_url.is_some()
    );

    Ok((
        StatusCode::OK,
        Json(MobileAuthResponse {
            session_token,
            expires_at,
            instances,
            target_instance_id,
            target_conversation_id,
            target_ws_url,
        }),
    )
        .into_response())
}

/// Build a PTY WebSocket URL using the same scheme/host detection that
/// `handle_simulator_token` applies — keeps behaviour consistent across every
/// handoff path (simulator one-shot, continue-on-iPhone).
fn build_pty_ws_url(container: &str, session_id: &str, bearer: &str) -> String {
    let (host, _channel) = best_qr_host();
    let bare = host
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let scheme = if bare.starts_with("localhost")
        || bare.starts_with("127.0.0.1")
        || bare.starts_with("192.168.")
        || bare.starts_with("10.")
    {
        "ws"
    } else {
        "wss"
    };
    format!(
        "{scheme}://{bare}/api/v1/terminals/{container}/pty?session={session_id}&token={bearer}"
    )
}

/// `GET /api/v1/mobile/status`
///
/// Mobile-authenticated (Bearer token). Validates the session token.
///
/// # Errors
///
/// Returns 401 if the Bearer token is missing or invalid.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_status(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let _username = extract_mobile_bearer(&state, &headers)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `GET /api/v1/mobile/instances`
///
/// Mobile-authenticated. Returns the list of all active instances with capabilities.
///
/// # Errors
///
/// Returns 401 if not authenticated, or 500 on DB failure.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_instances(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;
    let instances = build_instance_list(&state, &username).await?;
    Ok((
        StatusCode::OK,
        Json(json!({"data": instances, "has_more": false, "next_cursor": null})),
    )
        .into_response())
}

/// `POST /api/v1/mobile/logout`
///
/// Mobile-authenticated (Bearer token). Revokes the session token.
/// Does NOT call `validate_session` first — that would needlessly extend TTL
/// via the sliding window. `delete_session` is idempotent (0 rows deleted if
/// already expired).
///
/// # Errors
///
/// Returns 401 if the Authorization header is missing/malformed, or 500 on DB error.
#[tracing::instrument(skip_all)]
pub async fn handle_mobile_logout(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    state
        .mobile_sessions
        .delete_session(token)
        .map_err(|e| ApiError::internal(format!("delete session: {e}")))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ─── Simulator Token ─────────────────────────────────────────────────────────

/// 365 days in seconds.
const SIMULATOR_TOKEN_TTL: u64 = 365 * 24 * 3600;

#[derive(Debug, Deserialize)]
pub struct SimulatorTokenRequest {
    pub container: String,
}

/// `POST /api/v1/admin/simulator-token`
///
/// Admin-authenticated. Creates a long-lived mobile session token (365 days)
/// and a workspace for the given container. Returns everything the iOS
/// simulator needs to connect directly without the QR flow.
///
/// # Errors
///
/// Returns `ApiError` if the container doesn't exist, isn't active, or on DB failure.
#[tracing::instrument(skip(state), fields(container = %body.container))]
pub async fn handle_simulator_token(
    State(state): State<SharedState>,
    AdminUser(AuthUser { username, .. }): AdminUser,
    Json(body): Json<SimulatorTokenRequest>,
) -> Result<Response, ApiError> {
    let container = body.container.trim().to_string();
    if container.is_empty() {
        return Err(ApiError::bad_request("container is required"));
    }

    // Verify instance exists and is Active.
    let st = state.clone();
    let c = container.clone();
    let row =
        blocking(move || st.instance_db.get_by_container(&c).map_err(ApiError::from)).await??;
    let row = row.ok_or_else(|| ApiError::not_found("container not found"))?;
    if row.status != store_rs::InstanceStatus::Active {
        return Err(ApiError::bad_request(format!(
            "instance is {}, must be Active",
            row.status
        )));
    }

    // Create long-lived mobile session (365 days).
    let (session_token, expires_at) = state
        .mobile_sessions
        .create_session_with_ttl(&username, SIMULATOR_TOKEN_TTL)
        .map_err(|e| ApiError::internal(format!("create session: {e}")))?;

    // Create or resume a workspace for this container + user.
    let st = state.clone();
    let c = container.clone();
    let u = username.clone();
    let ws = blocking(move || {
        st.instance_db
            .resume_or_create_conversation(&c, &u)
            .map_err(ApiError::from)
    })
    .await??;

    let (host, _channel) = best_qr_host();
    let bare = host
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let scheme = if bare.starts_with("localhost")
        || bare.starts_with("127.0.0.1")
        || bare.starts_with("192.168.")
        || bare.starts_with("10.")
    {
        "ws"
    } else {
        "wss"
    };
    let ws_url = format!(
        "{scheme}://{bare}/api/v1/terminals/{}/pty?session={}&token={}",
        container, ws.id, session_token
    );

    tracing::info!(
        "[simulator] token created: user={username} container={container} workspace={}",
        ws.id
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "session_token": session_token,
            "session_id": ws.id,
            "container": container,
            "ws_url": ws_url,
            "expires_at": expires_at
        })),
    )
        .into_response())
}

// ─── Continue on iPhone (mobile-authed) ──────────────────────────────────────

/// Short TTL for "continue on iPhone" QR tokens. The flow is synchronous —
/// user holds the phone in one hand while the Mac shows the QR — so a 2-minute
/// window balances retry room against exposure time for a single-use token.
const CONTINUE_QR_TTL_SECS: u64 = 120;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContinueQrRequest {
    pub container: String,
    pub workspace_id: String,
}

/// `POST /api/v1/mobile/continue-qr`
///
/// Mobile-authenticated. Generates a short-lived QR token that, when scanned
/// by the iOS app, lands the user in the specific tmux workspace the caller
/// is currently attached to — bypassing the instance picker.
///
/// Ownership is enforced: the caller must own (or be admin for) the container,
/// AND the workspace must belong to the caller's username+container tuple.
///
/// # Errors
///
/// - 400 invalid container string
/// - 404 container not owned by user (ownership leak protection)
/// - 404 workspace doesn't exist or doesn't belong to user
#[tracing::instrument(skip(state), fields(container = %body.container, workspace_id = %body.workspace_id))]
pub async fn handle_generate_continue_qr(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(body): Json<ContinueQrRequest>,
) -> Result<Response, ApiError> {
    let container = crate::handlers_terminal::validate_container(&body.container)?;
    let workspace_id = body.workspace_id.trim().to_string();
    if workspace_id.is_empty() {
        return Err(ApiError::bad_request("workspace_id is required"));
    }

    // Ownership: user must be able to touch this container at all.
    crate::handlers_terminal::require_terminal_access(&state, &auth, &container).await?;

    // Resolve container → instance_id (used to populate the QR entry).
    let st = state.clone();
    let c = container.clone();
    let row =
        blocking(move || st.instance_db.get_by_container(&c).map_err(ApiError::from)).await??;
    let row = row.ok_or_else(|| ApiError::not_found("container not found"))?;

    // Workspace must be active AND belong to this (container, username).
    // `verify_conversation_owner` handles both checks atomically in one SQL round-trip.
    let st = state.clone();
    let ws_id = workspace_id.clone();
    let c = container.clone();
    let u = auth.username.clone();
    let is_owner = blocking(move || {
        st.instance_db
            .verify_conversation_owner(&ws_id, &c, &u)
            .map_err(ApiError::from)
    })
    .await??;
    if !is_owner {
        return Err(ApiError::not_found("workspace not found"));
    }

    let ttl = std::time::Duration::from_secs(CONTINUE_QR_TTL_SECS);
    let (token, expires_at) =
        state
            .mobile_tokens
            .create_continue_qr_token(&row.id, &auth.username, &workspace_id, ttl);

    let (qr_host, qr_channel) = best_qr_host();
    let deep_link = mobile_deep_link("connect", &[("token", &token), ("host", &qr_host)]);
    let image_id = state
        .mobile_tokens
        .store_image_link_with_ttl(&deep_link, ttl);

    tracing::info!(
        "[mobile] user={} generated continue QR for container={} workspace={} qr_host={} channel={}",
        auth.username,
        row.container,
        workspace_id,
        qr_host,
        qr_channel
    );

    Ok((
        StatusCode::OK,
        Json(QrTokenResponse {
            token,
            expires_at,
            qr_host,
            qr_channel,
            deep_link,
            image_id,
            instance: QrInstanceInfo {
                id: row.id,
                name: row.name,
                container: row.container,
                claw_type: row.claw_type,
            },
        }),
    )
        .into_response())
}

/// `GET /api/v1/mobile/qr-status/{token}`
///
/// Mobile-authenticated. Returns 200 while the continue-QR token is still
/// active (not yet consumed, not expired), 410 Gone once it's been consumed
/// or expired, 403 if the caller isn't the token's owner.
///
/// Used by the macOS app to dismiss the QR popover automatically when the
/// phone scans successfully. Peek (not redeem) — does not invalidate the token.
///
/// # Errors
///
/// - 403 token belongs to another user
/// - 410 token consumed or expired
#[tracing::instrument(skip(state), fields(token_hint = %token.chars().take(8).collect::<String>()))]
pub async fn handle_continue_qr_status(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    match state.mobile_tokens.peek_qr_token(&token) {
        Some(entry) if entry.username == auth.username => Ok(StatusCode::OK.into_response()),
        Some(_) => Err(ApiError::forbidden("token belongs to another user")),
        None => Ok(StatusCode::GONE.into_response()),
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Extract and validate the mobile Bearer token from the `Authorization` header.
fn extract_mobile_bearer(
    state: &SharedState,
    headers: &axum::http::HeaderMap,
) -> Result<String, ApiError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::unauthorized("invalid Authorization header format"))?;

    state
        .mobile_sessions
        .validate_session(token)
        .ok_or_else(|| ApiError::unauthorized("invalid or expired session token"))
}

/// Resolve a mobile bearer username into an `AuthUser` by looking up the users table.
async fn resolve_mobile_auth_user(
    state: &SharedState,
    username: &str,
) -> Result<AuthUser, ApiError> {
    let st = state.clone();
    let uname = username.to_string();
    let user = blocking(move || {
        st.instance_db
            .get_user_by_username(&uname)
            .map_err(ApiError::from)
    })
    .await??
    .ok_or_else(|| ApiError::unauthorized("user not found"))?;
    Ok(AuthUser {
        user_id: user.id,
        username: user.username,
        role: user.role,
    })
}

/// Build the mobile instance list from the database, scoped by user role.
/// Admin users see all active instances; regular users see only their owned instances.
async fn build_instance_list(
    state: &SharedState,
    username: &str,
) -> Result<Vec<MobileInstanceInfo>, ApiError> {
    let st = state.clone();
    let uname = username.to_string();
    let (rows, user) = blocking(move || {
        let rows = st.instance_db.list().map_err(ApiError::from)?;
        let user = st
            .instance_db
            .get_user_by_username(&uname)
            .map_err(ApiError::from)?;
        Ok::<_, ApiError>((rows, user))
    })
    .await??;

    let user = user.ok_or_else(|| {
        tracing::warn!("[mobile] user '{}' not found in users table", username);
        ApiError::unauthorized("user not found")
    })?;
    let is_admin = user.role == store_rs::UserRole::Admin;
    let user_id = Some(user.id.as_str());

    Ok(rows
        .into_iter()
        .filter(|r| {
            matches!(
                r.status,
                store_rs::InstanceStatus::Active
                    | store_rs::InstanceStatus::Stopped
                    | store_rs::InstanceStatus::Provisioning
            )
        })
        .filter(|r| is_admin || r.owner_id.as_deref() == user_id)
        .map(|row| {
            let capabilities = capabilities_for(&row.claw_type);
            // On macOS, read the VM IP so the mobile app can reach the instance
            let host = if cfg!(target_os = "macos") {
                let home = std::env::var("HOME").unwrap_or_default();
                let ip_path = std::path::PathBuf::from(&home)
                    .join("Library/Application Support/theyos/vms")
                    .join(&row.container)
                    .join("vm_ip");
                std::fs::read_to_string(ip_path)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            };
            // Provisioning metadata: only meaningful while the instance is
            // still being created. Once terminal, we drop these so the
            // mobile list stays clean.
            let is_provisioning = matches!(row.status, store_rs::InstanceStatus::Provisioning);
            MobileInstanceInfo {
                id: row.id,
                name: row.name,
                container: row.container,
                claw_type: row.claw_type,
                status: row.status.to_string(),
                host,
                capabilities,
                provisioning_message: if is_provisioning {
                    row.provisioning_message
                } else {
                    None
                },
                provisioning_phase: if is_provisioning {
                    row.provisioning_phase
                } else {
                    None
                },
                provisioning_error: if is_provisioning {
                    row.provisioning_error
                } else {
                    None
                },
            }
        })
        .collect())
}

// ─── Server pairing (US-4) ──────────────────────────────────────────────────

/// Optional JSON body for `POST /api/v1/mobile/pair-token`.
#[derive(Deserialize, Default)]
pub struct PairTokenRequest {
    /// Custom token TTL in seconds. Defaults to 15 minutes if absent.
    pub ttl_secs: Option<u64>,
}

/// Maximum allowed pair-token TTL: 30 days.
const MAX_PAIR_TTL_SECS: u64 = 30 * 24 * 3600;

/// Default pair-token TTL: 15 minutes.
const DEFAULT_PAIR_TTL_SECS: u64 = 15 * 60;

/// POST /api/v1/mobile/pair-token — generate a server-level pairing token.
///
/// Admin-authed. Returns a deep link for the mobile app to scan.
/// Accepts an optional JSON body with `ttl_secs` to set a custom token lifetime.
///
/// # Errors
///
/// Returns `ApiError` if token generation fails.
#[tracing::instrument(skip(state, body))]
pub async fn handle_pair_token(
    State(state): State<SharedState>,
    AdminUser(auth): AdminUser,
    body: Option<Json<PairTokenRequest>>,
) -> Result<Response, ApiError> {
    let ttl_secs = body
        .and_then(|b| b.ttl_secs)
        .unwrap_or(DEFAULT_PAIR_TTL_SECS);

    if ttl_secs == 0 || ttl_secs > MAX_PAIR_TTL_SECS {
        return Err(ApiError::bad_request(format!(
            "ttl_secs must be between 1 and {MAX_PAIR_TTL_SECS}"
        )));
    }

    let ttl = std::time::Duration::from_secs(ttl_secs);

    let (host, channel) = best_qr_host();
    let (token, expires_at) =
        state
            .mobile_tokens
            .create_qr_token_with_ttl("__server_pair__", &auth.username, ttl);

    let server_name = std::env::var("THEYOS_SERVER_NAME").unwrap_or_else(|_| "theyos".to_string());
    let platform = server_platform();

    let deep_link = mobile_deep_link(
        "pair",
        &[
            ("token", &token),
            ("host", &host),
            ("name", &server_name),
            ("platform", platform),
        ],
    );

    // Store a QR image link so the PNG endpoint can render it.
    let image_id = state
        .mobile_tokens
        .store_image_link_with_ttl(&deep_link, ttl);

    tracing::info!(
        "[mobile] user={} generated pair token (channel={channel}, ttl={ttl_secs}s)",
        auth.username
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "token": token,
            "expires_at": expires_at,
            "deep_link": deep_link,
            "host": host,
            "channel": channel,
            "server_name": server_name,
            "server_platform": platform,
            "image_id": image_id,
        })),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct PairRequest {
    pub token: String,
}

/// POST /api/v1/mobile/pair — exchange a pairing token for a mobile session.
///
/// Public endpoint (no auth required). The pairing token is single-use.
///
/// # Errors
///
/// Returns `ApiError` if the token is invalid, expired, or already used.
#[tracing::instrument(skip(state, req))]
pub async fn handle_pair(
    State(state): State<SharedState>,
    Json(req): Json<PairRequest>,
) -> Result<Response, ApiError> {
    let token = req.token.trim().to_string();
    if token.is_empty() {
        return Err(ApiError::bad_request("token is required"));
    }

    // Redeem the pairing token (single-use, 15-min expiry)
    // Server-pair tokens never carry a workspace_id.
    let (instance_id, username, _workspace_id) = state
        .mobile_tokens
        .redeem_qr_token(&token)
        .ok_or_else(|| ApiError::unauthorized("invalid or expired pairing token"))?;

    // Verify it's a server-level pair token
    if instance_id != "__server_pair__" {
        return Err(ApiError::bad_request("not a server pairing token"));
    }

    // Create a persistent mobile session
    let (session_token, expires_at) = state
        .mobile_sessions
        .create_session(&username)
        .map_err(|e| ApiError::internal(format!("create_session: {e}")))?;

    let (host, _channel) = best_qr_host();
    let server_name = std::env::var("THEYOS_SERVER_NAME").unwrap_or_else(|_| "theyos".to_string());
    let platform = server_platform();

    tracing::info!("[mobile] server paired by user={username}");

    Ok((
        StatusCode::OK,
        Json(json!({
            "session_token": session_token,
            "expires_at": expires_at,
            "server": {
                "name": server_name,
                "host": host,
                "platform": platform,
            }
        })),
    )
        .into_response())
}

// ─── QR code PNG endpoint ────────────────────────────────────────────────────

/// `GET /qr/{image_id}`
///
/// Public endpoint (no auth — the image ID is the secret). Returns a QR code
/// as a PNG image for the given image ID. The image ID is returned by
/// `POST /api/v1/mobile/pair-token` alongside the deep link.
///
/// # Errors
///
/// Returns 404 if the image ID is invalid or expired, or 500 on encoding failure.
pub async fn handle_pair_qr_image(
    State(state): State<SharedState>,
    Path(image_id): Path<String>,
) -> Result<Response, ApiError> {
    let deep_link = state
        .mobile_tokens
        .get_image_link(&image_id)
        .ok_or_else(|| ApiError::not_found("QR code not found or expired"))?;

    // QR generation + PNG encoding is CPU-bound — run off the async executor.
    let png_bytes = blocking(move || {
        let code =
            qrcode::QrCode::with_error_correction_level(deep_link.as_bytes(), qrcode::EcLevel::M)
                .map_err(|e| ApiError::internal(format!("QR generation failed: {e}")))?;

        let img = code
            .render::<image::Luma<u8>>()
            .quiet_zone(true)
            .module_dimensions(10, 10)
            .build();

        let mut buf = Vec::new();
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
            .map_err(|e| ApiError::internal(format!("PNG encoding failed: {e}")))?;

        Ok::<_, ApiError>(buf)
    })
    .await??;

    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "image/png"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        png_bytes,
    )
        .into_response())
}

// ─── New mobile endpoints ────────────────────────────────────────────────────

/// GET /api/v1/mobile/users — list all users (admin-only).
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid, user is not admin, or DB fails.
pub async fn handle_mobile_users(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;

    // Admin check
    let user = {
        let st = state.clone();
        let uname = username.clone();
        blocking(move || {
            st.instance_db
                .get_user_by_username(&uname)
                .map_err(ApiError::from)
        })
        .await??
    };
    match user {
        Some(u) if u.role == store_rs::UserRole::Admin => {}
        _ => return Err(ApiError::forbidden("admin access required")),
    }

    let users = {
        let st = state.clone();
        blocking(move || st.instance_db.list_users().map_err(ApiError::from)).await??
    };

    let items: Vec<serde_json::Value> = users
        .into_iter()
        .map(|u| {
            json!({
                "id": u.id,
                "username": u.username,
                "role": u.role.to_string(),
            })
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(json!({ "data": items, "has_more": false, "next_cursor": null })),
    )
        .into_response())
}

/// GET /api/v1/mobile/server-info — server metadata for the mobile app.
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid or version cache is poisoned.
#[allow(clippy::unused_async)]
pub async fn handle_mobile_server_info(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let _username = extract_mobile_bearer(&state, &headers)?;

    let server_name = std::env::var("THEYOS_SERVER_NAME").unwrap_or_else(|_| "theyos".to_string());

    let cache = state
        .ver_cache
        .read()
        .map_err(|e| ApiError::internal(format!("ver_cache: {e}")))?;
    let version = if cache.version.is_empty() {
        "unknown".to_string()
    } else {
        cache.version.clone()
    };

    let (host, _channel) = best_qr_host();
    let access_mode = std::env::var("THEYOS_ACCESS_MODE").unwrap_or_else(|_| "local".to_string());
    let platform = server_platform();

    Ok((
        StatusCode::OK,
        Json(json!({
            "name": server_name,
            "version": version,
            "host": host,
            "access_mode": access_mode,
            "platform": platform,
        })),
    )
        .into_response())
}

/// GET /api/v1/mobile/resource-options — available resource ranges (admin-only).
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid or user is not admin.
pub async fn handle_resource_options(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;

    // Admin check
    let user = {
        let st = state.clone();
        blocking(move || {
            st.instance_db
                .get_user_by_username(&username)
                .map_err(ApiError::from)
        })
        .await??
    };
    match user {
        Some(u) if u.role == store_rs::UserRole::Admin => {}
        _ => return Err(ApiError::forbidden("admin access required")),
    }

    // Compute capacity projection (single source of truth, includes warm pool)
    let disk_path = core_rs::host_resources::resolve_instance_disk_path();
    let host = core_rs::host_resources::detect_all(&disk_path).ok();

    let (cpu_max, ram_max, disk_max) = if let Some(ref h) = host {
        if let Ok(proj) = crate::capacity::compute_capacity_projection(&state.instance_db, h) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let cpu = proj.available_cpu.max(0) as u32;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let ram = proj.available_ram.max(0) as u32;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let disk = proj.available_disk.max(0) as u32;
            (cpu, ram, disk)
        } else {
            // Fallback: use host limits directly
            let reserve = crate::capacity::cpu_reserve();
            let pct = crate::capacity::ram_budget_percent();
            #[allow(clippy::cast_possible_truncation)]
            let cpu = h.cpu_cores.saturating_sub(reserve);
            #[allow(clippy::cast_possible_truncation)]
            let ram = ((h.total_ram_mb * pct) / 100) as u32;
            #[allow(clippy::cast_possible_truncation)]
            let disk = h.available_disk_gb as u32;
            (cpu, ram, disk)
        }
    } else {
        // No host detection available — return generous defaults
        (8, 16384, 100)
    };

    let options = match build_resource_options_response(
        cpu_max,
        ram_max,
        disk_max,
        cfg!(target_os = "macos"),
    ) {
        Ok(options) => options,
        Err(cap_err) => return Ok(resource_options_capacity_response(&cap_err)),
    };

    Ok((StatusCode::OK, Json(options)).into_response())
}

// ─── Create Instance (mobile) ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct MobileCreateInstanceReq {
    name: String,
    #[serde(default)]
    claw_type: String,
    #[serde(default)]
    guest_os: String,
    #[serde(default)]
    cpu_cores: Option<u32>,
    #[serde(default)]
    ram_mb: Option<u32>,
    #[serde(default)]
    disk_gb: Option<u32>,
    #[serde(default)]
    owner_id: Option<String>,
}

/// POST /api/v1/mobile/instances — create a new instance (admin-only).
///
/// Mobile-specific: validates resources and returns a flat `snake_case` response
/// suitable for the iOS client.
///
/// # Errors
///
/// Returns `ApiError` on validation failure, rate limiting, name conflict,
/// or database/blocking-task errors.
#[allow(clippy::too_many_lines)]
#[allow(clippy::similar_names)]
#[tracing::instrument(skip(state, req, headers))]
pub async fn handle_mobile_create_instance(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MobileCreateInstanceReq>,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;

    // Admin check
    let user = {
        let st = state.clone();
        let uname = username.clone();
        blocking(move || {
            st.instance_db
                .get_user_by_username(&uname)
                .map_err(ApiError::from)
        })
        .await??
    };
    match user {
        Some(u) if u.role == store_rs::UserRole::Admin => {}
        _ => return Err(ApiError::forbidden("admin access required")),
    }

    create_mobile_instance_for_actor(state, username, req, None).await
}

/// Household scope stamped on instances created through household `PoP` routes.
#[derive(Clone, Debug)]
pub(crate) struct HouseholdInstanceScope {
    pub household_id: String,
    pub household_machine_id: String,
}

/// Shared mobile-shaped create-instance implementation.
///
/// The normal `/api/v1/mobile/instances` handler performs bearer-token
/// authentication and admin lookup before calling this. Household `PoP` routes
/// call it after owner-key authorization and pass the owner person id as the
/// actor. Response shape intentionally stays flat `snake_case` for iOS.
#[allow(clippy::too_many_lines)]
#[allow(clippy::similar_names)]
pub(crate) async fn create_mobile_instance_for_actor(
    state: SharedState,
    username: String,
    req: MobileCreateInstanceReq,
    household_scope: Option<HouseholdInstanceScope>,
) -> Result<Response, ApiError> {
    // Validate name
    let name = store_rs::normalize_slug(&req.name);
    if name.is_empty() {
        return Err(ApiError::bad_request("container name is required"));
    }
    if name.len() > 64 {
        return Err(ApiError::bad_request("container name too long"));
    }

    // Validate claw type
    let claw_type = {
        let ct = store_rs::normalize_slug(&req.claw_type);
        if ct.is_empty() {
            "picoclaw".to_string()
        } else {
            ct
        }
    };
    if claw_type.len() > 32 {
        return Err(ApiError::bad_request("claw type name too long"));
    }
    // Unified availability gate: replaces the split-brain
    // Registry::is_valid + ClawStore::is_ready + maintenance early-return.
    // See handlers_instances.rs for the identical pattern and rationale.
    {
        use core_rs::availability::{OverallState, UnavailReason};

        let avail = crate::availability::project_claw(&claw_type, &state);
        let reasons_json = serde_json::to_value(&avail.reasons).unwrap_or(serde_json::Value::Null);
        match avail.overall {
            OverallState::Creatable => {}
            OverallState::Unknown => {
                return Err(ApiError::bad_request_with_reasons(
                    format!("unknown claw type: {claw_type}"),
                    reasons_json,
                ));
            }
            OverallState::NotInstalled => {
                return Err(ApiError::bad_request_with_reasons(
                    format!("claw type '{claw_type}' is not installed"),
                    reasons_json,
                ));
            }
            OverallState::Installing { percent } => {
                return Err(ApiError::bad_request_with_reasons(
                    format!("claw type '{claw_type}' is still installing ({percent}%)"),
                    reasons_json,
                ));
            }
            OverallState::Failed { ref error } => {
                return Err(ApiError::bad_request_with_reasons(
                    format!("claw type '{claw_type}' install failed: {error}"),
                    reasons_json,
                ));
            }
            OverallState::Blocked => {
                // Maintenance → 503 + Retry-After (transient).
                // Other blocked reasons → 400 (host config problem).
                let maintenance_retry = avail.reasons.iter().find_map(|r| match r {
                    UnavailReason::MaintenanceMode { retry_after_secs } => Some(*retry_after_secs),
                    _ => None,
                });
                if let Some(retry) = maintenance_retry {
                    return Ok((
                        StatusCode::SERVICE_UNAVAILABLE,
                        [("Retry-After", retry.to_string())],
                        Json(json!({
                            "error": "service temporarily unavailable — artifact sync in progress",
                            "code": "SERVICE_UNAVAILABLE",
                            "reasons": avail.reasons,
                            "retry_after_secs": retry,
                        })),
                    )
                        .into_response());
                }

                let blocked_msg = avail
                    .reasons
                    .iter()
                    .find_map(|r| match r {
                        UnavailReason::NoColdPathAvailable => Some(format!(
                            "claw type '{claw_type}' cannot be created: host rootfs missing"
                        )),
                        _ => None,
                    })
                    .unwrap_or_else(|| {
                        format!("claw type '{claw_type}' cannot be created right now")
                    });
                return Err(ApiError::bad_request_with_reasons(
                    blocked_msg,
                    reasons_json,
                ));
            }
        }
    }

    // Normalize guest_os: empty → platform default, validate known values
    let guest_os: String = if req.guest_os.is_empty() {
        (if cfg!(target_os = "macos") {
            "macos"
        } else {
            "linux"
        })
        .into()
    } else {
        match req.guest_os.as_str() {
            "macos" | "linux" => req.guest_os.clone(),
            _ => return Err(ApiError::bad_request("guest_os must be 'macos' or 'linux'")),
        }
    };

    #[cfg(target_os = "macos")]
    {
        let guest = crate::guest_image_state::GuestImageState::read_current();
        if guest.status.as_deref() != Some("done") {
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "macOS guest image is not ready",
                    "code": "GUEST_IMAGE_NOT_READY",
                    "guest_image_phase": guest.phase,
                    "guest_image_status": guest.status,
                    "guest_image_error": guest.error,
                })),
            )
                .into_response());
        }
    }

    // Validate resources — only enforce physical minimums.
    // Maximum limits enforced dynamically by check_capacity().
    let cpu_cores = req.cpu_cores.unwrap_or(2);
    let ram_mb = req.ram_mb.unwrap_or(2048);
    let disk_gb = req.disk_gb.unwrap_or(10);
    if cpu_cores < 1 {
        return Err(ApiError::bad_request("cpu_cores must be at least 1"));
    }
    if ram_mb < 512 {
        return Err(ApiError::bad_request("ram_mb must be at least 512"));
    }
    if disk_gb < 5 {
        return Err(ApiError::bad_request("disk_gb must be at least 5"));
    }

    #[cfg(target_os = "macos")]
    if req.disk_gb.is_some() {
        return Err(ApiError::bad_request(
            "custom disk_gb is not supported on macOS hosts; disk size is determined by the base image",
        ));
    }

    // Note: the maintenance gate that used to live here has been folded
    // into the unified availability projection check above. See
    // handlers_instances.rs for the same pattern, and AD5.1 in
    // kind-booping-stearns.md for the design rationale.

    // Rate limit
    {
        let st = state.clone();
        let uname = username.clone();
        let allowed = blocking(move || {
            st.rate_limiter
                .check(&uname, "create_instance")
                .unwrap_or(true)
        })
        .await?;
        if !allowed {
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "rate limit exceeded", "code": "RATE_LIMITED"})),
            )
                .into_response());
        }
    }

    let instance_id = format!("inst-{name}");
    let container = format!("{claw_type}-{name}");

    // Conflict check
    let conflict = {
        let st = state.clone();
        let iid = instance_id.clone();
        let n = name.clone();
        blocking(move || {
            st.instance_db
                .find_conflict(&iid, &n)
                .map_err(ApiError::from)
        })
        .await??
    };
    if conflict.is_some() {
        return Err(ApiError::bad_request(
            "instance with this name already exists",
        ));
    }

    // Detect host resources (I/O outside capacity lock)
    let disk_path = core_rs::host_resources::resolve_instance_disk_path();
    let host = core_rs::host_resources::detect_all(&disk_path)
        .map_err(|e| ApiError::internal(format!("{e}")))?;

    // Sunset date (30 days from now)
    let sunset_date = {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        crate::time_util::format_date(now_secs + 30 * 24 * 3600)
    };

    // Capacity lock serializes check + insert to prevent over-commitment
    let _cap_guard = state.capacity_lock.lock().await;

    let cap_req = crate::capacity::CapacityRequest {
        cpu_cores,
        ram_mb,
        disk_gb,
        guest_os: &guest_os,
        claw_type: Some(&claw_type),
    };

    // Capacity check — return 503 with retry metadata on failure
    let projection = match crate::capacity::check_capacity(&state, &host, &cap_req) {
        Ok(p) => p,
        Err(cap_err) => {
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": cap_err.message,
                    "code": "SERVICE_UNAVAILABLE",
                    "retry_after_secs": cap_err.retry_after_secs,
                })),
            )
                .into_response());
        }
    };

    // DB insert + lease creation (atomic transaction)
    let use_warm_pool = crate::capacity::request_matches_warm_pool_lease(
        &state.instance_db,
        Some(&claw_type),
        cpu_cores,
        ram_mb,
    );
    let create_started_snapshot = serde_json::to_string(&crate::capacity::project_after_request(
        &projection,
        &cap_req,
        use_warm_pool,
    ))
    .ok();

    {
        let st = state.clone();
        let iid = instance_id.clone();
        let n = name.clone();
        let cont = container.clone();
        let ct = claw_type.clone();
        let sdate = sunset_date.clone();
        let gos = guest_os.clone();
        let resource_snapshot = create_started_snapshot.clone();
        let household_scope = household_scope.clone();
        blocking(move || {
            let household_id = household_scope
                .as_ref()
                .map(|scope| scope.household_id.as_str());
            let household_machine_id = household_scope
                .as_ref()
                .map(|scope| scope.household_machine_id.as_str());
            let new_instance = store_rs::NewInstance {
                id: &iid,
                name: &n,
                container: &cont,
                claw_type: &ct,
                sunset_date: &sdate,
                guest_os: Some(&gos),
                aux_storage_path: None,
                cpu_cores: Some(i64::from(cpu_cores)),
                ram_config_mb: Some(i64::from(ram_mb)),
                disk_gb: Some(i64::from(disk_gb)),
                household_id,
                household_machine_id,
            };
            if use_warm_pool {
                st.instance_db
                    .insert_with_warm_pool_leases(
                        &new_instance,
                        PROVISIONING_TTL_SECS,
                        resource_snapshot.as_deref(),
                    )
                    .map_err(ApiError::from)
            } else {
                st.instance_db
                    .insert_with_leases(
                        &new_instance,
                        PROVISIONING_TTL_SECS,
                        resource_snapshot.as_deref(),
                    )
                    .map_err(ApiError::from)
            }
        })
        .await??;
    }

    // Owner assignment
    if let Some(ref oid) = req.owner_id {
        let st = state.clone();
        let iid = instance_id.clone();
        let oid = oid.clone();
        match blocking(move || {
            st.instance_db
                .set_owner(&iid, Some(&oid))
                .map_err(ApiError::from)
        })
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) | Err(e) => {
                rollback_inserted_instance(&state, &instance_id, "owner assignment", use_warm_pool)
                    .await;
                return Err(e);
            }
        }
    }

    // Create async job
    let tools = vec![
        "codex".to_string(),
        "claude-code".to_string(),
        "opencode".to_string(),
    ];
    let payload = serde_json::to_string(&json!({
        "name":     name,
        "claw_type": claw_type,
        "port":     0,
        "tools":    tools,
        "guest_os":  guest_os,
        "cpu_cores": cpu_cores,
        "ram_mb":    ram_mb,
        "disk_gb":   disk_gb,
    }))
    .unwrap_or_default();

    let mut job = jobs_rs::Job::new(
        jobs_rs::JobType::CreateInstance,
        instance_id.clone(),
        payload,
    );
    job.actor = Some(username.clone());
    let job_id = job.id.clone();

    {
        let st = state.clone();
        match blocking(move || st.jobs.create(&mut job).map_err(ApiError::from)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) | Err(e) => {
                rollback_inserted_instance(&state, &instance_id, "job creation", use_warm_pool)
                    .await;
                return Err(e);
            }
        }
    }

    // Update instance with job ID and initial "queuing" phase
    {
        let st = state.clone();
        let iid = instance_id.clone();
        let jid = job_id.clone();
        let _ = blocking(move || {
            if let Err(e) = st.instance_db.update_status(&store_rs::StatusUpdate {
                id: &iid,
                status: store_rs::InstanceStatus::Provisioning,
                message: "Waiting for resources...",
                error: "",
                job_id: &jid,
                phase: "queuing",
            }) {
                tracing::error!("[mobile] failed to set initial phase for {iid}: {e}");
            }
        })
        .await;
    }

    tracing::info!(
        "[mobile] user={} queued creation of {} ({}) [job: {}]",
        username,
        name,
        container,
        job_id
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "id":        instance_id,
            "name":      name,
            "container": container,
            "claw_type": claw_type,
            "status":    "provisioning",
            "job_id":    job_id,
        })),
    )
        .into_response())
}

/// GET /api/v1/mobile/instances/{id}/status — mobile-friendly provisioning status.
///
/// Returns a flat `snake_case` JSON response suitable for iOS `JSONDecoder` (no
/// `keyDecodingStrategy`). Includes the new `provisioning_phase` field for
/// Live Activity phase transitions.
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid or the instance is not found.
pub async fn handle_mobile_instance_status(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;
    let auth = resolve_mobile_auth_user(&state, &username).await?;
    let row = require_instance(&state, &auth, &id).await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": row.status.to_string(),
            "provisioning_message": row.provisioning_message,
            "provisioning_error": row.provisioning_error,
            "provisioning_phase": row.provisioning_phase,
        })),
    )
        .into_response())
}

/// GET /api/v1/mobile/claws — claw catalog for the mobile app.
///
/// Each item includes legacy fields (`status`, `installed_at`, `job_id`,
/// `error`) **and** a new `availability` field carrying the full
/// `core_rs::availability::ClawAvailability` projection. The iOS client
/// (`ClawModels.swift`) ignores unknown keys, so adding `availability`
/// is a fully backward-compatible extension.
///
/// Use `GET /api/v1/mobile/claws/{name}/availability` for efficient
/// single-claw polling during install (cheaper than re-listing the
/// whole catalog).
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid.
#[allow(clippy::unused_async)]
pub async fn handle_mobile_claws(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<ClawsQuery>,
) -> Result<Response, ApiError> {
    let _username = extract_mobile_bearer(&state, &headers)?;
    let verify_path = state.theyos_dir.join("claws/verify-results.json");
    let items = state
        .claw_store
        .catalog_with_status_merged(Some(&verify_path));

    // P-46 Fase F: optional `?tier=supported|available|detected|catalog` filter.
    // Unknown or empty values become "no filter" so older servers don't break.
    let tier_filter = q
        .tier
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| match s {
            "catalog" | "detected" | "available" | "supported" => Some(s.to_string()),
            _ => None,
        });

    // Share one host probe across all claws in the list.
    let availabilities = crate::availability::project_all_claws(&state);
    let by_name: std::collections::HashMap<String, _> = availabilities
        .into_iter()
        .map(|a| (a.name.clone(), a))
        .collect();

    let enriched: Vec<Value> = items
        .into_iter()
        .filter(|item| match &tier_filter {
            Some(t) => &item.tier == t,
            None => true,
        })
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

    Ok((
        StatusCode::OK,
        Json(json!({ "data": enriched, "has_more": false, "next_cursor": null })),
    )
        .into_response())
}

/// GET /api/v1/mobile/claws/{name}/availability — full availability projection
/// for a single claw.
///
/// Authoritative endpoint for answering "can this claw be created right
/// now?". Preferred over `GET /api/v1/mobile/claws/{name}` for install
/// progress polling: much cheaper than re-listing the whole catalog.
///
/// Returns the projection even for unknown names — the response will have
/// `overall.state == "unknown"`.
///
/// # Errors
///
/// Returns `ApiError` if the session is invalid.
#[allow(clippy::unused_async)]
pub async fn handle_mobile_claw_availability(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let _username = extract_mobile_bearer(&state, &headers)?;
    let avail = crate::availability::project_claw(&name, &state);
    let body = serde_json::to_value(&avail)
        .map_err(|e| ApiError::internal(format!("availability serialization: {e}")))?;
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// POST /api/v1/mobile/claws/{name}/install — trigger claw install (admin-only).
///
/// # Errors
///
/// Returns `ApiError` on auth failure, 404 if unknown claw, 400 if not buildable
/// or already installed, 409 if install already in progress.
pub async fn handle_mobile_install_claw(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;

    // Admin check
    let user = {
        let st = state.clone();
        blocking(move || {
            st.instance_db
                .get_user_by_username(&username)
                .map_err(ApiError::from)
        })
        .await??
    };
    match user {
        Some(u) if u.role == store_rs::UserRole::Admin => {}
        _ => return Err(ApiError::forbidden("admin access required")),
    }

    // 1. Must be in manifest
    let Some(entry) = core_rs::manifest::get(&name) else {
        return Err(ApiError::not_found(format!("unknown claw type: {name}")));
    };

    // 2. Single installability gate — see handle_install_claw for context.
    //    `ManifestEntry::installability()` is the one and only predicate.
    if let core_rs::manifest::ClawInstallability::Unavailable { code, message } =
        entry.installability()
    {
        return Err(ApiError::bad_request_with_reasons(
            format!("claw type '{name}' is not installable yet: {message}"),
            json!({
                "unavailable_reason_code": code,
                "unavailable_reason": message,
            }),
        ));
    }

    // 3. Check current status
    let current = state.claw_store.get_status(&name);
    match current {
        claw_rs::ClawStatus::Ready => {
            return Err(ApiError::bad_request(format!(
                "claw type '{name}' is already installed"
            )));
        }
        claw_rs::ClawStatus::Installing => {
            let existing_state = state.claw_store.get_state(&name);
            let job_id = existing_state.and_then(|s| s.job_id).unwrap_or_default();
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({
                    "job_id": job_id,
                    "message": "install already in progress"
                })),
            )
                .into_response());
        }
        _ => {}
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

    tracing::info!("[mobile] install queued: claw={claw_name} job={job_id}");

    Ok((
        StatusCode::OK,
        Json(json!({
            "job_id": job_id,
            "message": format!("install queued for {claw_name}")
        })),
    )
        .into_response())
}

/// POST /api/v1/mobile/claws/{name}/uninstall — trigger claw uninstall (admin-only).
///
/// # Errors
///
/// Returns `ApiError` on auth failure, 404 if unknown claw, 400 if not installed
/// or instances still exist.
pub async fn handle_mobile_uninstall_claw(
    State(state): State<SharedState>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let username = extract_mobile_bearer(&state, &headers)?;

    // Admin check
    let user = {
        let st = state.clone();
        blocking(move || {
            st.instance_db
                .get_user_by_username(&username)
                .map_err(ApiError::from)
        })
        .await??
    };
    match user {
        Some(u) if u.role == store_rs::UserRole::Admin => {}
        _ => return Err(ApiError::forbidden("admin access required")),
    }

    // 1. Must be in manifest
    if !core_rs::manifest::is_known(&name) {
        return Err(ApiError::not_found(format!("unknown claw type: {name}")));
    }

    // 2. Must be ready
    if !state.claw_store.is_ready(&name) {
        return Err(ApiError::bad_request(format!(
            "claw type '{name}' is not installed"
        )));
    }

    // 3. Block if instances still exist
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

    tracing::info!("[mobile] uninstall queued: claw={claw_name} job={job_id}");

    Ok((
        StatusCode::OK,
        Json(json!({
            "job_id": job_id,
            "message": format!("uninstall queued for {claw_name}")
        })),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_rs::network_detect::{CaddyStatus, ChannelStatus, NetworkStatus};

    fn make_channel(channel_type: &str, detected: bool) -> ChannelStatus {
        ChannelStatus {
            channel_type: channel_type.to_string(),
            configured: detected,
            detected,
            ip: None,
            hostname: None,
            has_dns: None,
            has_https: None,
            has_cert: None,
            has_serve: None,
            urls: Vec::new(),
            status_detail: None,
        }
    }

    fn make_caddy(running: bool) -> CaddyStatus {
        CaddyStatus {
            installed: running,
            running,
            admin_url: "http://localhost:2019".to_string(),
            status_detail: None,
        }
    }

    fn make_status(channels: Vec<ChannelStatus>, caddy: CaddyStatus) -> NetworkStatus {
        NetworkStatus { channels, caddy }
    }

    #[test]
    fn mobile_deep_link_percent_encodes_query_values() {
        let link = mobile_deep_link(
            "pair",
            &[
                ("token", "token-123"),
                ("host", "https://linux.example.test"),
                ("name", "theyOS Linux"),
            ],
        );

        assert_eq!(
            link,
            "theyos://pair?token=token-123&host=https%3A%2F%2Flinux.example.test&name=theyOS%20Linux"
        );
    }

    #[test]
    fn tailscale_with_serve_returns_https() {
        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        ts.has_https = Some(true); // effective: has_serve active

        let local = make_channel("local", true);
        let status = make_status(vec![local, ts], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "https://myhost.tail1234.ts.net");
        assert_eq!(channel, "tailscale");
    }

    #[test]
    fn tailscale_with_caddy_running_returns_https() {
        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        // Simulates post-processing in detect_network_status():
        // Caddy running → has_https upgraded to true
        ts.has_https = Some(true);

        let local = make_channel("local", true);
        let status = make_status(vec![local, ts], make_caddy(true));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "https://myhost.tail1234.ts.net");
        assert_eq!(channel, "tailscale");
    }

    #[test]
    fn tailscale_without_https_prefers_ip_with_port() {
        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        ts.ip = Some("100.64.0.5".to_string());
        ts.has_https = Some(false);

        let mut local = make_channel("local", true);
        local.urls = vec!["http://localhost:9000".to_string()];
        let status = make_status(vec![local, ts], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "http://100.64.0.5:9000");
        assert_eq!(channel, "tailscale");
    }

    #[test]
    fn tailscale_without_https_falls_back_to_hostname_when_ip_missing() {
        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        ts.has_https = Some(false);

        let mut local = make_channel("local", true);
        local.urls = vec!["http://localhost:9000".to_string()];
        let status = make_status(vec![local, ts], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "http://myhost.tail1234.ts.net:9000");
        assert_eq!(channel, "tailscale");
    }

    #[test]
    fn tailscale_ip_only_returns_http_with_port() {
        let mut ts = make_channel("tailscale", true);
        ts.ip = Some("100.64.0.5".to_string());

        let local = make_channel("local", true);
        let status = make_status(vec![local, ts], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "http://100.64.0.5:8892");
        assert_eq!(channel, "tailscale");
    }

    #[test]
    fn lan_returns_ip_with_port() {
        let mut lan = make_channel("lan", true);
        lan.ip = Some("192.168.1.10".to_string());

        let local = make_channel("local", true);
        let status = make_status(vec![local, lan], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "192.168.1.10:8892");
        assert_eq!(channel, "lan");
    }

    #[test]
    fn fallback_returns_localhost() {
        let local = make_channel("local", true);
        let status = make_status(vec![local], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "localhost:8892");
        assert_eq!(channel, "local");
    }

    #[test]
    fn cloudflare_takes_priority_over_tailscale() {
        let mut cf = make_channel("cloudflare", true);
        cf.hostname = Some("admin.example.com".to_string());

        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        ts.has_https = Some(true);

        let local = make_channel("local", true);
        let status = make_status(vec![local, cf, ts], make_caddy(false));

        let (host, channel) = best_qr_host_from_status(&status);
        assert_eq!(host, "admin.example.com");
        assert_eq!(channel, "cloudflare");
    }

    #[test]
    fn custom_port_from_local_channel() {
        let mut ts = make_channel("tailscale", true);
        ts.hostname = Some("myhost.tail1234.ts.net".to_string());
        ts.ip = Some("100.64.0.5".to_string());
        ts.has_https = Some(false);

        let mut local = make_channel("local", true);
        local.urls = vec!["http://localhost:7777".to_string()];

        let status = make_status(vec![local, ts], make_caddy(false));

        let (host, _) = best_qr_host_from_status(&status);
        assert_eq!(host, "http://100.64.0.5:7777");
    }

    #[test]
    fn resource_options_clamp_defaults_to_available_max() {
        let response = build_resource_options_response(1, 1024, 7, true).unwrap();

        assert_eq!(
            response,
            ResourceOptionsResponse {
                cpu_cores: ResourceOptionRange {
                    min: 1,
                    max: 1,
                    default: 1,
                    disabled: None,
                },
                ram_mb: ResourceOptionRange {
                    min: 512,
                    max: 1024,
                    default: 1024,
                    disabled: None,
                },
                disk_gb: ResourceOptionRange {
                    min: 5,
                    max: 7,
                    default: 7,
                    disabled: Some(true),
                },
            }
        );
    }

    #[test]
    fn resource_options_fail_when_available_is_below_minimum() {
        let err = build_resource_options_response(0, 4096, 20, false).unwrap_err();

        assert_eq!(
            err.message,
            "insufficient CPU: minimum supported is 1, but only 0 available"
        );
        assert_eq!(err.retry_after_secs, RESOURCE_OPTIONS_RETRY_AFTER_SECS);
    }
}
