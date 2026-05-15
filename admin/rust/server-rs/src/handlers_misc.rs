//! Miscellaneous handlers:
//!   GET /api/v1/claw-types
//!   GET /api/v1/version
//!   GET /api/v1/logs

use crate::state::SharedState;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use core_rs::error::{ApiError, RwLockExt, blocking};
use serde::Deserialize;
use serde_json::{Value, json};
use store_rs::LogEntry;

// ─── Claw types (DEPRECATED) ─────────────────────────────────────────────────

/// `GET /api/v1/claw-types` — **deprecated**, prefer `GET /api/v1/claws`.
///
/// Historically this returned `state.registry.names()`, a static list built
/// from the `CLAW_TYPES` env var at boot. It now returns
/// `manifest::all_names()` directly (the compile-time source of truth) so
/// the response is consistent with the install/availability endpoints.
///
/// The response shape is preserved exactly — `{"data": [strings], ...}` —
/// so the legacy smoke test (`e2e-rs/src/smoke.rs:check_claw_types`) still
/// passes. The `Deprecation` response header signals that consumers should
/// migrate to `/api/v1/claws` (which returns the full catalog with per-host
/// install state).
///
/// # Errors
///
/// Infallible in practice.
#[allow(clippy::unused_async)]
pub async fn handle_claw_types(State(_state): State<SharedState>) -> Result<Response, ApiError> {
    let names: Vec<String> = core_rs::manifest::all_names()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let mut response = (
        StatusCode::OK,
        Json(json!({ "data": names, "has_more": false, "next_cursor": null })),
    )
        .into_response();
    // `HeaderValue::from_static` is infallible for valid ASCII static strings
    // and checked at compile-time — no runtime panic risk.
    response
        .headers_mut()
        .insert("Deprecation", HeaderValue::from_static("true"));
    response.headers_mut().insert(
        "Link",
        HeaderValue::from_static("</api/v1/claws>; rel=\"successor-version\""),
    );
    Ok(response)
}

// ─── Version ──────────────────────────────────────────────────────────────────

/// `GET /api/v1/version`
///
/// # Errors
///
/// Returns `ApiError` if the version cache `RwLock` is poisoned.
#[allow(clippy::unused_async)]
pub async fn handle_version(State(state): State<SharedState>) -> Result<Json<Value>, ApiError> {
    let cache = state.ver_cache.read_or_internal("ver_cache")?;
    let version = if cache.version.is_empty() {
        "unknown".to_string()
    } else {
        cache.version.clone()
    };
    Ok(Json(json!({
        "version": version,
        "update_available": cache.update_available,
    })))
}

// ─── Logs ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LogsQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub container: Option<String>,
}

/// `GET /api/v1/logs`
///
/// Without `?container=X`: returns recent audit events from `SQLite` (most recent first).
/// With `?container=X`:    fetches logs from the running VM via SSH (vmrunner).
///
/// # Errors
///
/// Returns `ApiError` if the container is not found or log retrieval fails.
pub async fn handle_logs(
    State(state): State<SharedState>,
    Query(q): Query<LogsQuery>,
) -> Result<Response, ApiError> {
    let limit = q.limit.unwrap_or(100).max(1);

    if let Some(container) = q
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        // Container log request — validate then fetch via vmrunner
        let st = state.clone();
        let c = container.to_string();
        let container_exists =
            blocking(move || st.instance_db.has_container(&c).map_err(ApiError::from))
                .await
                .unwrap_or(Ok(false))
                .unwrap_or(false);

        if !container_exists {
            return Err(ApiError::not_found("container not found"));
        }

        let container_owned = container.to_string();
        let result = state.vm_runner.fetch_logs(&container_owned, limit).await;

        match result {
            Ok(lines) => {
                let items: Vec<LogEntry> = lines
                    .iter()
                    .enumerate()
                    .filter_map(|(i, line)| {
                        let line = line.trim();
                        if line.is_empty() {
                            return None;
                        }
                        let (at, message) = parse_container_log_line(line);
                        Some(LogEntry {
                            id: format!("log-{container}-{i}"),
                            level: "info".to_string(),
                            component: container.to_string(),
                            message,
                            at,
                            actor: None,
                        })
                    })
                    .collect();
                Ok(
                    Json(json!({"data": items, "has_more": false, "next_cursor": null}))
                        .into_response(),
                )
            }
            Err(e) => Err(ApiError::internal(format!("failed to fetch logs: {e}"))),
        }
    } else {
        // Audit events from SQLite
        let st = state.clone();
        let items: Vec<LogEntry> =
            blocking(move || st.instance_db.list_audit_events(limit).unwrap_or_default())
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|ev| LogEntry {
                    id: ev.id.to_string(),
                    level: "info".to_string(),
                    component: ev.actor.clone(),
                    message: match ev.detail {
                        Some(d) => format!("[{}] {}", ev.action, d),
                        None => ev.action,
                    },
                    at: ev.created_at,
                    actor: Some(ev.actor),
                })
                .collect();
        Ok(Json(json!({"data": items, "has_more": false, "next_cursor": null})).into_response())
    }
}

/// Parse a container log line into (ISO-8601-UTC-timestamp, message).
///
/// Lines are expected to be in RFC3339 format: `"2006-01-02T15:04:05Z message"`.
/// If the timestamp cannot be parsed, the current time is used.
fn parse_container_log_line(line: &str) -> (String, String) {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now_iso = {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Minimal RFC3339 UTC without chrono
        format_unix_secs_as_rfc3339(secs)
    };

    let idx = line.find(' ');
    match idx {
        None | Some(0) => (now_iso, line.to_string()),
        Some(i) => {
            let ts_str = &line[..i];
            let message = line[i + 1..].trim().to_string();
            // Validate it looks like an RFC3339 timestamp (starts with digit year)
            if ts_str.len() >= 10 && ts_str.starts_with(|c: char| c.is_ascii_digit()) {
                (ts_str.to_string(), message)
            } else {
                (now_iso, line.to_string())
            }
        }
    }
}

/// Format Unix seconds as a minimal RFC3339 UTC string (no chrono dependency).
fn format_unix_secs_as_rfc3339(secs: u64) -> String {
    core_rs::time::format_iso(secs)
}
