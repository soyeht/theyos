//! `handlers_instances.rs` — Instance CRUD handlers (Phase 2).
//!
//! Mirrors Go:
//!   `handleListInstances`     → GET    /api/v1/instances
//!   `handleCreateInstance`    → POST   /api/v1/instances
//!   `handleInstanceStatus`    → GET    /api/v1/instances/{id}/status
//!   `handle_stop_instance`    → POST   /api/v1/instances/{id}/stop
//!   `handle_restart_instance` → POST   /api/v1/instances/{id}/restart
//!   `handle_rebuild_instance` → POST   /api/v1/instances/{id}/rebuild
//!   `handle_delete_instance`  → DELETE /api/v1/instances/{id}
//!   `handleInstanceAutoUpdate` → POST  /api/v1/instances/{id}/autoupdate

use crate::auth::{AdminUser, AuthUser};
use crate::instance_create::rollback_inserted_instance;
use crate::responses::{InstanceResponse, ListResponse};
use crate::state::SharedState;
use crate::time_util::format_date;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use core_rs::error::{ApiError, ErrorCode, MutexExt, blocking};
use core_rs::pagination::{PaginationParams, decode_cursor, encode_cursor};
use executor_rs::{ExecuteFlowRequest, FlowStatus, FlowType};
use jobs_rs::{Job, JobType};
use serde::Deserialize;
use serde_json::{Value, json};
use store_rs::{InstanceStatus, NewInstance, StatusUpdate, normalize_slug};
use tracing::{info, warn};
use vmrunner_common_rs::VmCreateResourceSpec;

const MAX_NAME_LEN: usize = 64;
const MAX_CLAW_TYPE_LEN: usize = 32;

/// Normalize a tool name from various user-supplied variants to the canonical form.
fn normalize_tool_name(name: &str) -> Option<&'static str> {
    match name {
        "codex" => Some("codex"),
        "claude-code" | "claudeCode" | "claude_code" => Some("claude-code"),
        "opencode" | "openCode" | "open_code" | "open-code" => Some("opencode"),
        _ => None,
    }
}

// ─── helpers ──────────────────────────────────────────────────────────────────

fn ok(body: Value) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

fn accepted(body: Value) -> Response {
    (StatusCode::ACCEPTED, Json(body)).into_response()
}

async fn current_capacity_snapshot(state: &SharedState) -> Option<String> {
    let st = state.clone();
    match blocking(move || crate::capacity::capacity_snapshot_json(&st.instance_db)).await {
        Ok(Ok(snapshot)) => Some(snapshot),
        Ok(Err(e)) => {
            tracing::warn!(
                "[instances] capture capacity snapshot failed: {}",
                e.message
            );
            None
        }
        Err(e) => {
            tracing::warn!("[instances] spawn_blocking failed for capacity snapshot: {e}");
            None
        }
    }
}

/// Fetch an instance by ID and verify ownership.
///
/// Admins can access any instance. Regular users can only access instances they
/// own. Returns 404 if the instance doesn't exist or the user lacks access
/// (avoids leaking instance existence).
///
/// # Errors
///
/// Returns `ApiError::not_found` if the instance doesn't exist or the user
/// is not authorized to access it.
pub async fn require_instance(
    state: &SharedState,
    auth: &AuthUser,
    id: &str,
) -> Result<store_rs::InstanceRow, ApiError> {
    let st = state.clone();
    let iid = id.to_string();
    let row = blocking(move || st.instance_db.get(&iid).map_err(ApiError::from)).await??;
    let row = row.ok_or_else(|| ApiError::not_found("instance not found"))?;
    if auth.role == store_rs::UserRole::User && row.owner_id.as_deref() != Some(&auth.user_id) {
        return Err(ApiError::not_found("instance not found"));
    }
    Ok(row)
}

// ─── List ─────────────────────────────────────────────────────────────────────

/// GET /api/v1/instances
///
/// Supports cursor pagination: `?limit=N&cursor=...`
/// When no params are given, returns all instances (backward compat).
///
/// # Errors
///
/// Returns `ApiError` if the database query or blocking task fails.
#[tracing::instrument(skip(state, auth))]
pub async fn handle_list_instances(
    State(state): State<SharedState>,
    auth: AuthUser,
    Query(q): Query<PaginationParams>,
) -> Result<Json<ListResponse<InstanceResponse>>, ApiError> {
    let paginating = q.limit.is_some() || q.cursor.is_some();
    let limit = q.effective_limit(50, 100);
    let cursor = q
        .cursor
        .as_deref()
        .map(|c| decode_cursor(c).ok_or_else(|| ApiError::bad_request("invalid cursor")))
        .transpose()?;

    let mut rows = blocking(move || -> Result<Vec<_>, ApiError> {
        if paginating {
            let cur_ref = cursor.as_ref().map(|(s, id)| (s.as_str(), id.as_str()));
            match auth.role {
                store_rs::UserRole::Admin => state
                    .instance_db
                    .list_paginated(limit, cur_ref)
                    .map_err(ApiError::from),
                store_rs::UserRole::User => state
                    .instance_db
                    .list_for_user_paginated(&auth.user_id, limit, cur_ref)
                    .map_err(ApiError::from),
            }
        } else {
            match auth.role {
                store_rs::UserRole::Admin => state.instance_db.list().map_err(ApiError::from),
                store_rs::UserRole::User => state
                    .instance_db
                    .list_for_user(&auth.user_id)
                    .map_err(ApiError::from),
            }
        }
    })
    .await??;

    let has_more = paginating && rows.len() > limit;
    if has_more {
        rows.truncate(limit);
    }
    let next_cursor = if has_more {
        rows.last().map(|r| encode_cursor(&r.created_at, &r.id))
    } else {
        None
    };

    let items: Vec<InstanceResponse> = rows.into_iter().map(InstanceResponse::from_row).collect();
    Ok(Json(ListResponse::page(items, has_more, next_cursor)))
}

// ─── Get by ID ─────────────────────────────────────────────────────────────────

/// GET /api/v1/instances/{id}
///
/// Returns a single instance's details by ID.
///
/// # Errors
///
/// Returns `ApiError` if the instance is not found or database query fails.
#[tracing::instrument(skip(state, auth))]
pub async fn handle_get_instance(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let row = require_instance(&state, &auth, &id).await?;
    let instance = InstanceResponse::from_row(row);
    Ok(ok(json!(instance)))
}

// ─── Create ───────────────────────────────────────────────────────────────────

fn default_tools() -> Vec<String> {
    vec![
        "codex".to_string(),
        "claude-code".to_string(),
        "opencode".to_string(),
    ]
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreateInstanceReq {
    name: String,
    #[serde(default)]
    claw_type: String,
    /// AI coding tools to pre-install. Defaults to all three when absent.
    #[serde(default = "default_tools")]
    tools: Vec<String>,
    /// Guest OS: `"macos"` or `"linux"`. Empty/absent uses platform default
    /// (macOS host → macOS guest, Linux host → Linux guest).
    #[serde(default)]
    guest_os: String,
    /// CPU cores (1-4). Defaults to the shared vmrunner Create default.
    #[serde(default)]
    cpu_cores: Option<u32>,
    /// RAM in MB (512-8192). Defaults to the shared vmrunner Create default.
    #[serde(default)]
    ram_mb: Option<u32>,
    /// Disk size in GB (5-50). Defaults to the shared vmrunner Create default.
    #[serde(default)]
    disk_gb: Option<u32>,
    /// User to assign this instance to. Admin-only.
    #[serde(default)]
    owner_id: Option<String>,
}

/// POST /api/v1/instances
///
/// # Errors
///
/// Returns `ApiError` on validation failure (bad name, unsupported claw type),
/// rate limiting, name conflict, or database/blocking-task errors.
#[allow(clippy::too_many_lines)]
#[tracing::instrument(skip(state, req))]
pub async fn handle_create_instance_body(
    State(state): State<SharedState>,
    AdminUser(AuthUser { username, .. }): AdminUser,
    Json(req): Json<CreateInstanceReq>,
) -> Result<Response, ApiError> {
    let name = normalize_slug(&req.name);
    if name.is_empty() {
        return Err(ApiError::bad_request("container name is required"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(ApiError::bad_request("container name too long"));
    }

    let claw_type = {
        let ct = normalize_slug(&req.claw_type);
        if ct.is_empty() {
            "picoclaw".to_string()
        } else {
            ct
        }
    };
    if claw_type.len() > MAX_CLAW_TYPE_LEN {
        return Err(ApiError::bad_request("claw type name too long"));
    }

    // Unified availability gate: replaces the previous split-brain
    // Registry::is_valid + ClawStore::is_ready + maintenance early-return.
    // The projection fuses manifest (known?), ClawStore (installed?), and
    // host state (cold path + maintenance) into a single verdict.
    //
    // Maintenance mode is now handled here — when OverallState::Blocked
    // with reason MaintenanceMode, we return HTTP 503 + Retry-After header
    // directly. This lets us keep a single source of truth (the projection)
    // for "can this claw be created right now?" without sprinkling separate
    // gates across the handler.
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
                    format!(
                        "claw type '{claw_type}' is not installed — install it from the claw store first"
                    ),
                    reasons_json,
                ));
            }
            OverallState::Installing { percent } => {
                return Err(ApiError::bad_request_with_reasons(
                    format!(
                        "claw type '{claw_type}' is still installing ({percent}%) — wait for it to finish"
                    ),
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
                // Separate maintenance (503 + Retry-After) from other blocked
                // reasons (400 + reasons). Maintenance is transient — the
                // client is expected to back off and retry — whereas things
                // like NoColdPathAvailable indicate a host config problem.
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
                            "claw type '{claw_type}' cannot be created: no base rootfs or golden image available on this host"
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

    // Validate resource configuration — only enforce physical minimums.
    // Maximum limits are enforced dynamically by check_capacity() based on real
    // host resources and current allocation (no hardcoded caps).
    let resources =
        VmCreateResourceSpec::from_options(req.cpu_cores, req.ram_mb, req.disk_gb).resolve();
    let cpu_cores = resources.cpu_cores;
    let ram_mb = resources.ram_mb;
    let disk_gb = resources.disk_gb;

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

    // Validate and normalize tool names
    let tools: Vec<String> = req
        .tools
        .iter()
        .map(|t| {
            normalize_tool_name(t)
                .map(String::from)
                .ok_or_else(|| ApiError::bad_request(format!("unknown tool: {t}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Note: the maintenance gate that used to live here has been folded
    // into the unified availability projection check above. The projection
    // reads from the same `core_rs::maintenance::read_status` lockfile, so
    // there is a single source of truth for maintenance state across both
    // GET and write paths. See AD5.1 in kind-booping-stearns.md.

    // Rate limit: check + get_remaining in one blocking call
    let (rl_allowed, rl_remaining, rl_error) = {
        let st = state.clone();
        let uname = username.clone();
        blocking(
            move || match st.rate_limiter.check(&uname, "create_instance") {
                Ok(true) => (true, 0i64, None),
                Ok(false) => {
                    let remaining = st
                        .rate_limiter
                        .get_remaining(&uname, "create_instance")
                        .unwrap_or(0);
                    (false, remaining, None)
                }
                Err(e) => (true, 0i64, Some(e.to_string())),
            },
        )
        .await?
    };
    if let Some(e) = rl_error {
        warn!("[instances] rate limit check error: {e}");
    }
    if !rl_allowed {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("X-RateLimit-Remaining", rl_remaining.to_string()),
                ("Retry-After", "3600".to_string()),
            ],
            Json(json!({"error": "rate limit exceeded", "code": "RATE_LIMITED"})),
        )
            .into_response());
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

    // Insert into SQLite
    let sunset_date = {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let future = now_secs + 30 * 24 * 3600;
        format_date(future)
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

    // Provisioning TTL: 20 min, extended by worker between phases.
    // Covers macOS cold boot which can exceed 10 min.
    const PROVISIONING_TTL_SECS: i64 = 1200;
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
        let sd = sunset_date.clone();
        let gos = guest_os.clone();
        let resource_snapshot = create_started_snapshot.clone();
        blocking(move || {
            let new_instance = NewInstance {
                id: &iid,
                name: &n,
                container: &cont,
                claw_type: &ct,
                sunset_date: &sd,
                guest_os: Some(&gos),
                aux_storage_path: None,
                cpu_cores: Some(i64::from(cpu_cores)),
                ram_config_mb: Some(i64::from(ram_mb)),
                disk_gb: Some(i64::from(disk_gb)),
                household_id: None,
                household_machine_id: None,
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

    // Assign owner if specified
    if let Some(ref oid) = req.owner_id {
        let st = state.clone();
        let iid2 = instance_id.clone();
        let oid2 = oid.clone();
        match blocking(move || {
            st.instance_db
                .set_owner(&iid2, Some(&oid2))
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

    let inst = json!({
        "id":        instance_id,
        "name":      name,
        "container": container,
        "claw_type":  claw_type,
        "status":    "provisioning",
    });

    // Create async job.
    // Note: json! macro serialization cannot fail; unwrap_or_default is defensive only.
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

    let mut job = Job::new(JobType::CreateInstance, instance_id.clone(), payload);
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
        if let Err(e) = blocking(move || {
            if let Err(e) = st.instance_db.update_status(&StatusUpdate {
                id: &iid,
                status: InstanceStatus::Provisioning,
                message: "Waiting for resources...",
                error: "",
                job_id: &jid,
                phase: "queuing",
            }) {
                tracing::error!("[instances] failed to set initial phase for {iid}: {e}");
            }
        })
        .await
        {
            tracing::error!("[instances] spawn_blocking error setting initial phase: {e}");
        }
    }

    info!(
        "[instances] user={} queued creation of {} ({}) [job: {}]",
        username, name, container, job_id
    );

    Ok(accepted(json!({
        "instance":  inst,
        "job_id":     job_id,
        "message":   format!("Instance creation queued. Poll /api/v1/jobs/{job_id} for status."),
    })))
}

// ─── Status ───────────────────────────────────────────────────────────────────

/// GET /api/v1/instances/{id}/status
///
/// # Errors
///
/// Returns `ApiError` if the instance is not found or the database query fails.
#[tracing::instrument(skip(state, auth))]
pub async fn handle_instance_status(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let row = require_instance(&state, &auth, &id).await?;

    let is_provisioning = row.status == InstanceStatus::Provisioning;
    let row_job_id = row.job_id.clone();
    let inst = InstanceResponse::from_row(row);

    // If provisioning, fetch the latest job info
    let job_info: Option<Value> = if is_provisioning {
        if let Some(jid) = row_job_id.as_deref().filter(|s| !s.is_empty()) {
            let jid = jid.to_string();
            let st2 = state.clone();
            blocking(move || st2.jobs.get(&jid).map_err(ApiError::from))
                .await
                .ok()
                .and_then(std::result::Result::ok)
                .map(|j| serde_json::to_value(j).unwrap_or(Value::Null))
        } else {
            None
        }
    } else {
        None
    };

    Ok(ok(json!({"instance": inst, "job": job_info})))
}

// ─── Actions ─────────────────────────────────────────────────────────────────

/// Shared logic after the caller has already authorized and resolved the row.
pub(crate) async fn execute_instance_flow_for_row(
    state: &SharedState,
    id: &str,
    row: store_rs::InstanceRow,
    flow_type: FlowType,
) -> Result<(String, String, String), ApiError> {
    let (name, container, claw_type) = (row.name, row.container, row.claw_type);

    let flow_req = ExecuteFlowRequest {
        flow_type: flow_type.clone(),
        instance_id: id.to_string(),
        name: name.clone(),
        container: container.clone(),
        claw_type: claw_type.clone(),
        attempt_errors: vec![],
        attempt_ports: vec![],
        max_port_retries: 3,
        tools: vec![],
        guest_os: String::new(),
        cpu_cores: None,
        ram_mb: None,
        disk_gb: None,
    };

    let st = state.clone();
    let result = blocking(move || {
        st.executor
            .lock_or_internal("executor")
            .map(|exec| exec.execute_flow(&flow_req))
    })
    .await??;

    if result.status == FlowStatus::Failed {
        let act = flow_type.as_str();
        let msg = result.error.unwrap_or_else(|| format!("{act} flow failed"));
        return Err(match result.error_code {
            Some(ErrorCode::NotFound) => ApiError::not_found(msg),
            Some(ErrorCode::Timeout) => ApiError::timeout(msg),
            _ => ApiError::internal(msg),
        });
    }

    Ok((name, container, claw_type))
}

/// POST /api/v1/instances/{id}/stop → 204
///
/// # Errors
///
/// Returns `ApiError` on instance not found, executor failure, or DB error.
#[tracing::instrument(skip_all, fields(instance_id = %id))]
pub async fn handle_stop_instance(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let row = require_instance(&state, &auth, &id).await?;
    stop_instance_for_row(&state, &auth.username, &id, row).await
}

pub(crate) async fn stop_instance_for_row(
    state: &SharedState,
    actor_label: &str,
    id: &str,
    row: store_rs::InstanceRow,
) -> Result<StatusCode, ApiError> {
    let (_, container, _) = execute_instance_flow_for_row(state, id, row, FlowType::Stop).await?;

    let st = state.clone();
    let iid = id.to_string();
    blocking(move || {
        st.instance_db
            .set_desired_state(&iid, store_rs::DesiredState::Stopped)?;
        st.instance_db
            .update_status(&StatusUpdate {
                id: &iid,
                status: InstanceStatus::Stopped,
                message: "",
                error: "",
                job_id: "",
                phase: "",
            })
            .map_err(ApiError::from)
    })
    .await??;

    info!(
        "[instances] user={} action=stop instance={id} container={container}",
        actor_label
    );
    let snapshot = current_capacity_snapshot(state).await;
    // Record instance event (append-only audit trail)
    let _ = state
        .instance_db
        .record_instance_event(&store_rs::NewInstanceEvent {
            instance_id: Some(id),
            event_type: "stopped",
            actor: actor_label,
            detail: Some(&format!("container={container}")),
            resource_snapshot: snapshot.as_deref(),
        });
    state.clone().spawn_audit(
        Some(id.to_string()),
        actor_label.to_string(),
        "stop".to_string(),
        Some(format!("container={container}")),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/instances/{id}/restart → 204
///
/// # Errors
///
/// Returns `ApiError` on instance not found, executor failure, or DB error.
#[tracing::instrument(skip_all, fields(instance_id = %id))]
pub async fn handle_restart_instance(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let row = require_instance(&state, &auth, &id).await?;
    restart_instance_for_row(&state, &auth.username, &id, row).await
}

pub(crate) async fn restart_instance_for_row(
    state: &SharedState,
    actor_label: &str,
    id: &str,
    row: store_rs::InstanceRow,
) -> Result<StatusCode, ApiError> {
    let create_defaults = VmCreateResourceSpec::default().resolve();
    let cpu = row
        .cpu_cores
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(create_defaults.cpu_cores);
    let ram = row
        .ram_config_mb
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(create_defaults.ram_mb);
    let guest_os = row.guest_os.clone();
    let claw_type = row.claw_type.clone();
    let mut acquired_runtime_lease = false;

    {
        let disk_path = core_rs::host_resources::resolve_instance_disk_path();
        let host = core_rs::host_resources::detect_all(&disk_path)
            .map_err(|e| ApiError::internal(format!("{e}")))?;

        let _cap_guard = state.capacity_lock.lock().await;
        let needs_runtime_lease = !state
            .instance_db
            .has_active_lease("instance", id, "runtime")
            .map_err(ApiError::from)?;

        if needs_runtime_lease {
            if let Err(cap_err) = crate::capacity::check_capacity(
                state,
                &host,
                &crate::capacity::CapacityRequest {
                    cpu_cores: cpu,
                    ram_mb: ram,
                    disk_gb: 0, // disk already allocated (storage lease still active)
                    guest_os: &guest_os,
                    claw_type: Some(&claw_type),
                },
            ) {
                return Err(ApiError::service_unavailable(format!(
                    "insufficient resources to restart: {}",
                    cap_err.message
                )));
            }

            state
                .instance_db
                .create_lease(&store_rs::NewLease {
                    owner_type: "instance",
                    owner_id: id,
                    lease_kind: "runtime",
                    cpu_cores: i64::from(cpu),
                    ram_mb: i64::from(ram),
                    disk_gb: 0,
                    expires_at: None,
                })
                .map_err(ApiError::from)?;
            acquired_runtime_lease = true;
        }
    }

    let (_, container, _) =
        match execute_instance_flow_for_row(state, id, row, FlowType::Restart).await {
            Ok(out) => out,
            Err(err) => {
                if acquired_runtime_lease {
                    let _ = state.instance_db.release_lease("instance", id, "runtime");
                }
                return Err(err);
            }
        };

    let st = state.clone();
    let iid = id.to_string();
    blocking(move || {
        st.instance_db
            .set_desired_state(&iid, store_rs::DesiredState::Running)?;
        st.instance_db
            .update_status(&StatusUpdate {
                id: &iid,
                status: InstanceStatus::Active,
                message: "",
                error: "",
                job_id: "",
                phase: "",
            })
            .map_err(ApiError::from)
    })
    .await??;

    if let Err(e) = crate::public_sites::ensure_public_site_targets_for_instance(state, id).await {
        warn!("[instances] restart public site forward restore failed for {id}: {e}");
    }

    info!(
        "[instances] user={} action=restart instance={id} container={container}",
        actor_label
    );
    let snapshot = current_capacity_snapshot(state).await;
    let _ = state
        .instance_db
        .record_instance_event(&store_rs::NewInstanceEvent {
            instance_id: Some(id),
            event_type: "started",
            actor: actor_label,
            detail: Some(&format!("container={container}")),
            resource_snapshot: snapshot.as_deref(),
        });
    state.clone().spawn_audit(
        Some(id.to_string()),
        actor_label.to_string(),
        "restart".to_string(),
        Some(format!("container={container}")),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/v1/instances/{id}/rebuild → 204
///
/// # Errors
///
/// Returns `ApiError` on instance not found, executor failure, or DB error.
#[tracing::instrument(skip_all, fields(instance_id = %id))]
pub async fn handle_rebuild_instance(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let row = require_instance(&state, &auth, &id).await?;
    rebuild_instance_for_row(&state, &auth.username, &id, row).await
}

pub(crate) async fn rebuild_instance_for_row(
    state: &SharedState,
    actor_label: &str,
    id: &str,
    row: store_rs::InstanceRow,
) -> Result<StatusCode, ApiError> {
    let (_, container, _) =
        execute_instance_flow_for_row(state, id, row, FlowType::Rebuild).await?;

    let st = state.clone();
    let iid = id.to_string();
    blocking(move || {
        st.instance_db
            .update_status(&StatusUpdate {
                id: &iid,
                status: InstanceStatus::Active,
                message: "",
                error: "",
                job_id: "",
                phase: "",
            })
            .map_err(ApiError::from)
    })
    .await??;

    if let Err(e) = crate::public_sites::ensure_public_site_targets_for_instance(state, id).await {
        warn!("[instances] rebuild public site forward restore failed for {id}: {e}");
    }

    info!(
        "[instances] user={} action=rebuild instance={id} container={container}",
        actor_label
    );
    let snapshot = current_capacity_snapshot(state).await;
    let _ = state
        .instance_db
        .record_instance_event(&store_rs::NewInstanceEvent {
            instance_id: Some(id),
            event_type: "rebuilt",
            actor: actor_label,
            detail: Some(&format!("container={container}")),
            resource_snapshot: snapshot.as_deref(),
        });
    state.clone().spawn_audit(
        Some(id.to_string()),
        actor_label.to_string(),
        "rebuild".to_string(),
        Some(format!("container={container}")),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/v1/instances/{id} → 204
///
/// # Errors
///
/// Returns `ApiError` on instance not found, executor failure, or DB error.
#[tracing::instrument(skip_all, fields(instance_id = %id))]
pub async fn handle_delete_instance(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let row = require_instance(&state, &auth, &id).await?;
    delete_instance_for_row(&state, &auth.username, &id, row).await
}

pub(crate) async fn delete_instance_for_row(
    state: &SharedState,
    actor_label: &str,
    id: &str,
    row: store_rs::InstanceRow,
) -> Result<StatusCode, ApiError> {
    let delete_started_snapshot = current_capacity_snapshot(state).await;
    let _ = state
        .instance_db
        .record_instance_event(&store_rs::NewInstanceEvent {
            instance_id: Some(id),
            event_type: "delete_started",
            actor: actor_label,
            detail: Some(&format!("container={}", row.container)),
            resource_snapshot: delete_started_snapshot.as_deref(),
        });

    let (_, container, _) = execute_instance_flow_for_row(state, id, row, FlowType::Delete).await?;

    let st = state.clone();
    let iid = id.to_string();
    let container_for_ws = container.clone();
    blocking(move || {
        // Clean up terminal workspaces (they reference the container).
        if let Err(e) = st
            .instance_db
            .delete_conversations_for_container(&container_for_ws)
        {
            tracing::warn!("[instances] delete workspace cleanup: {e}");
        }
        // Soft delete: mark as deleted, keep row for audit history.
        // Leases are already released by the executor flow (Phase 2).
        st.instance_db.soft_delete(&iid).map_err(ApiError::from)
    })
    .await??;

    info!(
        "[instances] user={} action=delete instance={id} container={container}",
        actor_label
    );
    let snapshot = current_capacity_snapshot(state).await;
    let _ = state
        .instance_db
        .record_instance_event(&store_rs::NewInstanceEvent {
            instance_id: Some(id),
            event_type: "delete_completed",
            actor: actor_label,
            detail: Some(&format!("container={container}")),
            resource_snapshot: snapshot.as_deref(),
        });
    state.clone().spawn_audit(
        Some(id.to_string()),
        actor_label.to_string(),
        "delete".to_string(),
        Some(format!("container={container}")),
    );
    Ok(StatusCode::NO_CONTENT)
}

// ─── AutoUpdate ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AutoUpdateReq {
    enabled: bool,
}

/// POST /api/v1/instances/{id}/autoupdate
///
/// # Errors
///
/// Returns `ApiError` if the database update or blocking task fails.
#[tracing::instrument(skip(state, auth, req))]
pub async fn handle_instance_autoupdate(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<AutoUpdateReq>,
) -> Result<StatusCode, ApiError> {
    // Enforce ownership before allowing changes
    require_instance(&state, &auth, &id).await?;

    // Update in instance_db (primary)
    let st = state.clone();
    let iid = id.clone();
    let enabled = req.enabled;
    blocking(move || {
        st.instance_db
            .update_auto_update(&iid, enabled)
            .map_err(ApiError::from)
    })
    .await??;

    info!(
        "[instances] user={} autoupdate={} instance={id}",
        auth.username, req.enabled
    );
    Ok(StatusCode::NO_CONTENT)
}

// ─── Assign owner ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AssignOwnerReq {
    /// User ID to assign, or `null` to unassign.
    pub owner_id: Option<String>,
}

/// PATCH /api/v1/instances/{id}
///
/// Assign or unassign an owner for an instance. Admin-only.
///
/// # Errors
///
/// Returns `ApiError` if the user is not an admin, instance is not found,
/// owner doesn't exist, or database update fails.
#[tracing::instrument(skip(state, req))]
pub async fn handle_assign_owner(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<AssignOwnerReq>,
) -> Result<StatusCode, ApiError> {
    // Admin-only
    if auth.role != store_rs::UserRole::Admin {
        return Err(ApiError::forbidden("admin access required"));
    }

    let st = state.clone();
    let iid = id.clone();
    let owner = req.owner_id.clone();
    blocking(move || -> Result<(), ApiError> {
        // Verify instance exists
        let inst = st
            .instance_db
            .get(&iid)
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::not_found("instance not found"))?;

        // If assigning, verify the user exists
        if let Some(ref uid) = owner {
            st.instance_db
                .get_user(uid)
                .map_err(ApiError::from)?
                .ok_or_else(|| ApiError::not_found("user not found"))?;
        }

        st.instance_db
            .set_owner(&inst.id, owner.as_deref())
            .map_err(ApiError::from)?;

        Ok(())
    })
    .await??;

    info!(
        "[instances] user={} set owner_id={:?} instance={id}",
        auth.username, req.owner_id,
    );
    Ok(StatusCode::NO_CONTENT)
}
