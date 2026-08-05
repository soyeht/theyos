use crate::guest_image_state::GuestImageState;
use crate::state::SharedState;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use core_rs::error::{ApiError, blocking};
use core_rs::ipc::protocol::{LeaseKind, LeaseOwnerType};
use jobs_rs::{Job, JobType};
use serde_json::json;
use store_rs::{InstanceStatus, NewInstance, StatusUpdate, WarmPoolSlotId, normalize_slug};
use vmrunner_common_rs::VmCreateResourceSpec;

/// Max length of a normalized instance/container name, shared by every create
/// path (admin / mobile / household) so the limit can't drift per-surface.
pub(crate) const MAX_NAME_LEN: usize = 64;
/// Max length of a normalized claw-type, shared by every create path.
pub(crate) const MAX_CLAW_TYPE_LEN: usize = 32;

/// Outcome of [`rollback_inserted_instance`]: whether the orphaned instance row
/// was actually removed, or leaked because `delete` failed / the task panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackOutcome {
    /// The inserted row was deleted; no orphan remains.
    CleanedUp,
    /// The row could not be deleted and may still exist. The caller's original
    /// error stays client-facing, but the failure is logged and a best-effort
    /// second-line attempt marks the row terminally `Failed`.
    Orphaned,
}

/// Classify the result of the rollback delete (as returned by `blocking`).
///
/// `Ok(Ok(_))` means the delete committed (`CleanedUp`); anything else - a
/// `delete` error (`Ok(Err)`) or a spawn-blocking join/panic (`Err`) - means the
/// row may still exist (`Orphaned`). Generic over the error types so it is unit-
/// testable without constructing `ApiError` / `JoinError`.
fn classify_rollback_outcome<T, A, B>(result: &Result<Result<T, A>, B>) -> RollbackOutcome {
    if matches!(result, Ok(Ok(_))) {
        RollbackOutcome::CleanedUp
    } else {
        RollbackOutcome::Orphaned
    }
}

/// Best-effort lease cleanup followed by the instance-row delete, operating
/// directly on the instance DB so it is unit-testable with an in-memory DB.
///
/// Releases all resource leases (best-effort), optionally restores the
/// warm-pool lease (best-effort), then deletes the row and returns that delete
/// result - the only step whose failure leaves an orphan.
fn rollback_instance_db(
    instance_db: &store_rs::InstanceDb,
    instance_id: &str,
    restore_warm_pool_lease: bool,
) -> Result<(), ApiError> {
    let row = if restore_warm_pool_lease {
        instance_db.get(instance_id).ok().flatten()
    } else {
        None
    };

    // Release leases first (best-effort).
    if let Err(e) = instance_db.release_all_leases(LeaseOwnerType::Instance, instance_id) {
        tracing::warn!(
            "[create-instance] failed to release leases for {instance_id} during rollback: {e}"
        );
    }

    if restore_warm_pool_lease {
        if let Some(row) = row.as_ref() {
            if let Err(e) = instance_db.create_lease(&store_rs::NewLease {
                owner_type: LeaseOwnerType::WarmPool,
                owner_id: &WarmPoolSlotId::new(&row.claw_type).owner_id(),
                lease_kind: LeaseKind::Runtime,
                cpu_cores: row.cpu_cores.unwrap_or(crate::capacity::SLOT_CPU),
                ram_mb: row.ram_config_mb.unwrap_or(crate::capacity::SLOT_RAM),
                disk_gb: 0,
                expires_at: None,
            }) {
                tracing::warn!(
                    "[create-instance] failed to restore warm-pool lease for {instance_id} during rollback: {e}"
                );
            }
        }
    }

    instance_db.delete(instance_id).map_err(ApiError::from)
}

/// Best-effort cleanup for an instance row inserted before a later step failed.
///
/// This avoids leaving orphaned `provisioning` rows behind when create flows
/// fail after `instances.insert_with_leases()` but before the corresponding job
/// is queued. Releases all resource leases before deleting the row; when the
/// create had already claimed a warm-pool lease but failed before the executor
/// started, the warm-pool lease is restored so capacity accounting matches.
///
/// Returns [`RollbackOutcome::CleanedUp`] when the row was deleted. When the
/// delete fails (or the task panics) the row may be orphaned: this logs a
/// structured error and makes a best-effort second-line attempt to mark the
/// instance terminally `Failed`, so a leaked row is represented (not a phantom
/// `provisioning` row) - then returns [`RollbackOutcome::Orphaned`]. The
/// original create error stays the caller's client-facing cause.
pub async fn rollback_inserted_instance(
    state: &SharedState,
    instance_id: &str,
    failed_step: &str,
    restore_warm_pool_lease: bool,
) -> RollbackOutcome {
    let st = state.clone();
    let iid = instance_id.to_string();
    let delete_result =
        blocking(move || rollback_instance_db(&st.instance_db, &iid, restore_warm_pool_lease))
            .await;

    let outcome = classify_rollback_outcome(&delete_result);
    if outcome == RollbackOutcome::CleanedUp {
        tracing::warn!(
            "[create-instance] rolled back inserted instance {instance_id} after {failed_step} failed"
        );
        return outcome;
    }

    // Orphaned: surface the failure loudly and try a second-line mark-Failed so
    // the leaked row is terminal rather than a phantom `provisioning` row.
    let reason = match &delete_result {
        Ok(Err(e)) => e.to_string(),
        Err(e) => format!("rollback task failed: {e}"),
        Ok(Ok(())) => String::new(), // unreachable: classified CleanedUp above
    };
    tracing::error!(
        instance_id = %instance_id,
        failed_step = %failed_step,
        reason = %reason,
        "[create-instance] failed to roll back inserted instance; attempting to mark it Failed"
    );

    // Persist only a sanitized, generic message on the row: the raw delete/join
    // error may carry internal detail and can surface in UI/status. The raw
    // reason stays in the structured log above.
    let sanitized = format!("rollback cleanup failed after {failed_step}; manual cleanup required");
    let st2 = state.clone();
    let iid2 = instance_id.to_string();
    let mark = blocking(move || {
        st2.instance_db
            .update_status(&StatusUpdate {
                id: &iid2,
                status: InstanceStatus::Failed,
                message: "",
                error: &sanitized,
                job_id: "",
                phase: "",
            })
            .map_err(ApiError::from)
    })
    .await;
    if matches!(mark, Ok(Ok(()))) {
        tracing::warn!(
            instance_id = %instance_id,
            failed_step = %failed_step,
            "[create-instance] orphaned instance marked Failed after rollback delete failed"
        );
    } else {
        tracing::error!(
            instance_id = %instance_id,
            failed_step = %failed_step,
            "[create-instance] rollback delete failed AND could not mark instance Failed; manual cleanup required"
        );
    }

    outcome
}

/// macOS guest-image admission gate, shared by the admin and mobile/household
/// create paths so the `409 GUEST_IMAGE_NOT_READY` shape lives in exactly one
/// place. Returns `Some(conflict response)` when the host's guest image is not
/// yet `done`, else `None`.
///
/// Pure over the supplied state — the caller reads
/// `GuestImageState::read_current()` inside `#[cfg(target_os = "macos")]`, so
/// this is unit-testable on every platform without touching `init-state.json`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn guest_image_not_ready_response(guest: &GuestImageState) -> Option<Response> {
    if guest.status.as_deref() == Some("done") {
        return None;
    }
    Some(
        (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "macOS guest image is not ready",
                "code": "GUEST_IMAGE_NOT_READY",
                "guest_image_phase": guest.phase,
                "guest_image_status": guest.status,
                "guest_image_error": guest.error,
            })),
        )
            .into_response(),
    )
}

/// guest_os-aware wrapper around [`guest_image_not_ready_response`]: the macOS
/// base-image gate only applies to macOS guests. Linux guests boot from their
/// own rootfs and must pass even when no macOS base image exists on this host —
/// otherwise `409 GUEST_IMAGE_NOT_READY` blocks every Linux create and the
/// Linux capacity exemption (`capacity.rs`, guarded on `guest_os == "macos"`)
/// is never reached.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn guest_image_gate_for_guest_os(
    guest_os: &str,
    guest: &GuestImageState,
) -> Option<Response> {
    if guest_os != "macos" {
        return None;
    }
    guest_image_not_ready_response(guest)
}

/// Household scope stamped onto instances created through household `PoP` routes.
/// `PoP` authorization stays ABOVE the core; the core only threads this onto the
/// inserted row (`household_id` / `household_machine_id`).
#[derive(Clone, Debug)]
pub(crate) struct HouseholdInstanceScope {
    pub household_id: String,
    pub household_machine_id: String,
}

/// Per-surface shape of the create `429`. Admin enriches it with rate-limit
/// headers and logs a check error; mobile/household return a bare body and fail
/// open silently. Kept a parameter so the shared core preserves each surface's
/// existing behavior verbatim.
#[derive(Clone, Copy)]
pub(crate) enum RateLimitResponseStyle {
    /// Admin: `429` carries `X-RateLimit-Remaining` + `Retry-After: 3600`, and a
    /// rate-limiter check error is logged.
    Rich,
    /// Mobile / household: bare `429`; a check error fails open silently.
    Bare,
}

/// Tool list handed to the core. Admin passes raw request tools which the core
/// validates at the ORIGINAL admin validation point (after resources, before rate
/// limit) so error precedence is preserved; mobile/household pass the already-
/// validated default trio.
pub(crate) enum CreateTools {
    /// Pre-validated tools (mobile/household default trio) — used as-is.
    Validated(Vec<String>),
    /// Admin raw tool names — validated by the core (an unknown tool only
    /// surfaces after name / availability / `guest_os` / gate / resources).
    AdminRaw(Vec<String>),
}

/// Already-resolved create inputs the adapters hand to the core. Each adapter
/// parses its own request type, so the core never sees a surface-specific request
/// struct.
pub(crate) struct CreateInstanceInputs {
    pub name: String,
    pub claw_type: String,
    pub guest_os: String,
    pub cpu_cores: Option<u32>,
    pub ram_mb: Option<u32>,
    pub disk_gb: Option<u32>,
    pub owner_id: Option<String>,
    pub tools: CreateTools,
}

/// Identity facts about a successfully-queued instance. Each adapter renders its
/// own success envelope from these (admin nested, mobile/household flat).
pub(crate) struct CreatedInstanceFacts {
    pub instance_id: String,
    pub name: String,
    pub container: String,
    pub claw_type: String,
    pub job_id: String,
}

/// Outcome of the shared create pipeline: either a queued instance (the adapter
/// renders its envelope) or an early raw `Response` returned verbatim. The early
/// returns (maintenance 503 / rate-limit 429 / guest-image 409 / capacity 503)
/// are raw `(StatusCode, headers, Json)` responses, not `ApiError`.
pub(crate) enum CreateOutcome {
    Created(CreatedInstanceFacts),
    EarlyResponse(Response),
}

/// Provisioning TTL: 20 min, extended by the worker between phases. Covers macOS
/// cold boot which can exceed 10 min.
const PROVISIONING_TTL_SECS: i64 = 1200;

/// The default tool trio used by the mobile / household create surfaces.
pub(crate) fn default_mobile_tools() -> Vec<String> {
    ["codex", "claude-code", "opencode"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// Canonicalize an admin-supplied tool name, or `None` if unknown. Lives next to
/// the create core that validates admin tools so the core does not reach into a
/// handler module.
fn normalize_tool_name(name: &str) -> Option<&'static str> {
    match name {
        "codex" => Some("codex"),
        "claude-code" | "claudeCode" | "claude_code" => Some("claude-code"),
        "opencode" | "openCode" | "open_code" | "open-code" => Some("opencode"),
        _ => None,
    }
}

fn rate_limited_response(style: RateLimitResponseStyle, remaining: i64) -> Response {
    let body = json!({"error": "rate limit exceeded", "code": "RATE_LIMITED"});
    match style {
        RateLimitResponseStyle::Rich => (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("X-RateLimit-Remaining", remaining.to_string()),
                ("Retry-After", "3600".to_string()),
            ],
            Json(body),
        )
            .into_response(),
        RateLimitResponseStyle::Bare => (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response(),
    }
}

/// The single shared create-instance pipeline behind the admin, mobile, and
/// household create surfaces. Validation → availability projection → host-level
/// macOS guest-image gate → resource minimums → rate limit → conflict → capacity
/// lock + check + warm-pool lease decision + insert → owner assignment → Job
/// creation → initial status, rolling back the inserted row on owner/job failure.
///
/// Per-surface divergences are parameters only: `actor_username` (rate-limit key +
/// `job.actor`), `inputs.tools` (already final), `household_scope` (insert only),
/// and `rate_limit_style` (429 richness + check-error logging). Auth / `PoP` stays
/// ABOVE the core. Returns [`CreateOutcome::Created`] (the adapter renders its own
/// success envelope) or [`CreateOutcome::EarlyResponse`] for the raw early returns.
pub(crate) async fn create_instance_core(
    state: &SharedState,
    actor_username: &str,
    inputs: CreateInstanceInputs,
    household_scope: Option<&HouseholdInstanceScope>,
    rate_limit_style: RateLimitResponseStyle,
    log_tag: &'static str,
) -> Result<CreateOutcome, ApiError> {
    use core_rs::availability::{OverallState, UnavailReason};

    let name = normalize_slug(&inputs.name);
    if name.is_empty() {
        return Err(ApiError::bad_request("container name is required"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(ApiError::bad_request("container name too long"));
    }
    let claw_type = {
        let ct = normalize_slug(&inputs.claw_type);
        if ct.is_empty() {
            "picoclaw".to_string()
        } else {
            ct
        }
    };
    if claw_type.len() > MAX_CLAW_TYPE_LEN {
        return Err(ApiError::bad_request("claw type name too long"));
    }

    // Unified availability gate (manifest + ClawStore + host/maintenance).
    {
        let avail = crate::availability::project_claw(&claw_type, state);
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
                // Maintenance → 503 + Retry-After (transient); other blocked
                // reasons → 400 (host config problem).
                let maintenance_retry = avail.reasons.iter().find_map(|r| match r {
                    UnavailReason::MaintenanceMode { retry_after_secs } => Some(*retry_after_secs),
                    _ => None,
                });
                if let Some(retry) = maintenance_retry {
                    return Ok(CreateOutcome::EarlyResponse(
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            [("Retry-After", retry.to_string())],
                            Json(json!({
                                "error": "service temporarily unavailable — artifact sync in progress",
                                "code": "SERVICE_UNAVAILABLE",
                                "reasons": avail.reasons,
                                "retry_after_secs": retry,
                            })),
                        )
                            .into_response(),
                    ));
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
                    .unwrap_or_else(|| format!("claw type '{claw_type}' cannot be created right now"));
                return Err(ApiError::bad_request_with_reasons(
                    blocked_msg,
                    reasons_json,
                ));
            }
        }
    }

    // guest_os: empty → platform default; else validate.
    let guest_os: String = if inputs.guest_os.is_empty() {
        (if cfg!(target_os = "macos") {
            "macos"
        } else {
            "linux"
        })
        .into()
    } else {
        match inputs.guest_os.as_str() {
            "macos" | "linux" => inputs.guest_os.clone(),
            _ => return Err(ApiError::bad_request("guest_os must be 'macos' or 'linux'")),
        }
    };

    // Host-level macOS guest-image gate (PR-1; `#[cfg(target_os = "macos")]`).
    // Only macOS guests are gated — Linux guests boot from their own rootfs.
    #[cfg(target_os = "macos")]
    {
        if let Some(resp) = guest_image_gate_for_guest_os(
            &guest_os,
            &crate::guest_image_state::GuestImageState::read_current(),
        ) {
            return Ok(CreateOutcome::EarlyResponse(resp));
        }
    }

    // Resource minimums (max enforced dynamically by check_capacity()).
    let resources =
        VmCreateResourceSpec::from_options(inputs.cpu_cores, inputs.ram_mb, inputs.disk_gb)
            .resolve();
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
    if inputs.disk_gb.is_some() {
        return Err(ApiError::bad_request(
            "custom disk_gb is not supported on macOS hosts; disk size is determined by the base image",
        ));
    }

    // Resolve tools at the ORIGINAL admin validation point (after resources,
    // before rate limit) so error precedence is preserved: an invalid admin tool
    // only surfaces after name / availability / guest_os / gate / resources.
    // Mobile/household pass the pre-validated trio and skip validation (as before).
    let tools: Vec<String> = match inputs.tools {
        CreateTools::Validated(t) => t,
        CreateTools::AdminRaw(raw) => raw
            .iter()
            .map(|t| {
                normalize_tool_name(t)
                    .map(String::from)
                    .ok_or_else(|| ApiError::bad_request(format!("unknown tool: {t}")))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };

    // Rate limit. Rich (admin) logs a check error; Bare (mobile/household) fails
    // open silently. The 429 SHAPE is rendered per-surface by rate_limited_response.
    {
        let st = state.clone();
        let actor = actor_username.to_string();
        let rich = matches!(rate_limit_style, RateLimitResponseStyle::Rich);
        let denied: Option<i64> = blocking(move || {
            match st.rate_limiter.check(&actor, "create_instance") {
                Ok(true) => None,
                Ok(false) => Some(if rich {
                    st.rate_limiter
                        .get_remaining(&actor, "create_instance")
                        .unwrap_or(0)
                } else {
                    0
                }),
                Err(e) => {
                    // Rich (admin) preserves the original "[instances]" log; Bare
                    // (mobile/household) fails open silently.
                    if rich {
                        tracing::warn!("{log_tag} rate limit check error: {e}");
                    }
                    None
                }
            }
        })
        .await?;
        if let Some(remaining) = denied {
            return Ok(CreateOutcome::EarlyResponse(rate_limited_response(
                rate_limit_style,
                remaining,
            )));
        }
    }

    let instance_id = format!("inst-{name}");
    let container = format!("{claw_type}-{name}");

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

    // Detect host resources (I/O outside the capacity lock).
    let disk_path = core_rs::host_resources::resolve_instance_disk_path();
    let host = core_rs::host_resources::detect_all(&disk_path)
        .map_err(|e| ApiError::internal(format!("{e}")))?;

    let sunset_date = {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        crate::time_util::format_date(now_secs + 30 * 24 * 3600)
    };

    // Capacity lock serializes check + insert against over-commit.
    let _cap_guard = state.capacity_lock.lock().await;
    let cap_req = crate::capacity::CapacityRequest {
        cpu_cores,
        ram_mb,
        disk_gb,
        guest_os: &guest_os,
        claw_type: Some(&claw_type),
    };
    let projection = match crate::capacity::check_capacity(state, &host, &cap_req) {
        Ok(p) => p,
        Err(cap_err) => {
            return Ok(CreateOutcome::EarlyResponse(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "error": cap_err.message,
                        "code": "SERVICE_UNAVAILABLE",
                        "retry_after_secs": cap_err.retry_after_secs,
                    })),
                )
                    .into_response(),
            ));
        }
    };

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

    // Insert + leases (atomic). household_scope threads onto the row only.
    {
        let st = state.clone();
        let iid = instance_id.clone();
        let n = name.clone();
        let cont = container.clone();
        let ct = claw_type.clone();
        let sd = sunset_date.clone();
        let gos = guest_os.clone();
        let resource_snapshot = create_started_snapshot.clone();
        let household_id = household_scope.map(|s| s.household_id.clone());
        let household_machine_id = household_scope.map(|s| s.household_machine_id.clone());
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
                household_id: household_id.as_deref(),
                household_machine_id: household_machine_id.as_deref(),
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

    // Owner assignment (rolls back the inserted row on failure).
    if let Some(ref oid) = inputs.owner_id {
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
                // Original error stays client-facing; rollback represents any
                // orphan internally (structured log + best-effort mark-Failed).
                rollback_inserted_instance(state, &instance_id, "owner assignment", use_warm_pool)
                    .await;
                return Err(e);
            }
        }
    }

    // Create the async job (rolls back the inserted row on failure).
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
    job.actor = Some(actor_username.to_string());
    let job_id = job.id.clone();
    {
        let st = state.clone();
        match blocking(move || st.jobs.create(&mut job).map_err(ApiError::from)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) | Err(e) => {
                // Original error stays client-facing; rollback represents any
                // orphan internally (structured log + best-effort mark-Failed).
                rollback_inserted_instance(state, &instance_id, "job creation", use_warm_pool)
                    .await;
                return Err(e);
            }
        }
    }

    // Initial "queuing" phase (best-effort).
    {
        let st = state.clone();
        let iid = instance_id.clone();
        let jid = job_id.clone();
        // Inner update_status error preserves the per-surface tag. The OUTER
        // spawn_blocking error log was admin-only; it is now emitted on both
        // surfaces (mobile/household GAIN this observability-only log — admin
        // unchanged).
        if let Err(e) = blocking(move || {
            if let Err(e) = st.instance_db.update_status(&StatusUpdate {
                id: &iid,
                status: InstanceStatus::Provisioning,
                message: "Waiting for resources...",
                error: "",
                job_id: &jid,
                phase: "queuing",
            }) {
                tracing::error!("{log_tag} failed to set initial phase for {iid}: {e}");
            }
        })
        .await
        {
            tracing::error!("{log_tag} spawn_blocking error setting initial phase: {e}");
        }
    }

    tracing::info!(
        "{log_tag} user={} queued creation of {} ({}) [job: {}]",
        actor_username,
        name,
        container,
        job_id
    );

    Ok(CreateOutcome::Created(CreatedInstanceFacts {
        instance_id,
        name,
        container,
        claw_type,
        job_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_blocks_until_guest_image_done() {
        for status in ["pending", "in_progress", "failed"] {
            let guest = GuestImageState {
                status: Some(status.to_string()),
                ..Default::default()
            };
            let resp = guest_image_not_ready_response(&guest)
                .unwrap_or_else(|| panic!("status {status:?} must be gated"));
            assert_eq!(resp.status(), StatusCode::CONFLICT);
        }
        // No init-state.json yet (fresh / not started) gates too.
        let fresh = guest_image_not_ready_response(&GuestImageState::not_applicable())
            .expect("a fresh (not-started) guest image must be gated");
        assert_eq!(fresh.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn gate_allows_once_guest_image_done() {
        let done = GuestImageState {
            status: Some("done".to_string()),
            ..Default::default()
        };
        assert!(guest_image_not_ready_response(&done).is_none());
    }

    #[test]
    fn gate_skips_linux_guests_even_without_macos_image() {
        // A host with NO macOS base image (state file absent → not_applicable)
        // must still admit Linux guests: they boot from their own rootfs.
        assert!(guest_image_gate_for_guest_os("linux", &GuestImageState::not_applicable()).is_none());
        // ...and the same holds while the macOS image is pending, installing,
        // or failed — none of those concern a Linux guest.
        for status in ["pending", "in_progress", "failed"] {
            let guest = GuestImageState {
                status: Some(status.to_string()),
                ..Default::default()
            };
            assert!(
                guest_image_gate_for_guest_os("linux", &guest).is_none(),
                "linux guest must bypass the macOS image gate (status {status:?})"
            );
        }
    }

    #[test]
    fn gate_still_blocks_macos_guests_until_image_done() {
        let resp = guest_image_gate_for_guest_os("macos", &GuestImageState::not_applicable())
            .expect("macOS guest without a base image must still be gated");
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let done = GuestImageState {
            status: Some("done".to_string()),
            ..Default::default()
        };
        assert!(guest_image_gate_for_guest_os("macos", &done).is_none());
    }

    #[tokio::test]
    async fn gate_response_body_carries_the_failure_contract() {
        let guest = GuestImageState {
            phase: Some("install_macos".to_string()),
            status: Some("in_progress".to_string()),
            error: None,
            ..Default::default()
        };
        let resp = guest_image_not_ready_response(&guest).expect("must gate");
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(v["code"], "GUEST_IMAGE_NOT_READY");
        assert_eq!(v["guest_image_status"], "in_progress");
        assert_eq!(v["guest_image_phase"], "install_macos");
        assert!(
            v.as_object()
                .expect("object body")
                .contains_key("guest_image_error"),
            "the gate body must always carry guest_image_error (null when absent)"
        );
    }

    // rollback outcome classification + real delete

    #[test]
    fn classify_rollback_cleaned_up_on_ok_ok() {
        let r: Result<Result<(), &str>, &str> = Ok(Ok(()));
        assert_eq!(classify_rollback_outcome(&r), RollbackOutcome::CleanedUp);
    }

    #[test]
    fn classify_rollback_orphaned_on_delete_error() {
        let r: Result<Result<(), &str>, &str> = Ok(Err("delete failed"));
        assert_eq!(classify_rollback_outcome(&r), RollbackOutcome::Orphaned);
    }

    #[test]
    fn classify_rollback_orphaned_on_join_panic() {
        let r: Result<Result<(), &str>, &str> = Err("join/panic");
        assert_eq!(classify_rollback_outcome(&r), RollbackOutcome::Orphaned);
    }

    #[test]
    fn rollback_instance_db_removes_inserted_row() {
        use store_rs::{InstanceDb, NewInstance};
        let db = InstanceDb::open(":memory:").expect("open :memory:");
        let id = "inst-rollback-test";
        db.insert(&NewInstance {
            id,
            name: "rollme",
            container: "rollme-1",
            claw_type: "picoclaw",
            sunset_date: "2026-12-31",
            guest_os: None,
            aux_storage_path: None,
            cpu_cores: None,
            ram_config_mb: None,
            disk_gb: None,
            household_id: None,
            household_machine_id: None,
        })
        .expect("insert");
        assert!(
            db.get(id).unwrap().is_some(),
            "row should exist before rollback"
        );

        let result = rollback_instance_db(&db, id, false);
        assert!(result.is_ok(), "delete should succeed: {result:?}");
        assert!(
            db.get(id).unwrap().is_none(),
            "row should be removed after rollback"
        );
    }
}
