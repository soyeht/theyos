//! `jobs_worker.rs` — Background task that drains the jobs queue and runs
//! executor flows (Phase 2).
//!
//! Mirrors Go's `jobs.Manager` + `Server.handleJob` / `buildFlowRequest`.
//!
//! Runs as a tokio task. Uses `spawn_blocking` for all SQLite/executor calls.

use crate::state::SharedState;
use core_rs::error::MutexExt;
use executor_rs::{ExecuteFlowRequest, FlowStatus, FlowType};
use jobs_rs::JobType;
use std::time::Duration;
use store_rs::{InstanceStatus, StatusUpdate};
use tokio::time::sleep;
use tracing::{error, info, warn};
use vmrunner_common_rs::VmCreateTimingWire;

const MAX_PORT_RETRIES: i32 = 3;
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const ERROR_BACKOFF: Duration = Duration::from_secs(5);
/// How long to sleep before re-polling after deferring a `CreateInstance` job
/// due to maintenance mode. Longer than `POLL_INTERVAL` to avoid busy-looping
/// against the maintenance lock file.
const MAINTENANCE_DEFER_INTERVAL: Duration = Duration::from_secs(10);

/// Spawns the jobs worker as a background tokio task.
/// Returns the `JoinHandle` so the caller can monitor for panics.
pub fn start_jobs_worker(state: SharedState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_worker(state))
}

async fn run_worker(state: SharedState) {
    info!("[jobs-worker] started");

    // Recover from unclean shutdown: any job left in `running` will never
    // complete because the executor subprocess that was handling it is gone.
    // Mark them failed so the UI doesn't show stale "running" forever.
    let st = state.clone();
    if let Err(e) =
        tokio::task::spawn_blocking(
            move || match st.jobs.fail_running_jobs("server restarted") {
                Ok(0) => {}
                Ok(n) => {
                    warn!("[jobs-worker] marked {n} stale running job(s) as failed on startup");
                }
                Err(e) => warn!("[jobs-worker] failed to clean up running jobs on startup: {e}"),
            },
        )
        .await
    {
        error!("[jobs-worker] spawn_blocking join error on startup: {e}");
    }

    loop {
        // Wrap the entire loop body in error handling so no panic kills the worker.
        if let Err(e) = process_one_job(&state).await {
            error!("[jobs-worker] loop error: {e}");
            sleep(ERROR_BACKOFF).await;
        }
    }
}

/// Process a single job iteration. Returns Ok(()) on success or empty queue,
/// Err on any unexpected failure (logged by caller, never panics).
async fn process_one_job(state: &SharedState) -> Result<(), String> {
    let st = state.clone();
    let claimed = tokio::task::spawn_blocking(move || {
        st.jobs
            .claim_next_pending_excluding(&["install_claw", "uninstall_claw"])
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("spawn_blocking join: {e}"))??;

    match claimed {
        None => {
            // Queue empty — back off
            sleep(POLL_INTERVAL).await;
            Ok(())
        }
        Some(mut job) => {
            info!(
                "[jobs-worker] processing job={} type={} instance={}",
                job.id,
                job.job_type.as_str(),
                job.instance_id
            );

            // Maintenance mode gate: defer CreateInstance jobs during artifact sync.
            // The job is put back to pending so it will be picked up once maintenance
            // ends. Delete/Restart jobs are allowed through — they don't depend on
            // golden images or snapshots.
            if job.job_type == JobType::CreateInstance
                && core_rs::maintenance::creates_blocked(&state.locks_dir)
            {
                info!(
                    "[jobs-worker] deferring job={} (CreateInstance): maintenance in progress",
                    job.id
                );
                job.status = jobs_rs::Status::Pending;
                job.started_at = None;
                job.message = Some("deferred: maintenance in progress".to_string());
                let st = state.clone();
                let deferred_job = job;
                if let Err(e) = tokio::task::spawn_blocking(move || st.jobs.update(&deferred_job))
                    .await
                    .map_err(|e| format!("spawn_blocking join: {e}"))?
                {
                    error!("[jobs-worker] failed to defer job: {e}");
                }
                sleep(MAINTENANCE_DEFER_INTERVAL).await;
                return Ok(());
            }

            let flow_req = build_flow_request(&job);
            let job_id = job.id.clone();
            let instance_id = job.instance_id.clone();

            match flow_req {
                // Unknown job type — not a data error, just skip/fail
                Ok(None) => {
                    let msg = format!("unknown job type: {}", job.job_type.as_str());
                    error!("[jobs-worker] {}", msg);
                    mark_failed(state, &job_id, &instance_id, &msg, None).await;
                }
                // Known job type but payload could not be deserialized
                Err(msg) => {
                    error!("[jobs-worker] job={} bad payload: {}", job_id, msg);
                    mark_failed(state, &job_id, &instance_id, &msg, None).await;
                }
                Ok(Some(req)) => {
                    let st = state.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        st.executor
                            .lock_or_internal("executor")
                            .map(|exec| exec.execute_flow(&req))
                    })
                    .await
                    .map_err(|e| format!("spawn_blocking join: {e}"))?
                    .map_err(|e| format!("executor lock: {e}"))?;

                    if result.status == FlowStatus::Failed {
                        let msg = result
                            .error
                            .unwrap_or_else(|| "executor flow failed".to_string());
                        error!("[jobs-worker] job={} failed: {}", job_id, msg);
                        mark_failed(state, &job_id, &instance_id, &msg, result.error_context).await;
                    } else {
                        let result_json = create_timing_result_json(&result.create_timing);

                        info!("[jobs-worker] job={} completed", job_id);
                        mark_completed(state, &job_id, &instance_id, &result_json).await;
                    }
                }
            }
            Ok(())
        }
    }
}

/// Build an `ExecuteFlowRequest` from a claimed job.
///
/// Returns:
///   `Ok(Some(req))` — request built successfully
///   `Ok(None)`      — job type is unknown (already warned)
///   `Err(msg)`      — known job type but payload is malformed
fn build_flow_request(job: &jobs_rs::Job) -> Result<Option<ExecuteFlowRequest>, String> {
    match &job.job_type {
        JobType::CreateInstance => build_create_request(job).map(Some),
        JobType::DeleteInstance => build_delete_request(job).map(Some),
        JobType::RestartInstance => build_restart_request(job).map(Some),
        // InstallClaw/UninstallClaw are handled by install_worker — should never reach here
        // because claim_next_pending_excluding filters them out.
        JobType::InstallClaw | JobType::UninstallClaw => {
            warn!("[jobs-worker] install/uninstall job reached main worker — skipping");
            Ok(None)
        }
        JobType::Unknown(t) => {
            warn!("[jobs-worker] unknown job type: {t}");
            Ok(None)
        }
    }
}

fn build_create_request(job: &jobs_rs::Job) -> Result<ExecuteFlowRequest, String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    struct CreatePayload {
        name: String,
        #[serde(alias = "clawType")]
        claw_type: String,
        #[serde(default)]
        tools: Vec<String>,
        #[serde(default, alias = "guestOs")]
        guest_os: String,
        #[serde(default, alias = "cpuCores")]
        cpu_cores: Option<u32>,
        #[serde(default, alias = "ramMb")]
        ram_mb: Option<u32>,
        #[serde(default, alias = "diskGb")]
        disk_gb: Option<u32>,
    }

    let payload: CreatePayload = serde_json::from_str(&job.payload)
        .map_err(|e| format!("bad create payload for job {}: {e}", job.id))?;

    Ok(ExecuteFlowRequest {
        flow_type: FlowType::Create,
        instance_id: job.instance_id.clone(),
        name: payload.name.clone(),
        container: format!("{}-{}", payload.claw_type, payload.name),
        claw_type: payload.claw_type,
        attempt_errors: vec![],
        attempt_ports: vec![],
        max_port_retries: MAX_PORT_RETRIES,
        tools: payload.tools,
        guest_os: payload.guest_os,
        cpu_cores: payload.cpu_cores,
        ram_mb: payload.ram_mb,
        disk_gb: payload.disk_gb,
    })
}

fn build_delete_request(job: &jobs_rs::Job) -> Result<ExecuteFlowRequest, String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    struct DeletePayload {
        name: String,
        container: String,
        #[serde(alias = "clawType")]
        claw_type: String,
    }

    let payload: DeletePayload = serde_json::from_str(&job.payload)
        .map_err(|e| format!("bad delete payload for job {}: {e}", job.id))?;

    Ok(ExecuteFlowRequest {
        flow_type: FlowType::Delete,
        instance_id: job.instance_id.clone(),
        name: payload.name,
        container: payload.container,
        claw_type: payload.claw_type,
        attempt_errors: vec![],
        attempt_ports: vec![],
        max_port_retries: 0,
        tools: vec![],
        guest_os: String::new(),
        cpu_cores: None,
        ram_mb: None,
        disk_gb: None,
    })
}

fn build_restart_request(job: &jobs_rs::Job) -> Result<ExecuteFlowRequest, String> {
    #[derive(serde::Deserialize)]
    struct RestartPayload {
        container: String,
    }

    let payload: RestartPayload = serde_json::from_str(&job.payload)
        .map_err(|e| format!("bad restart payload for job {}: {e}", job.id))?;

    if payload.container.is_empty() {
        return Err(format!("restart job {} missing container", job.id));
    }

    Ok(ExecuteFlowRequest {
        flow_type: FlowType::Restart,
        instance_id: job.instance_id.clone(),
        name: String::new(),
        container: payload.container,
        claw_type: String::new(),
        attempt_errors: vec![],
        attempt_ports: vec![],
        max_port_retries: 0,
        tools: vec![],
        guest_os: String::new(),
        cpu_cores: None,
        ram_mb: None,
        disk_gb: None,
    })
}

// ─── Status helpers ───────────────────────────────────────────────────────────

async fn mark_failed(
    state: &SharedState,
    job_id: &str,
    instance_id: &str,
    msg: &str,
    error_context: Option<serde_json::Value>,
) {
    let st = state.clone();
    let jid = job_id.to_string();
    let iid = instance_id.to_string();
    let m = msg.to_string();
    // Serialize error_context into the result field so the API can return it.
    let ctx_json = error_context
        .map(|ctx| serde_json::json!({ "error_context": ctx }).to_string())
        .unwrap_or_default();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        let mut record_create_failed = false;
        let mut actor = String::from("system");

        // Update job status
        if let Ok(mut job) = st.jobs.get(&jid) {
            record_create_failed = job.job_type == jobs_rs::JobType::CreateInstance;
            if let Some(job_actor) = job.actor.clone() {
                actor = job_actor;
            }
            job.status = jobs_rs::Status::Failed;
            job.error = Some(m.clone());
            job.completed_at = Some(jobs_rs::now_iso());
            if !ctx_json.is_empty() {
                job.result = Some(ctx_json.clone());
            }
            if let Err(e) = st.jobs.update(&job) {
                error!("[jobs-worker] failed to update job status: {e}");
            }
        }
        // Update instance status in DB
        if let Err(e) = st.instance_db.update_status(&StatusUpdate {
            id: &iid,
            status: InstanceStatus::Failed,
            message: "",
            error: &m,
            job_id: "",
            phase: "",
        }) {
            error!("[jobs-worker] failed to update instance status: {e}");
        }

        if record_create_failed {
            let resource_snapshot = crate::capacity::capacity_snapshot_json(&st.instance_db).ok();
            if let Err(e) = st
                .instance_db
                .record_instance_event(&store_rs::NewInstanceEvent {
                    instance_id: Some(&iid),
                    event_type: "create_failed",
                    actor: &actor,
                    detail: Some(&m),
                    resource_snapshot: resource_snapshot.as_deref(),
                })
            {
                error!("[jobs-worker] failed to record create_failed event: {e}");
            }
        }
    })
    .await
    {
        error!("[jobs-worker] spawn_blocking join error: {e}");
    }
}

fn create_timing_result_json(timing: &VmCreateTimingWire) -> String {
    if timing.phases.is_none() {
        return "{}".to_string();
    }

    serde_json::to_string(timing).unwrap_or_else(|_| "{}".to_string())
}

async fn mark_completed(state: &SharedState, job_id: &str, instance_id: &str, result: &str) {
    let st = state.clone();
    let jid = job_id.to_string();
    let iid = instance_id.to_string();
    let res = result.to_string();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        let mut record_create_completed = false;
        let mut actor = String::from("system");

        // Update job status
        if let Ok(mut job) = st.jobs.get(&jid) {
            record_create_completed = job.job_type == jobs_rs::JobType::CreateInstance;
            if let Some(job_actor) = job.actor.clone() {
                actor = job_actor;
            }
            job.status = jobs_rs::Status::Completed;
            job.completed_at = Some(jobs_rs::now_iso());
            if !res.is_empty() && res != "{}" {
                job.result = Some(res);
            }
            if let Err(e) = st.jobs.update(&job) {
                error!("[jobs-worker] failed to update job status: {e}");
            }
        }
        // Update instance status in DB
        if let Err(e) = st.instance_db.update_status(&StatusUpdate {
            id: &iid,
            status: InstanceStatus::Active,
            message: "",
            error: "",
            job_id: "",
            phase: "",
        }) {
            error!("[jobs-worker] failed to update instance status: {e}");
        }

        if record_create_completed {
            let resource_snapshot = crate::capacity::capacity_snapshot_json(&st.instance_db).ok();
            if let Err(e) = st
                .instance_db
                .record_instance_event(&store_rs::NewInstanceEvent {
                    instance_id: Some(&iid),
                    event_type: "create_completed",
                    actor: &actor,
                    detail: Some("instance is active"),
                    resource_snapshot: resource_snapshot.as_deref(),
                })
            {
                error!("[jobs-worker] failed to record create_completed event: {e}");
            }
        }
    })
    .await
    {
        error!("[jobs-worker] spawn_blocking join error: {e}");
    }

    if let Err(e) =
        crate::public_sites::ensure_public_site_targets_for_instance(state, instance_id).await
    {
        warn!(
            "[jobs-worker] failed to ensure public site forwards for instance={instance_id}: {e}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmrunner_common_rs::VmCreatePhaseTiming;

    #[test]
    fn create_timing_result_json_preserves_current_shape() {
        let timing = VmCreateTimingWire {
            golden_image_used: Some(true),
            install_skipped: Some(false),
            phases: Some(vec![VmCreatePhaseTiming {
                phase: "pool_install_claw".to_string(),
                ms: 42,
            }]),
            total_ms: Some(100),
        };

        let value: serde_json::Value =
            serde_json::from_str(&create_timing_result_json(&timing)).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "golden_image_used": true,
                "install_skipped": false,
                "phases": [
                    {
                        "phase": "pool_install_claw",
                        "ms": 42
                    }
                ],
                "total_ms": 100
            })
        );
    }

    #[test]
    fn create_timing_result_json_preserves_no_timing_gate() {
        let timing = VmCreateTimingWire {
            total_ms: Some(100),
            ..Default::default()
        };

        assert_eq!(create_timing_result_json(&timing), "{}");
    }
}
