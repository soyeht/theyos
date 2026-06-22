//! Create instance flow implementation.

use serde_json::json;

use crate::{
    ExecuteFlowRequest, ExecuteFlowResult, Executor, ExecutorError, FlowStatus, PhaseTiming,
    orchestrator::{CreateInstanceFlowRequest, run_create_instance_flow, validate_create_request},
};
use core_rs::error::AppError;
use vmrunner_common_rs::{VmCreateResourceSpec, VmCreateTimingWire};

#[allow(clippy::too_many_lines)]
pub(crate) fn execute_create(exec: &Executor, req: &ExecuteFlowRequest) -> ExecuteFlowResult {
    let max_retries = if req.max_port_retries > 0 {
        req.max_port_retries
    } else {
        3
    };

    let mut attempt_errors: Vec<String> = req.attempt_errors.clone();
    let mut attempt_ports: Vec<i64> = req.attempt_ports.clone();

    let mut last_port_conflict_context: Option<serde_json::Value> = None;
    let mut port_conflict_attempts: usize = 0;

    for attempt in 0..max_retries {
        // Build the flow request for the inlined orchestrator.
        let orch_req = CreateInstanceFlowRequest {
            instance_id: req.instance_id.clone(),
            name: req.name.clone(),
            claw_type: req.claw_type.clone(),
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            // max_retries originates from a small positive config value; truncation and sign loss are safe.
            max_port_retries: max_retries as u8,
            attempt_errors: attempt_errors.clone(),
            attempt_ports: attempt_ports
                .iter()
                .filter_map(|p| u16::try_from(*p).ok())
                .collect(),
        };

        if let Err(e) = validate_create_request(&orch_req) {
            let msg = e.to_string();
            exec.set_instance_failed(&req.instance_id, &msg);
            return ExecuteFlowResult::failed(msg);
        }

        let orch_result = run_create_instance_flow(&orch_req);

        match orch_result.status.as_str() {
            "run_steps" => {
                if orch_result.run_steps.is_empty() {
                    let msg = "orchestrator returned empty run_steps".to_string();
                    exec.set_instance_failed(&req.instance_id, &msg);
                    return ExecuteFlowResult::failed(msg);
                }

                // Convert OrchestratorStep → serde_json::Value for execute_create_steps
                let steps: Vec<serde_json::Value> = orch_result
                    .run_steps
                    .iter()
                    .map(|s| {
                        json!({
                            "op": s.op,
                            "params": s.params,
                        })
                    })
                    .collect();

                let result = execute_create_steps(exec, req, &steps, &attempt_ports);

                if result.status == FlowStatus::Failed {
                    if let Some(ref err_msg) = result.error {
                        let is_port_conflict = exec.check_port_conflict(err_msg);
                        if is_port_conflict {
                            tracing::warn!(
                                "[executor] port conflict on attempt {} for {}: {}",
                                attempt,
                                req.instance_id,
                                err_msg
                            );
                            if result.error_context.is_some() {
                                last_port_conflict_context.clone_from(&result.error_context);
                            }
                            port_conflict_attempts += 1;
                            attempt_errors.push(err_msg.clone());
                            if let Some(port) = result.host_port {
                                attempt_ports.push(port);
                            }
                            if let Err(e) = exec.store.call(
                                "InstanceDbClearPort",
                                json!({
                                    "db_path": exec.config.store_db_path,
                                    "id": req.instance_id,
                                }),
                            ) {
                                tracing::warn!("[executor] clear port in db on port conflict: {e}");
                            }
                            if (attempt + 1) < max_retries {
                                continue;
                            }
                            break;
                        }
                    }
                    return result;
                }

                return result;
            }

            "retry" | "defer_go" => {
                // Loop continues to the next attempt naturally.
            }

            "completed" | "success" | "active" => {
                let port = exec.get_host_port(&req.instance_id).unwrap_or(0);
                return ExecuteFlowResult {
                    status: FlowStatus::Completed,
                    host_port: Some(port),
                    ..Default::default()
                };
            }

            "failed" | "error" => {
                let err_msg = orch_result
                    .error
                    .unwrap_or_else(|| "orchestrator flow failed".to_string());
                exec.set_instance_failed(&req.instance_id, &err_msg);
                return ExecuteFlowResult::failed(err_msg);
            }

            other => {
                let msg = format!("unexpected orchestrator status: {other}");
                exec.set_instance_failed(&req.instance_id, &msg);
                return ExecuteFlowResult::failed(msg);
            }
        }
    }

    let msg = format!("create exceeded {max_retries} port-conflict retries");
    exec.set_instance_failed(&req.instance_id, &msg);

    let retry_metadata = json!({
        "final_reason": msg,
        "retry_attempts": port_conflict_attempts,
        "attempt_errors": attempt_errors,
        "attempt_ports": attempt_ports,
    });

    let error_context = Some(if let Some(mut base) = last_port_conflict_context {
        merge_json_objects(&mut base, &retry_metadata);
        base
    } else {
        let stderr_summary = attempt_errors.join("; ");
        let mut synthetic = json!({
            "phase": "network.port_forward",
            "command": "slirp_add_hostfwd",
            "timed_out": false,
            "stderr_tail": stderr_summary,
        });
        merge_json_objects(&mut synthetic, &retry_metadata);
        synthetic
    });

    ExecuteFlowResult {
        status: FlowStatus::Failed,
        error: Some(msg),
        error_context,
        ..Default::default()
    }
}

#[allow(clippy::too_many_lines)]
fn execute_create_steps(
    exec: &Executor,
    req: &ExecuteFlowRequest,
    steps: &[serde_json::Value],
    _exclude_ports: &[i64],
) -> ExecuteFlowResult {
    let mut host_port: i64 = 0;
    let mut timing_phases: Option<Vec<PhaseTiming>> = None;
    let mut timing_total_ms: Option<u64> = None;
    let mut timing_golden_image_used: Option<bool> = None;
    let mut timing_install_skipped: Option<bool> = None;

    for step in steps {
        let op = step["op"].as_str().unwrap_or("");
        let params = &step["params"];

        match op {
            "create_vm" => {
                let claw_type = params["claw_type"]
                    .as_str()
                    .unwrap_or(&req.claw_type)
                    .to_string();
                let name = params["name"].as_str().unwrap_or(&req.name).to_string();
                let container = format!("{claw_type}-{name}");

                exec.update_instance_status(
                    &req.instance_id,
                    "provisioning",
                    &format!("Pulling {claw_type} image..."),
                    "",
                    "",
                    "pulling",
                );

                // Extend lease TTL between phases (20 min from now)
                {
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    #[allow(clippy::cast_possible_wrap)]
                    let new_expires = (now_secs as i64) + 1200;
                    if let Err(e) = exec.store.call(
                        "ResourceLeaseExtend",
                        json!({
                            "db_path": exec.config.store_db_path,
                            "owner_type": "instance",
                            "owner_id": req.instance_id,
                            "lease_kind": "runtime",
                            "new_expires_at": new_expires,
                        }),
                    ) {
                        tracing::warn!("[executor] extend lease TTL for {}: {e}", req.instance_id);
                    }
                }

                let guest_os = if req.guest_os.is_empty() {
                    if cfg!(target_os = "macos") {
                        "macos"
                    } else {
                        "linux"
                    }
                } else {
                    &req.guest_os
                };

                // macOS VZ: allocate a host port for NAT forwarding.
                // Firecracker (Linux) uses internal ports within the netns.
                #[cfg(target_os = "macos")]
                {
                    use std::net::TcpListener;
                    use vmrunner_common_rs::PUBLIC_APP_HOST_PORT_RANGE;

                    for p in PUBLIC_APP_HOST_PORT_RANGE.iter() {
                        if TcpListener::bind(("127.0.0.1", p)).is_ok() {
                            host_port = i64::from(p);
                            break;
                        }
                    }
                }

                let resources =
                    VmCreateResourceSpec::from_options(req.cpu_cores, req.ram_mb, req.disk_gb)
                        .resolve();

                let vm_result = exec.vmrunner.call_with_context(
                    "Create",
                    json!({
                        "container": container,
                        "customer": name,
                        "claw_type": claw_type,
                        "state_dir": exec.config.firecracker_state_dir,
                        "firecracker_bin": exec.config.firecracker_bin,
                        "kernel_image": exec.config.kernel_image,
                        "base_rootfs": exec.config.base_rootfs,
                        "ssh_key": exec.config.ssh_key,
                        "ssh_pubkey": exec.config.ssh_pubkey,
                        "ssh_wait_tries": exec.config.ssh_wait_tries,
                        "tools": req.tools,
                        "guest_os": guest_os,
                        "cpu_cores": resources.cpu_cores,
                        "ram_mb": resources.ram_mb,
                        "disk_gb": resources.disk_gb,
                        "port": host_port,
                    }),
                );

                let vm_response = match vm_result {
                    Ok(v) => v,
                    Err((e, error_context)) => {
                        tracing::warn!(
                            "[executor] create_vm failed for {} ({}), running Delete cleanup",
                            container,
                            e
                        );
                        if let Err(e) = exec.vmrunner.call(
                            "Delete",
                            json!({
                                "container": container,
                                "state_dir": exec.config.firecracker_state_dir,
                            }),
                        ) {
                            tracing::warn!("[executor] vm delete on create rollback: {e}");
                        }

                        // Release all leases on create failure
                        if let Err(e) = exec.store.call(
                            "ResourceLeaseReleaseAll",
                            json!({
                                "db_path": exec.config.store_db_path,
                                "owner_type": "instance",
                                "owner_id": req.instance_id,
                            }),
                        ) {
                            tracing::warn!("[executor] release leases on create rollback: {e}");
                        }

                        let exec_err = ExecutorError::from(e);
                        let code = exec_err.code();
                        let msg = exec_err.to_string();
                        return ExecuteFlowResult {
                            status: crate::FlowStatus::Failed,
                            error: Some(msg),
                            error_code: Some(code),
                            error_context,
                            host_port: Some(host_port),
                            ..Default::default()
                        };
                    }
                };

                // Extract SSH port from vm_response if available
                if let Some(port) = vm_response.get("port").and_then(serde_json::Value::as_i64) {
                    host_port = port;
                }

                // Persist vm_ip / vm_mac to the DB so callers like the
                // public-sites resolver (`public_sites.rs:should_use_vm_ip_target`)
                // can read them from `instances` instead of scraping per-container
                // files. The vmrunner subprocess writes the file as a side effect;
                // without this call the DB column stays NULL forever and any
                // create-public-site call answers `bad_request("instance has no
                // vm_ip yet")` even after the VM has booted.
                if let (Some(vm_ip), Some(vm_mac)) = (
                    vm_response.get("vm_ip").and_then(serde_json::Value::as_str),
                    vm_response
                        .get("vm_mac")
                        .and_then(serde_json::Value::as_str),
                ) {
                    if !vm_ip.is_empty() && !vm_mac.is_empty() {
                        if let Err(e) = exec.store.call(
                            "InstanceDbSetVmNetwork",
                            json!({
                                "db_path": exec.config.store_db_path,
                                "container": container,
                                "ip": vm_ip,
                                "mac": vm_mac,
                            }),
                        ) {
                            tracing::warn!(
                                "[executor] persist vm_ip/vm_mac for {}: {e}",
                                container
                            );
                        }
                    }
                }

                let timing = serde_json::from_value::<VmCreateTimingWire>(vm_response.clone())
                    .unwrap_or_default();
                timing_phases = timing.phases;
                timing_total_ms = timing.total_ms;
                timing_golden_image_used = timing.golden_image_used;
                timing_install_skipped = timing.install_skipped;
            }

            "set_active" => {
                exec.update_instance_status(
                    &req.instance_id,
                    "provisioning",
                    "Starting services...",
                    "",
                    "",
                    "starting",
                );
                exec.update_instance_status(&req.instance_id, "active", "", "", "", "");

                // Finalize runtime lease: clear expires_at (provisioning complete)
                if let Err(e) = exec.store.call(
                    "ResourceLeaseFinalize",
                    json!({
                        "db_path": exec.config.store_db_path,
                        "owner_type": "instance",
                        "owner_id": req.instance_id,
                        "lease_kind": "runtime",
                    }),
                ) {
                    tracing::warn!(
                        "[executor] finalize runtime lease for {}: {e}",
                        req.instance_id
                    );
                }

                tracing::info!("[executor] {} set active", req.instance_id);
            }

            "ensure_container" => {
                let container = params["container"].as_str().unwrap_or("");
                if !container.is_empty() {
                    if let Err(e) = exec
                        .terminal
                        .call("EnsureContainer", json!({"container": container}))
                    {
                        tracing::debug!("[executor] ensure container in terminal: {e}");
                    }
                    tracing::info!(
                        "[executor] {} ensured container {}",
                        req.instance_id,
                        container
                    );
                }
            }

            _ => {
                tracing::warn!("[executor] unknown create step op: {op}");
            }
        }
    }

    ExecuteFlowResult {
        status: FlowStatus::Completed,
        host_port: Some(host_port),
        phases: timing_phases,
        total_ms: timing_total_ms,
        golden_image_used: timing_golden_image_used,
        install_skipped: timing_install_skipped,
        ..Default::default()
    }
}

/// Merge all key-value pairs from `source` into `target`.
fn merge_json_objects(target: &mut serde_json::Value, source: &serde_json::Value) {
    if let (Some(obj), Some(src)) = (target.as_object_mut(), source.as_object()) {
        for (k, v) in src {
            obj.insert(k.clone(), v.clone());
        }
    }
}
