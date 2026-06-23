//! Delete instance flow implementation.

use serde_json::json;

use core_rs::ipc::client::IpcError;
use core_rs::ipc::protocol::{LeaseKind, LeaseOwnerType, StoreOp, VmRunnerOp};

use crate::{
    ExecuteFlowRequest, ExecuteFlowResult, Executor, FlowStatus,
    orchestrator::{DeleteInstanceFlowRequest, run_delete_instance_flow},
};

pub(crate) fn execute_delete(exec: &Executor, req: &ExecuteFlowRequest) -> ExecuteFlowResult {
    let orch_req = DeleteInstanceFlowRequest {
        instance_id: req.instance_id.clone(),
        name: req.name.clone(),
        container: req.container.clone(),
        claw_type: req.claw_type.clone(),
    };

    let result = run_delete_instance_flow(&orch_req);

    match result.status.as_str() {
        s if s.eq_ignore_ascii_case("run_steps") => {
            let steps: Vec<serde_json::Value> = result
                .run_steps
                .iter()
                .map(|s| json!({"op": s.op, "params": s.params}))
                .collect();
            execute_delete_steps(exec, req, &steps);
            tracing::info!("[executor] {} deleted", req.instance_id);
            ExecuteFlowResult {
                status: FlowStatus::Completed,
                ..Default::default()
            }
        }
        s if s.eq_ignore_ascii_case("failed") || s.eq_ignore_ascii_case("error") => {
            let err_msg = result
                .error
                .unwrap_or_else(|| "delete flow failed".to_string());
            ExecuteFlowResult::failed(err_msg)
        }
        other => {
            ExecuteFlowResult::failed(format!("unexpected orchestrator delete status: {other}"))
        }
    }
}

#[allow(clippy::too_many_lines)]
fn execute_delete_steps(exec: &Executor, req: &ExecuteFlowRequest, steps: &[serde_json::Value]) {
    for step in steps {
        let op = step["op"].as_str().unwrap_or("");
        let params = &step["params"];
        match op {
            "stop_vm" => {
                let container = params["container"].as_str().unwrap_or("");
                match exec.vmrunner.call(
                    VmRunnerOp::Stop.as_str(),
                    json!({"container": container, "state_dir": exec.config.firecracker_state_dir}),
                ) {
                    Ok(_) | Err(IpcError::NotFound(_)) => {}
                    Err(e) => {
                        tracing::warn!(
                            "[executor] stop_vm on delete for {container}: {e} (continuing)"
                        );
                    }
                }

                // Release runtime lease (CPU/RAM freed on VM stop)
                if let Err(e) = exec.store.call(
                    StoreOp::ResourceLeaseRelease.as_str(),
                    json!({
                        "db_path": exec.config.store_db_path,
                        "owner_type": LeaseOwnerType::Instance.as_str(),
                        "owner_id": req.instance_id,
                        "lease_kind": LeaseKind::Runtime.as_str(),
                    }),
                ) {
                    tracing::warn!(
                        "[executor] release runtime lease on delete for {}: {e}",
                        req.instance_id
                    );
                }
            }
            "delete_vm" => {
                let container = params["container"].as_str().unwrap_or("");
                match exec.vmrunner.call(
                    VmRunnerOp::Delete.as_str(),
                    json!({"container": container, "state_dir": exec.config.firecracker_state_dir}),
                ) {
                    Ok(_) | Err(IpcError::NotFound(_)) => {}
                    Err(e) => {
                        tracing::warn!(
                            "[executor] delete_vm on delete for {container}: {e} (continuing)"
                        );
                    }
                }
            }
            "cleanup_systemd" => {
                let container = params["container"].as_str().unwrap_or("");
                if let Err(e) = exec.vmrunner.call(
                    VmRunnerOp::CleanupSystemd.as_str(),
                    json!({"container": container}),
                ) {
                    tracing::warn!("[executor] cleanup systemd on delete: {e}");
                }
            }
            "cleanup_fs" => {
                let claw_type = params["claw_type"].as_str().unwrap_or("");
                let name = params["name"].as_str().unwrap_or("");
                let container = params["container"].as_str().unwrap_or("");
                match exec.vmrunner.call(
                    VmRunnerOp::CleanupFs.as_str(),
                    json!({"claw_type": claw_type, "name": name, "container": container, "state_dir": exec.config.firecracker_state_dir}),
                ) {
                    Ok(_) => {
                        // Filesystem cleanup confirmed — release storage lease (disk freed)
                        if let Err(e) = exec.store.call(
                            StoreOp::ResourceLeaseRelease.as_str(),
                            json!({
                                "db_path": exec.config.store_db_path,
                                "owner_type": LeaseOwnerType::Instance.as_str(),
                                "owner_id": req.instance_id,
                                "lease_kind": LeaseKind::Storage.as_str(),
                            }),
                        ) {
                            tracing::warn!(
                                "[executor] release storage lease on delete for {}: {e}",
                                req.instance_id
                            );
                        }
                    }
                    Err(e) => {
                        // Cleanup failed — storage lease stays active so disk is
                        // still reported as allocated until manual intervention.
                        tracing::warn!(
                            "[executor] cleanup fs on delete for {}: {e} \
                             (storage lease retained — disk still allocated)",
                            req.instance_id
                        );
                    }
                }
            }
            "delete_db_row" => {
                if let Err(e) = exec.store.call(
                    StoreOp::SoftDelete.as_str(),
                    json!({
                        "db_path": exec.config.store_db_path,
                        "id": req.instance_id,
                    }),
                ) {
                    tracing::warn!("[executor] soft delete instance row: {e}");
                }
            }
            "remove_container" => {
                let container = params["container"].as_str().unwrap_or("");
                if let Err(e) = exec
                    .terminal
                    .call("RemoveContainer", json!({"container": container}))
                {
                    tracing::debug!("[executor] remove container from terminal: {e}");
                }
            }
            _ => {
                tracing::warn!("[executor] unknown delete step op: {op}");
            }
        }
    }
}
