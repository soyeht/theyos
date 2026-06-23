//! Stop instance flow implementation.

use serde_json::json;

use core_rs::ipc::client::IpcError;
use core_rs::ipc::protocol::{LeaseKind, LeaseOwnerType, StoreOp, VmRunnerOp};

use crate::{
    ExecuteFlowRequest, ExecuteFlowResult, Executor, FlowStatus,
    orchestrator::{StopInstanceFlowRequest, run_stop_instance_flow},
};

pub(crate) fn execute_stop(exec: &Executor, req: &ExecuteFlowRequest) -> ExecuteFlowResult {
    let orch_req = StopInstanceFlowRequest {
        instance_id: req.instance_id.clone(),
        container: req.container.clone(),
    };

    let result = run_stop_instance_flow(&orch_req);

    match result.status.as_str() {
        s if s.eq_ignore_ascii_case("run_steps") => {
            for step in &result.run_steps {
                match step.op.as_str() {
                    "stop_vm" => {
                        let container = step.params.get("container").map_or("", String::as_str);
                        match exec.vmrunner.call(
                            VmRunnerOp::Stop.as_str(),
                            json!({
                                "container": container,
                                "state_dir": exec.config.firecracker_state_dir,
                            }),
                        ) {
                            Ok(_) | Err(IpcError::NotFound(_)) => {}
                            Err(e) => return ExecuteFlowResult::failed(e.to_string()),
                        }
                    }
                    "set_stopped" => {
                        exec.update_instance_status(&req.instance_id, "stopped", "", "", "", "");

                        // Release runtime lease (CPU/RAM freed). Storage lease stays active.
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
                                "[executor] release runtime lease on stop for {}: {e}",
                                req.instance_id
                            );
                        }
                    }
                    _ => {}
                }
            }
            tracing::info!("[executor] {} stopped", req.instance_id);
            ExecuteFlowResult {
                status: FlowStatus::Completed,
                ..Default::default()
            }
        }
        other => {
            let err_msg = result
                .error
                .unwrap_or_else(|| "stop flow failed".to_string());
            ExecuteFlowResult::failed(format!("stop status={other}: {err_msg}"))
        }
    }
}
