//! Restart instance flow implementation.

use core_rs::ipc::protocol::VmRunnerOp;
use serde_json::json;

use crate::{
    ExecuteFlowRequest, ExecuteFlowResult, Executor, FlowStatus,
    orchestrator::{RestartInstanceFlowRequest, run_restart_instance_flow},
};

pub(crate) fn execute_restart(exec: &Executor, req: &ExecuteFlowRequest) -> ExecuteFlowResult {
    let orch_req = RestartInstanceFlowRequest {
        instance_id: req.instance_id.clone(),
        container: req.container.clone(),
    };

    let result = run_restart_instance_flow(&orch_req);

    match result.status.as_str() {
        s if s.eq_ignore_ascii_case("run_steps") => {
            for step in &result.run_steps {
                match step.op.as_str() {
                    "restart_vm" => {
                        let container = step.params.get("container").map_or("", String::as_str);
                        if let Err(e) = exec.vmrunner.call(
                            VmRunnerOp::Restart.as_str(),
                            json!({
                                "container": container,
                                "state_dir": exec.config.firecracker_state_dir,
                                "ssh_key": exec.config.ssh_key,
                                "ssh_wait_tries": exec.config.ssh_wait_tries,
                                "firecracker_bin": exec.config.firecracker_bin,
                                "kernel_image": exec.config.kernel_image,
                            }),
                        ) {
                            return ExecuteFlowResult::failed(e.to_string());
                        }
                    }
                    "restart_terminal" => {
                        let container = step.params.get("container").map_or("", String::as_str);
                        if let Err(e) = exec
                            .terminal
                            .call("Restart", json!({"container": container, "session_id": ""}))
                        {
                            tracing::warn!("[executor] restart terminal session: {e}");
                        }
                    }
                    "set_active" => {
                        exec.update_instance_status(&req.instance_id, "active", "", "", "", "");
                    }
                    _ => {}
                }
            }
            tracing::info!("[executor] {} restarted", req.instance_id);
            ExecuteFlowResult {
                status: FlowStatus::Completed,
                ..Default::default()
            }
        }
        other => {
            let err_msg = result
                .error
                .unwrap_or_else(|| "restart flow failed".to_string());
            ExecuteFlowResult::failed(format!("restart status={other}: {err_msg}"))
        }
    }
}
