//! Rebuild instance flow implementation.
//!
//! Like restart, but replaces the rootfs with a clean copy from the snapshot
//! before rebooting the VM.

use core_rs::ipc::protocol::VmRunnerOp;
use serde_json::json;

use crate::{
    ExecuteFlowRequest, ExecuteFlowResult, Executor, FlowStatus,
    orchestrator::{RebuildInstanceFlowRequest, run_rebuild_instance_flow},
};

pub(crate) fn execute_rebuild(exec: &Executor, req: &ExecuteFlowRequest) -> ExecuteFlowResult {
    let orch_req = RebuildInstanceFlowRequest {
        instance_id: req.instance_id.clone(),
        container: req.container.clone(),
    };

    let result = run_rebuild_instance_flow(&orch_req);

    match result.status.as_str() {
        s if s.eq_ignore_ascii_case("run_steps") => {
            for step in &result.run_steps {
                match step.op.as_str() {
                    "rebuild_vm" => {
                        let container = step.params.get("container").map_or("", String::as_str);
                        if let Err(e) = exec.vmrunner.call(
                            VmRunnerOp::Rebuild.as_str(),
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
                            tracing::warn!("[executor] rebuild terminal session: {e}");
                        }
                    }
                    "set_active" => {
                        exec.update_instance_status(&req.instance_id, "active", "", "", "", "");
                    }
                    _ => {}
                }
            }
            tracing::info!("[executor] {} rebuilt", req.instance_id);
            ExecuteFlowResult {
                status: FlowStatus::Completed,
                ..Default::default()
            }
        }
        other => {
            let err_msg = result
                .error
                .unwrap_or_else(|| "rebuild flow failed".to_string());
            ExecuteFlowResult::failed(format!("rebuild status={other}: {err_msg}"))
        }
    }
}
