//! Rebuild-instance flow logic.
//!
//! Like restart, but the orchestrator emits a `rebuild_vm` step (instead of
//! `restart_vm`) which tells the executor to call the vmrunner `Rebuild` IPC
//! command — this replaces the rootfs before rebooting.

use super::types::{FlowResult, OrchestratorError, OrchestratorStep, RebuildInstanceFlowRequest};

/// Validate a rebuild-instance flow request.
///
/// # Errors
///
/// Returns a validation error if any required field is empty.
pub fn validate_rebuild_request(req: &RebuildInstanceFlowRequest) -> Result<(), OrchestratorError> {
    if req.instance_id.trim().is_empty() {
        return Err(OrchestratorError::Validation(
            "instance_id is required".to_string(),
        ));
    }
    if req.container.trim().is_empty() {
        return Err(OrchestratorError::Validation(
            "container is required".to_string(),
        ));
    }
    Ok(())
}

#[must_use]
pub fn run_rebuild_instance_flow(req: &RebuildInstanceFlowRequest) -> FlowResult {
    if let Err(e) = validate_rebuild_request(req) {
        return FlowResult {
            status: "failed".to_string(),
            attempts: 0,
            final_port: None,
            failed_ports: vec![],
            steps: vec!["validation-failed".to_string()],
            run_steps: vec![],
            error: Some(e.to_string()),
        };
    }

    let run_steps = vec![
        OrchestratorStep::new("rebuild_vm").with_param("container", &req.container),
        OrchestratorStep::new("restart_terminal").with_param("container", &req.container),
        OrchestratorStep::new("set_active"),
    ];

    FlowResult {
        status: "run_steps".to_string(),
        attempts: 0,
        final_port: None,
        failed_ports: vec![],
        steps: vec![
            "validated-request".to_string(),
            "emitting-rebuild-run-steps".to_string(),
        ],
        run_steps,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_rebuild_instance_flow_emits_run_steps_when_valid() {
        let req = RebuildInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            container: "picoclaw-demo".to_string(),
        };
        let out = run_rebuild_instance_flow(&req);
        assert_eq!(out.status, "run_steps");
        let ops: Vec<&str> = out.run_steps.iter().map(|s| s.op.as_str()).collect();
        assert_eq!(ops, vec!["rebuild_vm", "restart_terminal", "set_active"]);
    }

    #[test]
    fn run_rebuild_instance_flow_fails_when_container_missing() {
        let req = RebuildInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            container: String::new(),
        };
        let out = run_rebuild_instance_flow(&req);
        assert_eq!(out.status, "failed");
        assert!(
            out.error
                .as_deref()
                .unwrap_or("")
                .contains("container is required")
        );
    }

    #[test]
    fn run_rebuild_instance_flow_fails_when_instance_id_missing() {
        let req = RebuildInstanceFlowRequest {
            instance_id: String::new(),
            container: "picoclaw-demo".to_string(),
        };
        let out = run_rebuild_instance_flow(&req);
        assert_eq!(out.status, "failed");
        assert!(
            out.error
                .as_deref()
                .unwrap_or("")
                .contains("instance_id is required")
        );
    }
}
