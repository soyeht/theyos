//! Stop-instance flow logic (inlined from orchestrator-rs).

use super::types::{FlowResult, OrchestratorError, OrchestratorStep, StopInstanceFlowRequest};

/// Validate a stop-instance flow request.
///
/// # Errors
///
/// Returns a validation error if any required field is empty.
pub fn validate_stop_request(req: &StopInstanceFlowRequest) -> Result<(), OrchestratorError> {
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
pub fn run_stop_instance_flow(req: &StopInstanceFlowRequest) -> FlowResult {
    if let Err(e) = validate_stop_request(req) {
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
        OrchestratorStep::new("stop_vm").with_param("container", &req.container),
        OrchestratorStep::new("set_stopped"),
    ];

    FlowResult {
        status: "run_steps".to_string(),
        attempts: 0,
        final_port: None,
        failed_ports: vec![],
        steps: vec![
            "validated-request".to_string(),
            "emitting-stop-run-steps".to_string(),
        ],
        run_steps,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_stop_instance_flow_emits_run_steps_when_valid() {
        let req = StopInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            container: "picoclaw-demo".to_string(),
        };
        let out = run_stop_instance_flow(&req);
        assert_eq!(out.status, "run_steps");
        let ops: Vec<&str> = out.run_steps.iter().map(|s| s.op.as_str()).collect();
        assert_eq!(ops, vec!["stop_vm", "set_stopped"]);
    }

    #[test]
    fn run_stop_instance_flow_fails_when_container_missing() {
        let req = StopInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            container: String::new(),
        };
        let out = run_stop_instance_flow(&req);
        assert_eq!(out.status, "failed");
        assert!(
            out.error
                .as_deref()
                .unwrap_or("")
                .contains("container is required")
        );
    }
}
