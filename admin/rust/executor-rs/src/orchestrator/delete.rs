//! Delete-instance flow logic (inlined from orchestrator-rs).

use super::types::{DeleteInstanceFlowRequest, FlowResult, OrchestratorError, OrchestratorStep};

/// Validate a delete-instance flow request.
///
/// # Errors
///
/// Returns a validation error if any required field is empty.
pub fn validate_delete_request(req: &DeleteInstanceFlowRequest) -> Result<(), OrchestratorError> {
    if req.instance_id.trim().is_empty() {
        return Err(OrchestratorError::Validation(
            "instance_id is required".to_string(),
        ));
    }
    if req.name.trim().is_empty() {
        return Err(OrchestratorError::Validation(
            "name is required".to_string(),
        ));
    }
    if req.container.trim().is_empty() {
        return Err(OrchestratorError::Validation(
            "container is required".to_string(),
        ));
    }
    if req.claw_type.trim().is_empty() {
        return Err(OrchestratorError::Validation(
            "claw_type is required".to_string(),
        ));
    }
    Ok(())
}

#[must_use]
pub fn run_delete_instance_flow(req: &DeleteInstanceFlowRequest) -> FlowResult {
    if let Err(e) = validate_delete_request(req) {
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
        OrchestratorStep::new("delete_vm").with_param("container", &req.container),
        OrchestratorStep::new("cleanup_systemd").with_param("container", &req.container),
        OrchestratorStep::new("cleanup_fs")
            .with_param("claw_type", &req.claw_type)
            .with_param("name", &req.name)
            // The Linux runner locates the rootfs from claw_type/name/state_dir;
            // the macOS runner keys its per-instance dir on `container`. Pass both
            // so a single cleanup_fs contract serves both hosts.
            .with_param("container", &req.container),
        OrchestratorStep::new("delete_db_row"),
        OrchestratorStep::new("remove_from_store"),
        OrchestratorStep::new("remove_container").with_param("container", &req.container),
    ];

    FlowResult {
        status: "run_steps".to_string(),
        attempts: 0,
        final_port: None,
        failed_ports: vec![],
        steps: vec![
            "validated-request".to_string(),
            "emitting-delete-run-steps".to_string(),
        ],
        run_steps,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_delete_request_requires_container() {
        let req = DeleteInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            name: "demo".to_string(),
            container: String::new(),
            claw_type: "picoclaw".to_string(),
        };
        let err = validate_delete_request(&req).unwrap_err();
        assert_eq!(err.to_string(), "container is required");
    }

    #[test]
    fn run_delete_instance_flow_emits_run_steps_when_valid() {
        let req = DeleteInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            name: "demo".to_string(),
            container: "picoclaw-demo".to_string(),
            claw_type: "picoclaw".to_string(),
        };
        let out = run_delete_instance_flow(&req);
        assert_eq!(out.status, "run_steps");
        let ops: Vec<&str> = out.run_steps.iter().map(|s| s.op.as_str()).collect();
        assert_eq!(
            ops,
            vec![
                "stop_vm",
                "delete_vm",
                "cleanup_systemd",
                "cleanup_fs",
                "delete_db_row",
                "remove_from_store",
                "remove_container",
            ]
        );
    }

    #[test]
    fn run_delete_instance_flow_fails_when_container_missing() {
        let req = DeleteInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            name: "demo".to_string(),
            container: String::new(),
            claw_type: "picoclaw".to_string(),
        };
        let out = run_delete_instance_flow(&req);
        assert_eq!(out.status, "failed");
        assert!(
            out.error
                .as_deref()
                .unwrap_or("")
                .contains("container is required")
        );
    }
}
