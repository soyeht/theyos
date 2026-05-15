//! Create-instance flow logic (inlined from orchestrator-rs).

use super::types::{
    CreateAttemptDecision, CreateAttemptDecisionRequest, CreateInstanceFlowRequest, FlowResult,
    OrchestratorError, OrchestratorStep,
};

// ── Error-classification patterns (inlined from agentruntime-rs) ─────────────

const PORT_CONFLICT_PATTERNS: &[&str] = &[
    "address already in use",
    "port already in use",
    "slirp_add_hostfwd failed",
    "add_hostfwd",
];

/// Returns true when the error message indicates a port-conflict error.
#[must_use]
pub fn is_port_conflict_error(message: &str) -> bool {
    let msg = message.to_lowercase();
    PORT_CONFLICT_PATTERNS.iter().any(|p| msg.contains(*p))
}

#[must_use]
pub fn should_retry_create_attempt(attempt: i64, max_attempts: i64, message: &str) -> bool {
    if max_attempts <= 0 {
        return false;
    }
    is_port_conflict_error(message) && (attempt + 1) < max_attempts
}

#[must_use]
pub fn evaluate_create_attempt(req: &CreateAttemptDecisionRequest) -> CreateAttemptDecision {
    let mut failed_ports = req.failed_ports.clone();
    let retry = should_retry_create_attempt(req.attempt, req.max_attempts, &req.error);
    if retry {
        if let Some(port) = req.host_port {
            if !failed_ports.contains(&port) {
                failed_ports.push(port);
            }
        }
    }
    CreateAttemptDecision {
        retry,
        failed_ports,
    }
}

/// Validate a create-instance flow request.
///
/// # Errors
///
/// Returns a validation error if any required field is empty or the claw type
/// is unknown.
pub fn validate_create_request(req: &CreateInstanceFlowRequest) -> Result<(), OrchestratorError> {
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
    if req.claw_type.trim().is_empty() {
        return Err(OrchestratorError::Validation(
            "claw_type is required".to_string(),
        ));
    }
    if req.max_port_retries == 0 {
        return Err(OrchestratorError::Validation(
            "max_port_retries must be >= 1".to_string(),
        ));
    }
    Ok(())
}

#[must_use]
pub fn run_create_instance_flow(req: &CreateInstanceFlowRequest) -> FlowResult {
    if req.attempt_errors.is_empty() {
        // Fresh create: emit the canonical step sequence.
        let container = format!("{}-{}", req.claw_type, req.name);
        return FlowResult {
            status: "run_steps".to_string(),
            attempts: 0,
            final_port: None,
            failed_ports: vec![],
            steps: vec![
                "validated-request".to_string(),
                "no-attempt-history".to_string(),
                "emitting-run-steps".to_string(),
            ],
            run_steps: vec![
                OrchestratorStep::new("create_vm")
                    .with_param("claw_type", &req.claw_type)
                    .with_param("name", &req.name),
                OrchestratorStep::new("set_active"),
                OrchestratorStep::new("ensure_container").with_param("container", &container),
            ],
            error: None,
        };
    }

    let mut failed_ports: Vec<u16> = vec![];
    let mut attempts: u8 = 0;
    let mut steps: Vec<String> = vec!["validated-request".to_string()];
    steps.push(format!("evaluating-{}-attempts", req.attempt_errors.len()));

    for (idx, err_msg) in req.attempt_errors.iter().enumerate() {
        attempts = attempts.saturating_add(1);
        let host_port = req.attempt_ports.get(idx).copied();

        let port_conflict = is_port_conflict_error(err_msg);
        #[allow(clippy::cast_possible_wrap)]
        let decision = evaluate_create_attempt(&CreateAttemptDecisionRequest {
            attempt: idx as i64,
            max_attempts: i64::from(req.max_port_retries),
            error: err_msg.clone(),
            host_port,
            failed_ports: failed_ports.clone(),
        });

        if port_conflict {
            steps.push(format!(
                "attempt-{}-port-conflict-port-{}",
                idx,
                host_port.map_or_else(|| "unknown".to_string(), |p| p.to_string())
            ));
        } else {
            steps.push(format!("attempt-{idx}-non-retriable-error"));
        }

        failed_ports = decision.failed_ports;

        if !decision.retry {
            steps.push("terminal-failure".to_string());
            return FlowResult {
                status: "failed".to_string(),
                attempts,
                final_port: host_port,
                failed_ports,
                steps,
                run_steps: vec![],
                error: Some(err_msg.clone()),
            };
        }

        steps.push(format!("attempt-{idx}-will-retry"));
    }

    steps.push("all-attempts-retriable-needs-new-port".to_string());
    FlowResult {
        status: "retry".to_string(),
        attempts,
        final_port: req.attempt_ports.last().copied(),
        failed_ports,
        steps,
        run_steps: vec![],
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_conflict_patterns_count() {
        assert_eq!(PORT_CONFLICT_PATTERNS.len(), 4);
    }

    #[test]
    fn port_conflict_address_already_in_use() {
        assert!(is_port_conflict_error("bind: address already in use"));
        assert!(is_port_conflict_error("Address Already In Use"));
    }

    #[test]
    fn port_conflict_slirp() {
        assert!(is_port_conflict_error("SLIRP_ADD_HOSTFWD failed"));
        assert!(is_port_conflict_error("add_hostfwd: error allocating port"));
    }

    #[test]
    fn port_conflict_false_for_unrelated_error() {
        assert!(!is_port_conflict_error("permission denied"));
        assert!(!is_port_conflict_error("connection refused"));
    }

    #[test]
    fn validate_create_request_requires_name() {
        let req = CreateInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            name: String::new(),
            claw_type: "picoclaw".to_string(),
            max_port_retries: 3,
            attempt_errors: vec![],
            attempt_ports: vec![],
        };
        let err = validate_create_request(&req).unwrap_err();
        assert_eq!(err.to_string(), "name is required");
    }

    #[test]
    fn validate_create_request_rejects_zero_retries() {
        let req = CreateInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            name: "demo".to_string(),
            claw_type: "picoclaw".to_string(),
            max_port_retries: 0,
            attempt_errors: vec![],
            attempt_ports: vec![],
        };
        assert!(validate_create_request(&req).is_err());
    }

    #[test]
    fn should_retry_create_attempt_respects_bounds() {
        assert!(should_retry_create_attempt(
            0,
            3,
            "bind: address already in use"
        ));
        assert!(!should_retry_create_attempt(
            2,
            3,
            "bind: address already in use"
        ));
        assert!(!should_retry_create_attempt(0, 3, "permission denied"));
    }

    #[test]
    fn run_create_instance_flow_emits_run_steps_when_no_attempt_errors() {
        let req = CreateInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            name: "demo".to_string(),
            claw_type: "picoclaw".to_string(),
            max_port_retries: 3,
            attempt_errors: vec![],
            attempt_ports: vec![],
        };
        let out = run_create_instance_flow(&req);
        assert_eq!(out.status, "run_steps");
        let ops: Vec<&str> = out.run_steps.iter().map(|s| s.op.as_str()).collect();
        assert_eq!(ops, vec!["create_vm", "set_active", "ensure_container"]);
    }

    #[test]
    fn run_create_instance_flow_returns_retry_with_retryable_history() {
        let req = CreateInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            name: "demo".to_string(),
            claw_type: "picoclaw".to_string(),
            max_port_retries: 3,
            attempt_errors: vec!["address already in use".to_string()],
            attempt_ports: vec![31000],
        };
        let out = run_create_instance_flow(&req);
        assert_eq!(out.status, "retry");
        assert_eq!(out.failed_ports, vec![31000]);
    }

    #[test]
    fn run_create_instance_flow_fails_on_non_retryable_attempt() {
        let req = CreateInstanceFlowRequest {
            instance_id: "inst-1".to_string(),
            name: "demo".to_string(),
            claw_type: "picoclaw".to_string(),
            max_port_retries: 3,
            attempt_errors: vec!["permission denied".to_string()],
            attempt_ports: vec![31000],
        };
        let out = run_create_instance_flow(&req);
        assert_eq!(out.status, "failed");
    }
}
