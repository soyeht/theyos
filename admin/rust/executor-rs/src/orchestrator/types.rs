//! Shared types for the orchestrator module.

use core_rs::error::{AppError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrchestratorError {
    Validation(String),
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let OrchestratorError::Validation(msg) = self;
        write!(f, "{msg}")
    }
}

impl std::error::Error for OrchestratorError {}

impl AppError for OrchestratorError {
    fn code(&self) -> ErrorCode {
        match self {
            OrchestratorError::Validation(_) => ErrorCode::InvalidInput,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInstanceFlowRequest {
    pub instance_id: String,
    pub name: String,
    pub claw_type: String,
    pub max_port_retries: u8,
    #[serde(default)]
    pub attempt_errors: Vec<String>,
    #[serde(default)]
    pub attempt_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteInstanceFlowRequest {
    pub instance_id: String,
    pub name: String,
    pub container: String,
    pub claw_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildInstanceFlowRequest {
    pub instance_id: String,
    pub container: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartInstanceFlowRequest {
    pub instance_id: String,
    pub container: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StopInstanceFlowRequest {
    pub instance_id: String,
    pub container: String,
}

/// A single instruction for the executor to carry out.
///
/// When `FlowResult.status == "run_steps"` the executor iterates `run_steps`
/// and executes each `op` in order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrchestratorStep {
    pub op: String,
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub params: std::collections::HashMap<String, String>,
}

impl OrchestratorStep {
    #[must_use]
    pub fn new(op: impl Into<String>) -> Self {
        Self {
            op: op.into(),
            params: std::collections::HashMap::default(),
        }
    }

    #[must_use]
    pub fn with_param(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.params.insert(k.into(), v.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowResult {
    pub status: String,
    pub attempts: u8,
    pub final_port: Option<u16>,
    pub failed_ports: Vec<u16>,
    /// Diagnostic trace of what the flow did (human-readable strings).
    pub steps: Vec<String>,
    /// When status == "`run_steps`", executor must execute these in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub run_steps: Vec<OrchestratorStep>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAttemptDecisionRequest {
    pub attempt: i64,
    pub max_attempts: i64,
    pub error: String,
    pub host_port: Option<u16>,
    #[serde(default)]
    pub failed_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAttemptDecision {
    pub retry: bool,
    #[serde(default)]
    pub failed_ports: Vec<u16>,
}
