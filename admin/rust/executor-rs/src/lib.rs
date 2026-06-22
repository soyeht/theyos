mod flows;
mod orchestrator;
mod shutdown;
pub use core_rs::ipc::client::IpcClient;
pub use shutdown::{GRACEFUL_SHUTDOWN_TIMEOUT, ShutdownResult, graceful_shutdown_all};
pub use vmrunner_common_rs::{VmCreatePhaseTiming as PhaseTiming, VmCreateTimingWire};

use core_rs::error::{AppError, ErrorCode};
use core_rs::ipc::client::IpcError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("subprocess start failed: {0}")]
    SubprocessStart(String),
    #[error("ipc error: {0}")]
    Ipc(String),
    #[error("flow failed: {0}")]
    FlowFailed(String),
    #[error("not found: {0}")]
    NotFound(String),
}

impl AppError for ExecutorError {
    fn code(&self) -> ErrorCode {
        match self {
            ExecutorError::NotFound(_) => ErrorCode::NotFound,
            _ => ErrorCode::Internal,
        }
    }
}

impl From<IpcError> for ExecutorError {
    fn from(e: IpcError) -> Self {
        match e {
            IpcError::SubprocessStart(m) => ExecutorError::SubprocessStart(m),
            IpcError::Io(m) => ExecutorError::Ipc(m),
            IpcError::CallFailed(m) => ExecutorError::FlowFailed(m),
            IpcError::NotFound(m) => ExecutorError::NotFound(m),
        }
    }
}

// ─── Configuration ────────────────────────────────────────────────────────────

/// All paths and runtime configuration needed to launch sub-subprocesses and
/// execute flows.  Values are read from environment variables in `executor_ipc.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowConfig {
    // Paths to the IPC binaries (each launched as a subprocess)
    pub vmrunner_bin: String,
    pub store_bin: String,
    pub terminal_bin: String,

    // vmrunner-ipc forwarded config
    pub firecracker_state_dir: String,
    pub firecracker_bin: String,
    pub kernel_image: String,
    pub base_rootfs: String,
    pub ssh_key: String,
    pub ssh_pubkey: String,
    pub ssh_wait_tries: u32,

    // store-ipc InstanceDb path
    pub store_db_path: String,
}

// ─── Typed enums ─────────────────────────────────────────────────────────────

/// Typed flow lifecycle action — eliminates stringly-typed dispatch.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlowType {
    #[default]
    Create,
    CreateSync,
    Delete,
    Rebuild,
    Restart,
    Stop,
}

impl FlowType {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            FlowType::Create => "create",
            FlowType::CreateSync => "create_sync",
            FlowType::Delete => "delete",
            FlowType::Rebuild => "rebuild",
            FlowType::Restart => "restart",
            FlowType::Stop => "stop",
        }
    }
}

impl std::fmt::Display for FlowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed flow outcome — eliminates stringly-typed status comparisons.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlowStatus {
    Completed,
    #[default]
    Failed,
}

impl FlowStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            FlowStatus::Completed => "completed",
            FlowStatus::Failed => "failed",
        }
    }
}

impl std::fmt::Display for FlowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Request / result ─────────────────────────────────────────────────────────

/// Request passed to `Executor::execute_flow`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecuteFlowRequest {
    pub flow_type: FlowType,
    pub instance_id: String,
    pub name: String,
    pub container: String,
    pub claw_type: String,
    // For create retry loop bookkeeping
    #[serde(default)]
    pub attempt_errors: Vec<String>,
    #[serde(default)]
    pub attempt_ports: Vec<i64>,
    #[serde(default)]
    pub max_port_retries: i32,
    /// Optional AI coding tools to pre-install (e.g. `["codex", "claude-code", "opencode"]`).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Guest OS: `"macos"` or `"linux"`. Empty string uses platform default.
    #[serde(default)]
    pub guest_os: String,
    /// CPU cores (1-4). Default: 2.
    #[serde(default)]
    pub cpu_cores: Option<u32>,
    /// RAM in MB (512-8192). Default: 2048.
    #[serde(default)]
    pub ram_mb: Option<u32>,
    /// Disk size in GB (5-50). Default: 10.
    #[serde(default)]
    pub disk_gb: Option<u32>,
}

/// Result returned by `Executor::execute_flow`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecuteFlowResult {
    pub status: FlowStatus,
    /// Human-readable error message (present only on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Semantic error code for the failure (only propagated in-process, not over IPC).
    #[serde(skip)]
    pub error_code: Option<ErrorCode>,
    /// Structured diagnostic context for the failure: phase, command,
    /// `exit_code`, `stderr_tail`, `serial_log_tail`, etc. Present only on failure
    /// when the underlying operation produced structured context.
    /// Clients that don't know about this field will safely ignore it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_context: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_port: Option<i64>,
    /// VM Create timing fields, flattened to preserve the existing top-level
    /// `phases` / `total_ms` / `golden_image_used` / `install_skipped` JSON.
    #[serde(default, flatten)]
    pub create_timing: VmCreateTimingWire,
}

impl ExecuteFlowResult {
    /// Convenience constructor for a simple failure with no extra context.
    pub fn failed(msg: impl Into<String>) -> Self {
        Self {
            status: FlowStatus::Failed,
            error: Some(msg.into()),
            ..Default::default()
        }
    }

    /// Failure constructor that also carries a semantic error code.
    pub fn failed_with_code(msg: impl Into<String>, code: ErrorCode) -> Self {
        Self {
            status: FlowStatus::Failed,
            error: Some(msg.into()),
            error_code: Some(code),
            ..Default::default()
        }
    }
}

// ─── Executor ─────────────────────────────────────────────────────────────────

/// Long-running executor that holds open IPC connections to all sub-subprocesses.
///
/// On construction it spawns all sub-processes and verifies liveness with Ping.
/// Then it accepts `ExecuteFlow` calls, each of which coordinates the
/// sub-processes to carry out a complete instance lifecycle flow.
///
/// Flow logic (formerly orchestrator-rs) runs directly in-process — no extra
/// subprocess or IPC round-trip needed.
pub struct Executor {
    pub(crate) vmrunner: IpcClient,
    pub(crate) store: IpcClient,
    pub(crate) terminal: IpcClient,
    pub(crate) config: FlowConfig,
    last_vmrunner_respawn: AtomicU32,
}

impl Executor {
    /// Spawn all sub-subprocesses and verify they are alive.
    ///
    /// # Errors
    ///
    /// Returns an error if any IPC subprocess fails to start or does not
    /// respond to a health ping.
    pub fn new(config: FlowConfig) -> Result<Self, ExecutorError> {
        let vmrunner = IpcClient::start(&config.vmrunner_bin, &[])?;
        let store = IpcClient::start(&config.store_bin, &[])?;
        let terminal = IpcClient::start(&config.terminal_bin, &[])?;

        // Verify all are alive.
        vmrunner.ping()?;
        store.ping()?;
        terminal.ping()?;

        tracing::info!("[executor] all sub-subprocesses started and pinged");

        Ok(Self {
            vmrunner,
            store,
            terminal,
            config,
            last_vmrunner_respawn: AtomicU32::new(0),
        })
    }

    /// Execute a complete instance lifecycle flow.
    pub fn execute_flow(&self, req: &ExecuteFlowRequest) -> ExecuteFlowResult {
        tracing::info!(
            "[executor] execute_flow type={} instance={}",
            req.flow_type,
            req.instance_id
        );
        let result = match req.flow_type {
            FlowType::Create | FlowType::CreateSync => flows::create::execute_create(self, req),
            FlowType::Delete => flows::delete::execute_delete(self, req),
            FlowType::Rebuild => flows::rebuild::execute_rebuild(self, req),
            FlowType::Restart => flows::restart::execute_restart(self, req),
            FlowType::Stop => flows::stop::execute_stop(self, req),
        };
        self.check_vmrunner_respawn();
        result
    }

    /// If vmrunner has respawned since last check, re-trigger warm pool init.
    fn check_vmrunner_respawn(&self) {
        let current = self.vmrunner.respawn_count();
        let last = self.last_vmrunner_respawn.load(Ordering::SeqCst);
        if current > last {
            self.last_vmrunner_respawn.store(current, Ordering::SeqCst);
            tracing::warn!(
                "[executor] vmrunner respawned ({last} -> {current}), re-triggering warm pool init"
            );
            match self.warm_pool_init() {
                Ok(v) => tracing::info!("[executor] warm pool re-init triggered: {v}"),
                Err(e) => tracing::warn!("[executor] warm pool re-init failed (non-fatal): {e}"),
            }
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    pub(crate) fn update_instance_status(
        &self,
        id: &str,
        status: &str,
        message: &str,
        error: &str,
        job_id: &str,
        phase: &str,
    ) {
        if let Err(e) = self.store.call(
            "InstanceDbUpdateStatus",
            json!({
                "db_path": self.config.store_db_path,
                "id": id,
                "status": status,
                "message": message,
                "error": error,
                "job_id": job_id,
                "phase": phase,
            }),
        ) {
            tracing::warn!("[executor] update_instance_status failed for {id}: {e}");
        }
    }

    pub(crate) fn set_instance_failed(&self, id: &str, error: &str) {
        self.update_instance_status(id, "failed", "", error, "", "");
    }

    pub(crate) fn get_host_port(&self, id: &str) -> Result<i64, ExecutorError> {
        let v = self.store.call(
            "InstanceDbGetHostPort",
            json!({
                "db_path": self.config.store_db_path,
                "id": id,
            }),
        )?;
        Ok(v["port"].as_i64().unwrap_or(0))
    }

    /// Check whether an error message represents a port conflict.
    ///
    /// Uses the inlined orchestrator logic directly (no IPC round-trip).
    pub fn check_port_conflict(&self, error_msg: &str) -> bool {
        orchestrator::is_port_conflict_error(error_msg)
    }

    // ─── Warm pool admin (proxy to vmrunner IPC subprocess) ──────────────

    /// Query the warm pool status for all 6 claw types.
    ///
    /// Returns a JSON object mapping each claw type to its slot state:
    /// `"empty"`, `"filling"`, or `"warm"`.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmrunner IPC call fails.
    pub fn warm_pool_status(&self) -> Result<serde_json::Value, ExecutorError> {
        Ok(self.vmrunner.call(
            "WarmPoolStatus",
            json!({
                "state_dir": self.config.firecracker_state_dir,
            }),
        )?)
    }

    /// Trigger a warm pool refill for a single claw type.
    ///
    /// Returns immediately — the actual fill happens asynchronously inside
    /// the vmrunner subprocess.  Returns `already_warm` or `already_filling`
    /// if the slot is not empty.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmrunner IPC call fails.
    pub fn warm_pool_refill(&self, claw_type: &str) -> Result<serde_json::Value, ExecutorError> {
        Ok(self.vmrunner.call(
            "WarmPoolRefill",
            json!({
                "claw_type":       claw_type,
                "state_dir":       self.config.firecracker_state_dir,
                "firecracker_bin": self.config.firecracker_bin,
                "kernel_image":    self.config.kernel_image,
                "base_rootfs":     self.config.base_rootfs,
                "ssh_key":         self.config.ssh_key,
                "ssh_pubkey":      self.config.ssh_pubkey,
                "ssh_wait_tries":  self.config.ssh_wait_tries,
            }),
        )?)
    }

    /// Re-initialize the warm pool: marks all 6 slots as `filling` and spawns
    /// background tasks (concurrency=2) to fill them.
    ///
    /// Returns immediately.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmrunner IPC call fails.
    pub fn warm_pool_init(&self) -> Result<serde_json::Value, ExecutorError> {
        Ok(self.vmrunner.call(
            "WarmPoolInit",
            json!({
                "state_dir":       self.config.firecracker_state_dir,
                "firecracker_bin": self.config.firecracker_bin,
                "kernel_image":    self.config.kernel_image,
                "base_rootfs":     self.config.base_rootfs,
                "ssh_key":         self.config.ssh_key,
                "ssh_pubkey":      self.config.ssh_pubkey,
                "ssh_wait_tries":  self.config.ssh_wait_tries,
            }),
        )?)
    }

    /// Query macOS VM slot availability via IPC (`MacOsSlotStatus`).
    /// Returns `{ available, total, in_use }`.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmrunner IPC call fails.
    pub fn macos_slot_status(&self) -> Result<serde_json::Value, ExecutorError> {
        Ok(self.vmrunner.call("MacOsSlotStatus", json!({}))?)
    }

    /// Drain (kill) all pre-warmed VMs and clear their warm-pool slots.
    ///
    /// Returns the number of VMs drained.
    ///
    /// # Errors
    ///
    /// Returns an error if the vmrunner IPC call fails.
    pub fn warm_pool_drain(&self) -> Result<serde_json::Value, ExecutorError> {
        Ok(self.vmrunner.call(
            "WarmPoolDrain",
            json!({
                "state_dir": self.config.firecracker_state_dir,
            }),
        )?)
    }
}

/// Inline port-conflict pattern check used as fallback when the orchestrator
/// IPC is unavailable. Exported so callers and tests can use it directly.
#[must_use]
pub fn is_port_conflict_message(error_msg: &str) -> bool {
    let lower = error_msg.to_lowercase();
    lower.contains("address already in use")
        || lower.contains("port already in use")
        || lower.contains("add_hostfwd")
        || lower.contains("slirp_add_hostfwd")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_flow_result_serializes() {
        let r = ExecuteFlowResult {
            status: FlowStatus::Failed,
            error: Some("test error".to_string()),
            ..Default::default()
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("failed"));
    }

    #[test]
    fn execute_flow_result_default() {
        let r = ExecuteFlowResult::default();
        assert_eq!(r.status, FlowStatus::Failed);
        assert!(r.error.is_none());
        assert!(r.host_port.is_none());
    }

    #[test]
    fn execute_flow_request_roundtrip() {
        let req = ExecuteFlowRequest {
            flow_type: FlowType::Create,
            instance_id: "inst-demo".to_string(),
            name: "demo".to_string(),
            container: "picoclaw-demo".to_string(),
            claw_type: "picoclaw".to_string(),
            attempt_errors: vec![],
            attempt_ports: vec![],
            max_port_retries: 3,
            tools: vec![],
            guest_os: String::new(),
            cpu_cores: None,
            ram_mb: None,
            disk_gb: None,
        };
        let json_str = serde_json::to_string(&req).unwrap();
        let decoded: ExecuteFlowRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(decoded.instance_id, "inst-demo");
        assert_eq!(decoded.flow_type, FlowType::Create);
    }

    #[test]
    fn flow_type_serde_roundtrip() {
        let ft = FlowType::CreateSync;
        let json = serde_json::to_string(&ft).unwrap();
        assert_eq!(json, "\"create_sync\"");
        let decoded: FlowType = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, FlowType::CreateSync);
    }

    #[test]
    fn flow_status_display() {
        assert_eq!(FlowStatus::Completed.to_string(), "completed");
        assert_eq!(FlowStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn execute_flow_request_tools_roundtrip() {
        let req = ExecuteFlowRequest {
            flow_type: FlowType::Create,
            instance_id: "inst-tools".to_string(),
            name: "tools".to_string(),
            container: "picoclaw-tools".to_string(),
            claw_type: "picoclaw".to_string(),
            attempt_errors: vec![],
            attempt_ports: vec![],
            max_port_retries: 3,
            tools: vec![
                "codex".to_string(),
                "claude-code".to_string(),
                "opencode".to_string(),
            ],
            guest_os: String::new(),
            cpu_cores: None,
            ram_mb: None,
            disk_gb: None,
        };
        let json_str = serde_json::to_string(&req).unwrap();
        let decoded: ExecuteFlowRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(decoded.tools.len(), 3);
        assert_eq!(decoded.tools[0], "codex");
        assert_eq!(decoded.tools[1], "claude-code");
        assert_eq!(decoded.tools[2], "opencode");
    }

    #[test]
    fn execute_flow_request_tools_default_empty() {
        let json = r#"{"flow_type":"create","instance_id":"i","name":"n","container":"c","claw_type":"picoclaw","max_port_retries":0}"#;
        let req: ExecuteFlowRequest = serde_json::from_str(json).unwrap();
        assert!(req.tools.is_empty());
    }
}
