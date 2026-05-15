//! theyOS client library for macOS
//!
//! Provides a high-level client for interacting with the theyOS daemon
//! via the executor IPC interface.

// Module is fully implemented but not yet wired into CLI commands.
// Remove this annotation once the CLI subcommands use TheyOsClient.
#![allow(dead_code)]

use serde_json::json;

/// theyOS client for communicating with the executor daemon.
pub struct TheyOsClient {
    ipc: core_rs::ipc::client::IpcClient,
}

impl TheyOsClient {
    /// Create a new client connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the executor binary cannot be found or started.
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let executor_bin =
            std::env::var("THEYOS_EXECUTOR_RS_BIN").unwrap_or_else(|_| "executor_ipc".to_string());

        let ipc = core_rs::ipc::client::IpcClient::start(&executor_bin, &[])?;
        Ok(Self { ipc })
    }

    /// Check if the daemon is running.
    pub fn ping(&self) -> bool {
        matches!(
            self.ipc.call("Ping", json!({})),
            Ok(response) if response["ok"].as_bool().unwrap_or(false)
        )
    }

    /// Create a new claw instance.
    pub fn create_instance(
        &self,
        claw_type: &str,
        id: &str,
        port: u16,
    ) -> Result<InstanceStatus, Box<dyn std::error::Error>> {
        let params = json!({
            "instance_id": id,
            "name": id,
            "container": format!("{}-{}", claw_type, id),
            "claw_type": claw_type,
            "port": port,
        });

        let response = self.ipc.call(
            "ExecuteFlow",
            json!({
                "flow": "create",
                "params": params,
            }),
        )?;

        if response["ok"].as_bool().unwrap_or(false) {
            Ok(InstanceStatus::Provisioning)
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string()
                .into())
        }
    }

    /// Start an instance.
    pub fn start_instance(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let response = self.ipc.call(
            "ExecuteFlow",
            json!({
                "flow": "start",
                "params": { "instance_id": id },
            }),
        )?;

        if response["ok"].as_bool().unwrap_or(false) {
            Ok(())
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string()
                .into())
        }
    }

    /// Stop an instance.
    pub fn stop_instance(&self, id: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
        let response = self.ipc.call(
            "ExecuteFlow",
            json!({
                "flow": "stop",
                "params": {
                    "instance_id": id,
                    "force": force
                },
            }),
        )?;

        if response["ok"].as_bool().unwrap_or(false) {
            Ok(())
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string()
                .into())
        }
    }

    /// Delete an instance.
    pub fn delete_instance(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let response = self.ipc.call(
            "ExecuteFlow",
            json!({
                "flow": "delete",
                "params": { "instance_id": id },
            }),
        )?;

        if response["ok"].as_bool().unwrap_or(false) {
            Ok(())
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string()
                .into())
        }
    }

    /// Restart an instance.
    pub fn restart_instance(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let response = self.ipc.call(
            "ExecuteFlow",
            json!({
                "flow": "restart",
                "params": { "instance_id": id },
            }),
        )?;

        if response["ok"].as_bool().unwrap_or(false) {
            Ok(())
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string()
                .into())
        }
    }

    /// List all instances.
    pub fn list_instances(&self) -> Result<Vec<InstanceInfo>, Box<dyn std::error::Error>> {
        let response = self.ipc.call("InstanceDbList", json!({}))?;

        if response["ok"].as_bool().unwrap_or(false) {
            if let Some(instances) = response["result"]["instances"].as_array() {
                let mut result = Vec::new();
                for inst in instances {
                    result.push(InstanceInfo {
                        id: inst["id"].as_str().unwrap_or("").to_string(),
                        name: inst["name"].as_str().unwrap_or("").to_string(),
                        claw_type: inst["claw_type"].as_str().unwrap_or("").to_string(),
                        state: inst["status"].as_str().unwrap_or("unknown").into(),
                        #[allow(clippy::cast_possible_truncation)]
                        port: inst["host_port"].as_u64().map(|p| p as u16),
                    });
                }
                Ok(result)
            } else {
                Ok(Vec::new())
            }
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string()
                .into())
        }
    }

    /// Get instance logs.
    pub fn get_logs(&self, id: &str, tail: usize) -> Result<String, Box<dyn std::error::Error>> {
        let response = self.ipc.call(
            "ExecuteFlow",
            json!({
                "flow": "logs",
                "params": {
                    "instance_id": id,
                    "tail": tail
                },
            }),
        )?;

        if response["ok"].as_bool().unwrap_or(false) {
            Ok(response["result"]["logs"]
                .as_str()
                .unwrap_or("")
                .to_string())
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string()
                .into())
        }
    }

    /// Get warm pool status.
    pub fn pool_status(&self) -> Result<PoolStatus, Box<dyn std::error::Error>> {
        let response = self.ipc.call("WarmPoolStatus", json!({}))?;

        if response["ok"].as_bool().unwrap_or(false) {
            let result = response["result"].clone();
            Ok(PoolStatus {
                #[allow(clippy::cast_possible_truncation)]
                size: result["size"].as_u64().unwrap_or(0) as usize,
                #[allow(clippy::cast_possible_truncation)]
                available: result["available"].as_u64().unwrap_or(0) as usize,
                #[allow(clippy::cast_possible_truncation)]
                filling: result["filling"].as_u64().unwrap_or(0) as usize,
            })
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string()
                .into())
        }
    }

    /// Warm the pool for a claw type.
    pub fn warm_pool(&self, claw_type: &str) -> Result<(), Box<dyn std::error::Error>> {
        let response = self.ipc.call(
            "WarmPoolRefill",
            json!({
                "claw_type": claw_type,
            }),
        )?;

        if response["ok"].as_bool().unwrap_or(false) {
            Ok(())
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string()
                .into())
        }
    }

    /// Drain the warm pool.
    pub fn drain_pool(&self) -> Result<(), Box<dyn std::error::Error>> {
        let response = self.ipc.call("WarmPoolDrain", json!({}))?;

        if response["ok"].as_bool().unwrap_or(false) {
            Ok(())
        } else {
            Err(response["error"]
                .as_str()
                .unwrap_or("Unknown error")
                .to_string()
                .into())
        }
    }
}

/// Instance information.
#[derive(Debug, Clone)]
pub struct InstanceInfo {
    pub id: String,
    pub name: String,
    pub claw_type: String,
    pub state: InstanceStatus,
    pub port: Option<u16>,
}

/// Instance status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceStatus {
    Provisioning,
    Active,
    Stopped,
    Failed,
}

impl From<&str> for InstanceStatus {
    fn from(s: &str) -> Self {
        match s {
            "provisioning" => Self::Provisioning,
            "active" => Self::Active,
            "stopped" => Self::Stopped,
            _ => Self::Failed,
        }
    }
}

impl std::fmt::Display for InstanceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provisioning => write!(f, "provisioning"),
            Self::Active => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Warm pool status.
#[derive(Debug, Clone)]
pub struct PoolStatus {
    pub size: usize,
    pub available: usize,
    pub filling: usize,
}
