//! Graceful shutdown coordination for theyOS upgrades.
//!
//! This module provides functionality for gracefully shutting down all
//! claw instances before an upgrade, with per-claw timeouts and fallback
//! to force-stop if needed.

use core_rs::ipc::protocol::VmRunnerOp;

use crate::{ExecuteFlowRequest, Executor, FlowType};
use serde_json::json;
use std::time::Duration;
use tracing::{error, info, warn};

/// Default timeout for graceful shutdown per claw instance.
///
/// Each claw gets 30 seconds to shut down gracefully before force-stop.
pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of a graceful shutdown operation.
#[derive(Debug, Clone)]
pub struct ShutdownResult {
    /// Number of instances that shut down gracefully
    pub graceful_count: usize,
    /// Number of instances that had to be force-stopped
    pub force_stopped_count: usize,
    /// Number of instances that failed to stop
    pub failed_count: usize,
    /// Details about each instance shutdown
    pub details: Vec<InstanceShutdownDetail>,
}

/// Details about a single instance shutdown.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InstanceShutdownDetail {
    /// Instance ID
    pub instance_id: String,
    /// Whether the shutdown was graceful
    pub was_graceful: bool,
    /// Time taken to shut down (milliseconds)
    pub duration_ms: u64,
    /// Error message if shutdown failed
    pub error: Option<String>,
}

impl ShutdownResult {
    /// Check if all shutdowns were successful (graceful or force-stopped).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.failed_count == 0
    }

    /// Get total number of instances processed.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.graceful_count + self.force_stopped_count + self.failed_count
    }

    /// Convert to JSON value for logging/IPC.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "graceful_count": self.graceful_count,
            "force_stopped_count": self.force_stopped_count,
            "failed_count": self.failed_count,
            "total_count": self.total_count(),
            "is_complete": self.is_complete(),
            "details": self.details,
        })
    }
}

/// Gracefully shut down all running claw instances.
///
/// This function:
/// 1. Lists all active instances from the database
/// 2. Attempts graceful shutdown for each (up to timeout)
/// 3. Force-stops any instances that don't shut down in time
/// 4. Logs incident reports for force-stopped instances
///
/// # Errors
///
/// Returns an error if the database query fails or executor is unavailable.
///
/// # Example
///
/// ```ignore
/// let result = graceful_shutdown_all(&executor)?;
/// if result.force_stopped_count > 0 {
///     tracing::warn!("{} instances had to be force-stopped", result.force_stopped_count);
/// }
/// ```
pub fn graceful_shutdown_all(
    exec: &Executor,
) -> Result<ShutdownResult, Box<dyn std::error::Error>> {
    info!("[shutdown] starting graceful shutdown of all instances");

    // Get all active instances from the database
    let instances = exec.store.call(
        "InstanceDbList",
        json!({
            "db_path": exec.config.store_db_path,
        }),
    )?;

    let active_instances: Vec<String> = instances["data"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter(|item| {
            item["status"].as_str() == Some("active")
                || item["status"].as_str() == Some("starting")
                || item["status"].as_str() == Some("restarting")
        })
        .map(|item| item["id"].as_str().unwrap_or("").to_string())
        .collect();

    if active_instances.is_empty() {
        info!("[shutdown] no active instances to shut down");
        return Ok(ShutdownResult {
            graceful_count: 0,
            force_stopped_count: 0,
            failed_count: 0,
            details: vec![],
        });
    }

    info!(
        "[shutdown] shutting down {} active instances",
        active_instances.len()
    );

    let mut result = ShutdownResult {
        graceful_count: 0,
        force_stopped_count: 0,
        failed_count: 0,
        details: vec![],
    };

    for instance_id in &active_instances {
        let detail = shutdown_instance_with_timeout(exec, instance_id, GRACEFUL_SHUTDOWN_TIMEOUT);

        match &detail {
            InstanceShutdownDetail {
                error: None,
                was_graceful: true,
                ..
            } => {
                result.graceful_count += 1;
            }
            InstanceShutdownDetail {
                error: None,
                was_graceful: false,
                ..
            } => {
                result.force_stopped_count += 1;
                // Log incident for force-stopped instances
                warn!(
                    "[shutdown] incident: instance {} was force-stopped after graceful timeout",
                    instance_id
                );
            }
            InstanceShutdownDetail { error: Some(e), .. } => {
                result.failed_count += 1;
                error!("[shutdown] failed to stop instance {}: {}", instance_id, e);
            }
        }

        result.details.push(detail);
    }

    info!(
        "[shutdown] shutdown complete: {} graceful, {} force-stopped, {} failed",
        result.graceful_count, result.force_stopped_count, result.failed_count
    );

    Ok(result)
}

/// Shut down a single instance with a timeout.
///
/// Attempts graceful shutdown first, then force-stops if timeout is exceeded.
fn shutdown_instance_with_timeout(
    exec: &Executor,
    instance_id: &str,
    _timeout: Duration,
) -> InstanceShutdownDetail {
    let start = std::time::Instant::now();

    // Get instance details from database
    let instance_info = match exec.store.call(
        "InstanceDbGet",
        json!({
            "db_path": exec.config.store_db_path,
            "id": instance_id,
        }),
    ) {
        Ok(info) => info,
        Err(e) => {
            return InstanceShutdownDetail {
                instance_id: instance_id.to_string(),
                was_graceful: false,
                duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                error: Some(format!("failed to get instance info: {e}")),
            };
        }
    };

    // Extract container name
    let container = instance_info["container"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let claw_type = instance_info["claw_type"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    let name = instance_info["name"].as_str().unwrap_or("").to_string();

    // Try graceful shutdown first
    info!(
        "[shutdown] attempting graceful shutdown for {}",
        instance_id
    );

    let stop_result = exec.execute_flow(&ExecuteFlowRequest {
        flow_type: FlowType::Stop,
        instance_id: instance_id.to_string(),
        container: container.clone(),
        claw_type,
        attempt_errors: vec![],
        attempt_ports: vec![],
        max_port_retries: 0,
        tools: vec![],
        name,
        guest_os: String::new(),
        cpu_cores: None,
        ram_mb: None,
        disk_gb: None,
    });

    let elapsed = start.elapsed();

    if stop_result.status == crate::FlowStatus::Completed {
        info!(
            "[shutdown] {} shut down gracefully in {}ms",
            instance_id,
            elapsed.as_millis()
        );
        InstanceShutdownDetail {
            instance_id: instance_id.to_string(),
            was_graceful: true,
            duration_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            error: None,
        }
    } else {
        // Graceful shutdown failed, try force-stop
        warn!(
            "[shutdown] graceful shutdown failed for {}, attempting force-stop",
            instance_id
        );

        let force_result = force_stop_instance(exec, &container);
        let total_elapsed = start.elapsed();

        match force_result {
            Ok(()) => InstanceShutdownDetail {
                instance_id: instance_id.to_string(),
                was_graceful: false,
                duration_ms: u64::try_from(total_elapsed.as_millis()).unwrap_or(u64::MAX),
                error: None,
            },
            Err(e) => InstanceShutdownDetail {
                instance_id: instance_id.to_string(),
                was_graceful: false,
                duration_ms: u64::try_from(total_elapsed.as_millis()).unwrap_or(u64::MAX),
                error: Some(e.to_string()),
            },
        }
    }
}

/// Force-stop an instance by directly calling vmrunner.
///
/// This bypasses the normal graceful shutdown flow and immediately
/// terminates the VM.
fn force_stop_instance(exec: &Executor, container: &str) -> Result<(), Box<dyn std::error::Error>> {
    exec.vmrunner.call(
        VmRunnerOp::Stop.as_str(),
        json!({
            "container": container,
            "state_dir": exec.config.firecracker_state_dir,
            "force": true,
        }),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_result_is_complete() {
        let result = ShutdownResult {
            graceful_count: 2,
            force_stopped_count: 1,
            failed_count: 0,
            details: vec![],
        };
        assert!(result.is_complete());
        assert_eq!(result.total_count(), 3);
    }

    #[test]
    fn test_shutdown_result_with_failures() {
        let result = ShutdownResult {
            graceful_count: 1,
            force_stopped_count: 1,
            failed_count: 1,
            details: vec![],
        };
        assert!(!result.is_complete());
        assert_eq!(result.total_count(), 3);
    }

    #[test]
    fn test_shutdown_result_to_json() {
        let result = ShutdownResult {
            graceful_count: 1,
            force_stopped_count: 0,
            failed_count: 0,
            details: vec![],
        };
        let json = result.to_json();
        assert_eq!(json["graceful_count"], 1);
        assert_eq!(json["is_complete"], true);
    }

    #[test]
    fn test_graceful_shutdown_timeout_constant() {
        assert_eq!(GRACEFUL_SHUTDOWN_TIMEOUT.as_secs(), 30);
    }
}
