/// `executor_ipc` — JSON-RPC-over-stdin/stdout IPC binary for executor-rs.
///
/// Reads `FlowConfig` from environment variables, starts the Executor (which
/// in turn spawns portmanager-ipc, vmrunner-ipc, store-ipc,
/// and terminal-ipc), and enters the dispatch loop.
/// Flow decision logic (formerly orchestrator-rs) runs in-process.
use core_rs::env::env_or;
use core_rs::ipc::{harness::run_ipc_loop_with_init, wire::Response};
use executor_rs::{ExecuteFlowRequest, Executor, FlowConfig};
use serde_json::Value;

fn main() {
    run_ipc_loop_with_init("executor-ipc", init, dispatch);
}

fn init(_args: &[String]) -> Executor {
    eprintln!("[executor-ipc] starting up");

    let config = build_config_from_env();

    match Executor::new(config) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[executor-ipc] failed to start: {e}");
            std::process::exit(1);
        }
    }
}

fn dispatch(executor: &Executor, method: &str, params: &Value) -> Response {
    match method {
        "ExecuteFlow" => match serde_json::from_value::<ExecuteFlowRequest>(params.clone()) {
            Ok(req) => {
                let result = executor.execute_flow(&req);
                match serde_json::to_value(&result) {
                    Ok(v) => Response::ok(v),
                    Err(e) => Response::err(format!("serialize result: {e}")),
                }
            }
            Err(e) => Response::err(format!("parse ExecuteFlowRequest: {e}")),
        },
        other => Response::err(format!("unknown method: {other}")),
    }
}

/// Build a `FlowConfig` by reading environment variables.
fn build_config_from_env() -> FlowConfig {
    fn env(key: &str) -> String {
        std::env::var(key).unwrap_or_default()
    }

    // Select the appropriate vmrunner binary based on target OS
    // Use THEYOS_VMRUNNER_RS_BIN if set, otherwise use platform-specific default
    let vmrunner_bin = env("THEYOS_VMRUNNER_RS_BIN");
    let vmrunner_bin = if vmrunner_bin.is_empty() {
        default_vmrunner_bin()
    } else {
        vmrunner_bin
    };

    FlowConfig {
        vmrunner_bin,
        store_bin: env("THEYOS_STORE_RS_BIN"),
        terminal_bin: env("THEYOS_TERMINAL_RS_BIN"),

        firecracker_state_dir: env("FIRECRACKER_STATE_DIR"),
        firecracker_bin: env("FIRECRACKER_BIN"),
        kernel_image: env("FIRECRACKER_KERNEL_IMAGE"),
        base_rootfs: env("FIRECRACKER_BASE_ROOTFS"),
        ssh_key: env("FIRECRACKER_SSH_KEY"),
        ssh_pubkey: env("FIRECRACKER_SSH_PUBKEY"),
        ssh_wait_tries: std::env::var("FIRECRACKER_SSH_WAIT_TRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20),

        store_db_path: env_or("THEYOS_SQLITE_DB", "/tmp/theyos.db"),
    }
}

/// Returns the default vmrunner binary name for the current platform.
#[cfg(target_os = "linux")]
fn default_vmrunner_bin() -> String {
    "vmrunner_ipc".to_string()
}

/// Returns the default vmrunner binary name for the current platform.
#[cfg(target_os = "macos")]
fn default_vmrunner_bin() -> String {
    "vmrunner_macos_ipc".to_string()
}
