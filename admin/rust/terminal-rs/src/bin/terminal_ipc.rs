//! terminal-ipc — JSON-RPC-over-stdin/stdout bridge for the terminal-rs crate.
//!
//! v2: the PTY subsystem has been moved to live in-process in server-rs
//! (direct use of `PtyManager`), so the IPC-exposed surface is now limited
//! to the simple in-memory `Manager` for legacy `RunCommand` / history calls.
//! The PTY endpoints (`PTYSnapshot` / `PTYPoll` / `PTYWrite` / `PTYResize`)
//! have been removed because they required access to the per-process PTY
//! master fd, which doesn't cross IPC boundaries cleanly.
//!
//! # Request format
//!
//! ```json
//! {"method":"EnsureContainer","params":{"container":"box1"}}
//! {"method":"RunCommand","params":{"container":"box1","session_id":"","user":"admin","command":"ls"}}
//! ```
//!
//! # Response format
//!
//! ```json
//! {"ok":true,"result":{...}}
//! {"ok":false,"error":"..."}
//! ```

use core_rs::ipc::{harness::run_ipc_loop_with_init, wire::Response};
use serde_json::Value;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use terminal_rs::{ExecResult, Executor, Manager, TerminalError};

// ─── Real executor ───────────────────────────────────────────────────────────

/// Executor that calls `fc-ssh exec <container> <command>`.
struct FirecrackerExecutor {
    ctl_path: String,
}

impl FirecrackerExecutor {
    fn new() -> Self {
        FirecrackerExecutor {
            ctl_path: resolve_firecracker_ctl(),
        }
    }
}

/// Resolve the firecracker control binary with fallback chain.
fn resolve_firecracker_ctl() -> String {
    if let Ok(v) = std::env::var("FIRECRACKER_CTL") {
        if !v.is_empty() {
            return v;
        }
    }
    if which_exists("fc-ssh") {
        return "fc-ssh".to_string();
    }
    if let Some(debug_bin) = find_debug_fc_ssh() {
        return debug_bin;
    }
    eprintln!("[terminal-ipc] WARNING: fc-ssh not found; set FIRECRACKER_CTL");
    "fc-ssh".to_string()
}

fn which_exists(cmd: &str) -> bool {
    core_rs::os::which_binary(cmd).is_some()
}

fn find_debug_fc_ssh() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?;
    let candidate = dir.join("fc-ssh");
    if candidate.exists() {
        return Some(candidate.to_string_lossy().to_string());
    }
    for _ in 0..8 {
        dir = dir.parent()?;
        let candidate = dir.join("admin/rust/target/debug/fc-ssh");
        if candidate.exists() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }
    None
}

impl Executor for FirecrackerExecutor {
    fn exec(&self, container: &str, command: &str) -> Result<ExecResult, TerminalError> {
        let output = Command::new(&self.ctl_path)
            .args(["exec", container, command])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                let exit_code = out
                    .status
                    .code()
                    .unwrap_or_else(|| out.status.signal().map_or(1, |s| 128 + s));

                let combined = format!("{stdout}{stderr}").to_lowercase();
                if (combined.contains("not found")
                    || combined.contains("no such")
                    || combined.contains("does not exist"))
                    && (exit_code == 127 || combined.contains("runtime"))
                {
                    return Ok(ExecResult {
                        output: stdout,
                        exit_code: 127,
                    });
                }

                let result_output = if stdout.is_empty() && !stderr.is_empty() {
                    stderr
                } else {
                    stdout
                };

                Ok(ExecResult {
                    output: result_output,
                    exit_code,
                })
            }
            Err(e) => Err(TerminalError::Other(format!(
                "firecracker exec failed: {e}"
            ))),
        }
    }
}

// ─── State ────────────────────────────────────────────────────────────────────

struct State {
    manager: Manager,
    mock_mode: bool,
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    run_ipc_loop_with_init(
        "terminal-ipc",
        |_args| {
            let mock_mode = std::env::var("TERMINAL_IPC_MOCK_EXEC").unwrap_or_default() == "1";

            State {
                manager: if mock_mode {
                    eprintln!("[terminal-ipc] mock exec mode enabled");
                    Manager::new_empty()
                } else {
                    Manager::new(Box::new(FirecrackerExecutor::new()), &[])
                },
                mock_mode,
            }
        },
        dispatch,
    );
}

// ─── Dispatch ─────────────────────────────────────────────────────────────────

fn dispatch(state: &State, method: &str, params: &Value) -> Response {
    match method {
        "EnsureContainer" => handle_ensure_container(&state.manager, params),
        "RemoveContainer" => handle_remove_container(&state.manager, params),
        "ListContainers" => handle_list_containers(&state.manager),
        "HasContainer" => handle_has_container(&state.manager, params),
        "RunCommand" => {
            if state.mock_mode {
                handle_run_command_mock(&state.manager, params)
            } else {
                handle_run_command(&state.manager, params)
            }
        }
        "Restart" => handle_restart(&state.manager, params),
        "GetSessionHistory" => handle_get_session_history(&state.manager, params),
        other => Response::err(format!("unknown method: {other}")),
    }
}

fn handle_ensure_container(manager: &Manager, params: &Value) -> Response {
    let container = params["container"].as_str().unwrap_or("");
    manager.ensure_container(container);
    Response::ok_empty()
}

fn handle_remove_container(manager: &Manager, params: &Value) -> Response {
    let container = params["container"].as_str().unwrap_or("");
    manager.remove_container(container);
    Response::ok_empty()
}

fn handle_list_containers(manager: &Manager) -> Response {
    let containers = manager.list_containers();
    Response::ok(serde_json::json!({"containers": containers}))
}

fn handle_has_container(manager: &Manager, params: &Value) -> Response {
    let container = params["container"].as_str().unwrap_or("");
    let result = manager.has_container(container);
    Response::ok(serde_json::json!({"result": result}))
}

fn handle_run_command(manager: &Manager, params: &Value) -> Response {
    let container = params["container"].as_str().unwrap_or("");
    let session_id = params["session_id"].as_str().unwrap_or("");
    let user = params["user"].as_str().unwrap_or("soyeht");
    let command = params["command"].as_str().unwrap_or("");

    match manager.run_command(container, session_id, user, command) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e),
    }
}

fn handle_run_command_mock(manager: &Manager, params: &Value) -> Response {
    let container = params["container"].as_str().unwrap_or("");
    let session_id = params["session_id"].as_str().unwrap_or("");
    let user = params["user"].as_str().unwrap_or("soyeht");
    let command = params["command"].as_str().unwrap_or("");
    let mock_output = params["mock_output"].as_str().unwrap_or("");
    #[allow(clippy::cast_possible_truncation)]
    let mock_exit_code = params["mock_exit_code"].as_i64().unwrap_or(0) as i32;

    match manager.run_command_mock(
        container,
        session_id,
        user,
        command,
        mock_output,
        mock_exit_code,
    ) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e),
    }
}

fn handle_restart(manager: &Manager, params: &Value) -> Response {
    let container = params["container"].as_str().unwrap_or("");
    let session_id = params["session_id"].as_str().unwrap_or("");

    match manager.restart(container, session_id) {
        Ok(()) => Response::ok_empty(),
        Err(e) => Response::err(e),
    }
}

fn handle_get_session_history(manager: &Manager, params: &Value) -> Response {
    let container = params["container"].as_str().unwrap_or("");
    let session_id = params["session_id"].as_str().unwrap_or("");

    if container.trim().is_empty() || !manager.has_container(container) {
        return Response::err(TerminalError::ContainerNotFound);
    }

    let history = manager.get_session_history(container, session_id);
    Response::ok(serde_json::json!({"history": history, "count": history.len()}))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> State {
        State {
            manager: Manager::new_with_mock("", 0),
            mock_mode: true,
        }
    }

    #[test]
    fn ensure_and_list_containers() {
        let state = make_state();
        let p = serde_json::json!({"container": "box1"});
        assert!(handle_ensure_container(&state.manager, &p).ok);
        let resp = handle_list_containers(&state.manager);
        let containers = resp.result.unwrap()["containers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert!(containers.contains(&"box1".to_string()));
    }

    #[test]
    fn remove_container_removes_from_manager() {
        let state = make_state();
        let p = serde_json::json!({"container": "box"});
        handle_ensure_container(&state.manager, &p);
        handle_remove_container(&state.manager, &p);
        assert!(!state.manager.has_container("box"));
    }

    #[test]
    fn run_command_mock_updates_history() {
        let state = make_state();
        let p_ensure = serde_json::json!({"container": "box"});
        handle_ensure_container(&state.manager, &p_ensure);

        let p = serde_json::json!({
            "container": "box",
            "session_id": "",
            "user": "u",
            "command": "echo hi",
            "mock_output": "hi",
            "mock_exit_code": 0
        });
        let resp = handle_run_command_mock(&state.manager, &p);
        assert!(resp.ok);

        let hist = state.manager.get_session_history("box", "");
        assert!(hist.iter().any(|l| l.contains("echo hi")));
        assert!(hist.iter().any(|l| l == "hi"));
    }

    #[test]
    fn get_session_history_missing_container_errors() {
        let state = make_state();
        let p = serde_json::json!({"container": "no", "session_id": ""});
        let resp = handle_get_session_history(&state.manager, &p);
        assert!(!resp.ok);
    }
}
