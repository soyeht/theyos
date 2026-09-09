//! `theyos-engine ptyd` is the PTY supervisor run from the engine's own file.
//!
//! These tests pin the contract the Mac lifecycle relies on when it writes the
//! supervisor LaunchAgent with the engine as its program: the subcommand must
//! answer exactly like `soyeht-ptyd`, and it must never fall through into the
//! HTTP engine, which is what an engine without this dispatch would do.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn engine() -> Command {
    Command::new(env!("CARGO_BIN_EXE_server"))
}

#[test]
fn ptyd_contract_matches_the_supervisor_wire_version() {
    let output = engine().args(["ptyd", "--contract"]).output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        reply,
        serde_json::json!({"protocol_version": terminal_rs::supervisor_wire::VERSION})
    );
}

#[test]
fn ptyd_status_reports_an_absent_daemon_as_unavailable_with_exit_2() {
    let socket = std::env::temp_dir().join(format!("ptyd-absent-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let output = engine()
        .args(["ptyd", "--status", "--socket"])
        .arg(&socket)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let reply: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(reply, serde_json::json!({"error": "unavailable"}));
}

#[test]
fn ptyd_with_wrong_arguments_exits_with_usage_and_never_starts_an_engine() {
    // A bad argument list must fail fast. Starting an HTTP engine here would
    // hang this test on a listen socket, so the deadline is the assertion.
    let started = Instant::now();
    let output = engine()
        .args(["ptyd", "--socket", "/nonexistent/only"])
        .env("ADDR", "127.0.0.1:1")
        .output()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage:"), "stderr: {stderr}");
    assert!(!stderr.contains("Starting server-rs"), "stderr: {stderr}");
}

#[tokio::test]
async fn ptyd_serves_a_supervisor_that_the_client_library_can_query() {
    let root = std::env::temp_dir().join(format!("ptyd-serve-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let socket: PathBuf = root.join("control.sock");
    let state = root.join("state");
    let mut daemon = engine()
        .args(["ptyd", "--socket"])
        .arg(&socket)
        .arg("--state-dir")
        .arg(&state)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();
    let client = terminal_rs::supervisor_client::SupervisorClient::new(socket.clone());
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match client.status().await {
            Ok(status) => break status,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            Err(error) => panic!(
                "supervisor never answered on {}: {error:?}",
                socket.display()
            ),
        }
    };
    assert_eq!(
        status.protocol_version,
        terminal_rs::supervisor_wire::VERSION
    );
    assert_eq!(status.broker_pid, Some(daemon.id()));
    daemon.kill().unwrap();
    let _ = daemon.wait();
    let _ = std::fs::remove_dir_all(&root);
}
