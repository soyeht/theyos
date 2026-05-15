//! IPC contract tests for `vmrunner_ipc`.
//!
//! Validates the JSON-RPC line protocol between `server-rs` (caller) and
//! `vmrunner_ipc` (subprocess) WITHOUT requiring a live Firecracker environment.
//!
//! These tests verify:
//! - Wire format: request → JSON line → response JSON line
//! - Every known method rejects missing required params with `{"ok": false}`
//! - Unknown methods return `{"ok": false}`
//! - Response always has the `ok` field
//!
//! They run as part of `cargo test --workspace` (Phase 2 of `soyeht deploy`).

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

// ── Helper ──────────────────────────────────────────────────────────────────

/// Start `vmrunner_ipc` and return (stdin, stdout reader, child).
fn start_ipc() -> (
    std::process::ChildStdin,
    BufReader<std::process::ChildStdout>,
    std::process::Child,
) {
    // Locate the binary relative to the test binary location.
    // cargo test puts test binaries in target/debug/deps/ and the IPC binary
    // in target/debug/. Walk up to find target/debug/.
    let exe = std::env::current_exe().expect("current_exe");
    let target_debug = exe
        .parent() // deps/
        .and_then(|p| p.parent()) // debug/
        .expect("could not find target/debug from test exe");
    let bin = target_debug.join("vmrunner_ipc");
    assert!(
        bin.is_file(),
        "vmrunner_ipc not found at {}. Run `cargo build -p vmrunner-rs` first.",
        bin.display()
    );

    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null()) // suppress tracing output
        .spawn()
        .unwrap_or_else(|e| panic!("failed to start vmrunner_ipc: {e}"));

    let stdin = child.stdin.take().expect("no stdin");
    let stdout = BufReader::new(child.stdout.take().expect("no stdout"));

    (stdin, stdout, child)
}

/// Send a JSON request and read the JSON response.
fn call(
    stdin: &mut std::process::ChildStdin,
    stdout: &mut BufReader<std::process::ChildStdout>,
    method: &str,
    params: &serde_json::Value,
) -> serde_json::Value {
    let req = serde_json::json!({"method": method, "params": params});
    let mut line = serde_json::to_string(&req).expect("serialize request");
    line.push('\n');
    stdin.write_all(line.as_bytes()).expect("write to stdin");
    stdin.flush().expect("flush stdin");

    let mut response_line = String::new();
    stdout.read_line(&mut response_line).expect("read response");
    assert!(
        !response_line.is_empty(),
        "vmrunner_ipc closed stdout unexpectedly for method {method}"
    );

    serde_json::from_str(response_line.trim())
        .unwrap_or_else(|e| panic!("invalid JSON response for {method}: {e}\nraw: {response_line}"))
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Every response must have an `ok` boolean field.
fn assert_has_ok(resp: &serde_json::Value, method: &str) {
    assert!(
        resp.get("ok").is_some(),
        "response for {method} missing 'ok' field: {resp}"
    );
    assert!(
        resp["ok"].is_boolean(),
        "response for {method} 'ok' is not boolean: {resp}"
    );
}

/// Error response must have `ok: false` and an `error` string.
fn assert_error_response(resp: &serde_json::Value, method: &str) {
    assert_has_ok(resp, method);
    assert_eq!(
        resp["ok"].as_bool(),
        Some(false),
        "expected error for {method} with empty params, got: {resp}"
    );
    assert!(
        resp["error"].is_string(),
        "error response for {method} missing 'error' string: {resp}"
    );
}

/// Unknown methods must return `{"ok": false, "error": "unknown method: ..."}`.
#[test]
fn unknown_method_returns_error() {
    let (mut stdin, mut stdout, mut child) = start_ipc();

    let resp = call(
        &mut stdin,
        &mut stdout,
        "TotallyFakeMethod",
        &serde_json::json!({}),
    );

    assert_error_response(&resp, "TotallyFakeMethod");
    let err = resp["error"].as_str().unwrap();
    assert!(
        err.contains("unknown method"),
        "error should mention 'unknown method', got: {err}"
    );

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
}

/// All known methods with empty/missing required params must return errors
/// (not crash, not hang, not return ok: true).
#[test]
fn all_methods_reject_empty_params() {
    let (mut stdin, mut stdout, mut child) = start_ipc();

    let methods = [
        "Create",
        "Stop",
        "Delete",
        "Restart",
        "CleanupSystemd",
        "CleanupFs",
        "FetchLogs",
        "TakeBaseSnapshot",
        // WarmPoolInit and WarmPoolRefill also require params.
        "WarmPoolRefill",
    ];

    for method in &methods {
        let resp = call(&mut stdin, &mut stdout, method, &serde_json::json!({}));
        assert_error_response(&resp, method);
    }

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
}

/// `WarmPoolStatus` takes no params and should return ok: true with a result.
#[test]
fn warm_pool_status_returns_ok() {
    let (mut stdin, mut stdout, mut child) = start_ipc();

    let resp = call(
        &mut stdin,
        &mut stdout,
        "WarmPoolStatus",
        &serde_json::json!({}),
    );

    assert_has_ok(&resp, "WarmPoolStatus");
    assert_eq!(
        resp["ok"].as_bool(),
        Some(true),
        "WarmPoolStatus should succeed with empty params: {resp}"
    );
    // Result should exist (even if the pool is empty)
    assert!(
        resp.get("result").is_some(),
        "WarmPoolStatus response missing 'result' field: {resp}"
    );

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
}

/// Verify the Create method rejects params missing required fields, one by one.
/// This catches regressions where a field is renamed or removed.
#[test]
fn create_rejects_each_missing_required_field() {
    let (mut stdin, mut stdout, mut child) = start_ipc();

    // Full valid-ish params (paths don't need to exist — it should fail
    // on the first missing field before trying to access files).
    let full_params = serde_json::json!({
        "container": "test-ctr",
        "customer": "test-cust",
        "claw_type": "picoclaw",
        "state_dir": "/tmp/nonexistent",
        "firecracker_bin": "/tmp/nonexistent",
        "kernel_image": "/tmp/nonexistent",
        "base_rootfs": "/tmp/nonexistent",
        "ssh_key": "/tmp/nonexistent",
        "ssh_pubkey": "/tmp/nonexistent"
    });

    let required_fields = [
        "container",
        "customer",
        "claw_type",
        "state_dir",
        "firecracker_bin",
        "kernel_image",
        "base_rootfs",
        "ssh_key",
        "ssh_pubkey",
    ];

    for field in &required_fields {
        let mut params = full_params.clone();
        params.as_object_mut().unwrap().remove(*field);

        let resp = call(&mut stdin, &mut stdout, "Create", &params);
        assert_error_response(&resp, &format!("Create (missing {field})"));

        let err = resp["error"].as_str().unwrap_or("");
        assert!(
            err.contains(field) || err.contains("required"),
            "Create missing '{field}' should mention the field in error, got: {err}"
        );
    }

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
}

/// Multiple sequential calls on the same connection must all get responses
/// (no state corruption between calls).
#[test]
fn multiple_calls_on_same_connection() {
    let (mut stdin, mut stdout, mut child) = start_ipc();

    // Call 1: unknown method
    let r1 = call(
        &mut stdin,
        &mut stdout,
        "FakeMethod1",
        &serde_json::json!({}),
    );
    assert_error_response(&r1, "FakeMethod1");

    // Call 2: WarmPoolStatus (should succeed)
    let r2 = call(
        &mut stdin,
        &mut stdout,
        "WarmPoolStatus",
        &serde_json::json!({}),
    );
    assert_has_ok(&r2, "WarmPoolStatus");
    assert_eq!(r2["ok"].as_bool(), Some(true));

    // Call 3: another unknown method
    let r3 = call(
        &mut stdin,
        &mut stdout,
        "FakeMethod2",
        &serde_json::json!({}),
    );
    assert_error_response(&r3, "FakeMethod2");

    // Call 4: Stop with missing params
    let r4 = call(&mut stdin, &mut stdout, "Stop", &serde_json::json!({}));
    assert_error_response(&r4, "Stop");

    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
}
