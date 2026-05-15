//! Integration tests for executor-rs flows.
//!
//! Tests `Executor` construction (real subprocess spawn + Ping), port-conflict
//! detection logic, and `execute_flow` routing with a fake shell IPC server.
//!
//! Serialization roundtrips are covered by unit tests in `executor-rs/src/lib.rs`.

use executor_rs::{
    ExecuteFlowRequest, ExecuteFlowResult, Executor, FlowConfig, FlowStatus, FlowType,
    is_port_conflict_message,
};
use std::sync::OnceLock;
use tempfile::TempDir;

// ─── Fake IPC server (generic — returns {} for everything) ────────────────────

static FAKE_IPC: OnceLock<(TempDir, std::path::PathBuf)> = OnceLock::new();

/// Path to a shell script that responds `{"ok":true,"result":{}}` to every
/// JSON-RPC request. Written once; safe to run concurrently.
/// Uses a `TempDir` held in a static `OnceLock` so the directory (and script)
/// outlive all tests and are cleaned up automatically on process exit.
fn fake_ipc_path() -> &'static std::path::PathBuf {
    &FAKE_IPC
        .get_or_init(|| {
            let dir = TempDir::new().expect("create tempdir for fake ipc");
            let path = dir.path().join("executor-rs-test-fake-ipc.sh");
            std::fs::write(
            &path,
            b"#!/bin/sh\nwhile IFS= read -r _l; do printf '{\"ok\":true,\"result\":{}}\n'; done\n",
        )
        .expect("write fake ipc");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            (dir, path)
        })
        .1
}

// ─── Fake IPC servers for port-conflict retry test ────────────────────────────
//
// The port-conflict retry path uses the inlined orchestrator logic directly.
// We only need fakes for vmrunner (which fails with a port-conflict error) and
// the other sub-processes (portmanager, store, terminal).

static FAKE_VM_CONFLICT: OnceLock<(TempDir, std::path::PathBuf)> = OnceLock::new();
static FAKE_GENERIC_CONFLICT: OnceLock<(TempDir, std::path::PathBuf)> = OnceLock::new();

/// Vmrunner fake: always returns a port-conflict error with a realistic
/// `error_context` (`phase`, `command`, `exit_code`, `stderr_tail`).
fn fake_vm_conflict_path() -> &'static std::path::PathBuf {
    &FAKE_VM_CONFLICT.get_or_init(|| {
        let dir = TempDir::new().expect("create tempdir for vm conflict");
        let path = dir.path().join("executor-rs-test-vm-conflict.sh");
        // IMPORTANT: all JSON values must be on a single line — the IPC
        // protocol is newline-delimited.  Embed literal \n as \\n inside
        // string values so the response stays on one line.
        let script = r#"#!/bin/sh
while IFS= read -r line; do
    method=$(printf '%s' "$line" | grep -o '"method":"[^"]*"' | head -1 | sed 's/"method":"//;s/"//')
    case "$method" in
        Ping)
            printf '{"ok":true,"result":{"pong":true}}\n'
            ;;
        Create)
            printf '{"ok":false,"error":"slirp_add_hostfwd: address already in use","error_context":{"phase":"vm_boot","command":"slirp4netns","exit_code":1,"timed_out":false,"elapsed_ms":120,"stderr_tail":"bind: address already in use\\n","stdout_tail":"","serial_log_tail":"","slirp_log_tail":""}}\n'
            ;;
        *)
            printf '{"ok":true,"result":{}}\n'
            ;;
    esac
done
"#;
        std::fs::write(&path, script.as_bytes()).expect("write fake vm conflict");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        (dir, path)
    }).1
}

/// Generic fake for all other sub-processes (portmanager, store,
/// terminal): responds {"ok":true,"result":{}} to everything including Ping.
fn fake_generic_conflict_path() -> &'static std::path::PathBuf {
    &FAKE_GENERIC_CONFLICT
        .get_or_init(|| {
            let dir = TempDir::new().expect("create tempdir for generic conflict");
            let path = dir.path().join("executor-rs-test-generic-conflict.sh");
            std::fs::write(
            &path,
            b"#!/bin/sh\nwhile IFS= read -r _l; do printf '{\"ok\":true,\"result\":{}}\n'; done\n",
        )
        .expect("write fake generic conflict");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            (dir, path)
        })
        .1
}

fn conflict_config() -> FlowConfig {
    let vm = fake_vm_conflict_path().to_str().unwrap().to_string();
    let generic = fake_generic_conflict_path().to_str().unwrap().to_string();
    FlowConfig {
        vmrunner_bin: vm,
        store_bin: generic.clone(),
        terminal_bin: generic,
        firecracker_state_dir: "/tmp".to_string(),
        firecracker_bin: "/tmp/fc".to_string(),
        kernel_image: "/tmp/vmlinux".to_string(),
        base_rootfs: "/tmp/rootfs.ext4".to_string(),
        ssh_key: "/tmp/id_rsa".to_string(),
        ssh_pubkey: "/tmp/id_rsa.pub".to_string(),
        ssh_wait_tries: 1,
        store_db_path: ":memory:".to_string(),
    }
}

fn fake_config() -> FlowConfig {
    let bin = fake_ipc_path().to_str().unwrap().to_string();
    FlowConfig {
        vmrunner_bin: bin.clone(),
        store_bin: bin.clone(),
        terminal_bin: bin,
        firecracker_state_dir: "/tmp".to_string(),
        firecracker_bin: "/tmp/fc".to_string(),
        kernel_image: "/tmp/vmlinux".to_string(),
        base_rootfs: "/tmp/rootfs.ext4".to_string(),
        ssh_key: "/tmp/id_rsa".to_string(),
        ssh_pubkey: "/tmp/id_rsa.pub".to_string(),
        ssh_wait_tries: 1,
        store_db_path: ":memory:".to_string(),
    }
}

fn make_executor() -> Executor {
    Executor::new(fake_config()).expect("fake executor")
}

fn base_req(flow_type: FlowType) -> ExecuteFlowRequest {
    ExecuteFlowRequest {
        flow_type,
        instance_id: "inst-test".to_string(),
        name: "test".to_string(),
        container: "picoclaw-test".to_string(),
        claw_type: "picoclaw".to_string(),
        attempt_errors: vec![],
        attempt_ports: vec![],
        max_port_retries: 3,
        tools: vec![],
        guest_os: String::new(),
        cpu_cores: None,
        ram_mb: None,
        disk_gb: None,
    }
}

// ─── Serde edge cases not covered by unit tests ──────────────────────────────

#[test]
fn request_defaults_empty_vecs_when_fields_absent() {
    // Unit tests roundtrip with vecs already set; this tests #[serde(default)]
    // actually works when the JSON fields are absent.
    let json = r#"{"flow_type":"create","instance_id":"i","name":"n","container":"c","claw_type":"picoclaw","max_port_retries":0}"#;
    let req: ExecuteFlowRequest = serde_json::from_str(json).unwrap();
    assert!(req.attempt_errors.is_empty());
    assert!(req.attempt_ports.is_empty());
    assert!(req.tools.is_empty());
}

#[test]
fn request_tools_preserved_in_serde_roundtrip() {
    let req = ExecuteFlowRequest {
        tools: vec!["codex".to_string(), "opencode".to_string()],
        guest_os: String::new(),
        ..base_req(FlowType::Create)
    };
    let json_str = serde_json::to_string(&req).unwrap();
    let decoded: ExecuteFlowRequest = serde_json::from_str(&json_str).unwrap();
    assert_eq!(decoded.tools, vec!["codex", "opencode"]);
}

#[test]
fn result_skip_serializing_if_none() {
    // Unit tests don't verify skip_serializing_if behavior.
    let r = ExecuteFlowResult {
        status: FlowStatus::Failed,
        error: Some("broke".to_string()),
        ..Default::default()
    };
    let j = serde_json::to_value(&r).unwrap();
    assert!(j.get("host_port").is_none(), "None fields must be absent");
    assert!(j.get("phases").is_none());
    assert!(j.get("total_ms").is_none());
    assert_eq!(j["error"], "broke", "Some fields must be present");
}

#[test]
fn result_completed_serializes_optional_fields() {
    let r = ExecuteFlowResult {
        status: FlowStatus::Completed,
        host_port: Some(18790),
        total_ms: Some(4500),
        golden_image_used: Some(false),
        install_skipped: Some(true),
        ..Default::default()
    };
    let j = serde_json::to_value(&r).unwrap();
    assert_eq!(j["host_port"], 18790_i64);
    assert_eq!(j["total_ms"], 4500_u64);
    assert_eq!(j["install_skipped"], true);
    assert!(j.get("error").is_none());
}

// ─── Executor construction ────────────────────────────────────────────────────

#[test]
fn executor_constructs_with_fake_ipc() {
    // Verifies that Executor::new() spawns 6 sub-processes and all respond
    // to Ping. This is an integration test — unit tests can't spawn processes.
    let _exec = make_executor();
}

// ─── is_port_conflict_message — pure logic ───────────────────────────────────

#[test]
fn is_port_conflict_message_detects_address_already_in_use() {
    assert!(is_port_conflict_message(
        "slirp_add_hostfwd: address already in use"
    ));
    assert!(is_port_conflict_message(
        "EADDRINUSE: Address already in use"
    ));
}

#[test]
fn is_port_conflict_message_detects_port_already_in_use() {
    assert!(is_port_conflict_message("port already in use on 18790"));
}

#[test]
fn is_port_conflict_message_detects_hostfwd_patterns() {
    assert!(is_port_conflict_message(
        "add_hostfwd failed for port 18790"
    ));
    assert!(is_port_conflict_message("slirp_add_hostfwd returned error"));
}

#[test]
fn is_port_conflict_message_returns_false_for_unrelated_errors() {
    assert!(!is_port_conflict_message("ssh connection timeout"));
    assert!(!is_port_conflict_message("no such file or directory"));
    assert!(!is_port_conflict_message("out of memory"));
    assert!(!is_port_conflict_message(""));
}

// ─── check_port_conflict — direct pattern matching ───────────────────────────

#[test]
fn check_port_conflict_detects_known_patterns() {
    // check_port_conflict now uses inlined orchestrator logic directly.
    let exec = make_executor();
    assert!(
        exec.check_port_conflict("bind: address already in use"),
        "address already in use must be detected"
    );
    assert!(
        exec.check_port_conflict("slirp_add_hostfwd failed"),
        "slirp pattern must be detected"
    );
    assert!(
        !exec.check_port_conflict("permission denied"),
        "unrelated error must not be a port conflict"
    );
}

// ─── execute_flow routing ────────────────────────────────────────────────────
//
// The inlined orchestrator produces real step lists. The fake IPC sub-processes
// return {} for all calls (success), so flows complete successfully.
// We verify only that each flow type routes to the correct handler.

#[test]
fn execute_flow_routes_create_to_handler() {
    let exec = make_executor();
    // With inlined orchestrator + fake IPC: create completes (port=0 from fake).
    let result = exec.execute_flow(&base_req(FlowType::Create));
    assert_ne!(
        result.error.as_deref().unwrap_or(""),
        "unknown flow type",
        "should reach create handler"
    );
}

#[test]
fn execute_flow_routes_create_sync_to_handler() {
    let exec = make_executor();
    let result = exec.execute_flow(&base_req(FlowType::CreateSync));
    assert_ne!(
        result.error.as_deref().unwrap_or(""),
        "unknown flow type",
        "should reach create_sync handler"
    );
}

#[test]
fn execute_flow_routes_delete_to_handler() {
    let exec = make_executor();
    let result = exec.execute_flow(&base_req(FlowType::Delete));
    assert_ne!(
        result.error.as_deref().unwrap_or(""),
        "unknown flow type",
        "should reach delete handler"
    );
}

#[test]
fn execute_flow_routes_restart_to_handler() {
    let exec = make_executor();
    let result = exec.execute_flow(&base_req(FlowType::Restart));
    assert_ne!(
        result.error.as_deref().unwrap_or(""),
        "unknown flow type",
        "should reach restart handler"
    );
}

#[test]
fn execute_flow_routes_stop_to_handler() {
    let exec = make_executor();
    let result = exec.execute_flow(&base_req(FlowType::Stop));
    assert_ne!(
        result.error.as_deref().unwrap_or(""),
        "unknown flow type",
        "should reach stop handler"
    );
}

// ─── Port-conflict retry exhaustion preserves error_context ──────────────────

/// When `create_vm` fails with a port-conflict error on every attempt and the
/// retry limit is reached, the final `ExecuteFlowResult` must:
///
/// 1. Have `status == "failed"`
/// 2. Have error containing `"create exceeded"`
/// 3. Have `error_context` present (not `None`)
/// 4. Have `error_context` containing retry metadata:
///    `retry_attempts`, `attempt_errors`, `attempt_ports`, `final_reason`
/// 5. Have `error_context` containing fields from the last vmrunner failure:
///    `phase`, `command`, `exit_code`, `stderr_tail`
#[test]
fn port_conflict_retry_exhaustion_propagates_error_context() {
    let exec = Executor::new(conflict_config()).expect("conflict executor");

    let req = ExecuteFlowRequest {
        flow_type: FlowType::Create,
        instance_id: "inst-conflict-test".to_string(),
        name: "conflict-test".to_string(),
        container: "picoclaw-conflict-test".to_string(),
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

    let result = exec.execute_flow(&req);

    // ── 1. Basic failure shape ────────────────────────────────────────────────
    assert_eq!(
        result.status,
        FlowStatus::Failed,
        "should be failed after exhausting retries"
    );

    let err = result.error.as_deref().unwrap_or("");
    assert!(
        err.contains("create exceeded"),
        "error should mention retry exhaustion, got: {err:?}"
    );

    // ── 2. error_context must be present ─────────────────────────────────────
    let ctx = result
        .error_context
        .as_ref()
        .expect("error_context must be present after port-conflict retry exhaustion");

    // ── 3. Retry metadata ─────────────────────────────────────────────────────
    assert!(
        ctx.get("retry_attempts").is_some(),
        "error_context must contain retry_attempts, got: {ctx}"
    );
    let retry_attempts = ctx["retry_attempts"].as_u64().unwrap_or(0);
    assert!(
        retry_attempts > 0,
        "retry_attempts must be > 0, got: {retry_attempts}"
    );

    assert!(
        ctx.get("attempt_errors").is_some(),
        "error_context must contain attempt_errors, got: {ctx}"
    );
    let attempt_errors = ctx["attempt_errors"].as_array().unwrap();
    assert!(
        !attempt_errors.is_empty(),
        "attempt_errors must be non-empty, got: {ctx}"
    );

    assert!(
        ctx.get("attempt_ports").is_some(),
        "error_context must contain attempt_ports, got: {ctx}"
    );

    assert!(
        ctx.get("final_reason").is_some(),
        "error_context must contain final_reason, got: {ctx}"
    );
    assert!(
        ctx["final_reason"]
            .as_str()
            .unwrap_or("")
            .contains("create exceeded"),
        "final_reason should match the error message, got: {ctx}"
    );

    // ── 4. Fields from vmrunner error_context (last attempt) ─────────────────
    assert!(
        ctx.get("phase").is_some(),
        "error_context should contain phase from last vmrunner failure, got: {ctx}"
    );
    assert!(
        ctx.get("exit_code").is_some(),
        "error_context should contain exit_code from last vmrunner failure, got: {ctx}"
    );
    assert!(
        ctx.get("stderr_tail").is_some(),
        "error_context should contain stderr_tail from last vmrunner failure, got: {ctx}"
    );
}

// ─── Recording fake IPC ──────────────────────────────────────────────────────
//
// A shell script that records every request to a file AND responds OK.
// This lets us inspect the exact JSON params sent by each flow.

/// Create a recording IPC shell script that appends each request line to
/// `record_file` before responding with `{"ok":true,"result":{}}`.
fn write_recording_ipc(record_file: &std::path::Path) -> std::path::PathBuf {
    let script_path = record_file.with_extension("sh");
    let record_path_str = record_file.display();
    let script = format!(
        "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> \"{record_path_str}\"\n  printf '{{\"ok\":true,\"result\":{{}}}}\n'\ndone\n"
    );
    std::fs::write(&script_path, script.as_bytes()).expect("write recording ipc");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    script_path
}

fn recording_config(recording_ipc: &std::path::Path) -> FlowConfig {
    let vm = recording_ipc.to_str().unwrap().to_string();
    let generic = fake_ipc_path().to_str().unwrap().to_string();
    FlowConfig {
        vmrunner_bin: vm,
        store_bin: generic.clone(),
        terminal_bin: generic,
        firecracker_state_dir: "/tmp".to_string(),
        firecracker_bin: "/tmp/test-firecracker".to_string(),
        kernel_image: "/tmp/test-vmlinux".to_string(),
        base_rootfs: "/tmp/rootfs.ext4".to_string(),
        ssh_key: "/tmp/id_rsa".to_string(),
        ssh_pubkey: "/tmp/id_rsa.pub".to_string(),
        ssh_wait_tries: 1,
        store_db_path: ":memory:".to_string(),
    }
}

/// Parse the recording file and find the first request matching `method`.
/// Returns the `"params"` object from that request.
fn find_recorded_params(record_file: &std::path::Path, method: &str) -> Option<serde_json::Value> {
    let contents = std::fs::read_to_string(record_file).unwrap_or_default();
    for line in contents.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v["method"].as_str() == Some(method) {
                return Some(v["params"].clone());
            }
        }
    }
    None
}

// ─── Restart/Rebuild IPC param validation ────────────────────────────────────
//
// These tests verify that the flows pass the correct parameters to the
// vmrunner IPC subprocess.  If someone removes firecracker_bin or
// kernel_image from the flow code, these tests will catch it.

#[test]
fn restart_sends_firecracker_bin_and_kernel_image() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("vmrunner-restart.jsonl");
    let script = write_recording_ipc(&record_file);
    let config = recording_config(&script);

    let exec = Executor::new(config).expect("recording executor");
    let req = base_req(FlowType::Restart);
    let _result = exec.execute_flow(&req);

    let params =
        find_recorded_params(&record_file, "Restart").expect("Restart call not found in recording");

    assert_eq!(
        params["firecracker_bin"].as_str(),
        Some("/tmp/test-firecracker"),
        "firecracker_bin must be passed to Restart IPC"
    );
    assert_eq!(
        params["kernel_image"].as_str(),
        Some("/tmp/test-vmlinux"),
        "kernel_image must be passed to Restart IPC"
    );
}

#[test]
fn rebuild_sends_firecracker_bin_and_kernel_image() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("vmrunner-rebuild.jsonl");
    let script = write_recording_ipc(&record_file);
    let config = recording_config(&script);

    let exec = Executor::new(config).expect("recording executor");
    let req = base_req(FlowType::Rebuild);
    let _result = exec.execute_flow(&req);

    let params =
        find_recorded_params(&record_file, "Rebuild").expect("Rebuild call not found in recording");

    assert_eq!(
        params["firecracker_bin"].as_str(),
        Some("/tmp/test-firecracker"),
        "firecracker_bin must be passed to Rebuild IPC"
    );
    assert_eq!(
        params["kernel_image"].as_str(),
        Some("/tmp/test-vmlinux"),
        "kernel_image must be passed to Rebuild IPC"
    );
}

#[test]
fn restart_sends_container_from_request() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("vmrunner-container.jsonl");
    let script = write_recording_ipc(&record_file);
    let config = recording_config(&script);

    let exec = Executor::new(config).expect("recording executor");
    let mut req = base_req(FlowType::Restart);
    req.container = "zeroclaw-my-instance".to_string();
    let _result = exec.execute_flow(&req);

    let params =
        find_recorded_params(&record_file, "Restart").expect("Restart call not found in recording");

    assert_eq!(
        params["container"].as_str(),
        Some("zeroclaw-my-instance"),
        "container must match the request"
    );
}

// ── Delete flow best-effort tests ─────────────────────────────────────────

/// Fake IPC that fails `Stop` with a non-NotFound error but succeeds everything else.
/// Records all calls to a file so we can verify subsequent steps still ran.
/// The script is written next to the record file (same `TempDir`).
fn write_failing_stop_ipc(record_file: &std::path::Path) -> std::path::PathBuf {
    let rec = record_file.to_string_lossy();
    let script = record_file.with_extension("failing-stop.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             while IFS= read -r line; do\n\
               printf '%s\\n' \"$line\" >> \"{rec}\"\n\
               case \"$line\" in\n\
                 *'\"Stop\"'*) printf '{{\"ok\":false,\"error\":\"IPC timeout\"}}\\n' ;;\n\
                 *) printf '{{\"ok\":true,\"result\":{{}}}}\\n' ;;\n\
               esac\n\
             done\n"
        ),
    )
    .expect("write failing-stop ipc");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    script
}

#[test]
fn delete_flow_continues_after_stop_vm_failure() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("delete-best-effort.jsonl");
    let script = write_failing_stop_ipc(&record_file);

    // Use the failing-stop script only for vmrunner; others use generic recording
    let generic = write_recording_ipc(&tmp.path().join("generic.jsonl"));
    let mut config = recording_config(&generic);
    config.vmrunner_bin = script.to_string_lossy().to_string();

    let exec = Executor::new(config).expect("executor");
    let mut req = base_req(FlowType::Delete);
    req.container = "picoclaw-test-delete".to_string();
    req.instance_id = "inst-test-delete".to_string();

    let result = exec.execute_flow(&req);
    // The flow should succeed (best-effort) even though stop_vm failed
    assert_eq!(
        result.status,
        FlowStatus::Completed,
        "delete flow should complete even when stop_vm fails: {result:?}"
    );

    // Verify that steps AFTER stop_vm were still executed by checking the
    // vmrunner recording has both Stop AND Delete calls
    let content = std::fs::read_to_string(&record_file).unwrap_or_default();
    assert!(
        content.contains("\"Stop\""),
        "Stop should have been attempted"
    );
    assert!(
        content.contains("\"Delete\""),
        "Delete should have been called even though Stop failed"
    );
}

// ─── IPC auto-respawn: vmrunner respawn re-triggers warm pool ────────────────

/// Create a vmrunner recording script that crashes after 3 calls on first
/// incarnation (`Ping` + explicit `WarmPoolInit` + first real call), and runs forever on
/// subsequent incarnations. Uses a marker file to distinguish incarnations.
fn write_crashing_vmrunner_ipc(
    record_file: &std::path::Path,
    marker_file: &std::path::Path,
) -> std::path::PathBuf {
    let script_path = record_file.with_extension("vm.sh");
    let record = record_file.display();
    let marker = marker_file.display();
    let script = format!(
        r#"#!/bin/sh
if [ -f "{marker}" ]; then
  while IFS= read -r line; do
    printf '%s\n' "$line" >> "{record}"
    printf '{{"ok":true,"result":{{}}}}\n'
  done
else
  touch "{marker}"
  count=0
  while IFS= read -r line; do
    count=$((count + 1))
    printf '%s\n' "$line" >> "{record}"
    printf '{{"ok":true,"result":{{}}}}\n'
    if [ "$count" -ge 3 ]; then exit 0; fi
  done
fi
"#
    );
    std::fs::write(&script_path, script.as_bytes()).expect("write crashing vmrunner ipc");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    script_path
}

/// After vmrunner respawns, `check_vmrunner_respawn` should automatically
/// re-trigger `WarmPoolInit`. Verify by counting `WarmPoolInit` occurrences
/// in the recording (once from the explicit startup call, once after respawn).
#[test]
fn executor_vmrunner_respawn_retriggers_warm_pool() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("vmrunner-respawn.jsonl");
    let marker_file = tmp.path().join("vmrunner-respawn.marker");
    let script = write_crashing_vmrunner_ipc(&record_file, &marker_file);

    let generic = fake_ipc_path().to_str().unwrap().to_string();
    let config = FlowConfig {
        vmrunner_bin: script.to_str().unwrap().to_string(),
        store_bin: generic.clone(),
        terminal_bin: generic,
        firecracker_state_dir: "/tmp".to_string(),
        firecracker_bin: "/tmp/test-firecracker".to_string(),
        kernel_image: "/tmp/test-vmlinux".to_string(),
        base_rootfs: "/tmp/rootfs.ext4".to_string(),
        ssh_key: "/tmp/id_rsa".to_string(),
        ssh_pubkey: "/tmp/id_rsa.pub".to_string(),
        ssh_wait_tries: 1,
        store_db_path: ":memory:".to_string(),
    };

    let exec = Executor::new(config).expect("crashing vmrunner executor");
    exec.warm_pool_init().expect("explicit warm pool init");
    let req = base_req(FlowType::Restart);

    // First execute_flow: vmrunner handles Restart (3rd call), then exits.
    // The response was sent before exit, so the flow completes.
    let result = exec.execute_flow(&req);
    assert_eq!(
        result.status,
        FlowStatus::Completed,
        "first restart should succeed: {result:?}"
    );

    // Second execute_flow: vmrunner is dead → crash detected → respawn → retry.
    // After the flow, check_vmrunner_respawn detects the respawn and
    // re-triggers WarmPoolInit.
    let result = exec.execute_flow(&req);
    assert_eq!(
        result.status,
        FlowStatus::Completed,
        "second restart should succeed after respawn: {result:?}"
    );

    // Verify WarmPoolInit appears twice in recording
    let content = std::fs::read_to_string(&record_file).unwrap_or_default();
    let warm_pool_init_count = content
        .lines()
        .filter(|line| line.contains("\"WarmPoolInit\""))
        .count();
    assert_eq!(
        warm_pool_init_count, 2,
        "WarmPoolInit should appear twice (explicit startup + after respawn), found {warm_pool_init_count} in:\n{content}"
    );
}
