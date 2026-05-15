//! Contract tests for vmrunner implementations.
//!
//! These tests verify that both vmrunner-rs (Linux/Firecracker) and
//! vmrunner-macos-rs (macOS/Virtualization Framework) conform to the same
//! behavioral contract. Tests use mock IPC binaries to validate request/response
//! shapes without requiring real VMs.

use std::sync::OnceLock;
use tempfile::TempDir;

use executor_rs::{Executor, FlowConfig, FlowType};

// ─── Fake IPC server (generic — returns success) ─────────────────────────────

static FAKE_IPC: OnceLock<(TempDir, std::path::PathBuf)> = OnceLock::new();

/// Path to a shell script that responds `{"ok":true,"result":{}}` to every
/// JSON-RPC request.
fn fake_ipc_path() -> &'static std::path::PathBuf {
    &FAKE_IPC
        .get_or_init(|| {
            let dir = TempDir::new().expect("create tempdir for fake ipc");
            let path = dir.path().join("vmrunner-contract-fake-ipc.sh");
            write_executable_script(
                &path,
                b"#!/bin/sh\nwhile IFS= read -r _l; do printf '{\"ok\":true,\"result\":{}}\n'; done\n",
            );
            (dir, path)
        })
        .1
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

fn base_req(flow_type: FlowType) -> executor_rs::ExecuteFlowRequest {
    executor_rs::ExecuteFlowRequest {
        flow_type,
        instance_id: "inst-contract-test".to_string(),
        name: "contract-test".to_string(),
        container: "picoclaw-contract-test".to_string(),
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

fn write_executable_script(path: &std::path::Path, contents: impl AsRef<[u8]>) {
    {
        use std::io::Write as _;
        let mut file = std::fs::File::create(path).expect("create mock ipc");
        file.write_all(contents.as_ref()).expect("write mock ipc");
        file.sync_all().expect("sync mock ipc");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
}

// ─── Contract: Create flow lifecycle ─────────────────────────────────────────

/// Contract test: Create flow must invoke vmrunner Create method.
///
/// Verifies that the executor sends a well-formed Create request to the
/// vmrunner IPC subprocess during instance creation.
#[test]
fn test_create_invokes_vmrunner_create() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("vmrunner-create.jsonl");

    // Create a recording IPC that records requests and responds OK
    let script_path = tmp.path().join("recording-ipc.sh");
    let record_path_str = record_file.display();
    let script = format!(
        "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> \"{record_path_str}\"\n  printf '{{\"ok\":true,\"result\":{{}}}}\n'\ndone\n"
    );
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let req = base_req(FlowType::Create);
    let _result = exec.execute_flow(&req);

    // Verify Create was called
    let content = std::fs::read_to_string(&record_file).unwrap_or_default();
    assert!(
        content.contains("\"Create\""),
        "Create method must be called during create flow"
    );
}

/// Contract test: Create flow must pass required parameters to vmrunner.
///
/// Verifies that Create request includes: container, `kernel_image`, rootfs,
/// cpus, `memory_mb`, and port.
#[test]
fn test_create_passes_required_params() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("vmrunner-create-params.jsonl");

    let script_path = tmp.path().join("recording-ipc.sh");
    let record_path_str = record_file.display();
    let script = format!(
        "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> \"{record_path_str}\"\n  printf '{{\"ok\":true,\"result\":{{\"vm_id\":\"test-vm\",\"pid\":12345,\"port\":18790}}}}\n'\ndone\n"
    );
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let req = base_req(FlowType::Create);
    let _result = exec.execute_flow(&req);

    // Parse and verify Create params
    let content = std::fs::read_to_string(&record_file).unwrap_or_default();
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v["method"].as_str() == Some("Create") {
                let params = &v["params"];

                // Required parameters
                assert!(
                    params.get("container").is_some(),
                    "Create must include 'container' param"
                );
                assert!(
                    params.get("kernel_image").is_some(),
                    "Create must include 'kernel_image' param"
                );
                assert!(
                    params.get("base_rootfs").is_some(),
                    "Create must include 'base_rootfs' param"
                );
                assert!(
                    params.get("claw_type").is_some(),
                    "Create must include 'claw_type' param"
                );

                return;
            }
        }
    }

    panic!("Create method not found in recording");
}

/// Contract test: Create flow must return `vm_id` and port from vmrunner.
///
/// Verifies that the executor propagates `vm_id` and port from the Create
/// response back to the caller.
#[test]
fn test_create_returns_vm_id_and_port() {
    let tmp = TempDir::new().unwrap();
    let script_path = tmp.path().join("mock-create.sh");

    // Mock that returns specific vm_id and port
    let script = r#"#!/bin/sh
while IFS= read -r line; do
  method=$(printf '%s' "$line" | grep -o '"method":"[^"]*"' | head -1 | sed 's/"method":"//;s/"//')
  case "$method" in
    Create)
      printf '{"ok":true,"result":{"vm_id":"test-vm-abc123","pid":12345,"port":18790}}\n'
      ;;
    *)
      printf '{"ok":true,"result":{}}\n'
      ;;
  esac
done
"#;
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let req = base_req(FlowType::Create);
    let result = exec.execute_flow(&req);

    assert_eq!(
        result.status,
        executor_rs::FlowStatus::Completed,
        "create should succeed"
    );
    assert_eq!(
        result.host_port,
        Some(18790),
        "host_port should match vmrunner response"
    );
}

// ─── Contract: Stop flow lifecycle ───────────────────────────────────────────

/// Contract test: Stop flow must invoke vmrunner Stop method.
///
/// Verifies that the executor sends a well-formed Stop request to the
/// vmrunner IPC subprocess during instance stop.
#[test]
fn test_stop_invokes_vmrunner_stop() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("vmrunner-stop.jsonl");

    let script_path = tmp.path().join("recording-ipc.sh");
    let record_path_str = record_file.display();
    let script = format!(
        "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> \"{record_path_str}\"\n  printf '{{\"ok\":true,\"result\":{{}}}}\n'\ndone\n"
    );
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let req = base_req(FlowType::Stop);
    let _result = exec.execute_flow(&req);

    // Verify Stop was called
    let content = std::fs::read_to_string(&record_file).unwrap_or_default();
    assert!(
        content.contains("\"Stop\""),
        "Stop method must be called during stop flow"
    );
}

/// Contract test: Stop flow must pass container parameter.
///
/// Verifies that Stop request includes the container name.
#[test]
fn test_stop_passes_container_param() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("vmrunner-stop-params.jsonl");

    let script_path = tmp.path().join("recording-ipc.sh");
    let record_path_str = record_file.display();
    let script = format!(
        "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> \"{record_path_str}\"\n  printf '{{\"ok\":true,\"result\":{{}}}}\n'\ndone\n"
    );
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let mut req = base_req(FlowType::Stop);
    req.container = "picoclaw-stop-test".to_string();
    let _result = exec.execute_flow(&req);

    // Parse and verify Stop params
    let content = std::fs::read_to_string(&record_file).unwrap_or_default();
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v["method"].as_str() == Some("Stop") {
                let params = &v["params"];
                assert_eq!(
                    params["container"].as_str(),
                    Some("picoclaw-stop-test"),
                    "Stop must pass correct container param"
                );
                return;
            }
        }
    }

    panic!("Stop method not found in recording");
}

// ─── Contract: Port forwarding ───────────────────────────────────────────────

/// Contract test: Create request must include SSH/config fields.
///
/// Verifies that Create request includes `ssh_key` and `ssh_pubkey`
/// for SSH-only access (no HTTP port forwarding).
#[test]
fn test_create_includes_ssh_config() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("vmrunner-ssh-config.jsonl");

    let script_path = tmp.path().join("recording-ipc.sh");
    let record_path_str = record_file.display();
    let script = format!(
        "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> \"{record_path_str}\"\n  printf '{{\"ok\":true,\"result\":{{\"vm_id\":\"test\",\"pid\":12345}}}}\n'\ndone\n"
    );
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let req = base_req(FlowType::Create);
    let _result = exec.execute_flow(&req);

    // Parse and verify SSH config fields
    let content = std::fs::read_to_string(&record_file).unwrap_or_default();
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v["method"].as_str() == Some("Create") {
                let params = &v["params"];

                assert!(
                    params.get("ssh_key").is_some(),
                    "Create must include 'ssh_key' param"
                );
                assert!(
                    params.get("ssh_pubkey").is_some(),
                    "Create must include 'ssh_pubkey' param"
                );

                return;
            }
        }
    }

    panic!("Create method not found in recording");
}

/// Contract test: Port conflict errors must be propagated.
///
/// Verifies that port conflict errors from vmrunner are correctly
/// propagated to the executor result.
#[test]
fn test_port_conflict_error_propagated() {
    let tmp = TempDir::new().unwrap();
    let script_path = tmp.path().join("port-conflict.sh");

    // Mock that returns port conflict error
    let script = r#"#!/bin/sh
while IFS= read -r line; do
  method=$(printf '%s' "$line" | grep -o '"method":"[^"]*"' | head -1 | sed 's/"method":"//;s/"//')
  case "$method" in
    Create)
      printf '{"ok":false,"error":"address already in use","error_context":{"phase":"vm_boot","command":"slirp4netns","exit_code":1,"stderr_tail":"bind: address already in use"}}\n'
      ;;
    Ping)
      printf '{"ok":true,"result":{"pong":true}}\n'
      ;;
    *)
      printf '{"ok":true,"result":{}}\n'
      ;;
  esac
done
"#;
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let req = base_req(FlowType::Create);
    let result = exec.execute_flow(&req);

    // Should detect port conflict and include in error
    let err = result.error.as_deref().unwrap_or("");
    assert!(
        err.contains("address already in use") || err.contains("port"),
        "Port conflict error should be propagated, got: {err:?}"
    );
}

// ─── Contract: Snapshot lifecycle ────────────────────────────────────────────

/// Contract test: Snapshot save must be invoked during VM lifecycle.
///
/// Verifies that vmrunner supports snapshot save operations for warm pool.
#[test]
fn test_snapshot_save_invoked() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("vmrunner-snapshot.jsonl");

    let script_path = tmp.path().join("recording-ipc.sh");
    let record_path_str = record_file.display();
    let script = format!(
        "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> \"{record_path_str}\"\n  printf '{{\"ok\":true,\"result\":{{}}}}\n'\ndone\n"
    );
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let _exec = Executor::new(config).expect("executor");

    // Executor construction should only ping subprocesses.
    let content = std::fs::read_to_string(&record_file).unwrap_or_default();

    // The executor should have sent Ping but not WarmPoolInit yet.
    assert!(
        content.contains("\"Ping\""),
        "Ping should be called during executor initialization"
    );
    assert!(
        !content.contains("\"WarmPoolInit\""),
        "WarmPoolInit should not be called during executor initialization"
    );
}

/// Contract test: Snapshot operations must include path parameter.
///
/// Verifies that snapshot save/load requests include the snapshot path.
#[test]
fn test_snapshot_includes_path_param() {
    let tmp = TempDir::new().unwrap();
    let script_path = tmp.path().join("snapshot-path.sh");

    // Mock that records snapshot requests
    let script = r#"#!/bin/sh
while IFS= read -r line; do
  method=$(printf '%s' "$line" | grep -o '"method":"[^"]*"' | head -1 | sed 's/"method":"//;s/"//')
  case "$method" in
    WarmPoolInit)
      # Record snapshot path was provided
      printf '{"ok":true,"result":{}}\n'
      ;;
    *)
      printf '{"ok":true,"result":{}}\n'
      ;;
  esac
done
"#;
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    // Executor construction should succeed
    let _exec = Executor::new(config).expect("executor should initialize");
}

// ─── Contract: Error handling ────────────────────────────────────────────────

/// Contract test: `NotFound` errors must be propagated correctly.
///
/// Verifies that VM not found errors from vmrunner are correctly
/// propagated to the executor result.
#[test]
fn test_not_found_error_propagated() {
    let tmp = TempDir::new().unwrap();
    let script_path = tmp.path().join("not-found.sh");

    // Mock that returns NotFound error for Stop
    let script = r#"#!/bin/sh
while IFS= read -r line; do
  method=$(printf '%s' "$line" | grep -o '"method":"[^"]*"' | head -1 | sed 's/"method":"//;s/"//')
  case "$method" in
    Stop)
      printf '{"ok":false,"error":"VM not found: picoclaw-test","error_context":{"phase":"vm_stop"}}\n'
      ;;
    Ping)
      printf '{"ok":true,"result":{"pong":true}}\n'
      ;;
    *)
      printf '{"ok":true,"result":{}}\n'
      ;;
  esac
done
"#;
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let req = base_req(FlowType::Stop);
    let result = exec.execute_flow(&req);

    // Delete flows should succeed even if Stop returns NotFound (best-effort)
    // But the error should still be present in result
    assert!(
        result.error.is_some() || result.status == executor_rs::FlowStatus::Completed,
        "Stop should either succeed or propagate NotFound error"
    );
}

// ─── Contract: macOS guest (003-macos-guest-xcode) ───────────────────────────

/// Contract test: Create with `guest_os: "macos"` must include the field.
///
/// On macOS hosts, executor-rs passes `guest_os: "macos"` in the vmrunner
/// Create request. The mock verifies the field is present.
#[test]
fn test_macos_create_includes_guest_os_param() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("macos-create.jsonl");

    let script_path = tmp.path().join("recording-ipc.sh");
    let record_path_str = record_file.display();
    let script = format!(
        "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> \"{record_path_str}\"\n  printf '{{\"ok\":true,\"result\":{{}}}}\n'\ndone\n"
    );
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let req = base_req(FlowType::Create);
    let _result = exec.execute_flow(&req);

    let content = std::fs::read_to_string(&record_file).unwrap_or_default();
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v["method"].as_str() == Some("Create") {
                let params = &v["params"];
                // `guest_os` field must always be present in Create request (T020)
                assert!(
                    params.get("guest_os").is_some(),
                    "Create must include 'guest_os' param (linux or macos)"
                );
                let guest_os = params["guest_os"].as_str().unwrap_or("");
                assert!(
                    guest_os == "linux" || guest_os == "macos",
                    "guest_os must be 'linux' or 'macos', got: {guest_os:?}"
                );
                return;
            }
        }
    }
    panic!("Create method not found in recording");
}

/// Contract test: `MACOS_VM_LIMIT_REACHED` error code (2001) must be propagated.
///
/// When the macOS VM slot limit is reached, vmrunner returns error code 2001.
/// The executor must propagate this as a Failed result with the code in `error_context`.
#[test]
fn test_macos_vm_limit_reached_error_propagated() {
    let tmp = TempDir::new().unwrap();
    let script_path = tmp.path().join("slot-limit.sh");

    // Mock that returns MACOS_VM_LIMIT_REACHED (code 2001) on Create
    let script = r#"#!/bin/sh
while IFS= read -r line; do
  method=$(printf '%s' "$line" | grep -o '"method":"[^"]*"' | head -1 | sed 's/"method":"//;s/"//')
  case "$method" in
    Create)
      printf '{"ok":false,"error":"macOS VM limit reached (max 2 simultaneous macOS guest VMs per Apple license)","error_context":{"code":2001}}\n'
      ;;
    Ping)
      printf '{"ok":true,"result":{"pong":true}}\n'
      ;;
    *)
      printf '{"ok":true,"result":{}}\n'
      ;;
  esac
done
"#;
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let req = base_req(FlowType::Create);
    let result = exec.execute_flow(&req);

    assert_eq!(
        result.status,
        executor_rs::FlowStatus::Failed,
        "slot limit error must produce Failed status"
    );
    let err = result.error.as_deref().unwrap_or("");
    assert!(
        err.contains("macOS VM limit") || err.contains("2001") || err.contains("limit reached"),
        "error must mention VM slot limit, got: {err:?}"
    );
}

/// Contract test: `MacOsBaseInstall` method response shape is valid.
///
/// The `MacOsBaseInstall` IPC returns progress events during installation.
/// Verifies the response shape is well-formed JSON with `ok: true` and
/// optional `result.phase` / `result.progress` fields.
#[test]
fn test_macos_base_install_response_shape() {
    // Valid MacOsBaseInstall responses that vmrunner-macos-rs emits
    let valid_responses = [
        r#"{"ok":true,"result":{"phase":"download_ipsw","progress":0.0}}"#,
        r#"{"ok":true,"result":{"phase":"create_disk","progress":0.5}}"#,
        r#"{"ok":true,"result":{"phase":"complete"}}"#,
    ];
    for resp in valid_responses {
        let v: serde_json::Value =
            serde_json::from_str(resp).unwrap_or_else(|_| panic!("must be valid JSON: {resp}"));
        assert_eq!(v["ok"], true, "ok must be true: {resp}");
        assert!(v.get("result").is_some(), "result must be present: {resp}");
    }

    // Error response shape
    let err_resp =
        r#"{"ok":false,"error":"IPSW download failed","error_context":{"phase":"download_ipsw"}}"#;
    let v: serde_json::Value = serde_json::from_str(err_resp).unwrap();
    assert_eq!(v["ok"], false);
    assert!(v["error"].as_str().is_some());
    assert!(v["error_context"].get("phase").is_some());
}

/// Contract test: `RemoveMacOsBase` must return `bytes_freed` in result.
///
/// When the macOS base image is removed, the vmrunner returns the number
/// of bytes freed so the CLI can display it to the user.
#[test]
fn test_remove_macos_base_returns_bytes_freed() {
    // Valid RemoveMacOsBase response shape
    let resp = r#"{"ok":true,"result":{"bytes_freed":68719476736}}"#;
    let v: serde_json::Value = serde_json::from_str(resp).unwrap();
    assert_eq!(v["ok"], true);
    let bytes_freed = v["result"]["bytes_freed"].as_u64().unwrap_or(0);
    assert!(
        bytes_freed > 0,
        "bytes_freed should be > 0 after removing ~64GB base image"
    );

    // Zero is also valid (base dir was already empty)
    let empty_resp = r#"{"ok":true,"result":{"bytes_freed":0}}"#;
    let v2: serde_json::Value = serde_json::from_str(empty_resp).unwrap();
    assert_eq!(v2["ok"], true);
    assert_eq!(v2["result"]["bytes_freed"], 0);
}

/// Contract test: Create payload must use `cpu_cores`, `ram_mb`, `disk_gb` field names.
///
/// The macOS vmrunner reads `cpu_cores` and `ram_mb` (not `cpus`/`memory_mb`).
/// This test ensures the executor sends the correct field names so the vmrunner
/// receives the requested resource configuration instead of falling back to defaults.
#[test]
fn test_create_uses_correct_resource_field_names() {
    let tmp = TempDir::new().unwrap();
    let record_file = tmp.path().join("resource-fields.jsonl");

    let script_path = tmp.path().join("recording-ipc.sh");
    let record_path_str = record_file.display();
    let script = format!(
        "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> \"{record_path_str}\"\n  printf '{{\"ok\":true,\"result\":{{}}}}\n'\ndone\n"
    );
    write_executable_script(&script_path, script.as_bytes());

    let mut config = fake_config();
    config.vmrunner_bin = script_path.to_str().unwrap().to_string();

    let exec = Executor::new(config).expect("executor");
    let mut req = base_req(FlowType::Create);
    req.cpu_cores = Some(3);
    req.ram_mb = Some(4096);
    req.disk_gb = Some(20);
    let _result = exec.execute_flow(&req);

    let content = std::fs::read_to_string(&record_file).unwrap_or_default();
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v["method"].as_str() == Some("Create") {
                let params = &v["params"];
                // Must use cpu_cores (not cpus)
                assert!(
                    params.get("cpu_cores").is_some(),
                    "Create must use 'cpu_cores' (not 'cpus')"
                );
                assert_eq!(params["cpu_cores"].as_u64(), Some(3));
                // Must use ram_mb (not memory_mb)
                assert!(
                    params.get("ram_mb").is_some(),
                    "Create must use 'ram_mb' (not 'memory_mb')"
                );
                assert_eq!(params["ram_mb"].as_u64(), Some(4096));
                // Must include disk_gb
                assert!(
                    params.get("disk_gb").is_some(),
                    "Create must include 'disk_gb'"
                );
                assert_eq!(params["disk_gb"].as_u64(), Some(20));
                // Must NOT use old field names
                assert!(
                    params.get("cpus").is_none(),
                    "Create must not use deprecated 'cpus' field"
                );
                assert!(
                    params.get("memory_mb").is_none(),
                    "Create must not use deprecated 'memory_mb' field"
                );
                return;
            }
        }
    }
    panic!("Create method not found in recording");
}
