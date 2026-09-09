#![cfg(test)]

use super::*;
use crate::cid::{collect_used_ssh_ports, pick_ssh_port};
use crate::ssh_client::test_utils::{MockSshSession, SshCall};
use tempfile::TempDir;

// ── SSH port selection ─────────────────────────────────────────────────

#[test]
fn pick_ssh_port_skips_used_ports() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();

    // Create two fake instance.env files occupying the first two SSH ports.
    for (port, name) in [
        (core_rs::guest_net::SSH_HOST_PORT_RANGE_START, "inst0"),
        (core_rs::guest_net::SSH_HOST_PORT_RANGE_START + 1, "inst1"),
    ] {
        let dir = state_dir.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("instance.env"),
            format!(
                "CONTAINER_NAME={name}\nCUSTOMER_NAME={name}\nCLAW_TYPE=picoclaw\n\
                     PORT=35000\nSSH_PORT={port}\n\
                     ROOTFS_PATH=/tmp/r\nAPI_SOCK=/tmp/a\n\
                     SLIRP_API_SOCK=/tmp/s\nSERIAL_LOG=/tmp/sl\nSLIRP_LOG=/tmp/ll\n\
                     CUSTOMER_DIR=\nCODE_DIR=\nCONFIG_PATH=\nWORKSPACE_PATH=\n\
                     FIRECRACKER_PID=\nSLIRP_PID=\n"
            ),
        )
        .unwrap();
    }

    let (port, _reservation) = pick_ssh_port(state_dir).unwrap();
    assert!(
        core_rs::guest_net::ssh_host_port_range().contains(&port),
        "port {port} out of range"
    );
    assert_ne!(
        port,
        core_rs::guest_net::SSH_HOST_PORT_RANGE_START,
        "should skip first configured SSH port"
    );
    assert_ne!(
        port,
        core_rs::guest_net::SSH_HOST_PORT_RANGE_START + 1,
        "should skip second configured SSH port"
    );
}

#[test]
fn collect_used_ssh_ports_empty_dir() {
    let tmp = TempDir::new().unwrap();
    let ports = collect_used_ssh_ports(tmp.path());
    assert!(ports.is_empty());
}

#[test]
fn collect_used_ssh_ports_nonexistent_dir() {
    let ports = collect_used_ssh_ports(Path::new("/nonexistent/state/dir"));
    assert!(ports.is_empty());
}

#[test]
fn pool_fill_errors_never_publish_a_slot() {
    use crate::warm_pool::{WarmEntry, WarmPool};

    let outcomes = [
        VmError::Other("add_hostfwd failed".into()),
        VmError::HostfwdUncertain("SSH cleanup was not verified".into()),
        VmError::HostfwdUncertain("successful cleanup was not verified".into()),
    ];

    for (index, error) in outcomes.into_iter().enumerate() {
        let claw_type = format!("pool-error-{index}");
        let container = WarmPool::container_name(&claw_type, 0);
        let entry = WarmEntry {
            container: container.clone(),
            claw_type: claw_type.clone(),
            inst: InstanceEnv {
                container: container.clone(),
                customer: container.clone(),
                claw_type: claw_type.clone(),
                host_port: 0,
                ssh_port: core_rs::guest_net::SSH_HOST_PORT_RANGE_START,
                firecracker_pid: None,
                slirp_pid: None,
                instance_dir: std::path::PathBuf::from("/tmp/phase0-pool-error"),
                rootfs_path: std::path::PathBuf::from("/tmp/phase0-pool-error/rootfs.ext4"),
                firecracker_sock: std::path::PathBuf::from(
                    "/tmp/phase0-pool-error/firecracker.sock",
                ),
                slirp_api_sock: std::path::PathBuf::from("/tmp/phase0-pool-error/slirp-api.sock"),
                serial_log: std::path::PathBuf::from("/tmp/phase0-pool-error/serial.log"),
                slirp_log: std::path::PathBuf::from("/tmp/phase0-pool-error/slirp.log"),
                customer_dir: String::new(),
            },
            binary_present: false,
        };
        let mut pool = WarmPool::default();

        let result = VmRunner::store_warm_entry_after_fill(&mut pool, entry, Err(error));

        assert!(result.is_err(), "fill outcome must remain an error");
        assert_eq!(
            pool.slot_state(&claw_type),
            "empty",
            "failed fill must not publish a warm slot"
        );
    }
}

#[test]
fn snapshot_quiesce_commands_are_specific() {
    let picoclaw = snapshot_quiesce_commands("picoclaw");
    assert_eq!(picoclaw.len(), 1);
    assert!(picoclaw[0].contains("systemctl stop picoclaw-agent.service"));
    assert!(
        picoclaw.iter().all(|cmd| !cmd.contains("*.service")),
        "quiesce must not use wildcard service stops: {picoclaw:?}"
    );

    let openclaw = snapshot_quiesce_commands("openclaw");
    assert!(
        openclaw
            .iter()
            .any(|cmd| cmd.contains("systemctl --user stop openclaw-gateway.service"))
    );
    assert!(
        openclaw
            .iter()
            .any(|cmd| cmd.contains("loginctl disable-linger root"))
    );
    assert!(
        openclaw
            .iter()
            .any(|cmd| cmd.contains("pkill -f '[n]ode.*gateway'")),
        "openclaw quiesce must avoid pkill self-matching its own shell: {openclaw:?}"
    );
    assert!(
        openclaw.iter().all(|cmd| !cmd.contains("*.service")),
        "openclaw quiesce must not use wildcard service stops: {openclaw:?}"
    );
}

#[tokio::test]
async fn quiesce_for_snapshot_runs_expected_openclaw_commands() {
    let ssh = MockSshSession::new();
    quiesce_for_snapshot(&ssh, "openclaw").await.unwrap();

    let calls = ssh.recorded_calls().await;
    let execs: Vec<String> = calls
        .into_iter()
        .filter_map(|call| match call {
            SshCall::Exec(cmd) => Some(cmd),
            _ => None,
        })
        .collect();

    assert!(
        execs
            .iter()
            .any(|cmd| cmd == "systemctl stop openclaw-agent.service 2>/dev/null || true")
    );
    assert!(
        execs
            .iter()
            .any(|cmd| cmd == "systemctl --user stop openclaw-gateway.service 2>/dev/null || true")
    );
    assert!(
        execs.iter().all(|cmd| !cmd.contains("*.service")),
        "quiesce must not use wildcard stops: {execs:?}"
    );
}

#[tokio::test]
async fn restart_claw_agent_best_effort_appends_true() {
    let ssh = MockSshSession::new();

    restart_claw_agent_best_effort(&ssh, "picoclaw").await;

    let calls = ssh.recorded_calls().await;
    let execs: Vec<String> = calls
        .into_iter()
        .filter_map(|call| match call {
            SshCall::Exec(cmd) => Some(cmd),
            _ => None,
        })
        .collect();

    assert_eq!(
        execs,
        vec!["systemctl restart picoclaw-agent.service || true"]
    );
}

// ── Error cases ────────────────────────────────────────────────────────

#[test]
fn validate_binaries_missing_firecracker() {
    let runner = VmRunner {
        env: VmEnv {
            state_dir: PathBuf::from("/tmp"),
            firecracker_bin: PathBuf::from("/nonexistent/firecracker"),
            kernel_image: PathBuf::from("/tmp"),
            base_rootfs: PathBuf::from("/tmp"),
            ssh_key: PathBuf::from("/tmp"),
            ssh_pubkey: PathBuf::from("/tmp"),
            ssh_wait_tries: 1,
            home: PathBuf::from("/tmp"),
        },
    };
    let err = runner.validate_binaries().unwrap_err();
    assert!(
        err.to_string().contains("not found"),
        "expected 'not found', got: {err}"
    );
}

// ── Concurrent port allocation ────────────────────────────────────────

#[test]
fn concurrent_pick_ssh_port_no_duplicates() {
    // 10 threads pick SSH ports concurrently from the same state_dir.
    // All must get different ports — no duplicates.
    use std::sync::{Arc, Barrier, Mutex};

    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();

    let barrier = Arc::new(Barrier::new(10));
    let results: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let state_dir = state_dir.clone();
            let barrier = Arc::clone(&barrier);
            let results = Arc::clone(&results);
            std::thread::spawn(move || {
                barrier.wait();
                let (port, reservation) = pick_ssh_port(&state_dir).unwrap();
                results.lock().unwrap().push(port);
                // Keep reservation alive until all threads are done
                std::thread::sleep(std::time::Duration::from_millis(100));
                drop(reservation);
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    let ports = results.lock().unwrap();
    assert_eq!(ports.len(), 10, "all threads should have picked a port");

    let unique: std::collections::HashSet<u16> = ports.iter().copied().collect();
    assert_eq!(
        unique.len(),
        10,
        "all 10 ports must be unique, got: {ports:?}"
    );

    for &p in ports.iter() {
        assert!(
            core_rs::guest_net::ssh_host_port_range().contains(&p),
            "port {p} out of range"
        );
    }
}

#[test]
fn port_reservation_drop_removes_lock_file() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();

    let (port, reservation) = pick_ssh_port(state_dir).unwrap();
    let lock_path = state_dir.join(".port-locks").join(format!("{port}.lock"));
    assert!(lock_path.exists(), "lock file should exist while reserved");

    drop(reservation);
    assert!(
        !lock_path.exists(),
        "lock file should be removed after drop"
    );
}

#[test]
fn port_reservation_explicit_release() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();

    let (port, mut reservation) = pick_ssh_port(state_dir).unwrap();
    let lock_path = state_dir.join(".port-locks").join(format!("{port}.lock"));
    assert!(lock_path.exists());

    reservation.release();
    assert!(
        !lock_path.exists(),
        "lock file should be removed after explicit release"
    );

    // Second release is a no-op (no panic)
    reservation.release();
    // Drop is also a no-op after release
    drop(reservation);
}

// ── Error cases ────────────────────────────────────────────────────────

#[tokio::test]
async fn rebuild_fails_without_snapshot_rootfs() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().to_path_buf();

    // Create a fake instance directory with a minimal instance.env
    let inst_dir = state_dir.join("picoclaw-rebuild-test");
    fs::create_dir_all(&inst_dir).unwrap();
    fs::write(
        inst_dir.join("instance.env"),
        "CONTAINER_NAME=picoclaw-rebuild-test\nCUSTOMER_NAME=rebuild-test\n\
             CLAW_TYPE=picoclaw\nPORT=35000\nSSH_PORT=22099\n\
             ROOTFS_PATH=/tmp/r\nAPI_SOCK=/tmp/a\n\
             SLIRP_API_SOCK=/tmp/s\nSERIAL_LOG=/tmp/sl\nSLIRP_LOG=/tmp/ll\n\
             CUSTOMER_DIR=\nCODE_DIR=\nCONFIG_PATH=\nWORKSPACE_PATH=\n\
             FIRECRACKER_PID=\nSLIRP_PID=\n",
    )
    .unwrap();

    let runner = VmRunner {
        env: VmEnv {
            state_dir,
            firecracker_bin: PathBuf::from("/nonexistent/fc"),
            kernel_image: PathBuf::from("/nonexistent/vmlinux"),
            base_rootfs: PathBuf::from("/nonexistent/rootfs.ext4"),
            ssh_key: PathBuf::from("/nonexistent/key"),
            ssh_pubkey: PathBuf::from("/nonexistent/key.pub"),
            ssh_wait_tries: 1,
            home: tmp.path().to_path_buf(), // no snapshots here
        },
    };

    let err = runner.rebuild("picoclaw-rebuild-test").await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no snapshot rootfs"),
        "expected 'no snapshot rootfs', got: {msg}"
    );
}

#[tokio::test]
async fn create_fails_with_unsupported_claw_type() {
    let tmp = TempDir::new().unwrap();
    let runner = VmRunner {
        env: VmEnv {
            state_dir: tmp.path().to_path_buf(),
            firecracker_bin: PathBuf::from("/nonexistent/fc"),
            kernel_image: PathBuf::from("/nonexistent/vmlinux"),
            base_rootfs: PathBuf::from("/nonexistent/rootfs.ext4"),
            ssh_key: PathBuf::from("/nonexistent/key"),
            ssh_pubkey: PathBuf::from("/nonexistent/key.pub"),
            ssh_wait_tries: 1,
            home: PathBuf::from("/tmp"),
        },
    };
    let config = VmConfig {
        container: "unknownclaw-test".to_string(),
        customer: "test".to_string(),
        claw_type: "unknownclaw".to_string(),
        customer_dir: None,
        tools: vec![],
        cpu_cores: None,
        ram_mb: None,
        disk_gb: None,
    };
    let err = runner.create(&config).await.unwrap_err();
    // Could fail on validate_binaries (MissingBinary) OR unsupported type,
    // depending on order — both are acceptable errors for this config.
    let msg = err.to_string();
    assert!(
        msg.contains("not found") || msg.contains("unsupported"),
        "unexpected error: {msg}"
    );
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Helper to write a minimal instance.env for testing.
fn write_fake_instance_env(dir: &Path, container: &str, fc_pid: &str, slirp_pid: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("instance.env"),
        format!(
            "CONTAINER_NAME={container}\nCUSTOMER_NAME=test\nCLAW_TYPE=picoclaw\n\
                 PORT=35000\nSSH_PORT=22099\n\
                 FIRECRACKER_PID={fc_pid}\nSLIRP_PID={slirp_pid}\n"
        ),
    )
    .unwrap();
}

/// Write a full instance.env that round-trips through `InstanceEnv::load()`
/// and `InstanceEnv::save()` without losing fields.
fn write_full_instance_env(dir: &Path, container: &str, fc_pid: &str, slirp_pid: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("instance.env"),
        format!(
            "CONTAINER_NAME={container}\n\
                 CUSTOMER_NAME=test\n\
                 CLAW_TYPE=picoclaw\n\
                 PORT=35000\n\
                 SSH_PORT=22099\n\
                 ROOTFS_PATH={dir}/rootfs.ext4\n\
                 API_SOCK={dir}/firecracker.sock\n\
                 SLIRP_API_SOCK={dir}/slirp-api.sock\n\
                 SERIAL_LOG={dir}/serial.log\n\
                 SLIRP_LOG={dir}/slirp.log\n\
                 CUSTOMER_DIR=\n\
                 CODE_DIR=\n\
                 CONFIG_PATH=\n\
                 WORKSPACE_PATH=\n\
                 FIRECRACKER_PID={fc_pid}\n\
                 SLIRP_PID={slirp_pid}\n",
            dir = dir.display(),
        ),
    )
    .unwrap();
}

/// Helper: create a `VmRunner` with the given state dir and home.
fn test_runner(state_dir: &Path, home: &Path) -> VmRunner {
    VmRunner {
        env: VmEnv {
            state_dir: state_dir.to_path_buf(),
            firecracker_bin: PathBuf::new(),
            kernel_image: PathBuf::new(),
            base_rootfs: PathBuf::new(),
            ssh_key: PathBuf::new(),
            ssh_pubkey: PathBuf::new(),
            ssh_wait_tries: 1,
            home: home.to_path_buf(),
        },
    }
}

#[cfg(target_os = "linux")]
#[test]
fn prepare_rootfs_creates_missing_instance_dir_before_copy() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("firecracker/instances");
    fs::create_dir_all(&state_dir).unwrap();

    let legacy_golden = home.join("firecracker/assets/ubuntu-24.04-picoclaw.ext4");
    fs::create_dir_all(legacy_golden.parent().unwrap()).unwrap();
    let file = fs::File::create(&legacy_golden).unwrap();
    file.set_len(INSTANCE_ROOTFS_BYTES).unwrap();
    drop(file);

    let ssh_pubkey = home.join("id_ed25519.pub");
    let ssh_pubkey_contents = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestPubkey theyos-test\n";
    fs::write(&ssh_pubkey, ssh_pubkey_contents).unwrap();
    let ssh_pubkey_sha256 = {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(ssh_pubkey_contents.as_bytes());
        format!("{hash:x}")
    };
    fs::write(
        format!("{}.pubkey.sha256", legacy_golden.display()),
        format!("{ssh_pubkey_sha256}\n"),
    )
    .unwrap();

    let runner = VmRunner {
        env: VmEnv {
            state_dir: state_dir.clone(),
            firecracker_bin: PathBuf::new(),
            kernel_image: PathBuf::new(),
            base_rootfs: home.join("firecracker/assets/ubuntu-24.04-rootfs-v2.ext4"),
            ssh_key: PathBuf::new(),
            ssh_pubkey,
            ssh_wait_tries: 1,
            home: home.to_path_buf(),
        },
    };

    let instance_dir = state_dir.join("picoclaw-new");
    let inst = InstanceEnv {
        container: "picoclaw-new".into(),
        customer: "test".into(),
        claw_type: "picoclaw".into(),
        host_port: 0,
        ssh_port: 22099,
        firecracker_pid: None,
        slirp_pid: None,
        instance_dir: instance_dir.clone(),
        rootfs_path: instance_dir.join("rootfs.ext4"),
        firecracker_sock: instance_dir.join("firecracker.sock"),
        slirp_api_sock: instance_dir.join("slirp-api.sock"),
        serial_log: instance_dir.join("serial.log"),
        slirp_log: instance_dir.join("slirp.log"),
        customer_dir: String::new(),
    };

    let used_golden = runner
        .prepare_rootfs(&inst, DEFAULT_CREATE_DISK_GB)
        .unwrap();
    assert!(used_golden, "legacy golden should be used");
    assert!(instance_dir.is_dir(), "instance dir should be created");
    assert!(inst.rootfs_path.is_file(), "rootfs should be copied");
}

// ── Sweep orphans: warm pool VMs ──────────────────────────────────────

#[test]
fn sweep_orphans_cleans_warm_pool_dirs() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();

    // Create a warm pool directory with a fake instance.env.
    // Use PID 0 so it's never "running" (but for _warm-* we clean regardless).
    let warm_dir = state_dir.join("_warm-picoclaw-0");
    write_fake_instance_env(&warm_dir, "_warm-picoclaw-0", "", "");

    // Create a regular instance with a dead PID to confirm it's also cleaned
    let orphan_dir = state_dir.join("picoclaw-orphan");
    write_fake_instance_env(&orphan_dir, "picoclaw-orphan", "999999999", "");

    let runner = VmRunner {
        env: VmEnv {
            state_dir: state_dir.to_path_buf(),
            firecracker_bin: PathBuf::new(),
            kernel_image: PathBuf::new(),
            base_rootfs: PathBuf::new(),
            ssh_key: PathBuf::new(),
            ssh_pubkey: PathBuf::new(),
            ssh_wait_tries: 1,
            home: tmp.path().to_path_buf(),
        },
    };

    let report = runner.sweep_orphans();
    // Both should be cleaned: the warm pool dir (always) and the orphan (dead PID)
    assert!(
        report.instances_cleaned >= 2,
        "expected >=2, got {report:?}"
    );
    assert!(!warm_dir.exists(), "_warm- dir should be removed");
    // Non-warm orphan dir is preserved so restart() can load instance.env after reboot
    assert!(
        orphan_dir.exists(),
        "orphan state dir should be preserved for restart"
    );

    // cleaned_containers should include the orphan but NOT warm pool VMs
    assert!(
        report
            .cleaned_containers
            .contains(&"picoclaw-orphan".to_string()),
        "expected picoclaw-orphan in cleaned_containers: {:?}",
        report.cleaned_containers
    );
    assert!(
        !report
            .cleaned_containers
            .iter()
            .any(|c| c.starts_with("_warm-")),
        "warm pool VMs should not be in cleaned_containers: {:?}",
        report.cleaned_containers
    );
}

#[test]
fn sweep_orphans_tears_down_quarantined_warm_dir_before_removal() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let warm_dir = state_dir.join("_warm-picoclaw-0");
    write_full_instance_env(&warm_dir, "_warm-picoclaw-0", "", "");
    fs::write(
        warm_dir.join(crate::instance_env::HOSTFWD_UNCERTAIN_MARKER),
        "ambiguous hostfwd response\n",
    )
    .unwrap();

    let runner = test_runner(state_dir, tmp.path());
    let report = runner.sweep_orphans();

    assert_eq!(report.instances_cleaned, 1);
    assert!(
        !warm_dir.exists(),
        "a quarantined warm dir may be removed only after verified teardown"
    );
}

#[test]
fn sweep_orphans_preserves_invalid_warm_state() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let warm_dir = state_dir.join("_warm-picoclaw-0");
    fs::create_dir_all(&warm_dir).unwrap();
    fs::write(
        warm_dir.join("instance.env"),
        "CONTAINER_NAME=_warm-picoclaw-0\n\
             CUSTOMER_NAME=_warm-picoclaw-0\n\
             CLAW_TYPE=picoclaw\n\
             PORT=0\n\
             SSH_PORT=22002\n\
             FIRECRACKER_PID=not-a-pid\n\
             SLIRP_PID=\n",
    )
    .unwrap();

    let runner = test_runner(state_dir, tmp.path());
    let report = runner.sweep_orphans();

    assert_eq!(report.instances_cleaned, 0);
    assert!(
        warm_dir.exists(),
        "invalid warm state must be preserved for recovery"
    );
    assert!(
        warm_dir
            .join(crate::instance_env::HOSTFWD_UNCERTAIN_MARKER)
            .exists(),
        "invalid warm state must be quarantined"
    );
}

#[test]
fn sweep_orphans_preserves_instance_env_for_dead_instances() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();

    let orphan_dir = state_dir.join("picoclaw-test");
    write_fake_instance_env(&orphan_dir, "picoclaw-test", "999999999", "");
    fs::write(orphan_dir.join("rootfs.ext4"), b"fake rootfs").unwrap();

    let runner = VmRunner {
        env: VmEnv {
            state_dir: state_dir.to_path_buf(),
            firecracker_bin: PathBuf::new(),
            kernel_image: PathBuf::new(),
            base_rootfs: PathBuf::new(),
            ssh_key: PathBuf::new(),
            ssh_pubkey: PathBuf::new(),
            ssh_wait_tries: 1,
            home: tmp.path().to_path_buf(),
        },
    };

    let report = runner.sweep_orphans();

    assert_eq!(report.instances_cleaned, 1);
    assert!(
        report
            .cleaned_containers
            .contains(&"picoclaw-test".to_string()),
        "picoclaw-test must be in cleaned_containers"
    );
    // Directory and instance.env must survive so restart() can reload state.
    assert!(
        orphan_dir.exists(),
        "state dir must be preserved so restart() works"
    );
    assert!(
        orphan_dir.join("instance.env").exists(),
        "instance.env must be preserved"
    );
    assert!(
        orphan_dir.join("rootfs.ext4").exists(),
        "rootfs must be preserved"
    );
}

#[test]
fn sweep_orphans_skips_alive_non_warm_instances() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();

    // Use PID 1 (init) — always alive on Linux
    let alive_dir = state_dir.join("picoclaw-alive");
    write_fake_instance_env(&alive_dir, "picoclaw-alive", "1", "");

    let runner = VmRunner {
        env: VmEnv {
            state_dir: state_dir.to_path_buf(),
            firecracker_bin: PathBuf::new(),
            kernel_image: PathBuf::new(),
            base_rootfs: PathBuf::new(),
            ssh_key: PathBuf::new(),
            ssh_pubkey: PathBuf::new(),
            ssh_wait_tries: 1,
            home: tmp.path().to_path_buf(),
        },
    };

    let report = runner.sweep_orphans();
    assert_eq!(
        report.instances_cleaned, 0,
        "alive instance should not be cleaned"
    );
    assert!(alive_dir.exists(), "alive instance dir should still exist");
}

// ── stop / restart / rebuild / delete / sweep lifecycle ───────────────

#[test]
fn stop_vm_with_dead_pids_clears_them() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let inst_dir = state_dir.join("picoclaw-deadpid");
    write_full_instance_env(&inst_dir, "picoclaw-deadpid", "999999999", "999999998");

    let runner = test_runner(state_dir, tmp.path());
    runner.stop("picoclaw-deadpid").unwrap();

    // Reload and verify PIDs are cleared on disk
    let reloaded = InstanceEnv::load(&inst_dir).unwrap();
    assert_eq!(reloaded.firecracker_pid, None, "FC PID should be cleared");
    assert_eq!(reloaded.slirp_pid, None, "slirp PID should be cleared");
}

#[test]
fn stop_vm_with_empty_pids_is_noop() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let inst_dir = state_dir.join("picoclaw-nopid");
    write_full_instance_env(&inst_dir, "picoclaw-nopid", "", "");
    fs::write(inst_dir.join("rootfs.ext4"), b"fake rootfs").unwrap();

    let runner = test_runner(state_dir, tmp.path());
    runner.stop("picoclaw-nopid").unwrap();

    // File and rootfs should still exist — no changes needed
    assert!(
        inst_dir.join("instance.env").exists(),
        "instance.env must survive"
    );
    assert!(inst_dir.join("rootfs.ext4").exists(), "rootfs must survive");
}

#[test]
fn uncertain_teardown_persists_marker_before_stop() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let inst_dir = state_dir.join("picoclaw-uncertain-order");
    write_full_instance_env(&inst_dir, "picoclaw-uncertain-order", "", "");

    let inst = InstanceEnv::load_unchecked(&inst_dir).unwrap();
    VmRunner::quarantine_before_teardown(&inst, "ambiguous hostfwd response; teardown pending")
        .unwrap();

    assert!(
        inst_dir
            .join(crate::instance_env::HOSTFWD_UNCERTAIN_MARKER)
            .exists(),
        "the no-reuse marker must exist before teardown begins"
    );
    assert!(
        matches!(
            InstanceEnv::load(&inst_dir),
            Err(VmError::HostfwdUncertain(_))
        ),
        "normal lifecycle loads must refuse the quarantined instance"
    );
}

#[test]
fn stop_vm_keeps_quarantine_when_stopped_state_save_fails() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let inst_dir = state_dir.join("picoclaw-save-failure");
    write_full_instance_env(&inst_dir, "picoclaw-save-failure", "", "");

    let runner = test_runner(state_dir, tmp.path());
    let mut inst = InstanceEnv::load_unchecked(&inst_dir).unwrap();
    VmRunner::quarantine_before_teardown(&inst, "ambiguous hostfwd response; teardown pending")
        .unwrap();

    fs::remove_file(inst_dir.join("instance.env")).unwrap();
    fs::create_dir(inst_dir.join("instance.env")).unwrap();

    assert!(
        runner.stop_vm(&mut inst).is_err(),
        "state persistence failure must be surfaced"
    );
    assert!(
        inst_dir
            .join(crate::instance_env::HOSTFWD_UNCERTAIN_MARKER)
            .exists(),
        "quarantine must remain when durable stopped state was not saved"
    );
}

#[tokio::test]
async fn restart_fails_without_instance_dir() {
    let tmp = TempDir::new().unwrap();
    let runner = test_runner(tmp.path(), tmp.path());

    let err = runner.restart("ghost").await.unwrap_err();
    assert!(
        matches!(err, VmError::InstanceNotFound(_)),
        "expected InstanceNotFound, got: {err}"
    );
}

#[tokio::test]
async fn rebuild_fails_without_instance_dir() {
    let tmp = TempDir::new().unwrap();
    let runner = test_runner(tmp.path(), tmp.path());

    let err = runner.rebuild("ghost").await.unwrap_err();
    assert!(
        matches!(err, VmError::InstanceNotFound(_)),
        "expected InstanceNotFound, got: {err}"
    );
}

#[test]
fn delete_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let inst_dir = state_dir.join("picoclaw-delme");
    write_full_instance_env(&inst_dir, "picoclaw-delme", "", "");

    let runner = test_runner(state_dir, tmp.path());

    // First delete removes the directory
    runner.delete("picoclaw-delme").unwrap();
    assert!(
        !inst_dir.exists(),
        "directory should be gone after first delete"
    );

    // Second delete is idempotent — no error
    runner.delete("picoclaw-delme").unwrap();
}

#[test]
fn sweep_then_restart_loads_instance_env() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let inst_dir = state_dir.join("picoclaw-sweep-restart");
    write_full_instance_env(
        &inst_dir,
        "picoclaw-sweep-restart",
        "999999999",
        "999999998",
    );
    fs::write(inst_dir.join("rootfs.ext4"), b"fake rootfs").unwrap();

    let runner = test_runner(state_dir, tmp.path());

    let report = runner.sweep_orphans();
    assert_eq!(
        report.instances_cleaned, 1,
        "sweep should clean 1 orphan: {report:?}"
    );

    // instance.env must survive sweep so restart can reload it
    assert!(
        inst_dir.join("instance.env").exists(),
        "instance.env must survive sweep"
    );

    // InstanceEnv::load must succeed (this is what restart() calls first)
    let env = InstanceEnv::load(&inst_dir).unwrap();
    assert_eq!(env.container, "picoclaw-sweep-restart");
    // PIDs should be cleared after sweep
    assert_eq!(
        env.firecracker_pid, None,
        "FC PID should be cleared by sweep"
    );
    assert_eq!(env.slirp_pid, None, "slirp PID should be cleared by sweep");
}

#[tokio::test]
async fn sweep_then_rebuild_loads_instance_env() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let inst_dir = state_dir.join("picoclaw-sweep-rebuild");
    write_full_instance_env(
        &inst_dir,
        "picoclaw-sweep-rebuild",
        "999999999",
        "999999998",
    );
    fs::write(inst_dir.join("rootfs.ext4"), b"fake rootfs").unwrap();

    let runner = test_runner(state_dir, tmp.path());

    let report = runner.sweep_orphans();
    assert_eq!(
        report.instances_cleaned, 1,
        "sweep should clean 1: {report:?}"
    );

    // rebuild() must reach the snapshot check, NOT fail with InstanceNotFound
    let err = runner.rebuild("picoclaw-sweep-rebuild").await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no snapshot rootfs"),
        "expected 'no snapshot rootfs' (not InstanceNotFound), got: {msg}"
    );
}

#[test]
fn sweep_clears_pids_in_instance_env() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path();
    let inst_dir = state_dir.join("picoclaw-sweep-pids");
    write_full_instance_env(&inst_dir, "picoclaw-sweep-pids", "999999999", "999999998");

    let runner = test_runner(state_dir, tmp.path());
    let report = runner.sweep_orphans();
    assert_eq!(report.instances_cleaned, 1);

    let reloaded = InstanceEnv::load(&inst_dir).unwrap();
    assert_eq!(
        reloaded.firecracker_pid, None,
        "FC PID must be None after sweep"
    );
    assert_eq!(
        reloaded.slirp_pid, None,
        "slirp PID must be None after sweep"
    );
}

// ── Rootfs expansion ──────────────────────────────────────────────────

#[test]
fn instance_rootfs_bytes_is_10_gib() {
    assert_eq!(
        INSTANCE_ROOTFS_BYTES,
        10 * 1024 * 1024 * 1024,
        "INSTANCE_ROOTFS_BYTES must be 10 GiB",
    );
}

#[test]
fn expand_rootfs_skips_when_already_large_enough() {
    let tmp = TempDir::new().unwrap();
    let rootfs = tmp.path().join("rootfs.ext4");

    // Create a file exactly at the target size (just the metadata,
    // no real ext4 — we only test the skip logic).
    let f = fs::File::create(&rootfs).unwrap();
    f.set_len(INSTANCE_ROOTFS_BYTES).unwrap();
    drop(f);

    // Should be a no-op (no resize2fs needed).
    let result = VmRunner::expand_rootfs(&rootfs, INSTANCE_ROOTFS_BYTES);
    assert!(
        result.is_ok(),
        "expand_rootfs should succeed for large file"
    );
    assert_eq!(fs::metadata(&rootfs).unwrap().len(), INSTANCE_ROOTFS_BYTES);
}

#[test]
fn expand_rootfs_extends_small_file() {
    let tmp = TempDir::new().unwrap();
    let rootfs = tmp.path().join("rootfs.ext4");

    // Create a small file (not a real ext4 fs, so resize2fs will fail,
    // but set_len should succeed).
    fs::write(&rootfs, b"tiny").unwrap();
    let before = fs::metadata(&rootfs).unwrap().len();
    assert!(before < INSTANCE_ROOTFS_BYTES);

    // expand_rootfs will set_len to 10G, then resize2fs will fail
    // (not a real ext4), then e2fsck + retry will also fail, returning
    // an error. But the file should already be extended to 10G.
    let result = VmRunner::expand_rootfs(&rootfs, INSTANCE_ROOTFS_BYTES);
    assert!(result.is_err(), "resize2fs should fail on non-ext4 file");

    // The file was still extended before resize2fs was attempted.
    let after = fs::metadata(&rootfs).unwrap().len();
    assert_eq!(after, INSTANCE_ROOTFS_BYTES);
}

#[test]
fn expand_rootfs_fails_on_nonexistent_file() {
    let result = VmRunner::expand_rootfs(
        Path::new("/tmp/nonexistent_rootfs_test.ext4"),
        INSTANCE_ROOTFS_BYTES,
    );
    assert!(result.is_err());
}
