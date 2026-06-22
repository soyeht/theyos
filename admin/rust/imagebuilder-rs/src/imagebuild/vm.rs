//! Firecracker + slirp4netns VM lifecycle for golden image builds.
//!
//! Responsible for:
//! - Booting a Firecracker microVM using unprivileged networking (slirp4netns).
//! - Configuring the VM via the Firecracker REST API (unix socket).
//! - Setting up SSH port-forwarding via the slirp control socket.
//! - Graceful shutdown and deterministic cleanup (RAII via Drop).

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::error::{BuildError, BuildPhase, BuildResult};
// ── VmConfig ─────────────────────────────────────────────────────────────────

/// Configuration for the Firecracker build VM.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Path to Firecracker binary.
    pub firecracker_bin: PathBuf,
    /// Path to vmlinux kernel image.
    pub kernel_image: PathBuf,
    /// Path to the rootfs to use (mutable copy created by caller).
    pub rootfs_path: PathBuf,
    /// Directory for build sockets/logs.
    pub build_dir: PathBuf,
    /// Path to slirp4netns binary.
    pub slirp_bin: PathBuf,
    /// vCPU count (default 2).
    pub vcpu_count: u32,
    /// Memory in MiB (default 2048).
    pub mem_mib: u32,
    /// Timeout for the API socket to appear.
    pub api_socket_timeout: Duration,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            firecracker_bin: PathBuf::new(),
            kernel_image: PathBuf::new(),
            rootfs_path: PathBuf::new(),
            build_dir: PathBuf::new(),
            slirp_bin: PathBuf::new(),
            vcpu_count: 2,
            mem_mib: 2048,
            api_socket_timeout: Duration::from_secs(20),
        }
    }
}

// ── RunningVm ─────────────────────────────────────────────────────────────────

/// A running Firecracker build VM. Cleanup is triggered on Drop.
pub struct RunningVm {
    pub config: VmConfig,
    pub claw: String,
    fc_pid: Option<u32>,
    slirp_pid: Option<u32>,
    pub api_sock: PathBuf,
    pub slirp_api_sock: PathBuf,
    /// Host-side port forwarded to the VM's SSH port (22).
    /// Allocated dynamically so parallel verify runs don't conflict.
    pub ssh_port: u16,
}

impl RunningVm {
    /// Clean up all VM resources (sockets, processes).
    /// Called automatically on Drop; safe to call manually first.
    pub fn cleanup(&mut self) {
        if let Some(pid) = self.fc_pid.take() {
            kill_process(pid, true);
        }
        if let Some(pid) = self.slirp_pid.take() {
            kill_process(pid, false);
        }
        for path in &[&self.api_sock, &self.slirp_api_sock] {
            fs::remove_file(path).ok();
        }
        // Remove temp rootfs copy
        let build_rootfs = self
            .config
            .build_dir
            .join(format!("rootfs-{}.ext4", self.claw));
        if build_rootfs.exists() {
            fs::remove_file(&build_rootfs).ok();
        }
    }

    /// Graceful shutdown: best-effort poweroff via process kill → wait → force kill.
    /// SSH-based poweroff removed; we rely on process signals for the build VM.
    pub fn shutdown(&mut self) {
        log_phase(
            &self.claw,
            BuildPhase::Shutdown,
            "graceful shutdown via process signals",
        );

        // Send SIGTERM to the firecracker process to trigger graceful shutdown.
        if let Some(pid) = self.fc_pid {
            core_rs::os::kill_pid(pid);
            // Wait up to 15s for FC to exit
            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline {
                if !core_rs::os::is_pid_running(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        self.cleanup();
    }
}

impl Drop for RunningVm {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ── Boot ──────────────────────────────────────────────────────────────────────

/// Boot a Firecracker microVM for golden image building.
///
/// Returns a `RunningVm` handle that cleans up on Drop.
#[allow(clippy::too_many_lines)]
pub async fn boot_build_vm(config: VmConfig, claw: &str) -> BuildResult<RunningVm> {
    fs::create_dir_all(&config.build_dir)
        .map_err(|e| BuildError::new(BuildPhase::BootVm, claw, format!("create build_dir: {e}")))?;

    // Ensure build dir is root-owned so Firecracker inside
    // `unshare --user --map-root-user` can bind its API socket.
    // --map-root-user maps external uid 0 → internal uid 0; directories
    // owned by other UIDs (e.g. uid 1000 from prior non-sudo runs) are
    // inaccessible inside the user namespace.
    let _ = Command::new("chown")
        .args(["root:root", &config.build_dir.to_string_lossy()])
        .status();

    let api_sock = config.build_dir.join("firecracker.sock");
    let slirp_api_sock = config.build_dir.join("slirp-api.sock");
    let serial_log = config.build_dir.join("serial.log");
    let slirp_log = config.build_dir.join("slirp.log");

    // Remove stale sockets
    for p in &[&api_sock, &slirp_api_sock] {
        fs::remove_file(p).ok();
    }

    log_phase(claw, BuildPhase::BootVm, "spawning Firecracker");

    // Ensure all parent directories of the Firecracker binary are traversable
    // inside the `unshare --user --map-root-user` namespace.  The user namespace
    // only maps uid 0; directories owned by other UIDs (e.g. the service user's
    // home dir with mode 700) become inaccessible without the o+x bit.
    if let Some(mut dir) = config.firecracker_bin.parent() {
        while let Some(parent) = dir.parent() {
            if let Some(s) = dir.to_str() {
                let _ = Command::new("chmod").args(["a+rx", s]).status();
            }
            dir = parent;
            if dir.to_str() == Some("/") {
                break;
            }
        }
    }

    // Build the inner shell command that runs inside `unshare`.
    // The shared guest-net helper owns the dual-TAP identity and iptables
    // rules; this builder owns process orchestration.
    // P28.4: uses /bin/sh (POSIX) instead of bash; set -eu (no pipefail).
    let fc_bin = config.firecracker_bin.to_string_lossy().to_string();
    let api_sock_str = api_sock.to_string_lossy().to_string();
    let network_setup = core_rs::guest_net::firecracker_dual_tap_setup_script();
    let inner_cmd = format!(
        r"set -eu
{network_setup}
'{fc_bin}' --api-sock '{api_sock_str}' &
wait $!",
    );

    let serial_fd = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&serial_log)
        .map_err(|e| BuildError::new(BuildPhase::BootVm, claw, format!("open serial log: {e}")))?;

    let fc_child: Child = Command::new("setsid")
        .args([
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            "--mount-proc",
            "--fork",
            "--pid",
            "/bin/sh",
            "-c",
            &inner_cmd,
        ])
        .stdout(serial_fd.try_clone().map_err(|e| {
            BuildError::new(BuildPhase::BootVm, claw, format!("clone serial fd: {e}"))
        })?)
        .stderr(serial_fd)
        .spawn()
        .map_err(|e| {
            BuildError::new(
                BuildPhase::BootVm,
                claw,
                format!("spawn unshare/firecracker: {e}"),
            )
        })?;
    let fc_pid = fc_child.id();

    // Enable IP forwarding in the namespace (required for iptables FORWARD/MASQUERADE)
    vmrunner_rs::network::enable_ip_forward(fc_pid).ok();

    // Wait for API socket
    log_phase(claw, BuildPhase::BootVm, "waiting for API socket...");
    wait_for_path(&api_sock, config.api_socket_timeout)
        .await
        .map_err(|()| BuildError::new(BuildPhase::BootVm, claw, "API socket did not appear"))?;

    // Configure VM via Firecracker API (tap1 was created by unshare script)
    configure_vm(&api_sock, &config, claw).await?;

    // Start the VM — FC opens tap1 here
    let fc = vmrunner_rs::firecracker_api::FirecrackerClient::new(api_sock.clone());
    fc.start_instance().await.map_err(|e| {
        BuildError::new(BuildPhase::BootVm, claw, format!("FC start_instance: {e}"))
    })?;

    // Spawn slirp4netns AFTER FC — creates tap0 with --configure.
    // Dual-TAP: slirp owns tap0, iptables forwards between tap0↔tap1.
    log_phase(claw, BuildPhase::BootVm, "spawning slirp4netns");
    let slirp_fd = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&slirp_log)
        .map_err(|e| BuildError::new(BuildPhase::BootVm, claw, format!("open slirp log: {e}")))?;

    let slirp_child: Child = Command::new("setsid")
        .arg(&config.slirp_bin)
        .args([
            "--configure",
            "--mtu=1500",
            "--disable-host-loopback",
            "--api-socket",
        ])
        .arg(&slirp_api_sock)
        .arg(fc_pid.to_string())
        .arg(core_rs::guest_net::SLIRP_TAP_NAME)
        .stdout(slirp_fd.try_clone().map_err(|e| {
            BuildError::new(BuildPhase::BootVm, claw, format!("clone slirp fd: {e}"))
        })?)
        .stderr(slirp_fd)
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| {
            BuildError::new(BuildPhase::BootVm, claw, format!("spawn slirp4netns: {e}"))
        })?;
    let slirp_pid = slirp_child.id();

    wait_for_path(&slirp_api_sock, Duration::from_secs(15))
        .await
        .map_err(|()| {
            BuildError::new(BuildPhase::BootVm, claw, "slirp API socket did not appear")
        })?;

    // Allocate a free host port for SSH forwarding. Dynamic allocation lets
    // multiple verify runs execute concurrently without conflicting on a
    // single hardcoded port.
    let ssh_port = allocate_free_port(claw)?;

    // Set up SSH port forwarding via slirp control socket
    setup_ssh_hostfwd(&slirp_api_sock, ssh_port, claw)?;

    let vm = RunningVm {
        config,
        claw: claw.to_string(),
        fc_pid: Some(fc_pid),
        slirp_pid: Some(slirp_pid),
        api_sock,
        slirp_api_sock,
        ssh_port,
    };

    Ok(vm)
}

// ── VM configuration via Firecracker API ─────────────────────────────────────

async fn configure_vm(api_sock: &Path, config: &VmConfig, claw: &str) -> BuildResult<()> {
    let fc = vmrunner_rs::firecracker_api::FirecrackerClient::new(api_sock.to_path_buf());
    let map_err = |e: vmrunner_rs::error::VmError| {
        BuildError::new(BuildPhase::BootVm, claw, format!("FC API: {e}"))
    };

    // Machine config
    fc.set_machine_config(config.vcpu_count, config.mem_mib)
        .await
        .map_err(&map_err)?;

    // Boot source uses the shared guest-net Firecracker identity.
    let boot_args = core_rs::guest_net::firecracker_boot_args();
    fc.set_boot_source(&config.kernel_image.to_string_lossy(), &boot_args)
        .await
        .map_err(&map_err)?;

    // Root drive
    fc.set_rootfs(&config.rootfs_path.to_string_lossy(), false)
        .await
        .map_err(&map_err)?;

    // Network interface uses the shared Firecracker guest MAC.
    fc.set_network_interface(
        core_rs::guest_net::FIRECRACKER_GUEST_IFACE,
        core_rs::guest_net::FIRECRACKER_TAP_NAME,
        core_rs::guest_net::FIRECRACKER_GUEST_MAC,
    )
    .await
    .map_err(&map_err)?;

    Ok(())
}

// ── slirp hostfwd ─────────────────────────────────────────────────────────────

/// Pick a free TCP port on localhost. Binds to `127.0.0.1:0`, reads the
/// OS-assigned port, then drops the listener so slirp4netns can bind it.
fn allocate_free_port(claw: &str) -> BuildResult<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| {
        BuildError::new(BuildPhase::BootVm, claw, format!("allocate SSH port: {e}"))
    })?;
    let port = listener
        .local_addr()
        .map_err(|e| BuildError::new(BuildPhase::BootVm, claw, format!("read SSH port: {e}")))?
        .port();
    Ok(port)
}

fn setup_ssh_hostfwd(slirp_api_sock: &Path, host_port: u16, claw: &str) -> BuildResult<()> {
    // Send JSON command to slirp control socket via nc
    let cmd = core_rs::guest_net::slirp_add_hostfwd_payload(host_port, 22);

    let out = Command::new("nc")
        .args(["-N", "-U", slirp_api_sock.to_str().unwrap_or("")])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(cmd.as_bytes());
            }
            child.wait_with_output()
        })
        .map_err(|e| {
            BuildError::new(
                BuildPhase::BootVm,
                claw,
                format!("slirp hostfwd via nc: {e}"),
            )
        })?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(
            BuildError::new(BuildPhase::BootVm, claw, "slirp hostfwd command failed")
                .with_stderr(stderr),
        );
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Wait for a path to exist up to `timeout`.
async fn wait_for_path(path: &Path, timeout: Duration) -> Result<(), ()> {
    core_rs::poll::poll_until_exists_async(path, timeout, Duration::from_millis(200))
        .await
        .map_err(|_elapsed| ())
}

/// Kill a process by PID. If `do_kill_pgrp`, also sends signals to the process group.
fn kill_process(pid: u32, do_kill_pgrp: bool) {
    if !core_rs::os::is_pid_running(pid) {
        return;
    }
    if do_kill_pgrp {
        core_rs::os::kill_pgrp(pid);
        std::thread::sleep(Duration::from_millis(500));
        if core_rs::os::is_pid_running(pid) {
            core_rs::os::kill_pgrp_force(pid);
        }
    }
    core_rs::os::kill_pid(pid);
    std::thread::sleep(Duration::from_millis(200));
    if core_rs::os::is_pid_running(pid) {
        core_rs::os::kill_pid_force(pid);
    }
}

#[allow(clippy::needless_pass_by_value)]
fn log_phase(claw: &str, phase: BuildPhase, msg: &str) {
    eprintln!("[golden][{claw}] phase={phase} -- {msg}");
}
