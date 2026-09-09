//! vmrunner-rs — Rust reimplementation of `fc-agent-runtime.sh` and `firecracker.go`.
//!
// Lint suppressions — see NOTE comments for rationale.
// VmError is large by design (rich diagnostic context).
#![allow(clippy::result_large_err)]
// start_vm / fill_pool_slot_impl / claim_from_pool manage
// Firecracker VM lifecycle in a single coherent function body.
#![allow(clippy::too_many_lines)]
// All unsafe blocks use pre_exec() for async-signal-safe setsid(2). The setsid(2)
// syscall is required to create a new session so spawned VMs survive parent exit.
// Each unsafe block has a // SAFETY: comment immediately above it.
#![allow(unsafe_code)]
//!
//! # Architecture
//!
//! ```text
//! lib.rs          — VmRunner, VmConfig, VmEnv (public API)
//! cid.rs          — compute_guest_cid, posix_cksum, pick_ssh_port, SSH port helpers
//! network.rs      — slirp_add_hostfwd, OS helpers (is_pid_running, kill_*, resolve_*, home_dir, claw_data_base_dir)
//! error.rs        — unified VmError enum
//! instance_env.rs — parse/write instance.env state files
//! firecracker_api.rs — Firecracker REST API client (Unix socket)
//! ssh_client.rs   — SSH/SCP helpers wrapping ssh2
//! installer.rs    — ClawInstaller trait + per-type implementations
//! bin/vmrunner_ipc.rs — JSON-RPC IPC binary
//! ```
//!
//! # CID computation
//!
//! The bash script computes the guest CID as:
//! ```bash
//! crc="$(printf '%s' "${container}" | cksum | awk '{print $1}')"
//! cid=$(( (crc % 200000) + 3 ))
//! ```
//!
//! `cksum` produces a CRC-32 compatible with POSIX (see [`cid::compute_guest_cid`]).
//!
//! # SSH port selection
//!
//! Scans existing `instance.env` files for taken SSH ports, then probes each
//! candidate in the configured host SSH port range with a TCP connect; the
//! first free one wins.

pub mod cid;
pub mod create_guard;
pub mod error;
pub mod firecracker_api;
pub mod installer;
pub mod installer_plan;
pub mod instance_env;
pub mod network;
pub mod ssh_client;
pub mod timing;
pub mod tools_plan;
pub mod warm_pool;

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use crate::create_guard::{ClaimGuard, CreateGuard, PoolFillGuard};
use crate::error::VmError;
use crate::firecracker_api::FirecrackerClient;
use crate::installer::{InstallerConfig, get_installer};
use crate::instance_env::{InstanceEnv, persist_hostfwd_uncertain_marker};
use crate::network::{
    claw_data_base_dir, home_dir, is_pid_running, kill_pgrp, kill_pgrp_force, kill_pid,
    kill_pid_force, reap_pid, resolve_slirp4netns, slirp_add_hostfwd, slirp_list_hostfwd,
    slirp_remove_hostfwd_verified, slirp_wait_ready, which_systemctl,
};
use crate::ssh_client::{SshActions, SshSession};
use vmrunner_common_rs::{
    DEFAULT_CREATE_CPU_CORES, DEFAULT_CREATE_DISK_GB, DEFAULT_CREATE_RAM_MB, VmCreateResourceSpec,
};

// ── Constants ──────────────────────────────────────────────────────────────

/// Target rootfs size for instance VMs (10 GiB).
///
/// Must match `GOLDEN_ROOTFS_BYTES` in `imagebuilder-rs`. Firecracker
/// locks the virtio-block device size at snapshot time, so the guest can
/// never see more space than the golden image provides. The host-side
/// expand is kept as a safety net for non-snapshot (full kernel boot)
/// instances where the block device size IS determined by the backing file.
///
/// The expansion uses `File::set_len` (sparse) followed by `resize2fs`, so
/// the file only consumes real disk blocks for data actually written.
const INSTANCE_ROOTFS_BYTES: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB

// ── Public types ───────────────────────────────────────────────────────────

/// Result of a successful VM creation, including timing information.
#[derive(Debug, Clone)]
pub struct VmCreateResult {
    /// Whether a golden image was used (skips install)
    pub golden_image_used: bool,
    /// Whether the install step was skipped (binary already present)
    pub install_skipped: bool,
    /// Timing information for each phase
    pub phases: Vec<(String, std::time::Duration)>,
    /// Total time elapsed
    pub total_duration: std::time::Duration,
}

/// Configuration for creating a new VM instance.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Full container name, e.g. `picoclaw-myinst`
    pub container: String,
    /// Customer/instance slug, e.g. `myinst`
    pub customer: String,
    /// Claw type, e.g. `picoclaw`
    pub claw_type: String,
    /// Optional customer data directory
    pub customer_dir: Option<PathBuf>,
    /// Optional AI coding tools to install (e.g. `["codex", "claude-code", "opencode"]`).
    /// Empty vec means no tools; `None`-equivalent is handled at the API layer.
    #[allow(clippy::struct_field_names)]
    pub tools: Vec<String>,
    /// CPU cores (1-4). `None` uses the shared vmrunner Create default.
    pub cpu_cores: Option<u32>,
    /// RAM in MB (512-8192). `None` uses the shared vmrunner Create default.
    pub ram_mb: Option<u32>,
    /// Disk size in GB (5-50). `None` uses the shared vmrunner Create default.
    pub disk_gb: Option<u32>,
}

/// Environment configuration for the VM runner (read from env vars or provided directly).
#[derive(Debug, Clone)]
pub struct VmEnv {
    /// `FIRECRACKER_STATE_DIR`
    pub state_dir: PathBuf,
    /// `FIRECRACKER_BIN`
    pub firecracker_bin: PathBuf,
    /// `FIRECRACKER_KERNEL_IMAGE`
    pub kernel_image: PathBuf,
    /// `FIRECRACKER_BASE_ROOTFS`
    pub base_rootfs: PathBuf,
    /// `FIRECRACKER_SSH_KEY` (private key for root login)
    pub ssh_key: PathBuf,
    /// `FIRECRACKER_SSH_PUBKEY`
    pub ssh_pubkey: PathBuf,
    /// `FIRECRACKER_SSH_WAIT_TRIES` (default 20)
    pub ssh_wait_tries: u32,
    /// Cached HOME directory (computed once, avoids repeated `env::var` calls)
    pub home: PathBuf,
}

impl VmEnv {
    /// Build a `VmEnv` from environment variables, with the same defaults as
    /// `fc-agent-runtime.sh`.
    ///
    /// # Errors
    ///
    /// This function is infallible in practice (all env vars have defaults),
    /// but returns `Result` for forward compatibility.
    pub fn from_env() -> Result<Self, VmError> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());

        let state_dir = env_path("FIRECRACKER_STATE_DIR")
            .unwrap_or_else(|| PathBuf::from(format!("{home}/firecracker/instances")));

        let firecracker_bin = env_path("FIRECRACKER_BIN")
            .unwrap_or_else(|| PathBuf::from(format!("{home}/firecracker/bin/firecracker")));

        let kernel_image = env_path("FIRECRACKER_KERNEL_IMAGE").unwrap_or_else(|| {
            PathBuf::from(format!(
                "{home}/firecracker/assets/{}",
                core_rs::guest_net::KERNEL_FILENAME
            ))
        });

        // Prefer v2 rootfs, fall back to v1
        let base_rootfs = env_path("FIRECRACKER_BASE_ROOTFS").unwrap_or_else(|| {
            let v2 = PathBuf::from(format!(
                "{home}/firecracker/assets/ubuntu-24.04-rootfs-v2.ext4"
            ));
            if v2.exists() {
                v2
            } else {
                PathBuf::from(format!(
                    "{home}/firecracker/assets/ubuntu-24.04-rootfs.ext4"
                ))
            }
        });

        let ssh_key = env_path("FIRECRACKER_SSH_KEY").unwrap_or_else(|| {
            PathBuf::from(format!(
                "{home}/firecracker/assets/ubuntu-24.04-root.id_rsa"
            ))
        });

        let ssh_pubkey = env_path("FIRECRACKER_SSH_PUBKEY").unwrap_or_else(|| {
            PathBuf::from(format!(
                "{home}/firecracker/assets/ubuntu-24.04-root.id_rsa.pub"
            ))
        });

        let ssh_wait_tries = std::env::var("FIRECRACKER_SSH_WAIT_TRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(40);

        Ok(VmEnv {
            state_dir,
            firecracker_bin,
            kernel_image,
            base_rootfs,
            ssh_key,
            ssh_pubkey,
            ssh_wait_tries,
            home: PathBuf::from(home),
        })
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    core_rs::env::env_path(key)
}

fn can_prepare_snapshot_bind_target(path: &Path) -> bool {
    if path.exists() {
        return fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .is_ok();
    }

    let Some(parent) = path.parent() else {
        return false;
    };

    if !parent.exists() && fs::create_dir_all(parent).is_err() {
        return false;
    }

    let probe = parent.join(format!(".vmrunner-bind-probe-{}", std::process::id()));
    let created = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe)
        .is_ok();
    if created {
        let _ = fs::remove_file(&probe);
    }
    created
}

// Serialize warm-slot fill work to avoid concurrent `fill_pool_slot()` races
// across background refill tasks and foreground callers.
static POOL_FILL_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn pool_fill_lock() -> &'static tokio::sync::Mutex<()> {
    POOL_FILL_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Write `/root/.bashrc` inside the guest VM with the theyOS prompt.
/// This ensures instances from older golden images (that had a corrupted
/// binary .bashrc) get a working prompt on first terminal open.
async fn write_bashrc(ssh: &SshSession, config: &VmConfig) {
    let ok = core_rs::constants::PROMPT_COLOR_OK;
    let warn = core_rs::constants::PROMPT_COLOR_WARN;
    let cmd = format!(
        r#"cat > /root/.bashrc << 'BASHRC'
# theyOS shell prompt
PROMPT_COMMAND='if [ $? -eq 0 ]; then PS1="\[\{ok}\]> \[\033[0m\]"; else PS1="\[\{warn}\]> \[\033[0m\]"; fi'
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
BASHRC"#
    );
    match ssh.exec(&cmd).await {
        Ok(_) => tracing::info!("[vmrunner] wrote /root/.bashrc for {}", config.container),
        Err(e) => tracing::warn!("[vmrunner] failed to write .bashrc: {e}"),
    }
}

/// Node.js inline script that patches the openclaw JSON config with a new
/// auth token.  Expects the token as `process.argv[1]` and the config file
/// path as `process.argv[2]`.
///
/// The script:
/// 1. Reads the existing JSON config, or initializes `{}` if the file does not
///    exist yet.
/// 2. Deep-merges `gateway.auth.token` without touching other fields.
/// 3. Writes to a temp file and atomically renames — no partial writes.
///
/// Using `node -e` (~100ms cold start) instead of `openclaw config set`
fn agent_service_name(claw_type: &str) -> String {
    format!("{claw_type}-agent.service")
}

fn snapshot_quiesce_commands(claw_type: &str) -> Vec<String> {
    let mut commands = vec![format!(
        "systemctl stop {} 2>/dev/null || true",
        agent_service_name(claw_type)
    )];

    if claw_type == "openclaw" {
        commands.push("systemctl --user stop openclaw-gateway.service 2>/dev/null || true".into());
        commands.push("loginctl disable-linger root 2>/dev/null || true".into());
        commands.push("pkill -f '[n]ode.*gateway' 2>/dev/null || true".into());
        commands.push("pkill -f '[n]ode.*openclaw' 2>/dev/null || true".into());
    }

    commands
}

fn restart_claw_agent_command(claw_type: &str) -> String {
    format!("systemctl restart {}", agent_service_name(claw_type))
}

fn vm_config_from_instance(inst: &InstanceEnv) -> VmConfig {
    VmConfig {
        container: inst.container.clone(),
        customer: inst.customer.clone(),
        claw_type: inst.claw_type.clone(),
        customer_dir: None,
        tools: vec![],
        cpu_cores: None,
        ram_mb: None,
        disk_gb: None,
    }
}

async fn quiesce_for_snapshot(ssh: &dyn SshActions, claw_type: &str) -> Result<(), VmError> {
    for cmd in snapshot_quiesce_commands(claw_type) {
        ssh.exec(&cmd).await?;
    }

    if claw_type == "openclaw" {
        let out = ssh
            .exec("pgrep -c -f 'node.*gateway' 2>/dev/null || echo 0")
            .await?;
        let count: u32 = out.trim().parse().unwrap_or(0);
        if count > 0 {
            tracing::warn!(
                "[vmrunner] openclaw snapshot quiesce left {count} gateway process(es) running"
            );
        }
    }

    Ok(())
}

async fn flush_snapshot_guest_state(ssh: &dyn SshActions) -> Result<(), VmError> {
    ssh.exec("sync; echo 3 > /proc/sys/vm/drop_caches; sync")
        .await?;
    Ok(())
}

async fn restart_claw_agent_best_effort(ssh: &dyn SshActions, claw_type: &str) {
    let cmd = format!("{} || true", restart_claw_agent_command(claw_type));
    if let Err(e) = ssh.exec(&cmd).await {
        tracing::warn!(
            "[vmrunner] best-effort restart of {} failed: {e}",
            agent_service_name(claw_type)
        );
    }
}

// ── VmRunner ───────────────────────────────────────────────────────────────

/// High-level VM lifecycle manager.
///
/// Equivalent to the `fc-agent-runtime.sh` command set.
pub struct VmRunner {
    pub env: VmEnv,
}

/// Owns child processes while `start_vm` is still establishing a running
/// instance. The outer create/pool guards cannot learn these PIDs until the
/// async function returns, so ownership must begin inside `start_vm` itself.
struct StartedVmGuard<'a> {
    runner: &'a VmRunner,
    inst: InstanceEnv,
    committed: bool,
}

impl<'a> StartedVmGuard<'a> {
    fn new(runner: &'a VmRunner, inst: &InstanceEnv) -> Self {
        Self {
            runner,
            inst: inst.clone(),
            committed: false,
        }
    }

    fn already_running(runner: &'a VmRunner, inst: &InstanceEnv) -> Self {
        Self {
            runner,
            inst: inst.clone(),
            committed: true,
        }
    }

    fn set_fc_pid(&mut self, pid: u32) {
        self.inst.firecracker_pid = Some(pid);
    }

    fn set_slirp_pid(&mut self, pid: u32) {
        self.inst.slirp_pid = Some(pid);
    }

    fn firecracker_pid(&self) -> Option<u32> {
        self.inst.firecracker_pid
    }

    fn slirp_pid(&self) -> Option<u32> {
        self.inst.slirp_pid
    }

    /// Transfer responsibility to the caller's lifecycle guard.
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for StartedVmGuard<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        let quarantine_error = VmRunner::quarantine_before_teardown(
            &self.inst,
            "start_vm failed before startup ownership was committed",
        )
        .err();
        let stop_error = self.runner.stop_vm(&mut self.inst).err();

        if let Some(error) = quarantine_error {
            tracing::error!(
                "[vmrunner-start-guard] quarantine persistence failed for {}: {error}",
                self.inst.container
            );
        }
        if let Some(error) = stop_error {
            tracing::error!(
                "[vmrunner-start-guard] startup teardown was not verified for {}: {error}",
                self.inst.container
            );
        }
    }
}

impl VmRunner {
    /// Build from environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error if `VmEnv::from_env()` fails.
    pub fn from_env() -> Result<Self, VmError> {
        Ok(VmRunner {
            env: VmEnv::from_env()?,
        })
    }

    /// Create and fully bootstrap a new VM instance.
    ///
    /// Equivalent to `fc-agent-runtime.sh create`.
    /// Returns timing information for each phase.
    ///
    /// If a warm pool slot is available for this claw type, the pool VM is claimed
    /// immediately (fast path: ~2s). Otherwise falls back to full create (~20s).
    ///
    /// # Errors
    ///
    /// Returns an error if VM creation, network setup, boot, SSH wait, or claw
    /// installation fails at any stage.
    pub async fn create(&self, config: &VmConfig) -> Result<VmCreateResult, VmError> {
        use crate::timing::PhaseTimer;
        use crate::warm_pool::{global_pool, warm_pool_enabled};

        // ── Try warm pool first ────────────────────────────────────────────
        let warm_entry = if warm_pool_enabled() {
            let mut pool = global_pool()
                .lock()
                .map_err(|_| VmError::Other("warm pool mutex poisoned".into()))?;
            pool.take(&config.claw_type)
        } else {
            None
        };

        if let Some(entry) = warm_entry {
            tracing::info!(
                "[vmrunner] POOL_HIT: claiming warm VM {} for {}",
                entry.container,
                config.container
            );

            // Check instance doesn't already exist
            let instance_dir = self.env.state_dir.join(&config.container);
            if instance_dir.join("instance.env").exists() {
                return Err(VmError::Other(format!(
                    "instance already exists: {}",
                    config.container
                )));
            }

            // Refill is NOT triggered here — the warm_pool_reconciler handles
            // all refill decisions based on budget.
            return self.claim_from_pool(entry, config).await;
        }

        tracing::info!(
            "[vmrunner] POOL_MISS: no warm VM for {}, using full create path",
            config.claw_type
        );

        let mut timer = PhaseTimer::new(&config.container);

        // ── 1. Validate required binaries ──────────────────────────────────
        timer.start_phase("validate_binaries");
        self.validate_binaries()?;
        timer.start_phase("check_exists");

        // ── 2. Check instance doesn't already exist ────────────────────────
        let instance_dir = self.env.state_dir.join(&config.container);
        if instance_dir.join("instance.env").exists() {
            return Err(VmError::Other(format!(
                "instance already exists: {}",
                config.container
            )));
        }
        timer.start_phase("get_installer");

        // ── 3. Get installer for claw type ─────────────────────────────────
        let installer = get_installer(&config.claw_type)
            .ok_or_else(|| VmError::UnsupportedClawType(config.claw_type.clone()))?;
        timer.start_phase("pick_ssh_port");

        // ── 4. Allocate SSH port (atomic reservation) ──────────────────────
        let (ssh_port, _port_reservation) = cid::pick_ssh_port(&self.env.state_dir)?;
        timer.start_phase("create_dirs");

        // ── 5. Build initial InstanceEnv ───────────────────────────────────
        fs::create_dir_all(&instance_dir).map_err(|e| {
            VmError::Io(format!(
                "create instance dir {}: {e}",
                instance_dir.display()
            ))
        })?;

        // RAII guard: cleans up directory and kills processes if create fails.
        // Must be declared AFTER create_dir_all so it removes the dir on rollback.
        let mut guard = CreateGuard::new(instance_dir.clone());

        let mut inst = InstanceEnv {
            container: config.container.clone(),
            customer: config.customer.clone(),
            claw_type: config.claw_type.clone(),
            host_port: 0,
            ssh_port,
            firecracker_pid: None,
            slirp_pid: None,
            instance_dir: instance_dir.clone(),
            rootfs_path: instance_dir.join("rootfs.ext4"),
            firecracker_sock: instance_dir.join("firecracker.sock"),
            slirp_api_sock: instance_dir.join("slirp-api.sock"),
            serial_log: instance_dir.join("serial.log"),
            slirp_log: instance_dir.join("slirp.log"),
            customer_dir: config
                .customer_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        };
        timer.start_phase("prepare_rootfs");

        // Persist instance.env before rootfs setup so startup sweep sees an
        // in-progress create as stateful instead of deleting its directory.
        inst.save()?;

        let resources =
            VmCreateResourceSpec::from_options(config.cpu_cores, config.ram_mb, config.disk_gb)
                .resolve();

        // ── 6. Prepare rootfs ──────────────────────────────────────────────
        let golden_image_used = self.prepare_rootfs(&inst, resources.disk_gb)?;
        timer.start_phase("save_state");

        // Save initial state (port now visible to concurrent pick_ssh_port calls
        // via the instance.env scan — the port reservation guard can be dropped
        // implicitly as it's no longer needed after this point).
        inst.save()?;
        timer.start_phase("start_vm");

        // ── 7. Start VM ────────────────────────────────────────────────────
        let started_guard = self
            .start_vm(
                &mut inst,
                false,
                false,
                resources.cpu_cores,
                resources.ram_mb,
            )
            .await?;
        // Register PIDs in the guard so rollback can kill them if later steps fail.
        if let Some(pid) = started_guard.firecracker_pid() {
            guard.set_fc_pid(pid);
        }
        if let Some(pid) = started_guard.slirp_pid() {
            guard.set_slirp_pid(pid);
        }
        // Durable PID state has been handed to the outer guard before the
        // next await, so cancellation cannot strand startup-owned children.
        started_guard.commit();
        timer.start_phase("wait_ssh");

        // ── 8. Bootstrap claw agent ────────────────────────────────────────
        tracing::info!(
            "[vmrunner] waiting for SSH on {}:{}",
            config.container,
            ssh_port
        );
        let ssh =
            SshSession::wait_for_ssh_install(ssh_port, &self.env.ssh_key, self.env.ssh_wait_tries)
                .await?;

        // ── 8a. Health check: verify network is functional ──────────────────
        // This catches the case where the VM booted but iptables rules failed to
        // apply (async background subshell with no error feedback).
        timer.start_phase("health_check");
        self.health_check_vm(&ssh, &config.container, &instance_dir)
            .await?;

        timer.start_phase("install_claw");

        let install_config = InstallerConfig {
            customer: config.customer.clone(),
            claw_type: config.claw_type.clone(),
            golden_image_used,
            installers_dir: None,
        };

        // Check if install can be skipped (golden image with binary present)
        let install_skipped = if golden_image_used {
            let check_cmd = format!("test -x /usr/local/bin/{}", config.claw_type);
            if ssh.exec(&check_cmd).await.is_ok() {
                tracing::info!("[vmrunner] FAST_PATH: Binary already present, skipping install");
                true
            } else {
                tracing::warn!(
                    "[vmrunner] SLOW_PATH: Golden image missing binary, running install"
                );
                false
            }
        } else {
            false
        };

        // Run installer only if not skipped
        if !install_skipped {
            installer.install(&ssh, &install_config).await?;
        }
        timer.end_phase();

        // Install optional AI coding tools (best-effort, non-fatal)
        if !config.tools.is_empty() {
            timer.start_phase("install_coding_tools");
            crate::tools_plan::install_coding_tools(&ssh, &config.tools).await;
            timer.end_phase();
        }

        // Write /root/.bashrc with theyOS prompt (fixes corrupted binary .bashrc)
        timer.start_phase("write_bashrc");
        write_bashrc(&ssh, config).await;
        timer.end_phase();

        // Log timing summary
        timer.log_summary();
        tracing::info!("[vmrunner-timing-json] {}", timer.to_json_log());

        tracing::info!(
            "[vmrunner] created instance {} (ssh=127.0.0.1:{})",
            config.container,
            ssh_port,
        );

        // ── 9. Disarm rollback guard — create succeeded ────────────────────
        guard.commit();

        // Refill is NOT triggered here — the warm_pool_reconciler handles
        // all refill decisions based on budget.

        Ok(VmCreateResult {
            golden_image_used,
            install_skipped,
            phases: timer.phases().to_vec(),
            total_duration: timer.total_elapsed(),
        })
    }

    /// Stop a running VM.
    ///
    /// Equivalent to `fc-agent-runtime.sh stop`.
    ///
    /// # Errors
    ///
    /// Returns an error if the instance env cannot be loaded or the VM
    /// processes cannot be stopped.
    pub fn stop(&self, container: &str) -> Result<(), VmError> {
        let instance_dir = self.env.state_dir.join(container);
        let mut inst = InstanceEnv::load(&instance_dir)?;
        self.stop_vm(&mut inst)?;
        tracing::info!("[vmrunner] stopped {container}");
        Ok(())
    }

    /// Delete a VM and its state directory.
    ///
    /// Equivalent to `fc-agent-runtime.sh delete`.
    ///
    /// # Errors
    ///
    /// Returns an error if the instance directory cannot be removed.
    pub fn delete(&self, container: &str) -> Result<(), VmError> {
        let instance_dir = self.env.state_dir.join(container);
        // Stop first; ignore only "not found" (idempotent). A quarantined
        // instance is loaded through the cleanup-only path, and a failed stop
        // must prevent deleting the directory while a VM may still survive.
        match InstanceEnv::load(&instance_dir) {
            Ok(mut inst) => {
                self.stop_vm(&mut inst)?;
            }
            Err(VmError::HostfwdUncertain(_)) => {
                let mut inst = InstanceEnv::load_unchecked(&instance_dir)?;
                self.stop_vm(&mut inst)?;
            }
            Err(VmError::InstanceNotFound(_)) => {}
            Err(e) => return Err(e),
        }
        if instance_dir.exists() {
            fs::remove_dir_all(&instance_dir).map_err(|e| {
                VmError::Io(format!(
                    "remove instance dir {}: {e}",
                    instance_dir.display()
                ))
            })?;
        }
        tracing::info!("[vmrunner] deleted {container}");
        Ok(())
    }

    /// Restart a running VM.
    ///
    /// Equivalent to `fc-agent-runtime.sh restart`.
    ///
    /// # Errors
    ///
    /// Returns an error if the VM cannot be stopped, restarted, or SSH
    /// reconnection fails.
    pub async fn restart(&self, container: &str) -> Result<(), VmError> {
        let instance_dir = self.env.state_dir.join(container);
        let mut inst = InstanceEnv::load(&instance_dir)?;

        self.stop_vm(&mut inst)?;
        // Use force_kernel_boot=true to do a full kernel boot instead of snapshot
        // restore. This preserves the instance's modified rootfs. Snapshot restore
        // would load the seed's kernel memory (stale dentry/inode cache) over the
        // instance's modified disk, causing ext4 corruption.
        let started_guard = self
            .start_vm(
                &mut inst,
                false,
                true,
                DEFAULT_CREATE_CPU_CORES,
                DEFAULT_CREATE_RAM_MB,
            )
            .await?;

        let ssh =
            SshSession::wait_for_ssh(inst.ssh_port, &self.env.ssh_key, self.env.ssh_wait_tries)
                .await?;

        // Rewrite .bashrc to fix corrupted prompts from older golden images.
        let cfg = vm_config_from_instance(&inst);
        write_bashrc(&ssh, &cfg).await;
        restart_claw_agent_best_effort(&ssh, &inst.claw_type).await;

        started_guard.commit();

        tracing::info!("[vmrunner] restarted {container} (kernel boot, rootfs preserved)");
        Ok(())
    }

    /// Rebuild a running VM with a fresh rootfs from the snapshot.
    ///
    /// Like `restart`, but replaces the instance rootfs with a clean copy from
    /// the snapshot directory before rebooting.  This fixes corrupted filesystems
    /// without requiring a full delete + recreate cycle.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot rootfs is missing, the copy fails,
    /// or the VM cannot be restarted.
    pub async fn rebuild(&self, container: &str) -> Result<(), VmError> {
        let instance_dir = self.env.state_dir.join(container);
        let mut inst = InstanceEnv::load(&instance_dir)?;

        self.stop_vm(&mut inst)?;

        // Replace corrupted rootfs with a clean copy from the snapshot.
        let src = self.snapshot_dir_rootfs(&inst.claw_type).ok_or_else(|| {
            VmError::Other(format!(
                "no snapshot rootfs for {} — cannot rebuild (run imagebuilder build first)",
                inst.claw_type
            ))
        })?;
        tracing::info!(
            "[vmrunner] rebuild: replacing rootfs {} → {}",
            src.display(),
            inst.rootfs_path.display()
        );
        fs::copy(&src, &inst.rootfs_path)
            .map_err(|e| VmError::Io(format!("copy snapshot rootfs for rebuild: {e}")))?;

        // Fresh rootfs was just copied — snapshot restore is safe here because
        // the disk matches the seed's state that mem.snapshot was taken from.
        let started_guard = self
            .start_vm(
                &mut inst,
                false,
                false,
                DEFAULT_CREATE_CPU_CORES,
                DEFAULT_CREATE_RAM_MB,
            )
            .await?;

        let ssh =
            SshSession::wait_for_ssh(inst.ssh_port, &self.env.ssh_key, self.env.ssh_wait_tries)
                .await?;
        let cfg = vm_config_from_instance(&inst);
        write_bashrc(&ssh, &cfg).await;
        restart_claw_agent_best_effort(&ssh, &inst.claw_type).await;

        started_guard.commit();

        tracing::info!("[vmrunner] rebuilt {container} with fresh rootfs");
        Ok(())
    }

    /// Clean up systemd user units for a container (no-op if not found).
    ///
    /// Mirrors `cleanupSystemd` in `firecracker.go`.
    ///
    /// # Errors
    ///
    /// This function is infallible in practice (all operations are best-effort).
    pub fn cleanup_systemd(&self, container: &str) -> Result<(), VmError> {
        let service = format!("container-{container}.service");

        // Attempt to find systemctl; silently skip if not available
        let systemctl = which_systemctl();
        if let Some(ref bin) = systemctl {
            let _ = Command::new(bin)
                .args(["--user", "stop", &service])
                .output();
            let _ = Command::new(bin)
                .args(["--user", "disable", &service])
                .output();

            if let Some(home) = home_dir() {
                let unit_path = home
                    .join(".config")
                    .join("systemd")
                    .join("user")
                    .join(&service);
                let _ = fs::remove_file(&unit_path);
            }
            let _ = Command::new(bin).args(["--user", "daemon-reload"]).output();
        }
        Ok(())
    }

    /// Delete filesystem resources for a claw type/name.
    ///
    /// Mirrors `deleteInstanceFSResources` in `firecracker.go`.
    ///
    /// # Errors
    ///
    /// Returns an error if the customer directory exists but cannot be removed.
    pub fn cleanup_fs(&self, claw_type: &str, name: &str) -> Result<(), VmError> {
        // Remove customer dir under the claw's data base dir, if it exists.
        // This is a best-effort cleanup — missing dirs are not errors.
        let base = claw_data_base_dir(claw_type, &self.env.state_dir);
        if let Some(base) = base {
            let customer_dir = base.join("customers").join(name);
            if customer_dir.exists() {
                fs::remove_dir_all(&customer_dir).map_err(|e| {
                    VmError::Io(format!(
                        "remove customer dir {}: {e}",
                        customer_dir.display()
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Ensure a Linux/Firecracker public site host forward exists.
    ///
    /// The forward binds the configured loopback host address on the host and
    /// sends traffic to the configured slirp guest address. The operation is
    /// idempotent when the exact host/guest mapping already exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the instance is not running or the slirp API rejects
    /// the host forward. `VmError::HostfwdUncertain` is a distinct safety
    /// outcome: an ambiguous add may have installed a mapping, so this method
    /// stops the VM before returning and callers must not reuse it.
    pub fn ensure_public_hostfwd(
        &self,
        container: &str,
        host_port: u16,
        guest_port: u16,
    ) -> Result<(), VmError> {
        let instance_dir = self.env.state_dir.join(container);
        let mut inst = InstanceEnv::load(&instance_dir)?;

        match inst.slirp_pid {
            Some(pid) if is_pid_running(pid) => {}
            Some(pid) => {
                return Err(VmError::Other(format!(
                    "slirp4netns for {container} is not running (pid={pid})"
                )));
            }
            None => {
                return Err(VmError::Other(format!(
                    "instance {container} is not running; start it before publishing a Linux public site"
                )));
            }
        }

        slirp_wait_ready(&inst.slirp_api_sock, Duration::from_secs(5))?;
        let existing = slirp_list_hostfwd(&inst.slirp_api_sock)?
            .into_iter()
            .any(|(_, hp, gp)| hp == host_port && gp == guest_port);
        if existing {
            tracing::info!(
                "[vmrunner] public hostfwd already present: {container} 127.0.0.1:{host_port} -> guest:{guest_port}"
            );
            return Ok(());
        }

        match slirp_add_hostfwd(&inst.slirp_api_sock, host_port, guest_port) {
            Ok(_) => {}
            Err(e @ VmError::HostfwdUncertain(_)) => {
                tracing::error!(
                    "[vmrunner] public hostfwd state is uncertain for {container}; stopping VM before returning"
                );
                let quarantine_error = Self::quarantine_before_teardown(
                    &inst,
                    "ambiguous public hostfwd response; teardown pending",
                )
                .err();
                return match self.stop_vm(&mut inst) {
                    Ok(()) => match quarantine_error {
                        Some(quarantine_error) => Err(VmError::HostfwdUncertain(format!(
                            "{e}; teardown verified but quarantine persistence failed: {quarantine_error}"
                        ))),
                        None => Err(e),
                    },
                    Err(stop_error) => {
                        tracing::error!(
                            "[vmrunner] failed to prove VM {container} stopped after uncertain hostfwd state: {stop_error}"
                        );
                        let quarantine_detail = quarantine_error
                            .map(|error| format!("; quarantine persistence also failed: {error}"))
                            .unwrap_or_default();
                        Err(VmError::HostfwdUncertain(format!(
                            "{e}; VM teardown was not verified: {stop_error}{quarantine_detail}"
                        )))
                    }
                };
            }
            Err(e) => return Err(e),
        }
        tracing::info!(
            "[vmrunner] public hostfwd added: {container} 127.0.0.1:{host_port} -> guest:{guest_port}"
        );
        Ok(())
    }

    /// Fetch the last `tail` log lines from a running VM via SSH.
    ///
    /// Equivalent to `fc-agent-runtime.sh logs CONTAINER [TAIL]`.
    ///
    /// # Errors
    ///
    /// Returns an error if the instance env cannot be loaded, SSH connection
    /// fails, or the log command fails.
    pub async fn fetch_logs(&self, container: &str, tail: usize) -> Result<Vec<String>, VmError> {
        let instance_dir = self.env.state_dir.join(container);
        let inst = InstanceEnv::load(&instance_dir)?;

        let ssh = SshSession::wait_for_ssh(inst.ssh_port, &self.env.ssh_key, 3).await?;

        let service = format!("{}-agent.service", inst.claw_type);
        let cmd = format!(
            "journalctl -u {service} --no-pager -n {tail} -o short-iso || \
             journalctl --no-pager -n {tail} -o short-iso"
        );
        let output = ssh.exec(&cmd).await?;

        let lines: Vec<String> = output
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        Ok(lines)
    }

    /// Upload a local file to `~/Downloads/<remote_filename>` inside the claw.
    ///
    /// Uses a two-step approach for atomicity: upload to a `.part` temp file
    /// first, then rename to the final path.
    ///
    /// # Errors
    ///
    /// Returns an error if the instance env cannot be loaded, SSH connection
    /// fails, or the file upload/rename fails.
    pub async fn upload_file_to_downloads(
        &self,
        container: &str,
        local_path: &std::path::Path,
        subfolder: &str,
        remote_filename: &str,
    ) -> Result<String, VmError> {
        let instance_dir = self.env.state_dir.join(container);
        let inst = InstanceEnv::load(&instance_dir)?;
        let ssh = SshSession::wait_for_ssh(inst.ssh_port, &self.env.ssh_key, 3).await?;

        ssh.exec(&format!("mkdir -p \"$HOME/Downloads/{subfolder}\""))
            .await?;

        let part_path = format!("$HOME/Downloads/{subfolder}/.{remote_filename}.part");
        let final_path = format!("$HOME/Downloads/{subfolder}/{remote_filename}");

        ssh.upload_file(local_path, &part_path).await?;
        ssh.exec(&format!("mv \"{part_path}\" \"{final_path}\""))
            .await?;

        Ok(format!("~/Downloads/{subfolder}/{remote_filename}"))
    }

    /// Create a base snapshot for a given claw type from a running VM instance.
    ///
    /// Steps:
    /// 1. Load the instance env for the given container.
    /// 2. Pause the VM via Firecracker API.
    /// 3. Create a full snapshot (vmstate + memory) into the assets/snapshots dir.
    /// 4. Kill the VM (snapshot VMs are not kept running).
    ///
    /// The snapshot is stored at:
    ///   `~/firecracker/assets/snapshots/<claw_type>/vmstate.snapshot`
    ///   `~/firecracker/assets/snapshots/<claw_type>/mem.snapshot`
    ///
    /// # Errors
    ///
    /// Returns an error if the instance env cannot be loaded, the VM cannot be
    /// paused, or the snapshot creation fails.
    ///
    /// # Panics
    ///
    /// Panics if `vmstate_path` has no parent directory (guaranteed not to happen
    /// for paths constructed from `snapshot_paths()`).
    pub async fn take_base_snapshot(
        &self,
        container: &str,
        claw_type: &str,
    ) -> Result<(), VmError> {
        let instance_dir = self.env.state_dir.join(container);
        let inst = InstanceEnv::load(&instance_dir)?;
        let assets_dir = self.env.home.join("firecracker/assets");

        // Compute snapshot fingerprint from golden fingerprint + kernel hash.
        // If golden metadata exists (versionated layout), use DAG-based fingerprinting.
        // Otherwise, fall back to writing in the legacy flat directory.
        let golden_meta = core_rs::artifact_meta::read_current_golden_meta(&assets_dir, claw_type);
        let kernel_sha256 =
            core_rs::artifact_meta::sha256_file(&self.env.kernel_image).unwrap_or_default();

        let (snap_dir, snapshot_fp) = if let Some(ref gmeta) = golden_meta {
            // DAG-based: compute snapshot fingerprint and create versionated dir
            let fp =
                core_rs::artifact_meta::snapshot_fingerprint(&gmeta.fingerprint, &kernel_sha256);
            let ver_dir = core_rs::artifact_meta::snapshot_version_dir(&assets_dir, claw_type, &fp);
            fs::create_dir_all(&ver_dir).map_err(|e| {
                VmError::Io(format!("create snapshot dir {}: {e}", ver_dir.display()))
            })?;
            tracing::info!(
                "[vmrunner] snapshot fingerprint={} (golden={}, kernel={})",
                fp.short(),
                gmeta.fingerprint.short(),
                &kernel_sha256[..12.min(kernel_sha256.len())],
            );
            (ver_dir, Some(fp))
        } else {
            // Legacy flat layout
            let flat_dir = self
                .env
                .home
                .join(format!("firecracker/assets/snapshots/{claw_type}"));
            fs::create_dir_all(&flat_dir).map_err(|e| {
                VmError::Io(format!("create snapshot dir {}: {e}", flat_dir.display()))
            })?;
            tracing::info!(
                "[vmrunner] no golden metadata for {} — using legacy snapshot layout",
                claw_type
            );
            (flat_dir, None)
        };
        align_snapshot_dir_owner(&snap_dir, &inst.instance_dir)?;

        let vmstate_path = snap_dir.join("vmstate.snapshot");
        let mem_path = snap_dir.join("mem.snapshot");

        let ssh =
            SshSession::wait_for_ssh(inst.ssh_port, &self.env.ssh_key, self.env.ssh_wait_tries)
                .await?;

        tracing::info!("[vmrunner] quiescing VM {} before snapshot", container);
        quiesce_for_snapshot(&ssh, claw_type).await?;
        tracing::info!("[vmrunner] flushing guest page cache before snapshot");
        flush_snapshot_guest_state(&ssh).await?;

        let fc = FirecrackerClient::new(inst.firecracker_sock.clone());

        tracing::info!("[vmrunner] pausing VM {} for snapshot", container);
        fc.pause_vm().await?;

        tracing::info!(
            "[vmrunner] creating snapshot for {} → {}",
            claw_type,
            vmstate_path.display()
        );
        let t0 = std::time::Instant::now();
        fc.create_snapshot(
            &vmstate_path.display().to_string(),
            &mem_path.display().to_string(),
        )
        .await?;
        tracing::info!(
            "[vmrunner] snapshot created in {}ms",
            t0.elapsed().as_millis()
        );

        // Copy rootfs to the snapshot directory so the baked path survives
        // instance deletion. Without this, deleting the seed instance removes
        // the rootfs that warm-pool refill needs, causing slirp/VM failures.
        let snapshot_rootfs = snap_dir.join("rootfs.ext4");
        fs::copy(&inst.rootfs_path, &snapshot_rootfs).map_err(|e| {
            VmError::Io(format!(
                "copy rootfs to snapshot dir {}: {e}",
                snapshot_rootfs.display()
            ))
        })?;
        tracing::info!(
            "[vmrunner] copied rootfs to snapshot dir: {}",
            snapshot_rootfs.display()
        );

        // Write a marker file that records paths baked into the vmstate.
        // The restore logic uses this to set up the bind mount before load_snapshot.
        //
        // Format: "<claw_type>\n<rootfs_path>"
        //
        // rootfs_path MUST match the path baked in the vmstate binary —
        // i.e. the seed instance's rootfs_path (what set_rootfs() configured
        // when the VM was booted). The bind mount in the unshare script
        // targets this path, so Firecracker can reopen it after restore.
        //
        // The durable copy in the snapshot dir (snapshot_rootfs above) is
        // used separately as the fs::copy source when preparing new instances.
        let marker = snap_dir.join("snapshot.ready");
        let marker_content = format!("{}\n{}", claw_type, inst.rootfs_path.display());
        fs::write(&marker, &marker_content)
            .map_err(|e| VmError::Io(format!("write snapshot marker: {e}")))?;

        // Write snapshot.meta.json + update `current` symlink (versionated layout only)
        if let Some(fp) = &snapshot_fp {
            let snap_meta = core_rs::artifact_meta::SnapshotMeta {
                claw_type: claw_type.to_string(),
                fingerprint: fp.clone(),
                golden_fingerprint: golden_meta.as_ref().map_or_else(
                    || core_rs::artifact_meta::Fingerprint::new("unknown"),
                    |g| g.fingerprint.clone(),
                ),
                kernel_sha256: kernel_sha256.clone(),
                builder_version: env!("CARGO_PKG_VERSION").to_string(),
                created_at: core_rs::time::now_iso_secs(),
            };
            if let Err(e) =
                core_rs::artifact_meta::write_meta(&snap_dir.join("snapshot.meta.json"), &snap_meta)
            {
                tracing::warn!("[vmrunner] failed to write snapshot.meta.json: {e}");
            }

            let current_link =
                core_rs::artifact_meta::snapshot_current_link(&assets_dir, claw_type);
            if let Err(e) = core_rs::artifact_meta::update_current_link(&current_link, fp) {
                tracing::warn!("[vmrunner] failed to update snapshot current symlink: {e}");
            }

            tracing::info!(
                "[vmrunner] snapshot metadata written, current -> {} ({})",
                fp.short(),
                snap_dir.display()
            );
        }

        tracing::info!(
            "[vmrunner] base snapshot ready for {} | baked rootfs: {} | durable copy: {} (marker: {})",
            claw_type,
            inst.rootfs_path.display(),
            snapshot_rootfs.display(),
            marker.display()
        );
        Ok(())
    }

    // ── Private helpers ────────────────────────────────────────────────────

    /// Return the (vmstate, mem) snapshot paths for a given claw type.
    ///
    /// Resolves through the versionated `current` symlink first, then falls
    /// back to the legacy flat layout for pre-migration compatibility.
    fn snapshot_paths(&self, claw_type: &str) -> (PathBuf, PathBuf) {
        let snap_dir = self.resolve_snapshot_dir(claw_type);
        (
            snap_dir.join("vmstate.snapshot"),
            snap_dir.join("mem.snapshot"),
        )
    }

    /// Return true if a base snapshot exists for the given claw type.
    fn snapshot_exists(&self, claw_type: &str) -> bool {
        let (vmstate_path, mem_path) = self.snapshot_paths(claw_type);
        let snap_dir = self.resolve_snapshot_dir(claw_type);
        let marker = snap_dir.join("snapshot.ready");
        vmstate_path.exists() && mem_path.exists() && marker.exists()
    }

    /// Read the rootfs path that was baked into the snapshot vmstate at creation
    /// time. This is stored in the second line of `snapshot.ready`.
    fn snapshot_baked_rootfs(&self, claw_type: &str) -> Option<PathBuf> {
        let snap_dir = self.resolve_snapshot_dir(claw_type);
        let marker = snap_dir.join("snapshot.ready");
        let content = fs::read_to_string(&marker).ok()?;
        let mut lines = content.lines();
        lines.next(); // skip claw_type line
        lines.next().map(|p| PathBuf::from(p.trim()))
    }

    /// Return the durable rootfs copy in the snapshot directory.
    ///
    /// This is the persistent copy that survives seed instance deletion.
    /// Used as the `fs::copy` source when preparing new instances (NOT for the
    /// bind mount target, which uses the baked path from `snapshot_baked_rootfs`).
    fn snapshot_dir_rootfs(&self, claw_type: &str) -> Option<PathBuf> {
        let snap_dir = self.resolve_snapshot_dir(claw_type);
        let path = snap_dir.join("rootfs.ext4");
        if path.exists() { Some(path) } else { None }
    }

    /// Resolve the snapshot directory for a claw type.
    ///
    /// Tries the versionated layout (via `current` symlink) first, then falls
    /// back to the legacy flat layout `assets/snapshots/<claw>/`.
    fn resolve_snapshot_dir(&self, claw_type: &str) -> PathBuf {
        let assets_dir = self.env.home.join("firecracker/assets");
        let current_link = core_rs::artifact_meta::snapshot_current_link(&assets_dir, claw_type);

        // If the `current` symlink exists, resolve it
        if let Ok(target) = fs::read_link(&current_link) {
            let resolved = if target.is_relative() {
                current_link
                    .parent()
                    .map_or_else(|| target.clone(), |p| p.join(&target))
            } else {
                target
            };
            if resolved.is_dir() {
                return resolved;
            }
        }

        // Legacy flat layout fallback
        self.env
            .home
            .join(format!("firecracker/assets/snapshots/{claw_type}"))
    }

    fn validate_binaries(&self) -> Result<(), VmError> {
        let checks = [
            ("firecracker binary", &self.env.firecracker_bin),
            ("kernel image", &self.env.kernel_image),
            ("base rootfs", &self.env.base_rootfs),
            ("SSH private key", &self.env.ssh_key),
        ];
        for (label, path) in &checks {
            if !path.exists() {
                return Err(VmError::MissingBinary(format!(
                    "{label} not found: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// Prepare the rootfs for a new instance.
    ///
    /// Returns `true` if a golden image was used.
    fn prepare_rootfs(&self, inst: &InstanceEnv, disk_gb: u32) -> Result<bool, VmError> {
        let golden_image_used;
        let golden_image_src: Option<PathBuf>;

        if let Some(parent) = inst.rootfs_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                VmError::Io(format!("create instance dir {}: {e}", parent.display()))
            })?;
        }

        if inst.rootfs_path.exists() {
            tracing::info!(
                "[vmrunner] Rootfs already exists at {}, skipping copy",
                inst.rootfs_path.display()
            );
            golden_image_used = false;
            golden_image_src = None;
        } else {
            // Try versionated layout first (DAG-based), then fall back to
            // legacy flat path for pre-migration compatibility.
            let assets_dir = self.env.home.join("firecracker/assets");
            let golden =
                core_rs::artifact_meta::golden_current_rootfs(&assets_dir, &inst.claw_type)
                    .or_else(|| {
                        // Legacy flat path: ~/firecracker/assets/ubuntu-24.04-{claw}.ext4
                        let legacy = self.env.home.join(format!(
                            "firecracker/assets/ubuntu-24.04-{}.ext4",
                            inst.claw_type
                        ));
                        if legacy.exists() {
                            tracing::info!(
                                "[vmrunner] using legacy flat golden image at {}",
                                legacy.display()
                            );
                            Some(legacy)
                        } else {
                            None
                        }
                    });

            let src = if let Some(golden) = golden {
                let size = std::fs::metadata(&golden).map_or_else(
                    |_| "unknown".to_string(),
                    |m| format!("{}MB", m.len() / 1024 / 1024),
                );
                tracing::info!(
                    "[vmrunner] FAST_PATH: Using golden image for {} (size: {}, path: {})",
                    inst.claw_type,
                    size,
                    golden.display()
                );
                golden_image_used = true;
                golden_image_src = Some(golden.clone());
                golden
            } else {
                tracing::info!(
                    "[vmrunner] SLOW_PATH: Golden image not found for {}, falling back to base rootfs",
                    inst.claw_type
                );
                golden_image_used = false;
                golden_image_src = None;
                self.env.base_rootfs.clone()
            };

            let copy_start = std::time::Instant::now();

            // cp --sparse=always --reflink=auto <src> <dst>
            // --sparse=always: detect zero holes and skip writing them → 10-18s → ~1s
            // --reflink=auto:  use reflinks on btrfs/xfs if available (no-op on ext4)
            let status = Command::new("cp")
                .args([
                    "--sparse=always",
                    "--reflink=auto",
                    &src.display().to_string(),
                    &inst.rootfs_path.display().to_string(),
                ])
                .status()
                .map_err(|e| VmError::process_spawn_plain(format!("cp: {e}")))?;

            let copy_time = copy_start.elapsed();

            if !status.success() {
                return Err(VmError::Io(format!(
                    "copy rootfs from {} to {} failed",
                    src.display(),
                    inst.rootfs_path.display()
                )));
            }

            tracing::info!(
                "[vmrunner] Rootfs copy completed in {}ms (golden={})",
                copy_time.as_millis(),
                golden_image_used
            );

            // Expand the rootfs to the configured disk size. Golden images are
            // already built at the default size, so this is a no-op for the
            // snapshot path. It is a safety net for the full kernel boot (cold)
            // path where the backing file may be smaller than the target.
            let target_bytes = u64::from(disk_gb) * 1024 * 1024 * 1024;
            Self::expand_rootfs(&inst.rootfs_path, target_bytes)?;
        }

        // Inject SSH pubkey via debugfs — UNLESS the golden image already has
        // the correct pubkey baked in, in which case we skip all debugfs calls.
        //
        // A golden image has the pubkey pre-baked when a marker file
        // `<image>.pubkey.sha256` exists and contains the SHA256 of the current
        // pubkey. This saves ~7s of debugfs startup on every instance creation.
        if !self.env.ssh_pubkey.exists() {
            return Err(VmError::MissingBinary(format!(
                "SSH pubkey not found: {}",
                self.env.ssh_pubkey.display()
            )));
        }

        // Compute sha256 of the current pubkey in-process (avoids fork+exec).
        let pubkey_sha256 = std::fs::read(&self.env.ssh_pubkey)
            .ok()
            .map(|bytes| {
                use sha2::Digest;
                let hash = sha2::Sha256::digest(&bytes);
                format!("{hash:x}")
            })
            .unwrap_or_default();

        // Check if the golden image source has the pubkey pre-baked
        let skip_debugfs = if golden_image_used {
            let src = golden_image_src
                .as_ref()
                .expect("golden_image_src must be Some when golden_image_used is true");
            let marker = PathBuf::from(format!("{}.pubkey.sha256", src.display()));
            if let Ok(baked) = fs::read_to_string(&marker) {
                let baked = baked.trim();
                if baked == pubkey_sha256 && !pubkey_sha256.is_empty() {
                    tracing::info!(
                        "[vmrunner] pubkey pre-baked in golden image (sha256 match), skipping debugfs"
                    );
                    true
                } else {
                    tracing::info!(
                        "[vmrunner] pubkey mismatch (baked={}, current={}), running debugfs",
                        &baked[..8.min(baked.len())],
                        &pubkey_sha256[..8.min(pubkey_sha256.len())]
                    );
                    false
                }
            } else {
                tracing::info!("[vmrunner] no pubkey marker for golden image, running debugfs");
                false
            }
        } else {
            false
        };

        if !skip_debugfs {
            let t_dbfs = std::time::Instant::now();
            self.debugfs_inject_pubkey(&inst.rootfs_path)?;
            tracing::info!(
                "[vmrunner-timing] prepare_rootfs.debugfs_batch: {}ms",
                t_dbfs.elapsed().as_millis()
            );
        }

        Ok(golden_image_used)
    }

    /// Expand a rootfs image to the given target size (bytes).
    ///
    /// Golden images are already built at the default size, so for the
    /// snapshot path this is a no-op. For the full kernel boot (cold) path,
    /// this extends the file (sparse — no real disk consumed for zeroed
    /// regions) and grows the ext4 filesystem to fill it.
    ///
    /// Skipped when the file is already at or above the target size.
    fn expand_rootfs(rootfs: &Path, target_bytes: u64) -> Result<(), VmError> {
        let current_size = fs::metadata(rootfs).map_or(0, |m| m.len());
        if current_size >= target_bytes {
            return Ok(());
        }

        let t = std::time::Instant::now();

        // Extend the file (sparse — only metadata changes, no real blocks)
        let f = fs::OpenOptions::new()
            .write(true)
            .open(rootfs)
            .map_err(|e| {
                VmError::Io(format!("open rootfs for expand: {}: {e}", rootfs.display()))
            })?;
        f.set_len(target_bytes).map_err(|e| {
            VmError::Io(format!(
                "set_len rootfs to {target_bytes}: {}: {e}",
                rootfs.display()
            ))
        })?;
        drop(f);

        // Grow the ext4 filesystem to fill the new space.
        // Try resize2fs first; if it fails (e.g. unclean fs), run e2fsck and retry.
        let rootfs_str = rootfs.display().to_string();
        let status = Command::new("resize2fs")
            .arg(&rootfs_str)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .status()
            .map_err(|e| VmError::process_spawn_plain(format!("resize2fs: {e}")))?;

        if !status.success() {
            tracing::warn!(
                "[vmrunner] resize2fs failed on {}, trying e2fsck + retry",
                rootfs.display()
            );
            let _ = Command::new("e2fsck")
                .args(["-fy", &rootfs_str])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();

            let retry = Command::new("resize2fs")
                .arg(&rootfs_str)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .status()
                .map_err(|e| VmError::process_spawn_plain(format!("resize2fs retry: {e}")))?;

            if !retry.success() {
                return Err(VmError::Io(format!(
                    "resize2fs failed after e2fsck on {}",
                    rootfs.display()
                )));
            }
        }

        tracing::info!(
            "[vmrunner] rootfs expanded to {}G in {}ms (was {}M)",
            INSTANCE_ROOTFS_BYTES / 1024 / 1024 / 1024,
            t.elapsed().as_millis(),
            current_size / 1024 / 1024,
        );

        Ok(())
    }

    /// Batch-inject SSH pubkey into rootfs via a single `debugfs -w` invocation.
    /// Pipes multiple commands via stdin instead of 3 separate spawns (~7s → ~2-3s).
    fn debugfs_inject_pubkey(&self, rootfs: &Path) -> Result<(), VmError> {
        use std::io::Write;

        let commands = format!(
            "mkdir /root/.ssh\nrm /root/.ssh/authorized_keys\nwrite {} /root/.ssh/authorized_keys\n",
            self.env.ssh_pubkey.display()
        );

        let mut child = Command::new("debugfs")
            .args(["-w", &rootfs.display().to_string()])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| VmError::process_spawn_plain(format!("debugfs: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(commands.as_bytes());
            // stdin is dropped here, closing the pipe → debugfs processes & exits
        }

        let output = child
            .wait_with_output()
            .map_err(|e| VmError::process_spawn_plain(format!("debugfs wait: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // debugfs may report benign errors for mkdir/rm on already-existing/missing entries;
            // only fail if the write command likely failed (heuristic: check stderr for "write").
            if stderr.contains("write") && stderr.contains("error") {
                return Err(VmError::Io(format!("debugfs batch failed: {stderr}")));
            }
        }
        Ok(())
    }

    /// Start the VM using `unshare` + slirp4netns, then configure via Firecracker API.
    ///
    /// If a base snapshot exists for the claw type, restores from snapshot instead
    /// of doing a full kernel boot (dramatically faster: ~2s vs ~92s).
    ///
    /// When `pool_mode` is false (normal create / restart):
    ///   - Checks if the VM is already running (returns early if so)
    ///   - Adds SSH + app port hostfwds at the end via `slirp_add_hostfwd`
    ///
    /// When `pool_mode` is true (pool fill):
    ///   - Copies rootfs from the snapshot directory (durable copy for pool VMs)
    ///   - Skips hostfwd — ports are added later at claim time
    ///
    /// This mirrors `start_vm` in `fc-agent-runtime.sh`.
    async fn start_vm(
        &self,
        inst: &mut InstanceEnv,
        pool_mode: bool,
        force_kernel_boot: bool,
        cpu_cores: u32,
        ram_mb: u32,
    ) -> Result<StartedVmGuard<'_>, VmError> {
        let log_prefix = if pool_mode {
            "[vmrunner-pool]"
        } else {
            "[vmrunner]"
        };
        let timing_prefix = if pool_mode {
            "[vmrunner-pool-timing]"
        } else {
            "[vmrunner-timing]"
        };

        // In normal mode, check if the VM is already running.
        if !pool_mode {
            if let Some(pid) = inst.firecracker_pid {
                if is_pid_running(pid) {
                    tracing::info!("{log_prefix} instance already running: {}", inst.container);
                    return Ok(StartedVmGuard::already_running(self, inst));
                }
            }
        }

        // Clean up stale socket files
        let _ = fs::remove_file(&inst.firecracker_sock);
        let _ = fs::remove_file(&inst.slirp_api_sock);

        // Ownership of instance paths is managed by the host deployment layer.
        // Restart must not widen permissions automatically; stale ownership is
        // repaired by the service pre-start in nix/module.nix.

        let slirp_bin = resolve_slirp4netns()?;

        // Check if a base snapshot is available for this claw type.
        // force_kernel_boot skips snapshot restore — used by restart() to preserve
        // the instance's modified rootfs. Loading a snapshot over a previously-modified
        // rootfs causes ext4 corruption: the mem.snapshot restores the kernel's dentry
        // cache from the seed VM (e.g. /usr/bin/apt → inode 720), but the instance's
        // disk has already reallocated that inode to a different file.
        let use_snapshot = !force_kernel_boot && self.snapshot_exists(&inst.claw_type);
        if force_kernel_boot {
            tracing::info!(
                "{log_prefix} BOOT_PATH: force_kernel_boot set for {}, skipping snapshot restore",
                inst.claw_type
            );
        } else if use_snapshot {
            tracing::info!(
                "{log_prefix} SNAPSHOT_PATH: Snapshot available for {}, will restore from snapshot",
                inst.claw_type
            );
        } else {
            tracing::info!(
                "{log_prefix} BOOT_PATH: No snapshot for {}, doing full kernel boot",
                inst.claw_type
            );
        }

        // When restoring from snapshot, the vmstate has the rootfs path baked in
        // at snapshot-creation time. We set up a bind mount inside the private mount
        // namespace so Firecracker reopens the per-instance rootfs at that exact path.
        let (snapshot_vmstate, snapshot_mem) = self.snapshot_paths(&inst.claw_type);

        // Read the rootfs path that was baked into the vmstate during take_base_snapshot.
        // If missing, fall back to no snapshot (safe degradation).
        let baked_rootfs = if use_snapshot {
            if let Some(p) = self.snapshot_baked_rootfs(&inst.claw_type) {
                tracing::info!("{log_prefix} snapshot baked rootfs path: {}", p.display());
                Some(p)
            } else {
                tracing::warn!(
                    "{log_prefix} snapshot.ready missing rootfs line for {}, falling back to boot",
                    inst.claw_type
                );
                None
            }
        } else {
            None
        };
        let snapshot_bind_target_ready = baked_rootfs
            .as_ref()
            .is_some_and(|p| can_prepare_snapshot_bind_target(p));
        if let Some(baked_rootfs_path) = &baked_rootfs {
            if use_snapshot && !snapshot_bind_target_ready {
                tracing::warn!(
                    "{log_prefix} snapshot bind target is not writable ({}), falling back to boot path",
                    baked_rootfs_path.display()
                );
            }
        }
        let use_snapshot = use_snapshot && baked_rootfs.is_some() && snapshot_bind_target_ready;

        // Build the shell script that runs inside the new network namespace.
        // The shared guest-net helper owns the dual-TAP identity and iptables
        // rules; this backend owns process/mount orchestration.
        // P28.4: uses /bin/sh (POSIX) instead of bash; set -eu (no pipefail).
        let inner_script = if use_snapshot {
            let baked_path = baked_rootfs
                .as_ref()
                .expect("use_snapshot implies baked_rootfs is Some");
            // Snapshot restore path: bind-mount per-instance rootfs over the exact
            // path that was baked into the vmstate at snapshot-creation time.
            // The --mount flag on unshare ensures this bind-mount is private to
            // this namespace and doesn't affect other instances.
            let network_setup = core_rs::guest_net::firecracker_dual_tap_setup_script();
            format!(
                r"set -eu
{network_setup}
# Bind-mount per-instance rootfs over the EXACT path that was baked into the
# vmstate at snapshot-creation time. This makes Firecracker reopen the right file.
# The baked path may no longer exist (seed instance was deleted), so we create
# a placeholder file/dir structure for the bind mount target.
mkdir -p '{baked_rootfs_dir}'
touch '{baked_rootfs_path}'
mount --bind '{instance_rootfs}' '{baked_rootfs_path}'
'{firecracker_bin}' --api-sock '{api_sock}' &
wait $!
",
                network_setup = network_setup,
                firecracker_bin = self.env.firecracker_bin.display(),
                api_sock = inst.firecracker_sock.display(),
                instance_rootfs = inst.rootfs_path.display(),
                baked_rootfs_path = baked_path.display(),
                baked_rootfs_dir = baked_path
                    .parent()
                    .map_or_else(|| "/tmp".to_string(), |p| p.display().to_string()),
            )
        } else {
            let network_setup = core_rs::guest_net::firecracker_dual_tap_setup_script();
            format!(
                r"set -eu
{network_setup}
'{firecracker_bin}' --api-sock '{api_sock}' &
wait $!
",
                network_setup = network_setup,
                firecracker_bin = self.env.firecracker_bin.display(),
                api_sock = inst.firecracker_sock.display(),
            )
        };

        // Spawn: setsid unshare --user --map-root-user --net [--mount] --mount-proc --fork --pid /bin/sh -c "..."
        // For snapshot restore, we also need --mount to get a private mount namespace
        // for the bind-mount trick.
        // stdout/stderr → serial.log (append)
        let serial_log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&inst.serial_log)
            .map_err(|e| {
                VmError::Io(format!(
                    "open serial log {}: {e}",
                    inst.serial_log.display()
                ))
            })?;

        let mut unshare_args: Vec<&str> = vec![
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            "--mount",
            "--mount-proc",
            "--fork",
            "--pid",
        ];
        if let Some(mut current_dir) = self.env.firecracker_bin.parent() {
            while let Some(parent) = current_dir.parent() {
                if let Some(path_str) = current_dir.to_str() {
                    let _ = Command::new("chmod").args(["a+rx", path_str]).status();
                }
                current_dir = parent;
                if current_dir.to_str() == Some("/") {
                    break;
                }
            }
        }

        unshare_args.extend(["/bin/sh", "-c", &inner_script]);

        // Pool mode: copy rootfs from the snapshot directory (durable copy) and
        // fix up permissions so the unshare namespace can access the file.
        if pool_mode && baked_rootfs.is_some() {
            if let Some(parent) = inst.rootfs_path.parent() {
                let _ = fs::create_dir_all(parent);
                if let Some(parent_str) = parent.to_str() {
                    let _ = Command::new("chmod")
                        .args(["-R", "777", parent_str])
                        .status();
                }
            }
            // Copy from the snapshot dir rootfs (durable copy), NOT from the
            // baked path which may reference a deleted seed instance directory.
            // The baked path is only used for the bind mount target inside unshare.
            let snapshot_src = self.snapshot_dir_rootfs(&inst.claw_type).ok_or_else(|| {
                VmError::Io(format!(
                    "snapshot durable rootfs missing for {} — re-run imagebuilder build --all",
                    inst.claw_type
                ))
            })?;
            fs::copy(&snapshot_src, &inst.rootfs_path).map_err(|e| {
                VmError::Io(format!(
                    "copy snapshot rootfs {} → {}: {e}",
                    snapshot_src.display(),
                    inst.rootfs_path.display()
                ))
            })?;
            if let Some(rootfs_str) = inst.rootfs_path.to_str() {
                let _ = Command::new("chmod").args(["777", rootfs_str]).status();
            }
        }

        // QW4: Pre-warm the snapshot mem file in the OS page cache in a background
        // thread, running in parallel with FC startup. This avoids a cold-disk
        // read of the 2.1GB mem.snapshot during load_snapshot (~3.7s → ~0.6s).
        let mem_warmup_thread = if use_snapshot {
            let mem_path_clone = snapshot_mem.clone();
            let timing_prefix_owned = timing_prefix.to_string();
            Some(std::thread::spawn(move || {
                let t = std::time::Instant::now();
                // Use dd to sequentially read the file into page cache.
                let _ = Command::new("dd")
                    .args([
                        &format!("if={}", mem_path_clone.display()),
                        "of=/dev/null",
                        "bs=4M",
                    ])
                    .status();
                tracing::info!(
                    "{} start_vm.mem_warmup: {}ms (background)",
                    timing_prefix_owned,
                    t.elapsed().as_millis()
                );
            }))
        } else {
            None
        };

        let t_unshare_spawn = std::time::Instant::now();
        let mut startup_guard = StartedVmGuard::new(self, inst);
        // SAFETY: pre_exec runs between fork() and exec(); only async-signal-safe
        // functions may be called. libc::setsid() is AS-safe (POSIX.1-2008 §2.4.3,
        // signal-safety(7)). No heap allocation or Rust runtime state is touched.
        let child = unsafe {
            Command::new(unshare_args[0])
                .args(&unshare_args[1..])
                .stdout(
                    serial_log_file
                        .try_clone()
                        .map_err(|e| VmError::Io(e.to_string()))?,
                )
                .stderr(serial_log_file)
                .pre_exec(|| {
                    // Create a new session so the VM survives parent exit.
                    // By calling setsid(2) here instead of using the `setsid` command,
                    // child.id() returns the PID of `unshare` directly, which means
                    // kill_pgrp(child.id()) can reliably kill the entire process tree.
                    // The `setsid` command sometimes forks (when already a session leader),
                    // causing child.id() to be a dead PID while the real processes escape.
                    libc::setsid();
                    Ok(())
                })
                .spawn()
                .map_err(|e| VmError::process_spawn_plain(format!("unshare spawn: {e}")))?
        };

        let fc_pid = child.id();
        inst.firecracker_pid = Some(fc_pid);
        startup_guard.set_fc_pid(fc_pid);
        // Persist ownership immediately after spawn. Any later failure can be
        // recovered by an outer guard or startup sweep even before this
        // function returns the PID to its caller.
        inst.save()?;
        tracing::info!(
            "{timing_prefix} start_vm.unshare_spawn: {}ms",
            t_unshare_spawn.elapsed().as_millis()
        );

        // Wait for the Firecracker API socket to appear (20s)
        let t_wait_fc_sock = std::time::Instant::now();
        FirecrackerClient::wait_for_socket(&inst.firecracker_sock, Duration::from_secs(20)).await?;
        tracing::info!(
            "{timing_prefix} start_vm.wait_fc_socket: {}ms",
            t_wait_fc_sock.elapsed().as_millis()
        );

        // Enable IP forwarding in the network namespace (required for
        // iptables FORWARD/MASQUERADE between tap0 and tap1).
        // Must be done from host as real root; sysctl inside user namespace
        // silently fails on /proc/sys/net/ipv4/ip_forward.
        let _ = crate::network::enable_ip_forward(fc_pid);

        // ── Configure VM via Firecracker API ─────────────────────────────────
        // Dual-TAP setup is prepared by the shared guest-net script. This
        // backend configures Firecracker and slirp around those devices.
        let fc = FirecrackerClient::new(inst.firecracker_sock.clone());

        // Wait for mem warmup to complete before load_snapshot reads the file.
        if let Some(thread) = mem_warmup_thread {
            let t_join = std::time::Instant::now();
            let _ = thread.join();
            let join_wait = t_join.elapsed().as_millis();
            if join_wait > 50 {
                tracing::info!(
                    "{timing_prefix} start_vm.mem_warmup_join_wait: {}ms (still loading)",
                    join_wait
                );
            } else {
                tracing::info!(
                    "{timing_prefix} start_vm.mem_warmup_already_done: {}ms",
                    join_wait
                );
            }
        }

        let t_vm_configure = std::time::Instant::now();
        if use_snapshot {
            // Snapshot restore: skip machine config / boot source / drives / etc.
            // The vmstate already encodes all of that. Just load the snapshot.
            tracing::info!(
                "{log_prefix} restoring VM from snapshot: {}",
                snapshot_vmstate.display()
            );
            fc.load_snapshot(
                &snapshot_vmstate.display().to_string(),
                &snapshot_mem.display().to_string(),
                false, // enable_diff_snapshots — false for simplicity
            )
            .await?;
            tracing::info!(
                "{timing_prefix} start_vm.load_snapshot: {}ms",
                t_vm_configure.elapsed().as_millis()
            );
        } else {
            // Full kernel boot path.
            let boot_args = core_rs::guest_net::firecracker_boot_args();
            fc.set_machine_config(cpu_cores, ram_mb).await?;
            fc.set_boot_source(&self.env.kernel_image.display().to_string(), &boot_args)
                .await?;
            fc.set_rootfs(&inst.rootfs_path.display().to_string(), false)
                .await?;
            fc.set_network_interface(
                core_rs::guest_net::FIRECRACKER_GUEST_IFACE,
                core_rs::guest_net::FIRECRACKER_TAP_NAME,
                core_rs::guest_net::FIRECRACKER_GUEST_MAC,
            )
            .await?;
            fc.start_instance().await?;
            tracing::info!(
                "{timing_prefix} start_vm.full_boot_configure: {}ms",
                t_vm_configure.elapsed().as_millis()
            );
        }

        if !is_pid_running(fc_pid) {
            return Err(VmError::Other(
                "firecracker exited after InstanceStart/load_snapshot".to_string(),
            ));
        }

        // ── Start slirp4netns — creates tap0 with --configure ────────────────
        // Slirp owns the shared guest-net slirp TAP and exposes host-side
        // forwards through its API socket.
        let slirp_log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&inst.slirp_log)
            .map_err(|e| {
                VmError::Io(format!("open slirp log {}: {e}", inst.slirp_log.display()))
            })?;

        let t_slirp_spawn = std::time::Instant::now();
        // SAFETY: pre_exec runs between fork() and exec(); only async-signal-safe
        // functions may be called. libc::setsid() is AS-safe (POSIX.1-2008 §2.4.3,
        // signal-safety(7)). No heap allocation or Rust runtime state is touched.
        let slirp_child = unsafe {
            Command::new(&slirp_bin)
                .args([
                    "--configure",
                    "--mtu=1500",
                    "--disable-host-loopback",
                    "--api-socket",
                    &inst.slirp_api_sock.display().to_string(),
                    &fc_pid.to_string(),
                    core_rs::guest_net::SLIRP_TAP_NAME,
                ])
                .stdout(
                    slirp_log_file
                        .try_clone()
                        .map_err(|e| VmError::Io(e.to_string()))?,
                )
                .stderr(slirp_log_file)
                .stdin(std::process::Stdio::null())
                .pre_exec(|| {
                    libc::setsid();
                    Ok(())
                })
                .spawn()
                .map_err(|e| VmError::process_spawn_plain(format!("slirp4netns spawn: {e}")))?
        };

        let slirp_pid = slirp_child.id();
        inst.slirp_pid = Some(slirp_pid);
        startup_guard.set_slirp_pid(slirp_pid);
        inst.save()?;
        tracing::info!(
            "{timing_prefix} start_vm.slirp_spawn: {}ms",
            t_slirp_spawn.elapsed().as_millis()
        );

        // Wait for slirp API socket (15s)
        let t_wait_slirp_sock = std::time::Instant::now();
        if let Err(elapsed) = core_rs::poll::poll_until_exists_async(
            &inst.slirp_api_sock,
            Duration::from_secs(15),
            Duration::from_millis(25),
        )
        .await
        {
            // NOTE: elapsed_ms fits trivially in u64 (u128 overflow requires ~585M years).
            #[allow(clippy::cast_possible_truncation)]
            let elapsed_ms_val = elapsed.as_millis() as u64;
            let phase_name = if pool_mode {
                "pool.start_vm.wait_slirp_socket"
            } else {
                "start_vm.wait_slirp_socket"
            };
            let ctx = crate::error::ErrorContext::with_phase(phase_name)
                .container(&inst.container)
                .timed_out()
                .elapsed_ms(elapsed_ms_val)
                .serial_log_from_file(&inst.serial_log)
                .slirp_log_from_file(&inst.slirp_log);
            let msg = if pool_mode {
                format!(
                    "pool slirp API socket did not appear: {}",
                    inst.slirp_api_sock.display()
                )
            } else {
                format!(
                    "slirp API socket did not appear: {}",
                    inst.slirp_api_sock.display()
                )
            };
            return Err(VmError::timeout(msg, ctx));
        }
        tracing::info!(
            "{timing_prefix} start_vm.wait_slirp_socket: {}ms",
            t_wait_slirp_sock.elapsed().as_millis()
        );

        if !is_pid_running(slirp_pid) {
            return Err(VmError::Other(
                "slirp4netns exited unexpectedly after spawn".to_string(),
            ));
        }

        // Wait for slirp API to be actually ready (socket exists but API may
        // not be processing requests yet).
        slirp_wait_ready(&inst.slirp_api_sock, Duration::from_secs(30))?;

        if pool_mode {
            // Pool mode: no hostfwds yet — ports are added by claim_from_pool().
            tracing::info!(
                "{log_prefix} pool VM {} ready (no hostfwds yet)",
                inst.container
            );
        } else {
            // Normal mode: add SSH port-forward via slirp API
            let t_hostfwd = std::time::Instant::now();
            let _ = slirp_add_hostfwd(&inst.slirp_api_sock, inst.ssh_port, 22)?;
            tracing::info!(
                "{timing_prefix} start_vm.slirp_hostfwd: {}ms",
                t_hostfwd.elapsed().as_millis()
            );
        }

        // Return the still-armed guard. The caller must either adopt the
        // durable PIDs into its own guard or retain this guard through its
        // post-start work before committing it.
        Ok(startup_guard)
    }

    // ── Warm pool ──────────────────────────────────────────────────────────

    /// Publish a warm entry only after the temporary hostfwd check completed.
    ///
    /// Keeping the Result at the storage boundary makes it impossible for a
    /// future fill branch to turn an add or cleanup failure into a warm slot.
    fn store_warm_entry_after_fill(
        pool: &mut crate::warm_pool::WarmPool,
        mut entry: crate::warm_pool::WarmEntry,
        binary_present: Result<bool, VmError>,
    ) -> Result<(), VmError> {
        entry.binary_present = binary_present?;
        pool.store(entry);
        Ok(())
    }

    /// Fill a warm pool slot for the given claw type.
    ///
    /// Creates a pool VM named `_warm-<claw_type>-0`, runs through `prepare_rootfs`
    /// and `start_vm(pool_mode=true)` (which includes the expensive `load_snapshot`),
    /// then stores the result in the global pool.
    ///
    /// This should be called in a background thread so it doesn't block the
    /// IPC dispatch loop.
    /// # Errors
    ///
    /// Returns an error if the pool VM cannot be created, booted, or stored.
    pub async fn fill_pool_slot(&self, claw_type: &str) -> Result<(), VmError> {
        use crate::warm_pool::{WarmEntry, WarmPool, global_pool, is_shutting_down};

        let _fill_guard = pool_fill_lock().lock().await;
        let container = WarmPool::container_name(claw_type, 0);
        let instance_dir = self.env.state_dir.join(&container);

        // Checkpoint: bail early if a drain/shutdown was requested.
        if is_shutting_down() {
            tracing::info!("[vmrunner-pool] fill for {claw_type} aborted: shutdown in progress");
            return Err(VmError::Other(format!(
                "pool fill aborted for {claw_type}: shutdown in progress"
            )));
        }

        tracing::info!("[vmrunner-pool] filling pool slot for {claw_type} → {container}");

        // If an old warm VM is still running (e.g. from a previous backend restart),
        // clean it up first.
        if instance_dir.join("instance.env").exists() {
            let mut old_inst = InstanceEnv::load_unchecked(&instance_dir)?;
            tracing::info!("[vmrunner-pool] cleaning up stale pool VM {container}");
            self.stop_vm(&mut old_inst)?;
            fs::remove_dir_all(&instance_dir).map_err(|e| {
                VmError::Io(format!(
                    "remove stale pool VM directory {}: {e}",
                    instance_dir.display()
                ))
            })?;
            // Let process teardown settle before immediately recreating the slot.
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        fs::create_dir_all(&instance_dir)
            .map_err(|e| VmError::Io(format!("create pool dir {}: {e}", instance_dir.display())))?;

        // RAII guard: cleans up the pool dir and kills processes if fill fails.
        let mut fill_guard = PoolFillGuard::new(instance_dir.clone());

        // Allocate a temporary SSH port (atomic reservation).
        let (ssh_port, _port_reservation) = cid::pick_ssh_port(&self.env.state_dir)?;

        let mut inst = InstanceEnv {
            container: container.clone(),
            customer: container.clone(),
            claw_type: claw_type.to_string(),
            host_port: 0, // no host port — not used until claimed
            ssh_port,
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

        // Persist instance.env before rootfs setup so startup sweep does not
        // treat the warm slot as an empty orphan and remove its directory.
        inst.save()?;

        // Prepare rootfs (copy golden image; skip debugfs if pubkey is pre-baked)
        let t_rootfs = std::time::Instant::now();
        self.prepare_rootfs(&inst, DEFAULT_CREATE_DISK_GB)?;
        tracing::info!(
            "[vmrunner-pool] prepare_rootfs done in {}ms",
            t_rootfs.elapsed().as_millis()
        );
        inst.save()?;

        // Checkpoint: bail before expensive start_vm if shutdown was requested.
        if is_shutting_down() {
            tracing::info!(
                "[vmrunner-pool] fill for {claw_type} aborted before start_vm: shutdown"
            );
            return Err(VmError::Other(format!(
                "pool fill aborted for {claw_type}: shutdown in progress"
            )));
        }

        // Start VM without port forwards — the FC process runs, VM is booted/restored,
        // but no slirp hostfwds are added yet. Ports are added at claim time.
        let t_start = std::time::Instant::now();
        let started_guard = self
            .start_vm(
                &mut inst,
                true,
                false,
                DEFAULT_CREATE_CPU_CORES,
                DEFAULT_CREATE_RAM_MB,
            )
            .await?;
        tracing::info!(
            "[vmrunner-pool] start_vm(pool_mode) done in {}ms",
            t_start.elapsed().as_millis()
        );

        // Register PIDs in the fill guard so rollback can kill them.
        if let Some(pid) = started_guard.firecracker_pid() {
            fill_guard.set_fc_pid(pid);
        }
        if let Some(pid) = started_guard.slirp_pid() {
            fill_guard.set_slirp_pid(pid);
        }
        started_guard.commit();

        // Verify FC is still alive after start.
        if let Some(pid) = inst.firecracker_pid {
            if !is_pid_running(pid) {
                return Err(VmError::Other(format!(
                    "pool VM {container} FC process died after start"
                )));
            }
        }

        // Checkpoint: bail before SSH check if shutdown was requested.
        if is_shutting_down() {
            tracing::info!(
                "[vmrunner-pool] fill for {claw_type} aborted before SSH check: shutdown"
            );
            return Err(VmError::Other(format!(
                "pool fill aborted for {claw_type}: shutdown in progress"
            )));
        }

        // Add a temporary SSH hostfwd, wait for SSH, check the claw binary,
        // then remove the hostfwd. This moves the binary check to fill time so
        // claim time doesn't need an SSH round-trip for the install check.
        let t_ssh = std::time::Instant::now();
        let ssh_check_timeout = 30;
        let binary_present: Result<bool, VmError> = {
            let (temp_port, _temp_port_reservation) = cid::pick_ssh_port(&self.env.state_dir)?;
            // Add temporary hostfwd
            let temp_hostfwd = slirp_add_hostfwd(&inst.slirp_api_sock, temp_port, 22);
            match temp_hostfwd {
                Ok(fwd_id) => {
                    // Wait for SSH (short timeout — VM is already booted)
                    match SshSession::wait_for_ssh(temp_port, &self.env.ssh_key, ssh_check_timeout)
                        .await
                    {
                        Ok(ssh) => {
                            let check_cmd = format!("test -x /usr/local/bin/{claw_type}");
                            let present = ssh.exec(&check_cmd).await.is_ok();
                            tracing::info!(
                                "[vmrunner-pool] binary check for {claw_type}: present={present} in {}ms",
                                t_ssh.elapsed().as_millis()
                            );

                            // Health check: verify DNS works inside the VM.
                            // A pool VM without DNS will fail to install any
                            // claw that needs to download packages.
                            let dns_cmd = "getent hosts github.com 2>/dev/null || nslookup github.com 2>/dev/null";
                            let dns_ok = ssh.exec(dns_cmd).await.is_ok();
                            let cleanup_verified = slirp_remove_hostfwd_verified(
                                &inst.slirp_api_sock,
                                temp_port,
                                22,
                                fwd_id,
                            );
                            if dns_ok {
                                tracing::info!("[vmrunner-pool] DNS check passed for {claw_type}");

                                // A leaked hostfwd poisons the SSH port pool.
                                if cleanup_verified {
                                    Ok(present)
                                } else {
                                    tracing::error!(
                                        "[vmrunner-pool] temp hostfwd on port {temp_port} could not be verified removed for {claw_type}; aborting fill so PoolFillGuard tears down the VM"
                                    );
                                    Err(VmError::HostfwdUncertain(format!(
                                        "pool VM {claw_type} temporary hostfwd cleanup was not verified after successful SSH/DNS checks"
                                    )))
                                }
                            } else {
                                tracing::warn!(
                                    "[vmrunner-pool] pool VM for {claw_type} has no DNS — discarding"
                                );
                                if cleanup_verified {
                                    // fill_guard RAII will kill FC/slirp and remove the dir.
                                    Err(VmError::Other(format!(
                                        "pool VM DNS check failed for {claw_type}: cannot resolve github.com"
                                    )))
                                } else {
                                    tracing::error!(
                                        "[vmrunner-pool] temp hostfwd on port {temp_port} could not be verified removed for {claw_type} (DNS fail path); aborting fill so PoolFillGuard tears down the VM"
                                    );
                                    Err(VmError::HostfwdUncertain(format!(
                                        "pool VM {claw_type} temporary hostfwd cleanup was not verified after DNS failure"
                                    )))
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "[vmrunner-pool] SSH check failed for {claw_type}: {e}, assuming binary absent"
                            );
                            // The hostfwd was successfully added but SSH
                            // failed — we must still remove the hostfwd to
                            // avoid leaking a bound port on the host.
                            if slirp_remove_hostfwd_verified(
                                &inst.slirp_api_sock,
                                temp_port,
                                22,
                                fwd_id,
                            ) {
                                Ok(false)
                            } else {
                                tracing::error!(
                                    "[vmrunner-pool] temp hostfwd on port {temp_port} could not be verified removed for {claw_type} (SSH fail path); aborting fill so PoolFillGuard tears down the VM"
                                );
                                Err(VmError::HostfwdUncertain(format!(
                                    "pool VM {claw_type} temporary hostfwd cleanup was not verified after SSH failure"
                                )))
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "[vmrunner-pool] temp hostfwd failed for {claw_type}; aborting fill so PoolFillGuard tears down the VM: {e}"
                    );
                    // Any add error is terminal for a pool fill. Even a
                    // non-ambiguous error must not publish a VM whose port
                    // state was not established and verified as empty.
                    Err(e)
                }
            }
        };

        let entry = WarmEntry {
            container: container.clone(),
            claw_type: claw_type.to_string(),
            inst,
            binary_present: false,
        };

        {
            let mut pool = global_pool()
                .lock()
                .map_err(|_| VmError::Other("warm pool mutex poisoned".into()))?;
            // Every hostfwd add/cleanup failure reaches this helper as an Err.
            // Only a VM whose temporary mapping was verified absent is stored;
            // otherwise PoolFillGuard tears it down on return.
            Self::store_warm_entry_after_fill(&mut pool, entry, binary_present)?;
        }

        // Disarm fill guard — slot is warm and stored in the pool.
        fill_guard.commit();

        tracing::info!("[vmrunner-pool] slot for {claw_type} is now warm ✓");
        Ok(())
    }

    /// Claim a warm pool VM and configure it for the given `VmConfig`.
    ///
    /// Steps:
    /// 1. Rename pool dir to the real container name.
    /// 2. Update `instance.env` with the real identity (container, customer, ports).
    /// 3. Add slirp port-forwards for the real SSH port and app port.
    /// 4. Wait for SSH (VM is already running — should be fast, ~1s).
    /// 5. Run `install_claw` (usually skipped for golden images).
    ///
    /// Returns a `VmCreateResult` like `create()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the pool directory cannot be renamed, SSH connection
    /// fails, or port forwarding setup fails.
    // NOTE: WarmEntry is consumed at claim time; passing by value makes ownership clear
    // even though individual fields are small (Copy/Clone). Changing to &WarmEntry would
    // complicate caller ownership at the point where the entry is taken from the pool mutex.
    #[allow(clippy::needless_pass_by_value)]
    pub async fn claim_from_pool(
        &self,
        entry: crate::warm_pool::WarmEntry,
        config: &VmConfig,
    ) -> Result<VmCreateResult, VmError> {
        use crate::installer::{InstallerConfig, get_installer};
        use crate::timing::PhaseTimer;

        let mut timer = PhaseTimer::new(&config.container);

        let old_dir = self.env.state_dir.join(&entry.container);
        let new_dir = self.env.state_dir.join(&config.container);

        tracing::info!(
            "[vmrunner-pool] claiming warm VM {} → {}",
            entry.container,
            config.container
        );

        // ── 1. Allocate SSH port (atomic reservation) ─────────────────────
        timer.start_phase("pool_alloc_ssh_port");
        let (ssh_port, _port_reservation) = cid::pick_ssh_port(&self.env.state_dir)?;

        // ── 2. Rename pool dir to real container name ──────────────────────
        timer.start_phase("pool_rename_dir");
        fs::rename(&old_dir, &new_dir).map_err(|e| {
            VmError::Io(format!(
                "rename pool dir {} → {}: {e}",
                old_dir.display(),
                new_dir.display()
            ))
        })?;

        // RAII guard: if claim fails after rename, kills processes and removes dir.
        let mut claim_guard = ClaimGuard::new(
            new_dir.clone(),
            entry.inst.firecracker_pid,
            entry.inst.slirp_pid,
        );

        // Rebuild inst from the new location (paths are dir-relative)
        let inst = InstanceEnv {
            container: config.container.clone(),
            customer: config.customer.clone(),
            claw_type: config.claw_type.clone(),
            host_port: 0,
            ssh_port,
            firecracker_pid: entry.inst.firecracker_pid,
            slirp_pid: entry.inst.slirp_pid,
            instance_dir: new_dir.clone(),
            rootfs_path: new_dir.join("rootfs.ext4"),
            firecracker_sock: new_dir.join("firecracker.sock"),
            slirp_api_sock: new_dir.join("slirp-api.sock"),
            serial_log: new_dir.join("serial.log"),
            slirp_log: new_dir.join("slirp.log"),
            customer_dir: config
                .customer_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        };
        inst.save()?;

        // Verify FC is still alive after rename
        if let Some(pid) = inst.firecracker_pid {
            if !is_pid_running(pid) {
                return Err(VmError::Other(format!(
                    "pool VM FC process {pid} died before claim could complete"
                )));
            }
        }

        // ── 3. Add SSH port-forward ─────────────────────────────────────
        timer.start_phase("pool_add_hostfwd");
        let _ = slirp_add_hostfwd(&inst.slirp_api_sock, ssh_port, 22)?;
        tracing::info!("[vmrunner-pool] port-forward added: ssh={ssh_port}",);

        // ── 4. Wait for SSH ────────────────────────────────────────────────
        timer.start_phase("pool_wait_ssh");
        tracing::info!(
            "[vmrunner-pool] waiting for SSH on {}:{}",
            config.container,
            ssh_port
        );
        let ssh =
            SshSession::wait_for_ssh_install(ssh_port, &self.env.ssh_key, self.env.ssh_wait_tries)
                .await?;

        // ── 5. Install claw (usually skipped — binary_present checked at fill time) ──
        timer.start_phase("pool_install_claw");
        let install_skipped = if entry.binary_present {
            // Binary was confirmed during fill — skip the SSH check entirely.
            tracing::info!(
                "[vmrunner-pool] FAST_PATH: binary_present from fill, skipping install check"
            );
            true
        } else {
            // Binary status unknown (fill SSH check failed) — fall back to runtime check.
            let installer = get_installer(&config.claw_type)
                .ok_or_else(|| VmError::UnsupportedClawType(config.claw_type.clone()))?;
            let install_config = InstallerConfig {
                customer: config.customer.clone(),
                claw_type: config.claw_type.clone(),
                golden_image_used: true,
                installers_dir: None,
            };
            let check_cmd = format!("test -x /usr/local/bin/{}", config.claw_type);
            if ssh.exec(&check_cmd).await.is_ok() {
                tracing::info!("[vmrunner-pool] FAST_PATH: binary present (fallback check)");
                true
            } else {
                tracing::warn!("[vmrunner-pool] SLOW_PATH: binary missing, running install");
                installer.install(&ssh, &install_config).await?;
                false
            }
        };
        timer.end_phase();

        // Install optional AI coding tools (best-effort, non-fatal)
        if !config.tools.is_empty() {
            timer.start_phase("pool_install_coding_tools");
            crate::tools_plan::install_coding_tools(&ssh, &config.tools).await;
            timer.end_phase();
        }

        // Write /root/.bashrc with theyOS prompt (fixes corrupted binary .bashrc)
        timer.start_phase("pool_write_bashrc");
        write_bashrc(&ssh, config).await;
        timer.end_phase();

        timer.log_summary();
        tracing::info!("[vmrunner-pool-timing-json] {}", timer.to_json_log());

        tracing::info!(
            "[vmrunner-pool] claimed {} (ssh=127.0.0.1:{})",
            config.container,
            ssh_port,
        );

        // Disarm claim guard — claim succeeded.
        claim_guard.commit();

        // Refill is NOT triggered here — the warm_pool_reconciler handles
        // all refill decisions based on budget.

        Ok(VmCreateResult {
            golden_image_used: true,
            install_skipped,
            phases: timer.phases().to_vec(),
            total_duration: timer.total_elapsed(),
        })
    }

    /// Stop a running VM: kill slirp and firecracker, remove sockets.
    ///
    /// Sends SIGTERM first (via process group kill), waits briefly, then
    /// escalates to SIGKILL if any process survives. This prevents orphan
    /// VMs from accumulating after cleanup.
    // NOTE: &self keeps this as a method for future extension and consistent API style.
    #[allow(clippy::unused_self)]
    fn stop_vm(&self, inst: &mut InstanceEnv) -> Result<(), VmError> {
        let mut changed = false;

        if let Some(slirp_pid) = inst.slirp_pid {
            if is_pid_running(slirp_pid) {
                kill_pid(slirp_pid);
                changed = true;
            }
        }
        if let Some(fc_pid) = inst.firecracker_pid {
            if is_pid_running(fc_pid) {
                // Kill process group first (matches: kill -- -"${FIRECRACKER_PID}")
                kill_pgrp(fc_pid);
                kill_pid(fc_pid);
                changed = true;
            }
        }

        // Give processes time to exit, then escalate to SIGKILL if needed.
        if changed {
            std::thread::sleep(Duration::from_millis(200));
            if let Some(fc_pid) = inst.firecracker_pid {
                if is_pid_running(fc_pid) {
                    tracing::warn!("[vmrunner] FC PID {fc_pid} survived SIGTERM, sending SIGKILL");
                    kill_pgrp_force(fc_pid);
                    kill_pid_force(fc_pid);
                }
            }
            if let Some(slirp_pid) = inst.slirp_pid {
                if is_pid_running(slirp_pid) {
                    tracing::warn!(
                        "[vmrunner] slirp PID {slirp_pid} survived SIGTERM, sending SIGKILL"
                    );
                    kill_pid_force(slirp_pid);
                }
            }
            // Give SIGKILL a short, bounded window to become observable before
            // declaring teardown complete. The kill helpers intentionally do
            // not hide their return values behind a false success here.
            std::thread::sleep(Duration::from_millis(100));
        }

        // Reap zombie children. The original Child handles were dropped after
        // spawn (only PIDs were kept), so terminated processes linger as zombies
        // until waitpid is called. WNOHANG ensures no blocking.
        if let Some(fc_pid) = inst.firecracker_pid {
            reap_pid(fc_pid);
        }
        if let Some(slirp_pid) = inst.slirp_pid {
            reap_pid(slirp_pid);
        }

        let fc_survives = inst.firecracker_pid.is_some_and(is_pid_running);
        let slirp_survives = inst.slirp_pid.is_some_and(is_pid_running);
        if fc_survives || slirp_survives {
            let survivors =
                format!("firecracker_survives={fc_survives}, slirp_survives={slirp_survives}");
            let marker_result = inst.mark_hostfwd_uncertain(&survivors);
            let save_result = inst.save();
            let persistence_error = marker_result
                .err()
                .or_else(|| save_result.err())
                .map(|error| format!("; quarantine persistence failed: {error}"))
                .unwrap_or_default();
            return Err(VmError::HostfwdUncertain(format!(
                "VM teardown did not prove all processes stopped ({survivors}){persistence_error}"
            )));
        }

        let _ = fs::remove_file(&inst.firecracker_sock);
        let _ = fs::remove_file(&inst.slirp_api_sock);

        // Persist the cleared state durably before removing quarantine. If
        // save fails or the process crashes here, the marker remains and the
        // unchecked startup path can retry cleanup without allowing reuse.
        inst.firecracker_pid = None;
        inst.slirp_pid = None;
        inst.save()?;
        inst.clear_hostfwd_uncertain()?;
        Ok(())
    }

    /// Persist the no-reuse marker before any teardown signal is sent.
    ///
    /// This is deliberately separate from `stop_vm`: ambiguous hostfwd
    /// callers invoke it first, so a crash between detection and teardown
    /// cannot leave an apparently reusable instance on disk.
    fn quarantine_before_teardown(inst: &InstanceEnv, reason: &str) -> Result<(), VmError> {
        inst.mark_hostfwd_uncertain(reason)
    }

    /// Verify that a freshly-booted VM is actually usable.
    ///
    /// Checks:
    /// 1. SSH echo round-trip (confirms the channel works end-to-end)
    /// 2. DNS resolution (confirms slirp DNS forwarding works — needed for installers)
    ///
    /// Networking check (iptables DNAT) is implicitly covered by the fact that
    /// SSH is already working at this point.
    ///
    /// Returns `VmError::Other` if any check fails, which triggers `CreateGuard`
    /// rollback and surfaces a clear error to the caller.
    // NOTE: &self keeps this as a method for future extension and consistent API style.
    #[allow(clippy::unused_self)]
    async fn health_check_vm(
        &self,
        ssh: &SshSession,
        container: &str,
        instance_dir: &std::path::Path,
    ) -> Result<(), VmError> {
        tracing::info!("[vmrunner] health_check: starting for {container}");

        // 1. Basic SSH round-trip
        ssh.exec("echo ok").await.map_err(|e| {
            let ctx = crate::error::ErrorContext::with_phase("health_check.ssh_echo")
                .container(container)
                .command("echo ok")
                .serial_log_from_file(&instance_dir.join("serial.log"))
                .slirp_log_from_file(&instance_dir.join("slirp.log"));
            VmError::ssh_exec(
                format!("health_check SSH echo failed for {container}: {e}"),
                ctx,
            )
        })?;

        // 2. DNS resolution — required for installers that download from GitHub
        let dns_cmd = "getent hosts github.com || nslookup github.com || host github.com";
        let dns_ok = ssh.exec(dns_cmd).await.is_ok();
        if !dns_ok {
            let ctx = crate::error::ErrorContext::with_phase("health_check.dns")
                .container(container)
                .command(dns_cmd)
                .serial_log_from_file(&instance_dir.join("serial.log"))
                .slirp_log_from_file(&instance_dir.join("slirp.log"));
            return Err(VmError::ssh_exec(
                format!(
                    "health_check DNS resolution failed for {container}: \
                     cannot reach github.com — check slirp4netns"
                ),
                ctx,
            ));
        }

        tracing::info!("[vmrunner] health_check: {container} passed");
        Ok(())
    }

    /// Sweep for orphaned instance directories and clean them up.
    ///
    /// An instance is considered orphaned if:
    ///   - Its `instance.env` has a FC PID, but that process is no longer running, OR
    ///   - Its directory exists but has no `instance.env` (partial create with no state)
    ///
    /// Called on startup to clean up state left by crashed or interrupted creates.
    ///
    /// Returns a summary of what was cleaned up.
    pub fn sweep_orphans(&self) -> SweepReport {
        let mut report = SweepReport::default();

        let Ok(entries) = fs::read_dir(&self.env.state_dir) else {
            return report;
        };

        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let name = dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let env_path = dir.join("instance.env");

            // Warm pool VMs from a previous backend process are always stale —
            // the in-memory pool state was lost when the old process exited.
            // Kill processes and remove the directory only after teardown is
            // verified. A quarantine marker must never be treated as a reason
            // to discard the evidence before the survivor is gone.
            if name.starts_with("_warm-") {
                if env_path.exists() {
                    match InstanceEnv::load_unchecked(&dir) {
                        Ok(mut inst) => {
                            tracing::warn!(
                                "[vmrunner-sweep] killing stale warm-pool VM {name} \
                                 (fc_pid={:?}, slirp_pid={:?})",
                                inst.firecracker_pid,
                                inst.slirp_pid,
                            );
                            match self.stop_vm(&mut inst) {
                                Ok(()) => match fs::remove_dir_all(&dir) {
                                    Ok(()) => report.instances_cleaned += 1,
                                    Err(e) => tracing::warn!(
                                        "[vmrunner-sweep] failed to remove stopped warm dir {name}: {e}"
                                    ),
                                },
                                Err(e) => tracing::warn!(
                                    "[vmrunner-sweep] preserving warm dir {name} until teardown is verified: {e}"
                                ),
                            }
                        }
                        Err(e) => {
                            let marker_error = persist_hostfwd_uncertain_marker(
                                &dir,
                                "instance.env could not be parsed; process ownership requires recovery",
                            )
                            .err();
                            tracing::warn!(
                                "[vmrunner-sweep] preserving warm dir {name}; cannot load state for cleanup: {e}; marker_error={marker_error:?}"
                            );
                        }
                    }
                } else {
                    let _ = fs::remove_dir_all(&dir);
                    report.dirs_removed += 1;
                }
                continue;
            }

            if !env_path.exists() {
                // Directory with no instance.env — leftover from a very early
                // failed create (before state was saved).
                tracing::warn!(
                    "[vmrunner-sweep] removing dir with no instance.env: {}",
                    dir.display()
                );
                let _ = fs::remove_dir_all(&dir);
                report.dirs_removed += 1;
                continue;
            }

            let mut inst = match InstanceEnv::load(&dir) {
                Ok(i) => i,
                Err(VmError::HostfwdUncertain(_)) => {
                    let mut quarantined = match InstanceEnv::load_unchecked(&dir) {
                        Ok(i) => i,
                        Err(e) => {
                            tracing::warn!(
                                "[vmrunner-sweep] cannot load quarantined instance.env for {name}: {e}"
                            );
                            continue;
                        }
                    };
                    if let Err(e) = self.stop_vm(&mut quarantined) {
                        tracing::warn!(
                            "[vmrunner-sweep] quarantined instance {name} still needs teardown: {e}"
                        );
                    } else {
                        report.instances_cleaned += 1;
                    }
                    continue;
                }
                Err(e) => {
                    tracing::warn!("[vmrunner-sweep] cannot load instance.env for {name}: {e}");
                    continue;
                }
            };

            // Check if FC process is dead while instance is supposed to be running
            let fc_dead = inst.firecracker_pid.is_some_and(|pid| !is_pid_running(pid));

            if fc_dead {
                tracing::warn!(
                    "[vmrunner-sweep] orphaned instance {name}: FC PID {:?} is dead, killing processes",
                    inst.firecracker_pid
                );
                // Use stop_vm() instead of do_cleanup(): kills PIDs and clears them in
                // instance.env, but preserves the directory so restart() can still load
                // the config and reuse the rootfs after a reboot/power loss.
                if let Err(e) = self.stop_vm(&mut inst) {
                    tracing::warn!("[vmrunner-sweep] stop_vm for {name} failed (continuing): {e}");
                }
                report.instances_cleaned += 1;
                report.cleaned_containers.push(name);
            }
        }

        // Process-level sweep: kill any process whose cmdline references a
        // _warm-* path. This catches orphan FC/slirp/unshare from claimed
        // instances that were renamed but whose processes kept the old path.
        for claw in crate::warm_pool::WarmPool::all_claw_types() {
            let warm_dir = self.env.state_dir.join(format!("_warm-{claw}-0"));
            let warm_dir_str = warm_dir.display().to_string();
            let killed = core_rs::os::kill_processes_referencing_path(&warm_dir_str);
            if killed > 0 {
                tracing::warn!(
                    "[vmrunner-sweep] killed {killed} orphan process(es) referencing _warm-{claw}-0"
                );
                report.instances_cleaned += killed;
            }
        }

        if report.instances_cleaned > 0 || report.dirs_removed > 0 {
            tracing::info!(
                "[vmrunner-sweep] cleaned {} orphaned instances, {} empty dirs",
                report.instances_cleaned,
                report.dirs_removed
            );
        } else {
            tracing::info!("[vmrunner-sweep] no orphans found");
        }

        report
    }

    /// Drain the warm pool: kill all pre-warmed VMs and clear their slots.
    ///
    /// Called during graceful shutdown so that warm-pool VMs don't survive
    /// as orphan processes after the backend exits.
    ///
    /// Returns the number of VMs killed.
    ///
    /// # Panics
    ///
    /// Panics if the warm pool mutex is poisoned (another thread panicked
    /// while holding the lock).
    pub fn drain_warm_pool(&self) -> usize {
        use crate::warm_pool::{global_pool, signal_shutdown};

        // 1. Signal in-flight fill tasks to abort at the next checkpoint.
        signal_shutdown();

        // 2. Drain all slots (warm + filling) from the in-memory pool.
        let entries = {
            let mut pool = global_pool()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pool.drain_all()
        };

        let mut drained = 0;

        // 3. Kill processes and remove directories for warm entries.
        for entry in &entries {
            tracing::info!(
                "[vmrunner-drain] killing warm-pool VM {} (fc_pid={:?}, slirp_pid={:?})",
                entry.container,
                entry.inst.firecracker_pid,
                entry.inst.slirp_pid,
            );
            let dir = self.env.state_dir.join(&entry.container);
            if create_guard::do_cleanup(&dir, entry.inst.firecracker_pid, entry.inst.slirp_pid) {
                drained += 1;
            } else {
                tracing::error!(
                    "[vmrunner-drain] preserving warm-pool VM {} because teardown was not verified",
                    entry.container
                );
            }
        }

        // 4. Safety net: sweep _warm-* directories on disk that may not be in
        //    the in-memory pool (e.g. from a filling task that crashed or was
        //    cancelled before it could store its entry).
        if let Ok(rd) = fs::read_dir(&self.env.state_dir) {
            for dir_entry in rd.flatten() {
                let path = dir_entry.path();
                if !path.is_dir() {
                    continue;
                }
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if !name.starts_with("_warm-") {
                    continue;
                }
                // Skip directories we already cleaned up above.
                if entries.iter().any(|e| e.container == name) {
                    continue;
                }
                tracing::info!("[vmrunner-drain] cleaning up orphaned warm dir: {name}");
                if let Ok(inst) = InstanceEnv::load_unchecked(&path) {
                    if create_guard::do_cleanup(&path, inst.firecracker_pid, inst.slirp_pid) {
                        drained += 1;
                    } else {
                        tracing::error!(
                            "[vmrunner-drain] preserving orphaned warm dir {name} because teardown was not verified"
                        );
                    }
                } else if !path.join("instance.env").exists()
                    && !path
                        .join(crate::instance_env::HOSTFWD_UNCERTAIN_MARKER)
                        .exists()
                {
                    // A fill can leave an empty warm directory before the
                    // first durable instance.env save. No child ownership has
                    // been established in that state, so it is safe to remove.
                    if let Err(e) = fs::remove_dir_all(&path) {
                        tracing::warn!(
                            "[vmrunner-drain] failed to remove empty warm dir {name}: {e}"
                        );
                    } else {
                        drained += 1;
                    }
                } else {
                    let marker_error = persist_hostfwd_uncertain_marker(
                        &path,
                        "instance.env could not be parsed during warm-pool drain",
                    )
                    .err();
                    tracing::error!(
                        "[vmrunner-drain] preserving warm dir {name}; state cannot be loaded and process ownership is unverified; marker_error={marker_error:?}"
                    );
                }
            }
        }

        // 5. Process-level sweep: kill any process whose cmdline still
        //    references a _warm-* path. This catches orphan FC/slirp/unshare
        //    processes from claimed instances whose directories were renamed
        //    but whose processes still have the original path in argv.
        for claw in crate::warm_pool::WarmPool::all_claw_types() {
            let warm_dir = self.env.state_dir.join(format!("_warm-{claw}-0"));
            let warm_dir_str = warm_dir.display().to_string();
            let killed = core_rs::os::kill_processes_referencing_path(&warm_dir_str);
            if killed > 0 {
                tracing::info!(
                    "[vmrunner-drain] killed {killed} orphan process(es) referencing _warm-{claw}-0"
                );
                drained += killed;
            }
        }

        if drained > 0 {
            tracing::info!("[vmrunner-drain] drained {drained} warm-pool VM(s)");
        }
        drained
    }
}

#[cfg(unix)]
fn align_snapshot_dir_owner(snapshot_dir: &Path, instance_dir: &Path) -> Result<(), VmError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    if core_rs::os::geteuid() != 0 {
        return Ok(());
    }

    let owner = fs::metadata(instance_dir).map_err(|e| {
        VmError::Io(format!(
            "read instance dir owner {}: {e}",
            instance_dir.display()
        ))
    })?;
    let path = CString::new(snapshot_dir.as_os_str().as_bytes()).map_err(|_| {
        VmError::Io(format!(
            "snapshot dir path contains NUL: {}",
            snapshot_dir.display()
        ))
    })?;

    // The Firecracker process that owns the API socket may be running as the
    // service account while a maintenance command is invoked via sudo. In that
    // case root creates the snapshot directory, but Firecracker must write the
    // vmstate/memory files into it. Align the empty directory with the running
    // instance owner before calling /snapshot/create.
    let rc = unsafe { libc::chown(path.as_ptr(), owner.uid(), owner.gid()) };
    if rc != 0 {
        return Err(VmError::Io(format!(
            "chown snapshot dir {} to {}:{}: {}",
            snapshot_dir.display(),
            owner.uid(),
            owner.gid(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

#[cfg(not(unix))]
fn align_snapshot_dir_owner(_snapshot_dir: &Path, _instance_dir: &Path) -> Result<(), VmError> {
    Ok(())
}

/// Report returned by `sweep_orphans`.
#[derive(Debug, Default)]
pub struct SweepReport {
    pub instances_cleaned: usize,
    pub dirs_removed: usize,
    /// Container names of non-warm-pool instances whose FC process was dead.
    /// These are candidates for DB reconciliation (marking as Stopped).
    pub cleaned_containers: Vec<String>,
}

// ── Re-exports for backwards compatibility ─────────────────────────────────

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
