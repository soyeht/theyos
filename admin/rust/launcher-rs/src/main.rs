//! theyos-admin-host — Admin backend launcher (replaces run-backend-host.sh).
//!
//! Responsibilities:
//!   1. Load `.env` from the repo root (same precedence as the shell script:
//!      env vars already set take priority, then `.env`, then hardcoded defaults).
//!   2. Apply all defaults for every env var the server and its IPC subprocesses
//!      need.
//!   3. Resolve `slirp4netns` from PATH or `/nix/store`.
//!   4. Run preflight checks with clear error messages:
//!      - `SOYEHT_ADMIN_PASSWORD` must be non-empty
//!      - `FIRECRACKER_CTL` binary must exist and be executable
//!      - `/dev/kvm` device should exist (warning only)
//!      - openclaw binary check (warning only)
//!   5. `exec` the `server` binary, passing the fully-populated environment.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

#[cfg(target_os = "macos")]
use std::process::Command;

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug)]
enum LaunchError {
    MissingPassword(PathBuf),
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    MissingFcSsh(PathBuf),
    ServerBinaryNotFound(PathBuf),
    ExecFailed(std::io::Error),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaunchError::MissingPassword(env_file) => write!(
                f,
                "SOYEHT_ADMIN_PASSWORD is empty; set it in {}",
                env_file.display()
            ),
            LaunchError::MissingFcSsh(path) => write!(
                f,
                "Firecracker control binary not found or not executable: {}",
                path.display()
            ),
            LaunchError::ServerBinaryNotFound(path) => write!(
                f,
                "Rust server binary not found: {}\n  Build with: cd admin/rust && cargo build",
                path.display()
            ),
            LaunchError::ExecFailed(e) => write!(f, "exec failed: {e}"),
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        std::process::exit(0);
    }

    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("[theyos-admin-host][error] {e}");
            std::process::exit(1);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run() -> Result<(), LaunchError> {
    use std::os::unix::process::CommandExt;
    let repo_root = core_rs::path::resolve_repo_root().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    let env_file = repo_root.join(".env");

    // 1. Load .env into a map (only keys not already set in the process env)
    let dotenv = load_dotenv(&env_file);

    // Helper: read from process env first, then .env map, then fallback.
    let env_or = |key: &str, fallback: &str| -> String {
        env_val(key, &dotenv).unwrap_or_else(|| fallback.to_string())
    };
    let env_opt = |key: &str| -> Option<String> { env_val(key, &dotenv) };

    // 2. Build the full environment the server needs.
    let admin_port = env_or("ADMIN_PORT", "8892");
    let addr = env_opt("ADDR").unwrap_or_else(|| format!("0.0.0.0:{admin_port}"));
    let frontend_origin = env_or("FRONTEND_ORIGIN", "http://localhost:5173");
    let admin_user = env_or("SOYEHT_ADMIN_USER", "admin");
    let admin_password = env_opt("SOYEHT_ADMIN_PASSWORD").unwrap_or_default();
    let claw_runtime = env_or("CLAW_RUNTIME", "firecracker");
    // Default `CLAW_TYPES` to the full set from the compile-time manifest.
    // Previously hardcoded — went stale whenever a new claw (e.g.
    // hermes-agent, noclaw) was added to claws/manifest.yml without
    // someone also updating this string, causing the registry to miss
    // the new type at boot. Manifest is now the single source of truth.
    let claw_types_default: String = core_rs::manifest::all_names().join(",");
    let claw_types = env_or("CLAW_TYPES", &claw_types_default);

    // Prefer THEYOS_BIN_DIR (NixOS), then release (production), then debug (development).
    let rust_release_dir = repo_root.join("admin/rust/target/release");
    let rust_debug_dir = repo_root.join("admin/rust/target/debug");
    let env_bin_dir_buf;
    let rust_bin_dir = if let Some(d) = env_val("THEYOS_BIN_DIR", &dotenv) {
        let p = PathBuf::from(&d);
        if p.join("server").is_file() {
            env_bin_dir_buf = p;
            &env_bin_dir_buf
        } else {
            eprintln!(
                "[theyos-admin-host] warning: THEYOS_BIN_DIR={d} has no server binary, ignoring"
            );
            if rust_release_dir.join("server").is_file() {
                &rust_release_dir
            } else {
                &rust_debug_dir
            }
        }
    } else if rust_release_dir.join("server").is_file() {
        &rust_release_dir
    } else {
        &rust_debug_dir
    };
    let fc_ctl = env_or(
        "FIRECRACKER_CTL",
        &rust_bin_dir.join("fc-ssh").to_string_lossy(),
    );
    let theyos_home = env_or(
        "THEYOS_HOME",
        &repo_root.parent().unwrap_or(&repo_root).to_string_lossy(),
    );

    let claw = resolve_claw_env(&repo_root, &dotenv);
    let infra = resolve_infra_env(&repo_root, rust_bin_dir, &dotenv);

    // 3. Preflight checks
    preflight_checks(
        &admin_password,
        &env_file,
        &PathBuf::from(&fc_ctl),
        &claw_types,
        &claw.openclaw_binary,
        &claw.openclaw_code,
        &repo_root,
    )?;

    #[cfg(target_os = "macos")]
    ensure_tailscale_https_for_pairing(&admin_port);

    // 3b. macOS: check theyos-ssh is available for terminal sessions
    #[cfg(target_os = "macos")]
    {
        let ssh_ctl_path = PathBuf::from(&infra.ssh_ctl);
        if !ssh_ctl_path.as_os_str().is_empty() && !is_executable(&ssh_ctl_path) {
            eprintln!(
                "[theyos-admin-host] warning: theyos-ssh not found: {} — terminal sessions will fail",
                ssh_ctl_path.display()
            );
        }
    }

    // 4. Locate server binary
    let server_bin = rust_bin_dir.join("server");
    if !is_executable(&server_bin) {
        return Err(LaunchError::ServerBinaryNotFound(server_bin));
    }
    eprintln!(
        "[theyos-admin-host] using Rust server: {}",
        server_bin.display()
    );

    // 5. Build final env and exec
    let env = build_env_vec(
        addr,
        frontend_origin,
        admin_user,
        admin_password,
        claw_runtime,
        claw_types,
        fc_ctl,
        theyos_home,
        claw,
        infra,
    );

    // Set each var in the current process (exec inherits the full env)
    for (k, v) in &env {
        // SAFETY: This runs in main() before any threads are spawned;
        // exec() replaces the process immediately after, so no data races.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(k, v);
        };
    }

    // exec — replaces current process with server
    let err = std::process::Command::new(&server_bin).exec();
    Err(LaunchError::ExecFailed(err))
}

// ─── Env resolution helpers ───────────────────────────────────────────────────

/// Assemble the flat key=value vec that gets applied to the process environment
/// before `exec`-ing the server binary.
#[allow(clippy::too_many_arguments)]
fn build_env_vec(
    addr: String,
    frontend_origin: String,
    admin_user: String,
    admin_password: String,
    claw_runtime: String,
    claw_types: String,
    fc_ctl: String,
    theyos_home: String,
    claw: ClawEnv,
    infra: InfraEnv,
) -> Vec<(String, String)> {
    vec![
        ("ADDR".into(), addr),
        ("FRONTEND_ORIGIN".into(), frontend_origin),
        ("SOYEHT_ADMIN_USER".into(), admin_user),
        ("SOYEHT_ADMIN_PASSWORD".into(), admin_password),
        ("CLAW_RUNTIME".into(), claw_runtime),
        ("CLAW_TYPES".into(), claw_types),
        ("FIRECRACKER_CTL".into(), fc_ctl),
        ("THEYOS_HOME".into(), theyos_home),
        ("OPENCLAW_BINARY".into(), claw.openclaw_binary),
        ("ZEROCLAW_BINARY".into(), claw.zeroclaw_binary),
        ("NANOBOT_BINARY".into(), claw.nanobot_binary),
        ("PICOCLAW_BINARY".into(), claw.picoclaw_binary),
        ("PICOCLAW_CODE_DIR".into(), claw.picoclaw_code),
        ("ZEROCLAW_CODE_DIR".into(), claw.zeroclaw_code),
        ("NANOBOT_CODE_DIR".into(), claw.nanobot_code),
        ("OPENCLAW_CODE_DIR".into(), claw.openclaw_code),
        ("NULLCLAW_CODE_DIR".into(), claw.nullclaw_code),
        ("IRONCLAW_CODE_DIR".into(), claw.ironclaw_code),
        ("PICOCLAW_DATA_DIR".into(), claw.picoclaw_data),
        ("ZEROCLAW_DATA_DIR".into(), claw.zeroclaw_data),
        ("NANOBOT_DATA_DIR".into(), claw.nanobot_data),
        ("OPENCLAW_DATA_DIR".into(), claw.openclaw_data),
        ("NULLCLAW_DATA_DIR".into(), claw.nullclaw_data),
        ("IRONCLAW_DATA_DIR".into(), claw.ironclaw_data),
        ("PICOCLAW_HOST_BASE_DIR".into(), claw.picoclaw_host),
        ("ZEROCLAW_HOST_BASE_DIR".into(), claw.zeroclaw_host),
        ("NANOBOT_HOST_BASE_DIR".into(), claw.nanobot_host),
        ("OPENCLAW_HOST_BASE_DIR".into(), claw.openclaw_host),
        ("NULLCLAW_HOST_BASE_DIR".into(), claw.nullclaw_host),
        ("IRONCLAW_HOST_BASE_DIR".into(), claw.ironclaw_host),
        ("THEYOS_BASE_DOMAIN".into(), infra.base_domain),
        ("THEYOS_SQLITE_DB".into(), infra.sqlite_db),
        ("CADDY_ADMIN_URL".into(), infra.caddy_admin_url),
        ("THEYOS_JOB_WORKERS".into(), infra.job_workers),
        ("THEYOS_BACKUP_DIR".into(), infra.backup_dir),
        ("THEYOS_ORCHESTRATOR_RS_BIN".into(), infra.orchestrator_bin),
        ("THEYOS_VMRUNNER_RS_BIN".into(), infra.vmrunner_bin),
        ("THEYOS_STORE_RS_BIN".into(), infra.store_bin),
        ("THEYOS_TERMINAL_RS_BIN".into(), infra.terminal_bin),
        ("FIRECRACKER_STATE_DIR".into(), infra.fc_state_dir),
        ("FIRECRACKER_BIN".into(), infra.fc_bin),
        ("FIRECRACKER_KERNEL_IMAGE".into(), infra.fc_kernel),
        ("FIRECRACKER_BASE_ROOTFS".into(), infra.fc_rootfs),
        ("FIRECRACKER_SSH_KEY".into(), infra.fc_ssh_key),
        ("FIRECRACKER_SSH_PUBKEY".into(), infra.fc_ssh_pubkey),
        ("FIRECRACKER_SSH_WAIT_TRIES".into(), infra.fc_ssh_wait),
        ("SLIRP4NETNS_BIN".into(), infra.slirp),
        ("WEB_DIR".into(), infra.web_dir),
        ("THEYOS_SSH_CTL".into(), infra.ssh_ctl),
        ("THEYOS_VM_ASSETS_DIR".into(), infra.vm_assets_dir),
        ("THEYOS_SESSION_PEPPER".into(), infra.session_pepper),
        ("THEYOS_SESSION_TTL_SECS".into(), infra.session_ttl),
    ]
}

/// Resolved claw binaries, code dirs, data dirs, and host base dirs.
struct ClawEnv {
    openclaw_binary: String,
    zeroclaw_binary: String,
    nanobot_binary: String,
    picoclaw_binary: String,
    picoclaw_code: String,
    zeroclaw_code: String,
    nanobot_code: String,
    openclaw_code: String,
    nullclaw_code: String,
    ironclaw_code: String,
    picoclaw_data: String,
    zeroclaw_data: String,
    nanobot_data: String,
    openclaw_data: String,
    nullclaw_data: String,
    ironclaw_data: String,
    picoclaw_host: String,
    zeroclaw_host: String,
    nanobot_host: String,
    openclaw_host: String,
    nullclaw_host: String,
    ironclaw_host: String,
}

fn resolve_claw_env(repo_root: &Path, dotenv: &HashMap<String, String>) -> ClawEnv {
    let env_or = |key: &str, fallback: &str| -> String {
        env_val(key, dotenv).unwrap_or_else(|| fallback.to_string())
    };
    let env_opt = |key: &str| -> Option<String> { env_val(key, dotenv) };

    // Claw binaries (optional — read from env/.env only)
    let openclaw_binary = env_opt("OPENCLAW_BINARY").unwrap_or_default();
    let zeroclaw_binary = env_opt("ZEROCLAW_BINARY").unwrap_or_default();
    let nanobot_binary = env_opt("NANOBOT_BINARY").unwrap_or_default();
    let picoclaw_binary = env_opt("PICOCLAW_BINARY").unwrap_or_default();

    // Code dirs.
    // On macOS with VZ, claw source code lives inside the VM image — not on the host.
    // The registry only checks that the directory exists, so we default to stub dirs
    // under ~/.theyos/claws/<name>/ and create them if missing.
    #[cfg(target_os = "macos")]
    let code_dir_base = {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        std::path::PathBuf::from(home).join(".theyos/claws")
    };
    #[cfg(not(target_os = "macos"))]
    let code_dir_base = repo_root.join("claws/src");

    // Ensure stub dirs exist on macOS.
    #[cfg(target_os = "macos")]
    for name in &[
        "picoclaw", "zeroclaw", "nanobot", "openclaw", "nullclaw", "ironclaw",
    ] {
        let _ = std::fs::create_dir_all(code_dir_base.join(name));
    }

    let picoclaw_code = env_or(
        "PICOCLAW_CODE_DIR",
        &code_dir_base.join("picoclaw").to_string_lossy(),
    );
    let zeroclaw_code = env_or(
        "ZEROCLAW_CODE_DIR",
        &code_dir_base.join("zeroclaw").to_string_lossy(),
    );
    let nanobot_code = env_or(
        "NANOBOT_CODE_DIR",
        &code_dir_base.join("nanobot").to_string_lossy(),
    );
    let openclaw_code = env_or(
        "OPENCLAW_CODE_DIR",
        &code_dir_base.join("openclaw").to_string_lossy(),
    );
    let nullclaw_code = env_or(
        "NULLCLAW_CODE_DIR",
        &code_dir_base.join("nullclaw").to_string_lossy(),
    );
    let ironclaw_code = env_or(
        "IRONCLAW_CODE_DIR",
        &code_dir_base.join("ironclaw").to_string_lossy(),
    );

    // Data dirs
    let claws_data = repo_root.join("claws/data");
    let picoclaw_data = env_or(
        "PICOCLAW_DATA_DIR",
        &claws_data.join("picoclaw").to_string_lossy(),
    );
    let zeroclaw_data = env_or(
        "ZEROCLAW_DATA_DIR",
        &claws_data.join("zeroclaw").to_string_lossy(),
    );
    let nanobot_data = env_or(
        "NANOBOT_DATA_DIR",
        &claws_data.join("nanobot").to_string_lossy(),
    );
    let openclaw_data = env_or(
        "OPENCLAW_DATA_DIR",
        &claws_data.join("openclaw").to_string_lossy(),
    );
    let nullclaw_data = env_or(
        "NULLCLAW_DATA_DIR",
        &claws_data.join("nullclaw").to_string_lossy(),
    );
    let ironclaw_data = env_or(
        "IRONCLAW_DATA_DIR",
        &claws_data.join("ironclaw").to_string_lossy(),
    );

    // Host base dirs (same as data dirs by default)
    let picoclaw_host = env_or("PICOCLAW_HOST_BASE_DIR", &picoclaw_data);
    let zeroclaw_host = env_or("ZEROCLAW_HOST_BASE_DIR", &zeroclaw_data);
    let nanobot_host = env_or("NANOBOT_HOST_BASE_DIR", &nanobot_data);
    let openclaw_host = env_or("OPENCLAW_HOST_BASE_DIR", &openclaw_data);
    let nullclaw_host = env_or("NULLCLAW_HOST_BASE_DIR", &nullclaw_data);
    let ironclaw_host = env_or("IRONCLAW_HOST_BASE_DIR", &ironclaw_data);

    ClawEnv {
        openclaw_binary,
        zeroclaw_binary,
        nanobot_binary,
        picoclaw_binary,
        picoclaw_code,
        zeroclaw_code,
        nanobot_code,
        openclaw_code,
        nullclaw_code,
        ironclaw_code,
        picoclaw_data,
        zeroclaw_data,
        nanobot_data,
        openclaw_data,
        nullclaw_data,
        ironclaw_data,
        picoclaw_host,
        zeroclaw_host,
        nanobot_host,
        openclaw_host,
        nullclaw_host,
        ironclaw_host,
    }
}

/// Resolved IPC binary paths, Firecracker assets, slirp, and core infra vars.
struct InfraEnv {
    base_domain: String,
    sqlite_db: String,
    caddy_admin_url: String,
    job_workers: String,
    backup_dir: String,
    orchestrator_bin: String,
    vmrunner_bin: String,
    store_bin: String,
    terminal_bin: String,
    fc_state_dir: String,
    fc_bin: String,
    fc_kernel: String,
    fc_rootfs: String,
    fc_ssh_key: String,
    fc_ssh_pubkey: String,
    fc_ssh_wait: String,
    slirp: String,
    web_dir: String,
    ssh_ctl: String,
    vm_assets_dir: String,
    session_pepper: String,
    session_ttl: String,
}

#[allow(clippy::too_many_lines)]
fn resolve_infra_env(
    repo_root: &Path,
    rust_debug_dir: &Path,
    dotenv: &HashMap<String, String>,
) -> InfraEnv {
    let env_or = |key: &str, fallback: &str| -> String {
        env_val(key, dotenv).unwrap_or_else(|| fallback.to_string())
    };
    let env_opt = |key: &str| -> Option<String> { env_val(key, dotenv) };

    // Core infra
    // THEYOS_BASE_DOMAIN (or legacy CF_DOMAIN) is required — no hardcoded default.
    // Forks must set this in .env to their own domain.
    let base_domain = env_val("THEYOS_BASE_DOMAIN", dotenv)
        .or_else(|| env_val("CF_DOMAIN", dotenv))
        .unwrap_or_default();
    let run_dir = repo_root.join(".run");
    let sqlite_db = env_or(
        "THEYOS_SQLITE_DB",
        &run_dir.join("theyos.db").to_string_lossy(),
    );
    let caddy_admin_url = env_or("CADDY_ADMIN_URL", "http://localhost:2019");
    let job_workers = env_or("THEYOS_JOB_WORKERS", "1");
    let backup_dir = env_or(
        "THEYOS_BACKUP_DIR",
        &run_dir.join("backups").to_string_lossy(),
    );

    // IPC binaries
    let orchestrator_bin = env_or(
        "THEYOS_ORCHESTRATOR_RS_BIN",
        &rust_debug_dir.join("orchestrator-ipc").to_string_lossy(),
    );
    #[cfg(target_os = "macos")]
    let vmrunner_default = "vmrunner_macos_ipc";
    #[cfg(not(target_os = "macos"))]
    let vmrunner_default = "vmrunner_ipc";
    let vmrunner_bin = env_or(
        "THEYOS_VMRUNNER_RS_BIN",
        &rust_debug_dir.join(vmrunner_default).to_string_lossy(),
    );
    let store_bin = env_or(
        "THEYOS_STORE_RS_BIN",
        &rust_debug_dir.join("store-ipc").to_string_lossy(),
    );
    let terminal_bin = env_or(
        "THEYOS_TERMINAL_RS_BIN",
        &rust_debug_dir.join("terminal-ipc").to_string_lossy(),
    );

    // Firecracker assets (use $HOME from the real process environment)
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let fc_home = PathBuf::from(&home).join("firecracker");
    let fc_state_dir = env_or(
        "FIRECRACKER_STATE_DIR",
        &fc_home.join("instances").to_string_lossy(),
    );
    let fc_bin = env_or(
        "FIRECRACKER_BIN",
        &fc_home.join("bin/firecracker").to_string_lossy(),
    );
    let fc_kernel = env_or(
        "FIRECRACKER_KERNEL_IMAGE",
        &fc_home
            .join(format!("assets/{}", core_rs::guest_net::KERNEL_FILENAME))
            .to_string_lossy(),
    );
    let fc_rootfs = env_or(
        "FIRECRACKER_BASE_ROOTFS",
        &fc_home
            .join("assets/ubuntu-24.04-rootfs-v2.ext4")
            .to_string_lossy(),
    );
    let fc_ssh_key = env_or(
        "FIRECRACKER_SSH_KEY",
        &fc_home
            .join("assets/ubuntu-24.04-root.id_rsa")
            .to_string_lossy(),
    );
    let fc_ssh_pubkey = env_or(
        "FIRECRACKER_SSH_PUBKEY",
        &fc_home
            .join("assets/ubuntu-24.04-root.id_rsa.pub")
            .to_string_lossy(),
    );
    let fc_ssh_wait = env_or("FIRECRACKER_SSH_WAIT_TRIES", "30");

    // slirp4netns
    let slirp = env_opt("SLIRP4NETNS_BIN")
        .filter(|s| !s.is_empty() && Path::new(s).is_file())
        .or_else(resolve_slirp4netns)
        .unwrap_or_default();

    let web_dir = env_or("WEB_DIR", &repo_root.join("admin/web").to_string_lossy());

    // On macOS, default SSH wrapper to theyos-ssh (VZ VMs); on Linux, fc-ssh (Firecracker).
    #[cfg(target_os = "macos")]
    let ssh_ctl_default = "theyos-ssh";
    #[cfg(not(target_os = "macos"))]
    let ssh_ctl_default = "fc-ssh";
    let ssh_ctl = env_or(
        "THEYOS_SSH_CTL",
        &rust_debug_dir.join(ssh_ctl_default).to_string_lossy(),
    );

    // macOS: base VM images directory (picoclaw-base.raw, etc.).
    // On macOS, default to ~/Library/Application Support/theyos/vms (user-writable, no sudo).
    // On Linux, fall back to /usr/local/share/theyos/vms (system-wide).
    #[cfg(target_os = "macos")]
    let vm_assets_default = format!("{home}/Library/Application Support/theyos/vms");
    #[cfg(not(target_os = "macos"))]
    let vm_assets_default = "/usr/local/share/theyos/vms".to_string();
    let vm_assets_dir = env_or("THEYOS_VM_ASSETS_DIR", &vm_assets_default);

    // Session signing pepper — must be non-empty in production.
    let session_pepper = env_opt("THEYOS_SESSION_PEPPER").unwrap_or_default();
    let session_ttl = env_or("THEYOS_SESSION_TTL_SECS", "2592000");

    InfraEnv {
        base_domain,
        sqlite_db,
        caddy_admin_url,
        job_workers,
        backup_dir,
        orchestrator_bin,
        vmrunner_bin,
        store_bin,
        terminal_bin,
        fc_state_dir,
        fc_bin,
        fc_kernel,
        fc_rootfs,
        fc_ssh_key,
        fc_ssh_pubkey,
        fc_ssh_wait,
        slirp,
        web_dir,
        ssh_ctl,
        vm_assets_dir,
        session_pepper,
        session_ttl,
    }
}

/// Run preflight checks; return `Err` for fatal conditions, print warnings for soft issues.
fn preflight_checks(
    admin_password: &str,
    env_file: &Path,
    fc_ctl_path: &Path,
    claw_types: &str,
    openclaw_binary: &str,
    openclaw_code: &str,
    repo_root: &Path,
) -> Result<(), LaunchError> {
    if admin_password.is_empty() {
        return Err(LaunchError::MissingPassword(env_file.to_path_buf()));
    }

    #[cfg(target_os = "macos")]
    let _ = fc_ctl_path; // macOS uses theyos-ssh, not fc-ssh; checked separately after preflight

    #[cfg(not(target_os = "macos"))]
    if !is_executable(fc_ctl_path) {
        return Err(LaunchError::MissingFcSsh(fc_ctl_path.to_path_buf()));
    }

    #[cfg(not(target_os = "macos"))]
    if !Path::new("/dev/kvm").exists() {
        eprintln!("[theyos-admin-host] warning: /dev/kvm is missing; Firecracker create will fail");
    }

    if claw_types.contains("openclaw")
        && openclaw_binary.is_empty()
        && !Path::new(openclaw_code).join("openclaw").is_file()
        && !repo_root.join("claws/src/openclaw/openclaw").exists()
    {
        eprintln!(
            "[theyos-admin-host] warning: openclaw has no local binary; \
             set OPENCLAW_BINARY for openclaw create support"
        );
    }

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Parse a `.env` file and return key→value pairs, skipping comments and
/// blank lines. Strips surrounding quotes from values.
fn load_dotenv(path: &Path) -> HashMap<String, String> {
    core_rs::env::load_dotenv(path)
}

/// Returns a value from the process environment or the dotenv map.
fn env_val(key: &str, dotenv: &HashMap<String, String>) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| dotenv.get(key).cloned().filter(|v| !v.is_empty()))
}

/// Returns true if the path points to an executable file.
fn is_executable(path: &Path) -> bool {
    core_rs::os::is_executable(path)
}

/// Try to find `slirp4netns` via the shared resolver.
fn resolve_slirp4netns() -> Option<String> {
    let result = core_rs::os::resolve_slirp4netns().map(|p| p.to_string_lossy().into_owned());
    if result.is_none() {
        eprintln!(
            "[theyos-admin-host] warning: slirp4netns not found; VM create will fail (set SLIRP4NETNS_BIN)"
        );
    }
    result
}

#[cfg(target_os = "macos")]
fn ensure_tailscale_https_for_pairing(admin_port: &str) {
    if std::env::var("THEYOS_DISABLE_AUTO_TAILSCALE_SERVE")
        .ok()
        .is_some_and(|v| v == "1")
    {
        eprintln!(
            "[theyos-admin-host] tailscale auto-serve disabled by THEYOS_DISABLE_AUTO_TAILSCALE_SERVE=1"
        );
        return;
    }

    let Some(tailscale_bin) = core_rs::network_detect::find_tailscale_cli() else {
        return;
    };

    let Ok(status_output) = Command::new(&tailscale_bin)
        .args(["status", "--json"])
        .output()
    else {
        eprintln!("[theyos-admin-host] warning: could not inspect tailscale status");
        return;
    };
    if !status_output.status.success() {
        return;
    }

    let Ok(status_json) = serde_json::from_slice::<serde_json::Value>(&status_output.stdout) else {
        eprintln!("[theyos-admin-host] warning: could not parse tailscale status JSON");
        return;
    };

    let Some(hostname) = tailscale_https_hostname(&status_json) else {
        return;
    };

    match current_tailscale_serve_state(&tailscale_bin, admin_port) {
        TailscaleServeState::MatchesBackend => return,
        TailscaleServeState::OtherConfig => {
            eprintln!(
                "[theyos-admin-host] tailscale serve already configured; leaving existing config untouched"
            );
            return;
        }
        TailscaleServeState::Unknown => {
            eprintln!(
                "[theyos-admin-host] warning: could not inspect tailscale serve config; skipping auto-configuration"
            );
            return;
        }
        TailscaleServeState::Missing => {}
    }

    let Ok(enable_output) = Command::new(&tailscale_bin)
        .args(["serve", "--yes", "--bg", admin_port])
        .output()
    else {
        eprintln!("[theyos-admin-host] warning: failed to run tailscale serve");
        return;
    };

    if enable_output.status.success() {
        eprintln!("[theyos-admin-host] enabled tailscale HTTPS pairing at https://{hostname}/");
    } else {
        let stderr = String::from_utf8_lossy(&enable_output.stderr);
        eprintln!(
            "[theyos-admin-host] warning: tailscale serve setup failed: {}",
            stderr.trim()
        );
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TailscaleServeState {
    Missing,
    MatchesBackend,
    OtherConfig,
    Unknown,
}

#[cfg(target_os = "macos")]
fn current_tailscale_serve_state(tailscale_bin: &str, admin_port: &str) -> TailscaleServeState {
    let json_output = Command::new(tailscale_bin)
        .args(["serve", "status", "--json"])
        .output();

    if let Ok(output) = json_output {
        if output.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                if !tailscale_serve_has_any_config(&json) {
                    return TailscaleServeState::Missing;
                }
                if tailscale_serve_matches_backend(&json, "443", "127.0.0.1", admin_port)
                    || tailscale_serve_matches_backend(&json, "443", "localhost", admin_port)
                {
                    return TailscaleServeState::MatchesBackend;
                }
                return TailscaleServeState::OtherConfig;
            }
        }
    }

    let text_output = Command::new(tailscale_bin)
        .args(["serve", "status"])
        .output();
    if let Ok(output) = text_output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stdout.contains("No serve config") || stderr.contains("No serve config") {
            return TailscaleServeState::Missing;
        }
    }

    TailscaleServeState::Unknown
}

#[cfg(target_os = "macos")]
fn tailscale_https_hostname(status_json: &serde_json::Value) -> Option<String> {
    let hostname = status_json
        .get("Self")
        .and_then(|self_node| self_node.get("DNSName"))
        .and_then(serde_json::Value::as_str)
        .map(|name| name.trim_end_matches('.').to_string())?;

    let has_cert = status_json
        .get("CertDomains")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|domains| {
            domains
                .iter()
                .any(|value| value.as_str() == Some(hostname.as_str()))
        });

    has_cert.then_some(hostname)
}

#[cfg(target_os = "macos")]
fn tailscale_serve_has_any_config(serve_json: &serde_json::Value) -> bool {
    serve_json
        .get("TCP")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|tcp| !tcp.is_empty())
        || serve_json
            .get("Web")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|web| !web.is_empty())
}

#[cfg(target_os = "macos")]
fn tailscale_serve_matches_backend(
    serve_json: &serde_json::Value,
    external_port: &str,
    backend_host: &str,
    backend_port: &str,
) -> bool {
    let https_ok = serve_json
        .get("TCP")
        .and_then(|tcp| tcp.get(external_port))
        .and_then(|port| port.get("HTTPS"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);

    if !https_ok {
        return false;
    }

    let expected_proxy = format!("http://{backend_host}:{backend_port}");
    serve_json
        .get("Web")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|web| {
            web.values().any(|entry| {
                entry
                    .get("Handlers")
                    .and_then(|handlers| handlers.get("/"))
                    .and_then(|root| root.get("Proxy"))
                    .and_then(serde_json::Value::as_str)
                    == Some(expected_proxy.as_str())
            })
        })
}

fn print_usage() {
    println!(
        "Usage: theyos-admin-host [--help]

Loads .env, applies defaults, validates preflight conditions, then
execs the Rust admin server binary.

Environment (read from .env or process env):
  SOYEHT_ADMIN_PASSWORD   required — admin panel password
  ADMIN_PORT              default: 8892
  ADDR                    default: 0.0.0.0:<ADMIN_PORT>
  FRONTEND_ORIGIN         default: http://localhost:5173
  CLAW_RUNTIME            default: firecracker
  CLAW_TYPES              default: picoclaw,zeroclaw,nanobot,openclaw,nullclaw,ironclaw
  FIRECRACKER_CTL         default: <repo>/admin/rust/target/debug/fc-ssh
  THEYOS_HOME             default: parent of repo root
  THEYOS_SQLITE_DB        default: <repo>/.run/theyos.db
  CADDY_ADMIN_URL         default: http://localhost:2019
  THEYOS_JOB_WORKERS      default: 1
  THEYOS_BACKUP_DIR       default: <repo>/.run/backups
  SLIRP4NETNS_BIN         auto-resolved from PATH or /nix/store
  WEB_DIR                 default: <repo>/admin/web
  FIRECRACKER_*           Firecracker asset paths (defaulted to ~/firecracker/)
  THEYOS_*_RS_BIN         IPC subprocess binaries (defaulted to debug build)
"
    );
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core_rs::env::{remove_test_env, set_test_env};
    #[cfg(target_os = "macos")]
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn load_dotenv_parses_key_value() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "FOO=bar").unwrap();
        writeln!(f, "QUOTED=\"hello world\"").unwrap();
        writeln!(f, "SINGLE='value'").unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "EMPTY=").unwrap();
        let map = load_dotenv(f.path());
        assert_eq!(map.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(map.get("QUOTED").map(String::as_str), Some("hello world"));
        assert_eq!(map.get("SINGLE").map(String::as_str), Some("value"));
        assert!(!map.contains_key("# comment"));
        // EMPTY has empty value — not inserted (filtered in env_val)
        assert_eq!(map.get("EMPTY").map(String::as_str), Some(""));
    }

    #[test]
    fn load_dotenv_missing_file_returns_empty() {
        let map = load_dotenv(Path::new("/tmp/nonexistent-launcher-rs-test.env"));
        assert!(map.is_empty());
    }

    #[test]
    fn env_val_prefers_process_env_over_dotenv() {
        let key = "LAUNCHER_RS_TEST_PREF";
        set_test_env(key, "from_process");
        let mut map = HashMap::new();
        map.insert(key.to_string(), "from_dotenv".to_string());
        assert_eq!(env_val(key, &map).as_deref(), Some("from_process"));
        remove_test_env(key);
    }

    #[test]
    fn env_val_falls_back_to_dotenv() {
        let key = "LAUNCHER_RS_TEST_FALLBACK";
        remove_test_env(key);
        let mut map = HashMap::new();
        map.insert(key.to_string(), "from_dotenv".to_string());
        assert_eq!(env_val(key, &map).as_deref(), Some("from_dotenv"));
    }

    #[test]
    fn env_val_returns_none_when_absent() {
        let key = "LAUNCHER_RS_TEST_ABSENT_XYZ";
        remove_test_env(key);
        let map = HashMap::new();
        assert_eq!(env_val(key, &map), None);
    }

    #[test]
    fn env_val_ignores_empty_process_env_falls_back_to_dotenv() {
        let key = "LAUNCHER_RS_TEST_EMPTY_PROC";
        set_test_env(key, "");
        let mut map = HashMap::new();
        map.insert(key.to_string(), "dotenv_value".to_string());
        assert_eq!(env_val(key, &map).as_deref(), Some("dotenv_value"));
        remove_test_env(key);
    }

    #[test]
    fn is_executable_on_existing_executable() {
        // /bin/sh should always be executable
        assert!(is_executable(Path::new("/bin/sh")));
    }

    #[test]
    fn is_executable_on_missing_path() {
        assert!(!is_executable(Path::new(
            "/tmp/nonexistent-launcher-test-bin"
        )));
    }

    #[test]
    fn is_executable_on_non_executable_file() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "data").unwrap();
        // NamedTempFile is created with 0600 by default — not executable
        assert!(!is_executable(f.path()));
    }

    #[test]
    fn repo_root_contains_admin_dir() {
        // When running tests inside the workspace, resolve_repo_root() should resolve
        // to the actual repo root which contains admin/.
        let root = core_rs::path::resolve_repo_root().unwrap();
        assert!(
            root.join("admin").is_dir(),
            "resolve_repo_root() = {root:?} does not contain admin/",
        );
    }

    #[test]
    fn print_usage_does_not_panic() {
        print_usage();
    }

    #[test]
    fn launch_error_display_missing_password() {
        let e = LaunchError::MissingPassword(PathBuf::from("/repo/.env"));
        let s = e.to_string();
        assert!(s.contains("SOYEHT_ADMIN_PASSWORD"));
        assert!(s.contains("/repo/.env"));
    }

    #[test]
    fn launch_error_display_missing_fc_ssh() {
        let e = LaunchError::MissingFcSsh(PathBuf::from("/usr/bin/fc-ssh"));
        let s = e.to_string();
        assert!(s.contains("fc-ssh"));
    }

    #[test]
    fn launch_error_display_server_not_found() {
        let e = LaunchError::ServerBinaryNotFound(PathBuf::from(
            "/repo/admin/rust/target/debug/server",
        ));
        let s = e.to_string();
        assert!(s.contains("cargo build"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn tailscale_https_hostname_uses_matching_cert_domain() {
        let status = json!({
            "Self": {
                "DNSName": "host.tail1234.ts.net."
            },
            "CertDomains": ["host.tail1234.ts.net"]
        });

        assert_eq!(
            tailscale_https_hostname(&status).as_deref(),
            Some("host.tail1234.ts.net")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn tailscale_https_hostname_requires_cert_domain() {
        let status = json!({
            "Self": {
                "DNSName": "host.tail1234.ts.net."
            },
            "CertDomains": []
        });

        assert_eq!(tailscale_https_hostname(&status), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn tailscale_serve_matches_backend_detects_expected_proxy() {
        let serve = json!({
            "TCP": {
                "443": {
                    "HTTPS": true
                }
            },
            "Web": {
                "host.tail1234.ts.net:443": {
                    "Handlers": {
                        "/": {
                            "Proxy": "http://127.0.0.1:8892"
                        }
                    }
                }
            }
        });

        assert!(tailscale_serve_has_any_config(&serve));
        assert!(tailscale_serve_matches_backend(
            &serve,
            "443",
            "127.0.0.1",
            "8892"
        ));
        assert!(!tailscale_serve_matches_backend(
            &serve,
            "443",
            "127.0.0.1",
            "7777"
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn tailscale_serve_has_any_config_false_for_empty_json() {
        let serve = json!({});
        assert!(!tailscale_serve_has_any_config(&serve));
    }
}
