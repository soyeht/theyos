//! `init_macos_guest` — Initialize or remove the macOS guest base image.
//!
//! # Usage
//!
//! ```text
//! init_macos_guest [OPTIONS]
//! init_macos_guest remove
//! ```
//!
//! # Phases
//!
//! 1. `DownloadIpsw` — fetch IPSW URL from Apple + download (~12 GB)
//! 2. `CreateDisk` — create 64 GB sparse disk image
//! 3. `InstallMacOS` — `VZMacOSInstaller` (~20 min)
//! 4. Provision — inject SSH keys, launchd plists, claw binaries into APFS
//! 5. `CreateSnapshot` — boot VM, pause, save `.vzsnapshot`
//! 6. Complete — base image ready; subsequent calls are no-ops
//!
//! Resumable: re-running after interruption continues from the last saved phase.

#![cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, unused_imports, clippy::all, clippy::pedantic)
)]

use clap::{Parser, Subcommand};
use core_rs::ipc::client::IpcClient;
use serde_json::json;
use std::path::PathBuf;
use vmrunner_common_rs::{MacOsPrepareRequest, MacOsProvisionAndSnapshotRequest};

const VMRUNNER_ENV: &str = "THEYOS_VMRUNNER_RS_BIN";
const LEGACY_VMRUNNER_ENV: &str = "THEYOS_VMRUNNER_MACOS_RS_BIN";

/// Initialize or remove the macOS guest base image for theyOS.
#[derive(Parser)]
#[command(name = "init_macos_guest")]
#[command(version)]
#[command(about = "Initialize the macOS guest base image (IPSW download + install + provision)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Local IPSW path or direct Apple restore-image URL (skip latest-supported lookup)
    #[arg(long)]
    ipsw: Option<String>,

    /// Force re-initialization from scratch (deletes existing base image)
    #[arg(long)]
    force: bool,

    /// Force re-provisioning only (re-injects binaries/SSH keys, rebuilds snapshot; skips macOS install)
    #[arg(long)]
    force_provision: bool,

    /// Skip confirmation prompts
    #[arg(long, short = 'y')]
    yes: bool,

    /// CPU count for the base VM (default: 4)
    #[arg(long, default_value = "4")]
    cpus: u32,

    /// Memory in MB for the base VM (default: 4096)
    #[arg(long, default_value = "4096")]
    memory_mb: u32,

    /// URL to darwin/arm64 claw binary registry (e.g. <https://binaries.theyos.io/darwin-arm64>)
    #[arg(long, env = "THEYOS_CLAW_BINARIES_URL", default_value = "")]
    registry_url: String,

    /// Path to `vmrunner_macos_ipc` binary (default: `THEYOS_VMRUNNER_RS_BIN` env)
    #[arg(long, env = "THEYOS_VMRUNNER_RS_BIN")]
    vmrunner_bin: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Remove the macOS base image and all associated files
    Remove {
        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Show current initialization status
    Status,
}

#[cfg(target_os = "macos")]
fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Commands::Remove { yes }) => cmd_remove(yes),
        Some(Commands::Status) => cmd_status(&cli),
        None => cmd_init(&cli),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

// ── init (default) ────────────────────────────────────────────────────────────

fn cmd_init(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Safety check: --force requires confirmation unless --yes
    if cli.force && !cli.yes {
        eprint!(
            "WARNING: --force will delete and recreate the macOS base image (~64 GB disk + ~12 GB IPSW).\n\
             This takes ~30 min. Continue? [y/N] "
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!("=== theyOS macOS Guest Initialization ===");
    println!();
    println!("Requirements:");
    println!("  - macOS 14 (Sonoma) or later");
    println!("  - Apple Silicon (M1/M2/M3)");
    println!("  - ~100 GB free disk space");
    println!("  - ~30 min for first-time setup");
    println!();

    let client = build_client(cli.vmrunner_bin.as_deref())?;

    // ── Step 1: Prepare (download + disk + install) ─────────────────────────
    // No sudo needed — can take 30+ min.
    if cli.force_provision {
        println!("Step 1/3: Skipped (--force-provision).");
    } else {
        println!("Step 1/3: Preparing macOS image (download + install)...");
        println!("(This will take ~30 min on first run — please wait)");
        println!();

        let prepare_params = MacOsPrepareRequest {
            force: cli.force,
            force_provision: false,
            ipsw: cli.ipsw.clone(),
            registry_url: cli.registry_url.clone(),
        }
        .to_value();

        let response = client
            .call("MacOsPrepare", prepare_params)
            .map_err(|e| ipc_error_message(&e.to_string()))?;

        match response.get("status").and_then(|s| s.as_str()) {
            Some("already_complete") => {
                println!("macOS base image is already initialized.");
                if let Some(dir) = response.get("base_dir").and_then(|v| v.as_str()) {
                    println!("Base directory: {dir}");
                }
                println!(
                    "Run with --force to reinitialize, or --force-provision to rebuild the snapshot."
                );
                return Ok(());
            }
            Some("ready_for_provision") => {
                println!("Preparation complete. Ready for provisioning.");
            }
            _ => {
                return Err(format!("Unexpected MacOsPrepare response: {response:?}").into());
            }
        }
    }

    // ── Step 2: Provision (privileged helper) ───────────────────────────────
    // Re-prime sudo NOW — right before the privileged operation.
    // This eliminates the cache expiry problem: download+install can take
    // 30+ min (far exceeding the 5 min sudo cache), but we re-prompt here.
    println!();
    println!("Step 2/3: Provisioning disk image (requires admin password)...");

    prime_sudo()?;

    // The IPC handler calls inject_provision_files() which delegates to
    // sudo theyos-provision-inject. Since we just primed sudo, the -n flag works.

    // ── Step 3: Provision + Snapshot (single boot) ──────────────────────────
    println!();
    println!("Step 3/3: Creating base snapshot (single boot + SSH + software)...");
    println!();

    let snapshot_params = MacOsProvisionAndSnapshotRequest {
        cpus: Some(cli.cpus),
        memory_mb: Some(cli.memory_mb),
        force_provision: cli.force_provision,
        plist_dir: Some(resolve_plist_dir()),
        ..Default::default()
    }
    .to_value();

    let response = client
        .call("MacOsProvisionAndSnapshot", snapshot_params)
        .map_err(|e| ipc_error_message(&e.to_string()))?;

    match response.get("status").and_then(|s| s.as_str()) {
        Some("complete") => {
            println!("macOS base image initialized successfully.");
            if let Some(dir) = response.get("base_dir").and_then(|v| v.as_str()) {
                println!("Base directory: {dir}");
            }
            if let Some(version) = response.get("macos_version").and_then(|v| v.as_str()) {
                println!("macOS version: {version}");
            }
            if let Some(snapshot) = response.get("snapshot_path").and_then(|v| v.as_str()) {
                println!("Snapshot: {snapshot}");
            }
            println!();
            println!("You can now create macOS claw instances:");
            println!(
                "  POST /instances/create {{\"type\": \"picoclaw\", \"guest_os\": \"macos\"}}"
            );
        }
        _ => {
            return Err(
                format!("Unexpected MacOsProvisionAndSnapshot response: {response:?}").into(),
            );
        }
    }

    Ok(())
}

/// Prime sudo credentials interactively (we have terminal access).
fn prime_sudo() -> Result<(), Box<dyn std::error::Error>> {
    let sudo_ok = std::process::Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .is_ok_and(|s| s.success());
    if !sudo_ok {
        println!("Admin privileges are required to configure the VM.");
        let sudo_status = std::process::Command::new("sudo")
            .arg("-v")
            .status()
            .map_err(|e| format!("sudo -v failed: {e}"))?;
        if !sudo_status.success() {
            return Err(
                "sudo authentication failed. Cannot proceed without admin privileges.".into(),
            );
        }
    }
    Ok(())
}

/// Resolve the plist directory for `LaunchDaemon` templates.
fn resolve_plist_dir() -> String {
    // 1. THEYOS_DIR/scripts/launchd (Homebrew or dev with THEYOS_DIR set)
    if let Ok(dir) = std::env::var("THEYOS_DIR") {
        let p = PathBuf::from(&dir).join("scripts/launchd");
        if p.is_dir() {
            return p.display().to_string();
        }
    }
    // 2. Relative to current exe (dev: target/release/../../../scripts/launchd)
    if let Ok(exe) = std::env::current_exe() {
        // exe is in admin/rust/target/release/ or libexec/
        if let Some(rust_dir) = exe.parent().and_then(|p| p.parent()) {
            let p = rust_dir.join("../../scripts/launchd");
            if p.is_dir() {
                return p.display().to_string();
            }
        }
    }
    // 3. Fallback
    "scripts/launchd".to_string()
}

/// Compute the default serial log path for a given init phase.
///
/// Format IPC error messages with helpful hints.
fn ipc_error_message(msg: &str) -> String {
    if msg.contains("github.com/soyeht/theyos/issues/new") {
        return msg.to_string();
    }

    if msg.contains("software update") || msg.contains("Software Update") {
        format!(
            "{msg}\n\n\
             theyOS first tries to find a restore image that matches this Mac automatically.\n\
             If you still see this error, a compatible signed restore image was not found.\n\
             Update your Mac in System Settings → General → Software Update,\n\
             or run the command again with --ipsw /path/to/UniversalMac_<version>_<build>_Restore.ipsw."
        )
    } else {
        format!("IPC call failed: {msg}")
    }
}

// ── remove ────────────────────────────────────────────────────────────────────

fn cmd_remove(yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !yes {
        eprint!(
            "WARNING: This will remove the macOS base image and all associated files.\n\
             Any cloned macOS VMs will continue running but cannot be reprovisioned.\n\
             Continue? [y/N] "
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = build_client(None)?;

    println!("Removing macOS base image...");

    let response = client
        .call("RemoveMacOsBase", json!({}))
        .map_err(|e| format!("IPC call failed: {e}"))?;

    if response
        .get("removed")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        let bytes = response
            .get("bytes_freed")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        println!("Removed. Freed {} GB.", bytes / (1024 * 1024 * 1024));
    } else {
        let note = response
            .get("note")
            .and_then(|v| v.as_str())
            .unwrap_or("no response");
        println!("Nothing to remove: {note}");
    }

    Ok(())
}

// ── status ────────────────────────────────────────────────────────────────────

fn cmd_status(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let client = build_client(cli.vmrunner_bin.as_deref())?;

    let response = client
        .call("MacOsSlotStatus", json!({}))
        .map_err(|e| format!("IPC call failed: {e}"))?;

    println!("=== macOS VM Slot Status ===");
    println!(
        "Available: {}/{} slots",
        response
            .get("available")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        response
            .get("total")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(2),
    );
    println!(
        "In use: {}",
        response
            .get("in_use")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    );

    // Check if base image is initialized
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let base_state = PathBuf::from(&home)
        .join("Library/Application Support/theyos/vms/macos-base/init-state.json");

    if base_state.exists() {
        println!();
        println!("Base image: initialized");
        println!("  State file: {}", base_state.display());
        if let Ok(content) = std::fs::read_to_string(&base_state) {
            if let Ok(state) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(phase) = state.get("phase").and_then(|v| v.as_str()) {
                    println!("  Phase: {phase}");
                }
                if let Some(version) = state.get("macos_version").and_then(|v| v.as_str()) {
                    println!("  macOS version: {version}");
                }
                if let Some(host_version) = state.get("host_macos_version").and_then(|v| v.as_str())
                {
                    if let Some(host_build) = state.get("host_macos_build").and_then(|v| v.as_str())
                    {
                        println!("  Host macOS: {host_version} ({host_build})");
                    } else {
                        println!("  Host macOS: {host_version}");
                    }
                }
                if let Some(ipsw_build) = state.get("ipsw_build").and_then(|v| v.as_str()) {
                    println!("  Restore build: {ipsw_build}");
                }
                if let Some(source) = state.get("ipsw_source").and_then(|v| v.as_str()) {
                    println!("  Restore source: {source}");
                }
            }
        }
    } else {
        println!();
        println!("Base image: NOT initialized");
        println!("  Run `init_macos_guest` to initialize.");
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Spawn the `vmrunner_macos_ipc` subprocess and return an `IpcClient`.
///
/// Binary path resolution order:
/// 1. `bin_path` argument (from --vmrunner-bin CLI flag)
/// 2. `THEYOS_VMRUNNER_RS_BIN` environment variable
/// 3. Legacy `THEYOS_VMRUNNER_MACOS_RS_BIN` environment variable
/// 4. Same directory as the running binary
/// 5. Default: `./target/release/vmrunner_macos_ipc` (dev fallback)
fn build_client(bin_path: Option<&str>) -> Result<IpcClient, Box<dyn std::error::Error>> {
    let resolved = resolve_vmrunner_bin_path(bin_path);

    IpcClient::start(&resolved, &[]).map_err(|e| {
        format!(
            "Failed to start vmrunner_macos_ipc at '{resolved}': {e}\n\
             Set THEYOS_VMRUNNER_RS_BIN to the correct binary path \
             (legacy THEYOS_VMRUNNER_MACOS_RS_BIN is still accepted)."
        )
        .into()
    })
}

fn resolve_vmrunner_bin_path(bin_path: Option<&str>) -> String {
    resolve_vmrunner_bin_path_from_candidates(
        bin_path.map(str::to_string),
        std::env::var(VMRUNNER_ENV).ok(),
        std::env::var(LEGACY_VMRUNNER_ENV).ok(),
        same_exe_vmrunner_path(),
        cargo_vmrunner_path(),
    )
}

fn resolve_vmrunner_bin_path_from_candidates(
    explicit: Option<String>,
    canonical: Option<String>,
    legacy: Option<String>,
    same_exe: Option<String>,
    cargo: String,
) -> String {
    explicit
        .filter(|value| !value.is_empty())
        .or_else(|| canonical.filter(|value| !value.is_empty()))
        .or_else(|| legacy.filter(|value| !value.is_empty()))
        .or(same_exe)
        .unwrap_or(cargo)
}

fn same_exe_vmrunner_path() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join("vmrunner_macos_ipc");
    candidate.is_file().then(|| candidate.display().to_string())
}

fn cargo_vmrunner_path() -> String {
    // Dev fallback: look in Cargo target directory.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    PathBuf::from(manifest)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("target/release/vmrunner_macos_ipc")
        .display()
        .to_string()
}

// Stub main for non-macOS targets (the real main is cfg-gated above).
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("init_macos_guest requires macOS with Apple Virtualization Framework");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmrunner_bin_resolution_prefers_explicit_then_canonical_then_legacy() {
        let resolved = resolve_vmrunner_bin_path_from_candidates(
            Some("/explicit/vmrunner".into()),
            Some("/canonical/vmrunner".into()),
            Some("/legacy/vmrunner".into()),
            Some("/same-exe/vmrunner".into()),
            "/cargo/vmrunner".into(),
        );
        assert_eq!(resolved, "/explicit/vmrunner");

        let resolved = resolve_vmrunner_bin_path_from_candidates(
            None,
            Some("/canonical/vmrunner".into()),
            Some("/legacy/vmrunner".into()),
            Some("/same-exe/vmrunner".into()),
            "/cargo/vmrunner".into(),
        );
        assert_eq!(resolved, "/canonical/vmrunner");

        let resolved = resolve_vmrunner_bin_path_from_candidates(
            None,
            None,
            Some("/legacy/vmrunner".into()),
            Some("/same-exe/vmrunner".into()),
            "/cargo/vmrunner".into(),
        );
        assert_eq!(resolved, "/legacy/vmrunner");
    }

    #[test]
    fn vmrunner_bin_resolution_falls_back_to_same_exe_then_cargo() {
        let resolved = resolve_vmrunner_bin_path_from_candidates(
            None,
            None,
            None,
            Some("/same-exe/vmrunner".into()),
            "/cargo/vmrunner".into(),
        );
        assert_eq!(resolved, "/same-exe/vmrunner");

        let resolved = resolve_vmrunner_bin_path_from_candidates(
            None,
            None,
            None,
            None,
            "/cargo/vmrunner".into(),
        );
        assert_eq!(resolved, "/cargo/vmrunner");
    }
}
