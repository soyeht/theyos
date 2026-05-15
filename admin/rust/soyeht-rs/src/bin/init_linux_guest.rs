//! `init_linux_guest` — Initialize or remove the Linux guest base image.
//!
//! # Usage
//!
//! ```text
//! init_linux_guest [OPTIONS]
//! init_linux_guest remove [--yes]
//! init_linux_guest status
//! ```
//!
//! # Phases
//!
//! 1. `DownloadImage` — download Ubuntu 24.04 ARM64 cloud image (~600 MB)
//! 2. `ConvertImage` — qcow2 → raw, resize to 20 GB, fix GPT backup header
//! 3. `FirstBoot` — boot with blank NVRAM + cloud-init (GRUB populates NVRAM)
//! 4. `ValidateSsh` — SSH into VM, verify health
//! 5. `SaveBase` — shut down, save disk + NVRAM, create claw symlinks
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

/// Initialize or remove the Linux guest base image for theyOS.
#[derive(Parser)]
#[command(name = "init_linux_guest")]
#[command(version)]
#[command(about = "Initialize the Linux guest base image (download + first-boot + NVRAM setup)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Force re-initialization from scratch (deletes existing base image)
    #[arg(long)]
    force: bool,

    /// Force re-provisioning only (re-run first boot with existing disk; skips download + convert)
    #[arg(long)]
    force_provision: bool,

    /// Skip confirmation prompts
    #[arg(long, short = 'y')]
    yes: bool,

    /// CPU count for the base VM (default: 2)
    #[arg(long, default_value = "2")]
    cpus: u32,

    /// Memory in MB for the base VM (default: 2048)
    #[arg(long, default_value = "2048")]
    memory_mb: u32,

    /// Override Ubuntu cloud image URL
    #[arg(long, env = "THEYOS_LINUX_IMAGE_URL", default_value = "")]
    image_url: String,

    /// Path to `vmrunner_macos_ipc` binary (default: `THEYOS_VMRUNNER_MACOS_RS_BIN` env)
    #[arg(long, env = "THEYOS_VMRUNNER_MACOS_RS_BIN")]
    vmrunner_bin: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Remove the Linux base image and all associated files + claw symlinks
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
        Some(Commands::Remove { yes }) => cmd_remove(yes, &cli),
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
    if cli.force && !cli.yes {
        eprint!(
            "WARNING: --force will delete and recreate the Linux base image.\n\
             This takes ~5 min. Continue? [y/N] "
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!("=== theyOS Linux Guest Initialization ===");
    println!();
    println!("Requirements:");
    println!("  - macOS 14 (Sonoma) or later");
    println!("  - Apple Silicon (M1/M2/M3)");
    println!("  - ~25 GB free disk space");
    println!("  - qemu-img (brew install qemu)");
    println!("  - sgdisk (brew install gptfdisk)");
    println!("  - ~5 min for first-time setup");
    println!();

    let client = build_client(cli.vmrunner_bin.as_deref())?;

    let params = json!({
        "force": cli.force,
        "force_provision": cli.force_provision,
        "cpus": cli.cpus,
        "memory_mb": cli.memory_mb,
        "image_url": cli.image_url,
    });

    println!("Sending LinuxBaseInstall request to vmrunner...");
    println!("(This will take ~5 min on first run — please wait)");
    println!();

    let response = client
        .call("LinuxBaseInstall", params)
        .map_err(|e| format!("IPC call failed: {e}"))?;

    match response.get("status").and_then(|s| s.as_str()) {
        Some("already_complete") => {
            println!("Linux base image is already initialized.");
            if let Some(dir) = response.get("base_dir").and_then(|v| v.as_str()) {
                println!("Base directory: {dir}");
            }
            println!(
                "Run with --force to reinitialize, or --force-provision to re-run first boot."
            );
        }
        Some("complete") => {
            println!("Linux base image initialized successfully.");
            if let Some(dir) = response.get("base_dir").and_then(|v| v.as_str()) {
                println!("Base directory: {dir}");
            }
            if let Some(version) = response.get("ubuntu_version").and_then(|v| v.as_str()) {
                println!("Ubuntu version: {version}");
            }
            if let Some(gb) = response
                .get("disk_size_gb")
                .and_then(serde_json::Value::as_u64)
            {
                println!("Disk size: {gb} GB");
            }
            println!();
            println!("You can now create Linux claw instances:");
            println!(
                "  Select 'Linux (no limit)' in the create form at http://localhost:8892/create"
            );
        }
        _ => {
            println!("Unexpected response: {response:?}");
            return Err("Unexpected IPC response".into());
        }
    }

    Ok(())
}

// ── remove ────────────────────────────────────────────────────────────────────

fn cmd_remove(yes: bool, cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    if !yes {
        eprint!(
            "WARNING: This will remove the Linux base image and all claw symlinks.\n\
             Existing Linux VMs will continue running but new ones cannot be created.\n\
             Continue? [y/N] "
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let client = build_client(cli.vmrunner_bin.as_deref())?;

    println!("Removing Linux base image...");

    let response = client
        .call("RemoveLinuxBase", json!({}))
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
        #[allow(clippy::cast_precision_loss)]
        let gb = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        println!("Removed. Freed {gb:.1} GB.");
    } else {
        println!("Nothing to remove (base image not found).");
    }

    Ok(())
}

// ── status ────────────────────────────────────────────────────────────────────

fn cmd_status(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let client = build_client(cli.vmrunner_bin.as_deref())?;

    let response = client
        .call("LinuxBaseStatus", json!({}))
        .map_err(|e| format!("IPC call failed: {e}"))?;

    println!("=== Linux Guest Base Image Status ===");

    let complete = response
        .get("complete")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if complete {
        println!("Status: initialized");
    } else {
        println!("Status: NOT initialized");
    }

    if let Some(dir) = response.get("base_dir").and_then(|v| v.as_str()) {
        println!("Base directory: {dir}");
    }
    if let Some(phase) = response.get("phase") {
        if !phase.is_null() {
            println!("Phase: {phase}");
        }
    }
    if let Some(version) = response.get("ubuntu_version").and_then(|v| v.as_str()) {
        println!("Ubuntu version: {version}");
    }
    if let Some(gb) = response
        .get("disk_size_gb")
        .and_then(serde_json::Value::as_u64)
    {
        println!("Disk size: {gb} GB");
    }

    if !complete {
        println!();
        println!("Run `init_linux_guest` to initialize.");
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_client(bin_path: Option<&str>) -> Result<IpcClient, Box<dyn std::error::Error>> {
    let resolved = bin_path
        .map(str::to_string)
        .or_else(|| std::env::var("THEYOS_VMRUNNER_MACOS_RS_BIN").ok())
        .unwrap_or_else(|| {
            let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
            PathBuf::from(manifest)
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("target/release/vmrunner_macos_ipc")
                .display()
                .to_string()
        });

    IpcClient::start(&resolved, &[]).map_err(|e| {
        format!(
            "Failed to start vmrunner_macos_ipc at '{resolved}': {e}\n\
             Set THEYOS_VMRUNNER_MACOS_RS_BIN to the correct binary path."
        )
        .into()
    })
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("init_linux_guest requires macOS with Apple Virtualization Framework");
    std::process::exit(1);
}
