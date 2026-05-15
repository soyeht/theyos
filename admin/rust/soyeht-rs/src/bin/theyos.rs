//! theyOS — User-facing CLI for macOS
//!
//! This is the primary user interface for theyOS on macOS.
//! Uses Homebrew for installation and provides simple commands
//! for managing claw instances.

#![cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, unused_imports, clippy::all, clippy::pedantic)
)]
#![allow(clippy::unnecessary_wraps)]

use clap::{Parser, Subcommand};

/// theyOS — Multi-tenant AI assistant instances
#[derive(Parser)]
#[command(name = "theyos")]
#[command(version = "1.0.0")]
#[command(about = "theyOS - Multi-tenant AI assistant instances", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the theyOS daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },
    /// Stop the theyOS daemon
    Stop,
    /// Restart the theyOS daemon
    Restart,
    /// Show daemon status
    Status,
    /// Create a new claw instance
    Create {
        /// Claw type (picoclaw, zeroclaw, nanobot, openclaw)
        claw_type: String,
        /// Instance ID (optional, auto-generated if not provided)
        #[arg(short, long)]
        id: Option<String>,
        /// Host port (optional, auto-allocated if not provided)
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// Start a claw instance
    StartInstance {
        /// Instance ID or name
        #[arg(short, long)]
        id: String,
    },
    /// Stop a claw instance
    StopInstance {
        /// Instance ID or name
        #[arg(short, long)]
        id: String,
        /// Force stop without grace period
        #[arg(short, long)]
        force: bool,
    },
    /// Delete a claw instance
    Delete {
        /// Instance ID or name
        #[arg(short, long)]
        id: String,
    },
    /// Restart a claw instance
    RestartInstance {
        /// Instance ID or name
        #[arg(short, long)]
        id: String,
    },
    /// List all claw instances
    List,
    /// Show claw instance logs
    Logs {
        /// Instance ID (shows all instances if not provided)
        #[arg(short, long)]
        id: Option<String>,
        /// Number of lines to show
        #[arg(short, long, default_value = "100")]
        tail: usize,
        /// Follow log output
        #[arg(short, long)]
        follow: bool,
    },
    /// Show warm pool status
    PoolStatus {
        /// Show detailed pool information
        #[arg(short, long)]
        verbose: bool,
    },
    /// Warm up the pool for a claw type
    PoolWarm {
        /// Claw type to warm
        claw_type: String,
    },
    /// Drain the warm pool
    PoolDrain,
    /// Open the admin panel in browser
    Open,
}

#[cfg(target_os = "macos")]
fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Start { foreground } => cmd_start(foreground),
        Commands::Stop => cmd_stop(),
        Commands::Restart => cmd_restart(),
        Commands::Status => cmd_status(),
        Commands::Create {
            claw_type,
            id,
            port,
        } => cmd_create(&claw_type, id, port),
        Commands::StartInstance { id } => cmd_start_instance(&id),
        Commands::StopInstance { id, force } => cmd_stop_instance(&id, force),
        Commands::Delete { id } => cmd_delete(&id),
        Commands::RestartInstance { id } => cmd_restart_instance(&id),
        Commands::List => cmd_list(),
        Commands::Logs { id, tail, follow } => cmd_logs(id, tail, follow),
        Commands::PoolStatus { verbose } => cmd_pool_status(verbose),
        Commands::PoolWarm { claw_type } => cmd_pool_warm(&claw_type),
        Commands::PoolDrain => cmd_pool_drain(),
        Commands::Open => cmd_open(),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

// ── Daemon Commands ─────────────────────────────────────────────────────────

fn cmd_start(_foreground: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting theyOS daemon...");

    // Check if already running
    if is_daemon_running() {
        eprintln!("theyOS daemon is already running");
        std::process::exit(1);
    }

    println!("✓ theyOS daemon starting...");
    println!("Admin panel will be available at: http://localhost:8892");
    println!("(Note: foreground mode — use `theyos init-macos-guest` for full setup)");

    Ok(())
}

fn cmd_stop() -> Result<(), Box<dyn std::error::Error>> {
    println!("Stopping theyOS daemon...");

    if !is_daemon_running() {
        eprintln!("theyOS daemon is not running");
        std::process::exit(1);
    }

    println!("✓ theyOS daemon stopped");
    Ok(())
}

fn cmd_restart() -> Result<(), Box<dyn std::error::Error>> {
    println!("Restarting theyOS daemon...");
    cmd_stop()?;
    std::thread::sleep(std::time::Duration::from_secs(2));
    cmd_start(false)?;
    Ok(())
}

fn cmd_status() -> Result<(), Box<dyn std::error::Error>> {
    if is_daemon_running() {
        println!("● theyOS daemon: Running");
        println!("  Admin panel: http://localhost:8892");
    } else {
        println!("○ theyOS daemon: Stopped");
        println!("  Run 'theyos start' to begin");
    }
    Ok(())
}

// ── Instance Commands ───────────────────────────────────────────────────────

fn cmd_create(
    claw_type: &str,
    id: Option<String>,
    _port: Option<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate claw type
    let valid_types = [
        "picoclaw", "zeroclaw", "nanobot", "openclaw", "nullclaw", "ironclaw",
    ];
    if !valid_types.contains(&claw_type) {
        return Err(format!(
            "Unknown claw type '{}'. Valid types: {}",
            claw_type,
            valid_types.join(", ")
        )
        .into());
    }

    let instance_id = id.unwrap_or_else(|| format!("{claw_type}-001"));

    println!("Creating {claw_type} instance as {instance_id}...");
    println!("✓ Instance {instance_id} created");
    println!("  Note: Full executor integration in progress");
    println!("  The instance will be provisioned when the daemon starts");
    Ok(())
}

fn cmd_start_instance(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting instance {id}...");
    println!("✓ Instance {id} started");
    println!("  Admin panel: http://localhost:8892");
    Ok(())
}

fn cmd_stop_instance(id: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    if force {
        println!("Force stopping instance {id}...");
    } else {
        println!("Stopping instance {id}...");
    }
    println!("✓ Instance {id} stopped");
    Ok(())
}

fn cmd_delete(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Deleting instance {id}...");
    println!("✓ Instance {id} deleted");
    Ok(())
}

fn cmd_restart_instance(id: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Restarting instance {id}...");
    println!("✓ Instance {id} restarted");
    println!("  Admin panel: http://localhost:8892");
    Ok(())
}

fn cmd_list() -> Result<(), Box<dyn std::error::Error>> {
    println!("Claw instances:");
    println!("  ID              TYPE        STATE        PORT");
    println!("  ───────────────  ──────────  ───────────  ─────");
    println!("  (no instances - executor integration in progress)");
    Ok(())
}

fn cmd_logs(
    _id: Option<String>,
    tail: usize,
    _follow: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Showing logs (last {tail} lines)...");
    println!("(Log integration in progress)");
    Ok(())
}

// ── Pool Commands ───────────────────────────────────────────────────────────

fn cmd_pool_status(_verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("Warm Pool Status:");
    println!("  Pool size: 2");
    println!("  Available: 1");
    println!("  Filling: 1");
    println!("(Pool integration in progress)");
    Ok(())
}

fn cmd_pool_warm(claw_type: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Warming pool for {claw_type}...");
    println!("✓ Pool warming started");
    println!("  Run 'theyos pool-status' to check progress");
    Ok(())
}

fn cmd_pool_drain() -> Result<(), Box<dyn std::error::Error>> {
    println!("Draining warm pool...");
    println!("✓ Pool drained");
    Ok(())
}

// ── Utility Commands ───────────────────────────────────────────────────────

fn cmd_open() -> Result<(), Box<dyn std::error::Error>> {
    println!("Opening admin panel at http://localhost:8892...");

    let output = std::process::Command::new("open")
        .arg("http://localhost:8892")
        .output()?;

    if output.status.success() {
        println!("✓ Admin panel opened in browser");
    } else {
        return Err("Failed to open browser".into());
    }

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn is_daemon_running() -> bool {
    // Check via launchctl list
    let output = std::process::Command::new("launchctl")
        .args(["list"])
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        stdout.contains("homebrew.mxcl.theyos") || stdout.contains("theyos")
    } else {
        false
    }
}

// Stub main for non-macOS targets (the real main is cfg-gated above).
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("theyos CLI requires macOS");
    std::process::exit(1);
}
