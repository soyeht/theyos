use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};

use e2e_rs::benchmark::{BenchmarkConfig, run_benchmark};
use e2e_rs::client::AdminClient;
use e2e_rs::runner::{TestConfig, TestRunner, all_claw_types, print_summary};
use e2e_rs::smoke::run_smoke;
use e2e_rs::snapshot::{SnapshotConfig, run_snapshots};

/// E2E test runner, benchmarker, and snapshot creator for theyOS claw instances.
#[derive(Parser)]
#[command(name = "e2e-runner")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    common: CommonArgs,
}

#[derive(clap::Args)]
struct CommonArgs {
    /// Backend URL.
    #[arg(long, default_value = "http://localhost:8892")]
    base_url: String,

    /// Admin username.
    #[arg(long, default_value = "admin")]
    user: String,

    /// Admin password. Falls back to `SOYEHT_ADMIN_PASSWORD` env var, then .env file.
    #[arg(long)]
    password: Option<String>,

    /// Path to SSH private key for VM access.
    #[arg(long)]
    ssh_key: Option<PathBuf>,

    /// Firecracker instances state directory.
    /// For `--guest-os macos`, this is the scratch VZ VMs directory that holds
    /// `<container>/vm_ip`.
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run E2E tests for claw instances (default when no subcommand is given).
    Test(TestArgs),
    /// Benchmark claw creation: create, time, delete, summarize.
    Benchmark(BenchmarkArgs),
    /// Create Firecracker base snapshots for claw types.
    Snapshot(SnapshotArgs),
    /// Lightweight smoke test — verifies 7 critical API routes in ~5s (no VMs created).
    Smoke,
}

#[derive(clap::Args)]
#[allow(clippy::struct_excessive_bools)]
struct TestArgs {
    /// Claw types to test (default: all 6).
    #[arg(value_name = "CLAW_TYPES")]
    claw_types: Vec<String>,

    /// Enable warm pool timing assertions.
    #[arg(long)]
    warm_pool: bool,

    /// Settle time in seconds between claw tests.
    #[arg(long, default_value = "10")]
    settle: u64,

    /// Per-claw job timeout in seconds.
    #[arg(long, default_value = "300")]
    timeout: u64,

    /// Create retries on 429/error.
    #[arg(long, default_value = "3")]
    retries: u32,

    /// Retry delay in seconds between create retries.
    #[arg(long, default_value = "30")]
    retry_delay: u64,

    /// Skip SSH smoke test.
    #[arg(long)]
    skip_ssh: bool,

    /// Skip terminal PTY smoke test.
    #[arg(long)]
    skip_terminal: bool,

    /// Skip the one-shot terminal restart smoke.
    #[arg(long)]
    skip_terminal_restart: bool,

    /// Skip the terminal persistence test (tmux reconnect verification).
    #[arg(long)]
    skip_terminal_persist: bool,

    /// Skip warm pool refill regression test (picoclaw round 2).
    #[arg(long)]
    skip_refill_test: bool,

    /// Guest OS to request for created instances.
    #[arg(long, default_value = "linux", value_parser = ["linux", "macos"])]
    guest_os: String,

    /// Treat any job failure that lacks a well-formed `error_context` as a test failure.
    #[arg(long)]
    require_error_context: bool,

    /// Max allowed total create time (ms) for warm pool assertions.
    #[arg(long, default_value = "5000")]
    max_create_ms: u64,

    /// Max allowed `pool_install_claw` phase time (ms) for warm pool assertions.
    #[arg(long, default_value = "10")]
    max_install_ms: u64,
}

#[derive(clap::Args)]
struct BenchmarkArgs {
    /// Claw types to benchmark (default: all 6).
    #[arg(value_name = "CLAW_TYPES")]
    claw_types: Vec<String>,

    /// Poll interval in seconds when waiting for job completion.
    #[arg(long, default_value = "2")]
    poll_interval: u64,

    /// Write JSON results to this file.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Baseline JSON file for delta comparison.
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Per-claw job timeout in seconds.
    #[arg(long, default_value = "600")]
    timeout: u64,

    /// Settle time in seconds between claw benchmarks.
    #[arg(long, default_value = "3")]
    settle: u64,
}

#[derive(clap::Args)]
struct SnapshotArgs {
    /// Claw types to snapshot (default: all 6).
    #[arg(value_name = "CLAW_TYPES")]
    claw_types: Vec<String>,

    /// Rebuild even if the snapshot is fresh (< 7 days old).
    #[arg(long)]
    force: bool,

    /// Path to `vmrunner_ipc` binary.
    #[arg(long, env = "THEYOS_VMRUNNER_RS_BIN")]
    vmrunner_bin: Option<PathBuf>,

    /// Firecracker assets directory.
    #[arg(long)]
    assets_dir: Option<PathBuf>,

    /// Per-claw job timeout in seconds.
    #[arg(long, default_value = "300")]
    timeout: u64,

    /// Poll interval in seconds.
    #[arg(long, default_value = "5")]
    poll_interval: u64,

    /// Settle time in seconds between snapshot builds.
    #[arg(long, default_value = "10")]
    settle: u64,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let password = resolve_password(cli.common.password.as_deref());
    let repo_root = core_rs::path::resolve_repo_root().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    let home = core_rs::env::theyos_home(&repo_root);
    let ssh_key = cli.common.ssh_key.unwrap_or_else(|| {
        PathBuf::from(&home).join("firecracker/assets/ubuntu-24.04-root.id_rsa")
    });
    let state_dir = cli
        .common
        .state_dir
        .unwrap_or_else(|| PathBuf::from(&home).join("firecracker/instances"));

    // Smoke test: self-contained, manages its own HTTP agent + login.
    if matches!(cli.command, Some(Commands::Smoke)) {
        eprintln!(
            "[smoke] Running smoke test against {}...",
            cli.common.base_url
        );
        let ok = run_smoke(&cli.common.base_url, &cli.common.user, &password);
        std::process::exit(i32::from(!ok));
    }

    // Health check
    eprintln!("[e2e] Checking backend at {}...", cli.common.base_url);
    let probe = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build();
    match probe
        .get(&format!("{}/healthz", cli.common.base_url))
        .call()
    {
        Ok(_) => eprintln!("[e2e] Backend is up."),
        Err(e) => {
            eprintln!(
                "[e2e] ERROR: Backend not reachable at {}: {e}",
                cli.common.base_url
            );
            std::process::exit(1);
        }
    }

    // Login
    eprintln!("[e2e] Logging in as {}...", cli.common.user);
    let client = match AdminClient::login(&cli.common.base_url, &cli.common.user, &password) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[e2e] ERROR: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[e2e] Login OK.");

    match cli.command {
        Some(Commands::Test(args)) => run_test(client, args, ssh_key, state_dir),
        Some(Commands::Benchmark(args)) => run_bench(client, args),
        Some(Commands::Snapshot(args)) => run_snap(client, args, ssh_key, state_dir),
        Some(Commands::Smoke) => unreachable!("handled above"),
        // Backward compat: bare `e2e-runner` → treat as Test
        None => {
            let args = TestArgs {
                claw_types: vec![],
                warm_pool: false,
                settle: 10,
                timeout: 300,
                retries: 3,
                retry_delay: 30,
                skip_ssh: false,
                skip_terminal: false,
                skip_terminal_restart: false,
                skip_terminal_persist: false,
                skip_refill_test: false,
                guest_os: "linux".to_string(),
                require_error_context: false,
                max_create_ms: 5000,
                max_install_ms: 10,
            };
            run_test(client, args, ssh_key, state_dir);
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn run_test(client: AdminClient, args: TestArgs, ssh_key: PathBuf, state_dir: PathBuf) {
    let known = all_claw_types();
    let claw_types: Vec<&str> = if args.claw_types.is_empty() {
        known
    } else {
        for ct in &args.claw_types {
            if !known.contains(&ct.as_str()) {
                eprintln!(
                    "[e2e] ERROR: unknown claw type '{}'. Valid: {}",
                    ct,
                    known.join(", ")
                );
                std::process::exit(1);
            }
        }
        args.claw_types
            .iter()
            .map(std::string::String::as_str)
            .collect()
    };

    let config = TestConfig {
        timeout: Duration::from_secs(args.timeout),
        retries: args.retries,
        retry_delay: Duration::from_secs(args.retry_delay),
        settle_time: Duration::from_secs(args.settle),
        skip_ssh: args.skip_ssh,
        skip_terminal: args.skip_terminal,
        skip_terminal_restart: args.skip_terminal_restart,
        skip_terminal_persist: args.skip_terminal_persist,
        warm_pool_assertions: args.warm_pool,
        skip_refill_test: args.skip_refill_test,
        guest_os: args.guest_os,
        ssh_key_path: ssh_key,
        state_dir,
        max_create_ms: args.max_create_ms,
        max_install_ms: args.max_install_ms,
        require_error_context: args.require_error_context,
    };

    let runner = TestRunner::new(client, config);

    eprintln!(
        "[e2e] Running E2E for {} claw type(s): {}",
        claw_types.len(),
        claw_types.join(", ")
    );

    let results = runner.run_all(&claw_types);

    eprintln!();
    print_summary(&results);

    let all_passed = results.iter().all(|r| r.passed);
    std::process::exit(i32::from(!all_passed));
}

#[allow(clippy::needless_pass_by_value)]
fn run_snap(client: AdminClient, args: SnapshotArgs, ssh_key: PathBuf, state_dir: PathBuf) {
    let repo_root = core_rs::path::resolve_repo_root().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    let home = core_rs::env::theyos_home(&repo_root);

    let known = all_claw_types();
    let claw_types: Vec<&str> = if args.claw_types.is_empty() {
        known
    } else {
        for ct in &args.claw_types {
            if !known.contains(&ct.as_str()) {
                eprintln!(
                    "[snapshot] ERROR: unknown claw type '{}'. Valid: {}",
                    ct,
                    known.join(", ")
                );
                std::process::exit(1);
            }
        }
        args.claw_types
            .iter()
            .map(std::string::String::as_str)
            .collect()
    };

    let vmrunner_bin = args
        .vmrunner_bin
        .unwrap_or_else(|| default_vmrunner_bin(&home));

    let assets_dir = args
        .assets_dir
        .unwrap_or_else(|| PathBuf::from(&home).join("firecracker/assets"));
    let kernel_image = assets_dir.join(core_rs::guest_net::KERNEL_FILENAME);

    let config = SnapshotConfig {
        vmrunner_bin,
        home: PathBuf::from(&home),
        state_dir,
        assets_dir,
        kernel_image,
        ssh_key,
        force: args.force,
        settle: Duration::from_secs(args.settle),
        timeout: Duration::from_secs(args.timeout),
        poll_interval: Duration::from_secs(args.poll_interval),
    };

    let ok = run_snapshots(&client, &claw_types, &config);
    std::process::exit(i32::from(!ok));
}

fn default_vmrunner_bin(home: &str) -> PathBuf {
    let current_exe = std::env::current_exe().ok();
    select_vmrunner_bin(
        current_exe.as_deref(),
        &std::env::current_dir().unwrap_or_default(),
        home,
    )
}

fn select_vmrunner_bin(current_exe: Option<&Path>, cwd: &Path, home: &str) -> PathBuf {
    if let Some(exe) = current_exe {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("vmrunner_ipc");
            if sibling.exists() {
                return sibling;
            }
        }
    }

    let mut dir = cwd;
    for _ in 0..5 {
        for rel in [
            "admin/rust/target/release/vmrunner_ipc",
            "admin/rust/target/debug/vmrunner_ipc",
        ] {
            let candidate = dir.join(rel);
            if candidate.exists() {
                return candidate;
            }
        }

        if let Some(parent) = dir.parent() {
            dir = parent;
        } else {
            break;
        }
    }

    let release = PathBuf::from(format!(
        "{home}/theyos/admin/rust/target/release/vmrunner_ipc"
    ));
    if release.exists() {
        return release;
    }

    PathBuf::from(format!(
        "{home}/theyos/admin/rust/target/debug/vmrunner_ipc"
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn run_bench(client: AdminClient, args: BenchmarkArgs) {
    let known = all_claw_types();
    let claw_types: Vec<&str> = if args.claw_types.is_empty() {
        known
    } else {
        for ct in &args.claw_types {
            if !known.contains(&ct.as_str()) {
                eprintln!(
                    "[e2e] ERROR: unknown claw type '{}'. Valid: {}",
                    ct,
                    known.join(", ")
                );
                std::process::exit(1);
            }
        }
        args.claw_types
            .iter()
            .map(std::string::String::as_str)
            .collect()
    };

    let config = BenchmarkConfig {
        timeout: Duration::from_secs(args.timeout),
        poll_interval: Duration::from_secs(args.poll_interval),
        settle: Duration::from_secs(args.settle),
        output: args.output,
        baseline: args.baseline,
    };

    let summary = run_benchmark(&client, &claw_types, &config);

    let all_completed = summary.claws.values().all(|r| r.status == "completed");
    std::process::exit(i32::from(!all_completed));
}

/// Resolve admin password from CLI flag, env var, or .env file.
fn resolve_password(cli_password: Option<&str>) -> String {
    if let Some(p) = cli_password {
        return p.to_string();
    }

    if let Ok(p) = std::env::var("SOYEHT_ADMIN_PASSWORD") {
        if !p.is_empty() {
            return p;
        }
    }

    if let Some(p) = read_password_from_dotenv() {
        return p;
    }

    eprintln!("[e2e] ERROR: No admin password found.");
    eprintln!("[e2e] Provide via --password, SOYEHT_ADMIN_PASSWORD env var, or .env file.");
    std::process::exit(1);
}

fn read_password_from_dotenv() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let mut dir = cwd.as_path();
    for _ in 0..5 {
        let env_path = dir.join(".env");
        if let Ok(content) = std::fs::read_to_string(&env_path) {
            for line in content.lines() {
                if let Some(val) = line.strip_prefix("SOYEHT_ADMIN_PASSWORD=") {
                    let val = val.trim();
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
        dir = dir.parent()?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands, select_vmrunner_bin};
    use clap::Parser;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("e2e-runner-{name}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn select_vmrunner_bin_prefers_sibling_binary() {
        let root = temp_dir("sibling");
        let exe_dir = root.join("bin");
        fs::create_dir_all(&exe_dir).unwrap();
        let current_exe = exe_dir.join("e2e-runner");
        let sibling = exe_dir.join("vmrunner_ipc");
        fs::write(&current_exe, b"").unwrap();
        fs::write(&sibling, b"").unwrap();

        assert_eq!(
            select_vmrunner_bin(Some(&current_exe), &root, "/missing-home"),
            sibling
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn select_vmrunner_bin_prefers_workspace_release_over_debug() {
        let root = temp_dir("workspace");
        let workspace = root.join("repo");
        let release = workspace.join("admin/rust/target/release/vmrunner_ipc");
        let debug = workspace.join("admin/rust/target/debug/vmrunner_ipc");

        fs::create_dir_all(release.parent().unwrap()).unwrap();
        fs::create_dir_all(debug.parent().unwrap()).unwrap();
        fs::write(&release, b"").unwrap();
        fs::write(&debug, b"").unwrap();

        let selected = select_vmrunner_bin(None, &workspace, "/missing-home");
        assert_eq!(selected, release);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_command_accepts_macos_guest_os() {
        let cli =
            Cli::try_parse_from(["e2e-runner", "test", "picoclaw", "--guest-os", "macos"]).unwrap();

        let Some(Commands::Test(args)) = cli.command else {
            panic!("expected test command");
        };
        assert_eq!(args.guest_os, "macos");
    }

    #[test]
    fn test_command_defaults_guest_os_to_linux() {
        let cli = Cli::try_parse_from(["e2e-runner", "test", "picoclaw"]).unwrap();

        let Some(Commands::Test(args)) = cli.command else {
            panic!("expected test command");
        };
        assert_eq!(args.guest_os, "linux");
    }
}
