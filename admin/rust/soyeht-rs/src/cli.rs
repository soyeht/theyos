//! CLI structs — clap-derived argument types for soyeht.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "soyeht", about = "theyOS operations CLI", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start admin backend and infrastructure services.
    Start(StartArgs),
    /// Stop all services.
    Stop,
    /// Stop Homebrew-managed helpers and remove launch-agent residue before `brew uninstall`.
    CleanupHomebrew(CleanupHomebrewArgs),
    /// Rebuild and restart services.
    Rebuild(RebuildArgs),
    /// Follow infrastructure logs.
    Logs,
    /// Show service status.
    Status(StatusArgs),
    /// Create a full project backup.
    Backup,
    /// Check service health, tunnel, and security headers.
    Health,
    /// Firecracker environment diagnostics (replaces scripts/firecracker/doctor.sh).
    Doctor,
    /// Build Firecracker base snapshots (delegates to e2e-runner).
    SnapshotCreate(SnapshotArgs),
    /// Start the admin backend on the host.
    AdminHostStart,
    /// Stop the host admin backend.
    AdminHostStop,
    /// Show host admin backend status.
    AdminHostStatus,
    /// Follow host admin backend logs.
    AdminHostLogs,
    /// Start Rust backend + Vite dev server in background (replaces admin/scripts/dev).
    Dev(DevArgs),
    /// Build frontend (npm ci + npm run build) and Rust backend (replaces admin/scripts/rebuild).
    RebuildAdmin(RebuildAdminArgs),
    /// Run Rust workspace tests + frontend build check (replaces admin/scripts/test).
    TestAdmin,
    /// Check dev prerequisites: cargo, rustc, node, npm, key files (replaces admin/scripts/doctor).
    AdminDoctor,
    /// Interactive setup wizard — generates .env, directories, prepares Linux assets, clones claws.
    Setup(SetupArgs),
    /// Lightweight smoke test — verifies 7 critical API routes in ~5s (delegates to e2e-runner smoke).
    SmokeTest,
    /// Build release binaries and stage them for deploy (no sudo required).
    Build(BuildArgs),
    /// Run clippy and cargo test (no sudo required).
    Test(TestArgs),
    /// Deploy staged binaries: copy to release, restart service, smoke test.
    /// Rolls back automatically if smoke test fails. Requires sudo.
    Deploy(DeployArgs),
    /// Post-deploy validation: warm pool convergence + E2E tests for installed claws.
    /// Does NOT rollback on failure — admin stays running for debugging. Requires sudo.
    Validate(ValidateArgs),
    /// Reconcile artifact DAG: rebuild stale goldens and snapshots based on
    /// content-addressed fingerprints. Does NOT run E2E tests.
    /// Use `validate --sync-artifacts` to sync + warm pool + E2E.
    ArtifactsSync(ArtifactsSyncArgs),
    /// Garbage-collect unreferenced artifact versions (goldens + snapshots).
    /// Only deletes fingerprint directories not referenced by: current symlink,
    /// snapshot metadata, or the rollback window.
    ArtifactsGc(ArtifactsGcArgs),
    /// Probe a GitHub repo (or a list of repos) and append detected install
    /// template stubs to `claws/manifest.yml`. Requires `GITHUB_TOKEN` for
    /// batches larger than 5 URLs.
    ClawsDetect(ClawsDetectArgs),
    /// Compare `reviewed_upstream_commit` against live HEAD for every claw in
    /// the manifest and report drift. Never promotes reviewed commits.
    ClawsScan(ClawsScanArgs),
    /// Verify a detected claw's installer plan in a disposable sandbox VM.
    ClawsVerify(ClawsVerifyArgs),
    /// Promote a `tier: available` claw to `tier: supported` (requires a
    /// handwritten builtin plan in `vmrunner-rs/src/installer_plan.rs`).
    ClawsPromote(ClawsPromoteArgs),
    /// Write an agent-readable bundle (`artifacts/discover/<claw>.md`) for
    /// every `tier: catalog` claw where `claws-detect` could not assign a
    /// template. Consumed by an external coding agent (Claude Code, Codex,
    /// etc.) — this command does NOT call any LLM API and never edits the
    /// manifest. The agent edits `claws/manifest.yml` by hand after reading
    /// the bundle.
    ClawsDiscover(ClawsDiscoverArgs),
    /// Pull latest code, rebuild, and deploy in one command.
    /// Wraps git pull → build → deploy for end users.
    Update(UpdateArgs),
    /// Render .env from .env.example template + key-value overrides.
    /// Used by NixOS module activation and install-nixos fallback.
    RenderEnv(RenderEnvArgs),
    /// Generate a QR code for mobile app server pairing.
    Pair(PairArgs),
    /// macOS Caddy lifecycle (`LaunchAgent` + local CA).
    /// Subcommands: install, uninstall, start, stop, restart, reload, status,
    /// logs, trust, untrust.
    Caddy(CaddyArgs),
    /// macOS Cloudflare Tunnel lifecycle (`LaunchAgent` for cloudflared).
    /// Driven by the admin backend via `THEYOS_CLOUDFLARED`_*_CMD env vars set
    /// in the Homebrew formula's launchd service block. Mirrors NixOS
    /// `services.cloudflared` declaratively.
    /// Subcommands: install, start, stop, restart, reload, status, logs.
    Cloudflared(CloudflaredArgs),
}

#[derive(clap::Args)]
pub struct CaddyArgs {
    #[command(subcommand)]
    pub command: CaddyCommands,
}

#[derive(Subcommand)]
pub enum CaddyCommands {
    /// Detect Caddy, write `LaunchAgent` plist, bootstrap the agent.
    Install,
    /// Bootout the agent and remove the plist (does NOT untrust the local CA).
    Uninstall,
    /// Bootstrap or kickstart the agent. Auto-regenerates the plist when the
    /// repo path or detected binary has drifted since the last install.
    Start,
    /// Bootout the agent (Caddy stays down until next start/install).
    Stop,
    /// `launchctl kickstart -k` — restart in place.
    Restart,
    /// Hot-reload the Caddyfile via the admin API (no dropped connections).
    Reload,
    /// Print binary, plist, launchctl, and admin API status.
    Status,
    /// Tail the Caddy stdout log (or stderr with --err).
    Logs(CaddyLogsArgs),
    /// Run `caddy trust` to install the local CA into the System keychain.
    /// macOS prompts for an admin password via the GUI security dialog.
    Trust,
    /// Run `caddy untrust` to remove the local CA from the System keychain.
    Untrust,
}

#[derive(clap::Args)]
pub struct CaddyLogsArgs {
    /// Tail caddy.err.log instead of caddy.out.log.
    #[arg(long)]
    pub err: bool,
}

#[derive(clap::Args)]
pub struct CloudflaredArgs {
    #[command(subcommand)]
    pub command: CloudflaredCommands,
}

#[derive(Subcommand)]
pub enum CloudflaredCommands {
    /// Detect cloudflared, ensure dirs + stub config exist, write `LaunchAgent`
    /// plist. Does NOT start the agent (use `start` for that).
    Install,
    /// `install` + `launchctl bootstrap`. Idempotent — re-bootstrap is OK.
    /// Auto-regenerates the plist if config/token paths drifted.
    Start,
    /// `launchctl bootout`, wait for cloudflared to fully exit, remove the
    /// plist file. Caller (admin backend `handle_disconnect`) needs the
    /// process fully dead before deleting the tunnel via the Cloudflare API.
    Stop,
    /// `launchctl kickstart -k` — restart in place.
    Restart,
    /// Hot-reload via SIGHUP — cloudflared rereads ingress config without
    /// dropping connections.
    Reload,
    /// Print binary, plist, launchctl, and metrics-port status.
    Status,
    /// Tail cloudflared.out.log (or .err.log with --err).
    Logs(CloudflaredLogsArgs),
}

#[derive(clap::Args)]
pub struct CloudflaredLogsArgs {
    /// Tail cloudflared.err.log instead of cloudflared.out.log.
    #[arg(long)]
    pub err: bool,
}

#[derive(clap::Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct StartArgs {
    /// Clean start (currently a no-op, reserved for future use).
    #[arg(long)]
    pub clean: bool,

    /// Skip confirmation prompts (for scripts / CI).
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Reinitialize the macOS base image from scratch.
    #[arg(long)]
    pub force: bool,

    /// Skip macOS base image initialization check (used by launchd service).
    #[arg(long)]
    pub skip_init: bool,
}

#[derive(clap::Args)]
pub struct RebuildArgs {
    /// Force no-cache rebuild plus aggressive cleanup.
    #[arg(long)]
    pub clean: bool,

    /// Skip confirmation prompts (for scripts / CI).
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(clap::Args)]
pub struct CleanupHomebrewArgs {
    /// Also remove ~/.theyos, VMs, logs, caches, and temporary databases.
    #[arg(long)]
    pub purge_data: bool,
}

#[derive(clap::Args)]
pub struct StatusArgs {
    /// Include resource usage details.
    #[arg(long, conflicts_with = "deep")]
    pub resources: bool,

    /// Run deep checks (.env permissions, git tracking, disk space).
    #[arg(long, conflicts_with = "resources")]
    pub deep: bool,
}

#[derive(clap::Args)]
pub struct SnapshotArgs {
    /// Claw types to snapshot (default: all).
    #[arg(value_name = "CLAW_TYPE")]
    pub claw_types: Vec<String>,
}

#[derive(clap::Args)]
pub struct DevArgs {
    /// Stop background dev servers.
    #[arg(long, conflicts_with = "status")]
    pub kill: bool,

    /// Show running dev server PIDs.
    #[arg(long, conflicts_with = "kill")]
    pub status: bool,
}

#[derive(clap::Args)]
pub struct RebuildAdminArgs {
    /// Skip `npm ci` (only run `npm run build` + `cargo build`).
    #[arg(long)]
    pub skip_install: bool,
}

#[derive(clap::Args)]
pub struct SetupArgs {
    /// Skip Firecracker, kernel, and SSH key download steps.
    #[arg(long)]
    pub skip_assets: bool,

    /// Skip base rootfs build prompt.
    #[arg(long)]
    pub skip_rootfs: bool,
}

#[derive(clap::Args)]
pub struct BuildArgs {
    /// Skip frontend build (npm ci + npm run build).
    #[arg(long)]
    pub skip_frontend: bool,
}

#[derive(clap::Args)]
pub struct TestArgs {
    /// Skip clippy (only run cargo test).
    #[arg(long)]
    pub skip_clippy: bool,
}

#[derive(clap::Args)]
pub struct DeployArgs {
    /// Copy staged binaries without restarting the service (for debugging).
    #[arg(long)]
    pub skip_restart: bool,
}

#[derive(clap::Args)]
pub struct ValidateArgs {
    /// Claw types to test (default: installed claws on Linux, picoclaw on macOS).
    #[arg(value_name = "CLAW_TYPE")]
    pub claw_types: Vec<String>,

    /// Rebuild base snapshots before E2E tests.
    #[arg(long)]
    pub rebuild_snapshots: bool,

    /// Sync artifacts (DAG reconciliation) before warm pool + E2E.
    #[arg(long)]
    pub sync_artifacts: bool,

    /// Seconds to settle between E2E tests (default: 5).
    #[arg(long, default_value = "5")]
    pub settle: u64,

    /// E2E test timeout in seconds (default: 300).
    #[arg(long, default_value = "300")]
    pub timeout: u64,
}

#[derive(clap::Args)]
pub struct ArtifactsSyncArgs {
    /// Claw types to sync (default: installed claws).
    #[arg(value_name = "CLAW_TYPE")]
    pub claw_types: Vec<String>,

    /// Force rebuild even if DAG says fresh.
    #[arg(long)]
    pub force: bool,

    /// Run GC after sync to clean up unreferenced versions.
    #[arg(long)]
    pub gc: bool,
}

#[derive(clap::Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct UpdateArgs {
    /// Skip frontend build (npm ci + npm run build).
    #[arg(long)]
    pub skip_frontend: bool,
    /// Also run clippy + cargo test after build.
    #[arg(long)]
    pub test: bool,
    /// Skip the deploy step (only pull + build).
    #[arg(long)]
    pub skip_deploy: bool,
    /// After build, sync stale artifacts (golden images, snapshots) via DAG reconciliation.
    #[arg(long)]
    pub sync_artifacts: bool,
}

#[derive(clap::Args)]
pub struct ClawsDetectArgs {
    /// A single GitHub repo URL to detect.
    #[arg(long, value_name = "URL")]
    pub repo: Option<String>,

    /// Path to a text file containing one GitHub URL per line
    /// (blank lines and `#` comments are ignored).
    #[arg(long, value_name = "FILE")]
    pub from_list: Option<std::path::PathBuf>,

    /// Print the YAML block that would be appended, without touching the manifest.
    #[arg(long)]
    pub dry_run: bool,

    /// Skip confirmation prompts (reserved for future interactive review).
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(clap::Args)]
pub struct ClawsScanArgs {
    /// Patch `latest_upstream_commit` + `latest_checked_at` for stale claws.
    /// Never touches `reviewed_upstream_commit`.
    #[arg(long)]
    pub apply: bool,

    /// Emit JSON instead of human-readable text.
    #[arg(long)]
    pub json: bool,

    /// Bypass the 5-minute disk cache for HEAD SHAs.
    #[arg(long)]
    pub no_cache: bool,
}

#[derive(clap::Args)]
pub struct ClawsVerifyArgs {
    /// Specific claw to verify. Mutually exclusive with `--all-detected`.
    #[arg(value_name = "CLAW")]
    pub claw: Option<String>,

    /// Verify every claw currently `tier: detected`.
    #[arg(long, conflicts_with = "claw")]
    pub all_detected: bool,

    /// Sandbox kind: `firecracker` (Linux, default) or `mac` (not yet implemented).
    #[arg(long, default_value = "firecracker")]
    pub sandbox: String,

    /// Parallel verify jobs (v1 always executes sequentially).
    #[arg(long, default_value = "1")]
    pub concurrency: u32,

    /// Keep the sandbox VM around after verify finishes (for debugging).
    #[arg(long)]
    pub keep_vm: bool,
}

#[derive(clap::Args)]
pub struct ClawsPromoteArgs {
    /// Claw to promote from `tier: available` to `tier: supported`.
    #[arg(value_name = "CLAW")]
    pub claw: String,
}

#[derive(clap::Args)]
pub struct ClawsDiscoverArgs {
    /// Specific claw to bundle. Mutually exclusive with `--all-catalog`.
    #[arg(value_name = "CLAW")]
    pub claw: Option<String>,

    /// Write a bundle for every claw currently `tier: catalog`.
    #[arg(long, conflicts_with = "claw")]
    pub all_catalog: bool,
}

#[derive(clap::Args)]
pub struct ArtifactsGcArgs {
    /// Claw types to GC (default: all manifest claws).
    #[arg(value_name = "CLAW_TYPE")]
    pub claw_types: Vec<String>,

    /// Show what would be deleted without actually deleting.
    #[arg(long)]
    pub dry_run: bool,

    /// Number of extra versions to keep beyond `current` (default: 1).
    #[arg(long, default_value = "1")]
    pub rollback_window: usize,
}

#[derive(clap::Args)]
pub struct PairArgs {
    /// Token duration (e.g., 15m, 2h, 3d). Default: 15m.
    #[arg(short = 'd', long = "duration", default_value = "15m")]
    pub duration: String,
}

#[derive(clap::Args)]
pub struct RenderEnvArgs {
    /// Path to template file (default: .env.example in repo root).
    #[arg(long)]
    pub template: Option<String>,

    /// Output path (default: .env in repo root).
    #[arg(long)]
    pub output: Option<String>,

    /// Key-value overrides. Uncommented keys are replaced, commented keys are
    /// uncommented + replaced, missing keys are appended.
    /// Format: KEY=VALUE (repeatable).
    #[arg(long, value_name = "KEY=VALUE")]
    pub set: Vec<String>,
}
