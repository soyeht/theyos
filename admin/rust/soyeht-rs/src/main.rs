//! soyeht — theyOS operations CLI
//!
//! theyOS operations CLI. All stack management, admin backend lifecycle,
//! and dev tooling are exposed as subcommands.
//!
//! # Subcommands
//!
//! ```text
//! soyeht start [--clean]
//! soyeht stop
//! soyeht cleanup-homebrew [--purge-data]
//! soyeht rebuild [--clean]
//! soyeht logs
//! soyeht status [--resources | --deep]
//! soyeht backup
//! soyeht health
//! soyeht doctor           (replaces scripts/firecracker/doctor.sh)
//! soyeht setup            (replaces scripts/setup.sh — interactive installer)
//! soyeht snapshot-create [claw_type...]
//! soyeht admin-host-start
//! soyeht admin-host-stop
//! soyeht admin-host-status
//! soyeht admin-host-logs
//! soyeht dev [--kill | --status]   (replaces admin/scripts/dev)
//! soyeht rebuild-admin [--skip-install]  (replaces admin/scripts/rebuild)
//! soyeht test-admin                (replaces admin/scripts/test)
//! soyeht admin-doctor              (replaces admin/scripts/doctor)
//! soyeht smoke-test               (delegates to e2e-runner smoke — no VMs created)
//! soyeht build [--skip-frontend]          (no sudo — compile + stage binaries)
//! soyeht test  [--skip-clippy]            (no sudo — clippy + cargo test)
//! sudo soyeht deploy [--skip-restart]     (stage → release, restart, smoke test)
//! sudo soyeht validate [--rebuild-snapshots] [--settle N] [--timeout N]
//! soyeht update [--skip-frontend] [--test] [--skip-deploy]  (git pull → build → deploy)
//! soyeht uninstall [--keep-data] [--dry-run] [--yes]
//! soyeht render-env [--template FILE] [--output FILE] --set KEY=VALUE ...
//! ```

mod admin_backend;
mod artifacts;
#[cfg(target_os = "macos")]
mod caddy_manager;
mod claws_detect;
mod claws_discover;
mod claws_promote;
mod claws_scan;
mod claws_verify;
mod cli;
#[cfg(target_os = "macos")]
mod cloudflared_manager;
mod deploy;
mod detector;
mod dev;
mod doctor;
mod github_cache;
mod github_client;
mod infra;
mod nixos;
mod pair;
mod render_env;
mod sandbox;
mod setup;
mod uninstall;
mod util;
mod verify_sandbox;

#[cfg(target_os = "macos")]
mod theyos_client;

use clap::Parser;

#[cfg(target_os = "macos")]
use cli::{CaddyCommands, CloudflaredCommands};
use cli::{Cli, Commands};

#[allow(clippy::too_many_lines)]
fn main() {
    let cli = Cli::parse();

    // Pair and uninstall do not require a repo root. Pair reads a bootstrap
    // token path; uninstall detects the install receipt/model by itself.
    if let Commands::Uninstall(a) = &cli.command {
        uninstall::cmd_uninstall(a);
        return;
    }

    // Pair is the only remaining subcommand that doesn't need the theyOS repo root —
    // it reads a bootstrap token path (default or from THEYOS_BOOTSTRAP_TOKEN_PATH)
    // and POSTs to THEYOS_ADMIN_URL. Handle it before `resolve_repo_root()` so
    // it works from any working directory.
    if let Commands::Pair(a) = &cli.command {
        let secs = pair::parse_duration(&a.duration).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        });
        pair::run(std::path::Path::new(""), secs);
        return;
    }

    let root = core_rs::path::resolve_repo_root().unwrap_or_else(|e| {
        // macOS Homebrew fallback: ~/.theyos is the state dir even when the
        // shell wrapper is missing and we're not inside the repo tree.
        #[cfg(target_os = "macos")]
        {
            let home = std::env::var("HOME").unwrap_or_default();
            let state = std::path::PathBuf::from(&home).join(".theyos");
            if state.join(".env").is_file() {
                return state;
            }
        }
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    match cli.command {
        Commands::Start(a) => {
            infra::cmd_start(&root, a.clean, a.yes, a.force, a.skip_init);
        }
        Commands::Stop => infra::cmd_stop(&root),
        Commands::CleanupHomebrew(a) => infra::cmd_cleanup_homebrew(&root, a.purge_data),
        Commands::Rebuild(a) => {
            nixos::exit_nixos_managed(&root, "rebuild");
            infra::cmd_rebuild(&root, a.clean, a.yes);
        }
        Commands::Logs => infra::cmd_logs(&root),
        Commands::Status(a) => infra::cmd_status(&root, a.resources, a.deep),
        Commands::Backup => infra::cmd_backup(&root),
        Commands::Health => infra::cmd_health(&root),
        Commands::Doctor => doctor::cmd_doctor(&root),
        Commands::SnapshotCreate(a) => infra::cmd_snapshot_create(&root, &a.claw_types),
        Commands::AdminHostStart => {
            if !admin_backend::start_admin_backend(&root) {
                std::process::exit(1);
            }
        }
        Commands::AdminHostStop => admin_backend::stop_admin_backend(&root),
        Commands::AdminHostStatus => {
            if !admin_backend::admin_backend_status(&root) {
                std::process::exit(1);
            }
        }
        Commands::AdminHostLogs => admin_backend::admin_host_logs(&root),
        Commands::Dev(a) => dev::cmd_dev(&root, a.kill, a.status),
        Commands::RebuildAdmin(a) => {
            nixos::exit_nixos_managed(&root, "rebuild-admin");
            dev::cmd_rebuild_admin(&root, a.skip_install);
        }
        Commands::TestAdmin => dev::cmd_test_admin(&root),
        Commands::AdminDoctor => dev::cmd_admin_doctor(&root),
        Commands::Setup(a) => {
            nixos::exit_nixos_managed(&root, "setup");
            setup::cmd_setup(&root, &a);
        }
        Commands::SmokeTest => infra::cmd_smoke_test(&root),
        Commands::Build(a) => {
            nixos::exit_nixos_managed(&root, "build");
            deploy::cmd_build(&root, a.skip_frontend);
        }
        Commands::Test(a) => deploy::cmd_test(&root, a.skip_clippy),
        Commands::Deploy(a) => {
            nixos::exit_nixos_managed(&root, "deploy");
            deploy::cmd_deploy(&root, a.skip_restart);
        }
        Commands::Validate(a) => {
            #[cfg(target_os = "macos")]
            {
                deploy::cmd_validate_macos(&root, &a.claw_types, a.settle, a.timeout);
            }
            #[cfg(not(target_os = "macos"))]
            {
                deploy::cmd_validate(
                    &root,
                    a.rebuild_snapshots,
                    a.sync_artifacts,
                    a.settle,
                    a.timeout,
                );
            }
        }
        Commands::ArtifactsSync(a) => {
            artifacts::cmd_artifacts_sync(&root, a.force, a.gc, &a.claw_types);
        }
        Commands::ArtifactsGc(a) => {
            artifacts::cmd_artifacts_gc(&root, a.dry_run, a.rollback_window, &a.claw_types);
        }
        Commands::ClawsDetect(a) => {
            let args = claws_detect::ClawsDetectArgs {
                repo: a.repo,
                from_list: a.from_list,
                dry_run: a.dry_run,
                yes: a.yes,
            };
            claws_detect::cmd_claws_detect(&root, &args);
        }
        Commands::ClawsScan(a) => {
            let args = claws_scan::ClawsScanArgs {
                apply: a.apply,
                json: a.json,
                no_cache: a.no_cache,
            };
            claws_scan::cmd_claws_scan(&root, &args);
        }
        Commands::ClawsVerify(a) => {
            let args = claws_verify::ClawsVerifyArgs {
                claw: a.claw,
                all_detected: a.all_detected,
                sandbox: a.sandbox,
                concurrency: a.concurrency,
                keep_vm: a.keep_vm,
            };
            claws_verify::cmd_claws_verify(&root, &args);
        }
        Commands::ClawsPromote(a) => {
            let args = claws_promote::ClawsPromoteArgs { claw: a.claw };
            claws_promote::cmd_claws_promote(&root, &args);
        }
        Commands::ClawsDiscover(a) => {
            let args = claws_discover::ClawsDiscoverArgs {
                claw: a.claw,
                all_catalog: a.all_catalog,
            };
            claws_discover::cmd_claws_discover(&root, &args);
        }
        Commands::Update(a) => {
            if nixos::is_nixos_managed(&root) {
                nixos::nixos_update(&root);
            } else {
                #[cfg(target_os = "macos")]
                {
                    deploy::cmd_update_macos(&root, &a);
                }
                #[cfg(not(target_os = "macos"))]
                {
                    deploy::cmd_update(&root, &a);
                }
            }
        }
        Commands::Uninstall(_) => unreachable!("Uninstall is handled before resolve_repo_root"),
        Commands::RenderEnv(a) => render_env::cmd_render_env(&root, &a),
        Commands::Pair(_) => unreachable!("Pair is handled before resolve_repo_root"),
        Commands::Caddy(a) => {
            #[cfg(target_os = "macos")]
            {
                run_caddy_cmd(&root, a.command);
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = a;
                let _ = &root;
                eprintln!(
                    "soyeht caddy is macOS-only. On NixOS, Caddy is managed declaratively \
                     via services.caddy in nix/module.nix."
                );
                std::process::exit(1);
            }
        }
        Commands::Cloudflared(a) => {
            #[cfg(target_os = "macos")]
            {
                run_cloudflared_cmd(a.command);
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = a;
                eprintln!(
                    "soyeht cloudflared is macOS-only. On NixOS, cloudflared is managed \
                     declaratively via services.cloudflared in nix/module.nix."
                );
                std::process::exit(1);
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn run_caddy_cmd(root: &std::path::Path, cmd: CaddyCommands) {
    use caddy_manager::{CaddyError, stderr_log_path, stdout_log_path};

    fn die(err: &CaddyError) -> ! {
        eprintln!("[soyeht caddy] {err}");
        std::process::exit(1);
    }

    match cmd {
        CaddyCommands::Install => match caddy_manager::install(root) {
            Ok(c) => println!(
                "[soyeht caddy] installed (binary={}, version={})",
                c.path.display(),
                c.version
            ),
            Err(e) => die(&e),
        },
        CaddyCommands::Uninstall => match caddy_manager::uninstall() {
            Ok(()) => println!("[soyeht caddy] uninstalled (LaunchAgent removed)"),
            Err(e) => die(&e),
        },
        CaddyCommands::Start => match caddy_manager::start(root) {
            Ok(c) => println!(
                "[soyeht caddy] started (binary={}, version={})",
                c.path.display(),
                c.version
            ),
            Err(e) => die(&e),
        },
        CaddyCommands::Stop => match caddy_manager::stop() {
            Ok(()) => println!("[soyeht caddy] stopped"),
            Err(e) => die(&e),
        },
        CaddyCommands::Restart => match caddy_manager::restart() {
            Ok(()) => println!("[soyeht caddy] restarted"),
            Err(e) => die(&e),
        },
        CaddyCommands::Reload => match caddy_manager::reload(root) {
            Ok(()) => println!("[soyeht caddy] reloaded (zero-downtime via admin API)"),
            Err(e) => die(&e),
        },
        CaddyCommands::Status => {
            let s = caddy_manager::status(root);
            match &s.binary {
                Some(b) => println!("binary:    {} ({})", b.path.display(), b.version),
                None => println!("binary:    NOT INSTALLED"),
            }
            println!(
                "plist:     {}",
                if s.plist_present { "present" } else { "absent" }
            );
            if s.plist_drift {
                println!("           ⚠ stale (rerun: soyeht caddy start)");
            }
            println!(
                "agent:     loaded={}, pid={}, last_exit={}",
                s.launch.loaded,
                s.launch.pid.map_or_else(|| "-".into(), |p| p.to_string()),
                s.launch
                    .last_exit_code
                    .map_or_else(|| "-".into(), |c| c.to_string()),
            );
            println!(
                "admin api: {} (http://localhost:2019)",
                if s.admin_api_up { "up" } else { "down" }
            );
            if !s.admin_api_up || !s.launch.loaded {
                std::process::exit(1);
            }
        }
        CaddyCommands::Logs(args) => {
            let path = if args.err {
                stderr_log_path()
            } else {
                stdout_log_path()
            };
            std::process::Command::new("tail")
                .args(["-f", "-n", "200"])
                .arg(&path)
                .status()
                .ok();
        }
        CaddyCommands::Trust => match caddy_manager::detect_caddy() {
            Some(c) => match caddy_manager::caddy_trust(&c) {
                Ok(()) => println!("[soyeht caddy] local CA installed in System keychain"),
                Err(e) => die(&e),
            },
            None => die(&CaddyError::NotInstalled),
        },
        CaddyCommands::Untrust => match caddy_manager::detect_caddy() {
            Some(c) => match caddy_manager::caddy_untrust(&c) {
                Ok(()) => println!("[soyeht caddy] local CA removed from System keychain"),
                Err(e) => die(&e),
            },
            None => die(&CaddyError::NotInstalled),
        },
    }
}

#[cfg(target_os = "macos")]
fn run_cloudflared_cmd(cmd: CloudflaredCommands) {
    use cloudflared_manager::{CloudflaredError, stderr_log_path, stdout_log_path};

    fn die(err: &CloudflaredError) -> ! {
        eprintln!("[soyeht cloudflared] {err}");
        std::process::exit(1);
    }

    match cmd {
        CloudflaredCommands::Install => match cloudflared_manager::install() {
            Ok(c) => println!(
                "[soyeht cloudflared] installed (binary={}, version={})",
                c.path.display(),
                c.version
            ),
            Err(e) => die(&e),
        },
        CloudflaredCommands::Start => match cloudflared_manager::start() {
            Ok(c) => println!(
                "[soyeht cloudflared] started (binary={}, version={})",
                c.path.display(),
                c.version
            ),
            Err(e) => die(&e),
        },
        CloudflaredCommands::Stop => match cloudflared_manager::stop() {
            Ok(()) => println!("[soyeht cloudflared] stopped (LaunchAgent removed)"),
            Err(e) => die(&e),
        },
        CloudflaredCommands::Restart => match cloudflared_manager::restart() {
            Ok(()) => println!("[soyeht cloudflared] restarted"),
            Err(e) => die(&e),
        },
        CloudflaredCommands::Reload => match cloudflared_manager::reload() {
            Ok(()) => println!("[soyeht cloudflared] reloaded (SIGHUP — config rescanned)"),
            Err(e) => die(&e),
        },
        CloudflaredCommands::Status => {
            let s = cloudflared_manager::status();
            match &s.binary {
                Some(b) => println!("binary:    {} ({})", b.path.display(), b.version),
                None => println!("binary:    NOT INSTALLED"),
            }
            println!(
                "plist:     {}",
                if s.plist_present { "present" } else { "absent" }
            );
            if s.plist_drift {
                println!("           ⚠ stale (rerun: soyeht cloudflared start)");
            }
            println!(
                "agent:     loaded={}, pid={}, last_exit={}",
                s.launch.loaded,
                s.launch.pid.map_or_else(|| "-".into(), |p| p.to_string()),
                s.launch
                    .last_exit_code
                    .map_or_else(|| "-".into(), |c| c.to_string()),
            );
            println!(
                "metrics:   {} (127.0.0.1:2000)",
                if s.metrics_up { "up" } else { "down" }
            );
            if !s.metrics_up || !s.launch.loaded {
                std::process::exit(1);
            }
        }
        CloudflaredCommands::Logs(args) => {
            let path = if args.err {
                stderr_log_path()
            } else {
                stdout_log_path()
            };
            std::process::Command::new("tail")
                .args(["-f", "-n", "200"])
                .arg(&path)
                .status()
                .ok();
        }
    }
}
