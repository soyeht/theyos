//! Infrastructure commands — start, stop, rebuild, logs, status, backup, health,
//! snapshot-create, smoke-test.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

#[cfg(target_os = "macos")]
use std::path::PathBuf;

use crate::admin_backend::{admin_backend_status, start_admin_backend, stop_admin_backend};
use crate::util::{
    available_disk_kb, curl_headers, curl_ok, e2e_runner_bin, file_permissions, timestamp,
};

#[allow(clippy::fn_params_excessive_bools)]
pub fn cmd_start(root: &Path, _clean: bool, skip_confirm: bool, force_init: bool, skip_init: bool) {
    if crate::nixos::is_nixos_managed(root) {
        println!("[soyeht] NixOS mode: starting services via systemctl...");
        crate::nixos::systemctl_or_exit(&["start", "soyeht-admin-host.service"]);
        let health = crate::util::admin_health_url(root);
        for i in 0..30 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            if curl_ok(&health, 2) {
                println!("[soyeht] services started");
                return;
            }
            if i == 10 {
                println!("[soyeht] still waiting for backend...");
            }
        }
        eprintln!("[soyeht] admin backend not healthy after 30s");
        std::process::exit(1);
    }

    // macOS: auto-init guest base image on first start
    #[cfg(target_os = "macos")]
    if !skip_init && (force_init || !macos_base_is_ready()) {
        stop_stale_homebrew_runtime_processes(skip_confirm);
        if force_init {
            println!("[soyeht] --force requested. Reinitializing macOS base image...");
        } else {
            println!("[soyeht] macOS base image not found. Starting first-time setup...");
        }
        println!("[soyeht] This downloads macOS (~13 GB) and creates a VM (~30 min).");
        println!();
        if !skip_confirm {
            eprint!("Continue? [Y/n] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();
            if input.trim().eq_ignore_ascii_case("n") {
                std::process::exit(0);
            }
        }
        run_macos_init(root, force_init);
    }

    #[cfg(not(target_os = "macos"))]
    let _ = (skip_confirm, force_init, skip_init);

    println!("[soyeht] starting services...");

    if !start_admin_backend(root) {
        std::process::exit(1);
    }
    println!("[soyeht] services started");
}

#[cfg(target_os = "macos")]
fn stop_stale_homebrew_runtime_processes(skip_confirm: bool) {
    let prefix = homebrew_prefix();
    let pids: Vec<String> = managed_processes(&prefix)
        .into_iter()
        .map(|(pid, _)| pid)
        .filter(|pid| *pid != std::process::id())
        .map(|pid| pid.to_string())
        .collect();
    if pids.is_empty() {
        return;
    }

    println!(
        "[soyeht] stopping stale Homebrew theyOS runtime processes: {}",
        pids.join(", ")
    );
    let term_ok = Command::new("kill")
        .arg("-TERM")
        .args(&pids)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !term_ok {
        let mut sudo_ready = Command::new("sudo")
            .args(["-n", "true"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !sudo_ready && !skip_confirm {
            println!(
                "[soyeht] admin privileges are required to stop stale root-owned theyOS helpers."
            );
            sudo_ready = Command::new("sudo")
                .arg("-v")
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        }
        if sudo_ready {
            let _ = Command::new("sudo")
                .arg("-n")
                .arg("kill")
                .arg("-TERM")
                .args(&pids)
                .status();
        } else {
            eprintln!(
                "[soyeht] warning: stale root-owned theyOS helpers are still running; VM startup may fail"
            );
            return;
        }
    }

    std::thread::sleep(std::time::Duration::from_secs(2));
    let survivors: Vec<String> = pids
        .iter()
        .filter_map(|pid| pid.parse::<u32>().ok())
        .filter(|pid| core_rs::os::is_pid_running(*pid))
        .map(|pid| pid.to_string())
        .collect();
    if !survivors.is_empty() {
        let _ = Command::new("sudo")
            .arg("-n")
            .arg("kill")
            .arg("-KILL")
            .args(&survivors)
            .status();
    }
}

/// Check if the macOS base VM image is fully initialized.
#[cfg(target_os = "macos")]
fn macos_base_is_ready() -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let state_file = std::path::PathBuf::from(&home)
        .join("Library/Application Support/theyos/vms/macos-base/init-state.json");
    let Ok(content) = fs::read_to_string(&state_file) else {
        return false;
    };
    // Phase serializes as lowercase snake_case (see vmrunner-macos-rs/src/init_state.rs)
    serde_json::from_str::<serde_json::Value>(&content)
        .ok()
        .and_then(|v| v.get("phase")?.as_str().map(|s| s == "complete"))
        .unwrap_or(false)
}

/// Resolve the `init_macos_guest` binary path.
#[cfg(target_os = "macos")]
fn resolve_init_bin(root: &Path) -> std::path::PathBuf {
    if let Ok(d) = std::env::var("THEYOS_BIN_DIR") {
        let p = std::path::PathBuf::from(d).join("init_macos_guest");
        if p.is_file() {
            return p;
        }
    }
    let release = root.join("admin/rust/target/release/init_macos_guest");
    if release.is_file() {
        return release;
    }
    root.join("admin/rust/target/debug/init_macos_guest")
}

/// Spawn `init_macos_guest` to download IPSW and create base VM image.
#[cfg(target_os = "macos")]
fn run_macos_init(root: &Path, force: bool) {
    let bin = resolve_init_bin(root);
    if !bin.is_file() {
        eprintln!("[soyeht] init_macos_guest not found: {}", bin.display());
        eprintln!("[soyeht] Set THEYOS_BIN_DIR or run from the repo directory.");
        std::process::exit(1);
    }
    let mut cmd = Command::new(&bin);
    cmd.arg("--yes");
    if force {
        cmd.arg("--force");
    }
    let status = cmd
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();
    match status {
        Ok(s) if s.success() => println!("[soyeht] macOS base image ready."),
        _ => {
            eprintln!("[soyeht] macOS guest initialization failed.");
            eprintln!("[soyeht] If the error mentions 'software update', update your Mac first:");
            eprintln!("[soyeht]   System Settings → General → Software Update");
            eprintln!("[soyeht] Then re-run `soyeht start` — the IPSW download will be skipped.");
            std::process::exit(1);
        }
    }
}

pub fn cmd_stop(root: &Path) {
    if crate::nixos::is_nixos_managed(root) {
        println!("[soyeht] NixOS mode: stopping services via systemctl...");
        crate::nixos::systemctl_or_exit(&["stop", "soyeht-admin-host.service"]);
        println!("[soyeht] services stopped");
        return;
    }

    println!("[soyeht] stopping services...");
    stop_admin_backend(root);
    println!("[soyeht] services stopped");
}

#[cfg(target_os = "macos")]
const HOMEBREW_MANAGED_BINARIES: &[&str] = &[
    "soyeht",
    "init_macos_guest",
    "theyos-admin-host",
    "server",
    "executor_ipc",
    "store-ipc",
    "terminal-ipc",
    "vmrunner_macos_ipc",
    "theyos-provision-inject",
];

#[cfg(target_os = "macos")]
fn homebrew_prefix() -> PathBuf {
    Command::new("brew")
        .arg("--prefix")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
            (!prefix.is_empty()).then(|| PathBuf::from(prefix))
        })
        .unwrap_or_else(|| PathBuf::from("/opt/homebrew"))
}

#[cfg(target_os = "macos")]
fn managed_command_matches(command: &str, prefix: &Path) -> bool {
    let prefix = prefix.to_string_lossy();
    let opt_prefix = format!("{prefix}/opt/theyos/");
    let cellar_prefix = format!("{prefix}/Cellar/theyos/");

    command.contains("/libexec/")
        && (command.starts_with(&opt_prefix) || command.starts_with(&cellar_prefix))
        && HOMEBREW_MANAGED_BINARIES
            .iter()
            .any(|binary| command.contains(&format!("/libexec/{binary}")))
}

#[cfg(target_os = "macos")]
fn managed_processes(prefix: &Path) -> Vec<(u32, String)> {
    let Ok(output) = Command::new("ps").args(["-axo", "pid=,command="]).output() else {
        return Vec::new();
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut parts = line.trim().splitn(2, char::is_whitespace);
            let pid = parts.next()?.parse::<u32>().ok()?;
            let command = parts.next()?.trim().to_string();
            managed_command_matches(&command, prefix).then_some((pid, command))
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn terminate_managed_processes(prefix: &Path) {
    // Skip the current process: the Homebrew wrapper at bin/soyeht exec's into
    // libexec/soyeht, so `cleanup-homebrew` itself matches `managed_command_matches`
    // and would SIGTERM itself before finishing.
    let self_pid = std::process::id();
    let pids: Vec<u32> = managed_processes(prefix)
        .into_iter()
        .map(|(pid, _)| pid)
        .filter(|pid| *pid != self_pid)
        .collect();
    if pids.is_empty() {
        return;
    }

    for &pid in &pids {
        core_rs::os::kill_pid(pid);
    }
    std::thread::sleep(std::time::Duration::from_secs(2));

    for pid in pids {
        if core_rs::os::is_pid_running(pid) {
            core_rs::os::kill_pid_force(pid);
        }
    }
}

#[cfg(target_os = "macos")]
fn launch_agent_paths(prefix: &Path) -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    vec![
        PathBuf::from(&home).join("Library/LaunchAgents/homebrew.mxcl.theyos.plist"),
        prefix.join("opt/homebrew.mxcl.theyos.plist"),
    ]
}

#[cfg(target_os = "macos")]
fn remove_path(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        fs::remove_dir_all(path).map_err(|e| format!("{}: {e}", path.display()))
    } else {
        fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(target_os = "macos")]
pub fn cmd_cleanup_homebrew(root: &Path, purge_data: bool) {
    println!("[soyeht] cleaning up Homebrew-managed theyOS state...");

    stop_admin_backend(root);
    Command::new("brew")
        .args(["services", "stop", "theyos"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok();

    let prefix = homebrew_prefix();
    terminate_managed_processes(&prefix);

    let mut failures = Vec::new();
    for path in launch_agent_paths(&prefix) {
        if let Err(err) = remove_path(&path) {
            failures.push(err);
        }
    }
    if let Err(err) = remove_path(&prefix.join("var/log/theyos.log")) {
        failures.push(err);
    }

    if purge_data {
        println!("[soyeht] purging ~/.theyos, VMs, logs, caches, and temp databases...");
        let home = std::env::var("HOME").unwrap_or_default();
        let data_paths = [
            root.to_path_buf(),
            PathBuf::from(&home).join("Library/Application Support/theyos"),
            PathBuf::from(&home).join("Library/Logs/theyos"),
            PathBuf::from(&home).join("Library/Caches/theyos"),
            PathBuf::from("/tmp/theyos.db"),
            PathBuf::from("/tmp/theyos-sessions.db"),
        ];

        for path in data_paths {
            if let Err(err) = remove_path(&path) {
                failures.push(err);
            }
        }
    }

    if failures.is_empty() {
        println!("[soyeht] Homebrew cleanup complete");
        return;
    }

    eprintln!("[soyeht] cleanup completed with residual errors:");
    for failure in &failures {
        eprintln!("  - {failure}");
    }
    eprintln!(
        "[soyeht] If the purge hit EACCES under ~/Library/Application Support/theyos/vms/macos-base,\n\
         run: sudo chown -R $(whoami):staff ~/Library/Application\\ Support/theyos/vms/macos-base"
    );
    std::process::exit(1);
}

#[cfg(not(target_os = "macos"))]
pub fn cmd_cleanup_homebrew(_root: &Path, _purge_data: bool) {
    eprintln!("[soyeht] cleanup-homebrew is only available on macOS Homebrew installs");
    std::process::exit(1);
}

pub fn cmd_rebuild(root: &Path, _clean: bool, _skip_confirm: bool) {
    println!("[soyeht] restarting services...");
    stop_admin_backend(root);
    if !start_admin_backend(root) {
        std::process::exit(1);
    }
    println!("[soyeht] services restarted");
}

pub fn cmd_logs(root: &Path) {
    if crate::nixos::is_nixos_managed(root) {
        Command::new("journalctl")
            .args(["-u", "soyeht-admin-host.service", "-f", "--no-pager"])
            .status()
            .ok();
        return;
    }

    crate::admin_backend::admin_host_logs(root);
}

pub fn cmd_status(root: &Path, resources: bool, deep: bool) {
    if crate::nixos::is_nixos_managed(root) {
        println!("[soyeht] NixOS-managed services:");
        Command::new("systemctl")
            .args(["status", "--no-pager", "soyeht-admin-host.service"])
            .status()
            .ok();
        println!();
        println!("[soyeht] admin backend health:");
        let health = crate::util::admin_health_url(root);
        if curl_ok(&health, 2) {
            println!("  healthz: up");
        } else {
            println!("  healthz: down");
        }
        return;
    }

    println!("[soyeht] admin backend status:");
    admin_backend_status(root);

    if resources {
        println!();
        println!("[soyeht] host resources:");
        let disk_path = core_rs::host_resources::resolve_instance_disk_path();
        match core_rs::host_resources::detect_all(&disk_path) {
            Ok(h) => {
                let cpu_reserve: u32 = std::env::var("THEYOS_CPU_RESERVE")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                let ram_percent: u64 = std::env::var("THEYOS_RAM_BUDGET_PERCENT")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(80);
                let cpu_budget = h.cpu_cores.saturating_sub(cpu_reserve);
                let ram_budget = (h.total_ram_mb * ram_percent) / 100;

                println!("  ┌─────────────┬──────────┬──────────┐");
                println!("  │   Resource   │   Host   │  Budget  │");
                println!("  ├─────────────┼──────────┼──────────┤");
                println!(
                    "  │ CPU cores   │ {:>6}   │ {:>6}   │",
                    h.cpu_cores, cpu_budget
                );
                println!(
                    "  │ RAM (MB)    │ {:>6}   │ {:>6}   │",
                    h.total_ram_mb, ram_budget
                );
                println!("  │ RAM free    │ {:>6}   │          │", h.available_ram_mb);
                println!("  │ Disk (GB)   │ {:>6}   │          │", h.total_disk_gb);
                println!(
                    "  │ Disk free   │ {:>6}   │          │",
                    h.available_disk_gb
                );
                println!("  └─────────────┴──────────┴──────────┘");
                println!("  cpu_reserve={cpu_reserve}  ram_budget_percent={ram_percent}%");
            }
            Err(e) => println!("  [ERROR] failed to detect resources: {e}"),
        }
    }

    if deep {
        println!();
        println!("[soyeht] configuration and disk checks:");
        let ts = timestamp();

        // .env permissions
        let env_file = root.join(".env");
        if env_file.exists() {
            let perms = file_permissions(&env_file);
            if perms == "600" {
                println!("{ts} [OK] .env permissions OK");
            } else {
                println!("{ts} [WARN] .env has permissions {perms} (recommended: 600)");
                println!("       Suggestion: chmod 600 .env");
            }
        } else {
            println!("{ts} [WARN] .env file not found");
        }

        // .env tracked in git?
        let git_tracked = Command::new("git")
            .args(["ls-files", "--error-unmatch", ".env"])
            .current_dir(root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if git_tracked {
            println!("{ts} [CRITICAL] .env is tracked in git! Remove with:");
            println!("       git rm --cached .env && git commit -m 'Remove .env'");
        } else {
            println!("{ts} [OK] .env is not tracked in git");
        }

        // Disk space (warn if < 1 GB)
        let avail_kb = available_disk_kb("/");
        if avail_kb < 1_048_576 {
            println!("{ts} [WARN] low disk space ({avail_kb} KB available)");
        } else {
            println!("{ts} [OK] sufficient disk space ({avail_kb} KB available)");
        }
    }

    #[cfg(target_os = "macos")]
    {
        println!();
        println!("[soyeht] caddy:");
        let s = crate::caddy_manager::status(root);
        match &s.binary {
            Some(b) => println!(
                "  binary:        {} ({})",
                b.path.display(),
                if b.version.is_empty() {
                    "version unknown"
                } else {
                    &b.version
                }
            ),
            None => println!("  binary:        not found  (run: soyeht caddy install)"),
        }
        println!(
            "  plist:         {}",
            if s.plist_present {
                "installed (~/Library/LaunchAgents/com.soyeht.caddy.plist)"
            } else {
                "missing"
            }
        );
        let agent_state = if s.launch.loaded {
            match s.launch.pid {
                Some(p) => format!("loaded (pid {p})"),
                None => "loaded (not running)".to_string(),
            }
        } else {
            "not loaded".to_string()
        };
        println!("  agent:         {agent_state}");
        println!(
            "  admin api:     {}",
            if s.admin_api_up {
                "up (localhost:2019)"
            } else {
                "down"
            }
        );
        if s.plist_drift {
            println!("  [WARN] plist points at a stale repo path; run: soyeht caddy start");
        }
        if let Some(code) = s.launch.last_exit_code
            && code != 0
        {
            println!("  [WARN] last exit code: {code}");
        }
    }
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::many_single_char_names)]
pub fn cmd_backup(root: &Path) {
    println!("[soyeht] creating full project backup...");

    let ts = {
        let (y, mo, d, h, m, s) = core_rs::time::unix_to_datetime(core_rs::time::unix_now_secs());
        format!("{y:04}{mo:02}{d:02}_{h:02}{m:02}{s:02}")
    };

    let backup_parent = root.parent().unwrap_or(root).join("theyos-backups");
    let backup_dir = backup_parent.join(&ts);
    fs::create_dir_all(&backup_dir).unwrap_or_else(|e| {
        eprintln!("[soyeht] create backup dir: {e}");
        std::process::exit(1)
    });

    // Cloudflare configs
    let cloudflared = root.join("distro/cloudflared");
    if cloudflared.is_dir() {
        let jsons: Vec<_> = cloudflared
            .read_dir()
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .map(|e| e.path())
            .collect();
        if !jsons.is_empty() {
            println!("[soyeht] backing up Cloudflare configs...");
            let mut tar_args = vec!["-czf".to_string()];
            tar_args.push(
                backup_dir
                    .join(format!("configs_{ts}.tar.gz"))
                    .to_string_lossy()
                    .to_string(),
            );
            for j in &jsons {
                tar_args.push(j.to_string_lossy().to_string());
            }
            Command::new("tar")
                .args(&tar_args)
                .current_dir(root)
                .status()
                .ok();
        }
    }

    // Code backup
    println!("[soyeht] backing up code...");
    let bundle = backup_dir.join(format!("code_{ts}.bundle"));
    let bundle_ok = Command::new("git")
        .args(["bundle", "create", bundle.to_str().unwrap(), "--all"])
        .current_dir(root)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !bundle_ok {
        println!("[soyeht] git bundle failed; falling back to tar...");
        Command::new("tar")
            .args([
                "-czf",
                backup_dir
                    .join(format!("code_{ts}.tar.gz"))
                    .to_str()
                    .unwrap(),
                "--exclude=*.json",
                "--exclude=__pycache__",
                "--exclude=.git",
                ".",
            ])
            .current_dir(root)
            .status()
            .ok();
    }

    // RECREATE.md
    let git_head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "no-git".to_string(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        );

    let now_str = {
        let (y, mo, d, h, m, s) = core_rs::time::unix_to_datetime(core_rs::time::unix_now_secs());
        format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
    };

    let recreate = format!(
        r"# Recreation Guide — theyOS

**Backup date:** {now_str}
**Version:** {git_head}

## Restore Checklist

### 1. Restore Code
git clone https://github.com/soyeht/theyos.git theyos

### 2. Restore Configs
cd theyos
# Extract configs from backup, edit .env
cp .env.example .env

### 3. Start Services
soyeht rebuild
soyeht status --resources

### 4. Verify
- Admin Panel: http://localhost:8892
- Cloudflare Tunnel: https://admin.${{THEYOS_BASE_DOMAIN}} (from .env)

## Important Configurations
- Cloudflare Tunnel: distro/cloudflared/config.yml (gitignored, restore from backup)
"
    );

    let recreate_path = backup_dir.join(format!("RECREATE_{ts}.md"));
    fs::write(&recreate_path, recreate).ok();

    // Rotation: keep at most 3 most-recent backups
    if backup_parent.is_dir() {
        let mut entries: Vec<_> = backup_parent
            .read_dir()
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().is_dir())
            .collect();
        entries.sort_by_key(|e| {
            e.metadata()
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH)
        });
        entries.reverse(); // newest first
        if entries.len() > 3 {
            println!("[soyeht] removing old backups (keeping 3 most recent)...");
            for old in &entries[3..] {
                println!("  removing: {}", old.path().display());
                fs::remove_dir_all(old.path()).ok();
            }
        }
    }

    println!("[soyeht] backup created: {}", backup_dir.display());
    // List backup contents
    if let Ok(rd) = backup_dir.read_dir() {
        for e in rd.flatten() {
            let meta = e.metadata().ok();
            let size = meta.map_or(0, |m| m.len());
            println!("  {:>10} bytes  {}", size, e.file_name().to_string_lossy());
        }
    }
}

pub fn cmd_health(_root: &Path) {
    println!("[soyeht] checking service health...");
    let ts = timestamp();
    let mut fails: u32 = 0;

    // 1) Cloudflare Tunnel
    println!("[soyeht] checking Cloudflare Tunnel...");
    if curl_ok("http://127.0.0.1:2000/ready", 10) {
        println!("{ts} [OK] Cloudflare Tunnel OK");
    } else {
        println!("{ts} [FAIL] Cloudflare Tunnel is NOT ready");
        println!("       To check: sudo systemctl status cloudflared");
        fails += 1;
    }

    // 2) Local apps
    println!("[soyeht] checking local applications...");
    let apps = [
        ("http://localhost:8892", "Admin backend"),
        ("http://localhost:8080", "Caddy Proxy"),
    ];
    for (url, name) in &apps {
        if curl_ok(url, 10) {
            println!("{ts} [OK] {name} ({url})");
        } else {
            println!("{ts} [FAIL] {name} DOWN ({url})");
            fails += 1;
        }
    }

    // 2.1) Security headers
    println!("[soyeht] checking security headers on proxy...");
    let headers = curl_headers("http://localhost:8080");
    if headers.contains("x-content-type-options") {
        println!("{ts} [OK] security headers detected on localhost:8080");
    } else {
        println!("{ts} [WARN] security headers NOT detected on http://localhost:8080");
    }

    // 3) Public URLs (only if no failures yet and THEYOS_BASE_DOMAIN is set).
    // Skip if no base domain configured — forks don't have public URLs to check.
    if fails == 0 {
        if let Ok(base) = std::env::var("THEYOS_BASE_DOMAIN") {
            if !base.is_empty() {
                println!("[soyeht] checking public URLs...");
                let admin_url = format!("https://admin.{base}");
                let root_url = format!("https://{base}");
                let public = [
                    (admin_url.as_str(), "Admin"),
                    (root_url.as_str(), "Marketing"),
                ];
                for (url, name) in &public {
                    if curl_ok(url, 20) {
                        println!("{ts} [OK] {name} OK ({url})");
                    } else {
                        println!("{ts} [WARN] {name} may have issues ({url})");
                    }
                }
            }
        }
    }

    println!();
    if fails == 0 {
        println!("[soyeht] all services are running");
    } else {
        println!("[soyeht] {fails} issue(s) detected — try: soyeht rebuild");
        std::process::exit(1);
    }
}

pub fn cmd_snapshot_create(root: &Path, claw_types: &[String]) {
    let runner = e2e_runner_bin(root);
    let mut cmd = Command::new(&runner);
    cmd.arg("snapshot");
    for ct in claw_types {
        cmd.arg(ct);
    }
    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("[soyeht] e2e-runner: {e}");
        std::process::exit(1)
    });
    std::process::exit(status.code().unwrap_or(1));
}

/// Run a lightweight smoke test against the local admin backend.
///
/// Delegates to `e2e-runner smoke` which verifies 7 critical API routes
/// in ~5 seconds without creating any VM instances.
pub fn cmd_smoke_test(root: &Path) {
    let runner = e2e_runner_bin(root);
    if !runner.exists() {
        eprintln!(
            "[soyeht] e2e-runner binary not found at {}",
            runner.display()
        );
        eprintln!("[soyeht] Run `soyeht rebuild-admin` first to build it.");
        std::process::exit(1);
    }
    let status = Command::new(&runner)
        .arg("smoke")
        .status()
        .unwrap_or_else(|e| {
            eprintln!("[soyeht] e2e-runner smoke: {e}");
            std::process::exit(1)
        });
    std::process::exit(status.code().unwrap_or(1));
}
