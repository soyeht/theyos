//! Admin backend lifecycle — start, stop, status, logs.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::util::{admin_health_url, curl_ok, is_pid_running, read_pid};

// ── Path helpers ─────────────────────────────────────────────────────────────

pub fn admin_runner(root: &Path) -> PathBuf {
    if let Ok(d) = std::env::var("THEYOS_BIN_DIR") {
        let p = PathBuf::from(d).join("theyos-admin-host");
        if p.is_file() {
            return p;
        }
    }
    let release = root.join("admin/rust/target/release/theyos-admin-host");
    if release.is_file() {
        return release;
    }
    root.join("admin/rust/target/debug/theyos-admin-host")
}

pub fn pid_file(root: &Path) -> PathBuf {
    root.join(".run/soyeht-admin-host.pid")
}

pub fn log_file(root: &Path) -> PathBuf {
    root.join("logs/soyeht-admin-host.log")
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

pub fn start_admin_backend(root: &Path) -> bool {
    if crate::nixos::is_nixos_managed(root) {
        println!("[soyeht] NixOS mode: starting admin backend via systemctl...");
        crate::nixos::systemctl_or_exit(&["start", "soyeht-admin-host.service"]);
        let health = admin_health_url(root);
        for i in 0..30 {
            thread::sleep(Duration::from_secs(1));
            if curl_ok(&health, 2) {
                println!("[soyeht] admin host backend started (systemd)");
                return true;
            }
            if i == 10 {
                println!("[soyeht] still waiting for backend...");
            }
        }
        eprintln!("[soyeht] admin backend not healthy after 30s");
        return false;
    }

    let pid_path = pid_file(root);
    let log_path = log_file(root);
    let runner = admin_runner(root);
    let health = admin_health_url(root);

    fs::create_dir_all(pid_path.parent().unwrap()).ok();
    fs::create_dir_all(log_path.parent().unwrap()).ok();

    // Already running?
    if let Some(pid) = read_pid(&pid_path) {
        if is_pid_running(pid) && curl_ok(&health, 2) {
            println!("[soyeht] admin host backend already running (pid {pid})");
            return true;
        }
        fs::remove_file(&pid_path).ok();
    }
    if curl_ok(&health, 2) {
        println!("[soyeht] admin host backend already running (external process)");
        return true;
    }

    #[cfg(not(target_os = "macos"))]
    if !Path::new("/dev/kvm").exists() {
        eprintln!("[soyeht] warning: /dev/kvm not found — Firecracker create will fail");
    }

    if !runner.is_file() {
        eprintln!("[soyeht] admin runner not found: {}", runner.display());
        return false;
    }

    let log_fd = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .unwrap_or_else(|e| {
            eprintln!("[soyeht] open admin log: {e}");
            std::process::exit(1)
        });

    println!("[soyeht] starting admin backend on host...");

    let mut cmd = Command::new(&runner);
    cmd.stdin(Stdio::null())
        .stdout(log_fd.try_clone().expect("clone fd for stderr redirect"))
        .stderr(log_fd);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        // The CLI returns after startup. Put the backend in its own session so
        // shells, launch wrappers, and test harnesses do not reap it with the
        // parent process group.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let child = cmd.spawn();

    let pid = match child {
        Ok(c) => c.id(),
        Err(e) => {
            eprintln!("[soyeht] failed to spawn admin backend: {e}");
            return false;
        }
    };

    fs::write(&pid_path, pid.to_string()).ok();

    // Wait up to 30 seconds for it to become healthy
    for i in 0..30 {
        thread::sleep(Duration::from_secs(1));
        if curl_ok(&health, 2) {
            println!("[soyeht] admin host backend started (pid {pid})");
            return true;
        }
        if i == 10 {
            println!("[soyeht] still waiting for backend...");
        }
    }

    eprintln!("[soyeht] admin host backend failed to become healthy in 30s");
    if let Ok(tail) = fs::read_to_string(&log_path) {
        let lines: Vec<&str> = tail.lines().collect();
        let start = lines.len().saturating_sub(30);
        for line in &lines[start..] {
            eprintln!("  {line}");
        }
    }
    false
}

pub fn stop_admin_backend(root: &Path) {
    if crate::nixos::is_nixos_managed(root) {
        println!("[soyeht] NixOS mode: stopping admin backend via systemctl...");
        crate::nixos::systemctl_or_exit(&["stop", "soyeht-admin-host.service"]);
        println!("[soyeht] admin host backend stopped (systemd)");
        return;
    }

    let pid_path = pid_file(root);
    let Some(pid) = read_pid(&pid_path) else {
        println!("[soyeht] admin host backend is not running (no pid file)");
        return;
    };
    if is_pid_running(pid) {
        println!("[soyeht] stopping admin host backend (pid {pid})...");
        core_rs::os::kill_pid(pid);
        thread::sleep(Duration::from_secs(1));
        if is_pid_running(pid) {
            core_rs::os::kill_pid_force(pid);
        }
    }
    fs::remove_file(&pid_path).ok();
    println!("[soyeht] admin host backend stopped");
}

pub fn admin_backend_status(root: &Path) -> bool {
    if crate::nixos::is_nixos_managed(root) {
        let status = Command::new("systemctl")
            .args(["is-active", "soyeht-admin-host.service"])
            .output();
        let active = status.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "active");
        let health = admin_health_url(root);
        let healthy = curl_ok(&health, 2);
        println!(
            "admin-host: {} (systemd, health={})",
            if active { "active" } else { "inactive" },
            if healthy { "up" } else { "down" }
        );
        return active && healthy;
    }

    let pid_path = pid_file(root);
    let health = admin_health_url(root);
    let healthy = curl_ok(&health, 2);

    if let Some(pid) = read_pid(&pid_path) {
        if is_pid_running(pid) {
            println!(
                "admin-host: running (pid={pid}, health={})",
                if healthy { "up" } else { "down" }
            );
            return true;
        }
        println!(
            "admin-host: stale-pid (health={})",
            if healthy { "up" } else { "down" }
        );
        return false;
    }

    if healthy {
        println!("admin-host: running (external, no pid file)");
        return true;
    }

    println!("admin-host: stopped");
    false
}

pub fn admin_host_logs(root: &Path) {
    if crate::nixos::is_nixos_managed(root) {
        Command::new("journalctl")
            .args(["-u", "soyeht-admin-host.service", "-f", "--no-pager"])
            .status()
            .ok();
        return;
    }

    let log_path = log_file(root);
    fs::create_dir_all(log_path.parent().unwrap()).ok();
    if !log_path.exists() {
        fs::write(&log_path, "").ok();
    }

    // Stream the file (tail -f equivalent)
    let file = match fs::File::open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[soyeht] cannot open log file: {e}");
            return;
        }
    };

    let mut reader = io::BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                thread::sleep(Duration::from_millis(200));
            }
            Ok(_) => {
                print!("{line}");
                io::stdout().flush().ok();
            }
            Err(e) => {
                eprintln!("[soyeht] log read error: {e}");
                break;
            }
        }
    }
}
