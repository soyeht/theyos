//! Dev commands — dev server, rebuild-admin, test-admin, admin-doctor.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::cmd_available;

// ── Path helpers ─────────────────────────────────────────────────────────────

pub fn admin_dev_pid_file(root: &Path) -> PathBuf {
    root.join("admin/.dev.pids")
}

// ── Commands ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
pub fn cmd_dev(root: &Path, kill: bool, status: bool) {
    let pid_file = admin_dev_pid_file(root);

    if kill {
        if pid_file.is_file() {
            let content = fs::read_to_string(&pid_file).unwrap_or_default();
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    core_rs::os::kill_pid(pid);
                }
            }
            fs::remove_file(&pid_file).ok();
            println!("[dev] stopped");
        } else {
            println!("[dev] no pid file");
        }
        return;
    }

    if status {
        if pid_file.is_file() {
            let pids = fs::read_to_string(&pid_file).unwrap_or_default();
            println!("[dev] pids: {}", pids.lines().collect::<Vec<_>>().join(" "));
        } else {
            println!("[dev] not running");
        }
        return;
    }

    let admin_root = root.join("admin");
    let rs_binary = admin_root.join("rust/target/debug/server");
    let log_dir = std::env::var("LOG_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let backend_log = PathBuf::from(&log_dir).join("soyeht-admin-backend.log");
    let frontend_log = PathBuf::from(&log_dir).join("soyeht-admin-frontend.log");

    let addr = std::env::var("ADDR").unwrap_or_else(|_| "127.0.0.1:8892".to_string());
    let frontend_origin =
        std::env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:5173".to_string());
    let frontend_host = std::env::var("FRONTEND_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let frontend_port = std::env::var("FRONTEND_PORT").unwrap_or_else(|_| "5173".to_string());

    // Build Rust binary if missing
    if !rs_binary.is_file() {
        println!("[dev] Rust binary not found — building first...");
        let ok = Command::new("cargo")
            .args(["build", "-p", "server-rs"])
            .current_dir(admin_root.join("rust"))
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("[dev] cargo build failed");
            std::process::exit(1);
        }
    }

    // Truncate pid file
    fs::write(&pid_file, "").ok();

    // Start backend
    println!("[dev] backend -> {addr}");
    let backend_fd = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&backend_log)
        .unwrap_or_else(|e| {
            eprintln!("[soyeht] open backend log: {e}");
            std::process::exit(1)
        });
    let backend_child = Command::new(&rs_binary)
        .env("ADDR", &addr)
        .env("FRONTEND_ORIGIN", &frontend_origin)
        .env("WEB_DIR", admin_root.join("web"))
        .stdout(backend_fd.try_clone().expect("clone backend log fd"))
        .stderr(backend_fd)
        .spawn();
    match backend_child {
        Ok(c) => {
            let pid = c.id();
            let mut content = fs::read_to_string(&pid_file).unwrap_or_default();
            writeln!(content, "{pid}").expect("write pid");
            fs::write(&pid_file, content).ok();
        }
        Err(e) => {
            eprintln!("[dev] failed to start backend: {e}");
            std::process::exit(1);
        }
    }

    // Start frontend
    println!("[dev] frontend -> http://{frontend_host}:{frontend_port}");
    let frontend_fd = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&frontend_log)
        .unwrap_or_else(|e| {
            eprintln!("[soyeht] open frontend log: {e}");
            std::process::exit(1)
        });
    let frontend_child = Command::new("npm")
        .args([
            "run",
            "dev",
            "--",
            "--host",
            &frontend_host,
            "--port",
            &frontend_port,
        ])
        .current_dir(admin_root.join("frontend"))
        .stdout(frontend_fd.try_clone().expect("clone frontend log fd"))
        .stderr(frontend_fd)
        .spawn();
    match frontend_child {
        Ok(c) => {
            let pid = c.id();
            let mut content = fs::read_to_string(&pid_file).unwrap_or_default();
            writeln!(content, "{pid}").expect("write pid");
            fs::write(&pid_file, content).ok();
        }
        Err(e) => {
            eprintln!("[dev] failed to start frontend: {e}");
        }
    }

    println!("[dev] started (logs in {log_dir})");
}

pub fn cmd_rebuild_admin(root: &Path, skip_install: bool) {
    let admin_root = root.join("admin");

    println!("[rebuild] frontend");
    let frontend_dir = admin_root.join("frontend");

    if !skip_install {
        let ok = Command::new("npm")
            .arg("ci")
            .current_dir(&frontend_dir)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("[rebuild] npm ci failed");
            std::process::exit(1);
        }
    }

    let ok = Command::new("npm")
        .args(["run", "build"])
        .current_dir(&frontend_dir)
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("[rebuild] npm run build failed");
        std::process::exit(1);
    }

    println!("[rebuild] Rust workspace (all crates)");
    let ok = Command::new("cargo")
        .args(["build", "--workspace"])
        .current_dir(admin_root.join("rust"))
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("[rebuild] cargo build --workspace failed");
        std::process::exit(1);
    }

    println!("[rebuild] ok");
}

pub fn cmd_test_admin(root: &Path) {
    let admin_root = root.join("admin");

    println!("[test] rust workspace");
    let ok = Command::new("cargo")
        .args(["test", "--workspace"])
        .current_dir(admin_root.join("rust"))
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("[test] cargo test --workspace failed");
        std::process::exit(1);
    }

    println!("[test] frontend build");
    let ok = Command::new("npm")
        .args(["run", "build"])
        .current_dir(admin_root.join("frontend"))
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        eprintln!("[test] npm run build failed");
        std::process::exit(1);
    }

    println!("[test] ok");
}

pub fn cmd_admin_doctor(root: &Path) {
    let admin_root = root.join("admin");
    let mut fail = false;

    let check_cmd_tool = |name: &str| -> bool {
        let ok = cmd_available(name);
        if ok {
            println!("[doctor] ok: {name}");
        } else {
            eprintln!("[doctor] missing: {name}");
        }
        ok
    };

    let check_file_tool = |path: &Path| -> bool {
        if path.is_file() {
            println!(
                "[doctor] ok: {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            true
        } else {
            eprintln!("[doctor] missing: {}", path.display());
            false
        }
    };

    for tool in &["cargo", "rustc", "node", "npm"] {
        fail |= !check_cmd_tool(tool);
    }

    // Print versions for tools that are present
    for tool in &["cargo", "rustc", "node", "npm"] {
        if cmd_available(tool) {
            let out = Command::new(tool).arg("--version").output();
            if let Ok(o) = out {
                if o.status.success() {
                    let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    println!("[doctor] {tool}: {v}");
                } else {
                    eprintln!("[doctor] {tool} --version failed");
                    fail = true;
                }
            }
        }
    }

    if !check_file_tool(&admin_root.join("rust/Cargo.toml")) {
        fail = true;
    }
    if !check_file_tool(&admin_root.join("frontend/package.json")) {
        fail = true;
    }
    if !check_file_tool(&admin_root.join("frontend/package-lock.json")) {
        fail = true;
    }

    if fail {
        eprintln!("[doctor] issues found");
        std::process::exit(1);
    }

    println!("[doctor] ok");
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_dev_pid_file_path() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let pf = admin_dev_pid_file(dir.path());
        assert!(pf.to_string_lossy().ends_with("admin/.dev.pids"));
    }

    #[test]
    fn dev_status_when_no_pid_file() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let pid_file = admin_dev_pid_file(dir.path());
        assert!(!pid_file.exists());
        assert!(!pid_file.is_file(), "pid file should not exist");
    }

    #[test]
    fn dev_kill_when_no_pid_file() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let pid_file = admin_dev_pid_file(dir.path());
        assert!(!pid_file.exists());
        assert!(!pid_file.is_file(), "should be no-op");
    }
}
