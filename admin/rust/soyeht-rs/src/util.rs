//! Small shared utilities — process helpers, curl wrappers, timestamps, etc.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ── Process helpers ──────────────────────────────────────────────────────────

pub fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

pub fn is_pid_running(pid: u32) -> bool {
    core_rs::os::is_pid_running(pid)
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

pub fn curl_ok(url: &str, timeout_secs: u64) -> bool {
    Command::new("curl")
        .args(["-fs", "--max-time", &timeout_secs.to_string(), url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

pub fn curl_headers(url: &str) -> String {
    let out = Command::new("curl")
        .args(["-s", "-I", "--max-time", "10", url])
        .output()
        .unwrap_or_else(|_| std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: vec![],
            stderr: vec![],
        });
    String::from_utf8_lossy(&out.stdout).to_lowercase()
}

// ── Port / URL helpers ───────────────────────────────────────────────────────

pub fn admin_port(root: &Path) -> u16 {
    let env_file = root.join(".env");
    core_rs::env::read_env_field(&env_file, "ADMIN_PORT")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(core_rs::constants::DEFAULT_ADMIN_PORT)
}

pub fn admin_health_url(root: &Path) -> String {
    format!("http://127.0.0.1:{}/healthz", admin_port(root))
}

// ── Paths ────────────────────────────────────────────────────────────────────

pub fn debug_dir(root: &Path) -> PathBuf {
    root.join("admin/rust/target/debug")
}

pub fn imagebuilder_bin(root: &Path) -> PathBuf {
    resolve_sibling_bin(root, "imagebuilder")
}

pub fn e2e_runner_bin(root: &Path) -> PathBuf {
    resolve_sibling_bin(root, "e2e-runner")
}

/// Resolve a companion binary by name. Search order:
/// 1. `THEYOS_BIN_DIR` env var
/// 2. Same directory as the current executable (NixOS: all bins co-located in Nix store)
/// 3. `target/release/`
/// 4. `target/debug/` (fallback, may not exist)
fn resolve_sibling_bin(root: &Path, name: &str) -> PathBuf {
    if let Ok(d) = std::env::var("THEYOS_BIN_DIR") {
        let p = PathBuf::from(&d).join(name);
        if p.is_file() {
            return p;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join(name);
            if p.is_file() {
                return p;
            }
        }
    }
    let release = root.join("admin/rust/target/release").join(name);
    if release.is_file() {
        return release;
    }
    debug_dir(root).join(name)
}

// ── Claw store helpers ──────────────────────────────────────────────────────

/// Query the running admin server for installed ("ready") claws.
///
/// Falls back to reading the local claw store state file
/// (`$THEYOS_DIR/.run/installed_claws.json`) if the server is not reachable.
/// Returns an empty vec if no claws are installed.
pub fn ready_claws_from_server(root: &Path) -> Vec<String> {
    let base = admin_health_url(root).replace("/healthz", "");
    let url = format!("{base}/api/v1/claws");

    let resp = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .get(&url)
        .call();

    let Ok(resp) = resp else {
        return ready_claws_from_state_file(root);
    };

    let Ok(body) = resp.into_string() else {
        return ready_claws_from_state_file(root);
    };

    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) else {
        return ready_claws_from_state_file(root);
    };

    let Some(items) = parsed["data"].as_array() else {
        return ready_claws_from_state_file(root);
    };

    items
        .iter()
        .filter(|item| item["status"].as_str() == Some("ready"))
        .filter_map(|item| item["name"].as_str().map(String::from))
        .collect()
}

/// Fallback: read the local claw store state file directly.
///
/// The state file is the authoritative source of truth for which claws are
/// installed on this host. Respects `THEYOS_CLAW_STATE_FILE` env var override,
/// matching the same logic as `server-rs/src/main.rs`.
fn ready_claws_from_state_file(root: &Path) -> Vec<String> {
    let state_file = std::env::var("THEYOS_CLAW_STATE_FILE")
        .map_or_else(|_| root.join(".run/installed_claws.json"), PathBuf::from);
    let Ok(content) = std::fs::read_to_string(&state_file) else {
        return Vec::new();
    };
    let Ok(map) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&content)
    else {
        return Vec::new();
    };
    map.into_iter()
        .filter(|(_, v)| v.get("status").and_then(|s| s.as_str()) == Some("ready"))
        .map(|(name, _)| name)
        .collect()
}

// ── Time / formatting ────────────────────────────────────────────────────────

pub fn timestamp() -> String {
    core_rs::time::now_bracket()
}

// ── File system helpers ──────────────────────────────────────────────────────

pub fn file_permissions(path: &Path) -> String {
    let path_str = path.to_string_lossy();
    let out = Command::new("stat").args(["-c", "%a", &*path_str]).output();
    if let Ok(o) = out {
        if o.status.success() {
            return String::from_utf8_lossy(&o.stdout).trim().to_string();
        }
    }
    // BSD fallback
    let out = Command::new("stat")
        .args(["-f", "%Lp", &*path_str])
        .output();
    if let Ok(o) = out {
        if o.status.success() {
            return String::from_utf8_lossy(&o.stdout).trim().to_string();
        }
    }
    "000".to_string()
}

pub fn available_disk_kb(mount: &str) -> u64 {
    let out = Command::new("df").arg(mount).output();
    if let Ok(o) = out {
        let text = String::from_utf8_lossy(&o.stdout);
        // Second line, 4th field
        if let Some(line) = text.lines().nth(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if let Some(avail) = fields.get(3) {
                return avail.parse::<u64>().unwrap_or(0);
            }
        }
    }
    0
}

pub fn is_exec(path: &Path) -> bool {
    core_rs::os::is_executable(path)
}

pub fn cmd_available(cmd: &str) -> bool {
    core_rs::os::which_binary(cmd).is_some()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn civil_from_days_epoch() {
        let (y, m, d) = core_rs::time::civil_from_days(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_known_date() {
        let secs_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let days = secs_now / 86400;
        // NOTE: days since epoch fits in i64 for any foreseeable date.
        #[allow(clippy::cast_possible_wrap)]
        let (y, m, d) = core_rs::time::civil_from_days(days as i64);
        assert!((2025..=2030).contains(&y), "year out of range: {y}");
        assert!((1..=12).contains(&m), "month out of range: {m}");
        assert!((1..=31).contains(&d), "day out of range: {d}");
    }

    #[test]
    fn timestamp_is_non_empty() {
        let ts = timestamp();
        assert!(ts.starts_with('['), "timestamp should start with [: {ts}");
    }

    #[test]
    fn admin_port_default_when_no_env_file() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let port = admin_port(dir.path());
        assert_eq!(port, 8892);
    }

    #[test]
    fn admin_port_reads_from_env_file() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".env"), "ADMIN_PORT=9000\n").unwrap();
        let port = admin_port(dir.path());
        assert_eq!(port, 9000);
    }

    #[test]
    fn admin_health_url_format() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let url = admin_health_url(dir.path());
        assert_eq!(url, "http://127.0.0.1:8892/healthz");
    }

    #[test]
    fn is_exec_on_bin_sh() {
        assert!(is_exec(Path::new("/bin/sh")));
    }

    #[test]
    fn is_exec_on_missing() {
        assert!(!is_exec(Path::new("/tmp/no-such-soyeht-test-bin")));
    }

    #[test]
    fn cmd_available_true_for_ls() {
        assert!(cmd_available("ls"));
    }

    #[test]
    fn cmd_available_false_for_nonexistent() {
        assert!(!cmd_available("soyeht-definitely-not-a-real-command-xyz"));
    }

    // ── ready_claws_from_state_file tests ───────────────────────────────

    /// Test the env override path: `THEYOS_CLAW_STATE_FILE` points to a custom
    /// location, the default .run/ path has different content, and the override
    /// wins. Also covers the "reads ready claws" and "empty when missing" cases
    /// in a single test to avoid env var races with parallel threads.
    #[test]
    fn state_file_env_override_and_default_fallback() {
        use tempfile::TempDir;

        // Part 1: env override wins over default path
        let dir = TempDir::new().unwrap();

        let custom_path = dir.path().join("custom_state.json");
        std::fs::write(&custom_path, r#"{"ironclaw":{"status":"ready"}}"#).unwrap();

        let run_dir = dir.path().join(".run");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(
            run_dir.join("installed_claws.json"),
            r#"{"picoclaw":{"status":"ready"},"zeroclaw":{"status":"installing"},"nanobot":{"status":"ready"}}"#,
        )
        .unwrap();

        core_rs::env::set_test_env("THEYOS_CLAW_STATE_FILE", custom_path.to_str().unwrap());
        let result = ready_claws_from_state_file(dir.path());
        core_rs::env::remove_test_env("THEYOS_CLAW_STATE_FILE");

        // Override path has only ironclaw=ready
        assert_eq!(result, vec!["ironclaw".to_string()]);

        // Part 2: without override, reads default path and filters by status
        let result2 = ready_claws_from_state_file(dir.path());
        assert!(
            result2.contains(&"picoclaw".to_string()),
            "picoclaw should be ready"
        );
        assert!(
            result2.contains(&"nanobot".to_string()),
            "nanobot should be ready"
        );
        assert!(
            !result2.contains(&"zeroclaw".to_string()),
            "zeroclaw is installing, not ready"
        );
        assert_eq!(result2.len(), 2);

        // Part 3: missing state file returns empty
        let empty_dir = TempDir::new().unwrap();
        let result3 = ready_claws_from_state_file(empty_dir.path());
        assert!(result3.is_empty(), "missing state file should return empty");
    }
}
