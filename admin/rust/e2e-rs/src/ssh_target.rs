//! `SshTarget` — platform-agnostic SSH connection target for e2e tests.
//!
//! Abstracts the difference between Linux (`127.0.0.1:<port>` via Firecracker)
//! and macOS (`<vm_ip>:22` via VZ) so the test runner doesn't need to know
//! which platform it's running on.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::E2eError;

/// Result of an SSH command execution.
#[derive(Debug, Clone)]
pub struct SshResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_status: i32,
}

impl SshResult {
    /// True if the remote command exited with status 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.exit_status == 0
    }
}

/// Platform-agnostic SSH connection target.
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub key: PathBuf,
    pub user: String,
    /// Optional PATH prefix for macOS brew tools.
    /// When set, `exec` prepends `export PATH=<prefix>:$PATH;` to every command.
    pub path_prefix: Option<String>,
}

/// macOS PATH prefix for brew-installed tools.
pub const MACOS_PATH_PREFIX: &str = "/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH";

impl SshTarget {
    /// Resolve from Linux instance metadata.
    ///
    /// Reads `SSH_PORT` from `<state_dir>/<container>/instance.env`.
    /// Connects to `127.0.0.1:<port>`.
    ///
    /// # Errors
    ///
    /// Returns error if `instance.env` is missing or `SSH_PORT` is not found.
    pub fn from_linux(container: &str, state_dir: &Path, key: &Path) -> Result<Self, E2eError> {
        let env_path = state_dir.join(container).join("instance.env");
        let content = std::fs::read_to_string(&env_path).map_err(|e| E2eError::Setup {
            detail: format!("read {}: {e}", env_path.display()),
        })?;
        let port = parse_ssh_port(&content).ok_or_else(|| E2eError::Setup {
            detail: format!("SSH_PORT not found in {}", env_path.display()),
        })?;
        Ok(Self {
            host: "127.0.0.1".into(),
            port,
            key: key.to_path_buf(),
            user: "root".into(),
            path_prefix: None,
        })
    }

    /// Resolve from macOS instance metadata.
    ///
    /// Reads `vm_ip` from `~/Library/Application Support/theyos/vms/<container>/vm_ip`.
    /// Connects to `<ip>:22`.
    ///
    /// # Errors
    ///
    /// Returns error if `vm_ip` file is missing or empty.
    pub fn from_macos(container: &str, key: &Path) -> Result<Self, E2eError> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let vm_ip_path = PathBuf::from(home)
            .join("Library/Application Support/theyos/vms")
            .join(container)
            .join("vm_ip");
        let content = std::fs::read_to_string(&vm_ip_path).map_err(|e| E2eError::Setup {
            detail: format!("read {}: {e}", vm_ip_path.display()),
        })?;
        let ip = content.trim().to_string();
        if ip.is_empty() {
            return Err(E2eError::Setup {
                detail: format!("vm_ip file is empty: {}", vm_ip_path.display()),
            });
        }
        Ok(Self {
            host: ip,
            port: 22,
            key: key.to_path_buf(),
            user: "root".into(),
            path_prefix: Some(MACOS_PATH_PREFIX.into()),
        })
    }

    /// Resolve based on guest OS type.
    ///
    /// # Errors
    ///
    /// Returns error if the platform-specific metadata file cannot be read.
    pub fn resolve(
        container: &str,
        guest_os: &str,
        state_dir: &Path,
        key: &Path,
    ) -> Result<Self, E2eError> {
        if guest_os == "macos" {
            Self::from_macos(container, key)
        } else {
            Self::from_linux(container, state_dir, key)
        }
    }

    /// Build the full command with optional PATH prefix.
    fn build_command(&self, cmd: &str) -> String {
        if let Some(ref prefix) = self.path_prefix {
            format!("export PATH={prefix}; {cmd}")
        } else {
            cmd.to_string()
        }
    }

    /// Execute a command via SSH. Returns full result with exit status.
    ///
    /// # Errors
    ///
    /// Returns error if SSH connection or command execution fails.
    pub fn exec(&self, cmd: &str) -> Result<SshResult, E2eError> {
        let full_cmd = self.build_command(cmd);
        let output = std::process::Command::new("ssh")
            .args([
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "BatchMode=yes",
                "-o",
                "LogLevel=ERROR",
                "-p",
                &self.port.to_string(),
                "-i",
                self.key.to_str().unwrap_or(""),
                &format!("{}@{}", self.user, self.host),
                &full_cmd,
            ])
            .output()
            .map_err(|e| E2eError::Ssh {
                port: self.port,
                reason: format!("exec ssh: {e}"),
            })?;

        Ok(SshResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_status: output.status.code().unwrap_or(-1),
        })
    }

    /// Execute a command and return stdout only if exit status is 0.
    ///
    /// # Errors
    ///
    /// Returns error if the command fails or exits with non-zero status.
    pub fn exec_ok(&self, cmd: &str) -> Result<String, E2eError> {
        let result = self.exec(cmd)?;
        if result.success() {
            Ok(result.stdout)
        } else {
            Err(E2eError::Ssh {
                port: self.port,
                reason: format!(
                    "command '{}' exited with status {}: {}",
                    cmd,
                    result.exit_status,
                    result.stderr.trim()
                ),
            })
        }
    }

    /// Check if SSH port is reachable via TCP connect.
    #[must_use]
    pub fn is_reachable(&self, timeout: Duration) -> bool {
        use std::net::TcpStream;
        let addr = format!("{}:{}", self.host, self.port);
        addr.parse::<std::net::SocketAddr>()
            .ok()
            .and_then(|sa| TcpStream::connect_timeout(&sa, timeout).ok())
            .is_some()
    }
}

/// Parse `SSH_PORT=<value>` from `instance.env` content.
#[must_use]
pub fn parse_ssh_port(content: &str) -> Option<u16> {
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("SSH_PORT=") {
            return val.trim().parse().ok();
        }
    }
    None
}

/// Parse VM IP from `vm_ip` file content (may have trailing newline).
#[must_use]
pub fn parse_vm_ip(content: &str) -> Option<String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

// ── wait_until_guest_ready ───────────────────────────────────────────────────

/// Retry a probe function until it succeeds or timeout expires.
///
/// `probe` should return `Ok(())` when the guest is ready, or `Err` to retry.
/// Returns the last error on timeout.
///
/// # Errors
///
/// Returns the last probe error if timeout is reached.
pub fn wait_until_guest_ready<F>(
    probe: F,
    timeout: Duration,
    interval: Duration,
) -> Result<(), E2eError>
where
    F: Fn() -> Result<(), E2eError>,
{
    let deadline = Instant::now() + timeout;
    loop {
        match probe() {
            Ok(()) => return Ok(()),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(e);
                }
            }
        }
        std::thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ssh_port_from_instance_env() {
        let content = "FIRECRACKER_PID=123\nSSH_PORT=22345\nSOMETHING_ELSE=foo\n";
        assert_eq!(parse_ssh_port(content), Some(22345));
    }

    #[test]
    fn parse_ssh_port_missing() {
        let content = "FIRECRACKER_PID=123\nNO_SSH_HERE=true\n";
        assert_eq!(parse_ssh_port(content), None);
    }

    #[test]
    fn parse_ssh_port_invalid_number() {
        let content = "SSH_PORT=notanumber\n";
        assert_eq!(parse_ssh_port(content), None);
    }

    #[test]
    fn parse_vm_ip_trims_newline() {
        assert_eq!(parse_vm_ip("192.168.64.5\n"), Some("192.168.64.5".into()));
        assert_eq!(parse_vm_ip("192.168.64.5"), Some("192.168.64.5".into()));
        assert_eq!(
            parse_vm_ip("  192.168.64.5  \n"),
            Some("192.168.64.5".into())
        );
    }

    #[test]
    fn parse_vm_ip_empty_returns_none() {
        assert_eq!(parse_vm_ip(""), None);
        assert_eq!(parse_vm_ip("\n"), None);
        assert_eq!(parse_vm_ip("  \n"), None);
    }

    #[test]
    fn ssh_result_nonzero_exit_is_not_success() {
        let r = SshResult {
            stdout: String::new(),
            stderr: "err".into(),
            exit_status: 1,
        };
        assert!(!r.success());
    }

    #[test]
    fn ssh_result_zero_exit_is_success() {
        let r = SshResult {
            stdout: "ok".into(),
            stderr: String::new(),
            exit_status: 0,
        };
        assert!(r.success());
    }

    #[test]
    fn build_command_no_prefix() {
        let t = SshTarget {
            host: "127.0.0.1".into(),
            port: 22,
            key: PathBuf::from("/tmp/key"),
            user: "root".into(),
            path_prefix: None,
        };
        assert_eq!(t.build_command("ls"), "ls");
    }

    #[test]
    fn build_command_with_prefix() {
        let t = SshTarget {
            host: "192.168.64.5".into(),
            port: 22,
            key: PathBuf::from("/tmp/key"),
            user: "root".into(),
            path_prefix: Some("/opt/homebrew/bin:$PATH".into()),
        };
        assert_eq!(
            t.build_command("ls"),
            "export PATH=/opt/homebrew/bin:$PATH; ls"
        );
    }

    #[test]
    fn wait_until_guest_ready_succeeds_immediately() {
        let result =
            wait_until_guest_ready(|| Ok(()), Duration::from_secs(5), Duration::from_millis(10));
        assert!(result.is_ok());
    }

    #[test]
    fn wait_until_guest_ready_retries_then_succeeds() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let counter = AtomicU32::new(0);
        let result = wait_until_guest_ready(
            || {
                let n = counter.fetch_add(1, Ordering::Relaxed);
                if n < 3 {
                    Err(E2eError::Setup {
                        detail: format!("not ready yet ({n})"),
                    })
                } else {
                    Ok(())
                }
            },
            Duration::from_secs(5),
            Duration::from_millis(10),
        );
        assert!(result.is_ok());
        assert!(counter.load(Ordering::Relaxed) >= 4);
    }

    #[test]
    fn wait_until_guest_ready_times_out_with_last_error() {
        let result = wait_until_guest_ready(
            || {
                Err(E2eError::Setup {
                    detail: "still failing".into(),
                })
            },
            Duration::from_millis(50),
            Duration::from_millis(10),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("still failing"), "got: {err}");
    }
}
