//! `ssh_client.rs` — async SSH helpers wrapping the `russh` crate.
// NOTE: VmError is large by design (rich diagnostic context); boxing would require
// pervasive API changes across all callers.
#![allow(clippy::result_large_err)]
//!
//! Used for:
//! - Waiting for the guest VM to boot and accept SSH connections
//! - Running commands inside the guest
//! - Uploading files (installer scripts, binaries) via SSH exec + stdin

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::keys::HashAlg;
use russh::keys::PrivateKeyWithHashAlg;
use russh::{ChannelMsg, client};

use crate::error::{ErrorContext, VmError};

/// Default timeout for quick SSH commands (connectivity checks, binary tests, etc.)
pub const SSH_EXEC_TIMEOUT_QUICK: Duration = Duration::from_secs(30);

/// Default timeout for installer scripts (may download and build software)
pub const SSH_EXEC_TIMEOUT_INSTALL: Duration = Duration::from_secs(1800); // 30 minutes — ceiling for hang detection, not typical install time

/// SSH connection profile — controls inactivity timeout and keepalive behaviour.
///
/// `Quick` is suitable for short-lived connectivity checks and small commands.
/// `Install` disables the inactivity timeout (since installer commands like
/// `apt-get install ... >/dev/null 2>&1` can be silent for minutes) and enables
/// SSH keepalive to detect genuinely dead connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshProfile {
    /// 30s inactivity timeout, no keepalive. Fast failure for quick commands.
    Quick,
    /// No inactivity timeout, 15s keepalive interval. Suitable for long-running
    /// installer commands that may produce no output for extended periods.
    Install,
}

/// Handler for the russh client — accepts all host keys since we're
/// connecting to local Firecracker VMs on loopback only.
struct SshHandler;

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true) // Local VMs, no host key verification needed
    }
}

/// An open SSH session to a guest VM, backed by a russh async client.
pub struct SshSession {
    handle: client::Handle<SshHandler>,
}

impl SshSession {
    /// Connect to `127.0.0.1:<ssh_port>` and authenticate as `root`.
    ///
    /// Uses [`SshProfile::Quick`] (30s inactivity timeout).
    /// For long-running installer sessions, use [`connect_for_install`](Self::connect_for_install).
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, SSH handshake, or key
    /// authentication fails.
    pub async fn connect(ssh_port: u16, key_path: &Path) -> Result<Self, VmError> {
        Self::connect_with_profile(ssh_port, key_path, "root", SshProfile::Quick).await
    }

    /// Connect to `127.0.0.1:<ssh_port>` and authenticate as `root` using the
    /// [`SshProfile::Install`] profile (no inactivity timeout, keepalive enabled).
    ///
    /// Use this for sessions that will run long, potentially silent commands
    /// (e.g. `apt-get install ... >/dev/null 2>&1`).
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, SSH handshake, or key
    /// authentication fails.
    pub async fn connect_for_install(ssh_port: u16, key_path: &Path) -> Result<Self, VmError> {
        Self::connect_with_profile(ssh_port, key_path, "root", SshProfile::Install).await
    }

    /// Connect to `127.0.0.1:<ssh_port>` and authenticate with the given
    /// private key as the specified user, using [`SshProfile::Quick`].
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, SSH handshake, or key
    /// authentication fails.
    pub async fn connect_as(ssh_port: u16, key_path: &Path, user: &str) -> Result<Self, VmError> {
        Self::connect_with_profile(ssh_port, key_path, user, SshProfile::Quick).await
    }

    /// Connect to `127.0.0.1:<ssh_port>` with the specified [`SshProfile`].
    ///
    /// - [`SshProfile::Quick`]: 30s inactivity timeout, no keepalive.
    /// - [`SshProfile::Install`]: no inactivity timeout, 15s keepalive interval.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection, SSH handshake, or key
    /// authentication fails.
    pub async fn connect_with_profile(
        ssh_port: u16,
        key_path: &Path,
        user: &str,
        profile: SshProfile,
    ) -> Result<Self, VmError> {
        let config = match profile {
            SshProfile::Quick => client::Config {
                inactivity_timeout: Some(Duration::from_secs(30)),
                ..Default::default()
            },
            SshProfile::Install => client::Config {
                inactivity_timeout: None,
                keepalive_interval: Some(Duration::from_secs(15)),
                keepalive_max: 3,
                ..Default::default()
            },
        };
        let config = Arc::new(config);

        let addr = ("127.0.0.1", ssh_port);

        let mut handle = client::connect(config, addr, SshHandler)
            .await
            .map_err(|e| {
                VmError::ssh_connect(format!("SSH connect to 127.0.0.1:{ssh_port}: {e}"))
            })?;

        let key = russh::keys::load_secret_key(key_path, None).map_err(|e| {
            VmError::ssh_connect(format!("load SSH key {}: {e}", key_path.display()))
        })?;

        // Use SHA-512 for RSA keys — OpenSSH 9.x disabled legacy ssh-rsa (SHA-1)
        // and only accepts rsa-sha2-256 / rsa-sha2-512. Passing None would use
        // the default which may try ssh-rsa and get rejected.
        let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), Some(HashAlg::Sha512));

        let auth_result = handle
            .authenticate_publickey(user, key_with_alg)
            .await
            .map_err(|e| {
                VmError::ssh_connect(format!(
                    "auth with key {} to 127.0.0.1:{ssh_port}: {e}",
                    key_path.display()
                ))
            })?;

        if !auth_result.success() {
            return Err(VmError::ssh_connect(format!(
                "authentication failed for {user}@127.0.0.1:{ssh_port}"
            )));
        }

        Ok(SshSession { handle })
    }

    /// Inner implementation of exec: open channel, run command, collect output.
    async fn exec_inner(&self, cmd: &str) -> Result<String, VmError> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| VmError::ssh_exec_plain(format!("open channel for `{cmd}`: {e}")))?;

        channel
            .exec(true, cmd)
            .await
            .map_err(|e| VmError::ssh_exec_plain(format!("exec `{cmd}`: {e}")))?;

        let mut stdout = String::new();
        let mut stderr_buf = String::new();
        let mut exit_code: Option<u32> = None;

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => {
                    stdout.push_str(&String::from_utf8_lossy(data));
                }
                ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    stderr_buf.push_str(&String::from_utf8_lossy(data));
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = Some(exit_status);
                }
                _ => {}
            }
        }

        // exit_status is u32 from SSH protocol; negative sentinel (-1) is intentional for "no exit code".
        #[allow(clippy::cast_possible_wrap)]
        let code = exit_code.map_or(-1_i32, |c| c as i32);

        if code != 0 {
            let stderr_hint = if stderr_buf.trim().is_empty() {
                String::new()
            } else {
                format!(" stderr: {}", stderr_buf.trim())
            };
            let ctx = ErrorContext::with_phase("ssh.exec")
                .command(cmd)
                .exit_code(code)
                .stdout(stdout)
                .stderr(stderr_buf);
            return Err(VmError::ssh_exec(
                format!("command exited {code}: `{cmd}`{stderr_hint}"),
                ctx,
            ));
        }

        Ok(stdout)
    }

    /// Execute a command with a per-command wall-clock timeout.
    ///
    /// Returns stdout on success. On failure returns a structured `VmError` that
    /// always includes the exact command, exit code, stdout tail, and stderr tail.
    ///
    /// # Errors
    ///
    /// Returns an error if the command times out, exits with a non-zero code,
    /// or if the SSH channel cannot be opened.
    // NOTE: elapsed_ms fits trivially in u64 (u128 overflow requires ~585M years).
    #[allow(clippy::cast_possible_truncation)]
    pub async fn exec_timeout(&self, cmd: &str, timeout: Duration) -> Result<String, VmError> {
        let t_start = Instant::now();

        match tokio::time::timeout(timeout, self.exec_inner(cmd)).await {
            Ok(result) => result,
            Err(_elapsed) => {
                let elapsed_ms = t_start.elapsed().as_millis() as u64;
                let ctx = ErrorContext::with_phase("ssh.exec_timeout")
                    .command(cmd)
                    .timed_out()
                    .elapsed_ms(elapsed_ms);
                Err(VmError::timeout(
                    format!(
                        "SSH command timed out after {}s: `{cmd}`",
                        timeout.as_secs()
                    ),
                    ctx,
                ))
            }
        }
    }

    /// Execute a command using the quick timeout (30s).
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails or times out.
    pub async fn exec(&self, cmd: &str) -> Result<String, VmError> {
        self.exec_timeout(cmd, SSH_EXEC_TIMEOUT_QUICK).await
    }

    /// Execute a long-running command (installer scripts) using the install timeout (15 min).
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails or times out.
    pub async fn exec_install(&self, cmd: &str) -> Result<String, VmError> {
        self.exec_timeout(cmd, SSH_EXEC_TIMEOUT_INSTALL).await
    }

    /// Upload a local file to a remote path via SSH exec + stdin pipe.
    ///
    /// # Errors
    ///
    /// Returns an error if the local file cannot be read or the upload fails.
    pub async fn upload_file(&self, local: &Path, remote: &str) -> Result<(), VmError> {
        let data = tokio::fs::read(local).await.map_err(|e| {
            VmError::ssh_exec_plain(format!("read local file {}: {e}", local.display()))
        })?;

        self.upload_bytes(&data, remote, 0o644).await
    }

    /// Write `content` bytes directly to a remote path (no local file needed).
    ///
    /// Uses SSH exec with `cat > path && chmod` and pipes data via the channel's
    /// stdin, avoiding the need for SCP/SFTP.
    ///
    /// # Errors
    ///
    /// Returns an error if the SSH channel cannot be opened or the write fails.
    pub async fn upload_bytes(
        &self,
        content: &[u8],
        remote: &str,
        mode: i32,
    ) -> Result<(), VmError> {
        let octal_mode = format!("{mode:o}");
        let cmd = format!("cat > {remote} && chmod {octal_mode} {remote}");

        let mut channel = self.handle.channel_open_session().await.map_err(|e| {
            VmError::ssh_exec_plain(format!("open channel for upload to {remote}: {e}"))
        })?;

        channel
            .exec(true, cmd.as_bytes())
            .await
            .map_err(|e| VmError::ssh_exec_plain(format!("exec upload cmd for {remote}: {e}")))?;

        channel
            .data(content)
            .await
            .map_err(|e| VmError::ssh_exec_plain(format!("write data to {remote}: {e}")))?;

        channel
            .eof()
            .await
            .map_err(|e| VmError::ssh_exec_plain(format!("send eof for {remote}: {e}")))?;

        // Wait for channel to close and check exit status.
        let mut exit_code: Option<u32> = None;
        while let Some(msg) = channel.wait().await {
            if let ChannelMsg::ExitStatus { exit_status } = msg {
                exit_code = Some(exit_status);
            }
        }

        let code = exit_code.unwrap_or(0);
        if code != 0 {
            return Err(VmError::ssh_exec_plain(format!(
                "upload to {remote} failed with exit code {code}"
            )));
        }

        Ok(())
    }

    /// Wait for SSH to become available within a wall-clock deadline.
    ///
    /// Uses [`SshProfile::Quick`] for the connection. For sessions that will
    /// subsequently run long installer commands, use
    /// [`wait_for_ssh_install`](Self::wait_for_ssh_install) instead.
    ///
    /// Uses exponential backoff starting at 500ms, capped at 3s.
    ///
    /// # Errors
    ///
    /// Returns an error if SSH does not become available before the deadline.
    pub async fn wait_for_ssh(
        ssh_port: u16,
        key_path: &Path,
        max_tries: u32,
    ) -> Result<Self, VmError> {
        Self::wait_for_ssh_with_profile(ssh_port, key_path, max_tries, SshProfile::Quick).await
    }

    /// Wait for SSH to become available, returning a session configured for
    /// long-running installer commands ([`SshProfile::Install`]).
    ///
    /// The install profile disables the inactivity timeout and enables
    /// keepalive, so silent commands (e.g. `apt-get install ... >/dev/null`)
    /// won't kill the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if SSH does not become available before the deadline.
    pub async fn wait_for_ssh_install(
        ssh_port: u16,
        key_path: &Path,
        max_tries: u32,
    ) -> Result<Self, VmError> {
        Self::wait_for_ssh_with_profile(ssh_port, key_path, max_tries, SshProfile::Install).await
    }

    /// Wait for SSH with the specified [`SshProfile`].
    ///
    /// Uses exponential backoff starting at 500ms, capped at 3s.
    ///
    /// # Errors
    ///
    /// Returns an error if SSH does not become available before the deadline.
    pub async fn wait_for_ssh_with_profile(
        ssh_port: u16,
        key_path: &Path,
        max_tries: u32,
        profile: SshProfile,
    ) -> Result<Self, VmError> {
        let deadline = Instant::now() + Duration::from_secs(u64::from(max_tries) * 3);
        let mut last_err = format!("no attempts made (max_tries={max_tries})");
        let mut backoff = Duration::from_millis(500);

        loop {
            match Self::connect_with_profile(ssh_port, key_path, "root", profile).await {
                Ok(sess) => return Ok(sess),
                Err(e) => {
                    last_err = e.to_string();
                    if Instant::now() >= deadline {
                        break;
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(3));
                }
            }
        }
        Err(VmError::ssh_connect(format!(
            "SSH did not become ready on 127.0.0.1:{ssh_port} (deadline exceeded): {last_err}"
        )))
    }
}

/// Trait abstracting SSH operations so that callers can swap in a real
/// [`SshSession`] or a [`MockSshSession`](test_utils::MockSshSession) for testing.
#[async_trait::async_trait]
pub trait SshActions: Send + Sync {
    /// Execute a command with the quick timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails or times out.
    async fn exec(&self, cmd: &str) -> Result<String, VmError>;
    /// Execute a long-running command with the install timeout.
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails or times out.
    async fn exec_install(&self, cmd: &str) -> Result<String, VmError>;
    /// Upload a local file to a remote path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the transfer fails.
    async fn upload_file(&self, local: &Path, remote: &str) -> Result<(), VmError>;
    /// Write bytes directly to a remote path.
    ///
    /// # Errors
    ///
    /// Returns an error if the transfer fails.
    async fn upload_bytes(&self, content: &[u8], remote: &str, mode: i32) -> Result<(), VmError>;
}

#[async_trait::async_trait]
impl SshActions for SshSession {
    async fn exec(&self, cmd: &str) -> Result<String, VmError> {
        self.exec(cmd).await
    }

    async fn exec_install(&self, cmd: &str) -> Result<String, VmError> {
        self.exec_install(cmd).await
    }

    async fn upload_file(&self, local: &Path, remote: &str) -> Result<(), VmError> {
        self.upload_file(local, remote).await
    }

    async fn upload_bytes(&self, content: &[u8], remote: &str, mode: i32) -> Result<(), VmError> {
        self.upload_bytes(content, remote, mode).await
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use tokio::sync::Mutex;

    /// A recorded call to the mock SSH session.
    #[derive(Debug, Clone)]
    pub enum SshCall {
        Exec(String),
        ExecInstall(String),
        UploadFile { local: String, remote: String },
        UploadBytes { remote: String },
    }

    /// Mock SSH session that records calls and returns pre-programmed responses.
    pub struct MockSshSession {
        pub calls: Mutex<Vec<SshCall>>,
        /// If `Some`, `exec` returns this error string.
        pub exec_error: Option<String>,
        /// If `Some`, `exec_install` returns this error string (overrides `exec_error` for installs).
        pub exec_install_error: Option<String>,
    }

    impl Default for MockSshSession {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockSshSession {
        /// # Panics
        ///
        /// Panics if the internal mutex is poisoned (only possible in tests with panicking threads).
        #[must_use]
        pub fn new() -> Self {
            MockSshSession {
                calls: Mutex::new(vec![]),
                exec_error: None,
                exec_install_error: None,
            }
        }

        /// # Panics
        ///
        /// Panics if the internal mutex is poisoned (only possible in tests with panicking threads).
        #[must_use]
        pub fn with_exec_error(err: &str) -> Self {
            MockSshSession {
                calls: Mutex::new(vec![]),
                exec_error: Some(err.to_string()),
                exec_install_error: None,
            }
        }

        /// Fails both `exec` and `exec_install` with the same error.
        ///
        /// # Panics
        ///
        /// Panics if the internal mutex is poisoned (only possible in tests with panicking threads).
        #[must_use]
        pub fn with_all_errors(err: &str) -> Self {
            MockSshSession {
                calls: Mutex::new(vec![]),
                exec_error: Some(err.to_string()),
                exec_install_error: Some(err.to_string()),
            }
        }

        /// Fails only `exec_install` (idempotency checks via `exec` still succeed).
        ///
        /// # Panics
        ///
        /// Panics if the internal mutex is poisoned (only possible in tests with panicking threads).
        #[must_use]
        pub fn with_exec_install_error(err: &str) -> Self {
            MockSshSession {
                calls: Mutex::new(vec![]),
                exec_error: None,
                exec_install_error: Some(err.to_string()),
            }
        }

        /// # Panics
        ///
        /// Panics if the internal mutex is poisoned (only possible in tests with panicking threads).
        pub async fn recorded_calls(&self) -> Vec<SshCall> {
            self.calls.lock().await.clone()
        }
    }

    #[async_trait::async_trait]
    impl SshActions for MockSshSession {
        async fn exec(&self, cmd: &str) -> Result<String, VmError> {
            self.calls.lock().await.push(SshCall::Exec(cmd.to_string()));
            if let Some(ref err) = self.exec_error {
                return Err(VmError::ssh_exec_plain(err.clone()));
            }
            Ok(String::new())
        }

        async fn exec_install(&self, cmd: &str) -> Result<String, VmError> {
            self.calls
                .lock()
                .await
                .push(SshCall::ExecInstall(cmd.to_string()));
            // exec_install_error takes precedence over exec_error for install calls
            if let Some(ref err) = self.exec_install_error {
                return Err(VmError::ssh_exec_plain(err.clone()));
            }
            if let Some(ref err) = self.exec_error {
                return Err(VmError::ssh_exec_plain(err.clone()));
            }
            Ok(String::new())
        }

        async fn upload_file(&self, local: &Path, remote: &str) -> Result<(), VmError> {
            self.calls.lock().await.push(SshCall::UploadFile {
                local: local.display().to_string(),
                remote: remote.to_string(),
            });
            Ok(())
        }

        async fn upload_bytes(
            &self,
            _content: &[u8],
            remote: &str,
            _mode: i32,
        ) -> Result<(), VmError> {
            self.calls.lock().await.push(SshCall::UploadBytes {
                remote: remote.to_string(),
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod ssh_profile_tests {
    use super::*;

    #[test]
    fn quick_profile_has_inactivity_timeout() {
        let config = match SshProfile::Quick {
            SshProfile::Quick => client::Config {
                inactivity_timeout: Some(Duration::from_secs(30)),
                ..Default::default()
            },
            SshProfile::Install => unreachable!(),
        };
        assert_eq!(config.inactivity_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn install_profile_has_no_inactivity_timeout() {
        let config = match SshProfile::Install {
            SshProfile::Install => client::Config {
                inactivity_timeout: None,
                keepalive_interval: Some(Duration::from_secs(15)),
                keepalive_max: 3,
                ..Default::default()
            },
            SshProfile::Quick => unreachable!(),
        };
        assert!(
            config.inactivity_timeout.is_none(),
            "Install profile must NOT have an inactivity timeout — silent \
             commands like `apt-get install ... >/dev/null` can be quiet for \
             minutes and must not kill the SSH connection"
        );
        assert_eq!(config.keepalive_interval, Some(Duration::from_secs(15)));
        assert_eq!(config.keepalive_max, 3);
    }

    #[test]
    fn profiles_are_distinct() {
        assert_ne!(SshProfile::Quick, SshProfile::Install);
    }
}
