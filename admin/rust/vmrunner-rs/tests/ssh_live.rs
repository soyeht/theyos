//! Live SSH integration tests against a real OpenSSH sshd.
//!
//! These tests spawn a real `sshd` process on a random high port, generate
//! temporary RSA keys, and connect using the production `SshSession` code
//! path (russh + RSA + SHA-512).
//!
//! **Why this exists**: A missing `rsa` feature flag in russh caused
//! `authenticate_publickey` to silently produce SHA-1 signatures, which
//! OpenSSH 9.x rejects. All 500+ unit tests passed because `MockSshSession`
//! never touches russh. This test exercises the real SSH stack.
//!
//! Requires `sshd` in PATH. Skipped gracefully if not available.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use vmrunner_rs::ssh_client::SshSession;

// ── Test harness ───────────────────────────────────────────────────────────

/// A running sshd process with temporary keys, cleaned up on drop.
struct SshdFixture {
    /// sshd child process.
    child: Child,
    /// Port the sshd is listening on.
    port: u16,
    /// Path to the RSA private key for authentication.
    user_key: PathBuf,
    /// Username to authenticate as.
    user: String,
    /// Temp directory (dropped last → cleanup).
    _tmpdir: tempfile::TempDir,
}

impl SshdFixture {
    /// Spawn a real sshd on a random port with generated keys.
    ///
    /// Returns `None` if `sshd` is not available (graceful skip).
    fn start() -> Option<Self> {
        let sshd_bin = find_sshd()?;
        let user = whoami();

        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let base = tmpdir.path();

        // Generate host key
        let host_key = base.join("host_key");
        let ok = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(&host_key)
            .args(["-N", "", "-q"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[ssh_live] ssh-keygen (host key) failed");
            return None;
        }

        // Generate user key (RSA 4096 — matches production)
        let user_key = base.join("user_key");
        let ok = Command::new("ssh-keygen")
            .args(["-t", "rsa", "-b", "4096", "-f"])
            .arg(&user_key)
            .args(["-N", "", "-q"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[ssh_live] ssh-keygen (user key) failed");
            return None;
        }

        // Write authorized_keys
        let auth_dir = base.join("auth");
        std::fs::create_dir_all(&auth_dir).expect("create auth dir");
        let pubkey = std::fs::read_to_string(base.join("user_key.pub")).expect("read user pubkey");
        std::fs::write(auth_dir.join("authorized_keys"), &pubkey).expect("write authorized_keys");

        // Pick a free port
        let port = pick_free_port();

        // Spawn sshd
        let child = Command::new(&sshd_bin)
            .args(["-D", "-e"])
            .arg("-p")
            .arg(port.to_string())
            .arg("-h")
            .arg(&host_key)
            .arg("-o")
            .arg(format!(
                "AuthorizedKeysFile={}",
                auth_dir.join("authorized_keys").display()
            ))
            .args(["-o", "PasswordAuthentication=no"])
            .args(["-o", "UsePAM=no"])
            .args(["-o", "StrictModes=no"])
            .args(["-o", "ListenAddress=127.0.0.1"])
            .arg("-o")
            .arg(format!("PidFile={}", base.join("sshd.pid").display()))
            .stderr(Stdio::piped())
            .spawn();

        let child = match child {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[ssh_live] failed to spawn sshd: {e}");
                return None;
            }
        };

        let fixture = SshdFixture {
            child,
            port,
            user_key,
            user,
            _tmpdir: tmpdir,
        };

        // Wait for sshd to start accepting connections
        if !fixture.wait_for_listen(Duration::from_secs(5)) {
            eprintln!("[ssh_live] sshd did not start listening on port {port}");
            return None;
        }

        Some(fixture)
    }

    /// Poll until the sshd port is accepting TCP connections.
    fn wait_for_listen(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

impl Drop for SshdFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Find sshd binary. Checks common locations.
fn find_sshd() -> Option<String> {
    let candidates = [
        "/run/current-system/sw/bin/sshd", // NixOS
        "/usr/sbin/sshd",                  // Debian/Ubuntu
        "/usr/bin/sshd",                   // some distros
    ];
    for c in &candidates {
        if Path::new(c).exists() {
            return Some(c.to_string());
        }
    }
    // Try PATH
    let output = Command::new("which").arg("sshd").output().ok()?;
    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Some(path);
        }
    }
    None
}

/// Pick a free TCP port by binding to port 0.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to port 0");
    listener.local_addr().expect("local addr").port()
}

/// Get the current username.
fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "nobody".to_string())
}

/// Generate a second RSA key (for negative testing — wrong key).
fn generate_wrong_key(dir: &Path) -> PathBuf {
    let key_path = dir.join("wrong_key");
    let ok = Command::new("ssh-keygen")
        .args(["-t", "rsa", "-b", "2048", "-f"])
        .arg(&key_path)
        .args(["-N", "", "-q"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "failed to generate wrong key");
    key_path
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// Macro to skip the test gracefully if sshd is not available.
macro_rules! require_sshd {
    () => {
        match SshdFixture::start() {
            Some(f) => f,
            None => {
                eprintln!("[ssh_live] sshd not available — skipping test");
                return;
            }
        }
    };
}

/// T1: Connect + exec "echo OK" — validates the full russh auth + exec path.
///
/// This is THE test that catches the missing `rsa` feature. If russh cannot
/// sign with rsa-sha2-512, the sshd will reject the auth and this fails.
#[tokio::test]
async fn connect_and_exec_echo() {
    let sshd = require_sshd!();

    let sess = SshSession::connect_as(sshd.port, &sshd.user_key, &sshd.user)
        .await
        .expect("connect_as should succeed");

    let output = sess
        .exec("echo SSH_LIVE_OK")
        .await
        .expect("exec should succeed");
    assert!(
        output.contains("SSH_LIVE_OK"),
        "expected 'SSH_LIVE_OK' in stdout, got: {output:?}"
    );
}

/// T2: exec with non-zero exit code — validates stderr + structured error.
#[tokio::test]
async fn exec_nonzero_exit_code() {
    let sshd = require_sshd!();

    let sess = SshSession::connect_as(sshd.port, &sshd.user_key, &sshd.user)
        .await
        .expect("connect_as should succeed");

    let result = sess.exec("/bin/sh -c 'echo FAIL_MSG >&2; exit 42'").await;
    assert!(result.is_err(), "expected error for non-zero exit");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("42") || err_msg.contains("FAIL_MSG"),
        "error should mention exit code or stderr: {err_msg}"
    );
}

/// T3: `upload_bytes` — write content via SSH stdin pipe, then read it back.
#[tokio::test]
async fn upload_bytes_and_read_back() {
    let sshd = require_sshd!();

    let sess = SshSession::connect_as(sshd.port, &sshd.user_key, &sshd.user)
        .await
        .expect("connect_as should succeed");

    let test_content = b"hello from ssh_live test\n";
    let remote_path = "/tmp/ssh_live_test_upload.txt";

    sess.upload_bytes(test_content, remote_path, 0o644)
        .await
        .expect("upload_bytes should succeed");

    let readback = sess
        .exec(&format!("cat {remote_path} && rm -f {remote_path}"))
        .await
        .expect("cat should succeed");

    assert!(
        readback.contains("hello from ssh_live test"),
        "uploaded content should match: {readback:?}"
    );
}

/// T4: `exec_timeout` — validates that the timeout mechanism works.
#[tokio::test]
async fn exec_timeout_fires() {
    let sshd = require_sshd!();

    let sess = SshSession::connect_as(sshd.port, &sshd.user_key, &sshd.user)
        .await
        .expect("connect_as should succeed");

    let result = sess.exec_timeout("sleep 60", Duration::from_secs(1)).await;

    assert!(result.is_err(), "expected timeout error");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("timed out") || err_msg.contains("Timeout"),
        "error should mention timeout: {err_msg}"
    );
}

/// T5: Wrong key → authentication failure.
///
/// Validates that russh correctly reports auth failure when the key
/// doesn't match `authorized_keys`.
#[tokio::test]
async fn wrong_key_auth_failure() {
    let sshd = require_sshd!();

    let wrong_key_dir = tempfile::tempdir().expect("create tmpdir for wrong key");
    let wrong_key = generate_wrong_key(wrong_key_dir.path());

    let result = SshSession::connect_as(sshd.port, &wrong_key, &sshd.user).await;
    let err = result.err().expect("expected auth failure with wrong key");

    let err_msg = err.to_string();
    assert!(
        err_msg.contains("authentication failed") || err_msg.contains("auth"),
        "error should mention auth failure: {err_msg}"
    );
}

/// T6: Wrong port → connection failure.
#[tokio::test]
async fn wrong_port_connect_failure() {
    let port = pick_free_port(); // Nobody listening here

    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let key_path = tmpdir.path().join("dummy_key");
    let ok = Command::new("ssh-keygen")
        .args(["-t", "rsa", "-b", "2048", "-f"])
        .arg(&key_path)
        .args(["-N", "", "-q"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "failed to generate dummy key");

    let result = SshSession::connect_as(port, &key_path, "nobody").await;
    let err = result.err().expect("expected connection failure");

    let err_msg = err.to_string();
    assert!(
        err_msg.contains("connect") || err_msg.contains("Connection refused"),
        "error should mention connection failure: {err_msg}"
    );
}

/// T7: Multiple sequential commands on the same session.
///
/// Validates that the SSH session remains usable after multiple execs.
#[tokio::test]
async fn multiple_commands_same_session() {
    let sshd = require_sshd!();

    let sess = SshSession::connect_as(sshd.port, &sshd.user_key, &sshd.user)
        .await
        .expect("connect_as should succeed");

    let out1 = sess.exec("echo CMD_ONE").await.expect("cmd 1");
    let out2 = sess.exec("echo CMD_TWO").await.expect("cmd 2");
    let out3 = sess.exec("echo CMD_THREE").await.expect("cmd 3");

    assert!(out1.contains("CMD_ONE"), "cmd 1: {out1:?}");
    assert!(out2.contains("CMD_TWO"), "cmd 2: {out2:?}");
    assert!(out3.contains("CMD_THREE"), "cmd 3: {out3:?}");
}
