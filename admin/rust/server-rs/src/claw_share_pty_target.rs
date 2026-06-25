//! Real interactive PTY target for the claw-share data tunnel.
//!
//! Implements [`household_rs::claw_share_data_tunnel::ClawTargetRouter`] by
//! allocating a real local PTY and spawning a **policy-controlled** shell on
//! it. The serve loop then pipes the friend's terminal stdin/stdout over the
//! authenticated tunnel, propagates terminal resizes (`TIOCSWINSZ`), and
//! reports the shell's typed exit status when it terminates.
//!
//! ## Security / policy
//!
//! The spawned command is **fixed by [`PtyPolicy`]**, never chosen by the
//! connecting client — the friend can type into the terminal and resize it,
//! but cannot select the program, its arguments, or its environment. The
//! shell runs as the engine's own (unprivileged) service user; there is no
//! privilege escalation here. The environment is **cleared** and rebuilt from
//! a minimal allowlist (`TERM`, `PATH`, `LANG`, inherited `HOME`/`USER`), so
//! the child does not inherit the daemon's secrets. Reaching this target at
//! all already required a valid, non-revoked `GuestCredential` plus a
//! single-use proof-of-possession token bound to this claw (enforced in
//! `claw_share_data_tunnel`); this module decides only *what* runs once that
//! authorization has passed. `kill_on_drop` guarantees the child dies the
//! moment the session ends (clean close, revocation, idle timeout, or tunnel
//! drop) — no zombie shells.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use household_rs::claw_share_data_tunnel::{
    ClawTargetRouter, DataTunnelError, TargetExit, TargetSession,
};

/// What the engine runs when a friend opens an interactive claw session.
///
/// Pinned server-side — the client never chooses any of these fields.
#[derive(Debug, Clone)]
pub struct PtyPolicy {
    /// Absolute path to the shell/command to exec (e.g. `/bin/sh`).
    pub shell: String,
    /// Fixed arguments passed to `shell`.
    pub args: Vec<String>,
    /// `TERM` advertised to the child.
    pub term: String,
    /// Initial terminal dimensions before the client's first resize.
    pub cols: u16,
    pub rows: u16,
}

impl Default for PtyPolicy {
    fn default() -> Self {
        Self {
            shell: "/bin/sh".to_string(),
            args: Vec::new(),
            term: "xterm-256color".to_string(),
            cols: 80,
            rows: 24,
        }
    }
}

impl PtyPolicy {
    /// Build the policy from the environment. `THEYOS_CLAW_PTY_SHELL`
    /// overrides the shell (absolute path); everything else uses the
    /// hardened defaults. The override is an operator decision, not a
    /// client-supplied value.
    #[must_use]
    pub fn from_env() -> Self {
        let mut policy = Self::default();
        if let Ok(shell) = std::env::var("THEYOS_CLAW_PTY_SHELL") {
            if !shell.is_empty() {
                policy.shell = shell;
            }
        }
        policy
    }
}

/// Opens a fresh PTY + policy shell per session.
pub struct PtyTargetRouter {
    policy: PtyPolicy,
}

impl PtyTargetRouter {
    #[must_use]
    pub fn new(policy: PtyPolicy) -> Self {
        Self { policy }
    }
}

/// Apply a terminal window size to a (dup'd) PTY master fd via `TIOCSWINSZ`.
/// The kernel also delivers `SIGWINCH` to the foreground process group.
fn set_winsize(fd: RawFd, cols: u16, rows: u16) -> Result<(), DataTunnelError> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    #[allow(unsafe_code)]
    // SAFETY: `fd` is a live, owned dup of the PTY master held for the
    // lifetime of the resize closure; `ws` is a valid `winsize`.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as _, std::ptr::addr_of!(ws)) };
    if rc == 0 {
        Ok(())
    } else {
        Err(DataTunnelError::Io(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

/// Map a process exit status to the tunnel's typed [`TargetExit`].
fn exit_from_status(status: std::process::ExitStatus) -> TargetExit {
    use std::os::unix::process::ExitStatusExt as _;
    if let Some(code) = status.code() {
        TargetExit::Code(code)
    } else if let Some(signal) = status.signal() {
        TargetExit::Signal(signal)
    } else {
        TargetExit::Lost
    }
}

impl ClawTargetRouter for PtyTargetRouter {
    async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
        let (pty, pts) = pty_process::open()
            .map_err(|e| DataTunnelError::TargetUnavailable(format!("openpty: {e}")))?;
        // Initial size (best-effort — the client resizes immediately after).
        let _ = pty.resize(pty_process::Size::new(self.policy.rows, self.policy.cols));

        // Dup the master fd so the resize closure can drive TIOCSWINSZ
        // independently of the moved write half.
        let resize_fd = pty
            .as_fd()
            .try_clone_to_owned()
            .map_err(|e| DataTunnelError::TargetUnavailable(format!("dup pty master: {e}")))?;

        let mut cmd = pty_process::Command::new(&self.policy.shell);
        if !self.policy.args.is_empty() {
            cmd = cmd.args(&self.policy.args);
        }
        cmd = cmd
            .env_clear()
            .env("TERM", &self.policy.term)
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LANG", "C.UTF-8")
            .kill_on_drop(true);
        // Re-add a couple of benign inherited vars if present (the daemon's
        // secrets were already dropped by env_clear).
        if let Ok(home) = std::env::var("HOME") {
            cmd = cmd.env("HOME", home);
        }
        if let Ok(user) = std::env::var("USER") {
            cmd = cmd.env("USER", user);
        }

        let mut child = cmd
            .spawn(pts)
            .map_err(|e| DataTunnelError::TargetUnavailable(format!("spawn shell: {e}")))?;

        let (read_pty, write_pty) = pty.into_split();
        let exit = Box::pin(async move {
            match child.wait().await {
                Ok(status) => exit_from_status(status),
                Err(_) => TargetExit::Lost,
            }
        });
        let resize =
            Box::new(move |cols: u16, rows: u16| set_winsize(resize_fd.as_raw_fd(), cols, rows));

        Ok(TargetSession {
            reader: Box::new(read_pty),
            writer: Box::new(write_pty),
            resize,
            exit,
        })
    }
}

/// Drain a target session's output to a `String` until EOF (test helper).
#[cfg(test)]
async fn drain_output(reader: &mut (dyn tokio::io::AsyncRead + Send + Unpin)) -> String {
    use tokio::io::AsyncReadExt as _;
    let mut out = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn pty_runs_shell_command_and_propagates_exit_code() {
        let router = PtyTargetRouter::new(PtyPolicy {
            shell: "/bin/sh".into(),
            args: vec!["-c".into(), "echo R18-PTY-OK; exit 7".into()],
            ..Default::default()
        });
        let mut ts = router.open("claw_test").await.expect("open pty");
        let out = drain_output(&mut ts.reader).await;
        assert!(
            out.contains("R18-PTY-OK"),
            "shell output missing, got: {out:?}"
        );
        // After output EOF, the typed exit status is available.
        let status = ts.exit.await;
        assert_eq!(status, TargetExit::Code(7), "exit code must propagate");
    }

    #[tokio::test]
    async fn pty_signal_exit_propagates_as_signal() {
        // Shell kills itself with SIGKILL (9).
        let router = PtyTargetRouter::new(PtyPolicy {
            shell: "/bin/sh".into(),
            args: vec!["-c".into(), "kill -9 $$".into()],
            ..Default::default()
        });
        let mut ts = router.open("claw_test").await.expect("open pty");
        let _ = drain_output(&mut ts.reader).await;
        assert_eq!(
            ts.exit.await,
            TargetExit::Signal(9),
            "signal exit must propagate"
        );
    }

    #[tokio::test]
    async fn pty_echoes_interactive_input() {
        let router = PtyTargetRouter::new(PtyPolicy {
            shell: "/bin/cat".into(),
            ..Default::default()
        });
        let mut ts = router.open("claw_test").await.expect("open pty");
        ts.writer
            .write_all(b"ping-r18\n")
            .await
            .expect("write stdin");
        ts.writer.flush().await.expect("flush");
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), ts.reader.read(&mut buf))
            .await
            .expect("read did not time out")
            .expect("read ok");
        assert!(
            String::from_utf8_lossy(&buf[..n]).contains("ping-r18"),
            "interactive input must appear in PTY output"
        );
        // Dropping `ts` kills `cat` via kill_on_drop — no zombie.
    }

    #[tokio::test]
    async fn pty_resize_is_applied() {
        let router = PtyTargetRouter::new(PtyPolicy {
            shell: "/bin/cat".into(),
            ..Default::default()
        });
        let ts = router.open("claw_test").await.expect("open pty");
        assert!(
            (ts.resize)(120, 40).is_ok(),
            "resize must succeed on a live PTY"
        );
        assert!((ts.resize)(80, 24).is_ok());
    }
}
