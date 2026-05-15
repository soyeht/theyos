//! SSH operations for the golden image build pipeline.
//!
//! Uses `vmrunner_rs::ssh_client::SshSession` (russh-based, async) for
//! build VM interactions:
//! - waiting for SSH to become available,
//! - executing commands (including `InstallerPlan` steps),
//! - verifying installed binaries.

use std::path::Path;
use std::time::Duration;

use vmrunner_rs::ssh_client::SshSession;

use super::error::{BuildError, BuildPhase, BuildResult};
/// Wait up to `timeout` for SSH on the build VM to respond.
/// Returns the connected `SshSession` for reuse.
pub async fn wait_for_ssh(
    ssh_port: u16,
    ssh_key: &Path,
    timeout: Duration,
    claw: &str,
) -> BuildResult<SshSession> {
    // Convert timeout to a rough max-tries count (each try backs off ~2s avg)
    // NOTE: timeout.as_secs()/2 is always small enough for u32; truncation is safe.
    #[allow(clippy::cast_possible_truncation)]
    let max_tries = (timeout.as_secs() / 2).max(1) as u32;

    match SshSession::wait_for_ssh_install(ssh_port, ssh_key, max_tries).await {
        Ok(sess) => {
            eprintln!("[golden][{claw}] SSH ready");
            Ok(sess)
        }
        Err(e) => Err(BuildError::new(
            BuildPhase::WaitSsh,
            claw,
            format!("SSH did not respond within {}s: {e}", timeout.as_secs()),
        )),
    }
}

/// Execute a command inside the build VM via SSH. Returns stdout.
pub async fn ssh_exec(
    sess: &SshSession,
    command: &str,
    claw: &str,
    phase: BuildPhase,
) -> BuildResult<String> {
    sess.exec(command)
        .await
        .map_err(|e| vm_error_to_build_error(&e, command, claw, phase))
}

/// Execute a long-running command (e.g. `InstallerPlan` step) with the install
/// timeout (15 min). Output is captured; errors are reported with context.
pub async fn ssh_exec_live(
    sess: &SshSession,
    command: &str,
    claw: &str,
    phase: BuildPhase,
) -> BuildResult<()> {
    sess.exec_install(command)
        .await
        .map_err(|e| vm_error_to_build_error(&e, command, claw, phase))?;
    Ok(())
}

/// Convert a `VmError` into a `BuildError`, preserving stdout/stderr from
/// the `ErrorContext` when available.  This is the single conversion point
/// so that no SSH output is silently discarded.
fn vm_error_to_build_error(
    err: &vmrunner_rs::error::VmError,
    command: &str,
    claw: &str,
    phase: BuildPhase,
) -> BuildError {
    let mut build_err = BuildError::new(phase, claw, format!("command failed: {command}: {err}"));

    if let Some(ctx) = err.context() {
        if let Some(ref stdout) = ctx.stdout_tail {
            build_err = build_err.with_stdout(stdout);
        }
        if let Some(ref stderr) = ctx.stderr_tail {
            build_err = build_err.with_stderr(stderr);
        }
    }

    build_err
}

/// Verify that a binary exists in PATH inside the VM.
/// Returns the version string from `<binary> --version`.
///
/// Resolves via `command -v` (POSIX, honors PATH) rather than hardcoding
/// `/usr/local/bin/<binary>`. Builtins install to `/usr/local/bin/`, but
/// template-driven installs (e.g. `npm install -g`, `pipx install`,
/// `cargo install`) can land binaries in other PATH entries
/// (`/usr/bin/`, `/root/.cargo/bin/`, `/root/.local/bin/`, etc.).
pub async fn verify_binary(sess: &SshSession, binary: &str, claw: &str) -> BuildResult<String> {
    let check_cmd = format!("command -v {binary}");
    let path = sess.exec(&check_cmd).await.map_err(|_| {
        BuildError::new(
            BuildPhase::VerifyBinary,
            claw,
            format!("{binary} not found in PATH"),
        )
    })?;
    let path = path.trim();
    if path.is_empty() {
        return Err(BuildError::new(
            BuildPhase::VerifyBinary,
            claw,
            format!("{binary} not found in PATH"),
        ));
    }

    // Get version string (best-effort)
    let version = sess
        .exec(&format!("{binary} --version 2>&1 | head -1"))
        .await
        .unwrap_or_else(|_| "unknown".to_string());

    Ok(version.trim().to_string())
}

/// Run cleanup commands inside the VM to reduce image size.
pub async fn vm_cleanup(sess: &SshSession, claw: &str) {
    let cmd = "rm -rf /tmp/* /var/cache/apt/archives/*.deb /var/lib/apt/lists/* \
        /root/.cache/pip /root/.cargo/registry /root/.cargo/git 2>/dev/null; \
        apt-get clean 2>/dev/null || true; \
        history -c 2>/dev/null || true; \
        sync";
    // Best-effort — don't fail build on cleanup errors
    let _ = ssh_exec(sess, cmd, claw, BuildPhase::Cleanup).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmrunner_rs::error::ErrorContext;

    #[tokio::test]
    async fn wait_for_ssh_times_out_immediately_on_no_port() {
        // We test that the function returns an error when SSH is unreachable.
        // Use a very short timeout to keep the test fast.
        use std::path::PathBuf;
        let dummy_key = PathBuf::from("/nonexistent/key");
        let result = wait_for_ssh(0, &dummy_key, Duration::from_secs(1), "test").await;
        assert!(result.is_err());
    }

    // ── Context propagation tests ─────────────────────────────────────

    /// When a `VmError` carries stdout in its `ErrorContext`, the resulting
    /// `BuildError` must preserve it in `stdout_tail` and show it in Display.
    #[test]
    fn build_error_from_vm_error_preserves_stdout() {
        let ctx = ErrorContext::with_phase("ssh.exec")
            .command("pnpm build")
            .exit_code(1)
            .stdout("Building...\nERROR: module not found");
        let vm_err = vmrunner_rs::error::VmError::ssh_exec("command exited 1", ctx);

        let build_err =
            vm_error_to_build_error(&vm_err, "pnpm build", "openclaw", BuildPhase::RunInstaller);

        assert!(
            build_err.stdout_tail.is_some(),
            "stdout_tail should be populated from VmError context"
        );
        let stdout = build_err.stdout_tail.as_ref().unwrap();
        assert!(
            stdout.contains("ERROR: module not found"),
            "stdout_tail should contain the build output, got: {stdout}"
        );
        let display = build_err.to_string();
        assert!(
            display.contains("stdout tail"),
            "Display should show stdout section, got: {display}"
        );
    }

    /// When a `VmError` carries stderr in its `ErrorContext`, the resulting
    /// `BuildError` must preserve it in `stderr_tail` and show it in Display.
    #[test]
    fn build_error_from_vm_error_preserves_stderr() {
        let ctx = ErrorContext::with_phase("ssh.exec")
            .command("pnpm install")
            .exit_code(1)
            .stderr("ERR_PNPM_PREPARE_PACKAGE  spawn ENOENT");
        let vm_err = vmrunner_rs::error::VmError::ssh_exec("command exited 1", ctx);

        let build_err = vm_error_to_build_error(
            &vm_err,
            "pnpm install",
            "openclaw",
            BuildPhase::RunInstaller,
        );

        assert!(
            build_err.stderr_tail.is_some(),
            "stderr_tail should be populated from VmError context"
        );
        let stderr = build_err.stderr_tail.as_ref().unwrap();
        assert!(
            stderr.contains("ERR_PNPM_PREPARE_PACKAGE"),
            "stderr_tail should contain the error, got: {stderr}"
        );
    }

    /// When a `VmError` carries both stdout and stderr, both should be
    /// preserved and appear in the Display output.
    #[test]
    fn build_error_from_vm_error_preserves_both_streams() {
        let ctx = ErrorContext::with_phase("ssh.exec")
            .command("pnpm build")
            .exit_code(1)
            .stdout("Compiling packages...\nBuild step 3/5")
            .stderr("npm WARN deprecated\nspawn ENOENT");
        let vm_err = vmrunner_rs::error::VmError::ssh_exec("command exited 1", ctx);

        let build_err =
            vm_error_to_build_error(&vm_err, "pnpm build", "openclaw", BuildPhase::RunInstaller);

        assert!(build_err.stdout_tail.is_some(), "stdout_tail should be set");
        assert!(build_err.stderr_tail.is_some(), "stderr_tail should be set");
        let display = build_err.to_string();
        assert!(
            display.contains("Build step 3/5"),
            "Display should include stdout content, got: {display}"
        );
        assert!(
            display.contains("spawn ENOENT"),
            "Display should include stderr content, got: {display}"
        );
    }

    /// When a `VmError` has no `ErrorContext` (e.g. `ssh_exec_plain`), the
    /// `BuildError` should still work — just without stdout/stderr tails.
    #[test]
    fn build_error_from_vm_error_without_context_has_no_tails() {
        let vm_err = vmrunner_rs::error::VmError::ssh_exec_plain("connection reset");

        let build_err =
            vm_error_to_build_error(&vm_err, "some cmd", "test", BuildPhase::RunInstaller);

        assert!(
            build_err.stdout_tail.is_none(),
            "should have no stdout_tail"
        );
        assert!(
            build_err.stderr_tail.is_none(),
            "should have no stderr_tail"
        );
    }
}
