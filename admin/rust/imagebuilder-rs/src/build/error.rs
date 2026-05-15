//! Structured error type for the build pipeline.

use std::fmt;

/// Maximum number of lines kept from the tail of stdout/stderr for diagnostics.
const TAIL_LINES: usize = 20;

/// Keep the last `n` lines of a string.
fn keep_last_n_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Phase within the golden image build pipeline.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildPhase {
    Preflight,
    CopyRootfs,
    BootVm,
    WaitSsh,
    PushCache,
    RunInstaller,
    VerifyBinary,
    PullCache,
    Cleanup,
    Shutdown,
    PublishArtifact,
    /// `--verify-only` post-install liveness probe (start claw, 60s soak, kill -0).
    SmokeTest,
}

impl fmt::Display for BuildPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Preflight => "preflight",
            Self::CopyRootfs => "copy-rootfs",
            Self::BootVm => "boot-vm",
            Self::WaitSsh => "wait-ssh",
            Self::PushCache => "push-cache",
            Self::RunInstaller => "run-installer",
            Self::VerifyBinary => "verify-binary",
            Self::PullCache => "pull-cache",
            Self::Cleanup => "cleanup",
            Self::Shutdown => "shutdown",
            Self::PublishArtifact => "publish-artifact",
            Self::SmokeTest => "smoke-test",
        };
        write!(f, "{s}")
    }
}

/// Rich error returned by any build pipeline step.
#[derive(Debug)]
pub struct BuildError {
    pub phase: BuildPhase,
    pub claw: String,
    pub message: String,
    pub stdout_tail: Option<String>,
    pub stderr_tail: Option<String>,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl BuildError {
    pub fn new(phase: BuildPhase, claw: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            phase,
            claw: claw.into(),
            message: message.into(),
            stdout_tail: None,
            stderr_tail: None,
            source: None,
        }
    }

    /// Attach stdout output (last 20 lines). Ignored if empty/whitespace.
    pub fn with_stdout(mut self, stdout: impl Into<String>) -> Self {
        let s = stdout.into();
        if !s.trim().is_empty() {
            self.stdout_tail = Some(keep_last_n_lines(&s, TAIL_LINES));
        }
        self
    }

    /// Attach stderr output (last 20 lines). Ignored if empty/whitespace.
    pub fn with_stderr(mut self, stderr: impl Into<String>) -> Self {
        let s = stderr.into();
        if !s.trim().is_empty() {
            self.stderr_tail = Some(keep_last_n_lines(&s, TAIL_LINES));
        }
        self
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] phase={} — {}", self.claw, self.phase, self.message)?;
        if let Some(tail) = &self.stdout_tail {
            write!(f, "\n  --- stdout tail ---\n{tail}\n  ---")?;
        }
        if let Some(tail) = &self.stderr_tail {
            write!(f, "\n  --- stderr tail ---\n{tail}\n  ---")?;
        }
        Ok(())
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

pub type BuildResult<T> = Result<T, BuildError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shows_stdout_tail_when_present() {
        let err = BuildError::new(BuildPhase::RunInstaller, "openclaw", "pnpm build failed")
            .with_stdout("line1\nline2\nERROR: something broke");
        let msg = err.to_string();
        assert!(
            msg.contains("--- stdout tail ---"),
            "Display should include stdout tail section, got: {msg}"
        );
        assert!(
            msg.contains("ERROR: something broke"),
            "Display should include the actual stdout content, got: {msg}"
        );
    }

    #[test]
    fn display_shows_stderr_tail_when_present() {
        let err = BuildError::new(BuildPhase::RunInstaller, "openclaw", "pnpm build failed")
            .with_stderr("WARN: deprecated\nERR_PNPM: spawn ENOENT");
        let msg = err.to_string();
        assert!(
            msg.contains("--- stderr tail ---"),
            "Display should include stderr tail section, got: {msg}"
        );
        assert!(
            msg.contains("ERR_PNPM: spawn ENOENT"),
            "Display should include the actual stderr content, got: {msg}"
        );
    }

    #[test]
    fn display_shows_both_stdout_and_stderr_when_present() {
        let err = BuildError::new(BuildPhase::RunInstaller, "openclaw", "build failed")
            .with_stdout("Building package...\nCompile error on line 42")
            .with_stderr("npm WARN deprecated");
        let msg = err.to_string();
        assert!(
            msg.contains("--- stdout tail ---"),
            "should contain stdout section, got: {msg}"
        );
        assert!(
            msg.contains("Compile error on line 42"),
            "should contain stdout content, got: {msg}"
        );
        assert!(
            msg.contains("--- stderr tail ---"),
            "should contain stderr section, got: {msg}"
        );
        assert!(
            msg.contains("npm WARN deprecated"),
            "should contain stderr content, got: {msg}"
        );
    }

    #[test]
    fn display_omits_stdout_tail_when_empty_or_whitespace() {
        let err =
            BuildError::new(BuildPhase::RunInstaller, "openclaw", "failed").with_stdout("   \n  ");
        let msg = err.to_string();
        assert!(
            !msg.contains("stdout tail"),
            "should not show stdout section for whitespace-only, got: {msg}"
        );
    }

    #[test]
    fn display_omits_stderr_tail_when_empty_or_whitespace() {
        let err =
            BuildError::new(BuildPhase::RunInstaller, "openclaw", "failed").with_stderr("   \n  ");
        let msg = err.to_string();
        assert!(
            !msg.contains("stderr tail"),
            "should not show stderr section for whitespace-only, got: {msg}"
        );
    }

    #[test]
    fn with_stdout_keeps_last_20_lines() {
        let lines: Vec<String> = (1..=30).map(|i| format!("line {i}")).collect();
        let big = lines.join("\n");
        let err = BuildError::new(BuildPhase::RunInstaller, "test", "failed").with_stdout(big);
        let tail = err.stdout_tail.expect("should have stdout_tail");
        let tail_lines: Vec<&str> = tail.lines().collect();
        assert_eq!(tail_lines.len(), 20, "should keep last 20 lines");
        assert!(
            tail_lines[0].contains("line 11"),
            "first kept line should be 'line 11', got: {}",
            tail_lines[0]
        );
        assert!(
            tail_lines[19].contains("line 30"),
            "last kept line should be 'line 30', got: {}",
            tail_lines[19]
        );
    }
}
