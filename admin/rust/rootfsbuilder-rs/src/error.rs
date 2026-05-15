//! Error types with per-phase context for rootfs builds.
//!
//! Every error carries the phase where it occurred plus the command/path
//! that triggered it and any relevant output fragment (truncated) so that
//! the operator can immediately understand what failed and where.

use std::fmt;

/// Build phases, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootfsPhase {
    Preflight,
    Debootstrap,
    Chroot,
    ImageCreate,
    Verify,
}

impl fmt::Display for RootfsPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RootfsPhase::Preflight => write!(f, "Preflight"),
            RootfsPhase::Debootstrap => write!(f, "Debootstrap"),
            RootfsPhase::Chroot => write!(f, "Chroot"),
            RootfsPhase::ImageCreate => write!(f, "ImageCreate"),
            RootfsPhase::Verify => write!(f, "Verify"),
        }
    }
}

/// Rich error type: phase + human-readable description + optional context.
#[derive(Debug)]
pub struct RootfsError {
    pub phase: RootfsPhase,
    pub message: String,
    pub detail: Option<String>,
}

impl RootfsError {
    pub fn new(phase: RootfsPhase, message: impl Into<String>) -> Self {
        Self {
            phase,
            message: message.into(),
            detail: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Construct from a failed command with stdout/stderr.
    pub fn from_cmd(phase: RootfsPhase, cmd: &str, exit_code: Option<i32>, stderr: &str) -> Self {
        let exit_str = exit_code.map_or_else(|| "signal".into(), |c| format!("exit {c}"));
        let message = format!("command failed ({exit_str}): {cmd}");
        let detail = if stderr.is_empty() {
            None
        } else {
            // Keep only the last 20 lines to avoid huge dumps in the log.
            let tail: String = stderr
                .lines()
                .rev()
                .take(20)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            Some(tail)
        };
        Self {
            phase,
            message,
            detail,
        }
    }

    /// Construct from a missing file/binary.
    pub fn missing(phase: RootfsPhase, what: &str, path: &std::path::Path) -> Self {
        Self::new(phase, format!("{what} not found: {}", path.display()))
    }
}

impl fmt::Display for RootfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.phase, self.message)?;
        if let Some(d) = &self.detail {
            write!(f, "\n  detail:\n    {}", d.replace('\n', "\n    "))?;
        }
        Ok(())
    }
}

impl std::error::Error for RootfsError {}

pub type Result<T> = std::result::Result<T, RootfsError>;

// ── Convenience macros ────────────────────────────────────────────────────────

/// Return Err(RootfsError) from current function.
#[macro_export]
macro_rules! bail {
    ($phase:expr_2021, $msg:expr_2021) => {
        return Err($crate::error::RootfsError::new($phase, $msg))
    };
    ($phase:expr_2021, $fmt:expr_2021, $($arg:tt)*) => {
        return Err($crate::error::RootfsError::new($phase, format!($fmt, $($arg)*)))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_display() {
        assert_eq!(RootfsPhase::Preflight.to_string(), "Preflight");
        assert_eq!(RootfsPhase::Debootstrap.to_string(), "Debootstrap");
        assert_eq!(RootfsPhase::Chroot.to_string(), "Chroot");
        assert_eq!(RootfsPhase::ImageCreate.to_string(), "ImageCreate");
        assert_eq!(RootfsPhase::Verify.to_string(), "Verify");
    }

    #[test]
    fn error_display_no_detail() {
        let e = RootfsError::new(RootfsPhase::Preflight, "mke2fs not found");
        assert!(e.to_string().contains("[Preflight]"));
        assert!(e.to_string().contains("mke2fs not found"));
    }

    #[test]
    fn error_display_with_detail() {
        let e = RootfsError::new(RootfsPhase::Chroot, "chroot setup failed")
            .with_detail("dpkg: error processing package");
        let s = e.to_string();
        assert!(s.contains("[Chroot]"));
        assert!(s.contains("dpkg: error processing package"));
    }

    #[test]
    fn from_cmd_truncates_stderr() {
        #[allow(clippy::format_collect)]
        let long_stderr: String = (0..50).map(|i| format!("line {i}\n")).collect();
        let e = RootfsError::from_cmd(
            RootfsPhase::Debootstrap,
            "debootstrap",
            Some(1),
            &long_stderr,
        );
        let detail = e.detail.unwrap();
        // Must contain at most 20 lines
        assert!(detail.lines().count() <= 20);
    }

    #[test]
    fn from_cmd_empty_stderr_has_no_detail() {
        let e = RootfsError::from_cmd(RootfsPhase::ImageCreate, "mke2fs", Some(1), "");
        assert!(e.detail.is_none());
    }

    #[test]
    fn missing_error() {
        let path = std::path::PathBuf::from("/usr/sbin/mke2fs");
        let e = RootfsError::missing(RootfsPhase::Preflight, "mke2fs binary", &path);
        assert!(e.to_string().contains("/usr/sbin/mke2fs"));
    }
}
