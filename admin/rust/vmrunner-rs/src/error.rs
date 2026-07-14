//! error.rs — unified error type for vmrunner-rs.

use thiserror::Error;

/// Structured context attached to errors that happen inside a running VM operation.
///
/// Every field is optional so callers can fill in only what's known at the point
/// of failure — no field should be fabricated.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ErrorContext {
    /// High-level phase where the failure occurred (e.g. `"start_vm.wait_slirp_socket"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,

    /// Container/instance name being operated on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,

    /// The exact command that failed (SSH exec, process spawn, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Process or SSH exit code (absent for timeouts and spawn errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// True when the operation was killed by a wall-clock deadline rather than
    /// exiting with a non-zero code.
    #[serde(default)]
    pub timed_out: bool,

    /// How long the operation ran before failing, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,

    /// Last ≤ 8 KB of stdout from the failed command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_tail: Option<String>,

    /// Last ≤ 8 KB of stderr from the failed command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_tail: Option<String>,

    /// Last ≤ 8 KB of the VM's serial console log (`serial.log`).
    /// Populated for boot/network failures where the VM did not come up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_log_tail: Option<String>,

    /// Last ≤ 8 KB of the slirp4netns log (`slirp.log`).
    /// Populated for network/port-forward failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slirp_log_tail: Option<String>,
}

/// Maximum number of bytes kept from the end of any log/stream for diagnostics.
pub const TAIL_BYTES: usize = 8 * 1024;

impl ErrorContext {
    /// Return a new builder-style context with just the phase set.
    pub fn with_phase(phase: impl Into<String>) -> Self {
        ErrorContext {
            phase: Some(phase.into()),
            ..Default::default()
        }
    }

    /// Set the container field and return self (builder).
    #[must_use]
    pub fn container(mut self, container: impl Into<String>) -> Self {
        self.container = Some(container.into());
        self
    }

    /// Set the command field and return self (builder).
    #[must_use]
    pub fn command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Set `exit_code` and return self (builder).
    #[must_use]
    pub fn exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    /// Mark as timed out and return self (builder).
    #[must_use]
    pub fn timed_out(mut self) -> Self {
        self.timed_out = true;
        self
    }

    /// Set `elapsed_ms` and return self (builder).
    #[must_use]
    pub fn elapsed_ms(mut self, ms: u64) -> Self {
        self.elapsed_ms = Some(ms);
        self
    }

    /// Set `stdout_tail` from raw bytes (truncated to `TAIL_BYTES` from the end).
    #[must_use]
    pub fn stdout(mut self, s: impl Into<String>) -> Self {
        self.stdout_tail = Some(tail_str(s.into()));
        self
    }

    /// Set `stderr_tail` from raw bytes (truncated to `TAIL_BYTES` from the end).
    #[must_use]
    pub fn stderr(mut self, s: impl Into<String>) -> Self {
        self.stderr_tail = Some(tail_str(s.into()));
        self
    }

    /// Attach the tail of a file as `serial_log_tail` (best-effort; silent on error).
    #[must_use]
    pub fn serial_log_from_file(mut self, path: &std::path::Path) -> Self {
        self.serial_log_tail = read_file_tail(path);
        self
    }

    /// Attach the tail of a file as `slirp_log_tail` (best-effort; silent on error).
    #[must_use]
    pub fn slirp_log_from_file(mut self, path: &std::path::Path) -> Self {
        self.slirp_log_tail = read_file_tail(path);
        self
    }
}

/// Truncate a string to the last [`TAIL_BYTES`] bytes (splitting on UTF-8 boundary).
#[must_use]
pub fn tail_str(s: String) -> String {
    let bytes = s.as_bytes();
    if bytes.len() <= TAIL_BYTES {
        return s;
    }
    let start = bytes.len() - TAIL_BYTES;
    // Walk forward to the next valid UTF-8 boundary (bounded to bytes.len()).
    let aligned = (start..=bytes.len())
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(bytes.len());
    s[aligned..].to_string()
}

/// Read the last [`TAIL_BYTES`] bytes of a file as a lossy UTF-8 string.
/// Returns `None` on any error (missing file, permission denied, etc.).
#[must_use]
pub fn read_file_tail(path: &std::path::Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(TAIL_BYTES as u64);
    if start > 0 {
        f.seek(SeekFrom::Start(start)).ok()?;
    }
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Diagnostic log tails captured from an instance directory before it is
/// deleted by the rollback guard. Pass this into `ErrorContext` via
/// `apply_diagnostic_logs()` to attach boot/network failure context.
#[derive(Debug, Clone, Default)]
pub struct DiagnosticLogs {
    pub serial_log_tail: Option<String>,
    pub slirp_log_tail: Option<String>,
}

impl DiagnosticLogs {
    /// Read `serial.log` and `slirp.log` tails from an instance directory.
    /// Any missing or unreadable file is silently skipped.
    #[must_use]
    pub fn capture(instance_dir: &std::path::Path) -> Self {
        DiagnosticLogs {
            serial_log_tail: read_file_tail(&instance_dir.join("serial.log")),
            slirp_log_tail: read_file_tail(&instance_dir.join("slirp.log")),
        }
    }
}

impl ErrorContext {
    /// Attach pre-captured diagnostic logs to this context.
    #[must_use]
    pub fn apply_diagnostic_logs(mut self, logs: &DiagnosticLogs) -> Self {
        if self.serial_log_tail.is_none() {
            self.serial_log_tail.clone_from(&logs.serial_log_tail);
        }
        if self.slirp_log_tail.is_none() {
            self.slirp_log_tail.clone_from(&logs.slirp_log_tail);
        }
        self
    }
}

// ── VmError ───────────────────────────────────────────────────────────────

/// All errors that can occur during VM lifecycle operations.
#[derive(Debug, Error)]
pub enum VmError {
    #[error("instance not found: {0}")]
    InstanceNotFound(String),

    #[error("invalid env file: {0}")]
    InvalidEnvFile(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("missing binary or asset: {0}")]
    MissingBinary(String),

    /// SSH connection/handshake failure.
    #[error("SSH connect error: {message}")]
    SshConnect {
        message: String,
        #[source]
        context: Option<ContextError>,
    },

    /// SSH command execution failure — includes the real exit code and streams.
    #[error("SSH exec error: {message}")]
    SshExec {
        message: String,
        context: Option<Box<ErrorContext>>,
    },

    #[error("Firecracker API error: {0}")]
    FirecrackerApi(String),

    /// Wall-clock deadline exceeded.
    #[error("timeout: {message}")]
    Timeout {
        message: String,
        context: Option<Box<ErrorContext>>,
    },

    /// Installer script exited with a non-zero code.
    #[error("installer failed: {message}")]
    InstallerFailed {
        message: String,
        context: Option<Box<ErrorContext>>,
    },

    #[error("unsupported claw type: {0}")]
    UnsupportedClawType(String),

    /// Process spawn / OS-level error (unshare, slirp, debugfs, …).
    #[error("process spawn error: {message}")]
    ProcessSpawn {
        message: String,
        context: Option<Box<ErrorContext>>,
    },

    #[error(
        "no free SSH port available in range {}-{}",
        core_rs::guest_net::SSH_HOST_PORT_RANGE_START,
        core_rs::guest_net::SSH_HOST_PORT_RANGE_END
    )]
    NoFreeSshPort,

    /// The slirp host-forward state may be unknown after an ambiguous API
    /// response. The owning VM must be discarded rather than reused.
    #[error("hostfwd state is uncertain: {0}")]
    HostfwdUncertain(String),

    #[error("{0}")]
    Other(String),
}

/// Thin wrapper so `ErrorContext` can implement `std::error::Error`
/// (required by `#[source]`).
#[derive(Debug)]
pub struct ContextError(pub ErrorContext);
impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
impl std::error::Error for ContextError {}

// ── Convenience constructors ──────────────────────────────────────────────

impl VmError {
    /// Build a `SshConnect` error (no structured context needed — connect
    /// failures don't have exit codes or streams).
    pub fn ssh_connect(msg: impl Into<String>) -> Self {
        VmError::SshConnect {
            message: msg.into(),
            context: None,
        }
    }

    /// Build a `SshExec` error with full structured context.
    pub fn ssh_exec(msg: impl Into<String>, ctx: ErrorContext) -> Self {
        VmError::SshExec {
            message: msg.into(),
            context: Some(Box::new(ctx)),
        }
    }

    /// Build a `SshExec` error without context (for call sites that predate PR2).
    pub fn ssh_exec_plain(msg: impl Into<String>) -> Self {
        VmError::SshExec {
            message: msg.into(),
            context: None,
        }
    }

    /// Build a `Timeout` error with structured context.
    pub fn timeout(msg: impl Into<String>, ctx: ErrorContext) -> Self {
        VmError::Timeout {
            message: msg.into(),
            context: Some(Box::new(ctx)),
        }
    }

    /// Build a plain `Timeout` without context.
    pub fn timeout_plain(msg: impl Into<String>) -> Self {
        VmError::Timeout {
            message: msg.into(),
            context: None,
        }
    }

    /// Build an `InstallerFailed` error with context.
    pub fn installer_failed(msg: impl Into<String>, ctx: ErrorContext) -> Self {
        VmError::InstallerFailed {
            message: msg.into(),
            context: Some(Box::new(ctx)),
        }
    }

    /// Build a plain `InstallerFailed` without context.
    pub fn installer_failed_plain(msg: impl Into<String>) -> Self {
        VmError::InstallerFailed {
            message: msg.into(),
            context: None,
        }
    }

    /// Build a `ProcessSpawn` error with context.
    pub fn process_spawn(msg: impl Into<String>, ctx: ErrorContext) -> Self {
        VmError::ProcessSpawn {
            message: msg.into(),
            context: Some(Box::new(ctx)),
        }
    }

    /// Build a plain `ProcessSpawn` without context.
    pub fn process_spawn_plain(msg: impl Into<String>) -> Self {
        VmError::ProcessSpawn {
            message: msg.into(),
            context: None,
        }
    }

    /// Extract the `ErrorContext` from any variant that carries one.
    #[must_use]
    pub fn context(&self) -> Option<&ErrorContext> {
        match self {
            VmError::SshExec { context, .. }
            | VmError::Timeout { context, .. }
            | VmError::InstallerFailed { context, .. }
            | VmError::ProcessSpawn { context, .. } => context.as_deref(),
            _ => None,
        }
    }

    /// Human-readable short message (same as Display but without the variant prefix).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            VmError::SshConnect { message, .. }
            | VmError::SshExec { message, .. }
            | VmError::Timeout { message, .. }
            | VmError::InstallerFailed { message, .. }
            | VmError::ProcessSpawn { message, .. } => message.clone(),
            other => other.to_string(),
        }
    }
}

impl core_rs::error::AppError for VmError {
    fn code(&self) -> core_rs::error::ErrorCode {
        match self {
            VmError::InstanceNotFound(_) => core_rs::error::ErrorCode::NotFound,
            VmError::InvalidEnvFile(_) | VmError::UnsupportedClawType(_) => {
                core_rs::error::ErrorCode::InvalidInput
            }
            VmError::Timeout { .. } => core_rs::error::ErrorCode::Timeout,
            _ => core_rs::error::ErrorCode::Internal,
        }
    }
}
