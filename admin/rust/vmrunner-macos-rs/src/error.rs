//! Error types for vmrunner-macos-rs.

use thiserror::Error;

/// All errors that can occur in vmrunner-macos-rs.
#[derive(Debug, Error)]
pub enum VZError {
    /// VM creation failed.
    #[error("VM creation failed: {0}")]
    CreationFailed(String),

    /// VM start failed.
    #[error("VM start failed: {0}")]
    StartFailed(String),

    /// VM stop failed.
    #[error("VM stop failed: {0}")]
    StopFailed(String),

    /// Snapshot save failed.
    #[error("Snapshot save failed: {0}")]
    SnapshotSaveFailed(String),

    /// Snapshot load failed.
    #[error("Snapshot load failed: {0}")]
    SnapshotLoadFailed(String),

    /// Port already in use.
    #[error("Port {0} already in use")]
    PortInUse(u16),

    /// Insufficient disk space.
    #[error("Insufficient disk space: {message}")]
    InsufficientDiskSpace {
        /// Available bytes on disk.
        available_bytes: u64,
        /// Required bytes for VM creation.
        required_bytes: u64,
        /// Human-readable error message.
        message: String,
    },

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// VZ framework error (Objective-C FFI).
    #[error("VZ framework error: {0}")]
    VZFrameworkError(String),

    /// VM not found.
    #[error("VM not found: {0}")]
    NotFound(String),

    /// VM already exists.
    #[error("VM already exists: {0}")]
    AlreadyExists(String),

    /// Resource exhausted (CPU, memory, etc.).
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// YAML parsing error.
    #[error("Config parsing error: {0}")]
    ConfigParse(String),

    /// VZ virtualization operation error (`ObjC` FFI result).
    #[error("Virtualization error: {0}")]
    VirtualizationError(String),

    /// The macOS host active-VM limit has been reached (Apple's per-host
    /// concurrent macOS-guest limit). Either detected up front by the admission
    /// authority, or mapped reactively from VZ error `Code=6`. Carries an
    /// operator-readable message; the machine-readable failure code
    /// (`host_vm_limit_reached`) is attached downstream in `init-state.json`.
    #[error("Host VM limit reached: {0}")]
    HostVmLimitReached(String),

    /// Virtualization is unavailable for this process on this host —
    /// `+[VZVirtualMachine isSupported]` reported false. The cause is either
    /// unsupported host hardware/OS OR a missing virtualization authorization;
    /// the supportability probe cannot distinguish them, so this stays a typed
    /// LOCAL error and is deliberately NOT mapped to a guest-image failure code
    /// (that would need a new theyos<->iOS wire code — a separate decision).
    /// The message is worded to avoid `GuestImageFailureCode::classify` trigger
    /// substrings so it stays an honest `Unknown` if ever classified.
    #[error("Virtualization unavailable: {0}")]
    VirtualizationUnsupported(String),

    /// Snapshot operation error.
    #[error("Snapshot error: {0}")]
    SnapshotError(String),

    /// Network error (DHCP lookup, SSH key, etc.).
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Internal implementation error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Generic error wrapper.
    #[error("{0}")]
    Other(String),
}

impl VZError {
    /// Create a config parse error with line number context.
    #[must_use]
    pub fn config_parse(msg: &str, line: usize, col: usize) -> Self {
        Self::ConfigParse(format!("Line {line}, column {col}: {msg}"))
    }

    /// Create a config validation error with usage example.
    #[must_use]
    pub fn config_validation(msg: &str, example: &str) -> Self {
        Self::InvalidConfig(format!("{msg}\n\nExample:\n{example}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = VZError::PortInUse(8080);
        assert_eq!(err.to_string(), "Port 8080 already in use");

        let err = VZError::InsufficientDiskSpace {
            available_bytes: 1000,
            required_bytes: 5000,
            message: "Not enough space".to_string(),
        };
        assert_eq!(err.to_string(), "Insufficient disk space: Not enough space");
    }

    #[test]
    fn test_config_parse_error() {
        let err = VZError::config_parse("unexpected token", 5, 10);
        assert_eq!(
            err.to_string(),
            "Config parsing error: Line 5, column 10: unexpected token"
        );
    }
}
