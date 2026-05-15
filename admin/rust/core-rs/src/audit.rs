//! Audit logging for all claw operations.
//!
//! Provides structured audit logs for security and compliance (SR-005).
//! Logs are written to ~/Library/Logs/theyos/audit.log with one JSON record
//! per line for easy parsing and analysis.
//!
//! # Audit Events
//!
//! All claw lifecycle operations are logged with:
//! - Timestamp (ISO 8601)
//! - Event type (create, start, stop, delete, restart)
//! - Instance ID
//! - Claw type
//! - User (if authenticated)
//! - Outcome (success, failure)
//! - Error message (if applicable)
//! - Execution time (ms)
//!
//! # Example
//!
//! ```json
//! {"timestamp":"2026-03-20T12:34:56.789Z","event":"create","instance_id":"picoclaw-abc123","claw_type":"picoclaw","user":"admin","outcome":"success","duration_ms":1523}
//! ```

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

/// Audit log entry for a single operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO 8601 timestamp
    pub timestamp: String,

    /// Event type
    pub event: AuditEvent,

    /// Instance ID
    pub instance_id: String,

    /// Claw type (picoclaw, zeroclaw, etc.)
    pub claw_type: String,

    /// User who initiated the operation (if available)
    pub user: Option<String>,

    /// Operation outcome
    pub outcome: AuditOutcome,

    /// Error message (if outcome is failure)
    pub error: Option<String>,

    /// Execution time in milliseconds
    pub duration_ms: u64,

    /// Additional context (port numbers, config values, etc.)
    pub context: Option<serde_json::Value>,
}

/// Types of audit events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditEvent {
    /// Claw instance created
    Create,

    /// Claw instance started
    Start,

    /// Claw instance stopped
    Stop,

    /// Claw instance restarted
    Restart,

    /// Claw instance deleted
    Delete,

    /// Claw configuration updated
    ConfigUpdate,

    /// Snapshot created
    SnapshotCreate,

    /// Snapshot deleted
    SnapshotDelete,

    /// Warm pool operation
    WarmPoolOp,
}

/// Operation outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    /// Operation succeeded
    Success,

    /// Operation failed
    Failure,
}

/// Audit logger for claw operations.
pub struct AuditLogger {
    /// Path to audit log file
    log_path: PathBuf,

    /// File handle (mutex-protected for thread safety)
    file: Mutex<std::fs::File>,
}

impl AuditLogger {
    /// Create or open the audit log file.
    ///
    /// # Errors
    ///
    /// Returns an error if the log file cannot be created or opened.
    pub fn new() -> Result<Self, std::io::Error> {
        let log_dir = audit_dir();

        // Ensure audit directory exists
        std::fs::create_dir_all(&log_dir)?;

        let log_path = log_dir.join("audit.log");

        // Open file in append mode, create if doesn't exist
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        Ok(Self {
            log_path,
            file: Mutex::new(file),
        })
    }

    /// Log an audit event.
    ///
    /// # Errors
    ///
    /// Returns an error if the log entry cannot be written.
    pub fn log(&self, entry: &AuditEntry) -> Result<(), std::io::Error> {
        let json =
            serde_json::to_string(entry).map_err(|e| std::io::Error::other(e.to_string()))?;

        let mut file = self
            .file
            .lock()
            .map_err(|_| std::io::Error::other("lock poisoned"))?;

        writeln!(file, "{json}")?;
        file.flush()?;

        Ok(())
    }

    /// Log a successful operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the log entry cannot be written.
    pub fn log_success(
        &self,
        event: AuditEvent,
        instance_id: String,
        claw_type: String,
        user: Option<String>,
        duration_ms: u64,
    ) -> Result<(), std::io::Error> {
        let entry = AuditEntry {
            timestamp: format_timestamp(),
            event,
            instance_id,
            claw_type,
            user,
            outcome: AuditOutcome::Success,
            error: None,
            duration_ms,
            context: None,
        };

        self.log(&entry)
    }

    /// Log a failed operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the log entry cannot be written.
    pub fn log_failure(
        &self,
        event: AuditEvent,
        instance_id: String,
        claw_type: String,
        user: Option<String>,
        error: String,
        duration_ms: u64,
    ) -> Result<(), std::io::Error> {
        let entry = AuditEntry {
            timestamp: format_timestamp(),
            event,
            instance_id,
            claw_type,
            user,
            outcome: AuditOutcome::Failure,
            error: Some(error),
            duration_ms,
            context: None,
        };

        self.log(&entry)
    }

    /// Get the audit log file path.
    #[must_use]
    pub fn log_path(&self) -> &PathBuf {
        &self.log_path
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new().expect("failed to create audit logger")
    }
}

/// Get the audit log directory.
///
/// Returns ~/Library/Logs/theyos/ on macOS.
#[must_use]
pub fn audit_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join("Library/Logs/theyos")
    }

    #[cfg(not(target_os = "macos"))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".theyos/logs")
    }
}

/// Format current time as ISO 8601 timestamp.
fn format_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let nsecs = now.subsec_nanos();

    // Format: 2026-03-20T12:34:56.789Z
    let (year, month, day) = seconds_to_date(secs);
    let (hour, minute, second) = seconds_to_time(secs);
    let millis = nsecs / 1_000_000;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Convert Unix timestamp to (year, month, day).
#[allow(clippy::cast_possible_truncation)]
fn seconds_to_date(secs: u64) -> (u32, u32, u32) {
    // Simplified conversion - in production, use chrono or time crate
    const DAYS_PER_YEAR: u64 = 365;
    const SECONDS_PER_DAY: u64 = 86400;
    const EPOCH_YEAR: u32 = 1970;

    let days = secs / SECONDS_PER_DAY;
    // Safe: days/DAYS_PER_YEAR fits in u32 for any reasonable timestamp
    let year = EPOCH_YEAR + (days / DAYS_PER_YEAR) as u32;
    let mut remaining_days = (days % DAYS_PER_YEAR) as u32;

    // Approximate month calculation (ignoring leap years for simplicity)
    let month_lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u32;
    for (i, &days_in_month) in month_lengths.iter().enumerate() {
        if remaining_days < days_in_month {
            month = (i as u32) + 1;
            break;
        }
        remaining_days -= days_in_month;
    }

    let day = remaining_days + 1;

    (year, month, day)
}

/// Convert Unix timestamp to (hour, minute, second).
#[allow(clippy::cast_possible_truncation)]
fn seconds_to_time(secs: u64) -> (u32, u32, u32) {
    let secs_of_day = secs % 86400;
    // Safe: values are bounded by modular arithmetic (max 86399)
    let hour = (secs_of_day / 3600) as u32;
    let minute = ((secs_of_day % 3600) / 60) as u32;
    let second = (secs_of_day % 60) as u32;

    (hour, minute, second)
}

/// Helper for timing operations.
///
/// # Example
///
/// ```no_run
/// use core_rs::audit::Timer;
///
/// let timer = Timer::start();
/// // ... do work ...
/// let elapsed = timer.elapsed_ms();
/// ```
#[derive(Debug, Clone)]
pub struct Timer {
    start: std::time::Instant,
}

impl Timer {
    /// Create a new timer starting now.
    #[must_use]
    pub fn start() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }

    /// Get elapsed time in milliseconds.
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        // Safe: elapsed time won't exceed u64::MAX milliseconds in practice
        {
            self.start.elapsed().as_millis() as u64
        }
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::start()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer() {
        let timer = Timer::start();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = timer.elapsed_ms();

        assert!(elapsed >= 10);
        assert!(elapsed < 100); // Should be close to 10ms
    }

    #[test]
    fn test_format_timestamp() {
        let ts = format_timestamp();

        // Should be ISO 8601 format
        assert!(ts.contains('T'));
        assert!(ts.contains('Z'));
        assert!(ts.len() >= 24);
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            timestamp: "2026-03-20T12:34:56.789Z".to_string(),
            event: AuditEvent::Create,
            instance_id: "test-instance".to_string(),
            claw_type: "picoclaw".to_string(),
            user: Some("admin".to_string()),
            outcome: AuditOutcome::Success,
            error: None,
            duration_ms: 1234,
            context: None,
        };

        let json = serde_json::to_string(&entry).unwrap();

        assert!(json.contains("\"event\":\"create\""));
        assert!(json.contains("\"outcome\":\"success\""));
    }

    #[test]
    fn test_audit_dir_macos() {
        #[cfg(target_os = "macos")]
        {
            let dir = audit_dir();
            let dir_str = dir.to_string_lossy();
            assert!(dir_str.contains("Library/Logs/theyos"));
        }

        #[cfg(not(target_os = "macos"))]
        {
            let dir = audit_dir();
            let dir_str = dir.to_string_lossy();
            assert!(dir_str.contains(".theyos/logs"));
        }
    }
}
