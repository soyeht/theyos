//! Maintenance mode state management.
//!
//! During maintenance (artifact sync, snapshot rebuild, etc.) the system
//! blocks new instance creation, pauses warm pool auto-fill, and exposes
//! status information to operators and the frontend.
//!
//! ## States
//!
//! ```text
//! Off → Draining → Active → Off
//! ```
//!
//! - **Off**: Normal operation. Creates allowed, warm pool fills.
//! - **Draining**: Transition state. Warm pool is being drained, in-flight
//!   creates can finish but no new creates start.
//! - **Active**: Maintenance in progress. Creates return 503 + Retry-After.
//!   Warm pool auto-fill is blocked.
//!
//! ## Persistence
//!
//! State is stored as a JSON file at `<locks_dir>/maintenance.json`.
//! A missing file means "off".  The file is written atomically.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Maintenance mode state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MaintenanceState {
    /// Normal operation.
    Off,
    /// Warm pool is draining; new creates will be rejected soon.
    Draining,
    /// Full maintenance. Creates return 503.
    Active,
}

impl std::fmt::Display for MaintenanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Draining => write!(f, "draining"),
            Self::Active => write!(f, "active"),
        }
    }
}

/// Maintenance mode status (persisted to disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceStatus {
    /// Current state.
    pub state: MaintenanceState,
    /// Human-readable reason (e.g. "artifact sync in progress").
    pub reason: String,
    /// ISO 8601 timestamp when maintenance started.
    pub started_at: String,
    /// Suggested retry delay in seconds for 503 responses.
    pub retry_after_secs: u32,
}

impl Default for MaintenanceStatus {
    fn default() -> Self {
        Self {
            state: MaintenanceState::Off,
            reason: String::new(),
            started_at: String::new(),
            retry_after_secs: 30,
        }
    }
}

/// Path to the maintenance state file.
#[must_use]
pub fn maintenance_file(locks_dir: &Path) -> PathBuf {
    locks_dir.join("maintenance.json")
}

/// Read the current maintenance status.
///
/// Returns `Off` status if the file doesn't exist or is malformed.
#[must_use]
pub fn read_status(locks_dir: &Path) -> MaintenanceStatus {
    let path = maintenance_file(locks_dir);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Check whether the system is in maintenance mode (draining or active).
#[must_use]
pub fn is_maintenance(locks_dir: &Path) -> bool {
    let status = read_status(locks_dir);
    status.state != MaintenanceState::Off
}

/// Check whether creates should be blocked (active maintenance only).
///
/// During `Draining`, in-flight creates can finish. During `Active`,
/// all new creates are rejected with 503.
#[must_use]
pub fn creates_blocked(locks_dir: &Path) -> bool {
    let status = read_status(locks_dir);
    status.state == MaintenanceState::Active
}

/// Enter maintenance mode.
///
/// Writes the maintenance status file atomically.
///
/// # Errors
///
/// Returns an error if the locks directory doesn't exist or the write fails.
pub fn enter_maintenance(
    locks_dir: &Path,
    state: MaintenanceState,
    reason: &str,
    retry_after_secs: u32,
) -> io::Result<()> {
    std::fs::create_dir_all(locks_dir)?;
    let status = MaintenanceStatus {
        state,
        reason: reason.to_string(),
        started_at: crate::time::now_iso_secs(),
        retry_after_secs,
    };
    let json = serde_json::to_string_pretty(&status).map_err(io::Error::other)?;
    let path = maintenance_file(locks_dir);
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json.as_bytes())?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Exit maintenance mode (remove the state file).
///
/// # Errors
///
/// Returns an error if the file removal fails (missing file is OK).
pub fn exit_maintenance(locks_dir: &Path) -> io::Result<()> {
    let path = maintenance_file(locks_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_status_is_off() {
        let status = MaintenanceStatus::default();
        assert_eq!(status.state, MaintenanceState::Off);
        assert!(status.reason.is_empty());
    }

    #[test]
    fn read_missing_file_returns_off() {
        let dir = tempfile::tempdir().unwrap();
        let status = read_status(dir.path());
        assert_eq!(status.state, MaintenanceState::Off);
    }

    #[test]
    fn enter_and_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        enter_maintenance(dir.path(), MaintenanceState::Active, "test sync", 60).unwrap();

        let status = read_status(dir.path());
        assert_eq!(status.state, MaintenanceState::Active);
        assert_eq!(status.reason, "test sync");
        assert_eq!(status.retry_after_secs, 60);
        assert!(!status.started_at.is_empty());
    }

    #[test]
    fn exit_clears_state() {
        let dir = tempfile::tempdir().unwrap();
        enter_maintenance(dir.path(), MaintenanceState::Active, "test", 30).unwrap();
        assert!(is_maintenance(dir.path()));

        exit_maintenance(dir.path()).unwrap();
        assert!(!is_maintenance(dir.path()));
        assert_eq!(read_status(dir.path()).state, MaintenanceState::Off);
    }

    #[test]
    fn exit_missing_file_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        assert!(exit_maintenance(dir.path()).is_ok());
    }

    #[test]
    fn is_maintenance_detects_draining() {
        let dir = tempfile::tempdir().unwrap();
        enter_maintenance(dir.path(), MaintenanceState::Draining, "draining", 30).unwrap();
        assert!(is_maintenance(dir.path()));
    }

    #[test]
    fn creates_blocked_only_in_active() {
        let dir = tempfile::tempdir().unwrap();

        // Off: not blocked
        assert!(!creates_blocked(dir.path()));

        // Draining: not blocked (in-flight can finish)
        enter_maintenance(dir.path(), MaintenanceState::Draining, "drain", 30).unwrap();
        assert!(!creates_blocked(dir.path()));

        // Active: blocked
        enter_maintenance(dir.path(), MaintenanceState::Active, "sync", 60).unwrap();
        assert!(creates_blocked(dir.path()));
    }

    #[test]
    fn state_display() {
        assert_eq!(MaintenanceState::Off.to_string(), "off");
        assert_eq!(MaintenanceState::Draining.to_string(), "draining");
        assert_eq!(MaintenanceState::Active.to_string(), "active");
    }

    #[test]
    fn overwrite_state_transitions() {
        let dir = tempfile::tempdir().unwrap();

        enter_maintenance(dir.path(), MaintenanceState::Draining, "step 1", 30).unwrap();
        assert_eq!(read_status(dir.path()).state, MaintenanceState::Draining);

        enter_maintenance(dir.path(), MaintenanceState::Active, "step 2", 60).unwrap();
        assert_eq!(read_status(dir.path()).state, MaintenanceState::Active);
        assert_eq!(read_status(dir.path()).reason, "step 2");
    }

    #[test]
    fn malformed_file_returns_off() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(maintenance_file(dir.path()), "not json").unwrap();
        assert_eq!(read_status(dir.path()).state, MaintenanceState::Off);
    }

    #[test]
    fn serde_round_trip() {
        let status = MaintenanceStatus {
            state: MaintenanceState::Active,
            reason: "artifact sync".into(),
            started_at: "2026-03-09T00:00:00Z".into(),
            retry_after_secs: 45,
        };
        let json = serde_json::to_string(&status).unwrap();
        let loaded: MaintenanceStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.state, MaintenanceState::Active);
        assert_eq!(loaded.reason, "artifact sync");
        assert_eq!(loaded.retry_after_secs, 45);
    }
}
