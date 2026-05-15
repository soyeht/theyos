//! `verify_results.json` — persisted verify-status for detected claws.
//!
//! `claws-verify` records the outcome of each end-to-end verification run
//! against a discarded sandbox VM.  The same file is read by
//! `store::catalog_with_status` to surface verify state in the catalog API.
//!
//! Concurrent `claws-verify` runs serialise on a `flock(2)` over a sibling
//! `.lock` file (path + ".lock") so the JSON is never partially written.
//!
//! Layout (relative to `THEYOS_DIR`):
//!   `claws/verify-results.json`
//!
//! Schema:
//! ```json
//! {
//!   "picoclaw": {
//!     "verify_status": "ok",
//!     "verify_error": null,
//!     "verify_log_path": "artifacts/verify/picoclaw-2026-04-14T12-00-00Z.log",
//!     "verify_attempted_at": "2026-04-14T12:00:00Z"
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// Verification status for a single claw.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VerifyStatus {
    Pending,
    Ok,
    Failed,
}

impl std::fmt::Display for VerifyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Ok => write!(f, "ok"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// A single verify-result record.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VerifyResult {
    pub verify_status: VerifyStatus,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verify_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verify_log_path: Option<String>,
    /// ISO-8601 UTC seconds.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub verify_attempted_at: Option<String>,
}

/// Errors for the verify-results store.
#[derive(Debug, thiserror::Error)]
pub enum VerifyResultsError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("flock failed: {0}")]
    Flock(String),
}

/// Load the full verify-results map.  Returns an empty map if the file does not exist.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be parsed.
pub fn load(path: &Path) -> Result<HashMap<String, VerifyResult>, VerifyResultsError> {
    if !path.is_file() {
        return Ok(HashMap::new());
    }
    let content = fs::read_to_string(path)?;
    if content.trim().is_empty() {
        return Ok(HashMap::new());
    }
    let map: HashMap<String, VerifyResult> = serde_json::from_str(&content)?;
    Ok(map)
}

/// Fetch the record for `claw`, if any.
///
/// # Errors
///
/// Propagates errors from [`load`].
pub fn get(path: &Path, claw: &str) -> Result<Option<VerifyResult>, VerifyResultsError> {
    let map = load(path)?;
    Ok(map.get(claw).cloned())
}

/// Atomically record a verify-result for `claw`.
///
/// Uses `flock(LOCK_EX)` on `<path>.lock` so concurrent `claws-verify`
/// processes cannot clobber each other's updates.  The JSON file itself is
/// written via write-rename for crash safety.
///
/// # Errors
///
/// Returns an error if the lock cannot be acquired, the file cannot be
/// read/written, or the JSON cannot be serialised.
pub fn record(path: &Path, claw: &str, result: &VerifyResult) -> Result<(), VerifyResultsError> {
    // Ensure the parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // flock on sibling .lock file — we don't want to hold a lock on the JSON
    // itself while we rewrite it (that would confuse the atomic rename).
    let lock_path = sibling_lock_path(path);
    let lock_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    flock_exclusive(&lock_file)?;

    // Read-modify-write.
    let mut map = load(path)?;
    map.insert(claw.to_string(), result.clone());

    let json = serde_json::to_string_pretty(&map)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, format!("{json}\n"))?;
    fs::rename(&tmp, path)?;

    // flock is released when `lock_file` is dropped.
    drop(lock_file);
    Ok(())
}

fn sibling_lock_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

fn flock_exclusive(file: &File) -> Result<(), VerifyResultsError> {
    let fd = file.as_raw_fd();
    #[allow(unsafe_code)]
    // SAFETY: `fd` is a valid file descriptor owned by `file` for the
    // duration of this call; `libc::flock` has well-defined behavior for
    // valid fds.
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
    if ret != 0 {
        return Err(VerifyResultsError::Flock(
            io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_missing_file_returns_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-results.json");
        let map = load(&path).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn load_empty_file_returns_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-results.json");
        fs::write(&path, "").unwrap();
        let map = load(&path).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn record_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-results.json");
        let result = VerifyResult {
            verify_status: VerifyStatus::Ok,
            verify_error: None,
            verify_log_path: Some("artifacts/verify/picoclaw.log".into()),
            verify_attempted_at: Some("2026-04-14T12:00:00Z".into()),
        };
        record(&path, "picoclaw", &result).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.get("picoclaw"), Some(&result));
    }

    #[test]
    fn record_preserves_previous_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-results.json");

        let ok = VerifyResult {
            verify_status: VerifyStatus::Ok,
            verify_error: None,
            verify_log_path: None,
            verify_attempted_at: Some("2026-04-14T10:00:00Z".into()),
        };
        record(&path, "picoclaw", &ok).unwrap();

        let failed = VerifyResult {
            verify_status: VerifyStatus::Failed,
            verify_error: Some("healthcheck failed".into()),
            verify_log_path: None,
            verify_attempted_at: Some("2026-04-14T11:00:00Z".into()),
        };
        record(&path, "zeroclaw", &failed).unwrap();

        let map = load(&path).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("picoclaw"), Some(&ok));
        assert_eq!(map.get("zeroclaw"), Some(&failed));
    }

    #[test]
    fn record_overwrites_existing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-results.json");

        let pending = VerifyResult {
            verify_status: VerifyStatus::Pending,
            verify_error: None,
            verify_log_path: None,
            verify_attempted_at: None,
        };
        record(&path, "picoclaw", &pending).unwrap();

        let ok = VerifyResult {
            verify_status: VerifyStatus::Ok,
            verify_error: None,
            verify_log_path: None,
            verify_attempted_at: Some("2026-04-14T12:00:00Z".into()),
        };
        record(&path, "picoclaw", &ok).unwrap();

        let loaded = get(&path, "picoclaw").unwrap();
        assert_eq!(
            loaded.as_ref().map(|r| r.verify_status),
            Some(VerifyStatus::Ok)
        );
    }

    #[test]
    fn get_returns_none_for_missing_claw() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-results.json");
        assert!(get(&path, "nonexistent").unwrap().is_none());
    }

    #[test]
    fn status_roundtrips_json() {
        let r = VerifyResult {
            verify_status: VerifyStatus::Failed,
            verify_error: Some("boom".into()),
            verify_log_path: None,
            verify_attempted_at: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"failed\""));
        let back: VerifyResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn atomic_write_leaves_valid_json_after_crash_of_tmp_rename() {
        // Ensure the final file is valid JSON (not the temp file).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verify-results.json");
        let ok = VerifyResult {
            verify_status: VerifyStatus::Ok,
            verify_error: None,
            verify_log_path: None,
            verify_attempted_at: None,
        };
        record(&path, "picoclaw", &ok).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let parsed: HashMap<String, VerifyResult> =
            serde_json::from_str(&content).expect("final file must be valid JSON");
        assert!(parsed.contains_key("picoclaw"));
        // The .tmp file must be gone after the rename.
        assert!(!path.with_extension("json.tmp").exists());
    }
}
