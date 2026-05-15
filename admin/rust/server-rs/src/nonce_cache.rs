//! T078 — Teardown nonce replay cache.
//!
//! Stores single-use 32-byte nonces in `<state_dir>/recent-nonces/` as
//! plain files (`<nonce_hex> → creation_unix_seconds`). Nonces are retained
//! for 24 hours; after that they expire and the slot is freed on the next
//! cleanup pass.
//!
//! ## Atomicity
//!
//! `check_and_persist` uses `OpenOptions::create_new(true)` which is atomic on
//! POSIX: exactly one concurrent caller succeeds; others see `AlreadyExists`.
//!
//! ## Eviction
//!
//! `evict_expired` removes files older than 24 h. `evict_oldest_if_over_limit`
//! enforces the 100 k entry cap by removing the oldest (by mtime) entries.
//! Call both periodically; the teardown handler calls them opportunistically
//! after a successful persist.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

const TTL_SECS: u64 = 24 * 3600;
const MAX_ENTRIES: usize = 100_000;
const NONCE_DIR: &str = "recent-nonces";

#[derive(Debug)]
pub enum NonceError {
    AlreadyUsed,
    Io(io::Error),
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyUsed => write!(f, "nonce already used (replay)"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

fn nonce_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(NONCE_DIR)
}

fn nonce_path(state_dir: &Path, nonce: &[u8; 32]) -> PathBuf {
    nonce_dir(state_dir).join(hex::encode(nonce))
}

/// Check that `nonce` has not been used within the last 24 h, then atomically
/// persist it. Returns `Err(AlreadyUsed)` on replay.
pub fn check_and_persist(state_dir: &Path, nonce: &[u8; 32], now_unix: u64) -> Result<(), NonceError> {
    let dir = nonce_dir(state_dir);
    fs::create_dir_all(&dir).map_err(NonceError::Io)?;

    let path = nonce_path(state_dir, nonce);

    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);

    match opts.open(&path) {
        Ok(mut f) => {
            let ts = now_unix.to_string();
            f.write_all(ts.as_bytes()).map_err(NonceError::Io)?;
            f.sync_all().map_err(NonceError::Io)?;
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // File exists — replay unless it's expired (> 24h old).
            // For security, we treat presence as replay regardless of age;
            // the TTL only governs when evict_expired cleans them up.
            let _ = now_unix;
            Err(NonceError::AlreadyUsed)
        }
        Err(e) => Err(NonceError::Io(e)),
    }
}

/// Remove nonce files older than [`TTL_SECS`]. Call opportunistically.
pub fn evict_expired(state_dir: &Path, now_unix: u64) {
    let dir = nonce_dir(state_dir);
    let Ok(entries) = fs::read_dir(&dir) else { return };
    let cutoff = now_unix.saturating_sub(TTL_SECS);
    for entry in entries.flatten() {
        if let Ok(content) = fs::read_to_string(entry.path()) {
            if let Ok(ts) = content.trim().parse::<u64>() {
                if ts < cutoff {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

/// Enforce the 100 k entry cap by removing oldest-mtime files above the limit.
pub fn evict_oldest_if_over_limit(state_dir: &Path) {
    let dir = nonce_dir(state_dir);
    let Ok(entries) = fs::read_dir(&dir) else { return };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let mtime = e.metadata().ok()?.modified().ok()?;
            Some((mtime, e.path()))
        })
        .collect();
    if files.len() <= MAX_ENTRIES {
        return;
    }
    files.sort_unstable_by_key(|(t, _)| *t);
    for (_, path) in &files[..files.len() - MAX_ENTRIES] {
        let _ = fs::remove_file(path);
    }
}

/// Combined opportunistic cleanup — call after a successful persist.
pub fn cleanup(state_dir: &Path, now_unix: u64) {
    evict_expired(state_dir, now_unix);
    evict_oldest_if_over_limit(state_dir);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn first_nonce_accepted() {
        let dir = tmp();
        let nonce = [0x01u8; 32];
        assert!(check_and_persist(dir.path(), &nonce, 1000).is_ok());
    }

    #[test]
    fn second_nonce_replay() {
        let dir = tmp();
        let nonce = [0x02u8; 32];
        check_and_persist(dir.path(), &nonce, 1000).unwrap();
        let result = check_and_persist(dir.path(), &nonce, 1001);
        assert!(matches!(result, Err(NonceError::AlreadyUsed)));
    }

    #[test]
    fn different_nonces_both_accepted() {
        let dir = tmp();
        let n1 = [0x03u8; 32];
        let n2 = [0x04u8; 32];
        check_and_persist(dir.path(), &n1, 1000).unwrap();
        check_and_persist(dir.path(), &n2, 1001).unwrap();
    }

    #[test]
    fn evict_expired_removes_old_entries() {
        let dir = tmp();
        let nonce = [0x05u8; 32];
        check_and_persist(dir.path(), &nonce, 1000).unwrap();
        // Simulate time passing beyond TTL.
        evict_expired(dir.path(), 1000 + TTL_SECS + 1);
        // Now the same nonce can be inserted again (file is gone).
        assert!(check_and_persist(dir.path(), &nonce, 2000).is_ok());
    }

    #[test]
    fn evict_within_ttl_does_not_remove() {
        let dir = tmp();
        let nonce = [0x06u8; 32];
        check_and_persist(dir.path(), &nonce, 1000).unwrap();
        evict_expired(dir.path(), 1000 + TTL_SECS - 1);
        // Still present → replay.
        assert!(matches!(
            check_and_persist(dir.path(), &nonce, 1500),
            Err(NonceError::AlreadyUsed)
        ));
    }
}
