//! Encrypted-at-rest-by-OS file fallback for the keystore.
//!
//! Used in two scenarios:
//!
//! 1. Hosts without an accessible OS keystore (macOS without a login keychain,
//!    Linux without Secret Service / kernel keyring, CI runners).
//! 2. The household crate's `THEYOS_FORCE_SOFTWARE_KEYS=1` opt-in path for
//!    pre-T2 Intel Macs that have no Secure Enclave.
//!
//! Files live at `<state_dir>/secrets/<service>/<account>.bin` with mode `0600`
//! and atomic writes (tmp file + rename + parent fsync). Best-effort against
//! crashes; not designed to withstand a hostile root user — that's what the OS
//! keystore is for.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use crate::{KeystoreBackend, KeystoreError};

/// A keystore backed by `0600` files under a state directory.
///
/// Each backend instance is bound to one `(state_dir, service)` pair; accounts
/// live as separate files inside that directory so concurrent reads to
/// different accounts don't contend.
#[derive(Debug, Clone)]
pub struct FileKeystore {
    state_dir: PathBuf,
    service: String,
}

impl FileKeystore {
    /// Build a file-backed keystore rooted at `state_dir`, scoped to
    /// `service`. Distinct services share `state_dir` but get distinct
    /// subdirectories — this is what lets one host's file fallback hold
    /// household secrets AND LLM API keys without colliding.
    #[must_use]
    pub fn new(state_dir: impl AsRef<Path>, service: impl Into<String>) -> Self {
        Self {
            state_dir: state_dir.as_ref().to_path_buf(),
            service: service.into(),
        }
    }

    fn secrets_dir(&self) -> PathBuf {
        self.state_dir
            .join("secrets")
            .join(sanitize_path_segment(&self.service))
    }

    fn account_path(&self, account: &str) -> PathBuf {
        self.secrets_dir()
            .join(format!("{}.bin", sanitize_path_segment(account)))
    }

    /// Path the backend WOULD write to for `account`. Exposed for tests and
    /// for callers that need to surface the on-disk location in error
    /// messages.
    #[must_use]
    pub fn path_for(&self, account: &str) -> PathBuf {
        self.account_path(account)
    }
}

impl KeystoreBackend for FileKeystore {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeystoreError> {
        let path = self.account_path(account);
        let mut file = match OpenOptions::new().read(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(KeystoreError::NotFound {
                    label: format!("{} (file fallback)", path.display()),
                });
            }
            Err(e) => {
                return Err(KeystoreError::Io {
                    kind: e.kind().to_string(),
                    hint: format!("open {}: {e}", path.display()),
                });
            }
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("read {}: {e}", path.display()),
            })?;
        Ok(bytes)
    }

    fn set(&self, account: &str, value: &[u8]) -> Result<(), KeystoreError> {
        let dir = self.secrets_dir();
        if let Err(e) = fs::create_dir_all(&dir) {
            return Err(KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("create {}: {e}", dir.display()),
            });
        }
        let path = self.account_path(account);
        write_0600(&path, value).map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("write {}: {e}", path.display()),
        })?;
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<(), KeystoreError> {
        let path = self.account_path(account);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("delete {}: {e}", path.display()),
            }),
        }
    }
}

/// Sanitise a value used as a path segment so it stays inside the secrets
/// directory regardless of what the caller hands in. Replaces directory
/// separators and `..` traversal attempts with `_`.
fn sanitize_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '/' | '\\' | '\0' => out.push('_'),
            _ => out.push(ch),
        }
    }
    if out == ".." || out == "." {
        out.insert(0, '_');
    }
    out
}

#[cfg(unix)]
fn write_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp_path = path.with_extension("bin.tmp");
    match fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)?;
    if let Err(e) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Err(e) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(file);
    fs::rename(&tmp_path, path)?;
    if let Some(parent) = path.parent() {
        let dir = OpenOptions::new().read(true).open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // Non-Unix hosts can't enforce `0600` — they get standard ACL writes plus
    // the atomic rename. theyOS does not currently target Windows, but the
    // file fallback is harmless either way.
    let tmp_path = path.with_extension("bin.tmp");
    match fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)?;
    if let Err(e) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Err(e) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(file);
    fs::rename(&tmp_path, path)?;
    Ok(())
}
