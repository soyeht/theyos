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
        if let Err(e) = ensure_private_dir(&dir) {
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

/// Create `dir` if missing and, on unix, restrict it to owner-only `0o700`.
/// Idempotent: also tightens an already-existing directory whose mode is more
/// permissive, repairing dirs created under a looser umask before this guard
/// existed. The files inside are already `0o600`; this stops the secrets
/// directory from being listable by other local users (which would leak the
/// account names stored there).
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dir)?.permissions();
        if perms.mode() & 0o777 != 0o700 {
            perms.set_mode(0o700);
            fs::set_permissions(dir, perms)?;
        }
    }
    Ok(())
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn set_uses_owner_only_file_and_dir() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "household");
        ks.set("acct", b"secret-bytes").unwrap();

        let file = ks.path_for("acct");
        assert_eq!(mode_of(&file), 0o600, "secret file must be owner-only");
        assert_eq!(
            mode_of(file.parent().unwrap()),
            0o700,
            "secrets dir must be owner-only (not listable by other local users)"
        );
    }

    #[test]
    fn set_tightens_preexisting_loose_dir() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "household");
        let dir = ks.path_for("acct").parent().unwrap().to_path_buf();
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();

        ks.set("acct", b"secret-bytes").unwrap();

        assert_eq!(
            mode_of(&dir),
            0o700,
            "a pre-existing permissive secrets dir must be tightened on write"
        );
    }

    #[test]
    fn set_get_round_trip() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        ks.set("a", b"hello world").unwrap();
        assert_eq!(ks.get("a").unwrap(), b"hello world");
    }
}
