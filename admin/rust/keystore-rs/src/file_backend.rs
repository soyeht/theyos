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

    fn create_only(&self, account: &str, value: &[u8]) -> Result<(), KeystoreError> {
        let dir = self.secrets_dir();
        if let Err(e) = ensure_private_dir(&dir) {
            return Err(KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("create {}: {e}", dir.display()),
            });
        }
        let path = self.account_path(account);
        create_new_0600(&path, value).map_err(|e| {
            if e.kind() == ErrorKind::AlreadyExists {
                KeystoreError::Conflict {
                    label: format!("{} (file fallback)", path.display()),
                }
            } else {
                KeystoreError::Io {
                    kind: e.kind().to_string(),
                    hint: format!("create {}: {e}", path.display()),
                }
            }
        })
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

/// Create `final_path` with `bytes` iff it does not already exist. Returns
/// an `io::Error` with `kind() == AlreadyExists` when it does — that is the
/// conflict signal, not a real I/O failure.
///
/// Plain `tmp + rename` (as [`write_0600`] uses for `set`) is NOT create-only:
/// `rename(2)` silently replaces an existing destination. This instead
/// writes to a per-attempt, randomly-suffixed tmp file, then publishes with
/// `link(2)` (via [`fs::hard_link`]), which fails with `EEXIST` rather than
/// replacing when the destination is already there — genuine no-replace
/// atomicity, not a race window narrowed by convention.
fn create_new_0600(final_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = final_path
        .parent()
        .expect("account_path is always inside secrets_dir, which has a parent");

    let mut last_collision = None;
    for attempt in 0u32..8 {
        let tmp_path = tmp_attempt_path(final_path, attempt);
        match write_new_tmp_0600(&tmp_path, bytes) {
            Ok(()) => {
                let publish = fs::hard_link(&tmp_path, final_path);
                let _ = fs::remove_file(&tmp_path);
                return match publish {
                    // The entry now genuinely exists (the link landed) even
                    // if we can't prove the directory entry is durable —
                    // propagate the fsync failure instead of swallowing it,
                    // matching `write_0600`'s `?` below. A caller who sees
                    // this Err and retries will get a definitive answer:
                    // `Conflict` if the link already survived, another `Io`
                    // error otherwise. Silently returning `Ok(())` here would
                    // claim durability this function never actually proved.
                    Ok(()) => {
                        let dir = OpenOptions::new().read(true).open(parent)?;
                        dir.sync_all()?;
                        Ok(())
                    }
                    Err(e) => Err(e),
                };
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                // Our own randomized tmp name collided with a leftover or a
                // sibling attempt — vanishingly unlikely, just retry.
                last_collision = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            ErrorKind::AlreadyExists,
            "exhausted create-only tmp name attempts",
        )
    }))
}

/// Per-attempt tmp path for [`create_new_0600`]. Named per-attempt (not a
/// fixed `.tmp` suffix like [`write_0600`] uses) so two concurrent
/// `create_only` callers never contend on the same tmp file.
fn tmp_attempt_path(final_path: &Path, attempt: u32) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = final_path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}.{nanos}.{n}.{attempt}", std::process::id()));
    final_path.with_file_name(name)
}

#[cfg(unix)]
fn write_new_tmp_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    if let Err(e) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    if let Err(e) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_new_tmp_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(e) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    if let Err(e) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
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

    #[test]
    fn create_only_uses_owner_only_file_and_dir() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "household");
        ks.create_only("acct", b"secret-bytes").unwrap();

        let file = ks.path_for("acct");
        assert_eq!(mode_of(&file), 0o600, "create_only file must be owner-only");
        assert_eq!(
            mode_of(file.parent().unwrap()),
            0o700,
            "create_only must tighten the secrets dir too"
        );
        // No leftover per-attempt tmp files.
        let leftovers: Vec<_> = fs::read_dir(file.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "tmp attempt file not cleaned up: {leftovers:?}"
        );
    }

    #[test]
    fn create_only_never_overwrites_a_winner() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("create-only-conflict");

        ks.create_only(&account, b"first-writer-wins").unwrap();

        match ks.create_only(&account, b"second-writer-loses") {
            Err(KeystoreError::Conflict { label }) => {
                assert!(label.contains(&account), "label={label}");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }

        // The original value must be intact, not clobbered by the loser.
        assert_eq!(ks.get(&account).unwrap(), b"first-writer-wins");
    }

    #[test]
    fn create_only_succeeds_again_after_delete() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("create-only-recreate");

        ks.create_only(&account, b"v1").unwrap();
        ks.delete(&account).unwrap();
        ks.create_only(&account, b"v2").unwrap();

        assert_eq!(ks.get(&account).unwrap(), b"v2");
    }

    #[test]
    fn create_only_races_have_exactly_one_winner() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let td = tempfile::tempdir().unwrap();
        let ks = Arc::new(FileKeystore::new(td.path(), "svc"));
        let account = random_account("create-only-race");
        let workers = 8;
        let barrier = Arc::new(Barrier::new(workers));

        let handles: Vec<_> = (0..workers)
            .map(|i| {
                let ks = ks.clone();
                let account = account.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    ks.create_only(&account, format!("writer-{i}").as_bytes())
                        .is_ok()
                })
            })
            .collect();

        let wins = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(wins, 1, "exactly one concurrent create_only must win");
    }

    /// Random-suffixed account label so parallel test runs / repeated local
    /// runs never collide on shared on-disk state — same hygiene the
    /// `keys_se` test contract asks for, applied here to keystore-rs's own
    /// tests.
    fn random_account(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{prefix}.{}.{nanos}.{n}", std::process::id())
    }
}
