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

    /// Remove tmp files left behind by a [`KeystoreBackend::create_only`]
    /// call ([`KeystoreBackend`](crate::KeystoreBackend)) that crashed
    /// between installing its content and its own best-effort cleanup — the
    /// narrow window between `write_new_tmp_0600` succeeding and the
    /// `fs::remove_file` right after the `hard_link` attempt in
    /// `create_new_0600`. Those files hold the same plaintext bytes
    /// `create_only` was asked to store; they do not expire on their own.
    ///
    /// Deliberately NOT wired into `create_only`'s own hot path: a
    /// sweep-before-write step would race a genuinely concurrent sibling
    /// `create_only` call for the same account, deleting its in-flight tmp
    /// file out from under it (unlinking an open fd is safe on its own, but
    /// the sibling's subsequent `hard_link` would then fail against a
    /// source that no longer exists). Call this explicitly — e.g. once at
    /// startup, before any `create_only` traffic for this
    /// `(state_dir, service)` begins — not concurrently with live callers.
    ///
    /// Bounded to this keystore's own secrets directory (already `0700`,
    /// owner-only — nothing else can have planted a file there) and to
    /// names matching the exact tmp-attempt pattern `create_new_0600`
    /// produces (`<sanitized-account>.bin.tmp.<pid>.<nanos>.<n>.<attempt>`,
    /// all four trailing fields numeric); anything else, including a
    /// legitimate `<account>.bin` entry, is left untouched. Returns the
    /// number removed.
    pub fn sweep_orphaned_create_attempts(&self) -> std::io::Result<usize> {
        let dir = self.secrets_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let mut removed = 0usize;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if !is_orphaned_create_attempt_name(&name.to_string_lossy()) {
                continue;
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => removed += 1,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(removed)
    }
}

/// Matches exactly the names [`tmp_attempt_path`] produces: an original
/// `<account>.bin` final-path stem, followed by `.tmp.` and four numeric,
/// dot-separated fields (pid, nanos, counter, attempt). Deliberately strict
/// — a name that merely contains `.tmp.` somewhere is not enough, since an
/// account label could itself legitimately contain that substring.
fn is_orphaned_create_attempt_name(name: &str) -> bool {
    let Some((base, suffix)) = name.split_once(".tmp.") else {
        return false;
    };
    if Path::new(base).extension().and_then(|e| e.to_str()) != Some("bin") {
        return false;
    }
    let fields: Vec<&str> = suffix.split('.').collect();
    fields.len() == 4
        && fields
            .iter()
            .all(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
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
        match create_new_0600(&path, value) {
            Ok(CreateOutcome::Created) => Ok(()),
            Ok(CreateOutcome::AmbiguousDurability(e)) => Err(KeystoreError::AmbiguousDurability {
                label: format!("{} (file fallback)", path.display()),
                hint: format!("linked but parent-dir fsync unconfirmed: {e}"),
            }),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(KeystoreError::Conflict {
                label: format!("{} (file fallback)", path.display()),
            }),
            Err(e) => Err(KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("create {}: {e}", path.display()),
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

/// Result of a successful install attempt in [`create_new_0600`]. "Success"
/// at the syscall level splits into two cases that a caller must not
/// conflate: the link either landed *and* its durability was proven, or it
/// landed but the follow-up proof step failed/couldn't run. Only the first
/// is `Created`.
enum CreateOutcome {
    /// The link landed and the parent-directory fsync that proves it
    /// completed successfully.
    Created,
    /// The link landed but the parent-directory fsync failed or could not
    /// be attempted. The entry most likely exists; whether it would survive
    /// a crash before some future successful fsync is unproven.
    AmbiguousDurability(std::io::Error),
}

/// Create `final_path` with `bytes` iff it does not already exist.
///
/// - `Ok(Created)` / `Ok(AmbiguousDurability(_))` — the link syscall
///   installed the entry; see [`CreateOutcome`] for what distinguishes them.
/// - `Err(e)` with `e.kind() == AlreadyExists` — the link syscall itself
///   refused because the destination is already there. Nothing was
///   installed by this call.
/// - `Err(e)` otherwise — a real I/O failure; nothing was installed.
///
/// Plain `tmp + rename` (as [`write_0600`] uses for `set`) is NOT create-only:
/// `rename(2)` silently replaces an existing destination. This instead
/// writes to a per-attempt, randomly-suffixed tmp file, then publishes with
/// `link(2)` (via [`fs::hard_link`]), which fails with `EEXIST` rather than
/// replacing when the destination is already there — genuine no-replace
/// atomicity, not a race window narrowed by convention.
fn create_new_0600(final_path: &Path, bytes: &[u8]) -> std::io::Result<CreateOutcome> {
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
                    // The link landed — the entry genuinely exists now.
                    // Whether it survives a crash depends on this fsync,
                    // which we report distinctly instead of collapsing into
                    // an ordinary I/O failure: `Io` here would wrongly imply
                    // nothing was installed.
                    Ok(()) => match OpenOptions::new()
                        .read(true)
                        .open(parent)
                        .and_then(|dir| dir.sync_all())
                    {
                        Ok(()) => Ok(CreateOutcome::Created),
                        Err(e) => Ok(CreateOutcome::AmbiguousDurability(e)),
                    },
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

    #[test]
    fn orphaned_create_attempt_name_matcher_is_exact() {
        assert!(is_orphaned_create_attempt_name(
            "llm.api_key.anthropic.bin.tmp.1234.567890123.7.0"
        ));
        // A real, non-orphaned entry must never match.
        assert!(!is_orphaned_create_attempt_name(
            "llm.api_key.anthropic.bin"
        ));
        // Wrong field count / non-numeric fields must not match.
        assert!(!is_orphaned_create_attempt_name("acct.bin.tmp.1234.567"));
        assert!(!is_orphaned_create_attempt_name("acct.bin.tmp.a.b.c.d"));
        // Merely containing the substring, without the required `.bin`
        // stem right before it, must not match — an account label could
        // legitimately contain `.tmp.` itself.
        assert!(!is_orphaned_create_attempt_name("weird.tmp.1.2.3.4"));
        // set()'s own tmp file (fixed `.bin.tmp` suffix, no per-attempt
        // fields) must not match either — sweeping is scoped to
        // create_only's orphans only, not write_0600's.
        assert!(!is_orphaned_create_attempt_name("acct.bin.tmp"));
    }

    #[test]
    fn sweep_removes_only_orphaned_create_attempts() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("sweep");

        // A real, live entry that must survive the sweep.
        ks.create_only(&account, b"real-value").unwrap();

        // Simulate what a crash between write_new_tmp_0600 succeeding and
        // its own cleanup would leave behind: a tmp file matching the exact
        // pattern create_new_0600 produces, containing secret bytes.
        let orphan = ks.path_for(&account).with_file_name(format!(
            "{}.bin.tmp.99999.123456789.0.0",
            sanitize_path_segment(&account)
        ));
        fs::write(&orphan, b"leaked-plaintext-from-a-crash").unwrap();

        // An unrelated file in the same directory must also survive.
        let unrelated = ks.path_for(&account).with_file_name("unrelated.bin");
        fs::write(&unrelated, b"not ours").unwrap();

        let removed = ks.sweep_orphaned_create_attempts().unwrap();
        assert_eq!(removed, 1, "must remove exactly the one orphan");

        assert!(!orphan.exists(), "orphaned tmp file must be gone");
        assert!(unrelated.exists(), "unrelated file must be untouched");
        assert_eq!(
            ks.get(&account).unwrap(),
            b"real-value",
            "the real entry must be untouched"
        );
    }

    #[test]
    fn sweep_on_missing_dir_is_a_noop() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc-never-written-to");
        assert_eq!(ks.sweep_orphaned_create_attempts().unwrap(), 0);
    }
}
