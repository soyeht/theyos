//! Encrypted-at-rest-by-OS file fallback for the keystore.
//!
//! Used in two scenarios:
//!
//! 1. Hosts without an accessible OS keystore (macOS without a login keychain,
//!    Linux without Secret Service / kernel keyring, CI runners).
//! 2. The household crate's `THEYOS_FORCE_SOFTWARE_KEYS=1` opt-in path for
//!    pre-T2 Intel Macs that have no Secure Enclave.
//!
//! Files live at `<state_dir>/secrets/<service>/<account>.bin` with mode `0600`.
//! `set` uses tmp+rename+parent-fsync (best-effort against crashes, not
//! create-only). `create_only` uses a stronger, race-free protocol — see its
//! doc comment on [`KeystoreBackend`] and [`CreateOutcome`] for what it
//! proves. Neither is designed to withstand a hostile root user — that's
//! what the OS keystore is for.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use crate::{CreateOutcome, KeystoreBackend, KeystoreError};

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

    /// Create the secrets directory hierarchy if missing, level by level,
    /// fsyncing the parent of each level THIS call actually creates (a level
    /// that already existed gets no fsync from us — we didn't create it, so
    /// we owe no durability proof for it). `fs::create_dir_all` creates every
    /// missing level in a single call with no such per-level proof, which
    /// leaves open the question "did the directory itself survive a crash
    /// right after first use." Also (re-)tightens the final directory to
    /// `0700`, same as before.
    ///
    /// `pub(crate)` — used directly by [`crate::tpm_backend::TpmKeystore`],
    /// which shares this file-backed install path but must not go through
    /// [`KeystoreBackend::create_only`] on `self` (see that impl's docs on
    /// why: this backend's own byte-for-byte comparison is wrong for TPM's
    /// randomized ciphertext).
    pub(crate) fn ensure_dir(&self) -> std::io::Result<()> {
        ensure_private_dir_leveled(&self.state_dir, &self.secrets_dir())
    }

    /// Attempt to install `bytes` under `account`, iff absent. Does NOT
    /// reinspect on ambiguity/conflict — see [`Self::stabilize_and_classify`]
    /// for that. Exposed `pub(crate)` for the same reason as
    /// [`Self::ensure_dir`].
    pub(crate) fn raw_attempt_install(
        &self,
        account: &str,
        bytes: &[u8],
    ) -> std::io::Result<InstallOutcome> {
        attempt_install(&self.account_path(account), bytes)
    }

    /// Reinspect `account` through the same `O_NOFOLLOW` + fstat-validated
    /// path `create_only` itself uses, hand its raw bytes to `compare` (TPM
    /// needs to decrypt before it can judge "same value"; this backend's own
    /// [`Self::stabilize_and_classify`] compares them directly), and on a
    /// match, prove durability against the EXACT inode just read — not a
    /// fresh path lookup, which would reopen the very TOCTOU window this
    /// exists to close: an intervening delete+recreate at the same path
    /// between "compare" and "fsync" would otherwise let this fsync (and
    /// the parent-dir fsync that follows it) apply to a completely
    /// different file than the one whose content was actually verified.
    ///
    /// After the parent-dir fsync (which only proves SOME directory entry
    /// at this path is durable now, not which inode it is), a final
    /// `dev`+`ino` comparison against the originally-opened fd confirms no
    /// substitution happened in that last window either — anything else
    /// downgrades to [`CreateOutcome::MayHaveTakenEffect`] rather than
    /// claiming a durability proof for content that may not be the content
    /// actually compared.
    ///
    /// `pub(crate)` so [`crate::tpm_backend::TpmKeystore`] can compose it
    /// with its own decrypt-and-compare `compare` closure, getting the same
    /// held-fd guarantee TPM's own [`InstallOutcome`] delegation already
    /// gets from [`Self::raw_attempt_install`].
    pub(crate) fn reinspect_and_stabilize(
        &self,
        account: &str,
        compare: impl FnOnce(&[u8]) -> Result<bool, KeystoreError>,
    ) -> Result<CreateOutcome, KeystoreError> {
        let path = self.account_path(account);
        match secure_open_regular_nofollow(&path) {
            Ok(SecureOpen::Found(mut file, held_meta)) => {
                let mut bytes = Vec::new();
                if file.read_to_end(&mut bytes).is_err() {
                    return Ok(CreateOutcome::MayHaveTakenEffect);
                }
                if !compare(&bytes)? {
                    return Ok(CreateOutcome::Conflict);
                }
                if file.sync_all().is_err() {
                    return Ok(CreateOutcome::MayHaveTakenEffect);
                }
                if sync_parent_dir(&path).is_err() {
                    return Ok(CreateOutcome::MayHaveTakenEffect);
                }
                match fs::symlink_metadata(&path) {
                    Ok(now_meta) if same_inode(&held_meta, &now_meta) => {
                        Ok(CreateOutcome::ExistingExactDurable)
                    }
                    _ => Ok(CreateOutcome::MayHaveTakenEffect),
                }
            }
            Ok(SecureOpen::NotFound) => Ok(CreateOutcome::KnownNoEffect),
            // A security violation is never downgraded to "ambiguous, just
            // retry" — that would quietly swallow a symlink/ownership
            // problem behind a retry loop instead of surfacing it.
            Ok(SecureOpen::SecurityViolation(hint)) => Err(KeystoreError::SecurityViolation {
                label: format!("{} (file fallback)", path.display()),
                hint,
            }),
            Err(_) => Ok(CreateOutcome::MayHaveTakenEffect),
        }
    }

    /// Reinspect-and-classify step for [`KeystoreBackend::create_only`]'s
    /// own byte-for-byte comparison, via [`Self::reinspect_and_stabilize`].
    fn stabilize_and_classify(
        &self,
        account: &str,
        expected: &[u8],
    ) -> Result<CreateOutcome, KeystoreError> {
        self.reinspect_and_stabilize(account, |bytes| Ok(bytes == expected))
    }

    /// Remove tmp files left behind by a [`KeystoreBackend::create_only`]
    /// call that crashed between installing its content and its own
    /// best-effort cleanup. Those files hold the same plaintext bytes
    /// `create_only` was asked to store; they do not expire on their own.
    ///
    /// Deliberately NOT wired into `create_only`'s own hot path: a
    /// sweep-before-write step would race a genuinely concurrent sibling
    /// `create_only` call for the same account, deleting its in-flight tmp
    /// file out from under it. Call this explicitly — e.g. once at startup,
    /// under whatever exclusion the caller uses to guarantee no concurrent
    /// `create_only` traffic for this `(state_dir, service)` is in flight —
    /// not concurrently with live callers.
    ///
    /// Bounded to this keystore's own secrets directory (already `0700`,
    /// owner-only) and to names matching the exact tmp-attempt pattern
    /// [`tmp_attempt_path`] produces, parsed structurally from the end of
    /// the name (not by searching for a substring that could coincidentally
    /// appear inside an account label). Each candidate's actual content is
    /// re-hashed and compared against the digest embedded in its own name;
    /// a mismatch (a partial/corrupted write) is logged and still removed —
    /// it is not legitimate recoverable state either way, and leaving it
    /// keeps whatever secret-shaped bytes it holds on disk indefinitely.
    /// Returns the number removed; fsyncs the directory once at the end if
    /// anything was removed, so the sweep's own effect is itself durable.
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
            let name = name.to_string_lossy();
            let Some(parsed) = parse_create_attempt_tmp_name(&name) else {
                continue;
            };
            let path = entry.path();
            if let Ok(content) = fs::read(&path) {
                let final_path = dir.join(format!("{}.bin", parsed.stem));
                if content_digest_hex(&final_path, &content) != parsed.digest {
                    tracing::warn!(
                        name = %name,
                        "orphaned create-only tmp file's content does not match its own \
                         name's digest (partial/corrupted write) — removing anyway"
                    );
                }
            }
            match fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if removed > 0 {
            let _ = OpenOptions::new()
                .read(true)
                .open(&dir)
                .and_then(|d| d.sync_all());
        }
        Ok(removed)
    }
}

/// Structural parse of a name [`tmp_attempt_path`] could have produced:
/// `<stem>.bin.tmp.<pid>.<nanos>.<counter>.<attempt>.<digest16hex>`. Parses
/// from the END with a fixed, known field count rather than searching
/// forward for a `.tmp.` substring — an account label (hence `<stem>`) can
/// legitimately contain literal dots, `tmp`, `bin`, or digit runs, so a
/// forward substring search is not reliable; counting a fixed number of
/// trailing fields is.
struct ParsedTmpName {
    stem: String,
    digest: String,
}

fn parse_create_attempt_tmp_name(name: &str) -> Option<ParsedTmpName> {
    let parts: Vec<&str> = name.split('.').collect();
    // stem-parts... , "bin", "tmp", pid, nanos, counter, attempt, digest
    //                  ^ index len-7            ^ 4 numeric fields  ^ len-1
    if parts.len() < 8 {
        return None;
    }
    let digest = parts[parts.len() - 1];
    let numeric_fields = &parts[parts.len() - 5..parts.len() - 1];
    let tmp_marker = parts[parts.len() - 6];
    let bin_marker = parts[parts.len() - 7];
    if bin_marker != "bin" || tmp_marker != "tmp" {
        return None;
    }
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if !numeric_fields
        .iter()
        .all(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let stem = parts[..parts.len() - 6].join(".");
    if stem.is_empty() {
        return None;
    }
    Some(ParsedTmpName {
        stem,
        digest: digest.to_string(),
    })
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
        if let Err(e) = self.ensure_dir() {
            let dir = self.secrets_dir();
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

    /// See [`CreateOutcome`] for the full outcome contract. In short: on
    /// anything other than a clean, durability-proven install, this
    /// reinspects the CURRENT on-disk state (through the same
    /// O_NOFOLLOW/fstat-validated path, comparing bytes directly and
    /// re-proving durability fresh) rather than trusting the install
    /// attempt's own ambiguous result — that reinspection is what turns "the
    /// link syscall errored" into a real answer instead of a guess.
    fn create_only(&self, account: &str, value: &[u8]) -> Result<CreateOutcome, KeystoreError> {
        if let Err(e) = self.ensure_dir() {
            let dir = self.secrets_dir();
            return Err(KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("create {}: {e}", dir.display()),
            });
        }
        match self.raw_attempt_install(account, value) {
            Ok(InstallOutcome::Durable) => Ok(CreateOutcome::CreatedDurable),
            // Ambiguous, proven-conflict, AND pre-publish failures all fall
            // through to the same reinspection: whatever the reason we
            // can't trust the install attempt's own verdict, the actual
            // on-disk state is the only thing worth trusting, and it
            // resolves all three cases correctly on its own (including the
            // rare tmp-name-exhaustion case, which used to be misreported
            // as a destination Conflict even though nothing was installed —
            // reinspection here now correctly reports KnownNoEffect for it
            // instead, since final_path was never actually touched).
            Ok(InstallOutcome::Ambiguous(e)) => {
                tracing::debug!(error = %e, account, "create_only install ambiguous, reinspecting");
                self.stabilize_and_classify(account, value)
            }
            Ok(InstallOutcome::ProvenConflict) | Err(_) => {
                self.stabilize_and_classify(account, value)
            }
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

/// Create `dir` if missing, one path component at a time (like
/// `fs::create_dir_all`, so an entirely-missing `base` with multiple missing
/// ancestor levels above it still gets created — first-time setup of a
/// fresh `state_dir` is a real, supported case, not just the common repeat
/// case). Fsyncs the parent of each level AT OR BELOW `base` — including
/// when `create_dir` returns `AlreadyExists`, not only when it actually
/// created that level: a level that "already exists" is only proven to
/// survive a crash if SOME fsync of its parent has actually completed; if
/// the create that first produced it crashed before its own fsync finished,
/// the level is visible via cache/on-disk-but-unsynced-metadata without ever
/// having been durably proven, and a retry that trusted "already exists" as
/// proof would repeat exactly the visibility-is-not-durability mistake
/// `create_only` itself exists to avoid at the file level.
///
/// Levels ABOVE `base` (the caller's `state_dir`) are created if genuinely
/// missing but NOT fsynced by this call — `base` is the caller's own
/// pre-existing directory tree; this crate has no durability obligation for
/// it, and walking/fsyncing every ancestor up to the filesystem root on
/// every call (the common case, once everything already exists) would be
/// pure waste for levels we don't own.
fn ensure_private_dir_leveled(base: &Path, dir: &Path) -> std::io::Result<()> {
    let mut built = PathBuf::new();
    for component in dir.components() {
        built.push(component);
        if let Err(e) = fs::create_dir(&built) {
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(e);
            }
        }
        if built.starts_with(base) {
            if let Some(parent) = built.parent() {
                let d = OpenOptions::new().read(true).open(parent)?;
                d.sync_all()?;
            }
        }
    }
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

/// Result of [`attempt_install`]'s own syscall-level attempt, BEFORE any
/// reinspection. `pub(crate)` — TPM matches on this directly (see
/// [`FileKeystore::raw_attempt_install`]).
pub(crate) enum InstallOutcome {
    /// The link landed and the parent-directory fsync that proves it
    /// completed successfully.
    Durable,
    /// The link's own result does not unambiguously prove "nothing
    /// happened": either it landed but the follow-up durability fsync
    /// failed, or the link syscall itself returned an error OTHER than the
    /// well-defined "destination already exists" — a syscall failure does
    /// not generally prove its effect didn't land (e.g. a response can be
    /// lost after the operation already completed server-side on some
    /// filesystems), so this is the conservative default for anything that
    /// isn't a clean success or a clean, well-defined conflict.
    Ambiguous(std::io::Error),
    /// The link syscall refused with the well-defined "destination already
    /// exists" error. This alone does not distinguish "someone else's
    /// value" from "my own prior attempt already won" — that needs
    /// reinspection too, which is why this still isn't a final answer by
    /// itself.
    ProvenConflict,
}

/// Attempt to install `bytes` at `final_path` iff absent, returning
/// [`InstallOutcome`]. A pre-publish `Err` (failed before ever attempting to
/// publish, e.g. couldn't even write the private scratch file) is the one
/// case that's provably "nothing happened to `final_path`" — but callers
/// still reinspect rather than trust that inference blindly, since
/// `final_path` could independently already hold unrelated prior state.
///
/// Plain `tmp + rename` (as [`write_0600`] uses for `set`) is NOT create-only:
/// `rename(2)` silently replaces an existing destination. This instead
/// writes to a per-attempt tmp file bound to `(account, content-digest,
/// attempt)` — see [`tmp_attempt_path`] — then publishes with `link(2)` (via
/// [`fs::hard_link`]), which fails with `EEXIST` rather than replacing when
/// the destination is already there. The tmp file is NOT deleted until
/// after the outcome is classified (durable vs. ambiguous vs. conflict) —
/// deleting it eagerly, before that classification, would discard the one
/// place this call's own candidate bytes live if it turns out we need to
/// reason about them.
fn attempt_install(final_path: &Path, bytes: &[u8]) -> std::io::Result<InstallOutcome> {
    let mut last_collision = None;
    for attempt in 0u32..8 {
        let tmp_path = tmp_attempt_path(final_path, bytes, attempt);
        match write_new_tmp_0600(&tmp_path, bytes) {
            Ok(()) => {
                let publish = publish_link_override(fs::hard_link(&tmp_path, final_path));
                let outcome = match publish {
                    Ok(()) => match sync_parent_dir(final_path) {
                        Ok(()) => InstallOutcome::Durable,
                        Err(e) => InstallOutcome::Ambiguous(e),
                    },
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                        InstallOutcome::ProvenConflict
                    }
                    Err(e) => InstallOutcome::Ambiguous(e),
                };
                if !cleanup_armed() {
                    let _ = fs::remove_file(&tmp_path);
                }
                return Ok(outcome);
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                // Our own randomized tmp name collided with a leftover or a
                // sibling attempt — vanishingly unlikely, just retry.
                last_collision = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    // Exhausting 8 randomized, counter-uniqued tmp names is not "a real
    // destination conflict happened" — it's an anomaly (this crate's own
    // per-process atomic counter alone should make a same-process collision
    // impossible; 8 in a row is not something ordinary operation produces).
    // The caller's own reinspection resolves this correctly either way (see
    // `create_only`'s dispatch — this Err falls through to
    // `stabilize_and_classify` the same as any other non-durable install
    // outcome), but it's worth a loud diagnostic since it means something
    // about the tmp-naming assumptions themselves may be wrong on this host.
    tracing::warn!(
        path = %final_path.display(),
        "create_only exhausted all 8 tmp-name attempts — this should be \
         unreachable under normal operation; investigate clock/pid/counter \
         assumptions on this host"
    );
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            ErrorKind::AlreadyExists,
            "exhausted create-only tmp name attempts",
        )
    }))
}

/// Per-attempt tmp path for [`attempt_install`], bound to
/// `(account, content-digest, attempt)` rather than just opaque
/// pid/nanos/counter fields — this is what lets
/// [`FileKeystore::sweep_orphaned_create_attempts`] verify a found orphan's
/// content actually matches what its own name claims, instead of trusting
/// the name pattern alone.
fn tmp_attempt_path(final_path: &Path, bytes: &[u8], attempt: u32) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let digest = content_digest_hex(final_path, bytes);
    let mut name = final_path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(
        ".tmp.{}.{nanos}.{n}.{attempt}.{digest}",
        std::process::id()
    ));
    final_path.with_file_name(name)
}

/// Full 256-bit BLAKE3 fingerprint of `(final_path, bytes)`, binding an
/// orphaned tmp file's name to its own content for recovery/sweep to verify
/// against. Note on what this binding is and isn't: the trust boundary this
/// crate actually relies on is the `0700` secrets directory (a
/// same-privilege-level actor with read/write access there could read/write
/// the real target files directly regardless of any naming scheme, same as
/// any other file in that directory) — this digest's job is to let recovery
/// distinguish "this tmp file's content genuinely matches what its name
/// claims" from "this is a stray/corrupted/partial write", not to
/// authenticate across a privilege boundary that doesn't otherwise exist
/// here.
fn content_digest_hex(final_path: &Path, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(final_path.to_string_lossy().as_bytes());
    hasher.update(&[0u8]);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

#[cfg(unix)]
fn write_new_tmp_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(e) = write_tmp_failpoint() {
        return Err(e);
    }
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
    if let Some(e) = write_tmp_failpoint() {
        return Err(e);
    }
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

fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .expect("account_path is always inside secrets_dir, which has a parent");
    if let Some(e) = open_parent_failpoint() {
        return Err(e);
    }
    let dir = OpenOptions::new().read(true).open(parent)?;
    if let Some(e) = fsync_parent_failpoint() {
        return Err(e);
    }
    dir.sync_all()
}

/// Result of [`secure_open_regular_nofollow`]. `Found` carries the
/// [`std::fs::Metadata`] from the SAME `fstat` the security check itself
/// performed, so a caller that later needs to confirm "is this still the
/// same file" doesn't need a second, separately-racy stat call.
enum SecureOpen {
    Found(File, std::fs::Metadata),
    NotFound,
    /// Something is at this path this backend itself would never have
    /// produced: a symlink, a non-regular file, or a mode/owner mismatch.
    SecurityViolation(String),
}

/// `true` iff `a` and `b` refer to the same inode on the same device —
/// dev+ino identity, not path equality. Used to confirm a directory entry
/// re-observed after a fsync still points at the exact file whose content
/// was compared, not a substitution that landed at the same path in the
/// interim.
#[cfg(unix)]
fn same_inode(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}
#[cfg(not(unix))]
fn same_inode(_a: &std::fs::Metadata, _b: &std::fs::Metadata) -> bool {
    // No stable cross-platform dev+ino equivalent in std; this path is
    // already best-effort on non-unix (see secure_open_regular_nofollow's
    // non-unix variant, which has no O_NOFOLLOW/mode/owner checks either).
    true
}

/// Open `path` for reading with `O_NOFOLLOW` (refuse to follow a symlink at
/// the final path component) and validate, via `fstat` on the resulting fd
/// (not a second path lookup — no TOCTOU window between check and open),
/// that it is a regular file, mode `0600`, owned by this process's effective
/// uid. Used by every reinspection this module does, so a symlink swap or a
/// planted file with the wrong owner/mode is refused rather than silently
/// read through.
#[cfg(unix)]
#[allow(unsafe_code)]
fn secure_open_regular_nofollow(path: &Path) -> std::io::Result<SecureOpen> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => {
            let meta = file.metadata()?;
            if !meta.file_type().is_file() {
                return Ok(SecureOpen::SecurityViolation(format!(
                    "expected a regular file, found {:?}",
                    meta.file_type()
                )));
            }
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                return Ok(SecureOpen::SecurityViolation(format!(
                    "expected mode 0600, found {mode:o}"
                )));
            }
            // SAFETY: geteuid() takes no arguments and cannot fail; it is a
            // pure syscall wrapper with no preconditions on the caller.
            let euid = unsafe { libc::geteuid() };
            if meta.uid() != euid {
                return Ok(SecureOpen::SecurityViolation(format!(
                    "expected owner uid {euid}, found {}",
                    meta.uid()
                )));
            }
            Ok(SecureOpen::Found(file, meta))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(SecureOpen::NotFound),
        // O_NOFOLLOW makes the open itself fail with ELOOP when the final
        // component is a symlink — that IS the security violation we want
        // to fail closed on, not silently treat as absence.
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Ok(SecureOpen::SecurityViolation(
            format!("refusing to follow a symlink at {}", path.display()),
        )),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
fn secure_open_regular_nofollow(path: &Path) -> std::io::Result<SecureOpen> {
    match OpenOptions::new().read(true).open(path) {
        Ok(file) => {
            let meta = file.metadata()?;
            Ok(SecureOpen::Found(file, meta))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(SecureOpen::NotFound),
        Err(e) => Err(e),
    }
}

// Deterministic, in-process fault injection for the five points identified
// as needing it: the tmp file's own write, the publish/link syscall, opening
// the parent directory, fsyncing it, and the tmp file's post-install
// cleanup. Thread-local (not a single global `static`) so parallel tests
// (the default `cargo test` mode) never see each other's armed failpoints.
// No child process, no pipe, no shelling out — the injected `io::Error` and
// its `ErrorKind` are the same values production code already branches on,
// so a test's assertions exercise the real classification logic, not a
// simulation of it.
#[cfg(test)]
mod failpoints {
    use std::cell::Cell;
    use std::io;

    thread_local! {
        static WRITE_TMP: Cell<Option<io::ErrorKind>> = const { Cell::new(None) };
        static PUBLISH_LINK: Cell<Option<io::ErrorKind>> = const { Cell::new(None) };
        static OPEN_PARENT: Cell<Option<io::ErrorKind>> = const { Cell::new(None) };
        static FSYNC_PARENT: Cell<Option<io::ErrorKind>> = const { Cell::new(None) };
        static CLEANUP_SKIP: Cell<bool> = const { Cell::new(false) };
    }

    // All five failpoints are STICKY: `arm_*` stays in effect for every
    // subsequent check on this thread until the matching `disarm_*` call,
    // not just the next one. A one-shot (consume-on-read) design was tried
    // first and was wrong: `sync_parent_dir` is legitimately invoked TWICE
    // within a single `create_only` call whenever the install step is
    // ambiguous (once from the install attempt itself, once more from
    // `stabilize_and_classify`'s `reinspect_and_stabilize` fallback) — a
    // one-shot failpoint got consumed by the first of those two internal
    // calls, so the second one silently succeeded for real and the whole
    // top-level call self-healed to a durable outcome before ever returning,
    // which is correct production behavior but made it impossible to
    // deterministically simulate "this durability barrier stays down across
    // a whole retry sequence" — exactly the scenario the test matrix needs
    // exact (not `A | B`) assertions for.

    pub(crate) fn arm_write_tmp(kind: io::ErrorKind) {
        WRITE_TMP.with(|c| c.set(Some(kind)));
    }
    pub(crate) fn disarm_write_tmp() {
        WRITE_TMP.with(|c| c.set(None));
    }
    pub(crate) fn peek_write_tmp() -> Option<io::ErrorKind> {
        WRITE_TMP.with(Cell::get)
    }

    /// While armed, EVERY `fs::hard_link` call on this thread has its result
    /// DISCARDED and replaced with the injected error regardless of whether
    /// the real link actually succeeded — faithfully simulating "the
    /// operation landed but we were told it failed" (e.g. a lost response),
    /// not merely "the operation never ran."
    pub(crate) fn arm_publish_link(kind: io::ErrorKind) {
        PUBLISH_LINK.with(|c| c.set(Some(kind)));
    }
    pub(crate) fn disarm_publish_link() {
        PUBLISH_LINK.with(|c| c.set(None));
    }
    pub(crate) fn peek_publish_link() -> Option<io::ErrorKind> {
        PUBLISH_LINK.with(Cell::get)
    }

    pub(crate) fn arm_open_parent(kind: io::ErrorKind) {
        OPEN_PARENT.with(|c| c.set(Some(kind)));
    }
    pub(crate) fn disarm_open_parent() {
        OPEN_PARENT.with(|c| c.set(None));
    }
    pub(crate) fn peek_open_parent() -> Option<io::ErrorKind> {
        OPEN_PARENT.with(Cell::get)
    }

    pub(crate) fn arm_fsync_parent(kind: io::ErrorKind) {
        FSYNC_PARENT.with(|c| c.set(Some(kind)));
    }
    pub(crate) fn disarm_fsync_parent() {
        FSYNC_PARENT.with(|c| c.set(None));
    }
    pub(crate) fn peek_fsync_parent() -> Option<io::ErrorKind> {
        FSYNC_PARENT.with(Cell::get)
    }

    /// While armed, EVERY `attempt_install` call on this thread skips its
    /// own tmp-file cleanup entirely, simulating a crash between install and
    /// cleanup — the exact window
    /// [`super::FileKeystore::sweep_orphaned_create_attempts`] exists for.
    pub(crate) fn arm_cleanup_skip() {
        CLEANUP_SKIP.with(|c| c.set(true));
    }
    pub(crate) fn disarm_cleanup_skip() {
        CLEANUP_SKIP.with(|c| c.set(false));
    }
    pub(crate) fn peek_cleanup_skip() -> bool {
        CLEANUP_SKIP.with(Cell::get)
    }
}

#[cfg(test)]
fn write_tmp_failpoint() -> Option<std::io::Error> {
    failpoints::peek_write_tmp().map(|k| std::io::Error::new(k, "injected failpoint: write/tmp"))
}
#[cfg(not(test))]
fn write_tmp_failpoint() -> Option<std::io::Error> {
    None
}

#[cfg(test)]
fn publish_link_override(real: std::io::Result<()>) -> std::io::Result<()> {
    match failpoints::peek_publish_link() {
        Some(k) => Err(std::io::Error::new(k, "injected failpoint: publish/link")),
        None => real,
    }
}
#[cfg(not(test))]
fn publish_link_override(real: std::io::Result<()>) -> std::io::Result<()> {
    real
}

#[cfg(test)]
fn open_parent_failpoint() -> Option<std::io::Error> {
    failpoints::peek_open_parent()
        .map(|k| std::io::Error::new(k, "injected failpoint: open-parent"))
}
#[cfg(not(test))]
fn open_parent_failpoint() -> Option<std::io::Error> {
    None
}

#[cfg(test)]
fn fsync_parent_failpoint() -> Option<std::io::Error> {
    failpoints::peek_fsync_parent()
        .map(|k| std::io::Error::new(k, "injected failpoint: fsync-parent"))
}
#[cfg(not(test))]
fn fsync_parent_failpoint() -> Option<std::io::Error> {
    None
}

#[cfg(test)]
fn cleanup_armed() -> bool {
    failpoints::peek_cleanup_skip()
}
#[cfg(not(test))]
fn cleanup_armed() -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
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
        assert_eq!(
            ks.create_only("acct", b"secret-bytes").unwrap(),
            CreateOutcome::CreatedDurable
        );

        let file = ks.path_for("acct");
        assert_eq!(mode_of(&file), 0o600, "create_only file must be owner-only");
        assert_eq!(
            mode_of(file.parent().unwrap()),
            0o700,
            "create_only must tighten the secrets dir too"
        );
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
    fn create_only_different_value_is_conflict_and_leaves_winner_intact() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("create-only-conflict");

        assert_eq!(
            ks.create_only(&account, b"first-writer-wins").unwrap(),
            CreateOutcome::CreatedDurable
        );
        assert_eq!(
            ks.create_only(&account, b"second-writer-loses").unwrap(),
            CreateOutcome::Conflict
        );
        assert_eq!(ks.get(&account).unwrap(), b"first-writer-wins");
    }

    #[test]
    fn create_only_same_value_retry_converges_to_existing_exact_durable() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("create-only-idempotent-retry");

        assert_eq!(
            ks.create_only(&account, b"same-bytes").unwrap(),
            CreateOutcome::CreatedDurable
        );
        // A caller retrying create_only with the SAME bytes (e.g. because it
        // crashed before observing the first call's own return value) must
        // land on ExistingExactDurable, not Conflict — it's re-observing its
        // own value, not colliding with someone else's.
        assert_eq!(
            ks.create_only(&account, b"same-bytes").unwrap(),
            CreateOutcome::ExistingExactDurable
        );
    }

    #[test]
    fn create_only_succeeds_again_after_delete() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("create-only-recreate");

        ks.create_only(&account, b"v1").unwrap();
        ks.delete(&account).unwrap();
        assert_eq!(
            ks.create_only(&account, b"v2").unwrap(),
            CreateOutcome::CreatedDurable
        );
        assert_eq!(ks.get(&account).unwrap(), b"v2");
    }

    #[test]
    fn create_only_concurrent_same_value_all_converge_durable_no_split_brain() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let td = tempfile::tempdir().unwrap();
        let ks = Arc::new(FileKeystore::new(td.path(), "svc"));
        let account = random_account("create-only-race-same");
        let workers = 8;
        let barrier = Arc::new(Barrier::new(workers));

        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let ks = ks.clone();
                let account = account.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    ks.create_only(&account, b"identical-value").unwrap()
                })
            })
            .collect();

        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == CreateOutcome::CreatedDurable)
                .count(),
            1,
            "exactly one racer installs"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == CreateOutcome::ExistingExactDurable)
                .count(),
            workers - 1,
            "every other racer re-observes the SAME value as durable, not a conflict"
        );
        assert_eq!(ks.get(&account).unwrap(), b"identical-value");
    }

    #[test]
    fn create_only_concurrent_different_values_exactly_one_winner_rest_conflict() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let td = tempfile::tempdir().unwrap();
        let ks = Arc::new(FileKeystore::new(td.path(), "svc"));
        let account = random_account("create-only-race-diff");
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
                        .unwrap()
                })
            })
            .collect();

        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == CreateOutcome::CreatedDurable)
                .count(),
            1,
            "exactly one racer installs"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == CreateOutcome::Conflict)
                .count(),
            workers - 1,
            "every other racer with DIFFERENT bytes sees a real conflict"
        );
    }

    /// Disarms a failpoint on drop — guaranteed even on assertion panic
    /// (unwind), which matters because `cargo test`'s default thread pool
    /// can run a LATER test on the SAME OS thread, and the failpoints are
    /// thread-locals: a leaked armed failpoint would make an unrelated test
    /// flaky depending on scheduling, not depending on what that test
    /// itself does.
    struct FailpointGuard(fn());
    impl Drop for FailpointGuard {
        fn drop(&mut self) {
            (self.0)();
        }
    }

    #[test]
    fn failpoint_write_tmp_yields_known_no_effect() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-write-tmp");
        let _guard = FailpointGuard(failpoints::disarm_write_tmp);

        failpoints::arm_write_tmp(ErrorKind::PermissionDenied);
        assert_eq!(
            ks.create_only(&account, b"never-written").unwrap(),
            CreateOutcome::KnownNoEffect,
            "a pre-publish failure must resolve to KnownNoEffect via reinspection"
        );
        assert!(matches!(
            ks.get(&account),
            Err(KeystoreError::NotFound { .. })
        ));
    }

    #[test]
    fn failpoint_publish_link_reports_error_but_real_link_landed_and_converges() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-publish-link");
        let _guard = FailpointGuard(failpoints::disarm_publish_link);

        failpoints::arm_publish_link(ErrorKind::TimedOut);
        // The real hard_link call still runs (the override only replaces
        // the RESULT we see) — the entry genuinely exists after this call.
        // Durability proof (`reinspect_and_stabilize`, used by the stabilize
        // fallback this ambiguous install falls through to) syncs the
        // already-open file directly; it does not go through `fs::hard_link`
        // at all, so it is NOT affected by this failpoint even while armed —
        // the outcome is deterministically ExistingExactDurable on THIS
        // call already, not merely "eventually after a retry".
        assert_eq!(
            ks.create_only(&account, b"actually-landed").unwrap(),
            CreateOutcome::ExistingExactDurable,
            "publish/link being told it failed must not block the independent \
             durability proof the stabilize fallback performs"
        );
        assert_eq!(
            ks.create_only(&account, b"actually-landed").unwrap(),
            CreateOutcome::ExistingExactDurable,
            "still armed: repeat calls with the same bytes keep converging"
        );
    }

    #[test]
    fn failpoint_publish_link_different_retry_value_is_conflict_not_ambiguous_forever() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-publish-link-diff-retry");
        let _guard = FailpointGuard(failpoints::disarm_publish_link);

        failpoints::arm_publish_link(ErrorKind::TimedOut);
        let _ = ks.create_only(&account, b"original-value").unwrap();

        // A caller that (incorrectly) retries with DIFFERENT bytes after an
        // ambiguous outcome must see a real Conflict, not another ambiguous
        // result — the original value already won and is durable, and the
        // mismatch is provable regardless of this failpoint still being
        // armed (reinspection's content comparison doesn't call hard_link).
        assert_eq!(
            ks.create_only(&account, b"different-value").unwrap(),
            CreateOutcome::Conflict
        );
        assert_eq!(ks.get(&account).unwrap(), b"original-value");
    }

    #[test]
    fn failpoint_open_parent_yields_ambiguous_then_retry_converges() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-open-parent");
        let _guard = FailpointGuard(failpoints::disarm_open_parent);

        failpoints::arm_open_parent(ErrorKind::PermissionDenied);
        // Sticky: this failpoint fires on BOTH the install attempt's own
        // durability check AND the stabilize fallback's independent
        // `reinspect_and_stabilize` re-proof, so the whole call stays
        // ambiguous — it does not self-heal within one call.
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::MayHaveTakenEffect
        );
        failpoints::disarm_open_parent();
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::ExistingExactDurable,
            "once the barrier clears, a same-bytes retry must converge deterministically"
        );
    }

    #[test]
    fn failpoint_fsync_parent_yields_ambiguous_then_retry_converges() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-fsync-parent");
        let _guard = FailpointGuard(failpoints::disarm_fsync_parent);

        failpoints::arm_fsync_parent(ErrorKind::Other);
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::MayHaveTakenEffect
        );
        failpoints::disarm_fsync_parent();
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::ExistingExactDurable
        );
    }

    #[test]
    fn failpoint_cleanup_skip_simulates_crash_marker_and_sweep_recovers() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-cleanup-crash-marker");
        let _guard = FailpointGuard(failpoints::disarm_cleanup_skip);

        failpoints::arm_cleanup_skip();
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::CreatedDurable
        );

        let dir = ks.path_for(&account).parent().unwrap().to_path_buf();
        let leftover: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert_eq!(
            leftover.len(),
            1,
            "simulated crash must leave exactly one marker"
        );

        let removed = ks.sweep_orphaned_create_attempts().unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            ks.get(&account).unwrap(),
            b"value",
            "the real, durable entry must survive the sweep untouched"
        );
    }

    #[test]
    fn symlink_at_final_path_fails_closed_as_security_violation() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("symlink-swap");

        ks.ensure_dir().unwrap();
        let final_path = ks.path_for(&account);
        let elsewhere = td.path().join("elsewhere.bin");
        fs::write(&elsewhere, b"attacker-controlled").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &final_path).unwrap();

        match ks.create_only(&account, b"value") {
            Err(KeystoreError::SecurityViolation { .. }) => {}
            other => panic!("expected SecurityViolation, got {other:?}"),
        }
        // The symlink target must be untouched — we must never have
        // followed it.
        assert_eq!(fs::read(&elsewhere).unwrap(), b"attacker-controlled");
    }

    #[test]
    fn orphaned_create_attempt_name_matcher_is_exact() {
        let digest = content_digest_hex(Path::new("/tmp/x/llm.api_key.anthropic.bin"), b"v");
        assert!(
            parse_create_attempt_tmp_name(&format!(
                "llm.api_key.anthropic.bin.tmp.1234.567890123.7.0.{digest}"
            ))
            .is_some()
        );
        assert!(parse_create_attempt_tmp_name("llm.api_key.anthropic.bin").is_none());
        assert!(
            parse_create_attempt_tmp_name(&format!("acct.bin.tmp.1234.567.{digest}")).is_none()
        );
        assert!(parse_create_attempt_tmp_name(&format!("acct.bin.tmp.a.b.c.d.{digest}")).is_none());
        assert!(parse_create_attempt_tmp_name(&format!("weird.tmp.1.2.3.4.{digest}")).is_none());
        assert!(parse_create_attempt_tmp_name("acct.bin.tmp").is_none());
        // Wrong digest length/charset.
        assert!(parse_create_attempt_tmp_name("acct.bin.tmp.1.2.3.4.short").is_none());
    }

    #[test]
    fn sweep_removes_only_orphaned_create_attempts() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("sweep");

        ks.create_only(&account, b"real-value").unwrap();

        let final_path = ks.path_for(&account);
        let stem = sanitize_path_segment(&account);
        let digest = content_digest_hex(&final_path, b"leaked-plaintext-from-a-crash");
        let orphan =
            final_path.with_file_name(format!("{stem}.bin.tmp.99999.123456789.0.0.{digest}"));
        fs::write(&orphan, b"leaked-plaintext-from-a-crash").unwrap();

        let unrelated = final_path.with_file_name("unrelated.bin");
        fs::write(&unrelated, b"not ours").unwrap();

        let removed = ks.sweep_orphaned_create_attempts().unwrap();
        assert_eq!(removed, 1, "must remove exactly the one orphan");

        assert!(!orphan.exists(), "orphaned tmp file must be gone");
        assert!(unrelated.exists(), "unrelated file must be untouched");
        assert_eq!(ks.get(&account).unwrap(), b"real-value");
    }

    #[test]
    fn sweep_removes_orphan_with_mismatched_digest_too() {
        // A partially-written/corrupted tmp file (content doesn't match its
        // own name's digest) is still garbage that must not linger — the
        // digest is a diagnostic, not a gate on cleanup.
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("sweep-mismatch");
        ks.ensure_dir().unwrap();

        let final_path = ks.path_for(&account);
        let stem = sanitize_path_segment(&account);
        let orphan =
            final_path.with_file_name(format!("{stem}.bin.tmp.1.2.3.4.{}", "0".repeat(64)));
        fs::write(&orphan, b"corrupted").unwrap();

        assert_eq!(ks.sweep_orphaned_create_attempts().unwrap(), 1);
        assert!(!orphan.exists());
    }

    #[test]
    fn sweep_on_missing_dir_is_a_noop() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc-never-written-to");
        assert_eq!(ks.sweep_orphaned_create_attempts().unwrap(), 0);
    }

    #[test]
    fn ensure_dir_leveled_creates_nested_missing_hierarchy() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path().join("does/not/exist/yet"), "svc");
        ks.ensure_dir().unwrap();
        assert_eq!(mode_of(ks.path_for("acct").parent().unwrap()), 0o700);
    }

    /// Regression test for the "`AlreadyExists` skips the fsync entirely"
    /// gap: a retry that finds a level already present must still attempt
    /// to (re-)prove its parent durable, not treat visibility as proof.
    /// Proven behaviorally (no dedicated failpoint for directory-level
    /// fsync exists) by making the parent unreadable between calls — if the
    /// `AlreadyExists` path really does attempt `open+sync_all` on retry,
    /// the second call must fail; the pre-fix code silently skipped that
    /// attempt and would have returned `Ok(())` here instead.
    #[test]
    fn ensure_dir_retry_on_already_existing_level_still_attempts_parent_fsync() {
        let td = tempfile::tempdir().unwrap();
        let state_dir = td.path().join("state");
        let ks = FileKeystore::new(&state_dir, "svc");
        ks.ensure_dir().unwrap();

        // Lock down state_dir (the parent of the "secrets" level) so any
        // attempt to open it for the retry's fsync fails.
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o000)).unwrap();
        let result = ks.ensure_dir();
        // Restore permissions unconditionally before asserting, so a
        // failure here doesn't leave an unreadable directory behind for
        // the tempdir's own cleanup to trip over.
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            result.is_err(),
            "AlreadyExists path must still attempt (and here, fail) the parent fsync, \
             not silently skip it and report Ok"
        );
    }
}
