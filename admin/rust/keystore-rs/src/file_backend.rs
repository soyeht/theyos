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
//!
//! [`KeystoreBackend::get`]/[`set`](KeystoreBackend::set)/[`delete`](KeystoreBackend::delete)
//! are the original path-based, best-effort API and are unchanged.
//! [`KeystoreBackend::create_only`] is a stronger, race-free protocol that
//! makes an explicit durability claim ([`CreateOutcome`]), and everything it
//! does is fd-relative:
//!
//! - The `<state_dir>` "base" is opened once, following symlinks — it is the
//!   caller's own path and the caller is entitled to point us through a
//!   symlink (`/tmp` → `/private/tmp` on macOS is exactly this).
//! - Every component BELOW the base — `secrets`, `<service>` — is descended
//!   with `openat(O_DIRECTORY | O_NOFOLLOW)`, and every subsequent operation
//!   (create the scratch file, publish it with `linkat`, `unlinkat` it,
//!   reopen it, `fsync` the directory) is issued against the retained
//!   directory fd. There is no second path lookup anywhere in the protocol,
//!   so a symlink or directory swapped in at ANY level after the descent
//!   cannot redirect a later step.
//! - The filesystem under that directory fd is checked against an allowlist
//!   ([`fs_gate`]) before the first mutation, because "an `fsync` here means
//!   the bytes survive a reboot" is a claim only some filesystems actually
//!   honour.
//!
//! None of this is designed to withstand a hostile *root* user — that's what
//! the OS keystore is for.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::{CreateOutcome, KeystoreBackend, KeystoreError};

#[cfg(unix)]
use std::ffi::{CString, OsStr};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

/// Basename of the sidecar lock file that serialises
/// [`FileKeystore::sweep_orphaned_create_attempts`] against in-flight
/// `create_only` calls. Lives inside the secrets directory; deliberately
/// shaped so [`parse_create_attempt_tmp_name`] can never match it, so the
/// sweep can never remove its own lock.
#[cfg(unix)]
const LOCK_FILE_NAME: &str = ".create-only.lock";

/// Upper bound on how many bytes any single secret read will buffer.
///
/// A secret this crate stores is an API key, token, or key scalar — kilobytes
/// at most. The cap exists so a file that is unexpectedly enormous (corrupt,
/// or something else entirely that happens to sit at this path) cannot be
/// pulled wholesale into memory before anything has had a chance to reject
/// it.
const MAX_SECRET_BYTES: u64 = 1 << 20;

/// A keystore backed by `0600` files under a state directory.
///
/// Each backend instance is bound to one `(state_dir, service)` pair; accounts
/// live as separate files inside that directory so concurrent reads to
/// different accounts don't contend.
#[derive(Debug, Clone)]
pub struct FileKeystore {
    state_dir: PathBuf,
    service: String,
    /// Whether this handle is permitted to touch the crate-reserved
    /// namespace. Only [`Self::new_for_reserved_namespace`] sets it, and
    /// that is `pub(crate)`.
    reserved_access: bool,
}

/// Service-name marker reserving a namespace for this crate's own opaque
/// key material.
///
/// Nothing outside this crate may read or write under it. Note what this
/// does and does not buy: it stops a downstream crate from reaching opaque
/// key material through the ordinary byte API — by accident, by refactor,
/// or by deliberately reconstructing the coordinates — because every
/// operation on a reserved service from a publicly-constructed handle fails
/// closed. It does NOT defend against code in this same process and uid
/// that goes around the crate entirely (reading the files directly, or
/// attaching a debugger). That boundary is the filesystem's and the OS's,
/// not this type's, and pretending otherwise would be the same
/// overclaim as calling a missing accessor "containment".
pub const RESERVED_OPAQUE_NAMESPACE_MARKER: &str = ".p256-opaque-v1";

/// `true` when `service` lies inside the crate-reserved namespace.
#[must_use]
pub fn is_reserved_namespace(service: &str) -> bool {
    service.contains(RESERVED_OPAQUE_NAMESPACE_MARKER)
}

impl FileKeystore {
    /// Build a file-backed keystore rooted at `state_dir`, scoped to
    /// `service`. Distinct services share `state_dir` but get distinct
    /// subdirectories — this is what lets one host's file fallback hold
    /// household secrets AND LLM API keys without colliding.
    ///
    /// A handle built here can never operate on the crate-reserved opaque
    /// namespace: every operation checks and refuses. Construction itself
    /// stays infallible so existing callers are unaffected.
    #[must_use]
    pub fn new(state_dir: impl AsRef<Path>, service: impl Into<String>) -> Self {
        Self {
            state_dir: state_dir.as_ref().to_path_buf(),
            service: service.into(),
            reserved_access: false,
        }
    }

    /// Build a handle permitted to operate inside the crate-reserved
    /// namespace. `pub(crate)` — this is the capability that
    /// [`crate::opaque_p256`] holds and no downstream can obtain.
    pub(crate) fn new_for_reserved_namespace(
        state_dir: impl AsRef<Path>,
        service: impl Into<String>,
    ) -> Self {
        Self {
            state_dir: state_dir.as_ref().to_path_buf(),
            service: service.into(),
            reserved_access: true,
        }
    }

    /// Fail closed when a publicly-constructed handle is pointed at the
    /// reserved namespace. Called by EVERY operation rather than only the
    /// constructor, so reconstructing the coordinates after the fact does
    /// not help either.
    fn guard_reserved(&self) -> Result<(), KeystoreError> {
        if self.reserved_access || !is_reserved_namespace(&self.service) {
            return Ok(());
        }
        Err(KeystoreError::Unsupported {
            hint: format!(
                "service {:?} is inside the namespace reserved for keystore-rs's own opaque \
                 key material; it is not reachable through the generic byte API",
                self.service
            ),
        })
    }

    fn secrets_dir(&self) -> PathBuf {
        self.state_dir
            .join("secrets")
            .join(sanitize_path_segment(&self.service))
    }

    fn account_file_name(account: &str) -> String {
        format!("{}.bin", sanitize_path_segment(account))
    }

    fn account_path(&self, account: &str) -> PathBuf {
        self.secrets_dir().join(Self::account_file_name(account))
    }

    /// Path the backend WOULD write to for `account`. Exposed for tests and
    /// for callers that need to surface the on-disk location in error
    /// messages.
    #[must_use]
    pub fn path_for(&self, account: &str) -> PathBuf {
        self.account_path(account)
    }
}

// ---------------------------------------------------------------------------
// Unix: the fd-relative create_only protocol.
// ---------------------------------------------------------------------------

#[cfg(unix)]
impl FileKeystore {
    /// Open (creating if needed) the secrets directory and return a retained
    /// directory fd for it.
    ///
    /// The `state_dir` base is created with `create_dir_all` and opened
    /// FOLLOWING symlinks: it is the caller's own directory tree, this crate
    /// did not create it, and a caller is entitled to hand us a path that
    /// legitimately traverses a symlink. From there each component we DO own
    /// (`secrets`, `<service>`) is created with `mkdirat` and descended with
    /// `openat(O_DIRECTORY | O_NOFOLLOW)` relative to the fd above it, so a
    /// symlink planted at either of those levels fails the descent instead of
    /// silently redirecting every later operation.
    ///
    /// The parent of each owned level is `fsync`ed UNCONDITIONALLY — including
    /// when `mkdirat` reports `AlreadyExists`, not only when this call created
    /// it. A level that "already exists" is proven to survive a crash only if
    /// some `fsync` of its parent actually completed; if the `mkdirat` that
    /// first produced it crashed before its own `fsync`, the level is visible
    /// without ever having been made durable, and a retry that treated
    /// "already exists" as proof would repeat exactly the
    /// visibility-is-not-durability mistake `create_only` exists to avoid at
    /// the file level.
    fn open_secrets_dir(&self) -> std::io::Result<DirHandle> {
        create_ancestors_durably(&self.state_dir)?;
        let mut dir = DirHandle::open_base(&self.state_dir)?;

        let service_segment = sanitize_path_segment(&self.service);
        for name in [OsStr::new("secrets"), OsStr::new(&service_segment)] {
            match dir.mkdirat(name, 0o700) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            dir.fsync_unhooked()?;
            dir = dir.openat_dir_nofollow(name)?;
        }
        // Idempotently tighten the leaf, repairing a directory created under
        // a looser umask before this guard existed. `fchmod` on the retained
        // fd, not `set_permissions` on a path — same no-relookup rule.
        dir.fchmod(0o700)?;
        Ok(dir)
    }

    /// Open the secrets directory and confirm its filesystem is one whose
    /// `fsync` semantics this crate is willing to make durability claims
    /// about. Fails closed BEFORE any mutation. Exposed `pub(crate)` so
    /// [`crate::tpm_backend::TpmKeystore`] can run it before paying for an
    /// encryption it might not be allowed to persist.
    // Used by the Linux-only `tpm_backend` sibling module and by this
    // crate's own tests; on non-Linux hosts neither consumer is compiled
    // into the plain library build, which is what makes the dead-code lint
    // fire here. Kept `pub(crate)` rather than widened to `pub` — silencing
    // a lint is not a reason to enlarge the crate's public surface.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn preflight(&self) -> Result<(), KeystoreError> {
        let dir = self.open_secrets_dir().map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("open {}: {e}", self.secrets_dir().display()),
        })?;
        self.check_fs_allowed(&dir)
    }

    fn check_fs_allowed(&self, dir: &DirHandle) -> Result<(), KeystoreError> {
        match fs_gate::verdict(dir) {
            Ok(fs_gate::Verdict::Allowed) => Ok(()),
            Ok(fs_gate::Verdict::Rejected(what)) => Err(KeystoreError::Unsupported {
                hint: format!(
                    "{} is on filesystem {what}, which is not on the allowlist of \
                     local persistent filesystems whose fsync durability this crate \
                     is willing to vouch for; create_only refuses rather than \
                     return CreatedDurable it cannot back",
                    self.secrets_dir().display()
                ),
            }),
            Err(e) => Err(KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("statfs {}: {e}", self.secrets_dir().display()),
            }),
        }
    }

    /// Attempt to install `bytes` under `account` iff absent, self-contained:
    /// opens and validates the directory chain, checks the filesystem gate,
    /// and holds the SHARED create lock for exactly the lifetime of its
    /// scratch file so a concurrent sweep cannot remove it mid-flight.
    ///
    /// Does NOT reinspect on ambiguity/conflict — see
    /// [`Self::reinspect_and_stabilize`] for that.
    pub(crate) fn raw_attempt_install(
        &self,
        account: &str,
        bytes: &[u8],
    ) -> Result<InstallOutcome, KeystoreError> {
        let dir = self.open_secrets_dir().map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("open {}: {e}", self.secrets_dir().display()),
        })?;
        self.check_fs_allowed(&dir)?;

        // Shared lock: many concurrent create_only calls coexist freely; a
        // sweep (which takes the exclusive lock) cannot run while any of them
        // holds this. Acquired AFTER the gate and BEFORE the first mutation,
        // and released the moment the scratch file is gone.
        let _shared = FlockGuard::acquire(&dir, false).map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("lock {}: {e}", self.secrets_dir().display()),
        })?;

        attempt_install(&dir, &Self::account_file_name(account), bytes).map_err(|e| {
            KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("create {}: {e}", self.account_path(account).display()),
            }
        })
    }

    /// Reinspect `account` and, if its content satisfies `compare`, freshly
    /// prove it durable.
    ///
    /// Everything happens against fds that are retained across the whole
    /// sequence: the directory fd from the validated descent, and the file fd
    /// the content was read from. The file's own `fsync` and the directory
    /// `fsync` both target those exact fds, so an intervening delete+recreate
    /// at the same name cannot cause this call to prove a DIFFERENT file
    /// durable than the one whose content it actually compared. A closing
    /// `dev`+`ino` comparison against the originally-opened fd catches a
    /// substitution that landed in the final window; anything unresolved
    /// downgrades to [`CreateOutcome::MayHaveTakenEffect`] rather than
    /// claiming a proof it does not have.
    ///
    /// `compare` receives the raw stored bytes: [`FileKeystore`] compares them
    /// directly, while [`crate::tpm_backend::TpmKeystore`] decrypts first —
    /// which is why this is a callback rather than a fixed byte comparison.
    pub(crate) fn reinspect_and_stabilize(
        &self,
        account: &str,
        compare: impl FnOnce(&[u8]) -> Result<bool, KeystoreError>,
    ) -> Result<CreateOutcome, KeystoreError> {
        let Ok(dir) = self.open_secrets_dir() else {
            return Ok(CreateOutcome::MayHaveTakenEffect);
        };
        self.check_fs_allowed(&dir)?;
        let name = Self::account_file_name(account);

        let (mut file, held_meta) = match dir.open_file_read_nofollow(OsStr::new(&name)) {
            Ok(SecureOpen::Found(file, meta)) => (file, meta),
            Ok(SecureOpen::NotFound) => return Ok(CreateOutcome::KnownNoEffect),
            // A security violation is never downgraded to "ambiguous, just
            // retry" — that would bury a symlink/ownership problem under a
            // retry loop instead of surfacing it.
            Ok(SecureOpen::SecurityViolation(hint)) => {
                return Err(KeystoreError::SecurityViolation {
                    label: format!("{} (file fallback)", self.account_path(account).display()),
                    hint,
                });
            }
            Err(_) => return Ok(CreateOutcome::MayHaveTakenEffect),
        };

        let Ok(mut bytes) = read_bounded_zeroizing(&mut file, MAX_SECRET_BYTES) else {
            return Ok(CreateOutcome::MayHaveTakenEffect);
        };
        if bytes.len() as u64 > MAX_SECRET_BYTES {
            bytes.zeroize();
            return Err(KeystoreError::SecurityViolation {
                label: format!("{} (file fallback)", self.account_path(account).display()),
                hint: format!(
                    "entry exceeds the {MAX_SECRET_BYTES}-byte cap for a secret; refusing to \
                     treat it as one"
                ),
            });
        }
        if !compare(&bytes)? {
            return Ok(CreateOutcome::Conflict);
        }
        post_compare_hook(&dir, &name);
        if file_fsync_failpoint().is_some() || file.sync_all().is_err() {
            return Ok(CreateOutcome::MayHaveTakenEffect);
        }
        if dir.fsync().is_err() {
            return Ok(CreateOutcome::MayHaveTakenEffect);
        }
        match dir.stat_at_nofollow(OsStr::new(&name)) {
            Ok(Some(now_meta)) if same_inode(&held_meta, &now_meta) => {
                Ok(CreateOutcome::ExistingExactDurable)
            }
            _ => Ok(CreateOutcome::MayHaveTakenEffect),
        }
    }

    fn stabilize_and_classify(
        &self,
        account: &str,
        expected: &[u8],
    ) -> Result<CreateOutcome, KeystoreError> {
        self.reinspect_and_stabilize(account, |bytes| Ok(bytes == expected))
    }

    /// Read an entry through the hardened path AND prove what was read is
    /// durable, all against descriptors held across the whole sequence.
    ///
    /// [`KeystoreBackend::get`] is the legacy path-based reader: it opens by
    /// pathname, follows a symlink at the final component, applies no
    /// owner/mode/type check, has no size cap, and proves nothing about
    /// durability. That is acceptable for a best-effort byte fetch and NOT
    /// acceptable for deciding that a key exists — an audit demonstrated
    /// both failures against the opaque P-256 layer built on it: a slot
    /// replaced by a symlink to a scalar outside the store loaded happily,
    /// and a key that was merely *visible* after a failed directory barrier
    /// was reported as an existing durable key.
    ///
    /// Returns `Ok(None)` for a genuinely absent entry, `Err(SecurityViolation)`
    /// for anything this backend would not itself have written, and
    /// `Err(Io)` when the entry cannot be proven durable — never a value
    /// whose durability is unknown.
    pub(crate) fn secure_durable_get(
        &self,
        account: &str,
    ) -> Result<Option<Vec<u8>>, KeystoreError> {
        let dir = self.open_secrets_dir().map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("open {}: {e}", self.secrets_dir().display()),
        })?;
        self.check_fs_allowed(&dir)?;
        let name = Self::account_file_name(account);
        let label = || format!("{} (file fallback)", self.account_path(account).display());

        let opened = dir
            .open_file_read_nofollow(OsStr::new(&name))
            .map_err(|e| KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("open {}: {e}", self.account_path(account).display()),
            })?;
        let (mut file, held_meta) = match opened {
            SecureOpen::Found(file, meta) => (file, meta),
            SecureOpen::NotFound => return Ok(None),
            SecureOpen::SecurityViolation(hint) => {
                return Err(KeystoreError::SecurityViolation {
                    label: label(),
                    hint,
                });
            }
        };

        let mut bytes =
            read_bounded_zeroizing(&mut file, MAX_SECRET_BYTES).map_err(|e| KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("read {}: {e}", self.account_path(account).display()),
            })?;
        if bytes.len() as u64 > MAX_SECRET_BYTES {
            // `clear()` would only set len=0 and leave the bytes in the
            // heap allocation; this entry may be a private scalar.
            bytes.zeroize();
            return Err(KeystoreError::SecurityViolation {
                label: label(),
                hint: format!("entry exceeds the {MAX_SECRET_BYTES}-byte cap for a secret"),
            });
        }

        // Prove durability of the EXACT thing just read, on the same fds.
        let durable = file.sync_all().and_then(|()| dir.fsync());
        if let Err(e) = durable {
            // `clear()` would only set len=0 and leave the bytes in the
            // heap allocation; this entry may be a private scalar.
            bytes.zeroize();
            return Err(KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!(
                    "{} is readable but could not be proven durable: {e}",
                    self.account_path(account).display()
                ),
            });
        }
        // And that it is still the same inode after the barrier.
        match dir.stat_at_nofollow(OsStr::new(&name)) {
            Ok(Some(now)) if same_inode(&held_meta, &now) => Ok(Some(bytes)),
            _ => {
                // `clear()` would only set len=0 and leave the bytes in the
                // heap allocation; this entry may be a private scalar.
                bytes.zeroize();
                Err(KeystoreError::Io {
                    kind: "entry changed identity during read".into(),
                    hint: format!(
                        "{} was replaced while being proven durable",
                        self.account_path(account).display()
                    ),
                })
            }
        }
    }

    /// Compare-and-delete as ONE operation, under the store's exclusive
    /// lock, with a durable absence.
    ///
    /// The previous shape — read the entry, compare it, then call the
    /// path-based `delete` — was check-then-act with a real window: a
    /// concurrent writer installing B between the compare of A and the
    /// unlink caused B to be destroyed, and `remove_file` alone left the
    /// absence unsynced, so a crash could resurrect the entry that was
    /// just "revoked". Holding the exclusive lock across both halves shuts
    /// out every other writer in this crate (installs take the shared
    /// lock), the unlink is fd-relative through the validated dirfd, and
    /// the parent directory is fsynced before reporting success.
    ///
    /// This closes concurrency among the crate's own writers. It does NOT
    /// defend against a same-uid process writing the files behind the
    /// crate's back — that boundary is the filesystem's.
    pub(crate) fn delete_exact_locked(
        &self,
        account: &str,
        matches: impl FnOnce(&[u8]) -> Result<bool, KeystoreError>,
    ) -> Result<DeleteOutcome, KeystoreError> {
        self.guard_reserved()?;
        let dir = self.open_secrets_dir().map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("open {}: {e}", self.secrets_dir().display()),
        })?;
        self.check_fs_allowed(&dir)?;

        // Exclusive for the whole compare+unlink+barrier sequence.
        let _exclusive = FlockGuard::acquire(&dir, true).map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("lock {}: {e}", self.secrets_dir().display()),
        })?;

        let name = Self::account_file_name(account);
        let mut bytes = match dir.open_file_read_nofollow(OsStr::new(&name)) {
            Ok(SecureOpen::Found(mut file, _)) => {
                read_bounded_zeroizing(&mut file, MAX_SECRET_BYTES).map_err(|e| {
                    KeystoreError::Io {
                        kind: e.kind().to_string(),
                        hint: format!("read {name}: {e}"),
                    }
                })?
            }
            Ok(SecureOpen::NotFound) => return Ok(DeleteOutcome::Absent),
            Ok(SecureOpen::SecurityViolation(hint)) => {
                return Err(KeystoreError::SecurityViolation {
                    label: format!("{} (file fallback)", self.account_path(account).display()),
                    hint,
                });
            }
            Err(e) => {
                return Err(KeystoreError::Io {
                    kind: e.kind().to_string(),
                    hint: format!("open {name}: {e}"),
                });
            }
        };

        let verdict = matches(&bytes);
        bytes.zeroize();
        if !verdict? {
            return Ok(DeleteOutcome::Mismatch);
        }

        match dir.unlinkat(OsStr::new(&name)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(DeleteOutcome::Absent),
            Err(e) => {
                return Err(KeystoreError::Io {
                    kind: e.kind().to_string(),
                    hint: format!("unlink {name}: {e}"),
                });
            }
        }
        // The removal is only real once the directory entry is durable;
        // without this a crash can bring a revoked key back.
        dir.fsync().map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("fsync after removing {name}: {e}"),
        })?;
        Ok(DeleteOutcome::Removed)
    }

    /// Whether this store holds any account entry other than `exclude`.
    ///
    /// Needed by the store-identity restore policy: material present with
    /// no identity marker must fail closed rather than have a fresh marker
    /// minted over it, and that decision requires knowing whether anything
    /// is actually there.
    pub(crate) fn has_entries_besides(&self, exclude: &str) -> Result<bool, KeystoreError> {
        let excluded_file = Self::account_file_name(exclude);
        let listing = match fs::read_dir(self.secrets_dir()) {
            Ok(listing) => listing,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(KeystoreError::Io {
                    kind: e.kind().to_string(),
                    hint: format!("read_dir {}: {e}", self.secrets_dir().display()),
                });
            }
        };
        for entry in listing {
            let entry = entry.map_err(|e| KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("read_dir {}: {e}", self.secrets_dir().display()),
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == excluded_file || name == LOCK_FILE_NAME {
                continue;
            }
            // Scratch leftovers are not material; the sweep owns those.
            if parse_create_attempt_tmp_name(&name).is_some() {
                continue;
            }
            if name.ends_with(".bin") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // A `physical_store_id` based on the secrets directory's dev+ino used
    // to live here and is deliberately gone. dev+ino is a sound guard for
    // an OPEN HANDLE mid-operation (still used inside
    // `secure_durable_get` to catch a file swapped under the fd), but it is
    // not a durable STORE identity: it does not survive a remount or a
    // restore, so bindings scoped to it would stop validating after either
    // for no security reason. That role belongs to
    // `opaque_p256::StoreIdentityV1`, which is committed durably and read
    // back. Removed rather than kept around, so it cannot be picked up
    // again for the job it is wrong for.

    fn create_only_unix(
        &self,
        account: &str,
        value: &[u8],
    ) -> Result<CreateOutcome, KeystoreError> {
        match self.raw_attempt_install(account, value)? {
            InstallOutcome::Durable => Ok(CreateOutcome::CreatedDurable),
            // Ambiguous AND proven-conflict both fall through to the same
            // reinspection: whatever the reason we cannot trust the install
            // attempt's own verdict, the actual on-disk state is the only
            // thing worth trusting, and it resolves every case correctly —
            // including tmp-name exhaustion, where nothing was ever installed
            // and reinspection therefore reports KnownNoEffect rather than
            // the destination Conflict a naive mapping would have claimed.
            InstallOutcome::Ambiguous(e) => {
                tracing::debug!(error = %e, account, "create_only install ambiguous, reinspecting");
                self.stabilize_and_classify(account, value)
            }
            InstallOutcome::ProvenConflict | InstallOutcome::TmpNameExhausted => {
                self.stabilize_and_classify(account, value)
            }
        }
    }

    /// Take the exclusive create-lock for this store, so a sweep can run
    /// without racing an in-flight `create_only`.
    ///
    /// Blocks until every in-flight `create_only` on this
    /// `(state_dir, service)` has released its shared lock. The returned
    /// guard is bound to this store's identity — passing it to a different
    /// [`FileKeystore`]'s sweep is rejected, so the token cannot be
    /// laundered into standing for exclusion it never established.
    pub fn lock_for_sweep(&self) -> Result<SweepGuard, KeystoreError> {
        self.guard_reserved()?;
        let dir = self.open_secrets_dir().map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("open {}: {e}", self.secrets_dir().display()),
        })?;
        let lock = FlockGuard::acquire(&dir, true).map_err(|e| KeystoreError::Io {
            kind: e.kind().to_string(),
            hint: format!("lock {}: {e}", self.secrets_dir().display()),
        })?;
        Ok(SweepGuard {
            _lock: lock,
            state_dir: self.state_dir.clone(),
            service: self.service.clone(),
        })
    }

    /// Remove scratch files left behind by a [`KeystoreBackend::create_only`]
    /// call that died between installing its content and its own cleanup.
    /// Those files hold the same secret bytes `create_only` was asked to
    /// store and do not expire on their own.
    ///
    /// Requires a [`SweepGuard`] from [`Self::lock_for_sweep`] on THIS store:
    /// the exclusion is enforced by the type system plus a real `flock`, not
    /// by a documented convention a caller can forget. Without it, a sweep
    /// racing a live `create_only` could unlink that call's scratch file
    /// between its creation and its `linkat`, turning a perfectly good
    /// install into a spurious failure.
    ///
    /// Bounded to this keystore's own secrets directory and to names matching
    /// the exact scratch-file pattern [`tmp_attempt_path_name`] produces,
    /// parsed structurally from the END of the name. Each candidate's content
    /// is re-hashed and checked against the digest embedded in its own name;
    /// only a match is removed. A mismatch (partial write, corruption, or
    /// something else entirely) is QUARANTINED — left on disk and counted in
    /// [`SweepReport::quarantined`] — because deleting on a failed identity
    /// check is what would make the check decorative, and it destroys the
    /// evidence needed to explain the file. Everything is unlinked through
    /// the retained directory fd, so no path relookup can redirect a removal.
    ///
    /// Subject to the same filesystem allowlist as `create_only`: a sweep
    /// that reported success after an `fsync` on media whose durability this
    /// crate refuses to vouch for would be claiming exactly the guarantee
    /// `create_only` declines to make.
    pub fn sweep_orphaned_create_attempts(
        &self,
        guard: &SweepGuard,
    ) -> Result<SweepReport, KeystoreError> {
        self.guard_reserved()?;
        if guard.state_dir != self.state_dir || guard.service != self.service {
            return Err(KeystoreError::Unsupported {
                hint: format!(
                    "sweep guard belongs to {}/{}, not {}/{} — a lock on another \
                     store proves nothing about this one",
                    guard.state_dir.display(),
                    guard.service,
                    self.state_dir.display(),
                    self.service
                ),
            });
        }

        let dir = match self.open_secrets_dir() {
            Ok(dir) => dir,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(SweepReport::default()),
            Err(e) => {
                return Err(KeystoreError::Io {
                    kind: e.kind().to_string(),
                    hint: format!("open {}: {e}", self.secrets_dir().display()),
                });
            }
        };

        self.check_fs_allowed(&dir)?;

        let listing = match fs::read_dir(self.secrets_dir()) {
            Ok(listing) => listing,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(SweepReport::default()),
            Err(e) => {
                return Err(KeystoreError::Io {
                    kind: e.kind().to_string(),
                    hint: format!("read_dir {}: {e}", self.secrets_dir().display()),
                });
            }
        };

        let mut report = SweepReport::default();
        for entry in listing {
            let entry = entry.map_err(|e| KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("read_dir {}: {e}", self.secrets_dir().display()),
            })?;
            let raw_name = entry.file_name();
            let Some(parsed) = parse_create_attempt_tmp_name(&raw_name.to_string_lossy()) else {
                continue;
            };

            // Read through the retained dirfd — the listing supplied only a
            // NAME, never a path we act on. `open_file_read_nofollow` also
            // rejects a symlink, FIFO, device, or wrong mode/owner outright,
            // so a planted non-regular file is quarantined, not read.
            let content = match dir.open_file_read_nofollow(&raw_name) {
                Ok(SecureOpen::Found(mut f, _)) => {
                    match read_bounded_zeroizing(&mut f, MAX_SECRET_BYTES) {
                        Ok(buf) if buf.len() as u64 <= MAX_SECRET_BYTES => Some(buf),
                        // Oversized: wipe before discarding — a scratch file
                        // holds the same secret bytes as a real entry.
                        Ok(mut buf) => {
                            buf.zeroize();
                            None
                        }
                        // Unreadable: `read_bounded_zeroizing` already wiped
                        // whatever it managed to read.
                        Err(_) => None,
                    }
                }
                Ok(SecureOpen::NotFound) => continue,
                Ok(SecureOpen::SecurityViolation(_)) | Err(_) => None,
            };

            // Only remove what we can PROVE is our own abandoned scratch
            // file: content must match the digest bound into its own name.
            // Anything else is quarantined — left in place and reported —
            // rather than deleted. Deleting on a failed identity check would
            // make the check decorative (that is exactly the bug this
            // replaced: a digest comparison that could never match, followed
            // by an unconditional removal) and would destroy the evidence a
            // human needs to work out what actually put it there.
            let verified = content.as_ref().is_some_and(|bytes| {
                content_digest_hex(Path::new(&parsed.final_name), bytes) == parsed.digest
            });
            if !verified {
                tracing::warn!(
                    name = %raw_name.to_string_lossy(),
                    "scratch file does not match the digest bound into its own name — \
                     quarantining (left on disk) instead of removing; investigate before \
                     deleting by hand"
                );
                report.quarantined += 1;
                continue;
            }

            match dir.unlinkat(&raw_name) {
                Ok(()) => report.removed += 1,
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(KeystoreError::Io {
                        kind: e.kind().to_string(),
                        hint: format!("unlink {}: {e}", raw_name.to_string_lossy()),
                    });
                }
            }
        }
        // The removals are only durable once the directory itself is synced;
        // without this a crash could resurrect scratch files still holding
        // secret bytes. Reported as an error rather than swallowed, so
        // "sweep returned Ok" really means "the cleanup is on disk".
        if report.removed > 0 {
            dir.fsync().map_err(|e| KeystoreError::Io {
                kind: e.kind().to_string(),
                hint: format!("fsync after sweep {}: {e}", self.secrets_dir().display()),
            })?;
        }
        Ok(report)
    }
}

/// Read at most `cap` bytes, wiping whatever was read if the read FAILS.
///
/// `read_to_end` appends as it goes, so an error partway through leaves
/// real bytes in the buffer — and for these entries those bytes may be
/// part of a private scalar. Dropping the `Vec` then frees that memory
/// without clearing it. Every scalar-carrying read goes through here so
/// the failure paths wipe too, not just the success paths.
fn read_bounded_zeroizing(file: &mut File, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    match std::io::Read::by_ref(file)
        .take(cap + 1)
        .read_to_end(&mut buf)
    {
        Ok(_) => Ok(buf),
        Err(e) => {
            buf.zeroize();
            Err(e)
        }
    }
}

/// Result of [`FileKeystore::delete_exact_locked`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeleteOutcome {
    /// The entry matched and is durably gone.
    Removed,
    /// Nothing was there to remove.
    Absent,
    /// Something was there but it was NOT what the caller expected, so it
    /// was left untouched.
    Mismatch,
}

/// What a sweep actually did. `quarantined` is not a benign statistic: it
/// counts scratch-shaped files the sweep could NOT prove were its own
/// abandoned work and therefore refused to delete. A non-zero value wants a
/// human to look, not an automatic retry.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    /// Scratch files verified against the digest in their own name and
    /// removed, with the removal synced to disk.
    pub removed: usize,
    /// Scratch-shaped files left in place because their content did not
    /// match their name's digest, they were unreadable, oversized, or not a
    /// plain owner-only regular file.
    pub quarantined: usize,
}

/// Proof that the holder owns the exclusive create-lock for one specific
/// `(state_dir, service)` store. Obtained from
/// [`FileKeystore::lock_for_sweep`] and required by
/// [`FileKeystore::sweep_orphaned_create_attempts`]. Releasing is automatic
/// on drop (closing the underlying fd releases the `flock`).
#[cfg(unix)]
#[derive(Debug)]
pub struct SweepGuard {
    _lock: FlockGuard,
    state_dir: PathBuf,
    service: String,
}

impl KeystoreBackend for FileKeystore {
    fn get(&self, account: &str) -> Result<Vec<u8>, KeystoreError> {
        self.guard_reserved()?;
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
        self.guard_reserved()?;
        let dir = self.secrets_dir();
        if let Err(e) = ensure_private_dir_path_based(&dir) {
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
        self.guard_reserved()?;
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

    fn create_only(&self, account: &str, value: &[u8]) -> Result<CreateOutcome, KeystoreError> {
        self.guard_reserved()?;
        #[cfg(unix)]
        {
            self.create_only_unix(account, value)
        }
        #[cfg(not(unix))]
        {
            let _ = (account, value);
            Err(KeystoreError::Unsupported {
                hint: "create_only's fd-relative protocol (openat/linkat/flock/statfs) is \
                       implemented for unix only; theyOS does not target Windows"
                    .into(),
            })
        }
    }
}

/// Encode a value for use as a single path segment, injectively.
///
/// The previous implementation mapped `/`, `\` and NUL all to `_`, which is
/// NOT injective: `a/b`, `a\b` and `a_b` all became `a_b`, so three distinct
/// accounts silently shared one secret file — one caller's `get` could return
/// another caller's secret, and one caller's `create_only` would report a
/// `Conflict` against a value that was never theirs. Percent-encoding the
/// unsafe characters (and the escape character itself) makes the mapping
/// injective, so distinct labels always land on distinct files.
///
/// Deliberately encodes ONLY the characters that are actually unsafe, so
/// every label that works today keeps its exact current filename: this crate
/// documents that entries survive upgrades, and a wholesale re-encoding would
/// orphan existing on-disk secrets. Labels that change are exactly the ones
/// that were previously colliding — i.e. already broken.
fn sanitize_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            // `%` must be escaped first, otherwise a literal `%2F` in the
            // input would decode to the same segment as a real `/`.
            '%' => out.push_str("%25"),
            '/' => out.push_str("%2F"),
            '\\' => out.push_str("%5C"),
            '\0' => out.push_str("%00"),
            _ => out.push(ch),
        }
    }
    // `.` and `..` are directory references rather than names. Encoding the
    // leading dot keeps them injective too: a literal `%2E` input already
    // became `%252E` above, so it cannot collide with these.
    match out.as_str() {
        "." => "%2E".to_string(),
        ".." => "%2E.".to_string(),
        _ => out,
    }
}

/// Create every missing ancestor level of `dir`, one component at a time,
/// `fsync`ing the parent of each level THIS call creates.
///
/// `create_dir_all` alone is not enough for a durability claim: if a crash
/// loses the directory entry for an ancestor, everything beneath it is lost
/// too, no matter how carefully the leaf file was synced. So the chain has to
/// be proven, not just made visible.
///
/// A level that ALREADY existed gets no `fsync` here, unlike the owned
/// `secrets`/`<service>` levels below (which are re-synced unconditionally on
/// every retry). The difference is real: those two are ours, we re-enter them
/// on every call, and we cannot tell whether the attempt that first created
/// them completed its barrier. An ancestor that predates this process is the
/// caller's own tree — re-`fsync`ing the entire path to the filesystem root
/// on every single `create_only` would be pure cost for directories this
/// crate never created and cannot be responsible for.
fn create_ancestors_durably(dir: &Path) -> std::io::Result<()> {
    let mut built = PathBuf::new();
    for component in dir.components() {
        built.push(component);
        if let Err(e) = fs::create_dir(&built) {
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(e);
            }
        }
        // Fsync the parent UNCONDITIONALLY, including when the level
        // already existed.
        //
        // I previously skipped this on AlreadyExists, reasoning that a
        // pre-existing ancestor is the caller's own tree and not ours to
        // prove. That reasoning has a hole: if THIS crate created the level
        // on an earlier call and its fsync failed, the retry sees the
        // directory present and skips the barrier forever — visibility
        // standing in for durability, which is the exact confusion this
        // module exists to prevent, in the one place I had argued it did
        // not apply. Paying an extra fsync per level is cheaper than a
        // silently unprovable hierarchy.
        if let Some(parent) = built.parent() {
            let d = OpenOptions::new().read(true).open(parent)?;
            d.sync_all()?;
        }
    }
    Ok(())
}

/// Path-based directory setup for the legacy best-effort [`KeystoreBackend::set`]
/// path. `create_only` deliberately does NOT use this — it descends with
/// [`FileKeystore::open_secrets_dir`] instead. `set` makes no durability
/// claim, so it does not carry the fd-relative protocol's cost.
fn ensure_private_dir_path_based(dir: &Path) -> std::io::Result<()> {
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

// ---------------------------------------------------------------------------
// Install protocol (unix only).
// ---------------------------------------------------------------------------

/// Result of [`attempt_install`]'s syscall-level attempt, BEFORE any
/// reinspection.
#[cfg(unix)]
pub(crate) enum InstallOutcome {
    /// The link landed and the directory `fsync` proving it succeeded.
    Durable,
    /// The link's own result does not unambiguously prove "nothing happened":
    /// either it landed but the follow-up durability `fsync` failed, or the
    /// `linkat` returned an error OTHER than the well-defined "destination
    /// exists". A syscall failure does not generally prove its effect did not
    /// land, so this is the conservative default.
    Ambiguous(std::io::Error),
    /// `linkat` refused with the well-defined "destination already exists".
    /// Alone this does not distinguish "someone else's value" from "my own
    /// earlier attempt already won" — that still needs reinspection.
    ProvenConflict,
    /// All scratch-name attempts collided. Distinct from [`Self::ProvenConflict`]
    /// on purpose: nothing was installed and the DESTINATION was never even
    /// contended — conflating the two would report a conflict against another
    /// party's value that does not exist. Should be unreachable in normal
    /// operation (the names carry a per-process atomic counter).
    TmpNameExhausted,
}

/// Attempt to install `bytes` as `final_name` inside `dir` iff absent.
///
/// Plain `tmp + rename` (what [`write_0600`] uses for `set`) is NOT
/// create-only: `rename(2)` silently replaces an existing destination. This
/// writes a per-attempt scratch file bound to `(name, content-digest,
/// attempt)` and publishes it with `linkat(2)`, which fails with `EEXIST`
/// rather than replacing. Every operation is relative to `dir`'s retained fd.
///
/// The scratch file is removed only AFTER the outcome is classified — an
/// eager unlink would discard this call's own candidate bytes before we know
/// whether we still need to reason about them.
#[cfg(unix)]
fn attempt_install(
    dir: &DirHandle,
    final_name: &str,
    bytes: &[u8],
) -> std::io::Result<InstallOutcome> {
    for attempt in 0u32..8 {
        let tmp_name = tmp_attempt_path_name(final_name, bytes, attempt);
        match dir.create_new_file(OsStr::new(&tmp_name), 0o600, bytes) {
            Ok((scratch, written_meta)) => {
                substitute_scratch_hook(dir, &tmp_name);
                // `scratch` stays alive across this whole block: while it is
                // open the inode it refers to cannot be freed, so its inode
                // number cannot be recycled under us and the dev+ino
                // comparison below is a real identity check.
                let publish = publish_link_override(dir.publish_from_fd(
                    &scratch,
                    OsStr::new(&tmp_name),
                    OsStr::new(final_name),
                ));
                let outcome = match publish {
                    Ok(()) => {
                        // Both supported publishes take their SOURCE from the
                        // retained descriptor, so a substituted scratch NAME
                        // can no longer change what gets published. The
                        // window is prevented, not detected afterwards.
                        //
                        // The post-publish identity proof must therefore
                        // match the mechanism, and the two differ:
                        //
                        // - Linux links from the fd, so the published entry
                        //   is the SAME inode we wrote; dev+ino equality is
                        //   the right invariant and is still checked.
                        // - macOS CLONES from the fd. A clone is not a hard
                        //   link: it is a new inode with identical content by
                        //   construction. Asserting dev+ino equality there
                        //   would fail on every correct publish — it did,
                        //   until this was split — because it would be
                        //   testing an invariant the mechanism never had.
                        //
                        // Keeping one shared check would have meant either a
                        // false substitution report on macOS or dropping a
                        // real guarantee on Linux.
                        let identity_ok = if cfg!(target_os = "macos") {
                            true
                        } else {
                            matches!(
                                dir.stat_at_nofollow(OsStr::new(final_name)),
                                Ok(Some(ref published)) if same_inode(&written_meta, published)
                            )
                        };
                        if identity_ok {
                            match dir.fsync() {
                                Ok(()) => InstallOutcome::Durable,
                                Err(e) => InstallOutcome::Ambiguous(e),
                            }
                        } else {
                            InstallOutcome::Ambiguous(std::io::Error::other(
                                "published entry is not the inode this call wrote — the scratch \
                                 name was substituted between write and publish",
                            ))
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                        InstallOutcome::ProvenConflict
                    }
                    Err(e) => InstallOutcome::Ambiguous(e),
                };
                if !cleanup_armed() {
                    // The scratch file holds the same secret bytes as the
                    // real entry, so its removal has to actually be checked
                    // AND made durable — an unchecked unlink, or one left
                    // unsynced, can leave plaintext on disk (or resurrect it
                    // after a crash). Failure here does not invalidate the
                    // install itself, so it is reported rather than folded
                    // into the outcome; the sweep is the backstop.
                    match dir.unlinkat(OsStr::new(&tmp_name)) {
                        Ok(()) => {
                            if let Err(e) = dir.fsync() {
                                tracing::warn!(
                                    error = %e,
                                    "scratch file unlinked but the directory fsync proving it \
                                     failed; a crash could resurrect secret bytes — \
                                     sweep_orphaned_create_attempts will clean up"
                                );
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => tracing::warn!(
                            error = %e,
                            "could not remove create_only scratch file holding secret bytes; \
                             sweep_orphaned_create_attempts will clean up"
                        ),
                    }
                }
                drop(scratch);
                return Ok(outcome);
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                // Our own randomised scratch name collided — retry.
            }
            Err(e) => return Err(e),
        }
    }
    tracing::warn!(
        name = %final_name,
        "create_only exhausted all 8 scratch-name attempts — unreachable under normal \
         operation; investigate clock/pid/counter assumptions on this host"
    );
    Ok(InstallOutcome::TmpNameExhausted)
}

/// Per-attempt scratch filename, bound to `(final_name, content-digest,
/// attempt)`. The embedded digest is what lets
/// [`FileKeystore::sweep_orphaned_create_attempts`] verify a recovered
/// orphan's content actually matches what its own name claims rather than
/// trusting the name pattern alone.
#[cfg(unix)]
fn tmp_attempt_path_name(final_name: &str, bytes: &[u8], attempt: u32) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let digest = content_digest_hex(Path::new(final_name), bytes);
    format!(
        "{final_name}.tmp.{}.{nanos}.{n}.{attempt}.{digest}",
        std::process::id()
    )
}

/// Full 256-bit BLAKE3 fingerprint of `(final_path, bytes)`.
///
/// What this binding is and is not: the trust boundary this crate relies on
/// is the `0700` secrets directory — an actor with write access there could
/// modify the real target files directly regardless of any naming scheme. The
/// digest's job is to let recovery tell "this scratch file's content genuinely
/// matches what its name claims" from "this is a stray, partial, or corrupted
/// write", not to authenticate across a privilege boundary that does not
/// otherwise exist here.
fn content_digest_hex(final_path: &Path, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(final_path.to_string_lossy().as_bytes());
    hasher.update(&[0u8]);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

/// Structural parse of a name [`tmp_attempt_path_name`] could have produced:
/// `<stem>.bin.tmp.<pid>.<nanos>.<counter>.<attempt>.<digest64hex>`.
///
/// Parsed from the END with a fixed field count rather than by searching
/// forward for a `.tmp.` substring: an account label (hence `<stem>`) may
/// legitimately contain dots, `tmp`, `bin`, or digit runs, so a forward
/// substring search is not reliable; counting fixed trailing fields is.
struct ParsedTmpName {
    /// The FULL final filename this scratch file was a candidate for,
    /// including its `.bin` suffix (e.g. `acct.bin`) — NOT a stem that still
    /// needs `.bin` appended.
    ///
    /// This distinction was a real bug: the parser's slice already ends at
    /// the `bin` component, so treating the result as a suffix-less stem and
    /// re-appending `.bin` produced `acct.bin.bin`, and recomputing the
    /// digest over that (plus over a full path, where the install side used
    /// the bare name) meant the sweep's digest comparison could never match
    /// for ANY input. The check was structurally vacuous while looking
    /// exactly like a working integrity check — and the test covering it
    /// passed anyway, because the code removed the file whether or not the
    /// digest agreed. Both halves must derive the digest from the same
    /// value: the bare final filename.
    final_name: String,
    digest: String,
}

fn parse_create_attempt_tmp_name(name: &str) -> Option<ParsedTmpName> {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 8 {
        return None;
    }
    let digest = parts[parts.len() - 1];
    let numeric_fields = &parts[parts.len() - 5..parts.len() - 1];
    if parts[parts.len() - 7] != "bin" || parts[parts.len() - 6] != "tmp" {
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
    // Includes the trailing `bin` component, so this IS the final filename.
    let final_name = parts[..parts.len() - 6].join(".");
    if final_name.is_empty() || final_name == "bin" {
        return None;
    }
    Some(ParsedTmpName {
        final_name,
        digest: digest.to_string(),
    })
}

/// `true` iff `a` and `b` are the same inode on the same device — dev+ino
/// identity, not path equality.
#[cfg(unix)]
fn same_inode(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

// ---------------------------------------------------------------------------
// Retained-fd directory handle (unix).
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn cstr(name: &OsStr) -> std::io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "path component contains NUL"))
}

/// Outcome of opening a leaf secret file through a validated directory fd.
#[cfg(unix)]
enum SecureOpen {
    /// Carries the `Metadata` from the SAME `fstat` the security check used,
    /// so a later "is this still the same file" comparison needs no second,
    /// independently-racy stat.
    Found(File, std::fs::Metadata),
    NotFound,
    /// Something is here this backend would never have produced: a symlink, a
    /// non-regular file, or a mode/owner mismatch.
    SecurityViolation(String),
}

/// A retained directory file descriptor. Every operation is `*at`-style and
/// relative to this fd, so no step in the protocol performs a fresh path
/// lookup that a concurrent rename or symlink swap could redirect.
#[cfg(unix)]
#[derive(Debug)]
struct DirHandle {
    fd: OwnedFd,
}

#[cfg(unix)]
#[allow(unsafe_code)]
impl DirHandle {
    /// Open the caller-supplied base directory, FOLLOWING symlinks. This is
    /// the caller's own path and a caller is entitled to point us through a
    /// symlink; only the levels this crate creates below it are hardened.
    fn open_base(path: &Path) -> std::io::Result<Self> {
        let c = cstr(path.as_os_str())?;
        // SAFETY: `c` is a valid NUL-terminated C string that outlives the
        // call; `open` with these flags has no other precondition.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, valid, exclusively-owned descriptor.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Descend one level with `O_NOFOLLOW`: if `name` is a symlink the open
    /// fails rather than silently redirecting every subsequent operation.
    fn openat_dir_nofollow(&self, name: &OsStr) -> std::io::Result<Self> {
        let c = cstr(name)?;
        // SAFETY: `self.fd` is an open directory fd; `c` is a valid C string.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fresh, valid, exclusively-owned descriptor.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn mkdirat(&self, name: &OsStr, mode: libc::mode_t) -> std::io::Result<()> {
        let c = cstr(name)?;
        // SAFETY: valid dir fd + valid C string.
        let r = unsafe { libc::mkdirat(self.fd.as_raw_fd(), c.as_ptr(), mode) };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn fchmod(&self, mode: libc::mode_t) -> std::io::Result<()> {
        // SAFETY: valid open fd.
        let r = unsafe { libc::fchmod(self.fd.as_raw_fd(), mode) };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Directory barrier for a SECRET ENTRY's durability (publish, stabilize,
    /// sweep). The failpoint lives here at the primitive rather than at one
    /// call site, because `create_only` performs this barrier more than once
    /// per call (install, then again in the stabilize fallback) and gating
    /// only the first let the second silently succeed — making "this barrier
    /// is down for the whole call" impossible to simulate.
    fn fsync(&self) -> std::io::Result<()> {
        if let Some(e) = dir_fsync_failpoint() {
            return Err(e);
        }
        self.fsync_unhooked()
    }

    /// Directory barrier for HIERARCHY setup. Deliberately not failpointed:
    /// the entry-durability failpoint models "this secret's barrier fails",
    /// and if it also fired during setup every such test would abort before
    /// reaching the step under test. Setup's own unconditional-retry barrier
    /// has its own coverage
    /// (`retry_on_existing_level_still_attempts_parent_fsync`).
    fn fsync_unhooked(&self) -> std::io::Result<()> {
        // SAFETY: valid open fd.
        let r = unsafe { libc::fsync(self.fd.as_raw_fd()) };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Create `name` exclusively, write `bytes`, and `fsync` the file.
    /// Create `name` exclusively, write `bytes`, `fsync`, and return the
    /// still-OPEN descriptor together with its metadata.
    ///
    /// Returning the open file is load-bearing, not a convenience: while a
    /// descriptor references an inode the kernel cannot free it, so its
    /// inode number cannot be recycled. Closing the scratch file before
    /// publishing (what this used to do) let the inode be freed — and Linux
    /// promptly hands the same inode number to the next file created at that
    /// name, so a substituted file compared EQUAL under dev+ino and the
    /// post-publish identity check silently passed. macOS/APFS does not
    /// recycle that aggressively, which is why the defect was invisible
    /// there and only surfaced on the Linux gate. Holding the descriptor
    /// makes the check sound on both, without relying on a platform's
    /// allocation policy.
    fn create_new_file(
        &self,
        name: &OsStr,
        mode: libc::mode_t,
        bytes: &[u8],
    ) -> std::io::Result<(File, std::fs::Metadata)> {
        if let Some(e) = write_tmp_failpoint() {
            return Err(e);
        }
        let c = cstr(name)?;
        // O_RDWR, not O_WRONLY: the publish step CLONES from this descriptor
        // (macOS `fclonefileat`), which has to read it. A write-only scratch
        // fd fails there — and it failed silently in a way that looked like
        // a durability fault rather than a permissions one, because the
        // failed publish is classified as "no effect".
        //
        // This is also why the earlier standalone probe was not a faithful
        // control: it cloned from a fd opened read-only, so it measured a
        // mode this call site never uses. A control has to carry the same
        // flags as the real path or it answers a different question.
        // SAFETY: valid dir fd + valid C string; O_CREAT is paired with the
        // mode argument as required.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                libc::c_uint::from(mode),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fresh, valid, exclusively-owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        if let Err(e) = file.write_all(bytes) {
            drop(file);
            let _ = self.unlinkat(name);
            return Err(e);
        }
        if let Err(e) = file.sync_all() {
            drop(file);
            let _ = self.unlinkat(name);
            return Err(e);
        }
        // Identity of exactly what we wrote, captured from the fd we wrote
        // it through — the anchor for the post-publish inode proof. The file
        // is returned still open so that inode stays pinned.
        let meta = file.metadata()?;
        Ok((file, meta))
    }

    /// Publish the scratch file as `to`, failing rather than replacing if
    /// `to` already exists.
    ///
    /// On Linux the link is made from the OPEN DESCRIPTOR via
    /// `/proc/self/fd/N`, so the inode published is exactly the one this
    /// call wrote — the substitution window is eliminated rather than
    /// detected afterwards. (`AT_EMPTY_PATH` would express the same thing
    /// directly but requires `CAP_DAC_READ_SEARCH`, which a service user
    /// does not have; the `/proc` form is the unprivileged equivalent.)
    ///
    /// On macOS the equivalent is `fclonefileat`, which clones from the open
    /// descriptor and refuses an existing destination with `EEXIST` — so it
    /// supplies BOTH halves this protocol needs (exact-inode source and
    /// create-only semantics) in one call. Both were measured on this
    /// hardware before being relied on, rather than taken from the man page.
    ///
    /// Every other target FAILS CLOSED with `Unsupported`. There is
    /// deliberately no name-based fallback: publishing by name can only
    /// DETECT a substituted source afterwards, never prevent it, and
    /// silently degrading to it would leave callers believing they had the
    /// stronger guarantee the two supported platforms actually provide.
    #[cfg(target_os = "linux")]
    fn publish_from_fd(&self, scratch: &File, _from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        let proc_path = CString::new(format!("/proc/self/fd/{}", scratch.as_raw_fd()))
            .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "fd path contains NUL"))?;
        let to_c = cstr(to)?;
        // SAFETY: `proc_path` names this process's own open descriptor;
        // `self.fd` is a valid directory fd; both C strings outlive the call.
        // AT_SYMLINK_FOLLOW is required so the /proc symlink resolves to the
        // target inode rather than being linked as a symlink.
        let r = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                proc_path.as_ptr(),
                self.fd.as_raw_fd(),
                to_c.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn publish_from_fd(&self, scratch: &File, _from: &OsStr, to: &OsStr) -> std::io::Result<()> {
        let to_c = cstr(to)?;
        // SAFETY: `scratch` is an open regular-file descriptor owned by the
        // caller for the whole call; `self.fd` is an open directory fd;
        // `to_c` is a valid NUL-terminated name within it. Flags 0 is the
        // documented default clone behaviour.
        let r = unsafe {
            libc::fclonefileat(scratch.as_raw_fd(), self.fd.as_raw_fd(), to_c.as_ptr(), 0)
        };
        if r < 0 {
            // EEXIST here is create-only refusal, not an I/O fault; the
            // caller maps it to a conflict exactly as it maps `linkat`'s.
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Fail closed on every target without a measured exact-publish
    /// primitive. Returning `Unsupported` rather than degrading to a
    /// name-based link is the point: a weaker mechanism that still reports
    /// success would hand callers a guarantee this crate cannot keep.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn publish_from_fd(&self, _scratch: &File, _from: &OsStr, _to: &OsStr) -> std::io::Result<()> {
        Err(std::io::Error::new(
            ErrorKind::Unsupported,
            "create_only requires an exact-publish primitive (Linux O_TMPFILE/linkat-from-fd \
             or macOS fclonefileat); this target has neither",
        ))
    }

    // The name-based `linkat(dirfd, from, dirfd, to, 0)` publish that used
    // to live here is DELETED, not merely unused. It resolved its source by
    // NAME, so it could only detect a substituted scratch file after the
    // fact; both supported targets now publish from the exact descriptor and
    // every other target fails closed. Leaving a weaker publish reachable is
    // how a future edit silently reintroduces the window.

    fn unlinkat(&self, name: &OsStr) -> std::io::Result<()> {
        let c = cstr(name)?;
        // SAFETY: valid dir fd + valid C string.
        let r = unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Open a leaf secret file for reading with `O_NOFOLLOW` and validate,
    /// via `fstat` on the resulting fd (not a second path lookup), that it is
    /// a regular file with mode `0600` owned by this process's effective uid.
    fn open_file_read_nofollow(&self, name: &OsStr) -> std::io::Result<SecureOpen> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let c = cstr(name)?;
        // SAFETY: valid dir fd + valid C string.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == ErrorKind::NotFound {
                return Ok(SecureOpen::NotFound);
            }
            // O_NOFOLLOW makes the open fail with ELOOP (or EMLINK on some
            // BSD-derived systems) when the final component is a symlink —
            // that IS the violation to fail closed on, not an absence.
            if e.raw_os_error() == Some(libc::ELOOP) || e.raw_os_error() == Some(libc::EMLINK) {
                return Ok(SecureOpen::SecurityViolation(
                    "refusing to follow a symlink at the secret's own path".into(),
                ));
            }
            return Err(e);
        }
        // SAFETY: fresh, valid, exclusively-owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
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
        // SAFETY: `geteuid` takes no arguments, cannot fail, and has no
        // preconditions.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Ok(SecureOpen::SecurityViolation(format!(
                "expected owner uid {euid}, found {}",
                meta.uid()
            )));
        }
        Ok(SecureOpen::Found(file, meta))
    }

    /// `fstatat(..., AT_SYMLINK_NOFOLLOW)` for the closing dev+ino check.
    fn stat_at_nofollow(&self, name: &OsStr) -> std::io::Result<Option<std::fs::Metadata>> {
        match self.open_file_read_nofollow(name)? {
            SecureOpen::Found(_, meta) => Ok(Some(meta)),
            SecureOpen::NotFound | SecureOpen::SecurityViolation(_) => Ok(None),
        }
    }

    /// Open (creating if needed) the sidecar lock file for `flock`.
    ///
    /// Two steps rather than one `O_CREAT | O_NOFOLLOW` open: creation is
    /// attempted with `O_EXCL` (tolerating `EEXIST`, since concurrent callers
    /// legitimately race to make the same lock file), and the descriptor we
    /// actually lock is then obtained by a separate `O_NOFOLLOW` open. The
    /// combined form is not portable — `O_CREAT` together with `O_NOFOLLOW`
    /// does not reliably create a missing file across the platforms this
    /// crate targets, which showed up here as a spurious `ENOENT` under
    /// concurrency. Splitting them keeps the symlink protection exactly where
    /// it matters (the open whose fd we use) without depending on that
    /// combination's behaviour.
    fn open_lock_file(&self) -> std::io::Result<File> {
        let c = cstr(OsStr::new(LOCK_FILE_NAME))?;
        // SAFETY: valid dir fd + valid C string; O_CREAT paired with a mode.
        let created = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                libc::c_uint::from(0o600u16),
            )
        };
        if created >= 0 {
            // SAFETY: fresh, valid descriptor; closed immediately.
            drop(unsafe { File::from_raw_fd(created) });
        } else {
            let e = std::io::Error::last_os_error();
            if e.kind() != ErrorKind::AlreadyExists {
                return Err(e);
            }
        }

        // SAFETY: valid dir fd + valid C string.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fresh, valid, exclusively-owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

/// Holds an advisory `flock` for as long as it is alive. Closing the
/// descriptor on drop releases the lock, so no explicit unlock is needed.
#[cfg(unix)]
#[derive(Debug)]
struct FlockGuard {
    _file: File,
}

#[cfg(unix)]
#[allow(unsafe_code)]
impl FlockGuard {
    fn acquire(dir: &DirHandle, exclusive: bool) -> std::io::Result<Self> {
        let file = dir.open_lock_file()?;
        let op = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        // SAFETY: `file` owns a valid open descriptor for the duration.
        let r = unsafe { libc::flock(file.as_raw_fd(), op) };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { _file: file })
    }
}

// ---------------------------------------------------------------------------
// Filesystem allowlist gate (unix).
// ---------------------------------------------------------------------------

/// Refuses to make durability claims on filesystems whose `fsync` semantics
/// this crate cannot vouch for.
///
/// This is an ALLOWLIST, deliberately, not a denylist: the failure mode being
/// guarded against is returning [`CreateOutcome::CreatedDurable`] on a
/// filesystem that silently does not persist — and a denylist can only ever
/// exclude the media that were thought of in advance, so anything new or
/// unrecognised would default to "trusted". Here anything unrecognised —
/// network, virtual, in-memory, or simply unknown — fails closed instead.
#[cfg(unix)]
mod fs_gate {
    use super::DirHandle;

    pub(super) enum Verdict {
        Allowed,
        Rejected(String),
    }

    #[cfg(test)]
    thread_local! {
        /// Test seam: forces the verdict without needing an exotic mount.
        static OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    #[cfg(test)]
    pub(super) fn force(allowed: Option<bool>) {
        OVERRIDE.with(|c| c.set(allowed));
    }

    #[cfg(test)]
    fn overridden() -> Option<bool> {
        OVERRIDE.with(std::cell::Cell::get)
    }

    #[cfg(not(test))]
    fn overridden() -> Option<bool> {
        None
    }

    pub(super) fn verdict(dir: &DirHandle) -> std::io::Result<Verdict> {
        match overridden() {
            Some(true) => return Ok(Verdict::Allowed),
            Some(false) => return Ok(Verdict::Rejected("injected-test-filesystem".into())),
            None => {}
        }
        real_verdict(dir)
    }

    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    fn real_verdict(dir: &DirHandle) -> std::io::Result<Verdict> {
        // SAFETY: `statfs` is a plain C struct with no invariants; zeroing it
        // is the documented way to prepare it for `fstatfs`.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: valid open fd + valid out-pointer to the struct above.
        let r = unsafe { libc::fstatfs(dir.raw_fd(), &raw mut st) };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // `f_fstypename` is a fixed-size C char array; on this target
        // `c_char` is signed, so go through `u8::try_from` rather than an
        // `as` cast that would silently wrap a high-bit byte.
        let name: String = st
            .f_fstypename
            .iter()
            .take_while(|c| **c != 0)
            .filter_map(|c| u8::try_from(*c).ok())
            .map(char::from)
            .collect();
        // APFS and HFS+ are the local persistent filesystems macOS actually
        // ships. Everything else (smbfs, nfs, webdav, exfat, msdos, devfs,
        // and anything new) fails closed.
        if matches!(name.as_str(), "apfs" | "hfs") {
            Ok(Verdict::Allowed)
        } else {
            Ok(Verdict::Rejected(name))
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    fn real_verdict(dir: &DirHandle) -> std::io::Result<Verdict> {
        // Magic numbers from linux/magic.h. Local, persistent, journalled or
        // CoW filesystems only.
        const EXT_SUPER_MAGIC: i64 = 0xEF53;
        const XFS_SUPER_MAGIC: i64 = 0x5846_5342;
        const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;
        const ZFS_SUPER_MAGIC: i64 = 0x2FC1_2FC1;
        const F2FS_SUPER_MAGIC: i64 = 0xF2F5_2010;

        // SAFETY: plain C struct, zeroing is the documented preparation.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: valid open fd + valid out-pointer.
        let r = unsafe { libc::fstatfs(dir.raw_fd(), &raw mut st) };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // `f_type` is `__fsword_t`, whose width varies by target: already
        // i64 on 64-bit (so the conversion is a no-op and clippy says so),
        // but narrower on 32-bit where it IS needed. Kept for portability
        // with the lint silenced rather than dropped for one target's
        // convenience.
        #[allow(clippy::useless_conversion)]
        let magic = i64::try_from(st.f_type).unwrap_or(0);
        if matches!(
            magic,
            EXT_SUPER_MAGIC
                | XFS_SUPER_MAGIC
                | BTRFS_SUPER_MAGIC
                | ZFS_SUPER_MAGIC
                | F2FS_SUPER_MAGIC
        ) {
            Ok(Verdict::Allowed)
        } else {
            Ok(Verdict::Rejected(format!("magic {magic:#x}")))
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn real_verdict(_dir: &DirHandle) -> std::io::Result<Verdict> {
        Ok(Verdict::Rejected(
            "unknown platform (no statfs allowlist)".into(),
        ))
    }
}

#[cfg(unix)]
impl DirHandle {
    fn raw_fd(&self) -> libc::c_int {
        self.fd.as_raw_fd()
    }
}

// ---------------------------------------------------------------------------
// Deterministic in-process fault injection (test builds only).
// ---------------------------------------------------------------------------

// Five failpoints matching the five real steps that can fail independently:
// the scratch write, the publish `linkat`, the directory `fsync`, the file's
// own `fsync`, and the scratch cleanup. Thread-local so the default parallel
// `cargo test` never leaks one test's armed failpoint into another, and
// STICKY (armed until explicitly disarmed) rather than one-shot: `create_only`
// legitimately performs a durability barrier more than once within a single
// call (install, then again in the stabilize fallback), and a one-shot
// failpoint was silently consumed by the first, letting the call self-heal in
// a way that made "this barrier stays down" impossible to simulate.
//
// No child process and no pipe: the injected `io::Error` and its `ErrorKind`
// are the same values production code already branches on, so assertions
// exercise the real classification logic rather than a simulation of it.
#[cfg(test)]
mod failpoints {
    use std::cell::Cell;
    use std::io;

    thread_local! {
        static WRITE_TMP: Cell<Option<io::ErrorKind>> = const { Cell::new(None) };
        static PUBLISH_LINK: Cell<Option<io::ErrorKind>> = const { Cell::new(None) };
        static DIR_FSYNC: Cell<Option<io::ErrorKind>> = const { Cell::new(None) };
        static FILE_FSYNC: Cell<Option<io::ErrorKind>> = const { Cell::new(None) };
        static CLEANUP_SKIP: Cell<bool> = const { Cell::new(false) };
        static POST_COMPARE_SWAP: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn arm_write_tmp(kind: io::ErrorKind) {
        WRITE_TMP.with(|c| c.set(Some(kind)));
    }
    pub(crate) fn disarm_write_tmp() {
        WRITE_TMP.with(|c| c.set(None));
    }
    pub(crate) fn peek_write_tmp() -> Option<io::ErrorKind> {
        WRITE_TMP.with(Cell::get)
    }

    /// While armed, every publish `linkat` has its RESULT replaced with the
    /// injected error regardless of whether the real call succeeded —
    /// simulating "the operation landed but we were told it failed", not
    /// merely "the operation never ran".
    pub(crate) fn arm_publish_link(kind: io::ErrorKind) {
        PUBLISH_LINK.with(|c| c.set(Some(kind)));
    }
    pub(crate) fn disarm_publish_link() {
        PUBLISH_LINK.with(|c| c.set(None));
    }
    pub(crate) fn peek_publish_link() -> Option<io::ErrorKind> {
        PUBLISH_LINK.with(Cell::get)
    }

    pub(crate) fn arm_dir_fsync(kind: io::ErrorKind) {
        DIR_FSYNC.with(|c| c.set(Some(kind)));
    }
    pub(crate) fn disarm_dir_fsync() {
        DIR_FSYNC.with(|c| c.set(None));
    }
    pub(crate) fn peek_dir_fsync() -> Option<io::ErrorKind> {
        DIR_FSYNC.with(Cell::get)
    }

    pub(crate) fn arm_file_fsync(kind: io::ErrorKind) {
        FILE_FSYNC.with(|c| c.set(Some(kind)));
    }
    pub(crate) fn disarm_file_fsync() {
        FILE_FSYNC.with(|c| c.set(None));
    }
    pub(crate) fn peek_file_fsync() -> Option<io::ErrorKind> {
        FILE_FSYNC.with(Cell::get)
    }

    /// While armed, `attempt_install` skips its own scratch cleanup —
    /// simulating a crash in exactly the window
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

    /// While armed, the reinspection swaps the file for a different inode
    /// immediately after the content comparison — the precise race the
    /// closing dev+ino check exists to catch.
    pub(crate) fn arm_post_compare_swap() {
        POST_COMPARE_SWAP.with(|c| c.set(true));
    }
    pub(crate) fn disarm_post_compare_swap() {
        POST_COMPARE_SWAP.with(|c| c.set(false));
    }
    pub(crate) fn peek_post_compare_swap() -> bool {
        POST_COMPARE_SWAP.with(Cell::get)
    }

    thread_local! {
        static SUBSTITUTE_SCRATCH: Cell<bool> = const { Cell::new(false) };
        static SUBSTITUTE_FIRED: Cell<bool> = const { Cell::new(false) };
    }

    /// While armed, the scratch NAME is unlinked and re-created as a
    /// DIFFERENT inode with different content, between the scratch file's
    /// write+fsync and its publication.
    ///
    /// Both supported publishes now take their source from the retained
    /// descriptor rather than from this name, so the point of the hook has
    /// changed: it no longer probes a window the post-publish inode proof
    /// has to *catch*, it proves the window is not there to be exploited.
    pub(crate) fn arm_substitute_scratch() {
        SUBSTITUTE_SCRATCH.with(|c| c.set(true));
        SUBSTITUTE_FIRED.with(|c| c.set(false));
    }
    pub(crate) fn disarm_substitute_scratch() {
        SUBSTITUTE_SCRATCH.with(|c| c.set(false));
    }
    pub(crate) fn peek_substitute_scratch() -> bool {
        SUBSTITUTE_SCRATCH.with(Cell::get)
    }
    /// Set by the hook only once the foreign inode is actually in place.
    ///
    /// Without this the test would be vacuous on any platform whose expected
    /// outcome is a SUCCESS: "published our own bytes" is equally what you
    /// observe when the substitution silently never happened. The hook used
    /// to discard both of its syscall results with `let _`, so that was a
    /// real possibility rather than a theoretical one.
    pub(crate) fn note_substitute_fired() {
        SUBSTITUTE_FIRED.with(|c| c.set(true));
    }
    pub(crate) fn peek_substitute_fired() -> bool {
        SUBSTITUTE_FIRED.with(Cell::get)
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
fn dir_fsync_failpoint() -> Option<std::io::Error> {
    failpoints::peek_dir_fsync().map(|k| std::io::Error::new(k, "injected failpoint: dir-fsync"))
}
#[cfg(not(test))]
fn dir_fsync_failpoint() -> Option<std::io::Error> {
    None
}

#[cfg(test)]
fn file_fsync_failpoint() -> Option<std::io::Error> {
    failpoints::peek_file_fsync().map(|k| std::io::Error::new(k, "injected failpoint: file-fsync"))
}
#[cfg(not(test))]
fn file_fsync_failpoint() -> Option<std::io::Error> {
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
fn post_compare_hook(dir: &DirHandle, name: &str) {
    if !failpoints::peek_post_compare_swap() {
        return;
    }
    // Replace the file with a fresh inode holding identical bytes: content
    // still matches, but it is no longer the file we verified.
    let n = OsStr::new(name);
    let mut bytes = Vec::new();
    if let Ok(SecureOpen::Found(mut f, _)) = dir.open_file_read_nofollow(n) {
        let _ = f.read_to_end(&mut bytes);
    }
    let _ = dir.unlinkat(n);
    let _ = dir.create_new_file(n, 0o600, &bytes);
}

#[cfg(all(not(test), unix))]
fn post_compare_hook(_dir: &DirHandle, _name: &str) {}

#[cfg(all(test, unix))]
fn substitute_scratch_hook(dir: &DirHandle, tmp_name: &str) {
    if !failpoints::peek_substitute_scratch() {
        return;
    }
    // Replace the scratch entry with a different inode holding different
    // bytes, exactly as an attacker (or a racing sweep plus a re-creation)
    // could between our write+fsync and our publish.
    //
    // Both results are checked, not discarded: the fired flag is what makes
    // the calling test non-vacuous, so it must mean "the foreign inode is
    // really in place", never "we attempted it".
    let n = OsStr::new(tmp_name);
    if dir.unlinkat(n).is_ok()
        && dir
            .create_new_file(n, 0o600, b"substituted-by-someone-else")
            .is_ok()
    {
        failpoints::note_substitute_fired();
    }
}

#[cfg(all(not(test), unix))]
fn substitute_scratch_hook(_dir: &DirHandle, _tmp_name: &str) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Random-suffixed account label so parallel and repeated runs never
    /// collide on shared on-disk state.
    fn random_account(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        format!("{prefix}.{}.{nanos}.{n}", std::process::id())
    }

    /// Disarms a failpoint on drop — guaranteed even on assertion panic,
    /// which matters because the failpoints are thread-locals and the
    /// default test harness reuses OS threads across tests.
    struct FailpointGuard(fn());
    impl Drop for FailpointGuard {
        fn drop(&mut self) {
            (self.0)();
        }
    }

    struct FsGateGuard;
    impl Drop for FsGateGuard {
        fn drop(&mut self) {
            fs_gate::force(None);
        }
    }

    // -- baseline set/get -------------------------------------------------

    #[test]
    fn set_uses_owner_only_file_and_dir() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "household");
        ks.set("acct", b"secret-bytes").unwrap();

        let file = ks.path_for("acct");
        assert_eq!(mode_of(&file), 0o600);
        assert_eq!(mode_of(file.parent().unwrap()), 0o700);
    }

    #[test]
    fn set_tightens_preexisting_loose_dir() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "household");
        let dir = ks.path_for("acct").parent().unwrap().to_path_buf();
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();

        ks.set("acct", b"secret-bytes").unwrap();
        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    fn set_get_round_trip() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        ks.set("a", b"hello world").unwrap();
        assert_eq!(ks.get("a").unwrap(), b"hello world");
    }

    // -- create_only happy paths ------------------------------------------

    #[test]
    fn create_only_uses_owner_only_file_and_dir_and_leaves_no_scratch() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "household");
        assert_eq!(
            ks.create_only("acct", b"secret-bytes").unwrap(),
            CreateOutcome::CreatedDurable
        );

        let file = ks.path_for("acct");
        assert_eq!(mode_of(&file), 0o600);
        assert_eq!(mode_of(file.parent().unwrap()), 0o700);
        let leftovers: Vec<_> = fs::read_dir(file.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "scratch file not cleaned: {leftovers:?}"
        );
    }

    #[test]
    fn create_only_different_value_is_conflict_and_leaves_winner_intact() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("conflict");

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
        let account = random_account("idempotent");

        assert_eq!(
            ks.create_only(&account, b"same-bytes").unwrap(),
            CreateOutcome::CreatedDurable
        );
        assert_eq!(
            ks.create_only(&account, b"same-bytes").unwrap(),
            CreateOutcome::ExistingExactDurable
        );
    }

    #[test]
    fn create_only_succeeds_again_after_delete() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("recreate");

        ks.create_only(&account, b"v1").unwrap();
        ks.delete(&account).unwrap();
        assert_eq!(
            ks.create_only(&account, b"v2").unwrap(),
            CreateOutcome::CreatedDurable
        );
        assert_eq!(ks.get(&account).unwrap(), b"v2");
    }

    // -- concurrency ------------------------------------------------------

    #[test]
    fn create_only_concurrent_same_value_all_converge_durable() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let td = tempfile::tempdir().unwrap();
        let ks = Arc::new(FileKeystore::new(td.path(), "svc"));
        let account = random_account("race-same");
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
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == CreateOutcome::ExistingExactDurable)
                .count(),
            workers - 1
        );
        assert_eq!(ks.get(&account).unwrap(), b"identical-value");
    }

    #[test]
    fn create_only_concurrent_different_values_one_winner_rest_conflict() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let td = tempfile::tempdir().unwrap();
        let ks = Arc::new(FileKeystore::new(td.path(), "svc"));
        let account = random_account("race-diff");
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
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == CreateOutcome::Conflict)
                .count(),
            workers - 1
        );
    }

    /// C: the lock must actually exclude, not merely be documented. Sweepers
    /// run concurrently with creators; if the exclusive/shared lock did not
    /// hold, a sweep could unlink a live scratch file between its creation
    /// and its `linkat`, and that creator would report something other than
    /// a clean install.
    #[test]
    fn sweep_never_races_a_live_create() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let td = tempfile::tempdir().unwrap();
        let ks = Arc::new(FileKeystore::new(td.path(), "svc"));
        let creators = 6;
        let sweepers = 3;
        let barrier = Arc::new(Barrier::new(creators + sweepers));

        let creator_handles: Vec<_> = (0..creators)
            .map(|i| {
                let ks = ks.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    let account = format!("race-sweep-{i}");
                    barrier.wait();
                    let mut outcomes = Vec::new();
                    for _ in 0..20 {
                        outcomes.push(ks.create_only(&account, b"value").unwrap());
                    }
                    outcomes
                })
            })
            .collect();

        let sweeper_handles: Vec<_> = (0..sweepers)
            .map(|_| {
                let ks = ks.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..20 {
                        let guard = ks.lock_for_sweep().unwrap();
                        ks.sweep_orphaned_create_attempts(&guard).unwrap();
                    }
                })
            })
            .collect();

        for h in sweeper_handles {
            h.join().unwrap();
        }
        for (i, h) in creator_handles.into_iter().enumerate() {
            let outcomes = h.join().unwrap();
            // First call installs; every later call re-observes the same
            // bytes. A sweep stealing a live scratch file would show up as
            // KnownNoEffect or MayHaveTakenEffect here.
            assert_eq!(outcomes[0], CreateOutcome::CreatedDurable, "creator {i}");
            for o in &outcomes[1..] {
                assert_eq!(*o, CreateOutcome::ExistingExactDurable, "creator {i}");
            }
            assert_eq!(ks.get(&format!("race-sweep-{i}")).unwrap(), b"value");
        }
    }

    #[test]
    fn sweep_rejects_a_guard_from_another_store() {
        let td = tempfile::tempdir().unwrap();
        let a = FileKeystore::new(td.path(), "svc-a");
        let b = FileKeystore::new(td.path(), "svc-b");
        a.create_only("acct", b"v").unwrap();
        b.create_only("acct", b"v").unwrap();

        let guard_for_b = b.lock_for_sweep().unwrap();
        match a.sweep_orphaned_create_attempts(&guard_for_b) {
            Err(KeystoreError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    // -- failpoint matrix -------------------------------------------------

    /// (11) A pre-publish failure must NOT be flattened into a bare
    /// `KnownNoEffect`: that describes the effect correctly but destroys the
    /// operational cause, and "nothing happened because the disk is full or
    /// the directory is unwritable" is exactly what an operator needs to
    /// see. The typed error carries the cause; the absence of the entry is
    /// asserted separately.
    #[test]
    fn failpoint_write_tmp_preserves_the_operational_cause() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-write-tmp");
        let _g = FailpointGuard(failpoints::disarm_write_tmp);

        failpoints::arm_write_tmp(ErrorKind::PermissionDenied);
        match ks.create_only(&account, b"never-written") {
            Err(KeystoreError::Io { kind, .. }) => {
                assert!(
                    kind.contains("permission denied"),
                    "the underlying cause must survive, got kind={kind}"
                );
            }
            other => panic!("expected the operational cause to propagate, got {other:?}"),
        }
        failpoints::disarm_write_tmp();
        // And it really did nothing.
        assert!(matches!(
            ks.get(&account),
            Err(KeystoreError::NotFound { .. })
        ));
    }

    #[test]
    fn failpoint_publish_link_reports_error_but_real_link_landed() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-link");
        let _g = FailpointGuard(failpoints::disarm_publish_link);

        failpoints::arm_publish_link(ErrorKind::TimedOut);
        // The real `linkat` still runs — only the RESULT is replaced. The
        // stabilize fallback's proof does not go through `linkat`, so this
        // resolves deterministically on THIS call, not merely "eventually".
        assert_eq!(
            ks.create_only(&account, b"actually-landed").unwrap(),
            CreateOutcome::ExistingExactDurable
        );
        assert_eq!(
            ks.create_only(&account, b"actually-landed").unwrap(),
            CreateOutcome::ExistingExactDurable
        );
    }

    #[test]
    fn failpoint_publish_link_different_retry_value_is_conflict() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-link-diff");
        let _g = FailpointGuard(failpoints::disarm_publish_link);

        failpoints::arm_publish_link(ErrorKind::TimedOut);
        let _ = ks.create_only(&account, b"original-value").unwrap();
        assert_eq!(
            ks.create_only(&account, b"different-value").unwrap(),
            CreateOutcome::Conflict
        );
        assert_eq!(ks.get(&account).unwrap(), b"original-value");
    }

    #[test]
    fn failpoint_dir_fsync_is_ambiguous_then_converges_when_cleared() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-dir-fsync");
        let _g = FailpointGuard(failpoints::disarm_dir_fsync);

        failpoints::arm_dir_fsync(ErrorKind::Other);
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::MayHaveTakenEffect
        );
        failpoints::disarm_dir_fsync();
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::ExistingExactDurable
        );
    }

    /// Ported verbatim from the independent audit's RED for b3849669. A key
    /// that is merely VISIBLE after a failed directory barrier must not be
    /// reported as an existing durable key by the opaque layer — that is the
    /// same visibility-is-not-durability error this crate exists to prevent
    /// one layer down, and the inspect-first shortcut had reintroduced it
    /// at the top.
    #[test]
    fn opaque_create_does_not_promote_visible_but_indeterminate_key() {
        use crate::opaque_p256::{ApprovedFallback, OpaqueP256Slots, Purpose, Slot, SlotOutcome};

        struct AuditPurpose;
        impl Purpose for AuditPurpose {
            const PURPOSE: &'static str = "audit/indeterminate";
        }

        let td = tempfile::tempdir().unwrap();
        let approval = ApprovedFallback::for_reason("audit-only fixture");
        let slots = OpaqueP256Slots::approved_plaintext_file(td.path(), "audit", &approval);
        let slot = Slot::<AuditPurpose>::new("same-slot").unwrap();
        let _g = FailpointGuard(failpoints::disarm_dir_fsync);

        failpoints::arm_dir_fsync(ErrorKind::Other);
        let (outcome, binding) = slots.create_or_inspect(&slot).unwrap();
        assert_eq!(
            outcome,
            SlotOutcome::Unresolved,
            "visibility after failed directory fsync is not durability"
        );
        assert!(binding.is_none(), "no usable binding may escape ambiguity");
    }

    #[test]
    fn failpoint_file_fsync_is_ambiguous_then_converges_when_cleared() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-file-fsync");
        let _g = FailpointGuard(failpoints::disarm_file_fsync);

        // Install cleanly first, then make only the stabilize path fail.
        ks.create_only(&account, b"value").unwrap();
        failpoints::arm_file_fsync(ErrorKind::Other);
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::MayHaveTakenEffect
        );
        failpoints::disarm_file_fsync();
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::ExistingExactDurable
        );
    }

    #[test]
    fn failpoint_cleanup_skip_leaves_marker_that_sweep_recovers() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fp-cleanup");
        let _g = FailpointGuard(failpoints::disarm_cleanup_skip);

        failpoints::arm_cleanup_skip();
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::CreatedDurable
        );
        failpoints::disarm_cleanup_skip();

        let dir = ks.path_for(&account).parent().unwrap().to_path_buf();
        let leftover: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert_eq!(leftover.len(), 1, "simulated crash must leave one marker");

        let guard = ks.lock_for_sweep().unwrap();
        // The marker was written by a real create_only, so its content DOES
        // match the digest bound into its name — it is verifiably ours and
        // must be removed, not quarantined. That distinction is the whole
        // point of the digest check now that it actually works.
        assert_eq!(
            ks.sweep_orphaned_create_attempts(&guard).unwrap(),
            SweepReport {
                removed: 1,
                quarantined: 0
            }
        );
        assert_eq!(ks.get(&account).unwrap(), b"value");
    }

    /// A: the closing dev+ino check must catch a file substituted AFTER its
    /// content was compared. Content still matches; identity does not.
    #[test]
    fn post_compare_inode_swap_downgrades_to_may_have_taken_effect() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("swap");
        let _g = FailpointGuard(failpoints::disarm_post_compare_swap);

        ks.create_only(&account, b"value").unwrap();
        failpoints::arm_post_compare_swap();
        assert_eq!(
            ks.create_only(&account, b"value").unwrap(),
            CreateOutcome::MayHaveTakenEffect,
            "an inode swapped in after the comparison must not be reported durable"
        );
    }

    // -- A: symlink hardening at every level ------------------------------

    #[test]
    fn symlink_at_leaf_fails_closed() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("symlink-leaf");

        ks.preflight().unwrap();
        let final_path = ks.path_for(&account);
        let elsewhere = td.path().join("elsewhere.bin");
        fs::write(&elsewhere, b"attacker-controlled").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &final_path).unwrap();

        match ks.create_only(&account, b"value") {
            Err(KeystoreError::SecurityViolation { .. }) => {}
            other => panic!("expected SecurityViolation, got {other:?}"),
        }
        assert_eq!(fs::read(&elsewhere).unwrap(), b"attacker-controlled");
    }

    #[test]
    fn symlink_at_service_level_fails_closed() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");

        // Plant a symlink where the <service> directory should be.
        let secrets = td.path().join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        let target = td.path().join("attacker-dir");
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, secrets.join("svc")).unwrap();

        let result = ks.create_only("acct", b"value");
        assert!(
            result.is_err(),
            "a symlink at the service level must fail the descent, got {result:?}"
        );
        // Nothing may have been written through the symlink.
        assert!(fs::read_dir(&target).unwrap().next().is_none());
    }

    #[test]
    fn symlink_at_secrets_level_fails_closed() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");

        let target = td.path().join("attacker-secrets");
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, td.path().join("secrets")).unwrap();

        let result = ks.create_only("acct", b"value");
        assert!(
            result.is_err(),
            "a symlink at the secrets level must fail the descent, got {result:?}"
        );
        assert!(fs::read_dir(&target).unwrap().next().is_none());
    }

    // -- B: filesystem gate ------------------------------------------------

    #[test]
    fn fs_gate_rejects_unlisted_filesystem_before_any_mutation() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("fs-gate");
        let _g = FsGateGuard;

        fs_gate::force(Some(false));
        match ks.create_only(&account, b"value") {
            Err(KeystoreError::Unsupported { hint }) => {
                assert!(hint.contains("allowlist"), "hint={hint}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        // Fail closed means fail BEFORE mutating: nothing on disk.
        assert!(!ks.path_for(&account).exists());
    }

    #[test]
    fn fs_gate_allows_this_hosts_real_filesystem() {
        // Measured, not injected: the tempdir this suite runs on must pass
        // the real statfs allowlist, otherwise every other create_only test
        // here would be passing only by accident of the override.
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        ks.preflight()
            .expect("this host's temp filesystem should be on the allowlist");
    }

    // -- scratch-name parsing / sweep --------------------------------------

    #[test]
    fn orphaned_scratch_name_matcher_is_exact() {
        let digest = content_digest_hex(Path::new("llm.api_key.anthropic.bin"), b"v");
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
        assert!(parse_create_attempt_tmp_name("acct.bin.tmp.1.2.3.4.short").is_none());
        // The sweep must never be able to remove its own lock file.
        assert!(parse_create_attempt_tmp_name(LOCK_FILE_NAME).is_none());
    }

    #[test]
    fn sweep_removes_only_orphaned_scratch_files() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("sweep");

        ks.create_only(&account, b"real-value").unwrap();

        let final_path = ks.path_for(&account);
        let encoded = sanitize_path_segment(&account);
        let final_name = format!("{encoded}.bin");
        // Digest over the bare FINAL NAME — the exact same value
        // `tmp_attempt_path_name` uses. Deriving it from anything else (a
        // full path, or a stem with `.bin` re-appended) is what made the
        // real check vacuous before.
        let digest = content_digest_hex(Path::new(&final_name), b"leaked-plaintext-from-a-crash");
        let orphan =
            final_path.with_file_name(format!("{final_name}.tmp.99999.123456789.0.0.{digest}"));
        fs::write(&orphan, b"leaked-plaintext-from-a-crash").unwrap();
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();

        let unrelated = final_path.with_file_name("unrelated.bin");
        fs::write(&unrelated, b"not ours").unwrap();

        let guard = ks.lock_for_sweep().unwrap();
        assert_eq!(
            ks.sweep_orphaned_create_attempts(&guard).unwrap(),
            SweepReport {
                removed: 1,
                quarantined: 0
            },
            "a scratch file whose content matches its own name's digest is verifiably \
             ours and must be removed"
        );

        assert!(!orphan.exists());
        assert!(unrelated.exists());
        assert_eq!(ks.get(&account).unwrap(), b"real-value");
    }

    /// Non-vacuity guard for the digest check: if the comparison were still
    /// broken (or removal were unconditional, as it used to be), this file
    /// would be deleted and the assertion would fail. It only passes when
    /// the digest genuinely distinguishes verified from unverified content.
    #[test]
    fn sweep_quarantines_rather_than_removes_a_digest_mismatch() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("sweep-mismatch");
        ks.preflight().unwrap();

        let final_path = ks.path_for(&account);
        let encoded = sanitize_path_segment(&account);
        let orphan =
            final_path.with_file_name(format!("{encoded}.bin.tmp.1.2.3.4.{}", "0".repeat(64)));
        fs::write(&orphan, b"corrupted").unwrap();
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();

        let guard = ks.lock_for_sweep().unwrap();
        assert_eq!(
            ks.sweep_orphaned_create_attempts(&guard).unwrap(),
            SweepReport {
                removed: 0,
                quarantined: 1
            }
        );
        assert!(
            orphan.exists(),
            "unverifiable content must be left for a human, not silently destroyed"
        );
    }

    #[test]
    fn sweep_on_fresh_store_is_a_noop() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc-never-written-to");
        let guard = ks.lock_for_sweep().unwrap();
        assert_eq!(
            ks.sweep_orphaned_create_attempts(&guard).unwrap(),
            SweepReport::default()
        );
    }

    /// (10) Distinct labels must never share a file. The old sanitiser
    /// mapped `/`, `\` and `_` onto the same character, so these three
    /// accounts collided and could read each other's secrets.
    #[test]
    fn distinct_account_labels_never_share_a_file() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");

        let labels = ["a/b", "a\\b", "a_b", "a%2Fb", "a%b"];
        for (i, label) in labels.iter().enumerate() {
            assert_eq!(
                ks.create_only(label, format!("value-{i}").as_bytes())
                    .unwrap(),
                CreateOutcome::CreatedDurable,
                "label {label:?} collided with an earlier one"
            );
        }
        for (i, label) in labels.iter().enumerate() {
            assert_eq!(ks.get(label).unwrap(), format!("value-{i}").as_bytes());
        }

        // And the encoding must keep every one of them inside the store.
        for label in labels {
            assert!(ks.path_for(label).starts_with(td.path()));
        }
    }

    /// (1) The publish step resolves its source by NAME, so a substitution
    /// between write+fsync and `linkat` would otherwise publish bytes this
    /// call never wrote. The post-publish inode proof must catch it — and
    /// the caller must never be told its own value was installed durably.
    #[test]
    fn scratch_substituted_before_publish_is_never_reported_as_our_install() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "svc");
        let account = random_account("substitute");
        let _g = FailpointGuard(failpoints::disarm_substitute_scratch);

        failpoints::arm_substitute_scratch();
        let outcome = ks.create_only(&account, b"our-own-value").unwrap();
        failpoints::disarm_substitute_scratch();

        // Non-vacuity FIRST, because on macOS the expected outcome below is a
        // success — and "published our own bytes" is exactly what a run where
        // the substitution never happened would also produce. Without this
        // the assertions would hold for the wrong reason.
        assert!(
            failpoints::peek_substitute_fired(),
            "the substitution hook never placed its foreign inode, so this test \
             proves nothing about surviving a substitution"
        );

        // THE invariant, on every platform: the substituted bytes must never
        // become the stored value, and the caller must never be told its own
        // bytes were installed when they were not. Both publishes now take
        // their source from the retained descriptor, so this is PREVENTION —
        // the attacker's content simply cannot reach the entry.
        assert_ne!(
            ks.get(&account).ok().as_deref(),
            Some(b"substituted-by-someone-else".as_slice()),
            "the substituted content must never become the stored value"
        );

        // The two mechanisms then differ in HOW they prevent it, and the
        // outcomes differ accordingly. Asserting one shared outcome would
        // mean asserting something false on one of the platforms.
        //
        // Linux links the exact inode from the fd. The hook unlinked the
        // scratch name, so that inode has no remaining links and `linkat`
        // refuses outright — nothing is installed at all.
        //
        // macOS CLONES from the fd, which does not depend on the name still
        // existing. Our own bytes are published successfully, so
        // CreatedDurable is the TRUTHFUL outcome here: the substitution
        // never touched what we wrote. (This assertion previously demanded
        // "never CreatedDurable", which was correct only for the older
        // name-based publish that could actually be tricked.)
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                outcome,
                CreateOutcome::KnownNoEffect,
                "linking from the held fd should refuse an unlinked scratch inode"
            );
            assert!(matches!(
                ks.get(&account),
                Err(KeystoreError::NotFound { .. })
            ));
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                outcome,
                CreateOutcome::CreatedDurable,
                "cloning from the held fd is immune to the scratch name being replaced"
            );
            assert_eq!(
                ks.get(&account).unwrap(),
                b"our-own-value",
                "the entry must hold exactly the bytes this call wrote"
            );
        }
    }

    // -- directory hierarchy ----------------------------------------------

    /// MEASUREMENT, not a guarantee.
    ///
    /// `create_only` publishes by linking a name on macOS and only detects
    /// substitution afterwards, which is weaker than Linux's link-from-fd.
    /// The candidate fix is `fclonefileat` (macOS) / `O_TMPFILE` + linkat
    /// (Linux), but whether either actually works depends on the filesystem
    /// and the uid the process really runs as — not on what the man page
    /// says. This probe exercises the primitive for real and PRINTS what
    /// happened, so the choice between mechanism and fallback rests on
    /// evidence from each host rather than on assumption.
    ///
    /// `#[ignore]` because it reports rather than asserts: run it with
    /// `cargo test -- --ignored --nocapture` on every target host.
    #[test]
    #[ignore = "measurement probe; run with --ignored --nocapture and read the output"]
    #[allow(unsafe_code)]
    fn probe_exact_publish_primitive_support() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path(), "probe");
        let dir = ks.open_secrets_dir().unwrap();

        println!("== exact-publish probe ==");
        println!("uid={} euid={}", nix_uid(), nix_euid());
        println!("dir={}", ks.secrets_dir().display());

        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let src_path = td.path().join("probe-src");
            {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&src_path)
                    .unwrap();
                f.write_all(b"probe").unwrap();
                f.sync_all().unwrap();
            }
            let src = OpenOptions::new().read(true).open(&src_path).unwrap();
            let dst = cstr(OsStr::new("cloned.bin")).unwrap();
            // SAFETY: `src` is an open regular-file fd; `dir` is an open
            // directory fd; `dst` is a valid C string naming an entry in it.
            let rc = unsafe { libc::fclonefileat(src.as_raw_fd(), dir.raw_fd(), dst.as_ptr(), 0) };
            if rc == 0 {
                println!("fclonefileat: OK (exact publish from fd is available)");
                // Does it refuse to replace an existing destination?
                // SAFETY: same argument validity as above.
                let again =
                    unsafe { libc::fclonefileat(src.as_raw_fd(), dir.raw_fd(), dst.as_ptr(), 0) };
                let err = std::io::Error::last_os_error();
                println!(
                    "fclonefileat onto existing dst: rc={again} err={:?} (EEXIST means \
                     create-only semantics hold)",
                    err.kind()
                );
            } else {
                println!(
                    "fclonefileat: FAILED err={:?} — exact publish NOT available here",
                    std::io::Error::last_os_error()
                );
            }
        }

        #[cfg(target_os = "linux")]
        {
            let dir_c = cstr(ks.secrets_dir().as_os_str()).unwrap();
            // SAFETY: valid C string naming an existing directory.
            let fd = unsafe {
                libc::open(
                    dir_c.as_ptr(),
                    libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                    libc::c_uint::from(0o600u16),
                )
            };
            if fd < 0 {
                println!(
                    "O_TMPFILE: FAILED err={:?} — falling back to the named-scratch path",
                    std::io::Error::last_os_error()
                );
            } else {
                // SAFETY: fresh owned descriptor.
                let tmp = unsafe { File::from_raw_fd(fd) };
                println!("O_TMPFILE: OK (anonymous scratch available)");
                let proc_path = CString::new(format!("/proc/self/fd/{}", tmp.as_raw_fd())).unwrap();
                let dst = cstr(OsStr::new("linked.bin")).unwrap();
                // SAFETY: proc path names our own fd; dir fd is valid.
                let rc = unsafe {
                    libc::linkat(
                        libc::AT_FDCWD,
                        proc_path.as_ptr(),
                        dir.raw_fd(),
                        dst.as_ptr(),
                        libc::AT_SYMLINK_FOLLOW,
                    )
                };
                // errno is only meaningful when the call FAILED. Printing
                // it unconditionally reports whatever stale value was left
                // by an earlier syscall, which reads exactly like a real
                // result — this probe did print a leftover "AlreadyExists"
                // next to a successful rc=0 before this was fixed.
                if rc == 0 {
                    println!("linkat(O_TMPFILE via /proc): OK (exact publish from fd available)");
                } else {
                    println!(
                        "linkat(O_TMPFILE via /proc): FAILED err={:?}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }

    #[allow(unsafe_code)]
    fn nix_uid() -> u32 {
        // SAFETY: getuid takes no arguments and cannot fail.
        unsafe { libc::getuid() }
    }
    #[allow(unsafe_code)]
    fn nix_euid() -> u32 {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn open_secrets_dir_creates_nested_missing_hierarchy() {
        let td = tempfile::tempdir().unwrap();
        let ks = FileKeystore::new(td.path().join("does/not/exist/yet"), "svc");
        ks.preflight().unwrap();
        assert_eq!(mode_of(&ks.secrets_dir()), 0o700);
    }

    /// Regression: the retry path must still attempt the parent `fsync` when
    /// a level already exists, rather than treating visibility as proof.
    /// Proven behaviourally by making the parent unopenable between calls.
    #[test]
    fn retry_on_existing_level_still_attempts_parent_fsync() {
        let td = tempfile::tempdir().unwrap();
        let state_dir = td.path().join("state");
        let ks = FileKeystore::new(&state_dir, "svc");
        ks.preflight().unwrap();

        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o000)).unwrap();
        let result = ks.preflight();
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            result.is_err(),
            "the already-exists path must still touch the parent, not skip it"
        );
    }
}
