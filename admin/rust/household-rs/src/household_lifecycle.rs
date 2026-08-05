//! Cross-process serialization for installation and teardown of `household/`.
//!
//! The lock lives in the stable state root, outside the `household/` subtree
//! that teardown renames. A read guard permits an operation against the
//! currently installed household; a write guard permits a lifecycle mutation.
//! The empty lock file is coordination only: its contents and lock state are
//! never replay authority, household identity, or evidence that a household
//! exists.
//!
//! The filesystem threat boundary is cooperative code running as the state
//! directory's owner. A same-UID process that bypasses this module and mutates
//! directory entries directly can defeat pathname-based coordination and is a
//! deployment violation, not an attacker this lock can exclude.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fs2::FileExt;
use rand::{RngCore, rngs::OsRng};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use thiserror::Error;

use crate::storage::HOUSEHOLD_SUBDIR;

/// Stable filename shared by every official household lifecycle participant.
pub const HOUSEHOLD_LIFECYCLE_LOCK_FILENAME: &str = ".household-lifecycle-v1.lock";
/// Durable teardown breadcrumb name in the state root.
pub const HOUSEHOLD_TEARDOWN_BREADCRUMB: &str = "household.tearing-down";
/// Stable state-root witness that distinguishes two observations of
/// "no installed household" across an intervening install/teardown cycle.
pub const HOUSEHOLD_LIFECYCLE_GENERATION_FILENAME: &str = ".household-lifecycle-generation-v1";

const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(5);
const GENERATION_VERSION: u8 = 1;
const GENERATION_TOKEN_BYTES: usize = 32;
const GENERATION_FILE_BYTES: usize = 1 + GENERATION_TOKEN_BYTES;
const GENERATION_TMP_PREFIX: &str = ".household-lifecycle-generation-v1.tmp.";

#[cfg(target_os = "linux")]
const EXT4_SUPER_MAGIC: i64 = 0x0000_EF53;
#[cfg(target_os = "linux")]
const XFS_SUPER_MAGIC: i64 = 0x5846_5342;
#[cfg(target_os = "linux")]
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;

/// Failure to establish or acquire the stable lifecycle lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum HouseholdLifecycleLockError {
    #[error("household lifecycle path is unsafe")]
    UnsafePath,
    #[error("household lifecycle requires a local persistent filesystem")]
    UnsupportedFilesystem,
    #[error("household lifecycle lock acquisition timed out")]
    LockTimeout,
    #[error("a household teardown breadcrumb requires exclusive recovery")]
    RecoveryRequired,
    #[error("household lifecycle I/O failed")]
    Io,
}

/// Fixed-width lifecycle witness captured by pre-household ceremonies.
///
/// This is not household authority. Its only purpose is to make absence
/// non-ABA: a candidate that observed generation `G0` cannot install after a
/// different process has advanced the state root through `G1`/`G2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HouseholdLifecycleGenerationV1([u8; GENERATION_TOKEN_BYTES]);

impl HouseholdLifecycleGenerationV1 {
    /// Decode the fixed-width token persisted in a candidate window.
    pub fn from_token_bytes(bytes: &[u8]) -> Result<Self, HouseholdLifecycleLockError> {
        let token: [u8; GENERATION_TOKEN_BYTES] = bytes
            .try_into()
            .map_err(|_| HouseholdLifecycleLockError::UnsafePath)?;
        Ok(Self(token))
    }

    /// Exact fixed-width bytes suitable for an on-disk ceremony snapshot.
    #[must_use]
    pub const fn token_bytes(&self) -> &[u8; GENERATION_TOKEN_BYTES] {
        &self.0
    }
}

#[derive(Debug)]
struct LifecycleInner {
    state_path: PathBuf,
    state_dir: File,
    lock_dev: u64,
    lock_ino: u64,
}

/// Handle to the stable state-root lifecycle lock.
///
/// Every acquisition opens a fresh file description. This matters for
/// `flock(2)`: cloned descriptors can share one open-file description and an
/// unlock by one caller could otherwise release another caller's protection.
#[derive(Clone, Debug)]
pub struct HouseholdLifecycleLock {
    inner: Arc<LifecycleInner>,
}

impl HouseholdLifecycleLock {
    /// Open or durably create the stable lock below a verified state root.
    pub fn open_verified(state_path: &Path) -> Result<Self, HouseholdLifecycleLockError> {
        let state_path =
            std::path::absolute(state_path).map_err(|_| HouseholdLifecycleLockError::Io)?;
        let state_dir = File::from(
            rustix::fs::open(
                &state_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(map_errno)?,
        );
        validate_state_root(&state_dir)?;
        validate_supported_persistent_filesystem(&state_dir)?;

        let lock = open_or_create_lock(&state_dir)?;
        validate_lock_file(&state_dir, &lock)?;
        // Unconditional: an earlier creator may have made the dirent visible
        // and then failed its parent barrier. Visibility is not durability.
        lock.sync_all()
            .map_err(|_| HouseholdLifecycleLockError::Io)?;
        sync_state_root_after_lock_open(&state_dir)?;
        if !named_lock_matches(&state_dir, &lock) {
            return Err(HouseholdLifecycleLockError::UnsafePath);
        }

        let metadata = lock
            .metadata()
            .map_err(|_| HouseholdLifecycleLockError::Io)?;
        Ok(Self {
            inner: Arc::new(LifecycleInner {
                state_path,
                state_dir,
                lock_dev: metadata.dev(),
                lock_ino: metadata.ino(),
            }),
        })
    }

    /// Acquire a shared guard, waiting without a caller deadline.
    pub fn lock_shared(&self) -> Result<LifecycleReadGuard, HouseholdLifecycleLockError> {
        self.acquire(LockKind::Shared, None)
            .map(|guard| LifecycleReadGuard { guard })
    }

    /// Acquire a shared guard no later than `deadline`.
    pub fn lock_shared_until(
        &self,
        deadline: Instant,
    ) -> Result<LifecycleReadGuard, HouseholdLifecycleLockError> {
        self.acquire(LockKind::Shared, Some(deadline))
            .map(|guard| LifecycleReadGuard { guard })
    }

    /// Acquire an exclusive guard, waiting without a caller deadline.
    pub fn lock_exclusive(&self) -> Result<LifecycleWriteGuard, HouseholdLifecycleLockError> {
        self.acquire(LockKind::Exclusive, None)
            .map(|guard| LifecycleWriteGuard { guard })
    }

    /// Acquire an exclusive guard no later than `deadline`.
    pub fn lock_exclusive_until(
        &self,
        deadline: Instant,
    ) -> Result<LifecycleWriteGuard, HouseholdLifecycleLockError> {
        self.acquire(LockKind::Exclusive, Some(deadline))
            .map(|guard| LifecycleWriteGuard { guard })
    }

    pub(crate) fn clone_state_dir(&self) -> Result<File, HouseholdLifecycleLockError> {
        self.inner
            .state_dir
            .try_clone()
            .map_err(|_| HouseholdLifecycleLockError::Io)
    }

    fn acquire(
        &self,
        kind: LockKind,
        deadline: Option<Instant>,
    ) -> Result<LifecycleGuard, HouseholdLifecycleLockError> {
        let file = open_existing_lock(&self.inner.state_dir)?;
        validate_lock_file(&self.inner.state_dir, &file)?;
        if !self.file_matches_expected(&file) || !named_lock_matches(&self.inner.state_dir, &file) {
            return Err(HouseholdLifecycleLockError::UnsafePath);
        }

        loop {
            let result = match kind {
                LockKind::Shared => FileExt::try_lock_shared(&file),
                LockKind::Exclusive => FileExt::try_lock_exclusive(&file),
            };
            match result {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if deadline.is_some_and(|limit| Instant::now() >= limit) {
                        return Err(HouseholdLifecycleLockError::LockTimeout);
                    }
                    std::thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(_) => return Err(HouseholdLifecycleLockError::Io),
            }
        }

        let guard = LifecycleGuard {
            file,
            inner: self.inner.clone(),
        };
        if !guard.binding_is_current() {
            return Err(HouseholdLifecycleLockError::UnsafePath);
        }
        if kind == LockKind::Shared && guard.teardown_breadcrumb_exists()? {
            return Err(HouseholdLifecycleLockError::RecoveryRequired);
        }
        Ok(guard)
    }

    fn file_matches_expected(&self, file: &File) -> bool {
        file.metadata().is_ok_and(|metadata| {
            metadata.dev() == self.inner.lock_dev && metadata.ino() == self.inner.lock_ino
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockKind {
    Shared,
    Exclusive,
}

#[derive(Debug)]
struct LifecycleGuard {
    file: File,
    inner: Arc<LifecycleInner>,
}

impl LifecycleGuard {
    fn binding_is_current(&self) -> bool {
        self.file.metadata().is_ok_and(|metadata| {
            metadata.dev() == self.inner.lock_dev
                && metadata.ino() == self.inner.lock_ino
                && named_lock_matches(&self.inner.state_dir, &self.file)
                && self.state_root_path_is_current()
        })
    }

    fn ensure_current(&self) -> Result<(), HouseholdLifecycleLockError> {
        if self.binding_is_current() {
            Ok(())
        } else {
            Err(HouseholdLifecycleLockError::UnsafePath)
        }
    }

    fn state_root_path_is_current(&self) -> bool {
        let Ok(reopened) = rustix::fs::open(
            &self.inner.state_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            return false;
        };
        same_file(&self.inner.state_dir, &File::from(reopened))
    }

    fn entry_exists(&self, name: &str) -> Result<bool, HouseholdLifecycleLockError> {
        match rustix::fs::statat(&self.inner.state_dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(_) => Err(HouseholdLifecycleLockError::Io),
        }
    }

    fn teardown_breadcrumb_exists(&self) -> Result<bool, HouseholdLifecycleLockError> {
        self.entry_exists(HOUSEHOLD_TEARDOWN_BREADCRUMB)
    }
}

impl Drop for LifecycleGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Shared lifecycle protection held by one installed-household operation.
#[derive(Debug)]
pub struct LifecycleReadGuard {
    guard: LifecycleGuard,
}

impl LifecycleReadGuard {
    pub(crate) fn binding_is_current(&self) -> bool {
        self.guard.binding_is_current()
    }

    /// Prove that `state_path` still names the state root protected by this
    /// shared guard.
    ///
    /// A generation token alone is deliberately not used as a state-root
    /// capability: even a 256-bit token is probabilistic identity, while the
    /// retained directory descriptor gives us an exact binding.
    pub(crate) fn verify_state_root(
        &self,
        state_path: &Path,
    ) -> Result<(), HouseholdLifecycleLockError> {
        let reopened = File::from(
            rustix::fs::open(
                state_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(map_errno)?,
        );
        if same_file(&self.guard.inner.state_dir, &reopened) {
            Ok(())
        } else {
            Err(HouseholdLifecycleLockError::UnsafePath)
        }
    }

    /// Read the fixed-width generation while this shared guard prevents a
    /// concurrent rotate. Pair-window snapshot operations use this to prove
    /// that their retained generation is still current for the whole I/O.
    pub fn lifecycle_generation(
        &self,
    ) -> Result<Option<HouseholdLifecycleGenerationV1>, HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        read_generation(&self.guard.inner.state_dir)
    }
}

/// Exclusive lifecycle protection held by teardown, install, or recovery.
#[derive(Debug)]
pub struct LifecycleWriteGuard {
    guard: LifecycleGuard,
}

impl LifecycleWriteGuard {
    /// Clone the retained state-root descriptor for fd-relative helpers that
    /// execute inside this exclusive lifecycle transaction.
    pub(crate) fn clone_state_dir(&self) -> Result<File, HouseholdLifecycleLockError> {
        self.guard
            .inner
            .state_dir
            .try_clone()
            .map_err(|_| HouseholdLifecycleLockError::Io)
    }

    /// Clone the caller spelling of the verified state root while proving the
    /// retained lifecycle guard still protects that exact directory.
    ///
    /// This is intentionally crate-private. It exists only for bounded
    /// directory enumeration whose resulting entries are reopened and
    /// validated fd-relative against [`Self::clone_state_dir`].
    pub(crate) fn clone_state_path(&self) -> Result<PathBuf, HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        Ok(self.guard.inner.state_path.clone())
    }

    /// Prove that `state_path` still names this guard's retained state root.
    ///
    /// Lifecycle-aware persistence helpers use this to reject a guard opened
    /// for another engine state root.
    pub fn verify_state_root(&self, state_path: &Path) -> Result<(), HouseholdLifecycleLockError> {
        let reopened = File::from(
            rustix::fs::open(
                state_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(map_errno)?,
        );
        if same_file(&self.guard.inner.state_dir, &reopened) {
            Ok(())
        } else {
            Err(HouseholdLifecycleLockError::UnsafePath)
        }
    }

    /// Whether the canonical installed-household marker is currently visible.
    ///
    /// A residual `household/` directory is not authority. Only a regular,
    /// non-symlink `household/household_record.cbor` counts as an installed
    /// household; callers still decode and cryptographically validate it
    /// before use.
    pub fn household_exists(&self) -> Result<bool, HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        let household = match rustix::fs::openat(
            &self.guard.inner.state_dir,
            HOUSEHOLD_SUBDIR,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(Errno::NOENT) => return Ok(false),
            Err(error) => return Err(map_errno(error)),
        };
        match rustix::fs::statat(
            &household,
            "household_record.cbor",
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) => Ok(rustix::fs::FileType::from_raw_mode(stat.st_mode)
                == rustix::fs::FileType::RegularFile),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(map_errno(error)),
        }
    }

    /// Whether recovery must resolve `household.tearing-down` before reads.
    pub fn teardown_breadcrumb_exists(&self) -> Result<bool, HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        self.guard.teardown_breadcrumb_exists()
    }

    /// Atomically detach the installed household and durably commit the rename.
    ///
    /// Returns `false` when no installed household exists. A pre-existing
    /// teardown breadcrumb is never overwritten.
    pub fn rename_household_to_tearing_down(&self) -> Result<bool, HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        if self.teardown_breadcrumb_exists()? {
            return Err(HouseholdLifecycleLockError::RecoveryRequired);
        }
        if !self.guard.entry_exists(HOUSEHOLD_SUBDIR)? {
            return Ok(false);
        }
        // Centralized absence-ABA barrier: every caller that detaches a
        // household advances the durable generation before the authority
        // dirent moves. No transport handler may accidentally omit it.
        self.rotate_lifecycle_generation()?;
        match rustix::fs::renameat(
            &self.guard.inner.state_dir,
            HOUSEHOLD_SUBDIR,
            &self.guard.inner.state_dir,
            HOUSEHOLD_TEARDOWN_BREADCRUMB,
        ) {
            Ok(()) => {
                self.sync_state_root()?;
                Ok(true)
            }
            Err(Errno::NOENT) => Ok(false),
            Err(Errno::EXIST | Errno::NOTEMPTY) => {
                Err(HouseholdLifecycleLockError::RecoveryRequired)
            }
            Err(_) => Err(HouseholdLifecycleLockError::Io),
        }
    }

    /// Remove a recovered teardown breadcrumb and durably commit its absence.
    ///
    /// Recursive deletion uses the caller-provided state-root spelling only
    /// after proving that it still names the retained state-root descriptor.
    pub fn remove_tearing_down(&self) -> Result<bool, HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        let path = self
            .guard
            .inner
            .state_path
            .join(HOUSEHOLD_TEARDOWN_BREADCRUMB);
        match std::fs::remove_dir_all(path) {
            Ok(()) => {
                self.sync_state_root()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(HouseholdLifecycleLockError::Io),
        }
    }

    /// Commit state-root directory-entry changes while the write guard lives.
    pub fn sync_state_root(&self) -> Result<(), HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        self.guard
            .inner
            .state_dir
            .sync_all()
            .map_err(|_| HouseholdLifecycleLockError::Io)
    }

    /// Read the current durable lifecycle generation, if a legacy state root
    /// has not established one yet.
    ///
    /// Only an exclusive guard exposes this operation: observing the token and
    /// persisting a ceremony that depends on it must be one transaction.
    pub fn lifecycle_generation(
        &self,
    ) -> Result<Option<HouseholdLifecycleGenerationV1>, HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        sweep_generation_temps_best_effort(
            &self.guard.inner.state_path,
            &self.guard.inner.state_dir,
        );
        read_generation(&self.guard.inner.state_dir)
    }

    /// Establish and return the durable lifecycle generation for a candidate
    /// ceremony. A visible file is never returned until file+parent barriers
    /// and exact readback have succeeded.
    pub fn ensure_lifecycle_generation(
        &self,
    ) -> Result<HouseholdLifecycleGenerationV1, HouseholdLifecycleLockError> {
        if let Some(generation) = self.lifecycle_generation()? {
            return Ok(generation);
        }
        let generation = fresh_generation(None)?;
        commit_generation(&self.guard.inner.state_dir, generation)?;
        Ok(generation)
    }

    /// Advance the durable lifecycle generation before installing, replacing,
    /// or tearing down a household.
    ///
    /// A failure after rename but before the parent barrier remains an error;
    /// the caller must not mutate `household/`. A later lifecycle transaction
    /// re-reads the witness and decides from durable state instead of treating
    /// visibility as proof.
    pub(crate) fn rotate_lifecycle_generation(
        &self,
    ) -> Result<HouseholdLifecycleGenerationV1, HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        let previous = read_generation(&self.guard.inner.state_dir)?;
        let generation = fresh_generation(previous)?;
        commit_generation(&self.guard.inner.state_dir, generation)?;
        Ok(generation)
    }

    /// Reserve, but do not publish, the exact successor token for a durable
    /// multi-step transaction. The transaction must persist this token before
    /// calling [`Self::commit_reserved_lifecycle_generation`].
    pub(crate) fn reserve_next_lifecycle_generation(
        &self,
        expected_current: HouseholdLifecycleGenerationV1,
    ) -> Result<HouseholdLifecycleGenerationV1, HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        if read_generation(&self.guard.inner.state_dir)? != Some(expected_current) {
            return Err(HouseholdLifecycleLockError::RecoveryRequired);
        }
        fresh_generation(Some(expected_current))
    }

    /// Publish a successor token that was durably reserved by the caller.
    ///
    /// This is idempotent across a lost parent-sync acknowledgement. Any third
    /// token is a foreign lifecycle rotation and is rejected rather than being
    /// adopted as the caller's terminal generation.
    pub(crate) fn commit_reserved_lifecycle_generation(
        &self,
        expected_current: HouseholdLifecycleGenerationV1,
        reserved: HouseholdLifecycleGenerationV1,
    ) -> Result<HouseholdLifecycleGenerationV1, HouseholdLifecycleLockError> {
        self.guard.ensure_current()?;
        if reserved == expected_current {
            return Err(HouseholdLifecycleLockError::UnsafePath);
        }
        match read_generation(&self.guard.inner.state_dir)? {
            Some(current) if current == reserved => Ok(reserved),
            Some(current) if current == expected_current => {
                commit_generation(&self.guard.inner.state_dir, reserved)?;
                Ok(reserved)
            }
            _ => Err(HouseholdLifecycleLockError::RecoveryRequired),
        }
    }

    /// Reserve a fresh generation before materializing or replacing household
    /// authority. Internal authority updates do not change lifecycle and must
    /// not call this helper.
    pub fn reserve_household_install_generation(
        &self,
    ) -> Result<HouseholdLifecycleGenerationV1, HouseholdLifecycleLockError> {
        self.rotate_lifecycle_generation()
    }
}

fn fresh_generation(
    previous: Option<HouseholdLifecycleGenerationV1>,
) -> Result<HouseholdLifecycleGenerationV1, HouseholdLifecycleLockError> {
    for _ in 0..8 {
        let mut token = [0_u8; GENERATION_TOKEN_BYTES];
        OsRng
            .try_fill_bytes(&mut token)
            .map_err(|_| HouseholdLifecycleLockError::Io)?;
        let candidate = HouseholdLifecycleGenerationV1(token);
        if Some(candidate) != previous {
            return Ok(candidate);
        }
    }
    Err(HouseholdLifecycleLockError::Io)
}

fn generation_bytes(generation: HouseholdLifecycleGenerationV1) -> [u8; GENERATION_FILE_BYTES] {
    let mut bytes = [0_u8; GENERATION_FILE_BYTES];
    bytes[0] = GENERATION_VERSION;
    bytes[1..].copy_from_slice(generation.token_bytes());
    bytes
}

fn read_generation(
    state_dir: &File,
) -> Result<Option<HouseholdLifecycleGenerationV1>, HouseholdLifecycleLockError> {
    let fd = match rustix::fs::openat(
        state_dir,
        HOUSEHOLD_LIFECYCLE_GENERATION_FILENAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(map_errno(error)),
    };
    let mut file = File::from(fd);
    validate_generation_file(state_dir, &file)?;
    // A previous process may have installed this dirent and then lost the
    // acknowledgement for its parent barrier. Re-prove durability on the same
    // descriptors before treating visibility as a usable generation witness.
    file.sync_all()
        .map_err(|_| HouseholdLifecycleLockError::Io)?;
    if generation_fail_injection::fail_existing_parent_sync() {
        return Err(HouseholdLifecycleLockError::Io);
    }
    state_dir
        .sync_all()
        .map_err(|_| HouseholdLifecycleLockError::Io)?;
    if !named_generation_matches(state_dir, &file) {
        return Err(HouseholdLifecycleLockError::UnsafePath);
    }
    let mut bytes = [0_u8; GENERATION_FILE_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|_| HouseholdLifecycleLockError::UnsafePath)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| HouseholdLifecycleLockError::Io)?
        != 0
        || bytes[0] != GENERATION_VERSION
    {
        return Err(HouseholdLifecycleLockError::UnsafePath);
    }
    HouseholdLifecycleGenerationV1::from_token_bytes(&bytes[1..]).map(Some)
}

fn validate_generation_file(
    state_dir: &File,
    file: &File,
) -> Result<(), HouseholdLifecycleLockError> {
    use std::os::unix::fs::PermissionsExt;
    let state = state_dir
        .metadata()
        .map_err(|_| HouseholdLifecycleLockError::Io)?;
    let metadata = file
        .metadata()
        .map_err(|_| HouseholdLifecycleLockError::Io)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != state.uid()
        || metadata.nlink() != 1
        || metadata.len() != GENERATION_FILE_BYTES as u64
    {
        return Err(HouseholdLifecycleLockError::UnsafePath);
    }
    Ok(())
}

fn commit_generation(
    state_dir: &File,
    generation: HouseholdLifecycleGenerationV1,
) -> Result<(), HouseholdLifecycleLockError> {
    let mut nonce = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| HouseholdLifecycleLockError::Io)?;
    let mut tmp_name = String::with_capacity(GENERATION_TMP_PREFIX.len() + nonce.len() * 2);
    tmp_name.push_str(GENERATION_TMP_PREFIX);
    for byte in nonce {
        use std::fmt::Write as _;
        write!(&mut tmp_name, "{byte:02x}").map_err(|_| HouseholdLifecycleLockError::Io)?;
    }

    let fd = rustix::fs::openat(
        state_dir,
        tmp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(map_errno)?;
    let mut tmp = File::from(fd);
    let result = (|| {
        tmp.write_all(&generation_bytes(generation))
            .map_err(|_| HouseholdLifecycleLockError::Io)?;
        tmp.sync_all()
            .map_err(|_| HouseholdLifecycleLockError::Io)?;
        validate_generation_file(state_dir, &tmp)?;
        rustix::fs::renameat(
            state_dir,
            tmp_name.as_str(),
            state_dir,
            HOUSEHOLD_LIFECYCLE_GENERATION_FILENAME,
        )
        .map_err(map_errno)?;
        if generation_fail_injection::fail_after_generation_rename() {
            return Err(HouseholdLifecycleLockError::Io);
        }
        state_dir
            .sync_all()
            .map_err(|_| HouseholdLifecycleLockError::Io)?;
        if read_generation(state_dir)? != Some(generation) {
            return Err(HouseholdLifecycleLockError::UnsafePath);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(state_dir, tmp_name.as_str(), AtFlags::empty());
    }
    result
}

fn named_generation_matches(state_dir: &File, file: &File) -> bool {
    let Ok(named) = rustix::fs::statat(
        state_dir,
        HOUSEHOLD_LIFECYCLE_GENERATION_FILENAME,
        AtFlags::SYMLINK_NOFOLLOW,
    ) else {
        return false;
    };
    let Ok(opened) = rustix::fs::fstat(file) else {
        return false;
    };
    named.st_dev == opened.st_dev && named.st_ino == opened.st_ino
}

fn sweep_generation_temps_best_effort(state_path: &Path, state_dir: &File) {
    // Enumeration is path-based while deletion and its durability barrier are
    // fd-relative. This is sufficient only under this module's documented
    // same-uid-cooperative deployment boundary: an uncooperative peer with
    // direct directory-entry mutation remains outside the threat model.
    let Ok(entries) = std::fs::read_dir(state_path) else {
        return;
    };
    let mut removed = false;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(GENERATION_TMP_PREFIX) {
            continue;
        }
        if rustix::fs::unlinkat(state_dir, name, AtFlags::empty()).is_ok() {
            removed = true;
        }
    }
    if removed {
        let _ = state_dir.sync_all();
    }
}

#[cfg(test)]
mod generation_fail_injection {
    use std::cell::Cell;

    thread_local! {
        static FAIL_AFTER_RENAME: Cell<bool> = const { Cell::new(false) };
        static FAIL_EXISTING_PARENT_SYNC: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) struct ExistingSyncArmed;

    impl Drop for ExistingSyncArmed {
        fn drop(&mut self) {
            FAIL_EXISTING_PARENT_SYNC.with(|armed| armed.set(false));
        }
    }

    pub(super) fn arm_after_rename() {
        FAIL_AFTER_RENAME.with(|armed| armed.set(true));
    }

    pub(super) fn arm_existing_parent_sync() -> ExistingSyncArmed {
        FAIL_EXISTING_PARENT_SYNC.with(|armed| armed.set(true));
        ExistingSyncArmed
    }

    pub(super) fn fail_after_generation_rename() -> bool {
        crate::crash_park::park_if_armed("generation:after_rename");
        FAIL_AFTER_RENAME.with(|armed| armed.replace(false))
    }

    pub(super) fn fail_existing_parent_sync() -> bool {
        crate::crash_park::park_if_armed("generation:existing_parent_sync");
        FAIL_EXISTING_PARENT_SYNC.with(Cell::get)
    }
}

#[cfg(not(test))]
mod generation_fail_injection {
    pub(super) const fn fail_after_generation_rename() -> bool {
        false
    }

    pub(super) const fn fail_existing_parent_sync() -> bool {
        false
    }
}

fn open_or_create_lock(state_dir: &File) -> Result<File, HouseholdLifecycleLockError> {
    match rustix::fs::openat(
        state_dir,
        HOUSEHOLD_LIFECYCLE_LOCK_FILENAME,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => Ok(File::from(fd)),
        Err(Errno::EXIST) => open_existing_lock(state_dir),
        Err(error) => Err(map_errno(error)),
    }
}

fn open_existing_lock(state_dir: &File) -> Result<File, HouseholdLifecycleLockError> {
    rustix::fs::openat(
        state_dir,
        HOUSEHOLD_LIFECYCLE_LOCK_FILENAME,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(map_errno)
}

fn validate_state_root(state_dir: &File) -> Result<(), HouseholdLifecycleLockError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = state_dir
        .metadata()
        .map_err(|_| HouseholdLifecycleLockError::Io)?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(HouseholdLifecycleLockError::UnsafePath);
    }
    Ok(())
}

fn validate_lock_file(state_dir: &File, file: &File) -> Result<(), HouseholdLifecycleLockError> {
    use std::os::unix::fs::PermissionsExt;
    let state = state_dir
        .metadata()
        .map_err(|_| HouseholdLifecycleLockError::Io)?;
    let metadata = file
        .metadata()
        .map_err(|_| HouseholdLifecycleLockError::Io)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != state.uid()
        || metadata.nlink() != 1
    {
        return Err(HouseholdLifecycleLockError::UnsafePath);
    }
    Ok(())
}

fn named_lock_matches(state_dir: &File, file: &File) -> bool {
    let Ok(named) = rustix::fs::statat(
        state_dir,
        HOUSEHOLD_LIFECYCLE_LOCK_FILENAME,
        AtFlags::SYMLINK_NOFOLLOW,
    ) else {
        return false;
    };
    let Ok(opened) = rustix::fs::fstat(file) else {
        return false;
    };
    named.st_dev == opened.st_dev && named.st_ino == opened.st_ino
}

fn same_file(left: &File, right: &File) -> bool {
    let (Ok(left), Ok(right)) = (rustix::fs::fstat(left), rustix::fs::fstat(right)) else {
        return false;
    };
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn map_errno(error: Errno) -> HouseholdLifecycleLockError {
    if error == Errno::LOOP {
        HouseholdLifecycleLockError::UnsafePath
    } else {
        HouseholdLifecycleLockError::Io
    }
}

fn sync_state_root_after_lock_open(state_dir: &File) -> Result<(), HouseholdLifecycleLockError> {
    if lifecycle_fail_injection::take_parent_sync() {
        return Err(HouseholdLifecycleLockError::Io);
    }
    state_dir
        .sync_all()
        .map_err(|_| HouseholdLifecycleLockError::Io)
}

#[cfg(test)]
mod lifecycle_fail_injection {
    use std::cell::Cell;

    thread_local! {
        static FAIL_PARENT_SYNC: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) struct Armed;

    impl Drop for Armed {
        fn drop(&mut self) {
            FAIL_PARENT_SYNC.with(|armed| armed.set(false));
        }
    }

    pub(super) fn arm_parent_sync() -> Armed {
        FAIL_PARENT_SYNC.with(|armed| armed.set(true));
        Armed
    }

    pub(super) fn take_parent_sync() -> bool {
        FAIL_PARENT_SYNC.with(|armed| armed.replace(false))
    }
}

#[cfg(not(test))]
mod lifecycle_fail_injection {
    pub(super) const fn take_parent_sync() -> bool {
        false
    }
}

#[cfg(target_os = "macos")]
fn validate_supported_persistent_filesystem(dir: &File) -> Result<(), HouseholdLifecycleLockError> {
    let stat = rustix::fs::fstatfs(dir).map_err(|_| HouseholdLifecycleLockError::Io)?;
    let name: Vec<u8> = stat
        .f_fstypename
        .iter()
        .map(|byte| byte.to_ne_bytes()[0])
        .take_while(|byte| *byte != 0)
        .collect();
    if name == b"apfs" {
        Ok(())
    } else {
        Err(HouseholdLifecycleLockError::UnsupportedFilesystem)
    }
}

#[cfg(target_os = "linux")]
fn validate_supported_persistent_filesystem(dir: &File) -> Result<(), HouseholdLifecycleLockError> {
    let stat = rustix::fs::fstatfs(dir).map_err(|_| HouseholdLifecycleLockError::Io)?;
    if matches!(
        stat.f_type,
        EXT4_SUPER_MAGIC | XFS_SUPER_MAGIC | BTRFS_SUPER_MAGIC
    ) {
        Ok(())
    } else {
        Err(HouseholdLifecycleLockError::UnsupportedFilesystem)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn validate_supported_persistent_filesystem(_: &File) -> Result<(), HouseholdLifecycleLockError> {
    Err(HouseholdLifecycleLockError::UnsupportedFilesystem)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::thread;

    use tempfile::TempDir;

    use super::*;

    const CHILD_TEST_NAME: &str =
        "household_lifecycle::tests::multiprocess_shared_lifecycle_worker";
    const CHILD_STATE_ENV: &str = "THEYOS_HOUSEHOLD_LIFECYCLE_CHILD_STATE";
    const CHILD_READY_ENV: &str = "THEYOS_HOUSEHOLD_LIFECYCLE_CHILD_READY";

    #[test]
    fn shared_guard_blocks_exclusive_until_it_is_released() {
        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let shared = lifecycle.lock_shared().unwrap();
        assert_eq!(
            lifecycle
                .lock_exclusive_until(Instant::now() + Duration::from_millis(50))
                .unwrap_err(),
            HouseholdLifecycleLockError::LockTimeout
        );
        drop(shared);
        lifecycle
            .lock_exclusive_until(Instant::now() + Duration::from_secs(1))
            .unwrap();
    }

    #[test]
    fn visible_lock_is_never_reused_without_the_state_root_barrier() {
        let temp = TempDir::new().unwrap();
        let armed = lifecycle_fail_injection::arm_parent_sync();
        assert_eq!(
            HouseholdLifecycleLock::open_verified(temp.path()).unwrap_err(),
            HouseholdLifecycleLockError::Io
        );
        assert!(
            temp.path().join(HOUSEHOLD_LIFECYCLE_LOCK_FILENAME).exists(),
            "the failpoint models a visible lock whose parent barrier failed"
        );
        drop(armed);
        HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
    }

    #[test]
    fn lifecycle_generation_is_fixed_width_durable_and_changes_per_rotation() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        assert_eq!(write.lifecycle_generation().unwrap(), None);
        let first = write.ensure_lifecycle_generation().unwrap();
        assert_eq!(
            write.lifecycle_generation().unwrap(),
            Some(first),
            "an established witness must round-trip exact bytes"
        );
        let second = write.rotate_lifecycle_generation().unwrap();
        assert_ne!(first, second);
        assert_eq!(write.lifecycle_generation().unwrap(), Some(second));
        let metadata =
            fs::metadata(temp.path().join(HOUSEHOLD_LIFECYCLE_GENERATION_FILENAME)).unwrap();
        assert_eq!(metadata.len(), GENERATION_FILE_BYTES as u64);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn visible_generation_after_lost_parent_ack_is_stabilized_before_reuse() {
        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        generation_fail_injection::arm_after_rename();
        assert_eq!(
            write.ensure_lifecycle_generation().unwrap_err(),
            HouseholdLifecycleLockError::Io
        );
        assert!(
            temp.path()
                .join(HOUSEHOLD_LIFECYCLE_GENERATION_FILENAME)
                .exists(),
            "the failpoint models rename visibility without a parent-barrier acknowledgement"
        );

        let sticky = generation_fail_injection::arm_existing_parent_sync();
        assert_eq!(
            write.lifecycle_generation().unwrap_err(),
            HouseholdLifecycleLockError::Io,
            "retry must not trust the visible witness while its stabilizing barrier fails"
        );
        drop(sticky);
        write
            .lifecycle_generation()
            .unwrap()
            .expect("retry re-proves file and parent durability before returning the witness");
    }

    #[test]
    fn generation_operation_sweeps_crash_orphaned_nonce_temp() {
        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        let orphan = temp.path().join(format!("{GENERATION_TMP_PREFIX}orphan"));
        fs::write(&orphan, b"partial").unwrap();
        write.ensure_lifecycle_generation().unwrap();
        assert!(!orphan.exists());
    }

    #[test]
    fn shared_guard_refuses_an_unresolved_teardown_breadcrumb() {
        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        fs::create_dir(temp.path().join(HOUSEHOLD_TEARDOWN_BREADCRUMB)).unwrap();
        assert_eq!(
            lifecycle.lock_shared().unwrap_err(),
            HouseholdLifecycleLockError::RecoveryRequired
        );
        let write = lifecycle.lock_exclusive().unwrap();
        assert!(write.teardown_breadcrumb_exists().unwrap());
        assert!(write.remove_tearing_down().unwrap());
        drop(write);
        lifecycle.lock_shared().unwrap();
    }

    #[test]
    fn named_lock_substitution_after_open_fails_closed() {
        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let lock_path = temp.path().join(HOUSEHOLD_LIFECYCLE_LOCK_FILENAME);
        fs::remove_file(&lock_path).unwrap();
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(lock_path)
            .unwrap();
        assert_eq!(
            lifecycle.lock_shared().unwrap_err(),
            HouseholdLifecycleLockError::UnsafePath
        );
    }

    #[test]
    fn named_lock_substitution_after_flock_blocks_write_guard_mutation() {
        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        let lock_path = temp.path().join(HOUSEHOLD_LIFECYCLE_LOCK_FILENAME);
        fs::remove_file(&lock_path).unwrap();
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(lock_path)
            .unwrap();
        assert_eq!(
            write.sync_state_root().unwrap_err(),
            HouseholdLifecycleLockError::UnsafePath
        );
        assert_eq!(
            write.rename_household_to_tearing_down().unwrap_err(),
            HouseholdLifecycleLockError::UnsafePath
        );
    }

    #[test]
    fn write_guard_rejects_a_different_state_root() {
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(first.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        assert_eq!(
            write.verify_state_root(second.path()).unwrap_err(),
            HouseholdLifecycleLockError::UnsafePath
        );
        write.verify_state_root(first.path()).unwrap();
    }

    #[test]
    fn read_guard_rejects_a_different_state_root() {
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(first.path()).unwrap();
        let read = lifecycle.lock_shared().unwrap();
        assert_eq!(
            read.verify_state_root(second.path()).unwrap_err(),
            HouseholdLifecycleLockError::UnsafePath
        );
        read.verify_state_root(first.path()).unwrap();
    }

    #[test]
    fn residual_household_directory_without_record_is_not_installed_authority() {
        let state = TempDir::new().unwrap();
        fs::create_dir(state.path().join(HOUSEHOLD_SUBDIR)).unwrap();
        fs::create_dir(state.path().join(HOUSEHOLD_SUBDIR).join("owner_events")).unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        assert!(!write.household_exists().unwrap());
    }

    #[test]
    fn lifecycle_flock_serializes_processes_and_releases_on_child_death() {
        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let ready = temp.path().join("child-shared-ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(CHILD_TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_STATE_ENV, temp.path())
            .env(CHILD_READY_ENV, &ready)
            .spawn()
            .unwrap();
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                Instant::now() < ready_deadline,
                "child never acquired lifecycle shared guard"
            );
            thread::sleep(Duration::from_millis(5));
        }

        assert_eq!(
            lifecycle
                .lock_exclusive_until(Instant::now() + Duration::from_millis(50))
                .unwrap_err(),
            HouseholdLifecycleLockError::LockTimeout
        );
        child.kill().unwrap();
        child.wait().unwrap();
        lifecycle
            .lock_exclusive_until(Instant::now() + Duration::from_secs(1))
            .unwrap();
    }

    const ROTATE_CRASH_WORKER: &str = "household_lifecycle::tests::generation_rotate_crash_worker";

    /// Child: rotate the generation, parking after the rename so the parent
    /// can SIGKILL it in exactly that window.
    #[test]
    fn generation_rotate_crash_worker() {
        let Some(state_path) = std::env::var_os(CHILD_STATE_ENV).map(PathBuf::from) else {
            return;
        };
        let lifecycle = HouseholdLifecycleLock::open_verified(&state_path).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        // Arm only now, with the lock already held: arming earlier would let
        // the park fire on some other generation write during open, and the
        // crash would land on a different operation than the one under test.
        crate::crash_park::arm_from_env();
        let _ = write.rotate_lifecycle_generation();
    }

    /// G0 -> G1 across a REAL crash in the post-rename window.
    ///
    /// `rotate_lifecycle_generation` renames the new witness into place, and
    /// only then syncs the parent and reads it back. A process killed between
    /// those leaves a generation file that is VISIBLE but whose parent barrier
    /// never completed, and no caller alive to be told the rotation failed.
    ///
    /// Two things must hold afterwards:
    /// - the witness still reads back as a well-formed generation (never torn,
    ///   never a partial write) — it is fixed-width and renamed, so tearing
    ///   would mean the atomicity claim is wrong;
    /// - the household can still make progress, and the generation it moves to
    ///   is distinct from BOTH the pre-crash G0 and whatever became visible.
    ///   Landing back on G0 would be the ABA that lets artifacts tagged with
    ///   the old generation be adopted as current.
    #[test]
    fn sigkill_after_generation_rename_leaves_a_readable_witness_and_no_aba() {
        let temp = TempDir::new().unwrap();
        let g0 = {
            let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
            let write = lifecycle.lock_exclusive().unwrap();
            write.ensure_lifecycle_generation().unwrap()
        };

        let ready = temp.path().join("parked-generation-after-rename");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(ROTATE_CRASH_WORKER)
            .arg("--nocapture")
            .env(CHILD_STATE_ENV, temp.path())
            .env(crate::crash_park::PARK_SITE_ENV, "generation:after_rename")
            .env(crate::crash_park::PARK_READY_ENV, &ready)
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            if let Ok(Some(status)) = child.try_wait() {
                panic!("child exited ({status}) without reaching the post-rename window");
            }
            assert!(
                Instant::now() < deadline,
                "child never reached generation:after_rename"
            );
            thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        assert!(
            !child.wait().unwrap().success(),
            "the child was supposed to be killed in the window, not to exit cleanly"
        );

        // Restart: a fresh lock over the same state directory.
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();

        let visible = write
            .lifecycle_generation()
            .expect("witness must still parse after a crash in the rename window");
        let visible = visible.expect("a witness was established before the crash");
        assert_ne!(
            visible, g0,
            "the rename had already landed, so the visible witness must be the new one"
        );

        let g2 = write
            .rotate_lifecycle_generation()
            .expect("the household must still be able to advance after the crash");
        assert_ne!(g2, visible, "a rotation must advance");
        assert_ne!(
            g2, g0,
            "rotating after the crash must not land back on the pre-crash generation:              that is the ABA that lets old-generation artifacts be adopted as current"
        );
    }

    #[test]
    fn multiprocess_shared_lifecycle_worker() {
        let Some(state_path) = std::env::var_os(CHILD_STATE_ENV).map(PathBuf::from) else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os(CHILD_READY_ENV).unwrap());
        let lifecycle = HouseholdLifecycleLock::open_verified(&state_path).unwrap();
        let _shared = lifecycle.lock_shared().unwrap();
        fs::write(ready, b"ready").unwrap();
        // The parent deliberately terminates this process. A finite fallback
        // keeps an orphaned manually-invoked child from living forever.
        thread::sleep(Duration::from_secs(20));
    }
}
