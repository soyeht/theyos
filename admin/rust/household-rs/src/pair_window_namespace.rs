//! Generation-scoped durable namespace for pairing ceremony snapshots.
//!
//! Pairing windows are pre-household authority. Keeping their snapshots below
//! `household/` lets a callback from lifecycle generation G0 delete or recreate
//! bytes belonging to a later installed household G2. Each lifecycle generation
//! therefore owns one state-root directory whose fixed-width name includes G.

use std::ffi::CStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::{RngCore, rngs::OsRng};
use rustix::fs::{AtFlags, Dir, Mode, OFlags};
use rustix::io::Errno;
use serde::{Serialize, de::DeserializeOwned};

use crate::cbor;
use crate::error::{HouseholdError, StorageError};
use crate::household_lifecycle::{
    HouseholdLifecycleGenerationV1, HouseholdLifecycleLock, HouseholdLifecycleLockError,
    LifecycleReadGuard, LifecycleWriteGuard,
};

const CURRENT_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const NAMESPACE_PREFIX: &str = ".pair-windows-v2.";
const GENERATION_HEX_BYTES: usize = 64;
const PAIR_DEVICE_NAME: &str = "pair_device_window.cbor";
const PAIR_MACHINE_NAME: &str = "pair_machine_window.cbor";
const TMP_INFIX: &str = ".tmp.";
const MAX_SNAPSHOT_BYTES: u64 = 1024 * 1024;
const MAX_STALE_ENTRIES_PER_GENERATION: usize = 64;

/// Capability for exactly one lifecycle generation's pairing snapshots.
///
/// The retained directory descriptor is the authority. A stale callback may
/// retain this capability after rotation, but it cannot derive or open the new
/// generation. Cleanup removes the old directory name under lifecycle-exclusive;
/// a callback holding the now-unlinked descriptor can at worst write unreachable
/// bytes into its own old directory.
#[derive(Clone, Debug)]
pub struct PairWindowNamespaceV2 {
    inner: Arc<NamespaceInner>,
}

#[derive(Debug)]
struct NamespaceInner {
    state_path: PathBuf,
    state_dir: File,
    state_dev: u64,
    state_ino: u64,
    namespace_dir: File,
    namespace_dev: u64,
    namespace_ino: u64,
    namespace_name: String,
    generation: HouseholdLifecycleGenerationV1,
    lifecycle: HouseholdLifecycleLock,
}

impl PairWindowNamespaceV2 {
    /// Read a retained generation during install recovery without creating or
    /// sweeping any namespace. This is deliberately read-only: after terminal
    /// rotation the breadcrumb still needs to prove the G0 committed window
    /// before cleanup, but no stale-G writer capability may be reconstructed.
    pub fn read_pair_machine_generation_under_lifecycle<T: DeserializeOwned>(
        state_path: PathBuf,
        guard: &LifecycleWriteGuard,
        generation: HouseholdLifecycleGenerationV1,
    ) -> Result<Option<T>, StorageError> {
        guard
            .verify_state_root(&state_path)
            .map_err(|error| lifecycle_storage_error(&state_path, error))?;
        let state_dir = open_state_root(&state_path)?;
        let state_metadata = state_dir
            .metadata()
            .map_err(|error| io_storage_error(&state_path, &error))?;
        let namespace_name = format!("{NAMESPACE_PREFIX}{}", encode_generation(&generation));
        let namespace_path = state_path.join(&namespace_name);
        let namespace_fd = match rustix::fs::openat(
            &state_dir,
            namespace_name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(errno_storage_error(&namespace_path, error)),
        };
        let namespace_dir = File::from(namespace_fd);
        validate_namespace_dir(&state_dir, &namespace_dir, &namespace_path)?;
        let namespace_metadata = namespace_dir
            .metadata()
            .map_err(|error| io_storage_error(&namespace_path, &error))?;
        let lifecycle = HouseholdLifecycleLock::open_verified(&state_path)
            .map_err(|error| lifecycle_storage_error(&state_path, error))?;
        let namespace = Self {
            inner: Arc::new(NamespaceInner {
                state_path,
                state_dir,
                state_dev: state_metadata.dev(),
                state_ino: state_metadata.ino(),
                namespace_dir,
                namespace_dev: namespace_metadata.dev(),
                namespace_ino: namespace_metadata.ino(),
                namespace_name,
                generation,
                lifecycle,
            }),
        };
        namespace.read_named(PAIR_MACHINE_NAME)
    }

    /// Open the current namespace in a standalone synchronous context.
    ///
    /// This performs filesystem I/O and may wait up to 30 seconds for the
    /// lifecycle-exclusive lock. Async callers must use `spawn_blocking`, or
    /// call [`Self::current_under_lifecycle`] when they already retain the
    /// correctly ordered lifecycle guard.
    pub fn current(state_path: PathBuf) -> Result<Self, StorageError> {
        let lifecycle = HouseholdLifecycleLock::open_verified(&state_path)
            .map_err(|error| lifecycle_storage_error(&state_path, error))?;
        let guard = lifecycle
            .lock_exclusive_until(Instant::now() + CURRENT_LOCK_TIMEOUT)
            .map_err(|error| lifecycle_storage_error(&state_path, error))?;
        Self::current_under_lifecycle(state_path, &guard)
    }

    /// Open the current namespace while reusing an already-held exclusive
    /// lifecycle guard. This never reacquires the lifecycle lock.
    pub fn current_under_lifecycle(
        state_path: PathBuf,
        guard: &LifecycleWriteGuard,
    ) -> Result<Self, StorageError> {
        guard
            .verify_state_root(&state_path)
            .map_err(|error| lifecycle_storage_error(&state_path, error))?;
        remove_legacy_pair_snapshots(&state_path)?;
        let generation = guard
            .ensure_lifecycle_generation()
            .map_err(|error| lifecycle_storage_error(&state_path, error))?;
        // Ordering is load-bearing: the generation witness is durable before
        // its namespace directory can become visible.
        let state_dir = open_state_root(&state_path)?;
        let state_metadata = state_dir
            .metadata()
            .map_err(|error| io_storage_error(&state_path, &error))?;
        let namespace_name = format!("{NAMESPACE_PREFIX}{}", encode_generation(&generation));
        let namespace_dir = open_or_create_namespace(&state_path, &state_dir, &namespace_name)?;
        let namespace_metadata = namespace_dir
            .metadata()
            .map_err(|error| io_storage_error(&state_path.join(&namespace_name), &error))?;
        guard
            .verify_state_root(&state_path)
            .map_err(|error| lifecycle_storage_error(&state_path, error))?;
        let lifecycle = HouseholdLifecycleLock::open_verified(&state_path)
            .map_err(|error| lifecycle_storage_error(&state_path, error))?;
        let namespace = Self {
            inner: Arc::new(NamespaceInner {
                state_path,
                state_dir,
                state_dev: state_metadata.dev(),
                state_ino: state_metadata.ino(),
                namespace_dir,
                namespace_dev: namespace_metadata.dev(),
                namespace_ino: namespace_metadata.ino(),
                namespace_name,
                generation,
                lifecycle,
            }),
        };
        namespace.validate_binding()?;
        namespace.sweep_stale_generations()?;
        Ok(namespace)
    }

    /// Fixed-width lifecycle witness embedded in every snapshot stored here.
    #[must_use]
    pub fn generation(&self) -> HouseholdLifecycleGenerationV1 {
        self.inner.generation
    }

    pub(crate) fn pair_machine_snapshot_path(&self) -> PathBuf {
        self.inner
            .state_path
            .join(&self.inner.namespace_name)
            .join(PAIR_MACHINE_NAME)
    }

    /// Stage a Phase-3 multi-file commit while retaining exact-generation
    /// authority through the eventual promotion. The caller supplies every
    /// non-window item and the encoded committed window; this method alone
    /// appends the private generation-scoped target.
    pub fn stage_pair_machine_commit_under_lifecycle<'a>(
        &'a self,
        lifecycle: &'a LifecycleWriteGuard,
        mut pre_commit_items: Vec<(PathBuf, Vec<u8>)>,
        committed_window_bytes: Vec<u8>,
        commit_marker: (PathBuf, Vec<u8>),
    ) -> Result<PairWindowStagedCommit<'a>, StorageError> {
        self.validate_write_guard(lifecycle)?;
        // The generation-scoped window is an intermediate artifact. The
        // caller-supplied canonical commit marker must be promoted LAST so a
        // restart can distinguish partial installation from committed
        // authority without inferring from directory visibility.
        pre_commit_items.push((self.pair_machine_snapshot_path(), committed_window_bytes));
        pre_commit_items.push(commit_marker);
        let staged = crate::storage::stage_commit_files(&pre_commit_items)?;
        self.validate_write_guard(lifecycle)?;
        Ok(PairWindowStagedCommit {
            staged,
            namespace: self,
            lifecycle,
        })
    }

    #[cfg(test)]
    pub(crate) fn pair_device_snapshot_path(&self) -> PathBuf {
        self.inner
            .state_path
            .join(&self.inner.namespace_name)
            .join(PAIR_DEVICE_NAME)
    }

    pub(crate) fn read_pair_device<T: DeserializeOwned>(&self) -> Result<Option<T>, StorageError> {
        let _guard = self.acquire_current_shared()?;
        self.read_named(PAIR_DEVICE_NAME)
    }

    pub(crate) fn read_pair_machine<T: DeserializeOwned>(&self) -> Result<Option<T>, StorageError> {
        let _guard = self.acquire_current_shared()?;
        self.read_named(PAIR_MACHINE_NAME)
    }

    #[cfg(test)]
    pub(crate) fn write_pair_device<T: Serialize>(&self, value: &T) -> Result<(), StorageError> {
        let _guard = self.acquire_current_shared()?;
        self.write_named(PAIR_DEVICE_NAME, value)
    }

    pub(crate) fn write_pair_machine<T: Serialize>(&self, value: &T) -> Result<(), StorageError> {
        let _guard = self.acquire_current_shared()?;
        self.write_named(PAIR_MACHINE_NAME, value)
    }

    #[cfg(test)]
    pub(crate) fn delete_pair_device(&self) -> Result<(), StorageError> {
        let _guard = self.acquire_current_shared()?;
        self.delete_named(PAIR_DEVICE_NAME)
    }

    pub(crate) fn read_pair_device_under_lifecycle<T: DeserializeOwned>(
        &self,
        guard: &LifecycleWriteGuard,
    ) -> Result<Option<T>, StorageError> {
        self.validate_write_guard(guard)?;
        self.read_named(PAIR_DEVICE_NAME)
    }

    pub(crate) fn read_pair_device_under_shared<T: DeserializeOwned>(
        &self,
        guard: &LifecycleReadGuard,
    ) -> Result<Option<T>, StorageError> {
        self.validate_read_guard(guard)?;
        self.read_named(PAIR_DEVICE_NAME)
    }

    pub(crate) fn read_pair_machine_under_lifecycle<T: DeserializeOwned>(
        &self,
        guard: &LifecycleWriteGuard,
    ) -> Result<Option<T>, StorageError> {
        self.validate_write_guard(guard)?;
        self.read_named(PAIR_MACHINE_NAME)
    }

    /// Remove only the recovery sibling produced by a staged install in this
    /// exact generation. The live snapshot is left to the caller's explicit
    /// state transition (normally `return_to_idle`).
    pub(crate) fn clear_pair_machine_staged_under_lifecycle(
        &self,
        guard: &LifecycleWriteGuard,
    ) -> Result<(), StorageError> {
        self.validate_write_guard(guard)?;
        self.delete_named(&format!("{PAIR_MACHINE_NAME}.staged"))
    }

    pub(crate) fn write_pair_device_under_lifecycle<T: Serialize>(
        &self,
        value: &T,
        guard: &LifecycleWriteGuard,
    ) -> Result<(), StorageError> {
        self.validate_write_guard(guard)?;
        self.write_named(PAIR_DEVICE_NAME, value)
    }

    pub(crate) fn write_pair_device_under_shared<T: Serialize>(
        &self,
        value: &T,
        guard: &LifecycleReadGuard,
    ) -> Result<(), StorageError> {
        self.validate_read_guard(guard)?;
        self.write_named(PAIR_DEVICE_NAME, value)
    }

    pub(crate) fn write_pair_machine_under_lifecycle<T: Serialize>(
        &self,
        value: &T,
        guard: &LifecycleWriteGuard,
    ) -> Result<(), StorageError> {
        self.validate_write_guard(guard)?;
        self.write_named(PAIR_MACHINE_NAME, value)
    }

    pub(crate) fn delete_pair_device_under_lifecycle(
        &self,
        guard: &LifecycleWriteGuard,
    ) -> Result<(), StorageError> {
        self.validate_write_guard(guard)?;
        self.delete_named(PAIR_DEVICE_NAME)
    }

    pub(crate) fn delete_pair_device_under_shared(
        &self,
        guard: &LifecycleReadGuard,
    ) -> Result<(), StorageError> {
        self.validate_read_guard(guard)?;
        self.delete_named(PAIR_DEVICE_NAME)
    }

    pub(crate) fn acquire_current_shared(&self) -> Result<LifecycleReadGuard, StorageError> {
        let guard = self
            .inner
            .lifecycle
            .lock_shared_until(Instant::now() + CURRENT_LOCK_TIMEOUT)
            .map_err(|error| lifecycle_storage_error(&self.inner.state_path, error))?;
        if guard
            .lifecycle_generation()
            .map_err(|error| lifecycle_storage_error(&self.inner.state_path, error))?
            != Some(self.inner.generation)
        {
            return Err(stale_generation_error(&self.inner.state_path));
        }
        Ok(guard)
    }

    fn validate_read_guard(&self, guard: &LifecycleReadGuard) -> Result<(), StorageError> {
        guard
            .verify_state_root(&self.inner.state_path)
            .map_err(|error| lifecycle_storage_error(&self.inner.state_path, error))?;
        if guard
            .lifecycle_generation()
            .map_err(|error| lifecycle_storage_error(&self.inner.state_path, error))?
            != Some(self.inner.generation)
        {
            return Err(stale_generation_error(&self.inner.state_path));
        }
        Ok(())
    }

    pub(crate) fn validate_write_guard(
        &self,
        guard: &LifecycleWriteGuard,
    ) -> Result<(), StorageError> {
        guard
            .verify_state_root(&self.inner.state_path)
            .map_err(|error| lifecycle_storage_error(&self.inner.state_path, error))?;
        if guard
            .lifecycle_generation()
            .map_err(|error| lifecycle_storage_error(&self.inner.state_path, error))?
            != Some(self.inner.generation)
        {
            return Err(stale_generation_error(&self.inner.state_path));
        }
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn state_path(&self) -> &Path {
        &self.inner.state_path
    }

    fn validate_binding(&self) -> Result<(), StorageError> {
        let reopened_root = open_state_root(&self.inner.state_path)?;
        let root_metadata = reopened_root
            .metadata()
            .map_err(|error| io_storage_error(&self.inner.state_path, &error))?;
        if root_metadata.dev() != self.inner.state_dev
            || root_metadata.ino() != self.inner.state_ino
        {
            return Err(unsafe_storage_error(
                &self.inner.state_path,
                "state root was replaced while pair-window namespace was retained",
            ));
        }
        let named = rustix::fs::statat(
            &self.inner.state_dir,
            self.inner.namespace_name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| {
            errno_storage_error(
                &self.inner.state_path.join(&self.inner.namespace_name),
                error,
            )
        })?;
        let named_dev = namespace_dev_as_u64(&named).ok_or_else(|| {
            unsafe_storage_error(
                &self.inner.state_path.join(&self.inner.namespace_name),
                "pair-window namespace device id is not representable",
            )
        })?;
        if named_dev != self.inner.namespace_dev || named.st_ino != self.inner.namespace_ino {
            return Err(unsafe_storage_error(
                &self.inner.state_path.join(&self.inner.namespace_name),
                "pair-window generation namespace was replaced or retired",
            ));
        }
        Ok(())
    }

    fn snapshot_path(&self, name: &str) -> PathBuf {
        self.inner
            .state_path
            .join(&self.inner.namespace_name)
            .join(name)
    }

    fn read_named<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, StorageError> {
        self.validate_binding()?;
        let fd = match rustix::fs::openat(
            &self.inner.namespace_dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(error) => return Err(errno_storage_error(&self.snapshot_path(name), error)),
        };
        let mut file = File::from(fd);
        validate_snapshot_file(&self.inner.namespace_dir, &file, &self.snapshot_path(name))?;
        let metadata = file
            .metadata()
            .map_err(|error| io_storage_error(&self.snapshot_path(name), &error))?;
        if metadata.len() > MAX_SNAPSHOT_BYTES {
            return Err(unsafe_storage_error(
                &self.snapshot_path(name),
                "pair-window snapshot exceeds the 1 MiB ceiling",
            ));
        }
        let capacity = usize::try_from(metadata.len()).map_err(|_| {
            unsafe_storage_error(
                &self.snapshot_path(name),
                "pair-window snapshot length is not representable",
            )
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)
            .map_err(|error| io_storage_error(&self.snapshot_path(name), &error))?;
        self.validate_binding()?;
        cbor::from_canonical_slice(&bytes)
            .map(Some)
            .map_err(StorageError::Encoding)
    }

    fn write_named<T: Serialize>(&self, name: &str, value: &T) -> Result<(), StorageError> {
        self.validate_binding()?;
        let bytes = cbor::to_canonical_vec(value).map_err(StorageError::Encoding)?;
        if bytes.len() > usize::try_from(MAX_SNAPSHOT_BYTES).unwrap_or(usize::MAX) {
            return Err(unsafe_storage_error(
                &self.snapshot_path(name),
                "encoded pair-window snapshot exceeds the 1 MiB ceiling",
            ));
        }
        let tmp_name = self.fresh_tmp_name(name)?;
        let tmp_path = self.snapshot_path(&tmp_name);
        let fd = rustix::fs::openat(
            &self.inner.namespace_dir,
            tmp_name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| errno_storage_error(&tmp_path, error))?;
        let mut tmp = File::from(fd);
        let result = (|| {
            tmp.write_all(&bytes)
                .map_err(|error| io_storage_error(&tmp_path, &error))?;
            tmp.sync_all()
                .map_err(|error| io_storage_error(&tmp_path, &error))?;
            validate_snapshot_file(&self.inner.namespace_dir, &tmp, &tmp_path)?;
            self.validate_binding()?;
            rustix::fs::renameat(
                &self.inner.namespace_dir,
                tmp_name.as_str(),
                &self.inner.namespace_dir,
                name,
            )
            .map_err(|error| errno_storage_error(&self.snapshot_path(name), error))?;
            self.inner
                .namespace_dir
                .sync_all()
                .map_err(|error| io_storage_error(&self.snapshot_path(name), &error))?;
            self.validate_binding()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = rustix::fs::unlinkat(
                &self.inner.namespace_dir,
                tmp_name.as_str(),
                AtFlags::empty(),
            );
        }
        result
    }

    fn delete_named(&self, name: &str) -> Result<(), StorageError> {
        self.validate_binding()?;
        match rustix::fs::unlinkat(&self.inner.namespace_dir, name, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(error) => return Err(errno_storage_error(&self.snapshot_path(name), error)),
        }
        if namespace_fail_injection::take_delete_parent_sync() {
            return Err(StorageError::Io {
                path: self.snapshot_path(name),
                kind: "injected_parent_sync".into(),
                hint: "injected pair-window delete parent-sync failure".into(),
            });
        }
        // Unconditional: a previous unlink can be visible after losing its
        // parent acknowledgement. Absence is not durable before this barrier.
        self.inner
            .namespace_dir
            .sync_all()
            .map_err(|error| io_storage_error(&self.snapshot_path(name), &error))?;
        self.validate_binding()
    }

    /// Retain current only. Runs exclusively from construction while the
    /// caller's lifecycle write guard is live. Each old directory is scanned
    /// with a hard entry cap, unlinked fd-relative, then removed and root-fsynced.
    fn sweep_stale_generations(&self) -> Result<(), StorageError> {
        self.validate_binding()?;
        let scan_fd = rustix::fs::openat(
            &self.inner.state_dir,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| errno_storage_error(&self.inner.state_path, error))?;
        let root_entries = Dir::read_from(scan_fd)
            .map_err(|error| errno_storage_error(&self.inner.state_path, error))?;
        let mut stale = Vec::new();
        for entry in root_entries {
            let entry =
                entry.map_err(|error| errno_storage_error(&self.inner.state_path, error))?;
            let Some(name) = cstr_to_str(entry.file_name()) else {
                continue;
            };
            if name != self.inner.namespace_name && is_generation_namespace_name(name) {
                stale.push(name.to_owned());
            }
        }
        for name in stale {
            self.remove_stale_namespace(&name)?;
        }
        self.validate_binding()
    }

    fn remove_stale_namespace(&self, name: &str) -> Result<(), StorageError> {
        let path = self.inner.state_path.join(name);
        let fd = match rustix::fs::openat(
            &self.inner.state_dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(()),
            Err(error) => return Err(errno_storage_error(&path, error)),
        };
        let dir_file = File::from(fd);
        validate_namespace_dir(&self.inner.state_dir, &dir_file, &path)?;
        let scan_fd = rustix::fs::openat(
            &dir_file,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| errno_storage_error(&path, error))?;
        let entries = Dir::read_from(scan_fd).map_err(|error| errno_storage_error(&path, error))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| errno_storage_error(&path, error))?;
            let Some(entry_name) = cstr_to_str(entry.file_name()) else {
                return Err(unsafe_storage_error(
                    &path,
                    "non-UTF8 stale namespace entry",
                ));
            };
            if matches!(entry_name, "." | "..") {
                continue;
            }
            if names.len() == MAX_STALE_ENTRIES_PER_GENERATION {
                return Err(unsafe_storage_error(
                    &path,
                    "stale pair-window namespace exceeds bounded cleanup cap",
                ));
            }
            names.push(entry_name.to_owned());
        }
        for entry_name in names {
            let metadata =
                rustix::fs::statat(&dir_file, entry_name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|error| errno_storage_error(&path.join(&entry_name), error))?;
            if rustix::fs::FileType::from_raw_mode(metadata.st_mode)
                == rustix::fs::FileType::Directory
            {
                return Err(unsafe_storage_error(
                    &path.join(&entry_name),
                    "nested directory in stale pair-window namespace",
                ));
            }
            rustix::fs::unlinkat(&dir_file, entry_name.as_str(), AtFlags::empty())
                .map_err(|error| errno_storage_error(&path.join(&entry_name), error))?;
        }
        dir_file
            .sync_all()
            .map_err(|error| io_storage_error(&path, &error))?;
        rustix::fs::unlinkat(&self.inner.state_dir, name, AtFlags::REMOVEDIR)
            .map_err(|error| errno_storage_error(&path, error))?;
        self.inner
            .state_dir
            .sync_all()
            .map_err(|error| io_storage_error(&self.inner.state_path, &error))?;
        Ok(())
    }

    fn fresh_tmp_name(&self, name: &str) -> Result<String, StorageError> {
        let mut nonce = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|error| StorageError::Io {
                path: self.inner.state_path.clone(),
                kind: "rng".into(),
                hint: error.to_string(),
            })?;
        let mut output = String::with_capacity(name.len() + TMP_INFIX.len() + nonce.len() * 2);
        output.push_str(name);
        output.push_str(TMP_INFIX);
        for byte in nonce {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").map_err(|_| StorageError::Io {
                path: self.inner.state_path.clone(),
                kind: "format".into(),
                hint: "failed to format pair-window temp name".into(),
            })?;
        }
        Ok(output)
    }
}

/// Staged Phase-3 commit that cannot outlive the exact generation guard used
/// to resolve its private window target.
#[must_use]
pub struct PairWindowStagedCommit<'a> {
    staged: crate::storage::StagedCommit,
    namespace: &'a PairWindowNamespaceV2,
    lifecycle: &'a LifecycleWriteGuard,
}

impl PairWindowStagedCommit<'_> {
    pub fn commit(self) -> Result<(), StorageError> {
        self.namespace.validate_write_guard(self.lifecycle)?;
        self.staged.commit()
    }

    pub fn commit_preserve_on_error(self) -> Result<(), StorageError> {
        self.namespace.validate_write_guard(self.lifecycle)?;
        self.staged.commit_preserve_on_error()
    }

    pub fn preserve_for_recovery(self) {
        self.staged.preserve_for_recovery();
    }

    pub fn rollback(self) {
        self.staged.rollback();
    }
}

fn encode_generation(generation: &HouseholdLifecycleGenerationV1) -> String {
    let mut output = String::with_capacity(GENERATION_HEX_BYTES);
    for byte in generation.token_bytes() {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn cstr_to_str(name: &CStr) -> Option<&str> {
    name.to_str().ok()
}

fn is_generation_namespace_name(name: &str) -> bool {
    let Some(hex) = name.strip_prefix(NAMESPACE_PREFIX) else {
        return false;
    };
    hex.len() == GENERATION_HEX_BYTES
        && hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn remove_legacy_pair_snapshots(state_path: &Path) -> Result<(), StorageError> {
    let household_path = state_path.join("household");
    let household = match rustix::fs::open(
        &household_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(()),
        Err(error) => return Err(errno_storage_error(&household_path, error)),
    };
    let mut removed = false;
    for name in [
        "pair_window.cbor",
        "pair_device_window.cbor",
        "pair_machine_window.cbor",
    ] {
        match rustix::fs::unlinkat(&household, name, AtFlags::empty()) {
            Ok(()) => removed = true,
            Err(Errno::NOENT) => {}
            Err(error) => return Err(errno_storage_error(&household_path.join(name), error)),
        }
    }
    if removed {
        household
            .sync_all()
            .map_err(|error| io_storage_error(&household_path, &error))?;
    }
    Ok(())
}

fn open_state_root(path: &Path) -> Result<File, StorageError> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| errno_storage_error(path, error))
}

fn open_or_create_namespace(
    state_path: &Path,
    state_dir: &File,
    name: &str,
) -> Result<File, StorageError> {
    let path = state_path.join(name);
    match rustix::fs::mkdirat(state_dir, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(errno_storage_error(&path, error)),
    }
    let fd = rustix::fs::openat(
        state_dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| errno_storage_error(&path, error))?;
    let file = File::from(fd);
    validate_namespace_dir(state_dir, &file, &path)?;
    // Unconditional: a previous creator may have lost its parent acknowledgement.
    file.sync_all()
        .map_err(|error| io_storage_error(&path, &error))?;
    state_dir
        .sync_all()
        .map_err(|error| io_storage_error(state_path, &error))?;
    Ok(file)
}

fn validate_namespace_dir(parent: &File, dir: &File, path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    let parent_metadata = parent
        .metadata()
        .map_err(|error| io_storage_error(path, &error))?;
    let metadata = dir
        .metadata()
        .map_err(|error| io_storage_error(path, &error))?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != parent_metadata.uid()
        || metadata.nlink() < 2
    {
        return Err(unsafe_storage_error(
            path,
            "pair-window namespace is unsafe",
        ));
    }
    Ok(())
}

fn validate_snapshot_file(parent: &File, file: &File, path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    let parent_metadata = parent
        .metadata()
        .map_err(|error| io_storage_error(path, &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_storage_error(path, &error))?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != parent_metadata.uid()
        || metadata.nlink() != 1
    {
        return Err(unsafe_storage_error(path, "pair-window snapshot is unsafe"));
    }
    Ok(())
}

fn lifecycle_storage_error(path: &Path, error: HouseholdLifecycleLockError) -> StorageError {
    StorageError::Io {
        path: path.to_path_buf(),
        kind: "household_lifecycle".into(),
        hint: error.to_string(),
    }
}

/// Widens `Stat::st_dev` to the `u64` that `namespace_dev` is stored as.
///
/// `namespace_dev` comes from `MetadataExt::dev()`, which is `u64` on every
/// Unix, but `st_dev` is `dev_t`, whose width is decided by the target *vendor*:
/// `libc` defines it in `unix/bsd/apple/mod.rs` as `i32` for all five Apple
/// targets, and as `u64` for every Linux flavour (gnu and musl alike).
///
/// So the narrowing check is real on Apple and an identity on Linux, where
/// `u64::try_from` would trip `clippy::useless_conversion`. It must stay
/// fallible on Apple: `st_dev as u64` would silence the lint on both sides and
/// map a negative `dev_t` onto a huge `u64`, deleting the caller's
/// "not representable" error path — the one case that path exists for.
///
/// The split is on `target_vendor` rather than `any(macos, ios)` because vendor
/// is the property `libc` itself switches on; enumerating OSes would break if a
/// sixth Apple target appeared.
#[cfg(target_vendor = "apple")]
fn namespace_dev_as_u64(named: &rustix::fs::Stat) -> Option<u64> {
    u64::try_from(named.st_dev).ok()
}

// The `Option` is trivially `Some` here, which `clippy::unnecessary_wraps`
// (pedantic, on via the workspace lint table) rejects. It is not unnecessary —
// it is unnecessary *on this platform*. Both arms must expose the same
// signature so the single call site stays cfg-free and keeps one `ok_or_else`
// carrying the "not representable" error; narrowing this arm to `-> u64` would
// force the caller to be cfg-gated too.
#[cfg(not(target_vendor = "apple"))]
#[allow(clippy::unnecessary_wraps)]
fn namespace_dev_as_u64(named: &rustix::fs::Stat) -> Option<u64> {
    Some(named.st_dev)
}

fn unsafe_storage_error(path: &Path, hint: &str) -> StorageError {
    StorageError::Io {
        path: path.to_path_buf(),
        kind: "unsafe_path".into(),
        hint: hint.into(),
    }
}

fn stale_generation_error(path: &Path) -> StorageError {
    StorageError::Encoding(HouseholdError::InvalidRecord(format!(
        "pair-window namespace no longer matches the current lifecycle generation: {}",
        path.display()
    )))
}

fn errno_storage_error(path: &Path, error: Errno) -> StorageError {
    StorageError::Io {
        path: path.to_path_buf(),
        kind: error.to_string(),
        hint: "pair-window namespace I/O failed".into(),
    }
}

fn io_storage_error(path: &Path, error: &std::io::Error) -> StorageError {
    StorageError::Io {
        path: path.to_path_buf(),
        kind: error.kind().to_string(),
        hint: error.to_string(),
    }
}

#[cfg(test)]
mod namespace_fail_injection {
    use std::cell::Cell;

    thread_local! {
        static FAIL_DELETE_PARENT_SYNC: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn arm_delete_parent_sync() {
        FAIL_DELETE_PARENT_SYNC.with(|armed| armed.set(true));
    }

    pub(super) fn take_delete_parent_sync() -> bool {
        crate::crash_park::park_if_armed("namespace:delete_parent_sync");
        FAIL_DELETE_PARENT_SYNC.with(|armed| armed.replace(false))
    }
}

#[cfg(not(test))]
mod namespace_fail_injection {
    pub(super) const fn take_delete_parent_sync() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn namespace_name_is_fixed_width_and_outside_household() {
        let temp = TempDir::new().unwrap();
        let namespace = PairWindowNamespaceV2::current(temp.path().to_path_buf()).unwrap();
        let path = namespace.pair_machine_snapshot_path();
        let namespace_name = path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            namespace_name.len(),
            NAMESPACE_PREFIX.len() + GENERATION_HEX_BYTES
        );
        assert_eq!(path.parent().unwrap().parent(), Some(temp.path()));
        assert!(!path.starts_with(temp.path().join("household")));
    }

    #[test]
    fn rotation_sweeps_old_generation_and_stale_capability_cannot_recreate_it() {
        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let old = PairWindowNamespaceV2::current_under_lifecycle(temp.path().to_path_buf(), &guard)
            .unwrap();
        old.write_pair_device_under_lifecycle(&17_u64, &guard)
            .unwrap();
        let old_dir = old
            .pair_device_snapshot_path()
            .parent()
            .unwrap()
            .to_path_buf();
        guard.rotate_lifecycle_generation().unwrap();
        let current =
            PairWindowNamespaceV2::current_under_lifecycle(temp.path().to_path_buf(), &guard)
                .unwrap();
        assert!(!old_dir.exists());
        current
            .write_pair_device_under_lifecycle(&23_u64, &guard)
            .unwrap();
        assert!(
            old.write_pair_device_under_lifecycle(&17_u64, &guard)
                .is_err()
        );
        assert!(!old_dir.exists());
        assert_eq!(
            current
                .read_pair_device_under_lifecycle::<u64>(&guard)
                .unwrap(),
            Some(23)
        );
    }

    #[test]
    fn legacy_unscoped_snapshot_is_deleted_without_adoption() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir(temp.path().join("household")).unwrap();
        for name in [
            "pair_window.cbor",
            "pair_device_window.cbor",
            "pair_machine_window.cbor",
        ] {
            std::fs::write(temp.path().join("household").join(name), b"legacy").unwrap();
        }
        let namespace = PairWindowNamespaceV2::current(temp.path().to_path_buf()).unwrap();
        for name in [
            "pair_window.cbor",
            "pair_device_window.cbor",
            "pair_machine_window.cbor",
        ] {
            assert!(!temp.path().join("household").join(name).exists());
        }
        assert_eq!(namespace.read_pair_device::<u64>().unwrap(), None);
        assert_eq!(namespace.read_pair_machine::<u64>().unwrap(), None);
    }

    #[test]
    fn delete_never_reports_success_before_parent_barrier_and_retry_stabilizes_absence() {
        let temp = TempDir::new().unwrap();
        let namespace = PairWindowNamespaceV2::current(temp.path().to_path_buf()).unwrap();
        namespace.write_pair_device(&41_u64).unwrap();
        namespace_fail_injection::arm_delete_parent_sync();
        assert!(namespace.delete_pair_device().is_err());
        assert!(!namespace.pair_device_snapshot_path().exists());
        namespace.delete_pair_device().unwrap();
        assert!(!namespace.pair_device_snapshot_path().exists());
    }

    #[test]
    fn retention_is_current_generation_only_after_many_rotations() {
        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        for value in 0_u64..12 {
            if value != 0 {
                guard.rotate_lifecycle_generation().unwrap();
            }
            let namespace =
                PairWindowNamespaceV2::current_under_lifecycle(temp.path().to_path_buf(), &guard)
                    .unwrap();
            namespace
                .write_pair_device_under_lifecycle(&value, &guard)
                .unwrap();
        }
        let count = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(is_generation_namespace_name)
            })
            .count();
        assert_eq!(count, 1, "retention rule is current generation only");
    }

    #[test]
    fn stale_capability_cannot_stage_or_rematerialize_old_generation() {
        let temp = TempDir::new().unwrap();
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let stale =
            PairWindowNamespaceV2::current_under_lifecycle(temp.path().to_path_buf(), &guard)
                .unwrap();
        let old_dir = stale
            .pair_machine_snapshot_path()
            .parent()
            .unwrap()
            .to_path_buf();
        guard.rotate_lifecycle_generation().unwrap();
        PairWindowNamespaceV2::current_under_lifecycle(temp.path().to_path_buf(), &guard).unwrap();
        assert!(!old_dir.exists());
        assert!(
            stale
                .stage_pair_machine_commit_under_lifecycle(
                    &guard,
                    Vec::new(),
                    vec![0xA0],
                    (temp.path().join("commit-marker"), vec![0x01]),
                )
                .is_err()
        );
        assert!(!old_dir.exists());
    }
}
