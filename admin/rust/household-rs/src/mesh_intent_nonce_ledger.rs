//! Durable replay authority for signed mesh connection-intent nonces.
//!
//! One canonical record below `state_dir/household/mesh_intent_nonce_ledger`
//! is the complete authority for one target household, so production teardown
//! carries or removes the replay authority with the household lifecycle.
//! A stable `fs2` lock serializes the read/modify/write transaction across
//! processes. The lock file also carries a tiny durable clean/dirty marker:
//! an operation marks the record dirty *before* replacing it and marks it
//! clean only after rename, parent-directory fsync, and byte-exact readback.
//! A later process therefore never treats a merely visible post-rename record
//! as proof of durability; it first rewrites the same canonical bytes until
//! they are committed.
//! The ledger lock inode is hard-linked inside the household as a durable
//! anchor. A separate empty lifecycle lock in the stable state root is held
//! shared across every complete ledger transaction. Teardown/install hold it
//! exclusive, so the final binding check cannot be followed by a detached
//! dirfd write.
//! Every record operation is relative to retained root, household, and store
//! directory descriptors. The complete root→household→store chain and lock
//! binding are checked before and after locking, so a detached household
//! handle cannot keep mutating teardown state.
//!
//! The replay key is exactly
//! `(domain, hh_id, initiator_m_id, delegated_key_id, nonce[32])`. Channel and
//! intent digest are retained evidence, not additional replay namespaces.
//! Expired rows may be removed only when a caller-provided trusted wall floor
//! is *strictly greater* than `not_after`.
//!
//! The store accepts only measured, local, persistent filesystem families
//! (APFS on macOS; ext4, XFS, or Btrfs on Linux). It rejects tmpfs, NFS, and
//! unknown filesystems before creating authority. The state root must be owned
//! by the effective uid and not group/world writable; the ledger child and
//! lock are private to that uid. A non-cooperative process running as the same
//! uid and manipulating directory entries directly is outside this
//! component's threat model; deployment must keep the state directory
//! exclusive to the service account.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError, Weak, mpsc};
use std::time::{Duration, Instant};

use fs2::FileExt;
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::cbor;
#[cfg(test)]
use crate::household_lifecycle::HOUSEHOLD_TEARDOWN_BREADCRUMB;
use crate::household_lifecycle::{
    HouseholdLifecycleLock, HouseholdLifecycleLockError, LifecycleReadGuard,
};
use crate::ids::{HouseholdId, MachineId};
use crate::storage::HOUSEHOLD_SUBDIR;

pub use crate::machine_roster_store::TrustedWallFloor;

/// Domain component of every nonce replay key.
pub const MESH_INTENT_NONCE_KEY_DOMAIN: &str = "ledger-domain-v1";

const STORE_SUBDIR: &str = "mesh_intent_nonce_ledger";
const RECORD_FILENAME: &str = "ledger_v1.cbor";
const TEMP_FILENAME: &str = ".ledger_v1.cbor.tmp";
const LOCK_FILENAME: &str = "ledger_v1.lock";
const LOCK_ANCHOR_FILENAME: &str = ".mesh_intent_nonce_ledger_v1.anchor";
const RECORD_DOMAIN: &str = "soyeht/mesh-intent-nonce-ledger/v1";
const RECORD_VERSION: u8 = 1;
const MAX_DELEGATED_KEY_ID_BYTES: usize = 256;
const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONFIGURED_ENTRIES: usize = 8_192;
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(5);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(5);
const WORKER_QUEUE_CAPACITY: usize = 1;

#[cfg(any(test, target_os = "linux"))]
const EXT4_SUPER_MAGIC: i64 = 0x0000_EF53;
#[cfg(any(test, target_os = "linux"))]
const XFS_SUPER_MAGIC: i64 = 0x5846_5342;
#[cfg(any(test, target_os = "linux"))]
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;
// `pub(crate)` ONLY so `household_lifecycle` can pin its own allowlist equal
// to this one. There are two filesystem allowlists in this crate and they must
// not drift; a crosscheck cannot exist if neither can see the other. Not
// widened beyond the crate, and nothing outside the crosscheck reads it.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const LINUX_RENAME_KNOWN_NO_EFFECT_FILESYSTEMS: [i64; 3] =
    [EXT4_SUPER_MAGIC, XFS_SUPER_MAGIC, BTRFS_SUPER_MAGIC];
#[cfg(any(test, target_os = "macos"))]
pub(crate) const MACOS_RENAME_KNOWN_NO_EFFECT_FILESYSTEMS: [&[u8]; 1] = [b"apfs"];
#[cfg(test)]
const TMPFS_SUPER_MAGIC: i64 = 0x0102_1994;
#[cfg(test)]
const NFS_SUPER_MAGIC: i64 = 0x0000_6969;

const MARKER_INITIALIZING: &[u8] = b"MSNL1:I\n";
const MARKER_CLEAN: &[u8] = b"MSNL1:C\n";
const MARKER_DIRTY: &[u8] = b"MSNL1:D\n";

mod bstr32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?.into_vec();
        if bytes.len() != 32 {
            return Err(D::Error::custom("expected a 32-byte byte string"));
        }
        let mut out = [0_u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MeshIntentChannel {
    Dev,
    Release,
}

/// Canonical replay key. Channel and digest deliberately do not appear here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshIntentNonceKey {
    hh_id: HouseholdId,
    initiator_m_id: MachineId,
    delegated_key_id: String,
    nonce: [u8; 32],
}

impl MeshIntentNonceKey {
    pub fn new(
        hh_id: HouseholdId,
        initiator_m_id: MachineId,
        delegated_key_id: impl Into<String>,
        nonce: [u8; 32],
    ) -> Result<Self, MeshIntentNonceKeyError> {
        if !HouseholdId::is_well_formed(hh_id.as_str()) {
            return Err(MeshIntentNonceKeyError::InvalidHouseholdId);
        }
        if !MachineId::is_well_formed(initiator_m_id.as_str()) {
            return Err(MeshIntentNonceKeyError::InvalidInitiatorMachineId);
        }
        let delegated_key_id = delegated_key_id.into();
        if delegated_key_id.is_empty()
            || delegated_key_id.len() > MAX_DELEGATED_KEY_ID_BYTES
            || delegated_key_id.chars().any(char::is_control)
        {
            return Err(MeshIntentNonceKeyError::InvalidDelegatedKeyId);
        }
        Ok(Self {
            hh_id,
            initiator_m_id,
            delegated_key_id,
            nonce,
        })
    }

    #[must_use]
    pub fn household_id(&self) -> &HouseholdId {
        &self.hh_id
    }

    #[must_use]
    pub fn initiator_machine_id(&self) -> &MachineId {
        &self.initiator_m_id
    }

    #[must_use]
    pub fn delegated_key_id(&self) -> &str {
        &self.delegated_key_id
    }

    #[must_use]
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum MeshIntentNonceKeyError {
    #[error("household id is malformed")]
    InvalidHouseholdId,
    #[error("initiator machine id is malformed")]
    InvalidInitiatorMachineId,
    #[error("delegated key id is empty, oversized, or contains a control character")]
    InvalidDelegatedKeyId,
}

/// Evidence retained beside a consumed replay key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshIntentNonceEvidence {
    channel: MeshIntentChannel,
    intent_digest: [u8; 32],
    not_after: u64,
}

impl MeshIntentNonceEvidence {
    pub fn new(
        channel: MeshIntentChannel,
        intent_digest: [u8; 32],
        not_after: u64,
    ) -> Result<Self, MeshIntentNonceEvidenceError> {
        if not_after == 0 {
            return Err(MeshIntentNonceEvidenceError::ZeroNotAfter);
        }
        Ok(Self {
            channel,
            intent_digest,
            not_after,
        })
    }

    #[must_use]
    pub fn channel(&self) -> MeshIntentChannel {
        self.channel
    }

    #[must_use]
    pub fn intent_digest(&self) -> &[u8; 32] {
        &self.intent_digest
    }

    #[must_use]
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum MeshIntentNonceEvidenceError {
    #[error("not_after must be non-zero")]
    ZeroNotAfter,
}

/// Monotonic deadline inherited from the whole connection ceremony.
///
/// Unlike the trusted wall floor this is not authority-bearing; a caller may
/// only shorten its own attempt. The ledger never extends this deadline to its
/// configured lock timeout.
#[derive(Clone, Debug)]
pub struct MeshIntentNonceConsumeControl {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl MeshIntentNonceConsumeControl {
    #[must_use]
    pub fn from_absolute_deadline(deadline: Instant) -> Self {
        Self {
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cancel every in-flight attempt sharing this control token.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Persisted capacity is part of the record contract, so processes cannot
/// silently use different retention policies against the same ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshIntentNonceLedgerConfig {
    capacity: NonZeroUsize,
    lock_timeout: Duration,
}

impl MeshIntentNonceLedgerConfig {
    pub fn new(
        capacity: NonZeroUsize,
        lock_timeout: Duration,
    ) -> Result<Self, MeshIntentNonceLedgerConfigError> {
        if capacity.get() > MAX_CONFIGURED_ENTRIES {
            return Err(MeshIntentNonceLedgerConfigError::CapacityTooLarge);
        }
        if lock_timeout.is_zero() {
            return Err(MeshIntentNonceLedgerConfigError::ZeroLockTimeout);
        }
        Ok(Self {
            capacity,
            lock_timeout,
        })
    }

    #[must_use]
    pub const fn capacity(self) -> NonZeroUsize {
        self.capacity
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum MeshIntentNonceLedgerConfigError {
    #[error("ledger capacity exceeds the hard record bound")]
    CapacityTooLarge,
    #[error("lock timeout must be non-zero")]
    ZeroLockTimeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshIntentNonceCommitStage {
    /// The caller's deadline/cancellation won after a non-cancellable worker
    /// took ownership of the transaction. The worker remains responsible for
    /// reaching a durable terminal state; callers must reconcile by replaying
    /// the exact same key.
    WorkerInFlight,
    DirtyMarkerWrite,
    DirtyMarkerSync,
    TempInspect,
    TempCleanup,
    TempOpen,
    TempWrite,
    TempFlush,
    TempSync,
    Rename,
    ParentSync,
    Readback,
    ReadbackMismatch,
    CleanMarkerWrite,
    CleanMarkerSync,
    /// CLEAN is durable, but the lifecycle or household binding changed
    /// before the result could be returned. The semantic effect may exist.
    PostCommitBinding,
}

impl MeshIntentNonceCommitStage {
    #[must_use]
    pub const fn may_have_changed_record(self) -> bool {
        match self {
            Self::DirtyMarkerWrite
            | Self::DirtyMarkerSync
            | Self::TempInspect
            | Self::TempCleanup
            | Self::TempOpen
            | Self::TempWrite
            | Self::TempFlush
            | Self::TempSync
            | Self::Rename => false,
            Self::WorkerInFlight
            | Self::ParentSync
            | Self::Readback
            | Self::ReadbackMismatch
            | Self::CleanMarkerWrite
            | Self::CleanMarkerSync
            | Self::PostCommitBinding => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshIntentNonceUnavailable {
    WrongHousehold,
    WrongTrustedFloorHousehold,
    EvidenceExpired,
    CapacityExhausted,
    GenerationExhausted,
    LockTimeout,
    DeadlineExceeded,
    Cancelled,
    LockPoisoned,
    UnsafePath,
    UnsupportedFilesystem,
    CorruptRecord,
    PolicyMismatch,
    RecordTooLarge,
    RecoveryRequired,
    Io,
    WriteFailed(MeshIntentNonceCommitStage),
}

/// Exhaustive result of one atomic nonce consumption attempt.
///
/// There is intentionally no `Result<()>`: callers must distinguish an
/// idempotent replay, an indeterminate post-rename attempt, and an unavailable
/// authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeshIntentNonceConsumeOutcome {
    Committed { generation: u64 },
    AlreadyConsumed { evidence: MeshIntentNonceEvidence },
    MayHaveTakenEffect { stage: MeshIntentNonceCommitStage },
    Unavailable { reason: MeshIntentNonceUnavailable },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum MeshIntentNonceLedgerOpenError {
    #[error("ledger household identity is malformed")]
    InvalidIdentity,
    #[error("the physical ledger authority is already bound to another household")]
    AuthorityConflict,
    #[error("ledger path is unsafe")]
    UnsafePath,
    #[error("ledger requires an allowlisted local persistent filesystem")]
    UnsupportedFilesystem,
    #[error("ledger lock timed out")]
    LockTimeout,
    #[error("ledger lock is poisoned")]
    LockPoisoned,
    #[error("ledger I/O failed")]
    Io,
    #[error("ledger record or marker is corrupt")]
    Corrupt,
    #[error("ledger capacity differs from its persisted policy")]
    PolicyMismatch,
    #[error("ledger record exceeds its hard byte bound")]
    RecordTooLarge,
    #[error("ledger durability recovery did not complete")]
    RecoveryRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredKeyV1 {
    domain: String,
    hh_id: HouseholdId,
    initiator_m_id: MachineId,
    delegated_key_id: String,
    #[serde(with = "bstr32")]
    nonce: [u8; 32],
}

impl From<&MeshIntentNonceKey> for StoredKeyV1 {
    fn from(key: &MeshIntentNonceKey) -> Self {
        Self {
            domain: MESH_INTENT_NONCE_KEY_DOMAIN.to_owned(),
            hh_id: key.hh_id.clone(),
            initiator_m_id: key.initiator_m_id.clone(),
            delegated_key_id: key.delegated_key_id.clone(),
            nonce: key.nonce,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEntryV1 {
    key: StoredKeyV1,
    channel: MeshIntentChannel,
    #[serde(with = "bstr32")]
    intent_digest: [u8; 32],
    not_after: u64,
}

impl StoredEntryV1 {
    fn evidence(&self) -> MeshIntentNonceEvidence {
        MeshIntentNonceEvidence {
            channel: self.channel,
            intent_digest: self.intent_digest,
            not_after: self.not_after,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerRecordV1 {
    #[serde(rename = "v")]
    version: u8,
    domain: String,
    hh_id: HouseholdId,
    capacity: u32,
    generation: u64,
    entries: BTreeMap<String, StoredEntryV1>,
}

impl LedgerRecordV1 {
    fn empty(hh_id: HouseholdId, capacity: NonZeroUsize) -> Self {
        Self {
            version: RECORD_VERSION,
            domain: RECORD_DOMAIN.to_owned(),
            hh_id,
            capacity: u32::try_from(capacity.get()).expect("capacity hard-bound fits u32"),
            generation: 1,
            entries: BTreeMap::new(),
        }
    }
}

struct LedgerInner {
    target_hh_id: HouseholdId,
    config: MeshIntentNonceLedgerConfig,
    state_dir: File,
    household_dir: File,
    store_dir: File,
    lifecycle: HouseholdLifecycleLock,
    lock_file: Mutex<File>,
    worker_tx: mpsc::SyncSender<WorkerRequest>,
    #[cfg(test)]
    worker_block: Mutex<Option<Arc<TestWorkerBlock>>>,
    #[cfg(test)]
    queued_for_test: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    queue_waiters_for_test: std::sync::atomic::AtomicUsize,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct LedgerAuthorityId {
    state_dev: u64,
    state_ino: u64,
    household_dev: u64,
    household_ino: u64,
    store_dev: u64,
    store_ino: u64,
}

fn process_ledger_registry() -> &'static Mutex<HashMap<LedgerAuthorityId, Weak<LedgerInner>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<LedgerAuthorityId, Weak<LedgerInner>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

struct WorkerRequest {
    inner: Arc<LedgerInner>,
    key: MeshIntentNonceKey,
    evidence: MeshIntentNonceEvidence,
    trusted_floor: TrustedWallFloor,
    result_tx: mpsc::SyncSender<MeshIntentNonceConsumeOutcome>,
    #[cfg(test)]
    failpoint: Option<MeshIntentNonceCommitStage>,
}

#[cfg(test)]
struct TestWorkerBlock {
    entered: std::sync::Barrier,
    release: std::sync::Barrier,
}

fn spawn_worker(
    worker_rx: mpsc::Receiver<WorkerRequest>,
) -> Result<(), MeshIntentNonceLedgerOpenError> {
    std::thread::Builder::new()
        .name("mesh-intent-nonce-ledger".to_owned())
        .spawn(move || {
            while let Ok(request) = worker_rx.recv() {
                #[cfg(test)]
                request.inner.queued_for_test.fetch_sub(1, Ordering::AcqRel);
                #[cfg(test)]
                let _worker_failpoint = request.failpoint.map(fail_injection::arm);
                let ledger = MeshIntentNonceLedger {
                    inner: request.inner,
                };
                let outcome = ledger.consume_in_worker(
                    &request.key,
                    &request.evidence,
                    &request.trusted_floor,
                );
                let _ = request.result_tx.send(outcome);
            }
        })
        .map(|_| ())
        .map_err(|_| MeshIntentNonceLedgerOpenError::Io)
}

#[cfg(test)]
impl TestWorkerBlock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        })
    }
}

/// Narrow household-owned replay authority. It has no dependency on the
/// moving mesh-session core trait and can be adapted to it later.
#[derive(Clone)]
pub struct MeshIntentNonceLedger {
    inner: Arc<LedgerInner>,
}

impl MeshIntentNonceLedger {
    /// Low-level constructor. Production callers obtain the unique authority
    /// from `MachineRosterCoordinator::open_mesh_intent_nonce_ledger`, which
    /// binds both the state directory and household id.
    pub(crate) fn open(
        state_dir: impl AsRef<Path>,
        target_hh_id: HouseholdId,
        config: MeshIntentNonceLedgerConfig,
    ) -> Result<Self, MeshIntentNonceLedgerOpenError> {
        if !HouseholdId::is_well_formed(target_hh_id.as_str()) {
            return Err(MeshIntentNonceLedgerOpenError::InvalidIdentity);
        }
        // `open_verified` unconditionally syncs both the stable lock file and
        // its state-root parent, including retries where the lock is already
        // visible. No usable ledger escapes before that dirent is durable.
        let lifecycle = HouseholdLifecycleLock::open_verified(state_dir.as_ref())
            .map_err(map_lifecycle_to_open)?;
        let lifecycle_deadline = Instant::now()
            .checked_add(config.lock_timeout)
            .ok_or(MeshIntentNonceLedgerOpenError::LockTimeout)?;
        let lifecycle_guard = lifecycle
            .lock_shared_until(lifecycle_deadline)
            .map_err(map_lifecycle_to_open)?;
        let state_dir = lifecycle.clone_state_dir().map_err(map_lifecycle_to_open)?;
        let (state_dir, household_dir, store_dir) = open_store_dirs(state_dir)?;
        let authority_id = ledger_authority_id(&state_dir, &household_dir, &store_dir)?;
        let mut registry = process_ledger_registry()
            .lock()
            .map_err(|_| MeshIntentNonceLedgerOpenError::LockPoisoned)?;
        registry.retain(|_, authority| authority.strong_count() != 0);
        if let Some(existing) = registry.get(&authority_id).and_then(Weak::upgrade) {
            if existing.target_hh_id != target_hh_id {
                return Err(MeshIntentNonceLedgerOpenError::AuthorityConflict);
            }
            if existing.config != config {
                return Err(MeshIntentNonceLedgerOpenError::PolicyMismatch);
            }
            if !verify_authority_binding(
                &existing.state_dir,
                &existing.household_dir,
                &existing.store_dir,
            ) {
                return Err(MeshIntentNonceLedgerOpenError::UnsafePath);
            }
            let ledger = Self { inner: existing };
            ledger.initialize_or_recover(lifecycle_guard)?;
            return Ok(ledger);
        }

        let (lock_file, lock_created) = open_lock_file(&store_dir)?;
        verify_or_create_lock_anchor(&household_dir, &store_dir, &lock_file, lock_created)?;
        let (worker_tx, worker_rx) = mpsc::sync_channel(WORKER_QUEUE_CAPACITY);
        let ledger = Self {
            inner: Arc::new(LedgerInner {
                target_hh_id,
                config,
                state_dir,
                household_dir,
                store_dir,
                lifecycle,
                lock_file: Mutex::new(lock_file),
                worker_tx,
                #[cfg(test)]
                worker_block: Mutex::new(None),
                #[cfg(test)]
                queued_for_test: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                queue_waiters_for_test: std::sync::atomic::AtomicUsize::new(0),
            }),
        };
        ledger.initialize_or_recover(lifecycle_guard)?;
        spawn_worker(worker_rx)?;
        registry.insert(authority_id, Arc::downgrade(&ledger.inner));
        Ok(ledger)
    }

    #[must_use]
    pub fn target_household_id(&self) -> &HouseholdId {
        &self.inner.target_hh_id
    }

    #[cfg(test)]
    pub(crate) fn shares_process_worker_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    #[must_use]
    pub fn consume(
        &self,
        key: &MeshIntentNonceKey,
        evidence: &MeshIntentNonceEvidence,
        trusted_floor: TrustedWallFloor,
        control: &MeshIntentNonceConsumeControl,
    ) -> MeshIntentNonceConsumeOutcome {
        if key.hh_id != self.inner.target_hh_id {
            return unavailable(MeshIntentNonceUnavailable::WrongHousehold);
        }
        if trusted_floor.household_id() != &self.inner.target_hh_id {
            return unavailable(MeshIntentNonceUnavailable::WrongTrustedFloorHousehold);
        }
        if evidence.not_after <= trusted_floor.unix_seconds() {
            return unavailable(MeshIntentNonceUnavailable::EvidenceExpired);
        }
        if let Some(reason) = abort_reason(control) {
            return unavailable(reason);
        }

        #[cfg(test)]
        let worker_failpoint = fail_injection::take_armed();
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let mut request = WorkerRequest {
            inner: self.inner.clone(),
            key: key.clone(),
            evidence: evidence.clone(),
            trusted_floor,
            result_tx,
            #[cfg(test)]
            failpoint: worker_failpoint,
        };
        #[cfg(test)]
        let mut registered_waiter = false;
        loop {
            if let Some(reason) = abort_reason(control) {
                #[cfg(test)]
                if registered_waiter {
                    self.inner
                        .queue_waiters_for_test
                        .fetch_sub(1, Ordering::AcqRel);
                }
                return unavailable(reason);
            }
            #[cfg(test)]
            self.inner.queued_for_test.fetch_add(1, Ordering::AcqRel);
            match self.inner.worker_tx.try_send(request) {
                Ok(()) => {
                    #[cfg(test)]
                    if registered_waiter {
                        self.inner
                            .queue_waiters_for_test
                            .fetch_sub(1, Ordering::AcqRel);
                    }
                    break;
                }
                Err(mpsc::TrySendError::Full(returned)) => {
                    #[cfg(test)]
                    {
                        self.inner.queued_for_test.fetch_sub(1, Ordering::AcqRel);
                        if !registered_waiter {
                            self.inner
                                .queue_waiters_for_test
                                .fetch_add(1, Ordering::AcqRel);
                        }
                    }
                    #[cfg(test)]
                    {
                        registered_waiter = true;
                    }
                    request = returned;
                    std::thread::sleep(WORKER_POLL_INTERVAL);
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    #[cfg(test)]
                    {
                        self.inner.queued_for_test.fetch_sub(1, Ordering::AcqRel);
                        if registered_waiter {
                            self.inner
                                .queue_waiters_for_test
                                .fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    return unavailable(MeshIntentNonceUnavailable::Io);
                }
            }
        }

        // Only a successfully enqueued request can become WorkerInFlight.
        loop {
            match result_rx.try_recv() {
                Ok(outcome) => return outcome,
                Err(mpsc::TryRecvError::Disconnected) => {
                    return MeshIntentNonceConsumeOutcome::MayHaveTakenEffect {
                        stage: MeshIntentNonceCommitStage::WorkerInFlight,
                    };
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if abort_reason(control).is_some() {
                return MeshIntentNonceConsumeOutcome::MayHaveTakenEffect {
                    stage: MeshIntentNonceCommitStage::WorkerInFlight,
                };
            }
            let remaining = control.deadline.saturating_duration_since(Instant::now());
            match result_rx.recv_timeout(remaining.min(WORKER_POLL_INTERVAL)) {
                Ok(outcome) => return outcome,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return MeshIntentNonceConsumeOutcome::MayHaveTakenEffect {
                        stage: MeshIntentNonceCommitStage::WorkerInFlight,
                    };
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn consume_in_worker(
        &self,
        key: &MeshIntentNonceKey,
        evidence: &MeshIntentNonceEvidence,
        trusted_floor: &TrustedWallFloor,
    ) -> MeshIntentNonceConsumeOutcome {
        debug_assert_eq!(key.hh_id, self.inner.target_hh_id);
        debug_assert_eq!(trusted_floor.household_id(), &self.inner.target_hh_id);

        // Once spawned, this transaction is intentionally non-cancellable.
        // `fsync`/`rename` cannot be safely interrupted; the worker owns the
        // duty to finish or leave durable recovery evidence.
        let mut guard = match self.acquire(None) {
            Ok(guard) => guard,
            Err(reason) => return unavailable(reason),
        };
        let mut record = match self.load_clean_record(&mut guard) {
            Ok(record) => record,
            Err(reason) => return unavailable(reason),
        };
        // Strict `>` is intentional. Equality is still retained even though a
        // fresh intent at equality is no longer admissible.
        record
            .entries
            .retain(|_, entry| trusted_floor.unix_seconds() <= entry.not_after);

        let stored_key = StoredKeyV1::from(key);
        let Ok(entry_id) = entry_id(&stored_key) else {
            return unavailable(MeshIntentNonceUnavailable::CorruptRecord);
        };
        if let Some(existing) = record.entries.get(&entry_id) {
            if existing.key != stored_key {
                return unavailable(MeshIntentNonceUnavailable::CorruptRecord);
            }
            return MeshIntentNonceConsumeOutcome::AlreadyConsumed {
                evidence: existing.evidence(),
            };
        }

        if record.entries.len() >= self.inner.config.capacity.get() {
            return unavailable(MeshIntentNonceUnavailable::CapacityExhausted);
        }
        let Some(next_generation) = record.generation.checked_add(1) else {
            return unavailable(MeshIntentNonceUnavailable::GenerationExhausted);
        };
        record.generation = next_generation;
        record.entries.insert(
            entry_id,
            StoredEntryV1 {
                key: stored_key,
                channel: evidence.channel,
                intent_digest: evidence.intent_digest,
                not_after: evidence.not_after,
            },
        );

        let canonical = match cbor::to_canonical_vec(&record) {
            Ok(bytes) if bytes.len() <= MAX_RECORD_BYTES => bytes,
            Ok(_) => return unavailable(MeshIntentNonceUnavailable::RecordTooLarge),
            Err(_) => return unavailable(MeshIntentNonceUnavailable::CorruptRecord),
        };
        self.commit_semantic(&mut guard, &canonical, next_generation)
    }

    #[cfg(test)]
    fn install_worker_block_for_test(&self, block: Arc<TestWorkerBlock>) {
        *self.inner.worker_block.lock().unwrap() = Some(block);
    }

    #[cfg(test)]
    fn block_worker_once_for_test(&self) {
        let block = self.inner.worker_block.lock().unwrap().take();
        if let Some(block) = block {
            block.entered.wait();
            block.release.wait();
        }
    }

    fn initialize_or_recover(
        &self,
        lifecycle: LifecycleReadGuard,
    ) -> Result<(), MeshIntentNonceLedgerOpenError> {
        // `open` already holds lifecycle-shared before it takes the process
        // registry mutex. Reuse that exact guard so initialization follows
        // the single lock order lifecycle -> registry -> ledger; reacquiring
        // lifecycle here could wait behind an exclusive waiter that itself
        // cannot proceed until our first shared guard is released.
        let mut guard = self
            .acquire_after_lifecycle(lifecycle, None)
            .map_err(map_unavailable_to_open)?;
        let marker = read_marker(&mut guard).map_err(map_open_io)?;
        let visible_record = read_optional_record(&self.inner.store_dir, RECORD_FILENAME)
            .map_err(map_unavailable_to_open)?;

        match (visible_record, marker.as_deref()) {
            (Some(bytes), Some(MARKER_CLEAN)) => {
                self.decode_and_validate(&bytes)
                    .map_err(map_unavailable_to_open)?;
                Ok(())
            }
            // A marker write can tear after truncate and before write_all or
            // sync. Marker visibility is never authority: if a valid record is
            // visible, rewrite those exact bytes through the full durability
            // protocol and only then publish CLEAN. This covers DIRTY,
            // INITIALIZING, empty, unknown, and every partial prefix.
            (Some(bytes), _) => self.stabilize_visible_under_lock(&mut guard, &bytes),
            // Crash after creating/anchoring the lock, or a torn first write
            // of INITIALIZING, has no semantic record to lose. Empty and
            // byte-prefix-only INITIALIZING therefore resume initialization.
            (None, None) => self.initialize_fresh_under_lock(&mut guard),
            (None, Some(marker)) if MARKER_INITIALIZING.starts_with(marker) => {
                self.initialize_fresh_under_lock(&mut guard)
            }
            // CLEAN/DIRTY/unknown marker plus a missing record is not a fresh
            // store. Treat it as deletion/corruption and fail closed.
            (None, Some(_)) => Err(MeshIntentNonceLedgerOpenError::Corrupt),
        }
    }

    fn initialize_fresh_under_lock(
        &self,
        guard: &mut LedgerLockGuard<'_>,
    ) -> Result<(), MeshIntentNonceLedgerOpenError> {
        write_marker_raw(guard, MARKER_INITIALIZING).map_err(map_open_io)?;
        let record =
            LedgerRecordV1::empty(self.inner.target_hh_id.clone(), self.inner.config.capacity);
        let bytes =
            cbor::to_canonical_vec(&record).map_err(|_| MeshIntentNonceLedgerOpenError::Corrupt)?;
        match atomic_replace(
            &self.inner.store_dir,
            RECORD_FILENAME,
            TEMP_FILENAME,
            &bytes,
        ) {
            DurableWrite::Committed => {
                write_marker_raw(guard, MARKER_CLEAN).map_err(map_open_io)?;
                Ok(())
            }
            DurableWrite::NotCommitted { .. } | DurableWrite::Uncertain { .. } => {
                Err(MeshIntentNonceLedgerOpenError::RecoveryRequired)
            }
        }
    }

    fn stabilize_visible_under_lock(
        &self,
        guard: &mut LedgerLockGuard<'_>,
        bytes: &[u8],
    ) -> Result<(), MeshIntentNonceLedgerOpenError> {
        self.decode_and_validate(bytes)
            .map_err(map_unavailable_to_open)?;
        match atomic_replace(&self.inner.store_dir, RECORD_FILENAME, TEMP_FILENAME, bytes) {
            DurableWrite::Committed => {
                write_marker_raw(guard, MARKER_CLEAN).map_err(map_open_io)?;
                Ok(())
            }
            DurableWrite::NotCommitted { .. } | DurableWrite::Uncertain { .. } => {
                Err(MeshIntentNonceLedgerOpenError::RecoveryRequired)
            }
        }
    }

    fn acquire(
        &self,
        control: Option<&MeshIntentNonceConsumeControl>,
    ) -> Result<LedgerLockGuard<'_>, MeshIntentNonceUnavailable> {
        let configured_deadline = Instant::now()
            .checked_add(self.inner.config.lock_timeout)
            .ok_or(MeshIntentNonceUnavailable::LockTimeout)?;
        let deadline = control.map_or(configured_deadline, |ceremony| {
            ceremony.deadline.min(configured_deadline)
        });
        let timeout_reason =
            if control.is_some_and(|ceremony| ceremony.deadline <= configured_deadline) {
                MeshIntentNonceUnavailable::DeadlineExceeded
            } else {
                MeshIntentNonceUnavailable::LockTimeout
            };
        let lifecycle = self
            .inner
            .lifecycle
            .lock_shared_until(deadline)
            .map_err(map_lifecycle_to_unavailable)?;
        self.acquire_after_lifecycle_with_deadline(lifecycle, control, deadline, timeout_reason)
    }

    fn acquire_after_lifecycle(
        &self,
        lifecycle: LifecycleReadGuard,
        control: Option<&MeshIntentNonceConsumeControl>,
    ) -> Result<LedgerLockGuard<'_>, MeshIntentNonceUnavailable> {
        let configured_deadline = Instant::now()
            .checked_add(self.inner.config.lock_timeout)
            .ok_or(MeshIntentNonceUnavailable::LockTimeout)?;
        let deadline = control.map_or(configured_deadline, |ceremony| {
            ceremony.deadline.min(configured_deadline)
        });
        let timeout_reason =
            if control.is_some_and(|ceremony| ceremony.deadline <= configured_deadline) {
                MeshIntentNonceUnavailable::DeadlineExceeded
            } else {
                MeshIntentNonceUnavailable::LockTimeout
            };
        self.acquire_after_lifecycle_with_deadline(lifecycle, control, deadline, timeout_reason)
    }

    fn acquire_after_lifecycle_with_deadline(
        &self,
        lifecycle: LifecycleReadGuard,
        control: Option<&MeshIntentNonceConsumeControl>,
        deadline: Instant,
        timeout_reason: MeshIntentNonceUnavailable,
    ) -> Result<LedgerLockGuard<'_>, MeshIntentNonceUnavailable> {
        if !verify_authority_binding(
            &self.inner.state_dir,
            &self.inner.household_dir,
            &self.inner.store_dir,
        ) {
            return Err(MeshIntentNonceUnavailable::UnsafePath);
        }
        if let Some(reason) = control.and_then(abort_reason) {
            return Err(reason);
        }
        let guard = loop {
            if let Some(reason) = control.and_then(abort_reason) {
                return Err(reason);
            }
            match self.inner.lock_file.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(timeout_reason);
                    }
                    std::thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(MeshIntentNonceUnavailable::LockPoisoned);
                }
            }
        };
        if !verify_lock_anchor(&self.inner.household_dir, &guard) {
            return Err(MeshIntentNonceUnavailable::UnsafePath);
        }
        loop {
            if let Some(reason) = control.and_then(abort_reason) {
                return Err(reason);
            }
            match guard.try_lock_exclusive() {
                Ok(()) => {
                    let locked = LedgerLockGuard {
                        file: guard,
                        lifecycle,
                    };
                    if !verify_authority_binding(
                        &self.inner.state_dir,
                        &self.inner.household_dir,
                        &self.inner.store_dir,
                    ) {
                        return Err(MeshIntentNonceUnavailable::UnsafePath);
                    }
                    if !verify_lock_anchor(&self.inner.household_dir, &locked.file) {
                        return Err(MeshIntentNonceUnavailable::UnsafePath);
                    }
                    if let Some(reason) = control.and_then(abort_reason) {
                        return Err(reason);
                    }
                    return Ok(locked);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(timeout_reason);
                    }
                    std::thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(_) => return Err(MeshIntentNonceUnavailable::Io),
            }
        }
    }

    fn load_clean_record(
        &self,
        guard: &mut LedgerLockGuard<'_>,
    ) -> Result<LedgerRecordV1, MeshIntentNonceUnavailable> {
        let marker = read_marker(guard).map_err(|_| MeshIntentNonceUnavailable::Io)?;
        if marker.as_deref() == Some(MARKER_CLEAN) {
            return self.read_and_validate_record();
        }

        // Same recovery rule as process startup: any non-clean marker may be
        // a torn marker write. A valid visible record is stabilized byte-for-
        // byte; an absent or corrupt record fails closed.
        self.recover_visible_for_consume(guard)?;
        self.read_and_validate_record()
    }

    fn recover_visible_for_consume(
        &self,
        guard: &mut LedgerLockGuard<'_>,
    ) -> Result<(), MeshIntentNonceUnavailable> {
        let bytes = read_record_bytes(&self.inner.store_dir, RECORD_FILENAME)?;
        self.decode_and_validate(&bytes)?;
        match atomic_replace(
            &self.inner.store_dir,
            RECORD_FILENAME,
            TEMP_FILENAME,
            &bytes,
        ) {
            DurableWrite::Committed => write_marker_raw(guard, MARKER_CLEAN)
                .map_err(|_| MeshIntentNonceUnavailable::RecoveryRequired),
            DurableWrite::NotCommitted { .. } | DurableWrite::Uncertain { .. } => {
                Err(MeshIntentNonceUnavailable::RecoveryRequired)
            }
        }
    }

    fn read_and_validate_record(&self) -> Result<LedgerRecordV1, MeshIntentNonceUnavailable> {
        let bytes = read_record_bytes(&self.inner.store_dir, RECORD_FILENAME)?;
        self.decode_and_validate(&bytes)
    }

    fn decode_and_validate(
        &self,
        bytes: &[u8],
    ) -> Result<LedgerRecordV1, MeshIntentNonceUnavailable> {
        let record: LedgerRecordV1 = cbor::from_canonical_slice_strict(bytes)
            .map_err(|_| MeshIntentNonceUnavailable::CorruptRecord)?;
        if record.version != RECORD_VERSION
            || record.domain != RECORD_DOMAIN
            || record.hh_id != self.inner.target_hh_id
            || record.generation == 0
        {
            return Err(MeshIntentNonceUnavailable::CorruptRecord);
        }
        if usize::try_from(record.capacity).ok() != Some(self.inner.config.capacity.get()) {
            return Err(MeshIntentNonceUnavailable::PolicyMismatch);
        }
        if record.entries.len() > self.inner.config.capacity.get() {
            return Err(MeshIntentNonceUnavailable::CorruptRecord);
        }
        for (stored_id, entry) in &record.entries {
            if entry.key.domain != MESH_INTENT_NONCE_KEY_DOMAIN
                || entry.key.hh_id != record.hh_id
                || entry.key.delegated_key_id.is_empty()
                || entry.key.delegated_key_id.len() > MAX_DELEGATED_KEY_ID_BYTES
                || entry.key.delegated_key_id.chars().any(char::is_control)
                || entry.not_after == 0
                || entry_id(&entry.key).as_deref() != Ok(stored_id.as_str())
            {
                return Err(MeshIntentNonceUnavailable::CorruptRecord);
            }
        }
        Ok(record)
    }

    fn commit_semantic(
        &self,
        guard: &mut LedgerLockGuard<'_>,
        canonical: &[u8],
        generation: u64,
    ) -> MeshIntentNonceConsumeOutcome {
        if let Err(stage) = write_marker_staged(
            guard,
            MARKER_DIRTY,
            MeshIntentNonceCommitStage::DirtyMarkerWrite,
            MeshIntentNonceCommitStage::DirtyMarkerSync,
        ) {
            return unavailable(MeshIntentNonceUnavailable::WriteFailed(stage));
        }

        #[cfg(test)]
        self.block_worker_once_for_test();

        match atomic_replace(
            &self.inner.store_dir,
            RECORD_FILENAME,
            TEMP_FILENAME,
            canonical,
        ) {
            DurableWrite::NotCommitted { stage } => {
                // Leave DIRTY in place. A later operation rewrites the visible
                // pre-existing record through the same committed protocol and
                // then publishes CLEAN. A second best-effort clean here would
                // turn a failed marker write into ambiguous state again.
                unavailable(MeshIntentNonceUnavailable::WriteFailed(stage))
            }
            DurableWrite::Uncertain { stage } => {
                MeshIntentNonceConsumeOutcome::MayHaveTakenEffect { stage }
            }
            DurableWrite::Committed => {
                if let Err(stage) = write_marker_staged(
                    guard,
                    MARKER_CLEAN,
                    MeshIntentNonceCommitStage::CleanMarkerWrite,
                    MeshIntentNonceCommitStage::CleanMarkerSync,
                ) {
                    MeshIntentNonceConsumeOutcome::MayHaveTakenEffect { stage }
                } else if fail_injection::take(MeshIntentNonceCommitStage::PostCommitBinding)
                    || !guard.lifecycle.binding_is_current()
                    || !verify_authority_binding(
                        &self.inner.state_dir,
                        &self.inner.household_dir,
                        &self.inner.store_dir,
                    )
                {
                    MeshIntentNonceConsumeOutcome::MayHaveTakenEffect {
                        stage: MeshIntentNonceCommitStage::PostCommitBinding,
                    }
                } else {
                    MeshIntentNonceConsumeOutcome::Committed { generation }
                }
            }
        }
    }
}

fn unavailable(reason: MeshIntentNonceUnavailable) -> MeshIntentNonceConsumeOutcome {
    MeshIntentNonceConsumeOutcome::Unavailable { reason }
}

fn abort_reason(control: &MeshIntentNonceConsumeControl) -> Option<MeshIntentNonceUnavailable> {
    if control.is_cancelled() {
        Some(MeshIntentNonceUnavailable::Cancelled)
    } else if Instant::now() >= control.deadline {
        Some(MeshIntentNonceUnavailable::DeadlineExceeded)
    } else {
        None
    }
}

fn map_unavailable_to_open(reason: MeshIntentNonceUnavailable) -> MeshIntentNonceLedgerOpenError {
    match reason {
        MeshIntentNonceUnavailable::LockTimeout => MeshIntentNonceLedgerOpenError::LockTimeout,
        MeshIntentNonceUnavailable::LockPoisoned => MeshIntentNonceLedgerOpenError::LockPoisoned,
        MeshIntentNonceUnavailable::UnsafePath => MeshIntentNonceLedgerOpenError::UnsafePath,
        MeshIntentNonceUnavailable::UnsupportedFilesystem => {
            MeshIntentNonceLedgerOpenError::UnsupportedFilesystem
        }
        MeshIntentNonceUnavailable::CorruptRecord => MeshIntentNonceLedgerOpenError::Corrupt,
        MeshIntentNonceUnavailable::PolicyMismatch => {
            MeshIntentNonceLedgerOpenError::PolicyMismatch
        }
        MeshIntentNonceUnavailable::RecordTooLarge => {
            MeshIntentNonceLedgerOpenError::RecordTooLarge
        }
        MeshIntentNonceUnavailable::RecoveryRequired => {
            MeshIntentNonceLedgerOpenError::RecoveryRequired
        }
        MeshIntentNonceUnavailable::WrongHousehold
        | MeshIntentNonceUnavailable::WrongTrustedFloorHousehold
        | MeshIntentNonceUnavailable::EvidenceExpired
        | MeshIntentNonceUnavailable::CapacityExhausted
        | MeshIntentNonceUnavailable::GenerationExhausted
        | MeshIntentNonceUnavailable::DeadlineExceeded
        | MeshIntentNonceUnavailable::Cancelled
        | MeshIntentNonceUnavailable::Io
        | MeshIntentNonceUnavailable::WriteFailed(_) => MeshIntentNonceLedgerOpenError::Io,
    }
}

fn map_open_io(_: std::io::Error) -> MeshIntentNonceLedgerOpenError {
    MeshIntentNonceLedgerOpenError::Io
}

fn map_open_errno(error: Errno) -> MeshIntentNonceLedgerOpenError {
    if error == Errno::LOOP {
        MeshIntentNonceLedgerOpenError::UnsafePath
    } else {
        MeshIntentNonceLedgerOpenError::Io
    }
}

fn map_lifecycle_to_open(error: HouseholdLifecycleLockError) -> MeshIntentNonceLedgerOpenError {
    match error {
        HouseholdLifecycleLockError::UnsafePath => MeshIntentNonceLedgerOpenError::UnsafePath,
        HouseholdLifecycleLockError::UnsupportedFilesystem => {
            MeshIntentNonceLedgerOpenError::UnsupportedFilesystem
        }
        HouseholdLifecycleLockError::LockTimeout => MeshIntentNonceLedgerOpenError::LockTimeout,
        HouseholdLifecycleLockError::RecoveryRequired => {
            MeshIntentNonceLedgerOpenError::RecoveryRequired
        }
        HouseholdLifecycleLockError::Io => MeshIntentNonceLedgerOpenError::Io,
    }
}

fn map_lifecycle_to_unavailable(error: HouseholdLifecycleLockError) -> MeshIntentNonceUnavailable {
    match error {
        HouseholdLifecycleLockError::UnsafePath => MeshIntentNonceUnavailable::UnsafePath,
        HouseholdLifecycleLockError::UnsupportedFilesystem => {
            MeshIntentNonceUnavailable::UnsupportedFilesystem
        }
        HouseholdLifecycleLockError::LockTimeout => MeshIntentNonceUnavailable::LockTimeout,
        HouseholdLifecycleLockError::RecoveryRequired => {
            MeshIntentNonceUnavailable::RecoveryRequired
        }
        HouseholdLifecycleLockError::Io => MeshIntentNonceUnavailable::Io,
    }
}

fn entry_id(key: &StoredKeyV1) -> Result<String, ()> {
    let canonical = cbor::to_canonical_vec(key).map_err(|_| ())?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize()))
}

struct LedgerLockGuard<'a> {
    file: MutexGuard<'a, File>,
    lifecycle: LifecycleReadGuard,
}

impl Drop for LedgerLockGuard<'_> {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&*self.file);
    }
}

fn open_store_dirs(state_dir: File) -> Result<(File, File, File), MeshIntentNonceLedgerOpenError> {
    // The named household is the production teardown boundary. Retain its
    // parent descriptor so every operation can prove that this exact
    // household directory is still installed there.
    validate_owned_non_writable_directory(&state_dir)?;
    validate_supported_persistent_filesystem(&state_dir)?;

    let household_dir = File::from(
        rustix::fs::openat(
            &state_dir,
            HOUSEHOLD_SUBDIR,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_open_errno)?,
    );
    validate_owned_non_writable_directory(&household_dir)?;
    validate_supported_persistent_filesystem(&household_dir)?;
    if !verify_named_directory_binding(&state_dir, HOUSEHOLD_SUBDIR, &household_dir) {
        return Err(MeshIntentNonceLedgerOpenError::UnsafePath);
    }

    let created = match rustix::fs::mkdirat(&household_dir, STORE_SUBDIR, Mode::RWXU) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(error) => return Err(map_open_errno(error)),
    };
    let store_dir = File::from(
        rustix::fs::openat(
            &household_dir,
            STORE_SUBDIR,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            if error == Errno::LOOP {
                MeshIntentNonceLedgerOpenError::UnsafePath
            } else {
                map_open_errno(error)
            }
        })?,
    );
    if created {
        rustix::fs::fchmod(&store_dir, Mode::RWXU).map_err(map_open_errno)?;
    }
    validate_private_directory(&store_dir)?;
    validate_supported_persistent_filesystem(&store_dir)?;
    if !verify_authority_binding(&state_dir, &household_dir, &store_dir) {
        return Err(MeshIntentNonceLedgerOpenError::UnsafePath);
    }

    // Unconditional: an earlier attempt may have made the child visible but
    // failed the parent barrier. Visibility is never reused as durability.
    household_dir.sync_all().map_err(map_open_io)?;
    Ok((state_dir, household_dir, store_dir))
}

fn validate_private_directory(dir: &File) -> Result<(), MeshIntentNonceLedgerOpenError> {
    validate_directory_mode(dir, 0o077)
}

fn validate_owned_non_writable_directory(dir: &File) -> Result<(), MeshIntentNonceLedgerOpenError> {
    validate_directory_mode(dir, 0o022)
}

fn validate_directory_mode(
    dir: &File,
    forbidden_mode: u32,
) -> Result<(), MeshIntentNonceLedgerOpenError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = dir.metadata().map_err(map_open_io)?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & forbidden_mode != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(MeshIntentNonceLedgerOpenError::UnsafePath);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_supported_persistent_filesystem(
    dir: &File,
) -> Result<(), MeshIntentNonceLedgerOpenError> {
    let stat = rustix::fs::fstatfs(dir).map_err(map_open_errno)?;
    let name: Vec<u8> = stat
        .f_fstypename
        .iter()
        .map(|byte| byte.to_ne_bytes()[0])
        .take_while(|byte| *byte != 0)
        .collect();
    if macos_filesystem_is_allowlisted(&name) {
        Ok(())
    } else {
        Err(MeshIntentNonceLedgerOpenError::UnsupportedFilesystem)
    }
}

#[cfg(target_os = "linux")]
fn validate_supported_persistent_filesystem(
    dir: &File,
) -> Result<(), MeshIntentNonceLedgerOpenError> {
    let stat = rustix::fs::fstatfs(dir).map_err(map_open_errno)?;
    if linux_filesystem_is_allowlisted(stat.f_type) {
        Ok(())
    } else {
        Err(MeshIntentNonceLedgerOpenError::UnsupportedFilesystem)
    }
}

#[cfg(any(test, target_os = "linux"))]
fn linux_filesystem_is_allowlisted(fs_type: i64) -> bool {
    LINUX_RENAME_KNOWN_NO_EFFECT_FILESYSTEMS.contains(&fs_type)
}

#[cfg(any(test, target_os = "macos"))]
fn macos_filesystem_is_allowlisted(fs_type: &[u8]) -> bool {
    MACOS_RENAME_KNOWN_NO_EFFECT_FILESYSTEMS.contains(&fs_type)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn validate_supported_persistent_filesystem(
    _: &File,
) -> Result<(), MeshIntentNonceLedgerOpenError> {
    Err(MeshIntentNonceLedgerOpenError::UnsupportedFilesystem)
}

fn verify_named_directory_binding(parent: &File, name: &str, opened: &File) -> bool {
    let Ok(opened) = rustix::fs::fstat(opened) else {
        return false;
    };
    let Ok(named) = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return false;
    };
    opened.st_dev == named.st_dev && opened.st_ino == named.st_ino
}

fn verify_authority_binding(state_dir: &File, household_dir: &File, store_dir: &File) -> bool {
    verify_named_directory_binding(state_dir, HOUSEHOLD_SUBDIR, household_dir)
        && verify_named_directory_binding(household_dir, STORE_SUBDIR, store_dir)
}

fn ledger_authority_id(
    state_dir: &File,
    household_dir: &File,
    store_dir: &File,
) -> Result<LedgerAuthorityId, MeshIntentNonceLedgerOpenError> {
    use std::os::unix::fs::MetadataExt;

    let state = state_dir.metadata().map_err(map_open_io)?;
    let household = household_dir.metadata().map_err(map_open_io)?;
    let store = store_dir.metadata().map_err(map_open_io)?;
    Ok(LedgerAuthorityId {
        state_dev: state.dev(),
        state_ino: state.ino(),
        household_dev: household.dev(),
        household_ino: household.ino(),
        store_dev: store.dev(),
        store_ino: store.ino(),
    })
}

fn open_lock_file(store_dir: &File) -> Result<(File, bool), MeshIntentNonceLedgerOpenError> {
    let mut created = false;
    let file = match rustix::fs::openat(
        store_dir,
        LOCK_FILENAME,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => {
            created = true;
            File::from(fd)
        }
        Err(Errno::EXIST) => File::from(
            rustix::fs::openat(
                store_dir,
                LOCK_FILENAME,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                if error == Errno::LOOP {
                    MeshIntentNonceLedgerOpenError::UnsafePath
                } else {
                    map_open_errno(error)
                }
            })?,
        ),
        Err(error) => return Err(map_open_errno(error)),
    };
    validate_private_file_open(&file).map_err(map_unavailable_to_open)?;
    if created {
        file.sync_all().map_err(map_open_io)?;
        store_dir.sync_all().map_err(map_open_io)?;
    }
    Ok((file, created))
}

fn verify_or_create_lock_anchor(
    household_dir: &File,
    store_dir: &File,
    lock_file: &File,
    lock_created: bool,
) -> Result<(), MeshIntentNonceLedgerOpenError> {
    if let Some(anchor) = open_anchor(household_dir)? {
        if !same_file(&anchor, lock_file) {
            return Err(MeshIntentNonceLedgerOpenError::UnsafePath);
        }
        return Ok(());
    }
    if !lock_created && lock_file.metadata().map_err(map_open_io)?.len() != 0 {
        return Err(MeshIntentNonceLedgerOpenError::Corrupt);
    }
    match rustix::fs::linkat(
        store_dir,
        LOCK_FILENAME,
        household_dir,
        LOCK_ANCHOR_FILENAME,
        AtFlags::empty(),
    ) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(map_open_errno(error)),
    }
    let anchor =
        open_anchor(household_dir)?.ok_or(MeshIntentNonceLedgerOpenError::RecoveryRequired)?;
    if !same_file(&anchor, lock_file) {
        return Err(MeshIntentNonceLedgerOpenError::UnsafePath);
    }
    household_dir.sync_all().map_err(map_open_io)
}

fn open_anchor(household_dir: &File) -> Result<Option<File>, MeshIntentNonceLedgerOpenError> {
    match rustix::fs::openat(
        household_dir,
        LOCK_ANCHOR_FILENAME,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let file = File::from(fd);
            validate_private_file_open(&file).map_err(map_unavailable_to_open)?;
            Ok(Some(file))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::LOOP) => Err(MeshIntentNonceLedgerOpenError::UnsafePath),
        Err(error) => Err(map_open_errno(error)),
    }
}

fn same_file(left: &File, right: &File) -> bool {
    let (Ok(left), Ok(right)) = (rustix::fs::fstat(left), rustix::fs::fstat(right)) else {
        return false;
    };
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn verify_lock_anchor(household_dir: &File, lock_file: &File) -> bool {
    open_anchor(household_dir)
        .ok()
        .flatten()
        .is_some_and(|anchor| same_file(&anchor, lock_file))
}

fn read_marker(guard: &mut LedgerLockGuard<'_>) -> std::io::Result<Option<Vec<u8>>> {
    guard.file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut *guard.file)
        .take(32)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(bytes))
    }
}

fn write_marker_raw(guard: &mut LedgerLockGuard<'_>, marker: &[u8]) -> std::io::Result<()> {
    guard.file.seek(SeekFrom::Start(0))?;
    guard.file.set_len(0)?;
    guard.file.write_all(marker)?;
    guard.file.flush()?;
    guard.file.sync_all()
}

fn write_marker_staged(
    guard: &mut LedgerLockGuard<'_>,
    marker: &[u8],
    write_stage: MeshIntentNonceCommitStage,
    sync_stage: MeshIntentNonceCommitStage,
) -> Result<(), MeshIntentNonceCommitStage> {
    if fail_injection::take(write_stage) {
        return Err(write_stage);
    }
    guard
        .file
        .seek(SeekFrom::Start(0))
        .and_then(|_| guard.file.set_len(0))
        .and_then(|()| guard.file.write_all(marker))
        .and_then(|()| guard.file.flush())
        .map_err(|_| write_stage)?;
    if fail_injection::take(sync_stage) {
        return Err(sync_stage);
    }
    guard.file.sync_all().map_err(|_| sync_stage)
}

fn read_optional_record(
    parent: &File,
    name: &str,
) -> Result<Option<Vec<u8>>, MeshIntentNonceUnavailable> {
    let Some(file) = open_record_for_read(parent, name)? else {
        return Ok(None);
    };
    read_record_file(file).map(Some)
}

fn read_record_bytes(parent: &File, name: &str) -> Result<Vec<u8>, MeshIntentNonceUnavailable> {
    let file =
        open_record_for_read(parent, name)?.ok_or(MeshIntentNonceUnavailable::CorruptRecord)?;
    read_record_file(file)
}

fn open_record_for_read(
    parent: &File,
    name: &str,
) -> Result<Option<File>, MeshIntentNonceUnavailable> {
    match rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => {
            let file = File::from(fd);
            validate_private_file_open(&file)?;
            Ok(Some(file))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::LOOP) => Err(MeshIntentNonceUnavailable::UnsafePath),
        Err(_) => Err(MeshIntentNonceUnavailable::Io),
    }
}

fn validate_private_file_open(file: &File) -> Result<(), MeshIntentNonceUnavailable> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let meta = file
        .metadata()
        .map_err(|_| MeshIntentNonceUnavailable::Io)?;
    if !meta.is_file()
        || meta.permissions().mode() & 0o077 != 0
        || meta.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(MeshIntentNonceUnavailable::UnsafePath);
    }
    Ok(())
}

fn read_record_file(mut file: File) -> Result<Vec<u8>, MeshIntentNonceUnavailable> {
    let meta = file
        .metadata()
        .map_err(|_| MeshIntentNonceUnavailable::Io)?;
    if meta.len() > u64::try_from(MAX_RECORD_BYTES).expect("bound fits u64") {
        return Err(MeshIntentNonceUnavailable::RecordTooLarge);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(u64::try_from(MAX_RECORD_BYTES + 1).expect("bound fits u64"))
        .read_to_end(&mut bytes)
        .map_err(|_| MeshIntentNonceUnavailable::Io)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(MeshIntentNonceUnavailable::RecordTooLarge);
    }
    Ok(bytes)
}

enum DurableWrite {
    Committed,
    NotCommitted { stage: MeshIntentNonceCommitStage },
    Uncertain { stage: MeshIntentNonceCommitStage },
}

fn atomic_replace(
    parent: &File,
    target_name: &str,
    temp_name: &str,
    canonical: &[u8],
) -> DurableWrite {
    let not_committed = |stage| DurableWrite::NotCommitted { stage };
    if fail_injection::take(MeshIntentNonceCommitStage::TempInspect) {
        return not_committed(MeshIntentNonceCommitStage::TempInspect);
    }
    match open_record_for_read(parent, temp_name) {
        Ok(Some(temp)) => {
            drop(temp);
            if fail_injection::take(MeshIntentNonceCommitStage::TempCleanup)
                || rustix::fs::unlinkat(parent, temp_name, AtFlags::empty()).is_err()
                || parent.sync_all().is_err()
            {
                return not_committed(MeshIntentNonceCommitStage::TempCleanup);
            }
        }
        Ok(None) => {}
        Err(_) => return not_committed(MeshIntentNonceCommitStage::TempInspect),
    }

    if fail_injection::take(MeshIntentNonceCommitStage::TempOpen) {
        return not_committed(MeshIntentNonceCommitStage::TempOpen);
    }
    let Ok(fd) = rustix::fs::openat(
        parent,
        temp_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) else {
        return not_committed(MeshIntentNonceCommitStage::TempOpen);
    };
    let mut file = File::from(fd);
    if fail_injection::take(MeshIntentNonceCommitStage::TempWrite)
        || file.write_all(canonical).is_err()
    {
        return not_committed(MeshIntentNonceCommitStage::TempWrite);
    }
    if fail_injection::take(MeshIntentNonceCommitStage::TempFlush) || file.flush().is_err() {
        return not_committed(MeshIntentNonceCommitStage::TempFlush);
    }
    if fail_injection::take(MeshIntentNonceCommitStage::TempSync) || file.sync_all().is_err() {
        return not_committed(MeshIntentNonceCommitStage::TempSync);
    }
    drop(file);
    if fail_injection::take(MeshIntentNonceCommitStage::Rename) {
        return not_committed(MeshIntentNonceCommitStage::Rename);
    }
    // `open` admits only local persistent filesystems with POSIX rename
    // semantics. Therefore an actual failing rename did not replace the
    // target and is KnownNoEffect. Without that gate this classification
    // would be an unsupported assumption.
    if rustix::fs::renameat(parent, temp_name, parent, target_name).is_err() {
        return not_committed(MeshIntentNonceCommitStage::Rename);
    }

    let uncertain = |stage| DurableWrite::Uncertain { stage };
    if fail_injection::take(MeshIntentNonceCommitStage::ParentSync) || parent.sync_all().is_err() {
        return uncertain(MeshIntentNonceCommitStage::ParentSync);
    }
    if fail_injection::take(MeshIntentNonceCommitStage::Readback) {
        return uncertain(MeshIntentNonceCommitStage::Readback);
    }
    let Ok(readback) = read_record_bytes(parent, target_name) else {
        return uncertain(MeshIntentNonceCommitStage::Readback);
    };
    if fail_injection::take(MeshIntentNonceCommitStage::ReadbackMismatch) || readback != canonical {
        return uncertain(MeshIntentNonceCommitStage::ReadbackMismatch);
    }
    DurableWrite::Committed
}

#[cfg(test)]
mod fail_injection {
    use std::cell::Cell;

    use super::MeshIntentNonceCommitStage;

    thread_local! {
        static ARMED: Cell<Option<MeshIntentNonceCommitStage>> = const { Cell::new(None) };
    }

    pub(super) struct Armed;

    impl Drop for Armed {
        fn drop(&mut self) {
            ARMED.with(|armed| armed.set(None));
        }
    }

    pub(super) fn arm(stage: MeshIntentNonceCommitStage) -> Armed {
        ARMED.with(|armed| armed.set(Some(stage)));
        Armed
    }

    pub(super) fn take_armed() -> Option<MeshIntentNonceCommitStage> {
        ARMED.with(|armed| armed.replace(None))
    }

    pub(super) fn take(stage: MeshIntentNonceCommitStage) -> bool {
        crate::crash_park::park_if_armed(&format!("ledger:{stage:?}"));
        ARMED.with(|armed| {
            if armed.get() == Some(stage) {
                armed.set(None);
                true
            } else {
                false
            }
        })
    }
}

#[cfg(not(test))]
mod fail_injection {
    use super::MeshIntentNonceCommitStage;

    pub(super) const fn take(_: MeshIntentNonceCommitStage) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::num::NonZeroUsize;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};
    use std::thread;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::*;

    const WORKER_TEST_NAME: &str = "mesh_intent_nonce_ledger::tests::multiprocess_consume_worker";
    const LOCK_CONTENDER_TEST_NAME: &str =
        "mesh_intent_nonce_ledger::tests::lock_substitution_contender_worker";
    const CHILD_DIR_ENV: &str = "THEYOS_MESH_INTENT_LEDGER_CHILD_DIR";
    const CHILD_READY_ENV: &str = "THEYOS_MESH_INTENT_LEDGER_CHILD_READY";
    const CHILD_GO_ENV: &str = "THEYOS_MESH_INTENT_LEDGER_CHILD_GO";
    const CHILD_RESULT_ENV: &str = "THEYOS_MESH_INTENT_LEDGER_CHILD_RESULT";

    fn household(byte: char) -> HouseholdId {
        HouseholdId::parse(format!("hh_{}", byte.to_string().repeat(52))).unwrap()
    }

    fn machine(byte: char) -> MachineId {
        MachineId::parse(format!("m_{}", byte.to_string().repeat(52))).unwrap()
    }

    fn config(capacity: usize) -> MeshIntentNonceLedgerConfig {
        MeshIntentNonceLedgerConfig::new(
            NonZeroUsize::new(capacity).unwrap(),
            Duration::from_secs(10),
        )
        .unwrap()
    }

    fn key(nonce_byte: u8) -> MeshIntentNonceKey {
        key_for(household('a'), nonce_byte)
    }

    fn key_for(hh_id: HouseholdId, nonce_byte: u8) -> MeshIntentNonceKey {
        MeshIntentNonceKey::new(hh_id, machine('b'), "mesh-key-v1", [nonce_byte; 32]).unwrap()
    }

    fn evidence(
        channel: MeshIntentChannel,
        digest_byte: u8,
        not_after: u64,
    ) -> MeshIntentNonceEvidence {
        MeshIntentNonceEvidence::new(channel, [digest_byte; 32], not_after).unwrap()
    }

    fn open_at(path: &Path, capacity: usize) -> MeshIntentNonceLedger {
        prepare_household(path);
        MeshIntentNonceLedger::open(path, household('a'), config(capacity)).unwrap()
    }

    fn prepare_household(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        let household = path.join(HOUSEHOLD_SUBDIR);
        fs::create_dir_all(&household).unwrap();
        fs::set_permissions(household, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn store_path(path: &Path) -> PathBuf {
        path.join(HOUSEHOLD_SUBDIR).join(STORE_SUBDIR)
    }

    fn floor_for(hh_id: HouseholdId, unix_seconds: u64) -> TrustedWallFloor {
        TrustedWallFloor::for_test(hh_id, unix_seconds)
    }

    fn floor(unix_seconds: u64) -> TrustedWallFloor {
        floor_for(household('a'), unix_seconds)
    }

    fn ceremony_control() -> MeshIntentNonceConsumeControl {
        MeshIntentNonceConsumeControl::from_absolute_deadline(
            Instant::now() + Duration::from_secs(30),
        )
    }

    #[test]
    fn channel_and_digest_are_evidence_not_replay_namespaces() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 4);
        let replay_key = key(1);
        let first = evidence(MeshIntentChannel::Dev, 0x11, 500);
        assert!(matches!(
            ledger.consume(&replay_key, &first, floor(100), &ceremony_control(),),
            MeshIntentNonceConsumeOutcome::Committed { generation: 2 }
        ));

        let different_evidence = evidence(MeshIntentChannel::Release, 0x22, 700);
        let MeshIntentNonceConsumeOutcome::AlreadyConsumed { evidence: observed } = ledger.consume(
            &replay_key,
            &different_evidence,
            floor(100),
            &ceremony_control(),
        ) else {
            panic!("same canonical replay key must be consumed across channels");
        };
        assert_eq!(observed, first, "the first durable evidence wins");
    }

    #[test]
    fn canonical_key_domain_and_cbor_are_frozen_golden_bytes() {
        assert_eq!(MESH_INTENT_NONCE_KEY_DOMAIN, "ledger-domain-v1");
        let stored = StoredKeyV1::from(&key(0x2A));
        let bytes = cbor::to_canonical_vec(&stored).unwrap();
        assert_eq!(
            hex::encode(bytes),
            "a56568685f6964783768685f61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161656e6f6e636558202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a66646f6d61696e706c65646765722d646f6d61696e2d76316e696e69746961746f725f6d5f696478366d5f626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262627064656c6567617465645f6b65795f69646b6d6573682d6b65792d7631",
            "the replay-key wire contract must not drift silently"
        );
    }

    #[test]
    fn malformed_public_tuple_ids_are_rejected_before_record_io() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let record = store_path(temp.path()).join(RECORD_FILENAME);
        let before = fs::read(&record).unwrap();

        assert_eq!(
            MeshIntentNonceKey::new(
                household('a'),
                MachineId("not-a-machine-id".to_owned()),
                "mesh-key-v1",
                [0x70; 32],
            ),
            Err(MeshIntentNonceKeyError::InvalidInitiatorMachineId)
        );
        assert_eq!(
            MeshIntentNonceKey::new(
                HouseholdId("not-a-household-id".to_owned()),
                machine('b'),
                "mesh-key-v1",
                [0x71; 32],
            ),
            Err(MeshIntentNonceKeyError::InvalidHouseholdId)
        );
        assert_eq!(fs::read(&record).unwrap(), before);

        drop(ledger);
        let restarted = open_at(temp.path(), 2);
        assert!(matches!(
            restarted.consume(
                &key(0x72),
                &evidence(MeshIntentChannel::Dev, 0x72, 500),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));
    }

    #[test]
    fn trusted_wall_floor_is_bound_to_exact_household() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        assert_eq!(
            ledger.consume(
                &key(0x19),
                &evidence(MeshIntentChannel::Dev, 0x19, 500),
                floor_for(household('c'), 100),
                &ceremony_control(),
            ),
            unavailable(MeshIntentNonceUnavailable::WrongTrustedFloorHousehold)
        );
        assert!(matches!(
            ledger.consume(
                &key(0x19),
                &evidence(MeshIntentChannel::Dev, 0x19, 500),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));
    }

    #[test]
    fn retention_requires_floor_strictly_greater_than_not_after() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 1);
        assert!(matches!(
            ledger.consume(
                &key(1),
                &evidence(MeshIntentChannel::Dev, 1, 200),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));

        assert_eq!(
            ledger.consume(
                &key(2),
                &evidence(MeshIntentChannel::Dev, 2, 300),
                floor(200),
                &ceremony_control(),
            ),
            unavailable(MeshIntentNonceUnavailable::CapacityExhausted),
            "equality must retain the old row"
        );
        assert!(matches!(
            ledger.consume(
                &key(2),
                &evidence(MeshIntentChannel::Dev, 2, 300),
                floor(201),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { generation: 3 }
        ));
    }

    #[test]
    fn expired_new_evidence_is_refused_without_touching_the_record() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        assert_eq!(
            ledger.consume(
                &key(3),
                &evidence(MeshIntentChannel::Release, 3, 100),
                floor(100),
                &ceremony_control(),
            ),
            unavailable(MeshIntentNonceUnavailable::EvidenceExpired)
        );
        assert!(matches!(
            ledger.consume(
                &key(3),
                &evidence(MeshIntentChannel::Release, 3, 101),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { generation: 2 }
        ));
    }

    #[test]
    fn record_is_byte_exact_canonical_cbor() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        assert!(matches!(
            ledger.consume(
                &key(4),
                &evidence(MeshIntentChannel::Dev, 4, 500),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));
        let bytes = fs::read(store_path(temp.path()).join(RECORD_FILENAME)).unwrap();
        let decoded: LedgerRecordV1 = cbor::from_canonical_slice_strict(&bytes).unwrap();
        assert_eq!(cbor::to_canonical_vec(&decoded).unwrap(), bytes);
        assert_eq!(decoded.entries.len(), 1);
    }

    #[test]
    fn corrupt_or_missing_committed_record_fails_closed() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        assert!(matches!(
            ledger.consume(
                &key(5),
                &evidence(MeshIntentChannel::Dev, 5, 500),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));
        let record_path = store_path(temp.path()).join(RECORD_FILENAME);
        OpenOptions::new()
            .append(true)
            .open(&record_path)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        assert_eq!(
            ledger.consume(
                &key(6),
                &evidence(MeshIntentChannel::Dev, 6, 500),
                floor(100),
                &ceremony_control(),
            ),
            unavailable(MeshIntentNonceUnavailable::CorruptRecord)
        );

        // A clean marker plus no authority is never interpreted as a fresh
        // empty ledger on restart.
        fs::remove_file(&record_path).unwrap();
        assert_eq!(
            MeshIntentNonceLedger::open(temp.path(), household('a'), config(2))
                .err()
                .unwrap(),
            MeshIntentNonceLedgerOpenError::Corrupt
        );
    }

    #[test]
    fn persisted_capacity_prevents_cross_process_policy_drift() {
        let temp = TempDir::new().unwrap();
        let _ledger = open_at(temp.path(), 2);
        assert_eq!(
            MeshIntentNonceLedger::open(temp.path(), household('a'), config(3))
                .err()
                .unwrap(),
            MeshIntentNonceLedgerOpenError::PolicyMismatch
        );
    }

    #[test]
    fn wrong_target_household_is_refused() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let wrong =
            MeshIntentNonceKey::new(household('c'), machine('b'), "mesh-key-v1", [7; 32]).unwrap();
        assert_eq!(
            ledger.consume(
                &wrong,
                &evidence(MeshIntentChannel::Dev, 7, 500),
                floor(100),
                &ceremony_control(),
            ),
            unavailable(MeshIntentNonceUnavailable::WrongHousehold)
        );
    }

    #[test]
    fn expired_ceremony_deadline_is_refused_without_touching_the_record() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let record_path = store_path(temp.path()).join(RECORD_FILENAME);
        let before = fs::read(&record_path).unwrap();

        assert_eq!(
            ledger.consume(
                &key(8),
                &evidence(MeshIntentChannel::Dev, 8, 500),
                floor(100),
                &MeshIntentNonceConsumeControl::from_absolute_deadline(Instant::now()),
            ),
            unavailable(MeshIntentNonceUnavailable::DeadlineExceeded)
        );
        assert_eq!(fs::read(record_path).unwrap(), before);
    }

    #[test]
    fn cancelled_ceremony_is_refused_without_touching_the_record() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let record_path = store_path(temp.path()).join(RECORD_FILENAME);
        let before = fs::read(&record_path).unwrap();
        let control = ceremony_control();
        control.cancel();

        assert_eq!(
            ledger.consume(
                &key(9),
                &evidence(MeshIntentChannel::Dev, 9, 500),
                floor(100),
                &control,
            ),
            unavailable(MeshIntentNonceUnavailable::Cancelled)
        );
        assert_eq!(fs::read(record_path).unwrap(), before);
    }

    #[test]
    fn cancellation_during_local_lock_race_is_fail_closed() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let record_path = store_path(temp.path()).join(RECORD_FILENAME);
        let before = fs::read(&record_path).unwrap();
        let held = ledger.inner.lock_file.lock().unwrap();
        let control = ceremony_control();
        let canceller = control.clone();
        let worker_ledger = ledger.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let outcome = worker_ledger.consume(
                &key(11),
                &evidence(MeshIntentChannel::Dev, 11, 500),
                floor(100),
                &control,
            );
            tx.send(outcome).unwrap();
        });

        canceller.cancel();
        let observed = match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(outcome) => outcome,
            Err(error) => {
                drop(held);
                worker.join().unwrap();
                panic!("cancelled local-lock wait did not terminate: {error}");
            }
        };
        assert!(
            observed == unavailable(MeshIntentNonceUnavailable::Cancelled)
                || observed
                    == MeshIntentNonceConsumeOutcome::MayHaveTakenEffect {
                        stage: MeshIntentNonceCommitStage::WorkerInFlight,
                    },
            "cancel may win before spawn (known no effect) or after spawn (worker in flight): {observed:?}"
        );
        assert_eq!(fs::read(record_path).unwrap(), before);
        drop(held);
        worker.join().unwrap();

        // The detached worker keeps running after the caller stops waiting.
        // A same-key replay eventually observes its durable terminal result.
        let retry_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match ledger.consume(
                &key(11),
                &evidence(MeshIntentChannel::Dev, 11, 500),
                floor(100),
                &ceremony_control(),
            ) {
                MeshIntentNonceConsumeOutcome::AlreadyConsumed { .. } => break,
                MeshIntentNonceConsumeOutcome::Committed { .. }
                | MeshIntentNonceConsumeOutcome::MayHaveTakenEffect { .. } => {}
                other @ MeshIntentNonceConsumeOutcome::Unavailable { .. } => {
                    panic!("worker did not converge after cancellation: {other:?}")
                }
            }
            assert!(Instant::now() < retry_deadline, "worker did not converge");
        }
    }

    #[test]
    fn blocking_io_worker_outlives_caller_cancel_and_stabilizes() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let block = TestWorkerBlock::new();
        ledger.install_worker_block_for_test(block.clone());
        let control = ceremony_control();
        let cancel = control.clone();
        let caller_ledger = ledger.clone();
        let caller = thread::spawn(move || {
            caller_ledger.consume(
                &key(0x33),
                &evidence(MeshIntentChannel::Release, 0x33, 700),
                floor(100),
                &control,
            )
        });

        block.entered.wait();
        cancel.cancel();
        assert_eq!(
            caller.join().unwrap(),
            MeshIntentNonceConsumeOutcome::MayHaveTakenEffect {
                stage: MeshIntentNonceCommitStage::WorkerInFlight
            }
        );
        block.release.wait();

        assert!(matches!(
            ledger.consume(
                &key(0x33),
                &evidence(MeshIntentChannel::Dev, 0x44, 900),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::AlreadyConsumed { .. }
        ));
    }

    #[test]
    fn factory_reopens_share_one_bounded_worker_queue() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 4);
        let reopened = MeshIntentNonceLedger::open(temp.path(), household('a'), config(4)).unwrap();
        assert!(
            Arc::ptr_eq(&ledger.inner, &reopened.inner),
            "one physical authority must have one process worker and queue"
        );
        assert_eq!(
            MeshIntentNonceLedger::open(temp.path(), household('a'), config(3))
                .err()
                .unwrap(),
            MeshIntentNonceLedgerOpenError::PolicyMismatch
        );
        assert_eq!(
            MeshIntentNonceLedger::open(temp.path(), household('c'), config(4))
                .err()
                .unwrap(),
            MeshIntentNonceLedgerOpenError::AuthorityConflict
        );
        let block = TestWorkerBlock::new();
        ledger.install_worker_block_for_test(block.clone());

        let first_ledger = ledger.clone();
        let first = thread::spawn(move || {
            first_ledger.consume(
                &key(0x60),
                &evidence(MeshIntentChannel::Dev, 0x60, 900),
                floor(100),
                &ceremony_control(),
            )
        });
        block.entered.wait();

        let second_ledger = reopened.clone();
        let second = thread::spawn(move || {
            second_ledger.consume(
                &key(0x61),
                &evidence(MeshIntentChannel::Dev, 0x61, 900),
                floor(100),
                &ceremony_control(),
            )
        });
        let observation_deadline = Instant::now() + Duration::from_secs(2);
        while ledger.inner.queued_for_test.load(Ordering::Acquire) != 1 {
            assert!(
                Instant::now() < observation_deadline,
                "second request never occupied the single queue slot"
            );
            thread::yield_now();
        }

        let third_control = ceremony_control();
        let third_cancel = third_control.clone();
        let third_ledger = reopened;
        let third = thread::spawn(move || {
            third_ledger.consume(
                &key(0x62),
                &evidence(MeshIntentChannel::Dev, 0x62, 900),
                floor(100),
                &third_control,
            )
        });
        while ledger.inner.queue_waiters_for_test.load(Ordering::Acquire) != 1 {
            assert!(
                Instant::now() < observation_deadline,
                "third request never observed the bounded queue as full"
            );
            thread::yield_now();
        }
        third_cancel.cancel();
        assert_eq!(
            third.join().unwrap(),
            unavailable(MeshIntentNonceUnavailable::Cancelled),
            "work that never entered the bounded queue is KnownNoEffect"
        );

        block.release.wait();
        assert!(matches!(
            first.join().unwrap(),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));
        assert!(matches!(
            second.join().unwrap(),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));
        assert!(matches!(
            ledger.consume(
                &key(0x62),
                &evidence(MeshIntentChannel::Dev, 0x62, 900),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));
    }

    #[test]
    fn idle_worker_does_not_keep_ledger_inner_alive() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let weak = Arc::downgrade(&ledger.inner);
        drop(ledger);
        assert!(
            weak.upgrade().is_none(),
            "worker must not form an Arc cycle"
        );
    }

    #[test]
    fn replacing_the_named_store_directory_never_splits_the_live_authority() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let named = store_path(temp.path());
        let detached = temp.path().join("detached-ledger");
        let detached_record = named.join(RECORD_FILENAME);
        let before = fs::read(&detached_record).unwrap();

        fs::rename(&named, &detached).unwrap();
        fs::create_dir(&named).unwrap();
        fs::set_permissions(&named, fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(
            ledger.consume(
                &key(10),
                &evidence(MeshIntentChannel::Release, 10, 500),
                floor(100),
                &ceremony_control(),
            ),
            unavailable(MeshIntentNonceUnavailable::UnsafePath)
        );
        assert_eq!(fs::read(detached.join(RECORD_FILENAME)).unwrap(), before);
        assert!(
            !named.join(RECORD_FILENAME).exists(),
            "the replacement directory must never become a second authority"
        );
        assert_eq!(
            MeshIntentNonceLedger::open(temp.path(), household('a'), config(2))
                .err()
                .unwrap(),
            MeshIntentNonceLedgerOpenError::UnsafePath,
            "a fresh process must reject a replacement store as well"
        );
    }

    #[test]
    fn household_teardown_detaches_old_authority_and_new_household_starts_fresh() {
        let temp = TempDir::new().unwrap();
        let old = open_at(temp.path(), 4);
        assert!(matches!(
            old.consume(
                &key(0x73),
                &evidence(MeshIntentChannel::Dev, 0x73, 500),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));

        let installed = temp.path().join(HOUSEHOLD_SUBDIR);
        let detached = temp.path().join("household.tearing-down");
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        {
            let teardown = lifecycle.lock_exclusive().unwrap();
            assert!(teardown.rename_household_to_tearing_down().unwrap());
        }
        let detached_record = detached.join(STORE_SUBDIR).join(RECORD_FILENAME);
        let old_bytes = fs::read(&detached_record).unwrap();

        assert_eq!(
            old.consume(
                &key(0x74),
                &evidence(MeshIntentChannel::Dev, 0x74, 500),
                floor(100),
                &ceremony_control(),
            ),
            unavailable(MeshIntentNonceUnavailable::RecoveryRequired),
            "a live pre-teardown handle must not write into the detached household"
        );
        assert_eq!(fs::read(&detached_record).unwrap(), old_bytes);
        assert_eq!(
            MeshIntentNonceLedger::open(temp.path(), household('c'), config(4))
                .err()
                .unwrap(),
            MeshIntentNonceLedgerOpenError::RecoveryRequired,
            "a replacement must not install over an unresolved teardown breadcrumb"
        );

        {
            let recovery = lifecycle.lock_exclusive().unwrap();
            assert!(recovery.remove_tearing_down().unwrap());
            prepare_household(temp.path());
            recovery.sync_state_root().unwrap();
        }
        let replacement =
            MeshIntentNonceLedger::open(temp.path(), household('c'), config(4)).unwrap();
        assert!(!Arc::ptr_eq(&old.inner, &replacement.inner));

        assert!(matches!(
            replacement.consume(
                &key_for(household('c'), 0x73),
                &evidence(MeshIntentChannel::Release, 0x75, 700),
                floor_for(household('c'), 100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { generation: 2 }
        ));
        assert!(
            !temp.path().join(LOCK_ANCHOR_FILENAME).exists(),
            "the lock anchor must never outlive the household boundary"
        );
        assert!(
            !temp.path().join(STORE_SUBDIR).exists(),
            "no replay authority may live beside the household boundary"
        );
        assert!(
            installed.join(LOCK_ANCHOR_FILENAME).exists(),
            "the replacement authority owns an anchor inside its household"
        );

        drop(old);
        assert!(!detached.exists(), "the old household authority is gone");
        assert_eq!(replacement.target_household_id(), &household('c'));
    }

    #[test]
    fn lifecycle_exclusive_cannot_rename_after_postcheck_until_clean_commit_finishes() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 4);
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let block = TestWorkerBlock::new();
        ledger.install_worker_block_for_test(block.clone());
        let worker_ledger = ledger.clone();
        let worker = thread::spawn(move || {
            worker_ledger.consume(
                &key(0x76),
                &evidence(MeshIntentChannel::Dev, 0x76, 700),
                floor(100),
                &ceremony_control(),
            )
        });

        // This hook is after acquire's final binding check and DIRTY marker,
        // immediately before atomic_replace. The lifecycle read guard must
        // still be alive here.
        block.entered.wait();
        assert_eq!(
            lifecycle
                .lock_exclusive_until(Instant::now() + Duration::from_millis(50))
                .unwrap_err(),
            HouseholdLifecycleLockError::LockTimeout
        );
        assert!(temp.path().join(HOUSEHOLD_SUBDIR).exists());

        block.release.wait();
        assert!(matches!(
            worker.join().unwrap(),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));
        let teardown = lifecycle.lock_exclusive().unwrap();
        assert!(teardown.rename_household_to_tearing_down().unwrap());
        assert!(!temp.path().join(HOUSEHOLD_SUBDIR).exists());
    }

    #[test]
    fn worker_queued_behind_teardown_never_writes_the_detached_household() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 4);
        let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
        let teardown = lifecycle.lock_exclusive().unwrap();
        let worker_ledger = ledger.clone();
        let worker = thread::spawn(move || {
            worker_ledger.consume(
                &key(0x77),
                &evidence(MeshIntentChannel::Dev, 0x77, 700),
                floor(100),
                &ceremony_control(),
            )
        });

        assert!(teardown.rename_household_to_tearing_down().unwrap());
        let detached_record = temp
            .path()
            .join(HOUSEHOLD_TEARDOWN_BREADCRUMB)
            .join(STORE_SUBDIR)
            .join(RECORD_FILENAME);
        let before = fs::read(&detached_record).unwrap();
        drop(teardown);

        assert_eq!(
            worker.join().unwrap(),
            unavailable(MeshIntentNonceUnavailable::RecoveryRequired)
        );
        assert_eq!(fs::read(detached_record).unwrap(), before);
    }

    #[test]
    fn lifecycle_substitution_after_postcheck_downgrades_committed_to_indeterminate() {
        use std::os::unix::fs::OpenOptionsExt;

        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 4);
        let block = TestWorkerBlock::new();
        ledger.install_worker_block_for_test(block.clone());
        let worker_ledger = ledger.clone();
        let worker = thread::spawn(move || {
            worker_ledger.consume(
                &key(0x78),
                &evidence(MeshIntentChannel::Dev, 0x78, 700),
                floor(100),
                &ceremony_control(),
            )
        });

        block.entered.wait();
        let lock_path = temp
            .path()
            .join(crate::household_lifecycle::HOUSEHOLD_LIFECYCLE_LOCK_FILENAME);
        fs::remove_file(&lock_path).unwrap();
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(lock_path)
            .unwrap();
        block.release.wait();

        assert_eq!(
            worker.join().unwrap(),
            MeshIntentNonceConsumeOutcome::MayHaveTakenEffect {
                stage: MeshIntentNonceCommitStage::PostCommitBinding,
            }
        );
        let bytes = fs::read(store_path(temp.path()).join(RECORD_FILENAME)).unwrap();
        let record: LedgerRecordV1 = cbor::from_canonical_slice_strict(&bytes).unwrap();
        assert_eq!(
            record.entries.len(),
            1,
            "the downgrade must not claim no effect"
        );
    }

    #[test]
    fn replacing_the_named_lock_never_creates_a_second_cross_process_authority() {
        use std::os::unix::fs::OpenOptionsExt;

        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 4);
        let lock_path = store_path(temp.path()).join(LOCK_FILENAME);
        fs::remove_file(&lock_path).unwrap();
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();

        assert!(matches!(
            ledger.consume(
                &key(12),
                &evidence(MeshIntentChannel::Dev, 12, 500),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::Committed { .. }
        ));

        let result = temp.path().join("lock-contender-result");
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(LOCK_CONTENDER_TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_DIR_ENV, temp.path())
            .env(CHILD_RESULT_ENV, &result)
            .status()
            .unwrap();
        assert!(status.success(), "lock contender worker failed: {status}");
        assert_eq!(fs::read_to_string(result).unwrap(), "unsafe");
    }

    #[test]
    fn deterministic_failpoints_classify_every_durable_stage() {
        let stages = [
            MeshIntentNonceCommitStage::DirtyMarkerWrite,
            MeshIntentNonceCommitStage::DirtyMarkerSync,
            MeshIntentNonceCommitStage::TempInspect,
            MeshIntentNonceCommitStage::TempCleanup,
            MeshIntentNonceCommitStage::TempOpen,
            MeshIntentNonceCommitStage::TempWrite,
            MeshIntentNonceCommitStage::TempFlush,
            MeshIntentNonceCommitStage::TempSync,
            MeshIntentNonceCommitStage::Rename,
            MeshIntentNonceCommitStage::ParentSync,
            MeshIntentNonceCommitStage::Readback,
            MeshIntentNonceCommitStage::ReadbackMismatch,
            MeshIntentNonceCommitStage::CleanMarkerWrite,
            MeshIntentNonceCommitStage::CleanMarkerSync,
            MeshIntentNonceCommitStage::PostCommitBinding,
        ];

        for (index, stage) in stages.into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let ledger = open_at(temp.path(), 4);
            if stage == MeshIntentNonceCommitStage::TempCleanup {
                use std::os::unix::fs::PermissionsExt;

                let stale = store_path(temp.path()).join(TEMP_FILENAME);
                fs::write(&stale, b"stale").unwrap();
                fs::set_permissions(stale, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let armed = fail_injection::arm(stage);
            let replay_key = key(u8::try_from(index + 20).unwrap());
            let attempt = ledger.consume(
                &replay_key,
                &evidence(MeshIntentChannel::Dev, 9, 500),
                floor(100),
                &ceremony_control(),
            );
            drop(armed);

            if stage.may_have_changed_record() {
                assert_eq!(
                    attempt,
                    MeshIntentNonceConsumeOutcome::MayHaveTakenEffect { stage },
                    "post-rename stage {stage:?} must stay indeterminate"
                );
                assert!(matches!(
                    ledger.consume(
                        &replay_key,
                        &evidence(MeshIntentChannel::Release, 0xEE, 700),
                        floor(100),
                        &ceremony_control(),
                    ),
                    MeshIntentNonceConsumeOutcome::AlreadyConsumed { .. }
                ));
            } else {
                assert_eq!(
                    attempt,
                    unavailable(MeshIntentNonceUnavailable::WriteFailed(stage)),
                    "pre-rename stage {stage:?} must not claim an effect"
                );
                assert!(matches!(
                    ledger.consume(
                        &replay_key,
                        &evidence(MeshIntentChannel::Dev, 9, 500),
                        floor(100),
                        &ceremony_control(),
                    ),
                    MeshIntentNonceConsumeOutcome::Committed { .. }
                ));
            }
        }
    }

    #[test]
    fn dirty_marker_is_stabilized_before_a_visible_record_is_trusted() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let armed = fail_injection::arm(MeshIntentNonceCommitStage::ParentSync);
        let replay_key = key(0x44);
        assert_eq!(
            ledger.consume(
                &replay_key,
                &evidence(MeshIntentChannel::Dev, 0x44, 500),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::MayHaveTakenEffect {
                stage: MeshIntentNonceCommitStage::ParentSync
            }
        );
        drop(armed);
        assert_eq!(
            fs::read(store_path(temp.path()).join(LOCK_FILENAME)).unwrap(),
            MARKER_DIRTY
        );

        let restarted = open_at(temp.path(), 2);
        assert!(matches!(
            restarted.consume(
                &replay_key,
                &evidence(MeshIntentChannel::Release, 0x55, 600),
                floor(100),
                &ceremony_control(),
            ),
            MeshIntentNonceConsumeOutcome::AlreadyConsumed { .. }
        ));
        assert_eq!(
            fs::read(store_path(temp.path()).join(LOCK_FILENAME)).unwrap(),
            MARKER_CLEAN
        );
    }

    #[test]
    fn partial_dirty_and_clean_markers_recover_across_restart() {
        for partial in [&MARKER_DIRTY[..4], &MARKER_CLEAN[..6]] {
            let temp = TempDir::new().unwrap();
            let ledger = open_at(temp.path(), 2);
            assert!(matches!(
                ledger.consume(
                    &key(0x45),
                    &evidence(MeshIntentChannel::Dev, 0x45, 500),
                    floor(100),
                    &ceremony_control(),
                ),
                MeshIntentNonceConsumeOutcome::Committed { .. }
            ));
            let lock = store_path(temp.path()).join(LOCK_FILENAME);
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&lock)
                .unwrap();
            file.write_all(partial).unwrap();
            file.sync_all().unwrap();
            drop(file);

            let restarted = open_at(temp.path(), 2);
            assert!(matches!(
                restarted.consume(
                    &key(0x45),
                    &evidence(MeshIntentChannel::Release, 0x99, 700),
                    floor(100),
                    &ceremony_control(),
                ),
                MeshIntentNonceConsumeOutcome::AlreadyConsumed { .. }
            ));
            assert_eq!(fs::read(lock).unwrap(), MARKER_CLEAN);
        }
    }

    #[test]
    fn crash_after_lock_anchor_or_partial_initializing_resumes_fresh_init() {
        for marker in [Vec::new(), MARKER_INITIALIZING[..5].to_vec()] {
            let temp = TempDir::new().unwrap();
            prepare_household(temp.path());
            let lifecycle = HouseholdLifecycleLock::open_verified(temp.path()).unwrap();
            let _lifecycle_guard = lifecycle.lock_shared().unwrap();
            let state_dir = lifecycle.clone_state_dir().unwrap();
            let (state_dir, household_dir, store_dir) = open_store_dirs(state_dir).unwrap();
            let (mut lock_file, created) = open_lock_file(&store_dir).unwrap();
            assert!(created);
            verify_or_create_lock_anchor(&household_dir, &store_dir, &lock_file, created).unwrap();
            lock_file.write_all(&marker).unwrap();
            lock_file.sync_all().unwrap();
            drop(lock_file);
            drop(store_dir);
            drop(household_dir);
            drop(state_dir);

            let restarted = open_at(temp.path(), 2);
            assert!(matches!(
                restarted.consume(
                    &key(0x46),
                    &evidence(MeshIntentChannel::Dev, 0x46, 500),
                    floor(100),
                    &ceremony_control(),
                ),
                MeshIntentNonceConsumeOutcome::Committed { .. }
            ));
        }
    }

    #[test]
    fn owner_readable_state_root_creates_a_private_ledger_child() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        prepare_household(temp.path());
        let ledger = MeshIntentNonceLedger::open(temp.path(), household('a'), config(2)).unwrap();
        drop(ledger);
        assert_eq!(
            fs::metadata(store_path(temp.path()))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn group_or_world_writable_state_root_is_rejected_before_authority_creation() {
        use std::os::unix::fs::PermissionsExt;

        for mode in [0o775, 0o777] {
            let temp = TempDir::new().unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                MeshIntentNonceLedger::open(temp.path(), household('a'), config(2))
                    .err()
                    .unwrap(),
                MeshIntentNonceLedgerOpenError::UnsafePath
            );
            assert!(!store_path(temp.path()).exists());
        }
    }

    #[test]
    fn rename_known_no_effect_filesystem_allowlist_is_exact_and_review_gated() {
        // `MeshIntentNonceCommitStage::Rename => KnownNoEffect` is sound only
        // for this measured set. This exact-equality assertion deliberately
        // makes any allowlist expansion edit the test and revisit that outcome
        // classification; mere membership tests would let an unsafe addition
        // pass silently.
        assert_eq!(
            LINUX_RENAME_KNOWN_NO_EFFECT_FILESYSTEMS,
            [EXT4_SUPER_MAGIC, XFS_SUPER_MAGIC, BTRFS_SUPER_MAGIC]
        );
        assert_eq!(MACOS_RENAME_KNOWN_NO_EFFECT_FILESYSTEMS, [b"apfs"]);
        assert!(linux_filesystem_is_allowlisted(EXT4_SUPER_MAGIC));
        assert!(linux_filesystem_is_allowlisted(XFS_SUPER_MAGIC));
        assert!(linux_filesystem_is_allowlisted(BTRFS_SUPER_MAGIC));
        assert!(macos_filesystem_is_allowlisted(b"apfs"));
        assert!(!linux_filesystem_is_allowlisted(TMPFS_SUPER_MAGIC));
        assert!(!linux_filesystem_is_allowlisted(NFS_SUPER_MAGIC));
        assert!(!linux_filesystem_is_allowlisted(i64::MAX));
        assert!(!macos_filesystem_is_allowlisted(b"hfs"));
        assert!(!macos_filesystem_is_allowlisted(b"nfs"));
    }

    #[test]
    fn writable_lock_is_rejected_on_restart() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        drop(ledger);

        let lock = store_path(temp.path()).join(LOCK_FILENAME);
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o660)).unwrap();
        assert_eq!(
            MeshIntentNonceLedger::open(temp.path(), household('a'), config(2))
                .err()
                .unwrap(),
            MeshIntentNonceLedgerOpenError::UnsafePath
        );
    }

    fn child_command(dir: &Path, ready: &Path, go: &Path, result: &Path) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg(WORKER_TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_DIR_ENV, dir)
            .env(CHILD_READY_ENV, ready)
            .env(CHILD_GO_ENV, go)
            .env(CHILD_RESULT_ENV, result);
        command
    }

    fn wait_for_paths(paths: &[PathBuf]) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !paths.iter().all(|path| path.exists()) {
            assert!(Instant::now() < deadline, "child barrier timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_children(children: &mut [Child]) {
        for child in children {
            let status = child.wait().unwrap();
            assert!(status.success(), "ledger worker failed: {status}");
        }
    }

    #[test]
    fn real_processes_commit_exactly_once_and_restart_remembers() {
        const PROCESS_COUNT: usize = 6;
        let temp = TempDir::new().unwrap();
        let go = temp.path().join("go");
        let ready: Vec<_> = (0..PROCESS_COUNT)
            .map(|index| temp.path().join(format!("ready-{index}")))
            .collect();
        let results: Vec<_> = (0..PROCESS_COUNT)
            .map(|index| temp.path().join(format!("result-{index}")))
            .collect();
        let mut children: Vec<_> = ready
            .iter()
            .zip(&results)
            .map(|(ready_path, result_path)| {
                child_command(temp.path(), ready_path, &go, result_path)
                    .spawn()
                    .unwrap()
            })
            .collect();
        wait_for_paths(&ready);
        fs::write(&go, b"go").unwrap();
        wait_children(&mut children);

        let outcomes: Vec<_> = results
            .iter()
            .map(|path| fs::read_to_string(path).unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| *outcome == "committed")
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| *outcome == "already")
                .count(),
            PROCESS_COUNT - 1
        );

        // A fresh process after every writer exited is the restart proof.
        let restart_ready = temp.path().join("restart-ready");
        let restart_result = temp.path().join("restart-result");
        let mut restart = child_command(temp.path(), &restart_ready, &go, &restart_result)
            .spawn()
            .unwrap();
        assert!(restart.wait().unwrap().success());
        assert_eq!(fs::read_to_string(restart_result).unwrap(), "already");
    }

    #[test]
    fn multiprocess_consume_worker() {
        let Some(dir) = std::env::var_os(CHILD_DIR_ENV).map(PathBuf::from) else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os(CHILD_READY_ENV).unwrap());
        let go = PathBuf::from(std::env::var_os(CHILD_GO_ENV).unwrap());
        let result = PathBuf::from(std::env::var_os(CHILD_RESULT_ENV).unwrap());
        let ledger = open_at(&dir, 32);
        fs::write(&ready, b"ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !go.exists() {
            assert!(Instant::now() < deadline, "worker go barrier timed out");
            thread::sleep(Duration::from_millis(5));
        }
        let outcome = ledger.consume(
            &key(0xA5),
            &evidence(MeshIntentChannel::Dev, 0x5A, 1_000),
            floor(100),
            &ceremony_control(),
        );
        let label = match outcome {
            MeshIntentNonceConsumeOutcome::Committed { .. } => "committed",
            MeshIntentNonceConsumeOutcome::AlreadyConsumed { .. } => "already",
            MeshIntentNonceConsumeOutcome::MayHaveTakenEffect { .. } => "may-have",
            MeshIntentNonceConsumeOutcome::Unavailable { .. } => "unavailable",
        };
        fs::write(result, label).unwrap();
    }

    #[test]
    fn lock_substitution_contender_worker() {
        let Some(dir) = std::env::var_os(CHILD_DIR_ENV).map(PathBuf::from) else {
            return;
        };
        let result = PathBuf::from(std::env::var_os(CHILD_RESULT_ENV).unwrap());
        let label = match MeshIntentNonceLedger::open(&dir, household('a'), config(4)) {
            Err(MeshIntentNonceLedgerOpenError::UnsafePath) => "unsafe",
            Err(_) => "wrong-error",
            Ok(ledger) => match ledger.consume(
                &key(13),
                &evidence(MeshIntentChannel::Release, 13, 500),
                floor(100),
                &ceremony_control(),
            ) {
                MeshIntentNonceConsumeOutcome::Committed { .. } => "split-commit",
                MeshIntentNonceConsumeOutcome::AlreadyConsumed { .. } => "split-already",
                MeshIntentNonceConsumeOutcome::MayHaveTakenEffect { .. } => "split-may-have",
                MeshIntentNonceConsumeOutcome::Unavailable { .. } => "split-unavailable",
            },
        };
        fs::write(result, label).unwrap();
    }

    // =====================================================================
    // Crash-window harness (@khai, lane L1).
    //
    // The existing multiprocess test proves exactly-once across processes
    // that EXIT CLEANLY. That is not the case the durability protocol is
    // for. Markers, DIRTY/CLEAN and restart recovery only carry weight when
    // the process vanished mid-write and nothing got to run afterwards — no
    // unwinding, no Drop, no best-effort cleanup.
    //
    // So the child parks INSIDE the real commit routine at a named stage
    // (`crash_park`, reached through the same `fail_injection::take` every
    // stage already calls) and the parent SIGKILLs it there.
    // =====================================================================

    /// Every commit stage, with COMPILE-TIME exhaustiveness.
    ///
    /// The array alone would silently miss a stage added later, so
    /// `stage_index` carries an exhaustive `match`: a new variant fails to
    /// compile here (E0004) instead of quietly escaping the crash sweep.
    const ALL_COMMIT_STAGES: [MeshIntentNonceCommitStage; 16] = [
        MeshIntentNonceCommitStage::WorkerInFlight,
        MeshIntentNonceCommitStage::DirtyMarkerWrite,
        MeshIntentNonceCommitStage::DirtyMarkerSync,
        MeshIntentNonceCommitStage::TempInspect,
        MeshIntentNonceCommitStage::TempCleanup,
        MeshIntentNonceCommitStage::TempOpen,
        MeshIntentNonceCommitStage::TempWrite,
        MeshIntentNonceCommitStage::TempFlush,
        MeshIntentNonceCommitStage::TempSync,
        MeshIntentNonceCommitStage::Rename,
        MeshIntentNonceCommitStage::ParentSync,
        MeshIntentNonceCommitStage::Readback,
        MeshIntentNonceCommitStage::ReadbackMismatch,
        MeshIntentNonceCommitStage::CleanMarkerWrite,
        MeshIntentNonceCommitStage::CleanMarkerSync,
        MeshIntentNonceCommitStage::PostCommitBinding,
    ];

    const fn stage_index(stage: MeshIntentNonceCommitStage) -> usize {
        use MeshIntentNonceCommitStage as S;
        match stage {
            S::WorkerInFlight => 0,
            S::DirtyMarkerWrite => 1,
            S::DirtyMarkerSync => 2,
            S::TempInspect => 3,
            S::TempCleanup => 4,
            S::TempOpen => 5,
            S::TempWrite => 6,
            S::TempFlush => 7,
            S::TempSync => 8,
            S::Rename => 9,
            S::ParentSync => 10,
            S::Readback => 11,
            S::ReadbackMismatch => 12,
            S::CleanMarkerWrite => 13,
            S::CleanMarkerSync => 14,
            S::PostCommitBinding => 15,
        }
    }

    #[test]
    fn all_commit_stages_is_exhaustive() {
        for (index, stage) in ALL_COMMIT_STAGES.into_iter().enumerate() {
            assert_eq!(
                stage_index(stage),
                index,
                "ALL_COMMIT_STAGES is out of sync"
            );
        }
    }

    const CRASH_WORKER_TEST_NAME: &str =
        "mesh_intent_nonce_ledger::tests::crash_park_consume_worker";

    /// Spawn a child that will park at `site` inside the real commit, wait
    /// until it has demonstrably ARRIVED, then `SIGKILL` it there.
    ///
    /// Returns once the child is reaped. The ready-file wait is what makes
    /// this deterministic: killing on a timer would sometimes kill before the
    /// window and the test would pass for the wrong reason.
    fn kill_child_parked_at(dir: &Path, site: &str) {
        let ready = dir.join(format!("parked-{}", site.replace(':', "_")));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(CRASH_WORKER_TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_DIR_ENV, dir)
            .env(crate::crash_park::PARK_SITE_ENV, site)
            .env(crate::crash_park::PARK_READY_ENV, &ready)
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            if let Ok(Some(status)) = child.try_wait() {
                panic!("child exited ({status}) without ever reaching site {site}");
            }
            assert!(
                Instant::now() < deadline,
                "child never reached park site {site}"
            );
            thread::sleep(Duration::from_millis(10));
        }

        // A real SIGKILL. Not a simulated Drop, not an early return: the
        // process is destroyed with the ledger lock held and whatever bytes
        // it had written still exactly as the filesystem has them.
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(
            !status.success(),
            "child at {site} was supposed to be killed, not to exit cleanly"
        );
    }

    /// Child half: consume once, parking wherever the environment says.
    #[test]
    fn crash_park_consume_worker() {
        let Some(dir) = std::env::var_os(CHILD_DIR_ENV).map(PathBuf::from) else {
            return;
        };
        let ledger = open_at(&dir, 32);
        // Arm ONLY now: the subject is open, so the park can no longer fire on
        // initialization's own atomic_replace instead of the consume.
        crate::crash_park::arm_from_env();
        let _ = ledger.consume(
            &key(0xC7),
            &evidence(MeshIntentChannel::Dev, 0x7C, 1_000),
            floor(100),
            &ceremony_control(),
        );
    }

    /// Replay the SAME key in a fresh process-equivalent ledger and report
    /// what a caller would observe after the crash.
    fn replay_same_key(dir: &Path) -> MeshIntentNonceConsumeOutcome {
        let ledger = open_at(dir, 32);
        ledger.consume(
            &key(0xC7),
            &evidence(MeshIntentChannel::Dev, 0x7C, 1_000),
            floor(100),
            &ceremony_control(),
        )
    }

    /// THE crash-window invariant.
    ///
    /// For every stage the module itself classifies as possibly having
    /// changed the record, a `SIGKILL` there must never leave the nonce
    /// re-consumable: a later replay may report `AlreadyConsumed`, or refuse,
    /// but reporting a fresh `Committed` would mean the same nonce was
    /// consumed twice across a crash.
    ///
    /// Driven off `may_have_changed_record()` rather than a hand-written list
    /// so a stage added later is covered without anyone remembering to add
    /// it here.
    #[test]
    fn sigkill_after_the_record_may_have_changed_never_permits_a_second_commit() {
        for stage in ALL_COMMIT_STAGES {
            if !stage.may_have_changed_record() {
                continue;
            }
            if stage == MeshIntentNonceCommitStage::WorkerInFlight {
                // Not a filesystem stage: no park site on the write path.
                continue;
            }
            let temp = TempDir::new().unwrap();
            kill_child_parked_at(temp.path(), &format!("ledger:{stage:?}"));

            match replay_same_key(temp.path()) {
                MeshIntentNonceConsumeOutcome::Committed { .. } => panic!(
                    "SIGKILL at {stage:?} (may_have_changed_record) left the nonce \
                     re-consumable: replay reported a fresh Committed, which is the \
                     same nonce taking effect twice across a crash"
                ),
                other => {
                    eprintln!("stage {stage:?} -> replay {other:?}");
                }
            }
        }
    }

    /// Diagnostic: what does the filesystem actually hold after a SIGKILL at
    /// `ParentSync`, and what does recovery then decide?
    ///
    /// Written because the sweep flagged `ParentSync` and "replay committed
    /// again" has at least three explanations — recovery discarding a renamed
    /// record, a deliberate fail-toward-unconsumed design, or SIGKILL simply
    /// not being power loss (the rename survives in page cache). Naming which
    /// one it is requires looking, not reasoning.
    #[test]
    fn diagnose_parent_sync_crash_state() {
        let temp = TempDir::new().unwrap();
        kill_child_parked_at(temp.path(), "ledger:ParentSync");

        let store = store_path(temp.path());
        eprintln!("--- store dir after SIGKILL at ParentSync ---");
        if let Ok(entries) = fs::read_dir(&store) {
            for entry in entries.flatten() {
                let meta = entry.metadata().ok();
                eprintln!(
                    "  {} ({} bytes)",
                    entry.file_name().to_string_lossy(),
                    meta.map_or(0, |m| m.len())
                );
            }
        } else {
            eprintln!("  <store dir absent>");
        }
        let record = store.join(RECORD_FILENAME);
        eprintln!("record present: {}", record.exists());
        eprintln!(
            "record bytes:   {}",
            fs::metadata(&record).map_or(0, |m| m.len())
        );
        let lock = store.join(LOCK_FILENAME);
        let marker = fs::read(&lock).unwrap_or_default();
        eprintln!("marker raw:     {:?}", String::from_utf8_lossy(&marker));
        eprintln!(
            "marker is:      {}",
            match marker.as_slice() {
                m if m == MARKER_CLEAN => "CLEAN",
                m if m == MARKER_DIRTY => "DIRTY",
                m if m == MARKER_INITIALIZING => "INITIALIZING",
                _ => "other/empty",
            }
        );
        eprintln!("--- replay ---");
        eprintln!("{:?}", replay_same_key(temp.path()));
    }

    /// Non-vacuity for the harness itself: a `SIGKILL` BEFORE anything can
    /// have changed the record must leave the nonce still consumable.
    ///
    /// Without this, the test above would also pass on a ledger that simply
    /// refused everything forever — "never commits again" is only meaningful
    /// against a control that shows it still commits when it should.
    #[test]
    fn sigkill_before_the_record_can_change_leaves_the_nonce_consumable() {
        let temp = TempDir::new().unwrap();
        kill_child_parked_at(temp.path(), "ledger:TempWrite");
        assert!(
            matches!(
                replay_same_key(temp.path()),
                MeshIntentNonceConsumeOutcome::Committed { .. }
            ),
            "a crash before the rename must not cost the caller its nonce"
        );
    }

    /// The correct partition: production ends at the real test MODULE
    /// boundary, never at the first bare `#[cfg(test)]` attribute — a file
    /// can have (and this one does, 27 times) individual test-only items
    /// scattered through production code long before the module starts.
    /// Built via `concat!` on purpose: writing the marker as one literal
    /// string would make this function's own source a hit for any guard
    /// (including the one below) that greps this file for its own marker.
    fn split_at_test_module(text: &str) -> (&str, &str) {
        let marker = concat!("#[cfg(test)]", "\n", "mod tests {");
        match text.find(marker) {
            Some(idx) => (&text[..idx], &text[idx..]),
            None => (text, ""),
        }
    }

    /// The WRONG partition, kept only so `split_partition_control_has_teeth`
    /// below can demonstrate it fails where `split_at_test_module` succeeds.
    /// Never used by the real guard.
    fn split_at_first_cfg_test_attribute(text: &str) -> (&str, &str) {
        let marker = concat!("#[cfg(test)]");
        match text.find(marker) {
            Some(idx) => (&text[..idx], &text[idx..]),
            None => (text, ""),
        }
    }

    /// Proves the containment check that
    /// `mesh_intent_nonce_ledger_open_has_exactly_one_production_call_site`
    /// relies on actually discriminates a too-early cut from a correct
    /// one — on a SYNTHETIC fixture, not `include_str!` of a real file.
    ///
    /// A real-file demonstration is only as good as that file's current,
    /// incidental shape: `machine_roster_store.rs`'s first bare
    /// `#[cfg(test)]` happens to sit after
    /// `open_mesh_intent_nonce_ledger`'s definition today, so naive and
    /// correct partitioning coincide there — proving nothing about
    /// whether the check itself has teeth, only that this file hasn't
    /// been reorganised yet. A synthetic fixture with the SAME shape as
    /// the real trap (an early scattered `#[cfg(test)]`, then the
    /// definition, then the real module) demonstrates the property
    /// itself, independent of any file's future edits. (@zain)
    #[test]
    fn split_partition_control_has_teeth() {
        let fixture = concat!(
            "//! doc\n",
            "#[cfg(test)]\n",
            "fn helper_only_in_tests() {}\n",
            "\n",
            "pub(crate) fn open(path: &Path) -> Self {\n",
            "    todo!()\n",
            "}\n",
            "\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    // real test module\n",
            "}\n",
        );

        let (naive_production, _) = split_at_first_cfg_test_attribute(fixture);
        assert!(
            !naive_production.contains("pub(crate) fn open("),
            "control failed to fire: the naive first-attribute split must \
             lose the definition on this fixture, or the control proves \
             nothing"
        );

        let (correct_production, _) = split_at_test_module(fixture);
        assert!(
            correct_production.contains("pub(crate) fn open("),
            "the module-boundary split must keep the definition on a \
             fixture shaped exactly like the real trap"
        );
    }

    /// `MeshIntentNonceLedger::open` is `pub(crate)`: visibility already
    /// proves no crate OUTSIDE household-rs can call it (the
    /// `mesh_intent_nonce_ledger_raw_open.rs` compile-fail fixture proves
    /// that half). Visibility says nothing about INSIDE household-rs —
    /// nothing stops a second call site from opening a ledger with
    /// caller-chosen coordinates instead of going through
    /// `MachineRosterCoordinator::open_mesh_intent_nonce_ledger`, which
    /// supplies `&self.state_dir` and `self.hh_id.clone()` — the
    /// coordinator's own bound state, never a caller's choice. This proves
    /// the internal half: exactly one production call site exists in the
    /// whole crate, and it is that one.
    ///
    /// Anchored on the TYPE this file's own guard measures, qualified as
    /// `Type::open(`, never the bare verb `open(` alone — this crate has
    /// several unrelated private `open_*`
    /// helpers (`open_store_dirs`, `open_lock_file`, `open_anchor`,
    /// `open_record_for_read`) a verb-only anchor would also match.
    ///
    /// Excludes `tests/compile-fail/peer_expectation/mesh_intent_nonce_ledger_raw_open.rs`
    /// and its `.stderr` sibling on purpose: neither ever compiles into
    /// anything, so neither is a call site in any artifact this crate
    /// produces, and both live outside `src/`, which is all this sweeps.
    // (@khai) Grep-discoverability note: `needle` below is built via
    // `concat!` so this guard cannot match its own source — deliberate
    // (see `split_partition_control_has_teeth`'s doc), but it means a plain
    // text search for "MeshIntentNonceLedger::open" will NOT find this
    // guard. Anyone inventorying every reference to the ledger's `open`
    // should also search for `open_mesh_intent_nonce_ledger` and for this
    // function's own name.
    //
    // This co-habitation is a CHOICE, not a technical requirement (@khai,
    // @zain): the checks below are purely textual (`include_str!` plus
    // counting) and touch nothing `pub(crate)`, so a `tests/*.rs` file
    // using `include_str!("../src/mesh_intent_nonce_ledger.rs")` would
    // read the identical text without ever including ITS OWN source —
    // `include_str!` reads the target file, never the file containing the
    // call — and the self-reference this `concat!` works around would not
    // exist there at all. Kept here instead for two reasons: a new
    // `tests/*.rs` file is a new Cargo target, which moves the ratchet's
    // pinned count in both its sites for zero behavioral gain; and this
    // guard belongs with the rest of this module's ledger assertions
    // rather than split across two files.
    //
    // (@zain) One direct consequence of that choice: `this_test`'s
    // expected count of 13 below is no longer only a fact about this
    // file's test module — it also depends on `needle` staying `concat!`'d
    // rather than a plain literal. A future cleanup that "simplifies"
    // `needle` back to one string would make this function's own source
    // match itself once compiled into the test half, and the symptom
    // would be an unexplained 14. If this guard ever moves to its own
    // `tests/*.rs` file, `needle` can safely go back to a plain literal at
    // the same time — not before.
    #[test]
    fn mesh_intent_nonce_ledger_open_has_exactly_one_production_call_site() {
        let needle = concat!("MeshIntentNonceLedger", "::open(");

        let this_file = include_str!("mesh_intent_nonce_ledger.rs");
        let (this_production, this_test) = split_at_test_module(this_file);

        // Non-vacuity, direction 1 (@zain): if the partition ever matched
        // NOTHING and fell back to treating the whole file as "production"
        // (e.g. a broken `needle`/`marker` after a refactor), the 13 known
        // test call sites would show up right here, in the 0-expected
        // count below — this assertion is the upper bound, catching a
        // partition that swallowed the test module into "production".
        assert_eq!(
            this_production.matches(needle).count(),
            0,
            "no production call site in mesh_intent_nonce_ledger.rs itself \
             may call MeshIntentNonceLedger::open directly — if this is \
             13, the partition matched nothing and fell back to the whole \
             file"
        );
        // Non-vacuity, direction 2 (@zain): the count above passing is not
        // enough — a too-early cut ALSO reports 0 calls, for the wrong
        // reason (it excised the definition along with everything else).
        // This is the lower bound: the production half must still contain
        // the symbol being measured. Together, direction 1 and direction 2
        // are non-redundant — each catches a partition failure the other
        // does not. `split_partition_control_has_teeth` above proves this
        // specific check discriminates; here it guards the real
        // measurement.
        // This also catches the real `open` definition being moved or
        // removed (not just a too-early partition cut) — but only because
        // this guard lives in `mod tests`, on the far side of `marker`
        // from `this_production`. The residual (@zain): it takes all
        // three of (1) `marker` flattened to a plain literal, (2) this
        // guard itself relocated out of `mod tests` into production, and
        // (3) `needle` still `concat!`'d, for that to pass spuriously —
        // (1)+(2) alone would put this assertion's own plain copy of the
        // definer literal on the production side regardless of the
        // real definition's fate; (3) is what keeps the earlier
        // `this_production.matches(needle).count() == 0` check from
        // catching the same relocation via the guard's own needle use.
        // Improbable as a conjunction, but worth naming so nobody creates
        // it by accident while tidying one of the three in isolation.
        assert!(
            this_production.contains("pub(crate) fn open("),
            "production half of mesh_intent_nonce_ledger.rs lost the \
             `open` definition itself — either the partition cut too \
             early, or the real definition was moved/removed. This \
             assertion assumes the guard stays inside `mod tests`; see \
             the comment above for the narrow case where that stops \
             being true"
        );
        assert_eq!(
            this_test.matches(needle).count(),
            13,
            "expected exactly the known 13 test call sites; a different \
             count means either a call site was added/removed here, the \
             module-boundary split broke, or `needle` above was flattened \
             back to a plain literal — it lives in this same file's test \
             module, so a plain copy would count itself as a 14th match"
        );

        let coordinator_fn = concat!("fn open_mesh_intent_nonce_ledger", "(");
        let coordinator_file = include_str!("machine_roster_store.rs");
        let (coordinator_production, _coordinator_test) = split_at_test_module(coordinator_file);

        assert!(
            coordinator_production.contains(coordinator_fn),
            "production half of machine_roster_store.rs lost \
             open_mesh_intent_nonce_ledger's own definition — the \
             partition cut too early"
        );
        assert_eq!(
            coordinator_production.matches(needle).count(),
            1,
            "exactly one production call site to MeshIntentNonceLedger::open \
             may exist in the whole crate, and it must be in \
             machine_roster_store.rs"
        );

        // Not just "one call exists in production" — that one call must be
        // INSIDE open_mesh_intent_nonce_ledger's own body, not merely
        // somewhere else in the same production half. Isolate the
        // function's body by brace-matching from its signature.
        let fn_start = coordinator_production
            .find(coordinator_fn)
            .expect("checked above: the definition is present");
        let brace_open = coordinator_production[fn_start..]
            .find('{')
            .map(|offset| fn_start + offset)
            .expect("a fn definition must have an opening brace");
        let mut depth = 0i32;
        let mut fn_end = coordinator_production.len();
        for (offset, ch) in coordinator_production[brace_open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        fn_end = brace_open + offset + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let fn_body = &coordinator_production[fn_start..fn_end];
        assert_eq!(
            fn_body.matches(needle).count(),
            1,
            "the one production call to MeshIntentNonceLedger::open must be \
             inside open_mesh_intent_nonce_ledger's own body — a call \
             elsewhere in production would still pass the crate-wide count \
             above while bypassing the coordinator"
        );
    }

    // Split from the call-site test above (@zain, @khai): both tests read
    // the same `mod tests` boundary and the same production text, but the
    // containment assertion above and the membership check below panic on
    // DIFFERENT causes. Kept in one `#[test]`, a definition-loss mutation
    // that trips the containment assert masks this one — `cargo test`
    // stops that thread at the first panic, so a real, symmetric mutant
    // (rename/move the real definition) only ever shows ONE red, never
    // both, and whichever assertion happens to run second is silently
    // unexercised on every such run. As two `#[test]`s, both are
    // independently observable in the same `cargo test` invocation: a
    // mutation that only breaks containment fails just this file's own
    // call-site test; a mutation that lets a second file start defining
    // `open` fails just the membership test below; a mutation that does
    // both (e.g. the real definition genuinely moves to another file)
    // fails both, visibly, in the same run.
    //
    // Non-vacuity, closing the gap a minimum-cardinality check would
    // leave open: membership (which files DEFINE the symbol) must be
    // decided on each file's WHOLE content, never on a partitioned
    // half — a broken partition that cuts before the definition would
    // otherwise make this file look like it doesn't define `open` at
    // all, silently excluding it from every assertion above rather
    // than failing one. And the expected value is the SET `{
    // "mesh_intent_nonce_ledger.rs" }`, not `>= 1`: a minimum would
    // stay green if a second file quietly started defining `open` too
    // — exactly the drift this guard exists to catch. (@zain)
    //
    // This scan excludes ITSELF by `file!()` rather than by
    // obfuscating the literal (@khai): unlike the `needle`/`marker`
    // checks in the call-site test above — which must read this exact
    // file's own two halves and cannot avoid it — this loop scans MANY
    // files, and this file is only incidentally one of them.
    // `file!()`-exclusion survives a future `git mv` of this guard to
    // another file; a hidden literal would silently start matching
    // itself again the moment the guard moved into (or a walked
    // directory started including) wherever it now lives. The literal
    // below is therefore left PLAIN and grep-findable. Excluding this
    // file from the walk does not weaken the check: this file's own
    // definition is proven present by the OTHER test's direct `contains`
    // assertion, so this walk only needs to prove no OTHER file also
    // defines it — the two tests together cover both halves of
    // membership; neither alone does.
    #[test]
    fn mesh_intent_nonce_ledger_open_is_defined_in_exactly_one_file() {
        let definer = "pub(crate) fn open(";
        let self_basename = Path::new(file!())
            .file_name()
            .expect("file!() must have a basename")
            .to_owned();
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut defining_files_other_than_self: Vec<String> = std::fs::read_dir(&src_dir)
            .expect("household-rs/src must exist")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "rs"))
            .filter(|entry| entry.file_name() != self_basename)
            .filter_map(|entry| {
                let path = entry.path();
                let text = std::fs::read_to_string(&path).ok()?;
                text.contains(definer)
                    .then(|| path.file_name().unwrap().to_string_lossy().into_owned())
            })
            .collect();
        defining_files_other_than_self.sort();
        assert_eq!(
            defining_files_other_than_self,
            Vec::<String>::new(),
            "no file OTHER than mesh_intent_nonce_ledger.rs (excluded from \
             this scan by file!(), already proven to define `open` by the \
             direct assertion above) may also define `open` on this type — \
             any name here means the definition moved or duplicated"
        );
    }
}
