//! Durable replay authority for signed mesh connection-intent nonces.
//!
//! One canonical record is the complete authority for one target household.
//! A stable `fs2` lock serializes the read/modify/write transaction across
//! processes. The lock file also carries a tiny durable clean/dirty marker:
//! an operation marks the record dirty *before* replacing it and marks it
//! clean only after rename, parent-directory fsync, and byte-exact readback.
//! A later process therefore never treats a merely visible post-rename record
//! as proof of durability; it first rewrites the same canonical bytes until
//! they are committed.
//! The lock inode is hard-linked into the parent as a durable anchor. Every
//! record operation is relative to the retained store-directory descriptor,
//! and both directory and lock bindings are rechecked after locking, so a
//! renamed/recreated path cannot create a second authority.
//!
//! The replay key is exactly
//! `(domain, hh_id, initiator_m_id, delegated_key_id, nonce[32])`. Channel and
//! intent digest are retained evidence, not additional replay namespaces.
//! Expired rows may be removed only when a caller-provided trusted wall floor
//! is *strictly greater* than `not_after`.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use fs2::FileExt;
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::cbor;
use crate::ids::{HouseholdId, MachineId};

/// Domain component of every nonce replay key.
pub const MESH_INTENT_NONCE_KEY_DOMAIN: &str = "soyeht/mesh-intent-nonce-key/v1";

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

/// A wall-clock floor minted only by [`MachineRosterCoordinator`].
///
/// Downstream code cannot manufacture a high floor to erase replay history:
///
/// ```compile_fail
/// use household_rs::mesh_intent_nonce_ledger::TrustedWallFloor;
/// let forged = TrustedWallFloor(u64::MAX);
/// ```
///
/// [`MachineRosterCoordinator`]: crate::machine_roster_store::MachineRosterCoordinator
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TrustedWallFloor(u64);

impl TrustedWallFloor {
    pub(crate) const fn from_machine_roster(unix_seconds: u64) -> Self {
        Self(unix_seconds)
    }

    #[must_use]
    pub const fn unix_seconds(self) -> u64 {
        self.0
    }
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
            Self::ParentSync
            | Self::Readback
            | Self::ReadbackMismatch
            | Self::CleanMarkerWrite
            | Self::CleanMarkerSync => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshIntentNonceUnavailable {
    WrongHousehold,
    EvidenceExpired,
    CapacityExhausted,
    GenerationExhausted,
    LockTimeout,
    DeadlineExceeded,
    Cancelled,
    LockPoisoned,
    UnsafePath,
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
    #[error("ledger path is unsafe")]
    UnsafePath,
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
    store_dir: File,
    lock_file: Mutex<File>,
}

/// Narrow household-owned replay authority. It has no dependency on the
/// moving mesh-session core trait and can be adapted to it later.
#[derive(Clone)]
pub struct MeshIntentNonceLedger {
    inner: Arc<LedgerInner>,
}

impl MeshIntentNonceLedger {
    pub fn open(
        state_dir: impl AsRef<Path>,
        target_hh_id: HouseholdId,
        config: MeshIntentNonceLedgerConfig,
    ) -> Result<Self, MeshIntentNonceLedgerOpenError> {
        let (state_dir, store_dir) = open_store_dirs(state_dir.as_ref())?;
        let (lock_file, lock_created) = open_lock_file(&store_dir)?;
        verify_or_create_lock_anchor(&state_dir, &store_dir, &lock_file, lock_created)?;
        let ledger = Self {
            inner: Arc::new(LedgerInner {
                target_hh_id,
                config,
                state_dir,
                store_dir,
                lock_file: Mutex::new(lock_file),
            }),
        };
        ledger.initialize_or_recover()?;
        Ok(ledger)
    }

    #[must_use]
    pub fn target_household_id(&self) -> &HouseholdId {
        &self.inner.target_hh_id
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
        if evidence.not_after <= trusted_floor.0 {
            return unavailable(MeshIntentNonceUnavailable::EvidenceExpired);
        }

        let mut guard = match self.acquire(Some(control)) {
            Ok(guard) => guard,
            Err(reason) => return unavailable(reason),
        };
        let mut record = match self.load_clean_record(&mut guard) {
            Ok(record) => record,
            Err(reason) => return unavailable(reason),
        };
        if let Some(reason) = abort_reason(control) {
            return unavailable(reason);
        }

        // Strict `>` is intentional. Equality is still retained even though a
        // fresh intent at equality is no longer admissible.
        record
            .entries
            .retain(|_, entry| trusted_floor.0 <= entry.not_after);

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
        if let Some(reason) = abort_reason(control) {
            return unavailable(reason);
        }
        self.commit_semantic(&mut guard, &canonical, next_generation)
    }

    fn initialize_or_recover(&self) -> Result<(), MeshIntentNonceLedgerOpenError> {
        let mut guard = self.acquire(None).map_err(map_unavailable_to_open)?;
        let marker = read_marker(&mut guard).map_err(map_open_io)?;
        match marker.as_deref() {
            None | Some(MARKER_INITIALIZING) => self.initialize_under_lock(&mut guard),
            Some(MARKER_CLEAN) => {
                self.read_and_validate_record()
                    .map_err(map_unavailable_to_open)?;
                Ok(())
            }
            Some(MARKER_DIRTY) => self.recover_dirty_under_lock(&mut guard),
            Some(_) => Err(MeshIntentNonceLedgerOpenError::Corrupt),
        }
    }

    fn initialize_under_lock(
        &self,
        guard: &mut LedgerLockGuard<'_>,
    ) -> Result<(), MeshIntentNonceLedgerOpenError> {
        write_marker_raw(guard, MARKER_INITIALIZING).map_err(map_open_io)?;
        let record = match read_optional_record(&self.inner.store_dir, RECORD_FILENAME) {
            Ok(Some(bytes)) => self
                .decode_and_validate(&bytes)
                .map_err(map_unavailable_to_open)?,
            Ok(None) => {
                LedgerRecordV1::empty(self.inner.target_hh_id.clone(), self.inner.config.capacity)
            }
            Err(reason) => return Err(map_unavailable_to_open(reason)),
        };
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

    fn recover_dirty_under_lock(
        &self,
        guard: &mut LedgerLockGuard<'_>,
    ) -> Result<(), MeshIntentNonceLedgerOpenError> {
        let bytes = read_record_bytes(&self.inner.store_dir, RECORD_FILENAME)
            .map_err(map_unavailable_to_open)?;
        self.decode_and_validate(&bytes)
            .map_err(map_unavailable_to_open)?;
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

    fn acquire(
        &self,
        control: Option<&MeshIntentNonceConsumeControl>,
    ) -> Result<LedgerLockGuard<'_>, MeshIntentNonceUnavailable> {
        if !verify_store_dir_binding(&self.inner.state_dir, &self.inner.store_dir) {
            return Err(MeshIntentNonceUnavailable::UnsafePath);
        }
        if let Some(reason) = control.and_then(abort_reason) {
            return Err(reason);
        }
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
        if !verify_lock_anchor(&self.inner.state_dir, &guard) {
            return Err(MeshIntentNonceUnavailable::UnsafePath);
        }
        loop {
            if let Some(reason) = control.and_then(abort_reason) {
                return Err(reason);
            }
            match guard.try_lock_exclusive() {
                Ok(()) => {
                    let locked = LedgerLockGuard { file: guard };
                    if !verify_store_dir_binding(&self.inner.state_dir, &self.inner.store_dir) {
                        return Err(MeshIntentNonceUnavailable::UnsafePath);
                    }
                    if !verify_lock_anchor(&self.inner.state_dir, &locked.file) {
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
        match marker.as_deref() {
            Some(MARKER_CLEAN) => self.read_and_validate_record(),
            Some(MARKER_DIRTY) => {
                self.recover_dirty_for_consume(guard)?;
                self.read_and_validate_record()
            }
            _ => Err(MeshIntentNonceUnavailable::CorruptRecord),
        }
    }

    fn recover_dirty_for_consume(
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

        match atomic_replace(
            &self.inner.store_dir,
            RECORD_FILENAME,
            TEMP_FILENAME,
            canonical,
        ) {
            DurableWrite::NotCommitted { stage } => {
                let _ = write_marker_raw(guard, MARKER_CLEAN);
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

fn entry_id(key: &StoredKeyV1) -> Result<String, ()> {
    let canonical = cbor::to_canonical_vec(key).map_err(|_| ())?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize()))
}

struct LedgerLockGuard<'a> {
    file: MutexGuard<'a, File>,
}

impl Drop for LedgerLockGuard<'_> {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&*self.file);
    }
}

fn open_store_dirs(state_path: &Path) -> Result<(File, File), MeshIntentNonceLedgerOpenError> {
    let state_dir = File::from(
        rustix::fs::open(
            state_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_open_errno)?,
    );

    let created = match rustix::fs::mkdirat(&state_dir, STORE_SUBDIR, Mode::RWXU) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(error) => return Err(map_open_errno(error)),
    };
    let store_dir = File::from(
        rustix::fs::openat(
            &state_dir,
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
    if !verify_store_dir_binding(&state_dir, &store_dir) {
        return Err(MeshIntentNonceLedgerOpenError::UnsafePath);
    }

    // Unconditional: an earlier attempt may have made the child visible but
    // failed the parent barrier. Visibility is never reused as durability.
    state_dir.sync_all().map_err(map_open_io)?;
    Ok((state_dir, store_dir))
}

fn validate_private_directory(dir: &File) -> Result<(), MeshIntentNonceLedgerOpenError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = dir.metadata().map_err(map_open_io)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(MeshIntentNonceLedgerOpenError::UnsafePath);
    }
    Ok(())
}

fn verify_store_dir_binding(state_dir: &File, store_dir: &File) -> bool {
    let Ok(opened) = rustix::fs::fstat(store_dir) else {
        return false;
    };
    let Ok(named) = rustix::fs::statat(state_dir, STORE_SUBDIR, AtFlags::SYMLINK_NOFOLLOW) else {
        return false;
    };
    opened.st_dev == named.st_dev && opened.st_ino == named.st_ino
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
    state_dir: &File,
    store_dir: &File,
    lock_file: &File,
    lock_created: bool,
) -> Result<(), MeshIntentNonceLedgerOpenError> {
    if let Some(anchor) = open_anchor(state_dir)? {
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
        state_dir,
        LOCK_ANCHOR_FILENAME,
        AtFlags::empty(),
    ) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(map_open_errno(error)),
    }
    let anchor = open_anchor(state_dir)?.ok_or(MeshIntentNonceLedgerOpenError::RecoveryRequired)?;
    if !same_file(&anchor, lock_file) {
        return Err(MeshIntentNonceLedgerOpenError::UnsafePath);
    }
    state_dir.sync_all().map_err(map_open_io)
}

fn open_anchor(state_dir: &File) -> Result<Option<File>, MeshIntentNonceLedgerOpenError> {
    match rustix::fs::openat(
        state_dir,
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

fn verify_lock_anchor(state_dir: &File, lock_file: &File) -> bool {
    open_anchor(state_dir)
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
    use std::os::unix::fs::PermissionsExt;

    let meta = file
        .metadata()
        .map_err(|_| MeshIntentNonceUnavailable::Io)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
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
    if fail_injection::take(MeshIntentNonceCommitStage::Rename)
        || rustix::fs::renameat(parent, temp_name, parent, target_name).is_err()
    {
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

    pub(super) fn take(stage: MeshIntentNonceCommitStage) -> bool {
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
        MeshIntentNonceKey::new(
            household('a'),
            machine('b'),
            "mesh-key-v1",
            [nonce_byte; 32],
        )
        .unwrap()
    }

    fn evidence(
        channel: MeshIntentChannel,
        digest_byte: u8,
        not_after: u64,
    ) -> MeshIntentNonceEvidence {
        MeshIntentNonceEvidence::new(channel, [digest_byte; 32], not_after).unwrap()
    }

    fn open_at(path: &Path, capacity: usize) -> MeshIntentNonceLedger {
        MeshIntentNonceLedger::open(path, household('a'), config(capacity)).unwrap()
    }

    fn floor(unix_seconds: u64) -> TrustedWallFloor {
        TrustedWallFloor::from_machine_roster(unix_seconds)
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
        let bytes = fs::read(temp.path().join(STORE_SUBDIR).join(RECORD_FILENAME)).unwrap();
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
        let record_path = temp.path().join(STORE_SUBDIR).join(RECORD_FILENAME);
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
        let record_path = temp.path().join(STORE_SUBDIR).join(RECORD_FILENAME);
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
        let record_path = temp.path().join(STORE_SUBDIR).join(RECORD_FILENAME);
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
    fn cancellation_interrupts_an_in_process_lock_wait_without_effect() {
        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let record_path = temp.path().join(STORE_SUBDIR).join(RECORD_FILENAME);
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
        assert_eq!(observed, unavailable(MeshIntentNonceUnavailable::Cancelled));
        assert_eq!(fs::read(record_path).unwrap(), before);
        drop(held);
        worker.join().unwrap();
    }

    #[test]
    fn replacing_the_named_store_directory_never_splits_the_live_authority() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 2);
        let named = temp.path().join(STORE_SUBDIR);
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
    fn replacing_the_named_lock_never_creates_a_second_cross_process_authority() {
        use std::os::unix::fs::OpenOptionsExt;

        let temp = TempDir::new().unwrap();
        let ledger = open_at(temp.path(), 4);
        let lock_path = temp.path().join(STORE_SUBDIR).join(LOCK_FILENAME);
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
        ];

        for (index, stage) in stages.into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let ledger = open_at(temp.path(), 4);
            if stage == MeshIntentNonceCommitStage::TempCleanup {
                use std::os::unix::fs::PermissionsExt;

                let stale = temp.path().join(STORE_SUBDIR).join(TEMP_FILENAME);
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
            fs::read(temp.path().join(STORE_SUBDIR).join(LOCK_FILENAME)).unwrap(),
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
            fs::read(temp.path().join(STORE_SUBDIR).join(LOCK_FILENAME)).unwrap(),
            MARKER_CLEAN
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
}
