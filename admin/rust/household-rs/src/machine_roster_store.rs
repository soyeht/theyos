//! Durable signed-evidence store for household machine roster revocation
//! currency authority. DS-CP1: lock, codecs, strict writer, typed errors.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cbor;
use crate::error::{HouseholdError, StorageError};
use crate::household_record::HouseholdRecord;
use crate::ids::{HouseholdId, MachineId};
use crate::keys::P256PublicKey;
use crate::machine_cert::PersonId;
use crate::machine_roster_authority::{
    AcceptedRosterChainState, AdmissionContext, CanonicalCheckpoint, CheckpointAdmissionResult,
    HistoricalBridgeError, MachineCurrencyResult, MachineRosterCheckpointV1, ProjectionError,
    RosterAuthorityContext, RosterCryptoError, RosterSnapshotError, RosterSnapshotView,
    UnavailableReason, admit_checkpoint, admit_current_accepted_data, derive_machine_currency,
    derive_owner_binding_from_cert, historical_reapply_next,
};
use crate::owner_auth::{HouseholdAuthState, OwnerAuthError};

pub(crate) const MACHINE_ROSTER_SUBDIR: &str = "machine_roster";
pub(crate) const CLOCK_FLOOR_FILENAME: &str = "clock_floor_v1.cbor";
pub(crate) const ACCEPTED_CHAIN_FILENAME: &str = "accepted_chain_v1.cbor";
pub(crate) const RECORD_VERSION: u8 = 1;
pub(crate) const LOCK_TIMEOUT: Duration = Duration::from_millis(5000);
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);

// ─── IO stage / target enums (closed, exhaustive) ──────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreIoStage {
    CreateDir,
    StatDir,
    SetDirMode,
    ReadClock,
    ReadChain,
    WriteClock,
    WriteChain,
    StatTmp,
    RemoveTmp,
    OpenTmp,
    StatTmpMode,
    WritePayload,
    Flush,
    SyncTmp,
    Rename,
    OpenParent,
    SyncParent,
    Readback,
    LockCreate,
    LockStat,
    LockAcquire,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreTarget {
    ClockFloor,
    AcceptedChain,
    LockFile,
    Tmp,
}

// ─── Chain integrity errors (closed, unit-only, Copy+Eq) ───────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ChainIntegrityError {
    #[error("non-canonical record")]
    NonCanonicalRecord,
    #[error("duplicate key")]
    DuplicateKey,
    #[error("unknown field")]
    UnknownField,
    #[error("null field")]
    NullField,
    #[error("version mismatch")]
    VersionMismatch,
    #[error("household mismatch")]
    HouseholdMismatch,
    #[error("invalid state key set")]
    InvalidStateKeySet,
    #[error("checkpoint decode")]
    CheckpointDecode,
    #[error("checkpoint signature")]
    CheckpointSignature,
    #[error("owner certificate")]
    OwnerCertificate,
    #[error("owner continuity")]
    OwnerContinuity,
    #[error("sequence relation")]
    SequenceRelation,
    #[error("hash relation")]
    HashRelation,
    #[error("projection")]
    Projection,
    #[error("fork reapply mismatch")]
    ForkReapplyMismatch,
    #[error("temporal envelope")]
    Temporal,
    #[error("epoch relation")]
    EpochRelation,
}

// ─── Store errors (typed, no String catch-all) ─────────────────────────────

#[derive(Debug, Error)]
pub enum RosterStoreError {
    #[error("io at {stage:?} on {path}: {source}", path = path.display())]
    Io {
        stage: StoreIoStage,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("unsafe file type at {target:?}")]
    UnsafeFileType { target: StoreTarget },
    #[error("temp already exists (race)")]
    TempAlreadyExists,
    #[error("mode mismatch after create")]
    ModeMismatch,
    #[error("invalid path (no parent)")]
    InvalidPath,
    #[error("lock timeout")]
    LockTimeout,
    #[error("not initialized")]
    NotInitialized,
    #[error("already initialized")]
    AlreadyInitialized,
    #[error("inconsistent provisioning state")]
    InconsistentProvisioningState,
    #[error("readback mismatch")]
    ReadbackMismatch,
    #[error("latch poisoned")]
    LatchPoisoned,
    #[error(transparent)]
    Integrity(#[from] ChainIntegrityError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Household(#[from] HouseholdError),
    #[error(transparent)]
    OwnerAuth(#[from] OwnerAuthError),
    #[error("invalid current owner authority")]
    InvalidCurrentOwnerAuthority,
}

fn io_err(stage: StoreIoStage, path: &Path, source: std::io::Error) -> RosterStoreError {
    RosterStoreError::Io {
        stage,
        path: path.to_path_buf(),
        source,
    }
}

// ─── Path helpers ───────────────────────────────────────────────────────────

pub(crate) fn machine_roster_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("household").join(MACHINE_ROSTER_SUBDIR)
}

pub(crate) fn clock_floor_path(state_dir: &Path) -> PathBuf {
    machine_roster_dir(state_dir).join(CLOCK_FLOOR_FILENAME)
}

pub(crate) fn accepted_chain_path(state_dir: &Path) -> PathBuf {
    machine_roster_dir(state_dir).join(ACCEPTED_CHAIN_FILENAME)
}

pub(crate) fn lock_path(state_dir: &Path, hh_id: &HouseholdId) -> PathBuf {
    machine_roster_dir(state_dir).join(format!("roster-{}.lock", hh_id.as_str()))
}

// ─── ChainStateKind (manual serde uint 0..3) ───────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ChainStateKind {
    NoGenesis = 0,
    Accepted = 1,
    CheckpointForkConflict = 2,
    EventForkConflict = 3,
}

impl Serialize for ChainStateKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for ChainStateKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct KindVisitor;
        impl Visitor<'_> for KindVisitor {
            type Value = ChainStateKind;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an unsigned integer 0..=3")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<ChainStateKind, E> {
                match v {
                    0 => Ok(ChainStateKind::NoGenesis),
                    1 => Ok(ChainStateKind::Accepted),
                    2 => Ok(ChainStateKind::CheckpointForkConflict),
                    3 => Ok(ChainStateKind::EventForkConflict),
                    o => Err(E::invalid_value(de::Unexpected::Unsigned(o), &"0..=3")),
                }
            }
        }
        d.deserialize_u64(KindVisitor)
    }
}

// ─── ClockFloorRecordV1 (closed, canonical) ────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClockFloorRecordV1 {
    pub v: u8,
    pub hh_id: HouseholdId,
    pub floor_secs: u64,
}

// ─── AcceptedChainRecordV1 (custom visitor: duplicates/null/keysets) ───────

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcceptedChainRecordV1 {
    pub v: u8,
    pub hh_id: HouseholdId,
    pub state_kind: ChainStateKind,
    pub genesis_checkpoint: Option<Vec<u8>>,
    pub accepted_checkpoint: Option<Vec<u8>>,
    pub predecessor_checkpoint: Option<Vec<u8>>,
    pub conflicting_checkpoint: Option<Vec<u8>>,
}

impl Serialize for AcceptedChainRecordV1 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut count = 3;
        if self.genesis_checkpoint.is_some() {
            count += 1;
        }
        if self.accepted_checkpoint.is_some() {
            count += 1;
        }
        if self.predecessor_checkpoint.is_some() {
            count += 1;
        }
        if self.conflicting_checkpoint.is_some() {
            count += 1;
        }
        let mut map = s.serialize_map(Some(count))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("hh_id", &self.hh_id)?;
        map.serialize_entry("state_kind", &self.state_kind)?;
        if let Some(ref g) = self.genesis_checkpoint {
            map.serialize_entry("genesis_checkpoint", &serde_bytes::Bytes::new(g))?;
        }
        if let Some(ref a) = self.accepted_checkpoint {
            map.serialize_entry("accepted_checkpoint", &serde_bytes::Bytes::new(a))?;
        }
        if let Some(ref p) = self.predecessor_checkpoint {
            map.serialize_entry("predecessor_checkpoint", &serde_bytes::Bytes::new(p))?;
        }
        if let Some(ref c) = self.conflicting_checkpoint {
            map.serialize_entry("conflicting_checkpoint", &serde_bytes::Bytes::new(c))?;
        }
        map.end()
    }
}

struct AcceptedChainVisitor;

impl<'de> Visitor<'de> for AcceptedChainVisitor {
    type Value = AcceptedChainRecordV1;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a CBOR map for AcceptedChainRecordV1")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut v: Option<u8> = None;
        let mut hh_id: Option<HouseholdId> = None;
        let mut state_kind: Option<ChainStateKind> = None;
        let mut genesis: Option<Vec<u8>> = None;
        let mut accepted: Option<Vec<u8>> = None;
        let mut predecessor: Option<Vec<u8>> = None;
        let mut conflicting: Option<Vec<u8>> = None;

        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate key"));
            }
            match key.as_str() {
                "v" => {
                    let val: u8 = map.next_value()?;
                    v = Some(val);
                }
                "hh_id" => {
                    let val: HouseholdId = map.next_value()?;
                    hh_id = Some(val);
                }
                "state_kind" => {
                    let val: ChainStateKind = map.next_value()?;
                    state_kind = Some(val);
                }
                "genesis_checkpoint" => {
                    let val: serde_bytes::ByteBuf = map.next_value()?;
                    genesis = Some(val.into_vec());
                }
                "accepted_checkpoint" => {
                    let val: serde_bytes::ByteBuf = map.next_value()?;
                    accepted = Some(val.into_vec());
                }
                "predecessor_checkpoint" => {
                    let val: serde_bytes::ByteBuf = map.next_value()?;
                    predecessor = Some(val.into_vec());
                }
                "conflicting_checkpoint" => {
                    let val: serde_bytes::ByteBuf = map.next_value()?;
                    conflicting = Some(val.into_vec());
                }
                _ => {
                    return Err(de::Error::custom("unknown field"));
                }
            }
        }

        let v = v.ok_or_else(|| de::Error::missing_field("v"))?;
        let hh_id = hh_id.ok_or_else(|| de::Error::missing_field("hh_id"))?;
        let state_kind = state_kind.ok_or_else(|| de::Error::missing_field("state_kind"))?;

        if v != RECORD_VERSION {
            return Err(de::Error::custom("version mismatch"));
        }

        match state_kind {
            ChainStateKind::NoGenesis => {
                if genesis.is_some()
                    || accepted.is_some()
                    || predecessor.is_some()
                    || conflicting.is_some()
                {
                    return Err(de::Error::custom("invalid state key set"));
                }
            }
            ChainStateKind::Accepted => {
                let accepted_bytes = accepted
                    .as_deref()
                    .ok_or_else(|| de::Error::missing_field("accepted_checkpoint"))?;
                if genesis.is_none() {
                    return Err(de::Error::missing_field("genesis_checkpoint"));
                }
                if conflicting.is_some() {
                    return Err(de::Error::custom("invalid state key set"));
                }
                let accepted_cp: MachineRosterCheckpointV1 =
                    cbor::from_canonical_slice(accepted_bytes)
                        .map_err(|_| de::Error::custom("checkpoint decode"))?;
                let seq = accepted_cp.checkpoint_sequence;
                if seq > 1 && predecessor.is_none() {
                    return Err(de::Error::custom("invalid state key set"));
                }
                if seq == 1 && predecessor.is_some() {
                    return Err(de::Error::custom("invalid state key set"));
                }
            }
            ChainStateKind::CheckpointForkConflict => {
                let accepted_bytes = accepted
                    .as_deref()
                    .ok_or_else(|| de::Error::missing_field("accepted_checkpoint"))?;
                let conflicting_bytes = conflicting
                    .as_deref()
                    .ok_or_else(|| de::Error::missing_field("conflicting_checkpoint"))?;
                if genesis.is_none() {
                    return Err(de::Error::missing_field("genesis_checkpoint"));
                }
                let accepted_cp: MachineRosterCheckpointV1 =
                    cbor::from_canonical_slice(accepted_bytes)
                        .map_err(|_| de::Error::custom("checkpoint decode"))?;
                let conflicting_cp: MachineRosterCheckpointV1 =
                    cbor::from_canonical_slice(conflicting_bytes)
                        .map_err(|_| de::Error::custom("checkpoint decode"))?;
                if accepted_cp.checkpoint_sequence != conflicting_cp.checkpoint_sequence {
                    return Err(de::Error::custom("sequence relation"));
                }
                let seq = accepted_cp.checkpoint_sequence;
                if seq > 1 && predecessor.is_none() {
                    return Err(de::Error::custom("invalid state key set"));
                }
                if seq == 1 && predecessor.is_some() {
                    return Err(de::Error::custom("invalid state key set"));
                }
            }
            ChainStateKind::EventForkConflict => {
                let accepted_bytes = accepted
                    .as_deref()
                    .ok_or_else(|| de::Error::missing_field("accepted_checkpoint"))?;
                if genesis.is_none() || conflicting.is_none() {
                    return Err(de::Error::missing_field(
                        "genesis_checkpoint/conflicting_checkpoint",
                    ));
                }
                let accepted_cp: MachineRosterCheckpointV1 =
                    cbor::from_canonical_slice(accepted_bytes)
                        .map_err(|_| de::Error::custom("checkpoint decode"))?;
                let seq = accepted_cp.checkpoint_sequence;
                if seq > 1 && predecessor.is_none() {
                    return Err(de::Error::custom("invalid state key set"));
                }
                if seq == 1 && predecessor.is_some() {
                    return Err(de::Error::custom("invalid state key set"));
                }
            }
        }

        Ok(AcceptedChainRecordV1 {
            v,
            hh_id,
            state_kind,
            genesis_checkpoint: genesis,
            accepted_checkpoint: accepted,
            predecessor_checkpoint: predecessor,
            conflicting_checkpoint: conflicting,
        })
    }
}

impl<'de> Deserialize<'de> for AcceptedChainRecordV1 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(AcceptedChainVisitor)
    }
}

// ─── RosterLock (RAII; close-on-drop; rejects symlink/non-regular) ─────────

pub(crate) struct RosterLock {
    _file: File,
}

impl RosterLock {
    pub(crate) fn acquire(state_dir: &Path, hh_id: &HouseholdId) -> Result<Self, RosterStoreError> {
        let dir = machine_roster_dir(state_dir);
        fs::create_dir_all(&dir).map_err(|e| io_err(StoreIoStage::CreateDir, &dir, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta =
                fs::symlink_metadata(&dir).map_err(|e| io_err(StoreIoStage::StatDir, &dir, e))?;
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return Err(RosterStoreError::UnsafeFileType {
                    target: StoreTarget::LockFile,
                });
            }
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&dir, perms)
                .map_err(|e| io_err(StoreIoStage::SetDirMode, &dir, e))?;
        }

        let lp = lock_path(state_dir, hh_id);

        match fs::symlink_metadata(&lp) {
            Ok(m) => {
                if m.file_type().is_symlink() || !m.file_type().is_file() {
                    return Err(RosterStoreError::UnsafeFileType {
                        target: StoreTarget::LockFile,
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(StoreIoStage::LockStat, &lp, e)),
        }

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lp)
            .map_err(|e| io_err(StoreIoStage::LockCreate, &lp, e))?;

        let deadline = Instant::now() + LOCK_TIMEOUT;
        #[cfg(test)]
        let mut reported_blocked = false;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    #[cfg(test)]
                    {
                        if !reported_blocked {
                            if let Ok(marker_path) = std::env::var("ROSTER_BLOCKED_MARKER_PATH") {
                                let marker = PathBuf::from(&marker_path);
                                std::fs::write(&marker, "blocked")
                                    .map_err(|e| io_err(StoreIoStage::LockAcquire, &marker, e))?;
                            }
                            reported_blocked = true;
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(RosterStoreError::LockTimeout);
                    }
                    std::thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(e) => return Err(io_err(StoreIoStage::LockAcquire, &lp, e)),
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let fd_meta = file
                .metadata()
                .map_err(|e| io_err(StoreIoStage::LockStat, &lp, e))?;
            let path_meta =
                fs::symlink_metadata(&lp).map_err(|e| io_err(StoreIoStage::LockStat, &lp, e))?;
            if fd_meta.dev() != path_meta.dev() || fd_meta.ino() != path_meta.ino() {
                return Err(RosterStoreError::UnsafeFileType {
                    target: StoreTarget::LockFile,
                });
            }
            if !fd_meta.is_file() {
                return Err(RosterStoreError::UnsafeFileType {
                    target: StoreTarget::LockFile,
                });
            }
        }

        Ok(Self { _file: file })
    }
}

// ─── Strict atomic writer (create_new 0600, pre-write validation) ──────────

pub(crate) fn strict_atomic_replace(
    target: &Path,
    canonical: &[u8],
    validate: impl Fn(&[u8]) -> Result<(), RosterStoreError>,
) -> Result<(), RosterStoreError> {
    let parent = target.parent().ok_or(RosterStoreError::InvalidPath)?;
    let tmp_name = format!(
        "{}.tmp",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(RosterStoreError::InvalidPath)?
    );
    let tmp = parent.join(&tmp_name);

    match fs::symlink_metadata(&tmp) {
        Ok(m) if m.file_type().is_symlink() || !m.file_type().is_file() => {
            return Err(RosterStoreError::UnsafeFileType {
                target: StoreTarget::Tmp,
            });
        }
        Ok(_) => {
            fs::remove_file(&tmp).map_err(|e| io_err(StoreIoStage::RemoveTmp, &tmp, e))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(StoreIoStage::StatTmp, &tmp, e)),
    }

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(test)]
    if let Some(e) = check_active_fail(&tmp, FailStage::TmpOpen) {
        return Err(e);
    }
    let mut f = opts.open(&tmp).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            RosterStoreError::TempAlreadyExists
        } else {
            io_err(StoreIoStage::OpenTmp, &tmp, e)
        }
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let md = f
            .metadata()
            .map_err(|e| io_err(StoreIoStage::StatTmpMode, &tmp, e))?;
        if !md.is_file() || md.permissions().mode() & 0o777 != 0o600 {
            return Err(RosterStoreError::ModeMismatch);
        }
    }

    #[cfg(test)]
    if let Some(e) = check_active_fail(&tmp, FailStage::TmpWrite) {
        return Err(e);
    }
    f.write_all(canonical)
        .map_err(|e| io_err(StoreIoStage::WritePayload, &tmp, e))?;
    #[cfg(test)]
    if let Some(e) = check_active_fail(&tmp, FailStage::TmpFlush) {
        return Err(e);
    }
    f.flush()
        .map_err(|e| io_err(StoreIoStage::Flush, &tmp, e))?;
    #[cfg(test)]
    if let Some(e) = check_active_fail(&tmp, FailStage::TmpSync) {
        return Err(e);
    }
    f.sync_all()
        .map_err(|e| io_err(StoreIoStage::SyncTmp, &tmp, e))?;
    drop(f);

    #[cfg(test)]
    if let Some(e) = check_active_fail(target, FailStage::RenameBefore) {
        return Err(e);
    }
    fs::rename(&tmp, target).map_err(|e| io_err(StoreIoStage::Rename, target, e))?;

    #[cfg(test)]
    if let Some(e) = check_active_fail(parent, FailStage::ParentOpen) {
        return Err(e);
    }
    let dir = File::open(parent).map_err(|e| io_err(StoreIoStage::OpenParent, parent, e))?;
    #[cfg(test)]
    if let Some(e) = check_active_fail(parent, FailStage::ParentSync) {
        return Err(e);
    }
    dir.sync_all()
        .map_err(|e| io_err(StoreIoStage::SyncParent, parent, e))?;

    #[cfg(test)]
    if let Some(e) = check_active_fail(target, FailStage::Readback) {
        return Err(e);
    }
    let readback = fs::read(target).map_err(|e| io_err(StoreIoStage::Readback, target, e))?;
    if readback != canonical {
        return Err(RosterStoreError::ReadbackMismatch);
    }
    validate(&readback)?;

    Ok(())
}

// ─── Canonical decode wrappers (typed decode + re-encode + byte-compare) ───

fn pre_validate_map(
    bytes: &[u8],
    allowed: &[&str],
    required: &[&str],
) -> Result<ciborium::value::Value, ChainIntegrityError> {
    let value: ciborium::value::Value =
        ciborium::de::from_reader(bytes).map_err(|_| ChainIntegrityError::NonCanonicalRecord)?;
    let ciborium::value::Value::Map(entries) = &value else {
        return Err(ChainIntegrityError::NonCanonicalRecord);
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (key, val) in entries {
        let key_str = match key {
            ciborium::value::Value::Text(s) => s.as_str(),
            _ => return Err(ChainIntegrityError::UnknownField),
        };
        if !seen.insert(key_str.to_string()) {
            return Err(ChainIntegrityError::DuplicateKey);
        }
        if !allowed.contains(&key_str) {
            return Err(ChainIntegrityError::UnknownField);
        }
        if matches!(val, ciborium::value::Value::Null) {
            return Err(ChainIntegrityError::NullField);
        }
    }
    for req in required {
        if !seen.contains(*req) {
            return Err(ChainIntegrityError::InvalidStateKeySet);
        }
    }
    Ok(value)
}

fn extract_uint(value: &ciborium::value::Value, key: &str) -> Option<u64> {
    if let ciborium::value::Value::Map(entries) = value {
        for (k, v) in entries {
            if k == &ciborium::value::Value::Text(key.to_string()) {
                if let ciborium::value::Value::Integer(i) = v {
                    return u64::try_from(*i).ok();
                }
            }
        }
    }
    None
}

pub(crate) fn decode_clock_floor(
    bytes: &[u8],
    expected_hh_id: &HouseholdId,
) -> Result<ClockFloorRecordV1, ChainIntegrityError> {
    let allowed = ["v", "hh_id", "floor_secs"];
    let required = ["v", "hh_id", "floor_secs"];
    pre_validate_map(bytes, &allowed, &required)?;
    let rec: ClockFloorRecordV1 =
        cbor::from_canonical_slice(bytes).map_err(|_| ChainIntegrityError::NonCanonicalRecord)?;
    let re_encoded =
        cbor::to_canonical_vec(&rec).map_err(|_| ChainIntegrityError::NonCanonicalRecord)?;
    if re_encoded != bytes {
        return Err(ChainIntegrityError::NonCanonicalRecord);
    }
    if rec.v != RECORD_VERSION {
        return Err(ChainIntegrityError::VersionMismatch);
    }
    if rec.hh_id != *expected_hh_id {
        return Err(ChainIntegrityError::HouseholdMismatch);
    }
    Ok(rec)
}

pub(crate) fn decode_accepted_chain(
    bytes: &[u8],
    expected_hh_id: &HouseholdId,
) -> Result<AcceptedChainRecordV1, ChainIntegrityError> {
    let base_allowed = [
        "v",
        "hh_id",
        "state_kind",
        "genesis_checkpoint",
        "accepted_checkpoint",
        "predecessor_checkpoint",
        "conflicting_checkpoint",
    ];
    let required_base = ["v", "hh_id", "state_kind"];
    let value = pre_validate_map(bytes, &base_allowed, &required_base)?;

    let v_raw = extract_uint(&value, "v");
    if v_raw != Some(u64::from(RECORD_VERSION)) {
        return Err(ChainIntegrityError::VersionMismatch);
    }

    let kind_raw = extract_uint(&value, "state_kind");
    let kind = match kind_raw {
        Some(0) => ChainStateKind::NoGenesis,
        Some(1) => ChainStateKind::Accepted,
        Some(2) => ChainStateKind::CheckpointForkConflict,
        Some(3) => ChainStateKind::EventForkConflict,
        _ => return Err(ChainIntegrityError::InvalidStateKeySet),
    };

    let ciborium::value::Value::Map(entries) = &value else {
        return Err(ChainIntegrityError::NonCanonicalRecord);
    };
    let has = |key: &str| {
        entries
            .iter()
            .any(|(k, _)| k == &ciborium::value::Value::Text(key.to_string()))
    };
    let get_bstr = |key: &str| -> Option<&[u8]> {
        entries.iter().find_map(|(k, v)| {
            if k == &ciborium::value::Value::Text(key.to_string()) {
                if let ciborium::value::Value::Bytes(b) = v {
                    return Some(b.as_slice());
                }
            }
            None
        })
    };

    match kind {
        ChainStateKind::NoGenesis => {
            if has("genesis_checkpoint")
                || has("accepted_checkpoint")
                || has("predecessor_checkpoint")
                || has("conflicting_checkpoint")
            {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
        }
        ChainStateKind::Accepted => {
            if !has("genesis_checkpoint") || !has("accepted_checkpoint") {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
            if has("conflicting_checkpoint") {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
            let accepted_bytes =
                get_bstr("accepted_checkpoint").ok_or(ChainIntegrityError::CheckpointDecode)?;
            let accepted_cp: MachineRosterCheckpointV1 = cbor::from_canonical_slice(accepted_bytes)
                .map_err(|_| ChainIntegrityError::CheckpointDecode)?;
            let seq = accepted_cp.checkpoint_sequence;
            if seq > 1 && !has("predecessor_checkpoint") {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
            if seq == 1 && has("predecessor_checkpoint") {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
        }
        ChainStateKind::CheckpointForkConflict => {
            if !has("genesis_checkpoint")
                || !has("accepted_checkpoint")
                || !has("conflicting_checkpoint")
            {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
            let accepted_bytes =
                get_bstr("accepted_checkpoint").ok_or(ChainIntegrityError::CheckpointDecode)?;
            let conflicting_bytes =
                get_bstr("conflicting_checkpoint").ok_or(ChainIntegrityError::CheckpointDecode)?;
            let accepted_cp: MachineRosterCheckpointV1 = cbor::from_canonical_slice(accepted_bytes)
                .map_err(|_| ChainIntegrityError::CheckpointDecode)?;
            let conflicting_cp: MachineRosterCheckpointV1 =
                cbor::from_canonical_slice(conflicting_bytes)
                    .map_err(|_| ChainIntegrityError::CheckpointDecode)?;
            if accepted_cp.checkpoint_sequence != conflicting_cp.checkpoint_sequence {
                return Err(ChainIntegrityError::SequenceRelation);
            }
            let seq = accepted_cp.checkpoint_sequence;
            if seq > 1 && !has("predecessor_checkpoint") {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
            if seq == 1 && has("predecessor_checkpoint") {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
        }
        ChainStateKind::EventForkConflict => {
            if !has("genesis_checkpoint")
                || !has("accepted_checkpoint")
                || !has("conflicting_checkpoint")
            {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
            let accepted_bytes =
                get_bstr("accepted_checkpoint").ok_or(ChainIntegrityError::CheckpointDecode)?;
            let accepted_cp: MachineRosterCheckpointV1 = cbor::from_canonical_slice(accepted_bytes)
                .map_err(|_| ChainIntegrityError::CheckpointDecode)?;
            let seq = accepted_cp.checkpoint_sequence;
            if seq > 1 && !has("predecessor_checkpoint") {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
            if seq == 1 && has("predecessor_checkpoint") {
                return Err(ChainIntegrityError::InvalidStateKeySet);
            }
        }
    }

    let rec: AcceptedChainRecordV1 =
        cbor::from_canonical_slice(bytes).map_err(|_| ChainIntegrityError::CheckpointDecode)?;
    let re_encoded =
        cbor::to_canonical_vec(&rec).map_err(|_| ChainIntegrityError::NonCanonicalRecord)?;
    if re_encoded != bytes {
        return Err(ChainIntegrityError::NonCanonicalRecord);
    }
    if rec.hh_id != *expected_hh_id {
        return Err(ChainIntegrityError::HouseholdMismatch);
    }
    Ok(rec)
}

// ─── DS-CP3: Clock / Latch / Coordinator / BC2 ─────────────────────────────

pub(crate) const DURABLE_CLOCK_FUTURE_SKEW_SECS: u64 = 60;

pub(crate) trait ClockSource: Send + Sync {
    fn now_secs(&self) -> Result<u64, ClockError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClockError {
    BeforeEpoch,
    #[cfg(test)]
    Poisoned,
    #[cfg(test)]
    Exhausted,
}

struct SystemClock;
impl ClockSource for SystemClock {
    fn now_secs(&self) -> Result<u64, ClockError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| ClockError::BeforeEpoch)
    }
}

struct FloorLatch {
    last_verified: Option<u64>,
    failed_target: Option<u64>,
    failure_latched: bool,
}

impl FloorLatch {
    fn new() -> Self {
        Self {
            last_verified: None,
            failed_target: None,
            failure_latched: false,
        }
    }

    fn record_failure(&mut self, target: Option<u64>) {
        self.failure_latched = true;
        if let Some(t) = target {
            let candidates = [Some(t), self.last_verified, self.failed_target];
            self.failed_target = candidates.iter().filter_map(|c| *c).max();
        }
    }

    fn record_success(&mut self, value: u64) {
        self.last_verified = Some(value);
        self.failed_target = None;
        self.failure_latched = false;
    }
}

struct FloorUnavailable;

enum MissingFloorPolicy {
    InitializeNoGenesis,
    RejectUnavailable,
}

// ─── BC2 public enums ───────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicAdmissionOutcome {
    Accepted,
    IdempotentDuplicate,
    RejectedReplay,
    RejectedGap,
    RejectedRollback,
    RejectedMalformed,
    RejectedOwner,
    RejectedCaveat,
    RejectedSignature,
    RejectedTemporal,
    RejectedProjection,
    EpochMigrationRequired,
    CheckpointForkConflictRecorded,
    EventForkConflictRecorded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicCurrencyOutcome {
    Active {
        member: Box<crate::machine_roster_authority::MachineRosterMemberV1>,
    },
    Revoked {
        tombstone: Box<crate::machine_roster_authority::MachineRosterRevocationV1>,
    },
    NotListed,
    UnavailableNoGenesis,
    UnavailableCheckpointStale,
    UnavailableCheckpointForkConflict,
    UnavailableEventForkConflict,
    UnavailableClockState,
    UnavailableOwnerAuthority,
}

impl PublicCurrencyOutcome {
    /// Wire literal for the `outcome` field of
    /// `GET /api/v1/household/roster/currency/{m_id}`.
    ///
    /// The mapping lives beside the enum on purpose: it is the single
    /// canonical source of the currency vocabulary, so no transport or
    /// consumer re-spells these nine literals. Adding a variant without a
    /// literal is a compile error here rather than a silent wire drift.
    #[must_use]
    pub fn wire_str(&self) -> &'static str {
        match self {
            Self::Active { .. } => "active",
            Self::Revoked { .. } => "revoked",
            Self::NotListed => "not_listed",
            Self::UnavailableNoGenesis => "unavailable_no_genesis",
            Self::UnavailableCheckpointStale => "unavailable_checkpoint_stale",
            Self::UnavailableCheckpointForkConflict => "unavailable_checkpoint_fork_conflict",
            Self::UnavailableEventForkConflict => "unavailable_event_fork_conflict",
            Self::UnavailableClockState => "unavailable_clock_state",
            Self::UnavailableOwnerAuthority => "unavailable_owner_authority",
        }
    }
}

// ─── Coordinator ────────────────────────────────────────────────────────────

pub struct MachineRosterCoordinator {
    state_dir: PathBuf,
    hh_id: HouseholdId,
    hh_pub: P256PublicKey,
    owner_p_id: PersonId,
    owner_p_pub: P256PublicKey,
    owner_cert_bytes: Vec<u8>,
    owner_cert_fp: [u8; 32],
    latch: Mutex<FloorLatch>,
    clock: Arc<dyn ClockSource>,
}

/// Household-bound trusted wall-clock floor minted only while the
/// [`MachineRosterCoordinator`] holds and validates roster clock authority.
///
/// Downstream code cannot manufacture a high floor to erase nonce replay
/// history:
///
/// ```compile_fail
/// use household_rs::{ids::HouseholdId, mesh_intent_nonce_ledger::TrustedWallFloor};
/// let hh = HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap();
/// let forged = TrustedWallFloor::from_roster_observation(hh, u64::MAX);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedWallFloor {
    hh_id: HouseholdId,
    unix_seconds: u64,
}

impl TrustedWallFloor {
    fn from_roster_observation(hh_id: HouseholdId, unix_seconds: u64) -> Self {
        Self {
            hh_id,
            unix_seconds,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(hh_id: HouseholdId, unix_seconds: u64) -> Self {
        Self::from_roster_observation(hh_id, unix_seconds)
    }

    #[must_use]
    pub const fn household_id(&self) -> &HouseholdId {
        &self.hh_id
    }

    #[must_use]
    pub const fn unix_seconds(&self) -> u64 {
        self.unix_seconds
    }
}

impl MachineRosterCoordinator {
    pub fn from_validated_household(
        state_dir: &Path,
        record: &HouseholdRecord,
        auth_state: &HouseholdAuthState,
    ) -> Result<Self, RosterStoreError> {
        record.validate()?;
        auth_state.verify(record, auth_state.owner_person_cert.issued_at)?;
        let owner_cert_bytes = cbor::to_canonical_vec(&auth_state.owner_person_cert)?;
        let hh_id = record.hh_id.clone();
        let hh_pub = record.hh_pub.clone();
        let (p_id, p_pub, fp) = derive_owner_binding_from_cert(
            &owner_cert_bytes,
            &hh_id,
            &hh_pub,
            auth_state.owner_person_cert.issued_at,
        )
        .map_err(|_| RosterStoreError::InvalidCurrentOwnerAuthority)?;
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            hh_id,
            hh_pub,
            owner_p_id: p_id,
            owner_p_pub: p_pub,
            owner_cert_bytes,
            owner_cert_fp: fp,
            latch: Mutex::new(FloorLatch::new()),
            clock: Arc::new(SystemClock),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_validated_with_clock(
        state_dir: &Path,
        record: &HouseholdRecord,
        auth_state: &HouseholdAuthState,
        clock: Arc<dyn ClockSource>,
    ) -> Result<Self, RosterStoreError> {
        let mut coord = Self::from_validated_household(state_dir, record, auth_state)?;
        coord.clock = clock;
        Ok(coord)
    }

    fn current_owner_binding(
        &self,
        expected_historical_fp: Option<[u8; 32]>,
        effective_now: u64,
    ) -> Option<[u8; 32]> {
        let Ok((derived_p_id, derived_p_pub, derived_fp)) = derive_owner_binding_from_cert(
            &self.owner_cert_bytes,
            &self.hh_id,
            &self.hh_pub,
            effective_now,
        ) else {
            return None;
        };
        if derived_p_id != self.owner_p_id {
            return None;
        }
        if derived_p_pub != self.owner_p_pub {
            return None;
        }
        if derived_fp != self.owner_cert_fp {
            return None;
        }
        if let Some(hist_fp) = expected_historical_fp {
            if derived_fp != hist_fp {
                return None;
            }
        }
        Some(derived_fp)
    }

    fn observe_wall_floor(
        &self,
        lock: &RosterLock,
        latch: &mut FloorLatch,
        policy: &MissingFloorPolicy,
    ) -> Result<u64, FloorUnavailable> {
        let raw = self.clock.now_secs().map_err(|_| {
            latch.record_failure(None);
            FloorUnavailable
        })?;
        if raw == 0 {
            latch.record_failure(None);
            return Err(FloorUnavailable);
        }
        if raw.checked_add(DURABLE_CLOCK_FUTURE_SKEW_SECS).is_none() {
            latch.record_failure(Some(raw));
            return Err(FloorUnavailable);
        }
        let durable_floor = match self.read_clock_floor_inner(lock) {
            Ok(Some(rec)) => rec.floor_secs,
            Ok(None) => match policy {
                MissingFloorPolicy::InitializeNoGenesis => 0,
                MissingFloorPolicy::RejectUnavailable => {
                    latch.record_failure(Some(raw));
                    return Err(FloorUnavailable);
                }
            },
            Err(_) => {
                latch.record_failure(Some(raw));
                return Err(FloorUnavailable);
            }
        };
        if durable_floor > 0 && raw < durable_floor {
            let high = [
                Some(durable_floor),
                latch.last_verified,
                latch.failed_target,
                Some(raw),
            ]
            .iter()
            .filter_map(|c| *c)
            .max();
            latch.record_failure(high);
            return Err(FloorUnavailable);
        }
        if let Some(lv) = latch.last_verified {
            if raw < lv {
                let high = [Some(lv), latch.failed_target, Some(raw)]
                    .iter()
                    .filter_map(|c| *c)
                    .max();
                latch.record_failure(high);
                return Err(FloorUnavailable);
            }
        }
        let new_floor = [durable_floor, raw]
            .iter()
            .chain(latch.last_verified.iter())
            .chain(latch.failed_target.iter())
            .copied()
            .max()
            .unwrap_or(raw);
        let rec = ClockFloorRecordV1 {
            v: RECORD_VERSION,
            hh_id: self.hh_id.clone(),
            floor_secs: new_floor,
        };
        let canonical = cbor::to_canonical_vec(&rec).map_err(|_| {
            latch.record_failure(Some(new_floor));
            FloorUnavailable
        })?;
        let expected_rec = rec.clone();
        let floor_path = clock_floor_path(&self.state_dir);
        let hh_id = self.hh_id.clone();
        #[cfg(test)]
        let _pg = PhaseGuard::enter(FailPhase::ObserveFloor);
        strict_atomic_replace(&floor_path, &canonical, |readback| {
            let decoded = decode_clock_floor(readback, &hh_id)?;
            if decoded != expected_rec {
                return Err(RosterStoreError::ReadbackMismatch);
            }
            Ok(())
        })
        .map_err(|_| {
            latch.record_failure(Some(new_floor));
            FloorUnavailable
        })?;
        latch.record_success(new_floor);
        Ok(new_floor)
    }

    fn advance_floor_to(
        &self,
        lock: &RosterLock,
        latch: &mut FloorLatch,
        target: u64,
    ) -> Result<u64, FloorUnavailable> {
        if target == 0 {
            latch.record_failure(None);
            return Err(FloorUnavailable);
        }
        let Ok(Some(rec)) = self.read_clock_floor_inner(lock) else {
            latch.record_failure(Some(target));
            return Err(FloorUnavailable);
        };
        let current_floor = rec.floor_secs;
        let new_floor = [current_floor, target]
            .iter()
            .chain(latch.last_verified.iter())
            .chain(latch.failed_target.iter())
            .copied()
            .max()
            .unwrap_or(target);
        let floor_rec = ClockFloorRecordV1 {
            v: RECORD_VERSION,
            hh_id: self.hh_id.clone(),
            floor_secs: new_floor,
        };
        let canonical = cbor::to_canonical_vec(&floor_rec).map_err(|_| {
            latch.record_failure(Some(new_floor));
            FloorUnavailable
        })?;
        let expected_rec = floor_rec.clone();
        let floor_path = clock_floor_path(&self.state_dir);
        let hh_id = self.hh_id.clone();
        #[cfg(test)]
        let _pg = PhaseGuard::enter(FailPhase::SecondFloor);
        strict_atomic_replace(&floor_path, &canonical, |readback| {
            let decoded = decode_clock_floor(readback, &hh_id)?;
            if decoded != expected_rec {
                return Err(RosterStoreError::ReadbackMismatch);
            }
            Ok(())
        })
        .map_err(|_| {
            latch.record_failure(Some(new_floor));
            FloorUnavailable
        })?;
        latch.record_success(new_floor);
        Ok(new_floor)
    }

    fn read_clock_floor_inner(
        &self,
        _lock: &RosterLock,
    ) -> Result<Option<ClockFloorRecordV1>, RosterStoreError> {
        let path = clock_floor_path(&self.state_dir);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(StoreIoStage::ReadClock, &path, e)),
            Ok(m) if m.file_type().is_symlink() || !m.file_type().is_file() => {
                return Err(RosterStoreError::UnsafeFileType {
                    target: StoreTarget::ClockFloor,
                });
            }
            Ok(_) => {}
        }
        let bytes = fs::read(&path).map_err(|e| io_err(StoreIoStage::ReadClock, &path, e))?;
        let rec = decode_clock_floor(&bytes, &self.hh_id)?;
        if rec.floor_secs == 0 {
            return Err(RosterStoreError::Integrity(
                ChainIntegrityError::NonCanonicalRecord,
            ));
        }
        Ok(Some(rec))
    }

    fn read_chain_record_inner(
        &self,
        _lock: &RosterLock,
    ) -> Result<Option<AcceptedChainRecordV1>, RosterStoreError> {
        let path = accepted_chain_path(&self.state_dir);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(StoreIoStage::ReadChain, &path, e)),
            Ok(m) if m.file_type().is_symlink() || !m.file_type().is_file() => {
                return Err(RosterStoreError::UnsafeFileType {
                    target: StoreTarget::AcceptedChain,
                });
            }
            Ok(_) => {}
        }
        let bytes = fs::read(&path).map_err(|e| io_err(StoreIoStage::ReadChain, &path, e))?;
        let rec = decode_accepted_chain(&bytes, &self.hh_id)?;
        Ok(Some(rec))
    }

    fn commit_chain_record(
        &self,
        _lock: &RosterLock,
        record: &AcceptedChainRecordV1,
        expected_state: &AcceptedRosterChainState,
    ) -> Result<(), RosterStoreError> {
        let path = accepted_chain_path(&self.state_dir);
        let canonical = cbor::to_canonical_vec(record).map_err(RosterStoreError::Household)?;
        let hh_id = self.hh_id.clone();
        let hh_pub = self.hh_pub.clone();
        let expected = expected_state.clone();
        #[cfg(test)]
        let _pg = PhaseGuard::enter(FailPhase::ChainCommit);
        strict_atomic_replace(&path, &canonical, move |readback| {
            let decoded = decode_accepted_chain(readback, &hh_id)?;
            if decoded != *record {
                return Err(RosterStoreError::ReadbackMismatch);
            }
            if decoded.state_kind == ChainStateKind::NoGenesis {
                if !matches!(expected, AcceptedRosterChainState::NoGenesis) {
                    return Err(RosterStoreError::ReadbackMismatch);
                }
                return Ok(());
            }
            let hh_ctx = HistoricalHouseholdContext {
                hh_id: hh_id.clone(),
                hh_pub: hh_pub.clone(),
            };
            let genesis_bytes = decoded
                .genesis_checkpoint
                .as_deref()
                .ok_or(RosterStoreError::ReadbackMismatch)?;
            let accepted_bytes = decoded
                .accepted_checkpoint
                .as_deref()
                .ok_or(RosterStoreError::ReadbackMismatch)?;
            let predecessor_bytes = decoded.predecessor_checkpoint.as_deref();
            let rederived = match decoded.state_kind {
                ChainStateKind::Accepted => {
                    let (state, _) = rederive_accepted(
                        genesis_bytes,
                        accepted_bytes,
                        predecessor_bytes,
                        &hh_ctx,
                    )?;
                    state
                }
                ChainStateKind::CheckpointForkConflict | ChainStateKind::EventForkConflict => {
                    let conflicting_bytes = decoded
                        .conflicting_checkpoint
                        .as_deref()
                        .ok_or(RosterStoreError::ReadbackMismatch)?;
                    let (state, _) = rederive_fork(
                        genesis_bytes,
                        accepted_bytes,
                        predecessor_bytes,
                        conflicting_bytes,
                        decoded.state_kind,
                        &hh_ctx,
                    )?;
                    state
                }
                ChainStateKind::NoGenesis => unreachable!(),
            };
            if rederived != expected {
                return Err(RosterStoreError::ReadbackMismatch);
            }
            Ok(())
        })
    }

    pub fn provision_no_genesis(&self) -> Result<(), RosterStoreError> {
        let lock = RosterLock::acquire(&self.state_dir, &self.hh_id)?;
        let _latch = self
            .latch
            .lock()
            .map_err(|_| RosterStoreError::LatchPoisoned)?;

        let chain = self.read_chain_record_inner(&lock)?;
        if chain.is_some() {
            return Err(RosterStoreError::AlreadyInitialized);
        }
        let floor_path = clock_floor_path(&self.state_dir);
        match fs::symlink_metadata(&floor_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(StoreIoStage::ReadClock, &floor_path, e)),
            Ok(m) if m.file_type().is_symlink() || !m.file_type().is_file() => {
                return Err(RosterStoreError::InconsistentProvisioningState);
            }
            Ok(_) => return Err(RosterStoreError::InconsistentProvisioningState),
        }
        let record = AcceptedChainRecordV1 {
            v: RECORD_VERSION,
            hh_id: self.hh_id.clone(),
            state_kind: ChainStateKind::NoGenesis,
            genesis_checkpoint: None,
            accepted_checkpoint: None,
            predecessor_checkpoint: None,
            conflicting_checkpoint: None,
        };
        self.commit_chain_record(&lock, &record, &AcceptedRosterChainState::NoGenesis)
    }

    pub fn admit_checkpoint(
        &self,
        checkpoint_bytes: &[u8],
    ) -> Result<PublicAdmissionOutcome, RosterStoreError> {
        let lock = RosterLock::acquire(&self.state_dir, &self.hh_id)?;
        let mut latch = self
            .latch
            .lock()
            .map_err(|_| RosterStoreError::LatchPoisoned)?;

        let chain_rec = self
            .read_chain_record_inner(&lock)?
            .ok_or(RosterStoreError::NotInitialized)?;

        let policy = if chain_rec.state_kind == ChainStateKind::NoGenesis
            && !latch.failure_latched
            && latch.failed_target.is_none()
        {
            MissingFloorPolicy::InitializeNoGenesis
        } else {
            MissingFloorPolicy::RejectUnavailable
        };

        let floor = match self.observe_wall_floor(&lock, &mut latch, &policy) {
            Ok(f) => f,
            Err(FloorUnavailable) => return Ok(PublicAdmissionOutcome::RejectedTemporal),
        };

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: self.hh_id.clone(),
            hh_pub: self.hh_pub.clone(),
        };

        let (current_state, historical_fp) = Self::rederive_current_state(&chain_rec, &hh_ctx)?;

        let bound = self.current_owner_binding(historical_fp, floor);

        if matches!(current_state, AcceptedRosterChainState::NoGenesis) && bound.is_none() {
            return Ok(PublicAdmissionOutcome::RejectedOwner);
        }

        let Ok(candidate) = CanonicalCheckpoint::from_raw(checkpoint_bytes) else {
            return Ok(PublicAdmissionOutcome::RejectedMalformed);
        };

        let admission_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &self.hh_pub,
                expected_hh_id: &self.hh_id,
                expected_p_id: &self.owner_p_id,
                expected_p_pub: &self.owner_p_pub,
                effective_now: floor,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: bound,
        };

        let (returned_state, result) = admit_checkpoint(&candidate, &current_state, &admission_ctx);

        let is_mutating = returned_state != current_state
            && matches!(
                result,
                CheckpointAdmissionResult::Accepted
                    | CheckpointAdmissionResult::CheckpointForkConflictRecorded
                    | CheckpointAdmissionResult::EventForkConflictRecorded
            );

        if is_mutating {
            let candidate_cp = candidate.checkpoint();
            let target = floor.max(candidate_cp.issued_at);
            match self.advance_floor_to(&lock, &mut latch, target) {
                Ok(_) => {}
                Err(FloorUnavailable) => return Ok(PublicAdmissionOutcome::RejectedTemporal),
            }
            let new_record = self.build_chain_record(&chain_rec, &returned_state, checkpoint_bytes);
            self.commit_chain_record(&lock, &new_record, &returned_state)?;
        }

        Ok(map_admission_result(&result))
    }

    pub fn query_machine_currency(
        &self,
        m_id: &MachineId,
    ) -> Result<PublicCurrencyOutcome, RosterStoreError> {
        let lock = RosterLock::acquire(&self.state_dir, &self.hh_id)?;
        let mut latch = self
            .latch
            .lock()
            .map_err(|_| RosterStoreError::LatchPoisoned)?;

        let chain_rec = self
            .read_chain_record_inner(&lock)?
            .ok_or(RosterStoreError::NotInitialized)?;

        let policy = if chain_rec.state_kind == ChainStateKind::NoGenesis
            && !latch.failure_latched
            && latch.failed_target.is_none()
        {
            MissingFloorPolicy::InitializeNoGenesis
        } else {
            MissingFloorPolicy::RejectUnavailable
        };

        let floor = match self.observe_wall_floor(&lock, &mut latch, &policy) {
            Ok(f) => f,
            Err(FloorUnavailable) => return Ok(PublicCurrencyOutcome::UnavailableClockState),
        };

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: self.hh_id.clone(),
            hh_pub: self.hh_pub.clone(),
        };

        let (current_state, historical_fp) = Self::rederive_current_state(&chain_rec, &hh_ctx)?;

        let bound = self.current_owner_binding(historical_fp, floor);

        let query_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &self.hh_pub,
                expected_hh_id: &self.hh_id,
                expected_p_id: &self.owner_p_id,
                expected_p_pub: &self.owner_p_pub,
                effective_now: floor,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: bound,
        };

        let result = derive_machine_currency(&current_state, m_id, &query_ctx);
        Ok(map_currency_result(&result))
    }

    /// Projection for the B0b evidence surface.
    ///
    /// Returns the outcome plus, when that outcome is `available`, an immutable
    /// snapshot of the chain. No internal record escapes: `state_kind` crosses
    /// as `u8` so `ChainStateKind` stays private.
    ///
    /// **Not side-effect-free.** It performs no roster-chain mutation — no
    /// checkpoint is admitted, no membership changes, no chain record is
    /// written and no roster signature is minted — but it is not a read-only
    /// call either: it takes the cross-process `RosterLock` and goes through
    /// `observe_wall_floor`, which may durably persist or advance the monotonic
    /// clock floor by atomic replacement, and on a no-genesis store may create
    /// that floor record for the first time. Serving evidence is therefore an
    /// authenticated temporal-state write, not a cache read.
    ///
    /// **Chain and floor are captured under one `RosterLock` acquisition.**
    /// Captured separately they could describe different moments, and the two
    /// evidence digests would then attest a state that never existed. The lock
    /// covers that capture only — it is released when this returns, before the
    /// caller builds the body, digests it, or signs, none of which need it.
    ///
    /// `signer_m_id` exists only so this can reuse `derive_machine_currency`'s
    /// documented priority order (clock → terminal chain → owner authority →
    /// stale → per-machine). Evidence has no machine in its request, so the
    /// three per-machine results are deliberately collapsed: `Active`,
    /// `Revoked` and `NotListed` all mean "chain accepted, owner available, not
    /// stale", which is `available` with `state_kind` 1. The evidence answer is
    /// therefore independent of which machine is passed — pinned by
    /// `evidence_outcome_is_independent_of_the_machine_argument`.
    pub fn query_roster_evidence(
        &self,
        signer_m_id: &MachineId,
    ) -> Result<
        (
            crate::machine_roster_evidence::RosterEvidenceOutcome,
            Option<crate::machine_roster_evidence::RosterEvidenceSnapshot>,
        ),
        RosterStoreError,
    > {
        use crate::machine_roster_evidence::{RosterEvidenceOutcome, RosterEvidenceSnapshot};

        let lock = RosterLock::acquire(&self.state_dir, &self.hh_id)?;
        let mut latch = self
            .latch
            .lock()
            .map_err(|_| RosterStoreError::LatchPoisoned)?;

        let chain_rec = self
            .read_chain_record_inner(&lock)?
            .ok_or(RosterStoreError::NotInitialized)?;

        let policy = if chain_rec.state_kind == ChainStateKind::NoGenesis
            && !latch.failure_latched
            && latch.failed_target.is_none()
        {
            MissingFloorPolicy::InitializeNoGenesis
        } else {
            MissingFloorPolicy::RejectUnavailable
        };

        let floor = match self.observe_wall_floor(&lock, &mut latch, &policy) {
            Ok(floor) => floor,
            Err(FloorUnavailable) => {
                return Ok((RosterEvidenceOutcome::UnavailableClockState, None));
            }
        };

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: self.hh_id.clone(),
            hh_pub: self.hh_pub.clone(),
        };
        let (current_state, historical_fp) = Self::rederive_current_state(&chain_rec, &hh_ctx)?;
        let bound = self.current_owner_binding(historical_fp, floor);
        let query_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &self.hh_pub,
                expected_hh_id: &self.hh_id,
                expected_p_id: &self.owner_p_id,
                expected_p_pub: &self.owner_p_pub,
                effective_now: floor,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: bound,
        };
        let result = derive_machine_currency(&current_state, signer_m_id, &query_ctx);

        let snapshot = RosterEvidenceSnapshot {
            hh_id: chain_rec.hh_id.clone(),
            state_kind: chain_rec.state_kind as u8,
            floor_secs: floor,
            genesis_checkpoint: chain_rec.genesis_checkpoint.clone(),
            accepted_checkpoint: chain_rec.accepted_checkpoint.clone(),
            predecessor_checkpoint: chain_rec.predecessor_checkpoint.clone(),
            conflicting_checkpoint: chain_rec.conflicting_checkpoint.clone(),
        };

        // The repartition: currency calls no-genesis and both forks
        // `unavailable_*`; evidence serves them as `available` carrying
        // state_kind 0/2/3. Only clock, owner authority and staleness are
        // unavailable here.
        let outcome = match &result {
            MachineCurrencyResult::Unavailable {
                reason: UnavailableReason::ClockStateUnavailable,
            } => RosterEvidenceOutcome::UnavailableClockState,
            MachineCurrencyResult::Unavailable {
                reason: UnavailableReason::OwnerAuthorityUnavailable,
            } => RosterEvidenceOutcome::UnavailableOwnerAuthority,
            MachineCurrencyResult::Unavailable {
                reason: UnavailableReason::CheckpointStale,
            } => RosterEvidenceOutcome::UnavailableCheckpointStale,
            MachineCurrencyResult::Unavailable {
                reason:
                    UnavailableReason::NoGenesis
                    | UnavailableReason::CheckpointForkConflict
                    | UnavailableReason::EventForkConflict,
            }
            | MachineCurrencyResult::Active { .. }
            | MachineCurrencyResult::Revoked { .. }
            | MachineCurrencyResult::NotListed => RosterEvidenceOutcome::Available,
        };

        Ok(match outcome {
            RosterEvidenceOutcome::Available => (outcome, Some(snapshot)),
            _ => (outcome, None),
        })
    }

    /// D-1 (B-ROSTER-ADAPTER v2 CFX-2): the same floor/owner-authority/
    /// freshness sequence as `query_machine_currency`, stopping before the
    /// per-machine lookup via the shared `admit_current_accepted_data`
    /// helper (RED-R21 pins that the two never diverge), then projects a
    /// `RosterSnapshotView` instead of a per-machine currency result.
    pub fn current_snapshot(&self) -> Result<RosterSnapshotView, RosterSnapshotError> {
        self.current_snapshot_with_trusted_wall_floor()
            .map(|(snapshot, _floor)| snapshot)
    }

    /// Capture the accepted roster and the same durable trusted wall floor
    /// under one `RosterLock` acquisition.
    ///
    /// The opaque floor is the only production token accepted by the mesh
    /// intent nonce ledger for retention. Keeping its constructor private to
    /// this coordinator module prevents other crate code from forging a
    /// far-future floor and pruning live replay entries.
    pub fn current_snapshot_with_trusted_wall_floor(
        &self,
    ) -> Result<(RosterSnapshotView, TrustedWallFloor), RosterSnapshotError> {
        let lock = RosterLock::acquire(&self.state_dir, &self.hh_id)?;
        let mut latch = self
            .latch
            .lock()
            .map_err(|_| RosterSnapshotError::LatchPoisoned)?;

        let chain_rec = self
            .read_chain_record_inner(&lock)?
            .ok_or(RosterSnapshotError::NotInitialized)?;

        let policy = if chain_rec.state_kind == ChainStateKind::NoGenesis
            && !latch.failure_latched
            && latch.failed_target.is_none()
        {
            MissingFloorPolicy::InitializeNoGenesis
        } else {
            MissingFloorPolicy::RejectUnavailable
        };

        let floor = match self.observe_wall_floor(&lock, &mut latch, &policy) {
            Ok(f) => f,
            Err(FloorUnavailable) => return Err(RosterSnapshotError::ClockStateUnavailable),
        };

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: self.hh_id.clone(),
            hh_pub: self.hh_pub.clone(),
        };
        let (current_state, historical_fp) = Self::rederive_current_state(&chain_rec, &hh_ctx)?;
        let bound = self.current_owner_binding(historical_fp, floor);
        let query_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &self.hh_pub,
                expected_hh_id: &self.hh_id,
                expected_p_id: &self.owner_p_id,
                expected_p_pub: &self.owner_p_pub,
                effective_now: floor,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: bound,
        };

        let data = admit_current_accepted_data(&current_state, &query_ctx)?;
        Ok((
            RosterSnapshotView::project(&self.hh_id, data),
            TrustedWallFloor::from_roster_observation(self.hh_id.clone(), floor),
        ))
    }

    /// Open the unique durable mesh-intent nonce authority bound to this
    /// coordinator's validated household and state directory.
    ///
    /// Callers cannot choose either coordinate independently; doing so could
    /// split one household's replay authority across directories or use a
    /// trusted wall floor minted for a different household.
    pub fn open_mesh_intent_nonce_ledger(
        &self,
        config: crate::mesh_intent_nonce_ledger::MeshIntentNonceLedgerConfig,
    ) -> Result<
        crate::mesh_intent_nonce_ledger::MeshIntentNonceLedger,
        crate::mesh_intent_nonce_ledger::MeshIntentNonceLedgerOpenError,
    > {
        crate::mesh_intent_nonce_ledger::MeshIntentNonceLedger::open(
            &self.state_dir,
            self.hh_id.clone(),
            config,
        )
    }

    fn rederive_current_state(
        chain_rec: &AcceptedChainRecordV1,
        hh_ctx: &HistoricalHouseholdContext,
    ) -> Result<(AcceptedRosterChainState, Option<[u8; 32]>), RosterStoreError> {
        match chain_rec.state_kind {
            ChainStateKind::NoGenesis => Ok((AcceptedRosterChainState::NoGenesis, None)),
            ChainStateKind::Accepted => {
                let genesis =
                    chain_rec
                        .genesis_checkpoint
                        .as_deref()
                        .ok_or(RosterStoreError::Integrity(
                            ChainIntegrityError::CheckpointDecode,
                        ))?;
                let accepted =
                    chain_rec
                        .accepted_checkpoint
                        .as_deref()
                        .ok_or(RosterStoreError::Integrity(
                            ChainIntegrityError::CheckpointDecode,
                        ))?;
                let predecessor = chain_rec.predecessor_checkpoint.as_deref();
                let (state, binding) = rederive_accepted(genesis, accepted, predecessor, hh_ctx)
                    .map_err(RosterStoreError::Integrity)?;
                Ok((state, Some(binding.cert_fingerprint)))
            }
            ChainStateKind::CheckpointForkConflict | ChainStateKind::EventForkConflict => {
                let genesis =
                    chain_rec
                        .genesis_checkpoint
                        .as_deref()
                        .ok_or(RosterStoreError::Integrity(
                            ChainIntegrityError::CheckpointDecode,
                        ))?;
                let accepted =
                    chain_rec
                        .accepted_checkpoint
                        .as_deref()
                        .ok_or(RosterStoreError::Integrity(
                            ChainIntegrityError::CheckpointDecode,
                        ))?;
                let predecessor = chain_rec.predecessor_checkpoint.as_deref();
                let conflicting = chain_rec.conflicting_checkpoint.as_deref().ok_or(
                    RosterStoreError::Integrity(ChainIntegrityError::CheckpointDecode),
                )?;
                let (state, binding) = rederive_fork(
                    genesis,
                    accepted,
                    predecessor,
                    conflicting,
                    chain_rec.state_kind,
                    hh_ctx,
                )
                .map_err(RosterStoreError::Integrity)?;
                Ok((state, Some(binding.cert_fingerprint)))
            }
        }
    }

    fn build_chain_record(
        &self,
        old: &AcceptedChainRecordV1,
        new_state: &AcceptedRosterChainState,
        candidate_bytes: &[u8],
    ) -> AcceptedChainRecordV1 {
        match new_state {
            AcceptedRosterChainState::Accepted(_) => {
                let predecessor = old.accepted_checkpoint.clone();
                AcceptedChainRecordV1 {
                    v: RECORD_VERSION,
                    hh_id: self.hh_id.clone(),
                    state_kind: ChainStateKind::Accepted,
                    genesis_checkpoint: old.genesis_checkpoint.clone().or_else(|| {
                        if old.state_kind == ChainStateKind::NoGenesis {
                            Some(candidate_bytes.to_vec())
                        } else {
                            None
                        }
                    }),
                    accepted_checkpoint: Some(candidate_bytes.to_vec()),
                    predecessor_checkpoint: predecessor,
                    conflicting_checkpoint: None,
                }
            }
            AcceptedRosterChainState::CheckpointForkConflict { .. } => AcceptedChainRecordV1 {
                v: RECORD_VERSION,
                hh_id: self.hh_id.clone(),
                state_kind: ChainStateKind::CheckpointForkConflict,
                genesis_checkpoint: old.genesis_checkpoint.clone(),
                accepted_checkpoint: old.accepted_checkpoint.clone(),
                predecessor_checkpoint: old.predecessor_checkpoint.clone(),
                conflicting_checkpoint: Some(candidate_bytes.to_vec()),
            },
            AcceptedRosterChainState::EventForkConflict { .. } => AcceptedChainRecordV1 {
                v: RECORD_VERSION,
                hh_id: self.hh_id.clone(),
                state_kind: ChainStateKind::EventForkConflict,
                genesis_checkpoint: old.genesis_checkpoint.clone(),
                accepted_checkpoint: old.accepted_checkpoint.clone(),
                predecessor_checkpoint: old.predecessor_checkpoint.clone(),
                conflicting_checkpoint: Some(candidate_bytes.to_vec()),
            },
            AcceptedRosterChainState::NoGenesis => AcceptedChainRecordV1 {
                v: RECORD_VERSION,
                hh_id: self.hh_id.clone(),
                state_kind: ChainStateKind::NoGenesis,
                genesis_checkpoint: None,
                accepted_checkpoint: None,
                predecessor_checkpoint: None,
                conflicting_checkpoint: None,
            },
        }
    }
}

fn map_admission_result(r: &CheckpointAdmissionResult) -> PublicAdmissionOutcome {
    match r {
        CheckpointAdmissionResult::Accepted => PublicAdmissionOutcome::Accepted,
        CheckpointAdmissionResult::IdempotentDuplicate => {
            PublicAdmissionOutcome::IdempotentDuplicate
        }
        CheckpointAdmissionResult::RejectedReplay => PublicAdmissionOutcome::RejectedReplay,
        CheckpointAdmissionResult::RejectedGap => PublicAdmissionOutcome::RejectedGap,
        CheckpointAdmissionResult::RejectedRollback => PublicAdmissionOutcome::RejectedRollback,
        CheckpointAdmissionResult::RejectedMalformed => PublicAdmissionOutcome::RejectedMalformed,
        CheckpointAdmissionResult::RejectedOwner => PublicAdmissionOutcome::RejectedOwner,
        CheckpointAdmissionResult::RejectedCaveat => PublicAdmissionOutcome::RejectedCaveat,
        CheckpointAdmissionResult::RejectedSignature => PublicAdmissionOutcome::RejectedSignature,
        CheckpointAdmissionResult::RejectedTemporal => PublicAdmissionOutcome::RejectedTemporal,
        CheckpointAdmissionResult::RejectedProjection => PublicAdmissionOutcome::RejectedProjection,
        CheckpointAdmissionResult::EpochMigrationRequired => {
            PublicAdmissionOutcome::EpochMigrationRequired
        }
        CheckpointAdmissionResult::CheckpointForkConflictRecorded => {
            PublicAdmissionOutcome::CheckpointForkConflictRecorded
        }
        CheckpointAdmissionResult::EventForkConflictRecorded => {
            PublicAdmissionOutcome::EventForkConflictRecorded
        }
    }
}

fn map_currency_result(r: &MachineCurrencyResult) -> PublicCurrencyOutcome {
    match r {
        MachineCurrencyResult::Active { member } => PublicCurrencyOutcome::Active {
            member: member.clone(),
        },
        MachineCurrencyResult::Revoked { tombstone } => PublicCurrencyOutcome::Revoked {
            tombstone: tombstone.clone(),
        },
        MachineCurrencyResult::NotListed => PublicCurrencyOutcome::NotListed,
        MachineCurrencyResult::Unavailable { reason } => match reason {
            UnavailableReason::NoGenesis => PublicCurrencyOutcome::UnavailableNoGenesis,
            UnavailableReason::CheckpointStale => PublicCurrencyOutcome::UnavailableCheckpointStale,
            UnavailableReason::CheckpointForkConflict => {
                PublicCurrencyOutcome::UnavailableCheckpointForkConflict
            }
            UnavailableReason::EventForkConflict => {
                PublicCurrencyOutcome::UnavailableEventForkConflict
            }
            UnavailableReason::ClockStateUnavailable => {
                PublicCurrencyOutcome::UnavailableClockState
            }
            UnavailableReason::OwnerAuthorityUnavailable => {
                PublicCurrencyOutcome::UnavailableOwnerAuthority
            }
        },
    }
}

// ─── DS-CP4: Failure injection infrastructure (cfg(test)) ──────────────────

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum FailPhase {
    ObserveFloor,
    SecondFloor,
    ChainCommit,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailStage {
    TmpOpen,
    TmpWrite,
    TmpFlush,
    TmpSync,
    RenameBefore,
    ParentOpen,
    ParentSync,
    Readback,
}

#[cfg(test)]
struct FailPoint {
    phase: FailPhase,
    stage: FailStage,
    target_path: PathBuf,
}

#[cfg(test)]
thread_local! {
    static CURRENT_PHASE: std::cell::Cell<Option<FailPhase>> = const { std::cell::Cell::new(None) };
    static ACTIVE_FAIL: std::cell::RefCell<Option<FailPoint>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct PhaseGuard {
    previous: Option<FailPhase>,
}

#[cfg(test)]
impl PhaseGuard {
    fn enter(phase: FailPhase) -> Self {
        let previous = CURRENT_PHASE.with(|c| c.replace(Some(phase)));
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for PhaseGuard {
    fn drop(&mut self) {
        CURRENT_PHASE.with(|c| c.set(self.previous));
    }
}

#[cfg(test)]
struct FailGuard;

#[cfg(test)]
impl Drop for FailGuard {
    fn drop(&mut self) {
        ACTIVE_FAIL.with(|f| *f.borrow_mut() = None);
        CURRENT_PHASE.with(|c| c.set(None));
    }
}

#[cfg(test)]
fn install_fail(phase: FailPhase, stage: FailStage, path: PathBuf) -> FailGuard {
    ACTIVE_FAIL.with(|f| {
        *f.borrow_mut() = Some(FailPoint {
            phase,
            stage,
            target_path: path,
        })
    });
    FailGuard
}

#[cfg(test)]
fn check_active_fail(path: &Path, stage: FailStage) -> Option<RosterStoreError> {
    let current_phase = CURRENT_PHASE.with(|c| c.get());
    ACTIVE_FAIL.with(|f| {
        let mut slot = f.borrow_mut();
        if let Some(fp) = slot.as_ref() {
            if Some(fp.phase) == current_phase && fp.stage == stage && fp.target_path == path {
                let fp = slot.take().unwrap();
                return Some(stage_error(fp.stage, &fp.target_path));
            }
        }
        None
    })
}

#[cfg(test)]
fn stage_error(stage: FailStage, path: &Path) -> RosterStoreError {
    use std::io::{Error, ErrorKind};
    match stage {
        FailStage::TmpOpen => io_err(
            StoreIoStage::OpenTmp,
            path,
            Error::new(ErrorKind::PermissionDenied, "injected TmpOpen"),
        ),
        FailStage::TmpWrite => io_err(
            StoreIoStage::WritePayload,
            path,
            Error::new(ErrorKind::WriteZero, "injected TmpWrite"),
        ),
        FailStage::TmpFlush => io_err(
            StoreIoStage::Flush,
            path,
            Error::new(ErrorKind::Other, "injected TmpFlush"),
        ),
        FailStage::TmpSync => io_err(
            StoreIoStage::SyncTmp,
            path,
            Error::new(ErrorKind::Other, "injected TmpSync"),
        ),
        FailStage::RenameBefore => io_err(
            StoreIoStage::Rename,
            path,
            Error::new(ErrorKind::PermissionDenied, "injected RenameBefore"),
        ),
        FailStage::ParentOpen => io_err(
            StoreIoStage::OpenParent,
            path,
            Error::new(ErrorKind::NotFound, "injected ParentOpen"),
        ),
        FailStage::ParentSync => io_err(
            StoreIoStage::SyncParent,
            path,
            Error::new(ErrorKind::Other, "injected ParentSync"),
        ),
        FailStage::Readback => RosterStoreError::ReadbackMismatch,
    }
}

// ─── Historical types (DS-CP2) ─────────────────────────────────────────────

#[derive(Debug)]
pub(crate) struct HistoricalHouseholdContext {
    pub hh_id: HouseholdId,
    pub hh_pub: P256PublicKey,
}

#[derive(Debug)]
pub(crate) struct HistoricalOwnerBinding {
    pub p_id: PersonId,
    pub p_pub: P256PublicKey,
    pub cert_fingerprint: [u8; 32],
}

// ─── Error mappers (DS-CP2) ────────────────────────────────────────────────

fn map_crypto(e: &RosterCryptoError) -> ChainIntegrityError {
    match e {
        RosterCryptoError::CborEncode
        | RosterCryptoError::CborDecode
        | RosterCryptoError::SchemaInvalid => ChainIntegrityError::CheckpointDecode,
        RosterCryptoError::CertDecode
        | RosterCryptoError::CertNotCanonical
        | RosterCryptoError::OwnerCertInvalid
        | RosterCryptoError::WeakProvenance
        | RosterCryptoError::MissingCaveatAddMachine
        | RosterCryptoError::MissingCaveatRevoke => ChainIntegrityError::OwnerCertificate,
        RosterCryptoError::SignatureRejected => ChainIntegrityError::CheckpointSignature,
        #[cfg(test)]
        RosterCryptoError::SignFailed | RosterCryptoError::SignerPubMismatch => {
            ChainIntegrityError::CheckpointSignature
        }
        RosterCryptoError::HouseholdMismatch => ChainIntegrityError::HouseholdMismatch,
        RosterCryptoError::OwnerIdMismatch
        | RosterCryptoError::OwnerPubMismatch
        | RosterCryptoError::FingerprintMismatch => ChainIntegrityError::OwnerContinuity,
        RosterCryptoError::MachineCertInvalid
        | RosterCryptoError::MachineCertNotCanonical
        | RosterCryptoError::MachineIdMismatch
        | RosterCryptoError::MachinePubMismatch
        | RosterCryptoError::MachineFingerprintMismatch
        | RosterCryptoError::MachineHouseholdMismatch => ChainIntegrityError::Projection,
    }
}

fn map_projection(e: &ProjectionError) -> ChainIntegrityError {
    match e {
        ProjectionError::RevocationValidation(r) => admit_result_to_integrity(r),
        ProjectionError::EventHashChainBroken
        | ProjectionError::EventHeadMismatch
        | ProjectionError::EventSequenceMismatch
        | ProjectionError::OwnerFpMismatch
        | ProjectionError::RevokedNotPreviouslyActive
        | ProjectionError::RevokedTargetMismatch
        | ProjectionError::DuplicateRevocation
        | ProjectionError::ActiveSortInvalid
        | ProjectionError::ActiveDuplicateId
        | ProjectionError::ActiveDuplicatePub
        | ProjectionError::ActiveDuplicateFingerprint
        | ProjectionError::MemberProvenanceInvalid
        | ProjectionError::ProjectedMismatch => ChainIntegrityError::Projection,
    }
}

pub(crate) fn admit_result_to_integrity(r: &CheckpointAdmissionResult) -> ChainIntegrityError {
    match r {
        CheckpointAdmissionResult::RejectedMalformed => ChainIntegrityError::CheckpointDecode,
        CheckpointAdmissionResult::RejectedSignature => ChainIntegrityError::CheckpointSignature,
        CheckpointAdmissionResult::RejectedOwner => ChainIntegrityError::OwnerContinuity,
        CheckpointAdmissionResult::RejectedCaveat => ChainIntegrityError::OwnerCertificate,
        CheckpointAdmissionResult::RejectedProjection => ChainIntegrityError::Projection,
        CheckpointAdmissionResult::RejectedGap
        | CheckpointAdmissionResult::RejectedReplay
        | CheckpointAdmissionResult::RejectedRollback => ChainIntegrityError::SequenceRelation,
        CheckpointAdmissionResult::RejectedTemporal => ChainIntegrityError::Temporal,
        CheckpointAdmissionResult::EpochMigrationRequired => ChainIntegrityError::EpochRelation,
        CheckpointAdmissionResult::Accepted
        | CheckpointAdmissionResult::IdempotentDuplicate
        | CheckpointAdmissionResult::CheckpointForkConflictRecorded
        | CheckpointAdmissionResult::EventForkConflictRecorded => {
            ChainIntegrityError::ForkReapplyMismatch
        }
    }
}

fn map_bridge(e: &HistoricalBridgeError) -> ChainIntegrityError {
    match e {
        HistoricalBridgeError::Crypto(ce) => map_crypto(ce),
        HistoricalBridgeError::Projection(pe) => map_projection(pe),
        HistoricalBridgeError::Admission(r) => admit_result_to_integrity(r),
        HistoricalBridgeError::Temporal => ChainIntegrityError::Temporal,
    }
}

// ─── Historical rederive (DS-CP2) ──────────────────────────────────────────

fn hist_admission<'a>(
    hh_ctx: &'a HistoricalHouseholdContext,
    binding: &'a HistoricalOwnerBinding,
    effective_now: u64,
) -> AdmissionContext<'a> {
    AdmissionContext {
        authority: RosterAuthorityContext {
            hh_pub: &hh_ctx.hh_pub,
            expected_hh_id: &hh_ctx.hh_id,
            expected_p_id: &binding.p_id,
            expected_p_pub: &binding.p_pub,
            effective_now,
        },
        clock_available: true,
        bound_owner_cert_fingerprint: Some(binding.cert_fingerprint),
    }
}

pub(crate) fn rederive_accepted(
    genesis_bytes: &[u8],
    accepted_bytes: &[u8],
    predecessor_bytes: Option<&[u8]>,
    hh_ctx: &HistoricalHouseholdContext,
) -> Result<(AcceptedRosterChainState, HistoricalOwnerBinding), ChainIntegrityError> {
    let genesis_canonical =
        CanonicalCheckpoint::from_raw(genesis_bytes).map_err(|r| admit_result_to_integrity(&r))?;
    let genesis_cp = genesis_canonical.checkpoint();

    let (derived_p_id, derived_p_pub, derived_fp) = derive_owner_binding_from_cert(
        &genesis_cp.owner_person_cert,
        &hh_ctx.hh_id,
        &hh_ctx.hh_pub,
        genesis_cp.issued_at,
    )
    .map_err(|e| map_crypto(&e))?;

    if genesis_cp.owner_p_id != derived_p_id {
        return Err(ChainIntegrityError::OwnerContinuity);
    }
    if genesis_cp.owner_cert_fingerprint != derived_fp {
        return Err(ChainIntegrityError::OwnerContinuity);
    }

    let binding = HistoricalOwnerBinding {
        p_id: derived_p_id,
        p_pub: derived_p_pub,
        cert_fingerprint: derived_fp,
    };

    let genesis_ctx = hist_admission(hh_ctx, &binding, genesis_cp.issued_at);
    let (genesis_state, genesis_result) = admit_checkpoint(
        &genesis_canonical,
        &AcceptedRosterChainState::NoGenesis,
        &genesis_ctx,
    );
    if genesis_result != CheckpointAdmissionResult::Accepted {
        return Err(admit_result_to_integrity(&genesis_result));
    }

    let accepted_canonical =
        CanonicalCheckpoint::from_raw(accepted_bytes).map_err(|r| admit_result_to_integrity(&r))?;
    let accepted_cp = accepted_canonical.checkpoint();

    if accepted_cp.checkpoint_sequence == 1 {
        if predecessor_bytes.is_some() {
            return Err(ChainIntegrityError::InvalidStateKeySet);
        }
        if accepted_bytes != genesis_bytes {
            return Err(ChainIntegrityError::HashRelation);
        }
        return Ok((genesis_state, binding));
    }

    let pred_bytes = predecessor_bytes.ok_or(ChainIntegrityError::InvalidStateKeySet)?;
    let pred_canonical =
        CanonicalCheckpoint::from_raw(pred_bytes).map_err(|r| admit_result_to_integrity(&r))?;
    let pred_cp = pred_canonical.checkpoint();

    let expected_pred_seq = accepted_cp
        .checkpoint_sequence
        .checked_sub(1)
        .ok_or(ChainIntegrityError::SequenceRelation)?;
    if pred_cp.checkpoint_sequence != expected_pred_seq {
        return Err(ChainIntegrityError::SequenceRelation);
    }

    let AcceptedRosterChainState::Accepted(ref genesis_data) = genesis_state else {
        return Err(ChainIntegrityError::CheckpointDecode);
    };
    let genesis_basis = &genesis_data.genesis_basis;

    if pred_cp.checkpoint_sequence == 1 {
        if pred_bytes != genesis_bytes {
            return Err(ChainIntegrityError::HashRelation);
        }
        let curr_ctx = hist_admission(hh_ctx, &binding, accepted_cp.issued_at);
        crate::machine_roster_authority::verify_checkpoint_full_historical(
            accepted_cp,
            &curr_ctx.authority,
        )
        .map_err(|e| map_crypto(&e))?;
        let (final_state, result) =
            admit_checkpoint(&accepted_canonical, &genesis_state, &curr_ctx);
        if result != CheckpointAdmissionResult::Accepted {
            return Err(admit_result_to_integrity(&result));
        }
        return Ok((final_state, binding));
    }

    let pred_ctx = hist_admission(hh_ctx, &binding, pred_cp.issued_at);
    let curr_ctx = hist_admission(hh_ctx, &binding, accepted_cp.issued_at);
    let final_state = historical_reapply_next(
        &accepted_canonical,
        pred_cp,
        genesis_basis,
        &pred_ctx,
        &curr_ctx,
    )
    .map_err(|e| map_bridge(&e))?;

    Ok((final_state, binding))
}

pub(crate) fn rederive_fork(
    genesis_bytes: &[u8],
    accepted_bytes: &[u8],
    predecessor_bytes: Option<&[u8]>,
    conflicting_bytes: &[u8],
    expected_kind: ChainStateKind,
    hh_ctx: &HistoricalHouseholdContext,
) -> Result<(AcceptedRosterChainState, HistoricalOwnerBinding), ChainIntegrityError> {
    if expected_kind != ChainStateKind::CheckpointForkConflict
        && expected_kind != ChainStateKind::EventForkConflict
    {
        return Err(ChainIntegrityError::InvalidStateKeySet);
    }

    let (accepted_state, binding) =
        rederive_accepted(genesis_bytes, accepted_bytes, predecessor_bytes, hh_ctx)?;

    let conflicting_canonical = CanonicalCheckpoint::from_raw(conflicting_bytes)
        .map_err(|r| admit_result_to_integrity(&r))?;
    let conflicting_cp = conflicting_canonical.checkpoint();

    let curr_ctx = hist_admission(hh_ctx, &binding, conflicting_cp.issued_at);
    crate::machine_roster_authority::verify_checkpoint_full_historical(
        conflicting_cp,
        &curr_ctx.authority,
    )
    .map_err(|e| map_crypto(&e))?;

    let (returned_state, result) =
        admit_checkpoint(&conflicting_canonical, &accepted_state, &curr_ctx);

    match expected_kind {
        ChainStateKind::CheckpointForkConflict => {
            if result == CheckpointAdmissionResult::CheckpointForkConflictRecorded
                && matches!(
                    returned_state,
                    AcceptedRosterChainState::CheckpointForkConflict { .. }
                )
            {
                return Ok((returned_state, binding));
            }
        }
        ChainStateKind::EventForkConflict => {
            if result == CheckpointAdmissionResult::EventForkConflictRecorded
                && matches!(
                    returned_state,
                    AcceptedRosterChainState::EventForkConflict { .. }
                )
            {
                return Ok((returned_state, binding));
            }
        }
        _ => {}
    }
    Err(ChainIntegrityError::ForkReapplyMismatch)
}

// ─── Focused low-level tests ───────────────────────────────────────────────

#[cfg(test)]
mod tests;
