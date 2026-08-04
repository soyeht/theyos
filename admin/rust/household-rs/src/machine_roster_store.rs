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
    /// `GET /api/v1/household/roster/currency/{m_id}` — see
    /// `docs/household-protocol.md` §Machine Roster Currency.
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
        Ok(RosterSnapshotView::project(&self.hh_id, data))
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
mod tests {
    use super::*;
    use crate::ids::derive_household_id;
    use crate::keys::{IdentityKey as _, P256Keypair, P256Signature};
    use crate::machine_cert::PersonId;
    use crate::machine_roster_authority::{
        CHECKPOINT_KIND, CHECKPOINT_VERSION, MachineRosterCheckpointV1,
    };

    const SCALAR_A: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    fn test_hh_id() -> HouseholdId {
        let kp = P256Keypair::from_secret_scalar(&SCALAR_A).unwrap();
        derive_household_id(&kp.public())
    }

    fn test_checkpoint_bytes(seq: u64) -> Vec<u8> {
        let hh = test_hh_id();
        let cp = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: seq,
            prev_checkpoint_hash: [0xBB; 32],
            event_sequence: seq,
            event_head_hash: [0xCC; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1_700_000_000,
            not_after: 1_800_000_000,
            owner_p_id: PersonId("p_test".to_string()),
            owner_cert_fingerprint: [0xEE; 32],
            active: vec![],
            revocations: vec![],
            owner_person_cert: vec![1, 2, 3],
            signature: P256Signature([0u8; 64]),
        };
        cbor::to_canonical_vec(&cp).unwrap()
    }

    fn roundtrip_floor(rec: &ClockFloorRecordV1) -> ClockFloorRecordV1 {
        let bytes = cbor::to_canonical_vec(rec).unwrap();
        cbor::from_canonical_slice(&bytes).unwrap()
    }

    #[test]
    fn clock_floor_roundtrip() {
        let rec = ClockFloorRecordV1 {
            v: 1,
            hh_id: test_hh_id(),
            floor_secs: 1_700_000_000,
        };
        let rt = roundtrip_floor(&rec);
        assert_eq!(rt, rec);
    }

    #[test]
    fn clock_floor_rejects_unknown_field() {
        use ciborium::value::Value;
        let hh = test_hh_id();
        let map = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("hh_id".into()), Value::Text(hh.0.clone())),
            (Value::Text("floor_secs".into()), Value::Integer(100.into())),
            (Value::Text("extra".into()), Value::Integer(0.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let result: Result<ClockFloorRecordV1, _> = cbor::from_canonical_slice(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn clock_floor_rejects_wrong_version() {
        let hh = test_hh_id();
        let rec = ClockFloorRecordV1 {
            v: 1,
            hh_id: hh.clone(),
            floor_secs: 100,
        };
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let mut val: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        if let ciborium::value::Value::Map(ref mut entries) = val {
            for (k, v) in entries.iter_mut() {
                if k == &ciborium::value::Value::Text("v".into()) {
                    *v = ciborium::value::Value::Integer(99.into());
                }
            }
        }
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&val, &mut buf).unwrap();
        let result = decode_clock_floor(&buf, &hh);
        assert!(matches!(result, Err(ChainIntegrityError::VersionMismatch)));
    }

    #[test]
    fn chain_state_kind_roundtrip() {
        for (kind, expected) in [
            (ChainStateKind::NoGenesis, 0u8),
            (ChainStateKind::Accepted, 1),
            (ChainStateKind::CheckpointForkConflict, 2),
            (ChainStateKind::EventForkConflict, 3),
        ] {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&kind, &mut buf).unwrap();
            assert_eq!(buf, vec![expected]);
            let rt: ChainStateKind = ciborium::de::from_reader(buf.as_slice()).unwrap();
            assert_eq!(rt, kind);
        }
    }

    #[test]
    fn chain_state_kind_rejects_out_of_range() {
        let buf = vec![0x04u8];
        let result: Result<ChainStateKind, _> = ciborium::de::from_reader(buf.as_slice());
        assert!(result.is_err());
        let buf = vec![0x18, 0xFF];
        let result: Result<ChainStateKind, _> = ciborium::de::from_reader(buf.as_slice());
        assert!(result.is_err());
    }

    fn no_genesis_record() -> AcceptedChainRecordV1 {
        AcceptedChainRecordV1 {
            v: 1,
            hh_id: test_hh_id(),
            state_kind: ChainStateKind::NoGenesis,
            genesis_checkpoint: None,
            accepted_checkpoint: None,
            predecessor_checkpoint: None,
            conflicting_checkpoint: None,
        }
    }

    fn accepted_record_seq1() -> AcceptedChainRecordV1 {
        AcceptedChainRecordV1 {
            v: 1,
            hh_id: test_hh_id(),
            state_kind: ChainStateKind::Accepted,
            genesis_checkpoint: Some(test_checkpoint_bytes(1)),
            accepted_checkpoint: Some(test_checkpoint_bytes(1)),
            predecessor_checkpoint: None,
            conflicting_checkpoint: None,
        }
    }

    fn accepted_record_seq2() -> AcceptedChainRecordV1 {
        AcceptedChainRecordV1 {
            v: 1,
            hh_id: test_hh_id(),
            state_kind: ChainStateKind::Accepted,
            genesis_checkpoint: Some(test_checkpoint_bytes(1)),
            accepted_checkpoint: Some(test_checkpoint_bytes(2)),
            predecessor_checkpoint: Some(test_checkpoint_bytes(1)),
            conflicting_checkpoint: None,
        }
    }

    fn fork_record(kind: ChainStateKind) -> AcceptedChainRecordV1 {
        AcceptedChainRecordV1 {
            v: 1,
            hh_id: test_hh_id(),
            state_kind: kind,
            genesis_checkpoint: Some(test_checkpoint_bytes(1)),
            accepted_checkpoint: Some(test_checkpoint_bytes(2)),
            predecessor_checkpoint: Some(test_checkpoint_bytes(1)),
            conflicting_checkpoint: Some(test_checkpoint_bytes(2)),
        }
    }

    fn roundtrip_chain(rec: &AcceptedChainRecordV1) -> AcceptedChainRecordV1 {
        let bytes = cbor::to_canonical_vec(rec).unwrap();
        cbor::from_canonical_slice(&bytes).unwrap()
    }

    #[test]
    fn accepted_chain_no_genesis_roundtrip() {
        let rec = no_genesis_record();
        assert_eq!(roundtrip_chain(&rec), rec);
    }

    #[test]
    fn accepted_chain_accepted_seq1_roundtrip() {
        let rec = accepted_record_seq1();
        assert_eq!(roundtrip_chain(&rec), rec);
    }

    #[test]
    fn accepted_chain_accepted_seq2_roundtrip() {
        let rec = accepted_record_seq2();
        assert_eq!(roundtrip_chain(&rec), rec);
    }

    #[test]
    fn accepted_chain_checkpoint_fork_roundtrip() {
        let rec = fork_record(ChainStateKind::CheckpointForkConflict);
        assert_eq!(roundtrip_chain(&rec), rec);
    }

    #[test]
    fn accepted_chain_event_fork_roundtrip() {
        let rec = fork_record(ChainStateKind::EventForkConflict);
        assert_eq!(roundtrip_chain(&rec), rec);
    }

    #[test]
    fn accepted_chain_rejects_duplicate_key() {
        use ciborium::value::Value;
        let hh = test_hh_id();
        let map = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("hh_id".into()), Value::Text(hh.0.clone())),
            (Value::Text("state_kind".into()), Value::Integer(0.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = ciborium::de::from_reader(buf.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn accepted_chain_rejects_null_value() {
        use ciborium::value::Value;
        let hh = test_hh_id();
        let map = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("hh_id".into()), Value::Text(hh.0.clone())),
            (Value::Text("state_kind".into()), Value::Integer(1.into())),
            (Value::Text("genesis_checkpoint".into()), Value::Null),
            (
                Value::Text("accepted_checkpoint".into()),
                Value::Bytes(vec![1, 2]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = ciborium::de::from_reader(buf.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn accepted_chain_rejects_unknown_key() {
        use ciborium::value::Value;
        let hh = test_hh_id();
        let map = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("hh_id".into()), Value::Text(hh.0.clone())),
            (Value::Text("state_kind".into()), Value::Integer(0.into())),
            (Value::Text("bogus".into()), Value::Integer(0.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = ciborium::de::from_reader(buf.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn accepted_chain_rejects_conflicting_in_no_genesis() {
        let mut rec = no_genesis_record();
        rec.conflicting_checkpoint = Some(vec![1]);
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = cbor::from_canonical_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn accepted_chain_rejects_conflicting_in_accepted() {
        let mut rec = accepted_record_seq1();
        rec.conflicting_checkpoint = Some(test_checkpoint_bytes(1));
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = cbor::from_canonical_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn accepted_chain_rejects_missing_genesis_in_fork() {
        let mut rec = fork_record(ChainStateKind::CheckpointForkConflict);
        rec.genesis_checkpoint = None;
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = cbor::from_canonical_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn accepted_chain_rejects_wrong_version() {
        let mut rec = no_genesis_record();
        rec.v = 99;
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = cbor::from_canonical_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn accepted_chain_seq1_rejects_predecessor() {
        let mut rec = accepted_record_seq1();
        rec.predecessor_checkpoint = Some(test_checkpoint_bytes(1));
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = cbor::from_canonical_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn accepted_chain_seq2_requires_predecessor() {
        let mut rec = accepted_record_seq2();
        rec.predecessor_checkpoint = None;
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = cbor::from_canonical_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn fork_seq2_requires_predecessor() {
        let mut rec = fork_record(ChainStateKind::CheckpointForkConflict);
        rec.predecessor_checkpoint = None;
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = cbor::from_canonical_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn fork_seq1_rejects_predecessor() {
        let mut rec = fork_record(ChainStateKind::CheckpointForkConflict);
        rec.accepted_checkpoint = Some(test_checkpoint_bytes(1));
        rec.conflicting_checkpoint = Some(test_checkpoint_bytes(1));
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = cbor::from_canonical_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn checkpoint_fork_rejects_seq_mismatch() {
        let mut rec = fork_record(ChainStateKind::CheckpointForkConflict);
        rec.conflicting_checkpoint = Some(test_checkpoint_bytes(3));
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result: Result<AcceptedChainRecordV1, _> = cbor::from_canonical_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn event_fork_seq2_roundtrip() {
        let rec = fork_record(ChainStateKind::EventForkConflict);
        assert_eq!(roundtrip_chain(&rec), rec);
    }

    #[test]
    fn strict_writer_creates_0600() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test.cbor");
        let data = b"hello";
        strict_atomic_replace(&target, data, |_| Ok(())).unwrap();
        assert_eq!(fs::read(&target).unwrap(), data);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let md = fs::metadata(&target).unwrap();
            assert_eq!(md.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn strict_writer_rejects_symlink_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test.cbor");
        let tmp = dir.path().join("test.cbor.tmp");
        let link_target = dir.path().join("real_file");
        fs::write(&link_target, b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&link_target, &tmp).unwrap();
        let result = strict_atomic_replace(&target, b"data", |_| Ok(()));
        assert!(matches!(
            result,
            Err(RosterStoreError::UnsafeFileType {
                target: StoreTarget::Tmp
            })
        ));
    }

    #[test]
    fn strict_writer_rejects_nonregular_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test.cbor");
        let tmp = dir.path().join("test.cbor.tmp");
        fs::create_dir(&tmp).unwrap();
        let result = strict_atomic_replace(&target, b"data", |_| Ok(()));
        assert!(matches!(
            result,
            Err(RosterStoreError::UnsafeFileType {
                target: StoreTarget::Tmp
            })
        ));
    }

    #[test]
    fn strict_writer_removes_stale_regular_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test.cbor");
        let tmp = dir.path().join("test.cbor.tmp");
        fs::write(&tmp, b"stale").unwrap();
        strict_atomic_replace(&target, b"fresh", |_| Ok(())).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"fresh");
        assert!(!tmp.exists());
    }

    #[test]
    fn strict_writer_validator_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test.cbor");
        let result =
            strict_atomic_replace(&target, b"bad", |_| Err(RosterStoreError::ReadbackMismatch));
        assert!(matches!(result, Err(RosterStoreError::ReadbackMismatch)));
    }

    #[test]
    fn strict_writer_no_parent() {
        let result = strict_atomic_replace(Path::new(""), b"data", |_| Ok(()));
        assert!(matches!(result, Err(RosterStoreError::InvalidPath)));
    }

    #[test]
    fn roster_lock_acquire_release() {
        let dir = tempfile::tempdir().unwrap();
        let hh = test_hh_id();
        let lock = RosterLock::acquire(dir.path(), &hh).unwrap();
        drop(lock);
        let lock2 = RosterLock::acquire(dir.path(), &hh).unwrap();
        drop(lock2);
    }

    #[test]
    fn roster_lock_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let hh = test_hh_id();
        let roster_dir = machine_roster_dir(dir.path());
        fs::create_dir_all(&roster_dir).unwrap();
        let lp = lock_path(dir.path(), &hh);
        let link_target = dir.path().join("real");
        fs::write(&link_target, b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&link_target, &lp).unwrap();
        let result = RosterLock::acquire(dir.path(), &hh);
        assert!(matches!(
            result,
            Err(RosterStoreError::UnsafeFileType {
                target: StoreTarget::LockFile
            })
        ));
    }

    #[test]
    fn roster_lock_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        let hh = test_hh_id();
        let roster_dir = machine_roster_dir(dir.path());
        fs::create_dir_all(&roster_dir).unwrap();
        let lp = lock_path(dir.path(), &hh);
        fs::create_dir(&lp).unwrap();
        let result = RosterLock::acquire(dir.path(), &hh);
        assert!(matches!(
            result,
            Err(RosterStoreError::UnsafeFileType {
                target: StoreTarget::LockFile
            })
        ));
    }

    #[test]
    fn roster_lock_contention_then_release() {
        use fs2::FileExt;
        let dir = tempfile::tempdir().unwrap();
        let hh = test_hh_id();
        let roster_dir = machine_roster_dir(dir.path());
        fs::create_dir_all(&roster_dir).unwrap();
        let lp = lock_path(dir.path(), &hh);
        let blocker = File::create(&lp).unwrap();
        blocker.lock_exclusive().unwrap();

        let dir_path = dir.path().to_path_buf();
        let hh_clone = hh.clone();
        let handle = std::thread::spawn(move || RosterLock::acquire(&dir_path, &hh_clone));

        std::thread::sleep(Duration::from_millis(100));
        drop(blocker);

        let result = handle.join().unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn path_helpers_correct() {
        let state = Path::new("/tmp/state");
        let hh = test_hh_id();
        assert_eq!(
            machine_roster_dir(state),
            PathBuf::from("/tmp/state/household/machine_roster")
        );
        assert_eq!(
            clock_floor_path(state),
            PathBuf::from("/tmp/state/household/machine_roster/clock_floor_v1.cbor")
        );
        assert_eq!(
            accepted_chain_path(state),
            PathBuf::from("/tmp/state/household/machine_roster/accepted_chain_v1.cbor")
        );
        assert_eq!(
            lock_path(state, &hh),
            PathBuf::from(format!(
                "/tmp/state/household/machine_roster/roster-{}.lock",
                hh.as_str()
            ))
        );
    }

    #[test]
    fn chain_integrity_error_is_copy_eq() {
        let a = ChainIntegrityError::DuplicateKey;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn roster_store_error_from_integrity() {
        let e: RosterStoreError = ChainIntegrityError::OwnerContinuity.into();
        assert!(matches!(
            e,
            RosterStoreError::Integrity(ChainIntegrityError::OwnerContinuity)
        ));
    }

    #[test]
    fn decode_clock_floor_valid() {
        let hh = test_hh_id();
        let rec = ClockFloorRecordV1 {
            v: 1,
            hh_id: hh.clone(),
            floor_secs: 1_700_000_000,
        };
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let decoded = decode_clock_floor(&bytes, &hh).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn decode_clock_floor_rejects_non_canonical() {
        let hh = test_hh_id();
        let rec = ClockFloorRecordV1 {
            v: 1,
            hh_id: hh.clone(),
            floor_secs: 100,
        };
        let mut bytes = cbor::to_canonical_vec(&rec).unwrap();
        bytes.push(0x00);
        let result = decode_clock_floor(&bytes, &hh);
        assert!(matches!(
            result,
            Err(ChainIntegrityError::NonCanonicalRecord)
        ));
    }

    #[test]
    fn decode_clock_floor_rejects_version() {
        let hh = test_hh_id();
        let rec = ClockFloorRecordV1 {
            v: 1,
            hh_id: hh.clone(),
            floor_secs: 100,
        };
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let mut val: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        if let ciborium::value::Value::Map(ref mut entries) = val {
            for (k, v) in entries.iter_mut() {
                if k == &ciborium::value::Value::Text("v".into()) {
                    *v = ciborium::value::Value::Integer(99.into());
                }
            }
        }
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&val, &mut buf).unwrap();
        let result = decode_clock_floor(&buf, &hh);
        assert!(matches!(result, Err(ChainIntegrityError::VersionMismatch)));
    }

    #[test]
    fn decode_clock_floor_rejects_hh_mismatch() {
        let hh = test_hh_id();
        let rec = ClockFloorRecordV1 {
            v: 1,
            hh_id: hh.clone(),
            floor_secs: 100,
        };
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let other = HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap();
        let result = decode_clock_floor(&bytes, &other);
        assert!(matches!(
            result,
            Err(ChainIntegrityError::HouseholdMismatch)
        ));
    }

    #[test]
    fn decode_accepted_chain_valid() {
        let hh = test_hh_id();
        let rec = accepted_record_seq1();
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let decoded = decode_accepted_chain(&bytes, &hh).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn decode_accepted_chain_rejects_non_canonical() {
        let hh = test_hh_id();
        let rec = accepted_record_seq1();
        let mut bytes = cbor::to_canonical_vec(&rec).unwrap();
        bytes.push(0x00);
        let result = decode_accepted_chain(&bytes, &hh);
        assert!(matches!(
            result,
            Err(ChainIntegrityError::NonCanonicalRecord)
        ));
    }

    #[test]
    fn decode_accepted_chain_rejects_hh_mismatch() {
        let rec = accepted_record_seq1();
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let other = HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap();
        let result = decode_accepted_chain(&bytes, &other);
        assert!(matches!(
            result,
            Err(ChainIntegrityError::HouseholdMismatch)
        ));
    }

    #[test]
    fn decode_accepted_chain_rejects_duplicate_key() {
        use ciborium::value::Value;
        let hh = test_hh_id();
        let map = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("hh_id".into()), Value::Text(hh.0.clone())),
            (Value::Text("state_kind".into()), Value::Integer(0.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let result = decode_accepted_chain(&buf, &hh);
        assert!(matches!(result, Err(ChainIntegrityError::DuplicateKey)));
    }

    #[test]
    fn decode_accepted_chain_rejects_null_field() {
        use ciborium::value::Value;
        let hh = test_hh_id();
        let map = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("hh_id".into()), Value::Text(hh.0.clone())),
            (Value::Text("state_kind".into()), Value::Integer(0.into())),
            (Value::Text("genesis_checkpoint".into()), Value::Null),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let result = decode_accepted_chain(&buf, &hh);
        assert!(matches!(result, Err(ChainIntegrityError::NullField)));
    }

    #[test]
    fn decode_accepted_chain_rejects_unknown_field() {
        use ciborium::value::Value;
        let hh = test_hh_id();
        let map = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("hh_id".into()), Value::Text(hh.0.clone())),
            (Value::Text("state_kind".into()), Value::Integer(0.into())),
            (Value::Text("bogus".into()), Value::Integer(0.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let result = decode_accepted_chain(&buf, &hh);
        assert!(matches!(result, Err(ChainIntegrityError::UnknownField)));
    }

    #[test]
    fn decode_accepted_chain_rejects_invalid_keyset() {
        use ciborium::value::Value;
        let hh = test_hh_id();
        let map = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("hh_id".into()), Value::Text(hh.0.clone())),
            (Value::Text("state_kind".into()), Value::Integer(0.into())),
            (
                Value::Text("genesis_checkpoint".into()),
                Value::Bytes(vec![1]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let result = decode_accepted_chain(&buf, &hh);
        assert!(matches!(
            result,
            Err(ChainIntegrityError::InvalidStateKeySet)
        ));
    }

    #[test]
    fn decode_clock_floor_rejects_duplicate_key() {
        use ciborium::value::Value;
        let hh = test_hh_id();
        let map = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("hh_id".into()), Value::Text(hh.0.clone())),
            (Value::Text("floor_secs".into()), Value::Integer(100.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        let result = decode_clock_floor(&buf, &hh);
        assert!(matches!(result, Err(ChainIntegrityError::DuplicateKey)));
    }

    #[test]
    fn decode_accepted_chain_rejects_version() {
        let hh = test_hh_id();
        let mut rec = accepted_record_seq1();
        rec.v = 99;
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result = decode_accepted_chain(&bytes, &hh);
        assert!(matches!(result, Err(ChainIntegrityError::VersionMismatch)));
    }

    #[test]
    fn decode_accepted_chain_seq2_missing_predecessor() {
        let hh = test_hh_id();
        let mut rec = accepted_record_seq2();
        rec.predecessor_checkpoint = None;
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result = decode_accepted_chain(&bytes, &hh);
        assert!(matches!(
            result,
            Err(ChainIntegrityError::InvalidStateKeySet)
        ));
    }

    #[test]
    fn decode_accepted_chain_seq1_extra_predecessor() {
        let hh = test_hh_id();
        let mut rec = accepted_record_seq1();
        rec.predecessor_checkpoint = Some(test_checkpoint_bytes(1));
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result = decode_accepted_chain(&bytes, &hh);
        assert!(matches!(
            result,
            Err(ChainIntegrityError::InvalidStateKeySet)
        ));
    }

    #[test]
    fn decode_accepted_chain_fork_seq_mismatch() {
        let hh = test_hh_id();
        let mut rec = fork_record(ChainStateKind::CheckpointForkConflict);
        rec.conflicting_checkpoint = Some(test_checkpoint_bytes(3));
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result = decode_accepted_chain(&bytes, &hh);
        assert!(matches!(result, Err(ChainIntegrityError::SequenceRelation)));
    }

    #[test]
    fn decode_accepted_chain_event_fork_seq2_missing_predecessor() {
        let hh = test_hh_id();
        let mut rec = fork_record(ChainStateKind::EventForkConflict);
        rec.predecessor_checkpoint = None;
        let bytes = cbor::to_canonical_vec(&rec).unwrap();
        let result = decode_accepted_chain(&bytes, &hh);
        assert!(matches!(
            result,
            Err(ChainIntegrityError::InvalidStateKeySet)
        ));
    }

    #[test]
    fn roster_lock_rejects_symlink_dir() {
        let dir = tempfile::tempdir().unwrap();
        let hh = test_hh_id();
        let real_dir = dir.path().join("real_roster");
        fs::create_dir(&real_dir).unwrap();
        let roster_dir = machine_roster_dir(dir.path());
        if let Some(parent) = roster_dir.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_dir, &roster_dir).unwrap();
        let result = RosterLock::acquire(dir.path(), &hh);
        assert!(matches!(
            result,
            Err(RosterStoreError::UnsafeFileType {
                target: StoreTarget::LockFile
            })
        ));
    }

    // ─── DS-CP2 restart evidence tests ─────────────────────────────────────

    const SCALAR_ROOT: [u8; 32] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const SCALAR_OWNER: [u8; 32] = [
        2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    struct FullRig {
        hh_ctx: HistoricalHouseholdContext,
        owner_kp: P256Keypair,
        cert_bytes: Vec<u8>,
        fp: [u8; 32],
        p_id: PersonId,
        owner_pub: P256PublicKey,
        genesis_bytes: Vec<u8>,
        genesis_hash: [u8; 32],
    }

    fn make_full_rig() -> FullRig {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);

        let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
            &root_kp,
            crate::person_cert::SignOwnerOptions {
                hh_id: hh_id.clone(),
                p_pub: owner_pub.clone(),
                display_name: "Owner".into(),
                issued_at: 500,
            },
            crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
        )
        .unwrap();
        cert.nonce = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        let sb = cert.signing_bytes().unwrap();
        cert.signature = root_kp.sign(&sb).unwrap();
        let cert_bytes = crate::cbor::to_canonical_vec(&cert).unwrap();
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(&cert).unwrap();

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &owner_kp, &cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
        let genesis_hash = crate::machine_roster_authority::checkpoint_hash(&genesis).unwrap();

        FullRig {
            hh_ctx: HistoricalHouseholdContext {
                hh_id,
                hh_pub: root_pub,
            },
            owner_kp,
            cert_bytes,
            fp,
            p_id,
            owner_pub,
            genesis_bytes,
            genesis_hash,
        }
    }

    fn sign_seq(rig: &FullRig, seq: u64, prev_hash: [u8; 32], issued_at: u64) -> Vec<u8> {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let mut cp = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: seq,
            prev_checkpoint_hash: prev_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at,
            not_after: issued_at + 200,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &rig.hh_ctx.hh_pub,
            expected_hh_id: &rig.hh_ctx.hh_id,
            expected_p_id: &rig.p_id,
            expected_p_pub: &rig.owner_pub,
            effective_now: issued_at,
        };
        sign_checkpoint(&mut cp, &rig.owner_kp, &rig.cert_bytes, &ctx).unwrap();
        crate::cbor::to_canonical_vec(&cp).unwrap()
    }

    fn cp_hash(bytes: &[u8]) -> [u8; 32] {
        let cp: MachineRosterCheckpointV1 = crate::cbor::from_canonical_slice(bytes).unwrap();
        crate::machine_roster_authority::checkpoint_hash(&cp).unwrap()
    }

    #[test]
    fn rederive_accepted_seq1() {
        let rig = make_full_rig();
        let (state, binding) =
            rederive_accepted(&rig.genesis_bytes, &rig.genesis_bytes, None, &rig.hh_ctx).unwrap();
        assert!(matches!(state, AcceptedRosterChainState::Accepted(_)));
        assert_eq!(binding.cert_fingerprint, rig.fp);
    }

    #[test]
    fn rederive_accepted_seq1_rejects_predecessor_some() {
        let rig = make_full_rig();
        let result = rederive_accepted(
            &rig.genesis_bytes,
            &rig.genesis_bytes,
            Some(&rig.genesis_bytes),
            &rig.hh_ctx,
        );
        assert!(matches!(
            result,
            Err(ChainIntegrityError::InvalidStateKeySet)
        ));
    }

    #[test]
    fn rederive_accepted_seq1_rejects_different_valid_genesis() {
        let rig = make_full_rig();
        let other = sign_seq(&rig, 1, [0u8; 32], 1050);
        let result = rederive_accepted(&rig.genesis_bytes, &other, None, &rig.hh_ctx);
        assert!(matches!(result, Err(ChainIntegrityError::HashRelation)));
    }

    #[test]
    fn rederive_accepted_seq2() {
        let rig = make_full_rig();
        let seq2 = sign_seq(&rig, 2, rig.genesis_hash, 1100);
        let (state, _) = rederive_accepted(
            &rig.genesis_bytes,
            &seq2,
            Some(&rig.genesis_bytes),
            &rig.hh_ctx,
        )
        .unwrap();
        assert!(matches!(state, AcceptedRosterChainState::Accepted(_)));
    }

    #[test]
    fn rederive_accepted_seq2_missing_predecessor() {
        let rig = make_full_rig();
        let seq2 = sign_seq(&rig, 2, rig.genesis_hash, 1100);
        let result = rederive_accepted(&rig.genesis_bytes, &seq2, None, &rig.hh_ctx);
        assert!(matches!(
            result,
            Err(ChainIntegrityError::InvalidStateKeySet)
        ));
    }

    #[test]
    fn rederive_accepted_seq3_immediate_predecessor() {
        let rig = make_full_rig();
        let seq2 = sign_seq(&rig, 2, rig.genesis_hash, 1100);
        let seq2_hash = cp_hash(&seq2);
        let seq3 = sign_seq(&rig, 3, seq2_hash, 1200);
        let (state, _) =
            rederive_accepted(&rig.genesis_bytes, &seq3, Some(&seq2), &rig.hh_ctx).unwrap();
        assert!(matches!(state, AcceptedRosterChainState::Accepted(_)));
    }

    #[test]
    fn rederive_accepted_seq4_immediate_predecessor() {
        let rig = make_full_rig();
        let seq2 = sign_seq(&rig, 2, rig.genesis_hash, 1100);
        let seq2_hash = cp_hash(&seq2);
        let seq3 = sign_seq(&rig, 3, seq2_hash, 1200);
        let seq3_hash = cp_hash(&seq3);
        let seq4 = sign_seq(&rig, 4, seq3_hash, 1300);
        let (state, _) =
            rederive_accepted(&rig.genesis_bytes, &seq4, Some(&seq3), &rig.hh_ctx).unwrap();
        assert!(matches!(state, AcceptedRosterChainState::Accepted(_)));
    }

    #[test]
    fn rederive_accepted_predecessor_seq_mismatch() {
        let rig = make_full_rig();
        let seq2 = sign_seq(&rig, 2, rig.genesis_hash, 1100);
        let seq2_hash = cp_hash(&seq2);
        let seq3 = sign_seq(&rig, 3, seq2_hash, 1200);
        let result = rederive_accepted(
            &rig.genesis_bytes,
            &seq3,
            Some(&rig.genesis_bytes),
            &rig.hh_ctx,
        );
        assert!(matches!(result, Err(ChainIntegrityError::SequenceRelation)));
    }

    #[test]
    fn rederive_fork_kind2_same_seq() {
        let rig = make_full_rig();
        let conflicting = sign_seq(&rig, 1, [0u8; 32], 1050);
        let result = rederive_fork(
            &rig.genesis_bytes,
            &rig.genesis_bytes,
            None,
            &conflicting,
            ChainStateKind::CheckpointForkConflict,
            &rig.hh_ctx,
        );
        assert!(matches!(
            result,
            Ok((AcceptedRosterChainState::CheckpointForkConflict { .. }, _))
        ));
    }

    #[test]
    fn rederive_fork_rejects_no_genesis_kind() {
        let rig = make_full_rig();
        let result = rederive_fork(
            &rig.genesis_bytes,
            &rig.genesis_bytes,
            None,
            &rig.genesis_bytes,
            ChainStateKind::NoGenesis,
            &rig.hh_ctx,
        );
        assert!(matches!(
            result,
            Err(ChainIntegrityError::InvalidStateKeySet)
        ));
    }

    #[test]
    fn rederive_fork_rejects_accepted_kind() {
        let rig = make_full_rig();
        let result = rederive_fork(
            &rig.genesis_bytes,
            &rig.genesis_bytes,
            None,
            &rig.genesis_bytes,
            ChainStateKind::Accepted,
            &rig.hh_ctx,
        );
        assert!(matches!(
            result,
            Err(ChainIntegrityError::InvalidStateKeySet)
        ));
    }

    #[test]
    fn map_crypto_exhaustive_signer_pub() {
        let e = RosterCryptoError::SignerPubMismatch;
        assert!(matches!(
            map_crypto(&e),
            ChainIntegrityError::CheckpointSignature
        ));
    }

    #[test]
    fn map_crypto_household() {
        let e = RosterCryptoError::HouseholdMismatch;
        assert!(matches!(
            map_crypto(&e),
            ChainIntegrityError::HouseholdMismatch
        ));
    }

    #[test]
    fn admit_result_temporal() {
        let r = CheckpointAdmissionResult::RejectedTemporal;
        assert!(matches!(
            admit_result_to_integrity(&r),
            ChainIntegrityError::Temporal
        ));
    }

    #[test]
    fn admit_result_epoch() {
        let r = CheckpointAdmissionResult::EpochMigrationRequired;
        assert!(matches!(
            admit_result_to_integrity(&r),
            ChainIntegrityError::EpochRelation
        ));
    }

    #[test]
    fn map_projection_revocation_validation_preserved() {
        let pe = ProjectionError::RevocationValidation(CheckpointAdmissionResult::RejectedCaveat);
        assert!(matches!(
            map_projection(&pe),
            ChainIntegrityError::OwnerCertificate
        ));
    }

    #[test]
    fn map_projection_member_provenance() {
        let pe = ProjectionError::MemberProvenanceInvalid;
        assert!(matches!(
            map_projection(&pe),
            ChainIntegrityError::Projection
        ));
    }

    #[test]
    fn rederive_accepted_historical_time_split() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);

        let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
            &root_kp,
            crate::person_cert::SignOwnerOptions {
                hh_id: hh_id.clone(),
                p_pub: owner_pub.clone(),
                display_name: "Owner".into(),
                issued_at: 500,
            },
            crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
        )
        .unwrap();
        cert.not_after = Some(1150);
        cert.nonce = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        let sb = cert.signing_bytes().unwrap();
        cert.signature = root_kp.sign(&sb).unwrap();
        let cert_bytes = crate::cbor::to_canonical_vec(&cert).unwrap();
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(&cert).unwrap();

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &owner_kp, &cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();

        let hh_ctx = HistoricalHouseholdContext {
            hh_id,
            hh_pub: root_pub,
        };
        let (state, _) = rederive_accepted(&genesis_bytes, &genesis_bytes, None, &hh_ctx).unwrap();
        assert!(matches!(state, AcceptedRosterChainState::Accepted(_)));
    }

    #[test]
    fn rederive_fork_kind3_event_fork() {
        use crate::machine_roster_authority::{
            RosterAuthorityContext, revocation_event_hash, sign_checkpoint, sign_revocation,
        };
        let rig = make_full_rig();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let m_kp = P256Keypair::from_secret_scalar(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();
        let m_pub = m_kp.public();
        let m_id = crate::ids::derive_machine_id(&m_pub);
        let m_cert = crate::machine_cert::MachineCert::sign(
            &root_kp,
            &m_pub,
            &crate::machine_cert::SignOptions {
                hh_id: rig.hh_ctx.hh_id.clone(),
                hostname: "test".into(),
                platform: crate::machine_cert::Platform::Macos,
                joined_at: 500,
            },
        )
        .unwrap();
        let m_cert_bytes = crate::cbor::to_canonical_vec(&m_cert).unwrap();
        let m_fp = crate::machine_roster_authority::machine_cert_fingerprint(&m_cert).unwrap();

        let member = crate::machine_roster_authority::MachineRosterMemberV1 {
            m_id: m_id.clone(),
            m_pub: m_pub.clone(),
            machine_cert: m_cert_bytes,
            machine_cert_fingerprint: m_fp,
        };

        let mut genesis_with_member = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![member.clone()],
            revocations: vec![],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &rig.hh_ctx.hh_pub,
            expected_hh_id: &rig.hh_ctx.hh_id,
            expected_p_id: &rig.p_id,
            expected_p_pub: &rig.owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(
            &mut genesis_with_member,
            &rig.owner_kp,
            &rig.cert_bytes,
            &ctx,
        )
        .unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis_with_member).unwrap();
        let genesis_hash =
            crate::machine_roster_authority::checkpoint_hash(&genesis_with_member).unwrap();

        let mut rev = crate::machine_roster_authority::MachineRosterRevocationV1 {
            v: crate::machine_roster_authority::REVOCATION_VERSION,
            kind: crate::machine_roster_authority::REVOCATION_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            sequence: 1,
            prev_event_hash: [0u8; 32],
            m_id: m_id.clone(),
            m_pub: m_pub.clone(),
            machine_cert_fingerprint: m_fp,
            revoked_at: 1050,
            reason: crate::machine_roster_authority::RevocationReason::OwnerAction,
            cascade: crate::machine_roster_authority::RevocationCascade::MachineOnly,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        sign_revocation(&mut rev, &rig.owner_kp, &rig.cert_bytes, &ctx).unwrap();
        let event_head = revocation_event_hash(&rev).unwrap();

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 1,
            event_head_hash: event_head,
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![],
            revocations: vec![rev.clone()],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx2 = RosterAuthorityContext {
            hh_pub: &rig.hh_ctx.hh_pub,
            expected_hh_id: &rig.hh_ctx.hh_id,
            expected_p_id: &rig.p_id,
            expected_p_pub: &rig.owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &rig.owner_kp, &rig.cert_bytes, &ctx2).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();
        let seq2_hash = crate::machine_roster_authority::checkpoint_hash(&seq2).unwrap();

        let mut rev2 = rev.clone();
        rev2.revoked_at = 1060;
        sign_revocation(&mut rev2, &rig.owner_kp, &rig.cert_bytes, &ctx2).unwrap();
        let event_head2 = revocation_event_hash(&rev2).unwrap();

        let mut conflicting = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 3,
            prev_checkpoint_hash: seq2_hash,
            event_sequence: 1,
            event_head_hash: event_head2,
            mesh_log_digest: [0xDD; 32],
            issued_at: 1150,
            not_after: 1350,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![],
            revocations: vec![rev2],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        sign_checkpoint(&mut conflicting, &rig.owner_kp, &rig.cert_bytes, &ctx2).unwrap();
        let conflicting_bytes = crate::cbor::to_canonical_vec(&conflicting).unwrap();

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: rig.hh_ctx.hh_id.clone(),
            hh_pub: rig.hh_ctx.hh_pub.clone(),
        };
        let result = rederive_fork(
            &genesis_bytes,
            &seq2_bytes,
            Some(&genesis_bytes),
            &conflicting_bytes,
            ChainStateKind::EventForkConflict,
            &hh_ctx,
        );
        match result {
            Ok((
                AcceptedRosterChainState::EventForkConflict {
                    sequence, hashes, ..
                },
                _,
            )) => {
                assert_eq!(sequence, 1);
                assert_eq!(hashes, vec![event_head, event_head2]);
            }
            other => panic!("expected EventForkConflict, got {other:?}"),
        }
    }

    #[test]
    fn rederive_accepted_epoch_mismatch_exact() {
        let rig = make_full_rig();
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let mut cp = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xBB; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: rig.genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &rig.hh_ctx.hh_pub,
            expected_hh_id: &rig.hh_ctx.hh_id,
            expected_p_id: &rig.p_id,
            expected_p_pub: &rig.owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut cp, &rig.owner_kp, &rig.cert_bytes, &ctx).unwrap();
        let bad_epoch_bytes = crate::cbor::to_canonical_vec(&cp).unwrap();
        let result = rederive_accepted(
            &rig.genesis_bytes,
            &bad_epoch_bytes,
            Some(&rig.genesis_bytes),
            &rig.hh_ctx,
        );
        assert!(matches!(result, Err(ChainIntegrityError::EpochRelation)));
    }

    #[test]
    fn guard_pred_effective_now_mismatch() {
        let rig = make_full_rig();
        let seq2 = sign_seq(&rig, 2, rig.genesis_hash, 1100);
        let genesis_canonical = CanonicalCheckpoint::from_raw(&rig.genesis_bytes).unwrap();
        let genesis_cp = genesis_canonical.checkpoint();
        let binding = HistoricalOwnerBinding {
            p_id: rig.p_id.clone(),
            p_pub: rig.owner_pub.clone(),
            cert_fingerprint: rig.fp,
        };
        let pred_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 9999,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(rig.fp),
        };
        let curr_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 1100,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(rig.fp),
        };
        let seq2_canonical = CanonicalCheckpoint::from_raw(&seq2).unwrap();
        let genesis_data_cp: MachineRosterCheckpointV1 =
            crate::cbor::from_canonical_slice(&rig.genesis_bytes).unwrap();
        let basis = crate::machine_roster_authority::VerifiedGenesisRoster {
            epoch: genesis_data_cp.epoch,
            members: genesis_data_cp.active.clone(),
        };
        let result = crate::machine_roster_authority::historical_reapply_next(
            &seq2_canonical,
            genesis_cp,
            &basis,
            &pred_ctx,
            &curr_ctx,
        );
        assert!(matches!(result, Err(HistoricalBridgeError::Temporal)));
    }

    #[test]
    fn guard_curr_effective_now_mismatch() {
        let rig = make_full_rig();
        let seq2 = sign_seq(&rig, 2, rig.genesis_hash, 1100);
        let genesis_canonical = CanonicalCheckpoint::from_raw(&rig.genesis_bytes).unwrap();
        let genesis_cp = genesis_canonical.checkpoint();
        let binding = HistoricalOwnerBinding {
            p_id: rig.p_id.clone(),
            p_pub: rig.owner_pub.clone(),
            cert_fingerprint: rig.fp,
        };
        let pred_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 1000,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(rig.fp),
        };
        let curr_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 8888,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(rig.fp),
        };
        let seq2_canonical = CanonicalCheckpoint::from_raw(&seq2).unwrap();
        let basis = crate::machine_roster_authority::VerifiedGenesisRoster {
            epoch: genesis_cp.epoch,
            members: genesis_cp.active.clone(),
        };
        let result = crate::machine_roster_authority::historical_reapply_next(
            &seq2_canonical,
            genesis_cp,
            &basis,
            &pred_ctx,
            &curr_ctx,
        );
        assert!(matches!(result, Err(HistoricalBridgeError::Temporal)));
    }

    #[test]
    fn guard_hh_pub_mismatch() {
        let rig = make_full_rig();
        let seq2 = sign_seq(&rig, 2, rig.genesis_hash, 1100);
        let genesis_canonical = CanonicalCheckpoint::from_raw(&rig.genesis_bytes).unwrap();
        let genesis_cp = genesis_canonical.checkpoint();
        let other_pub = P256Keypair::from_secret_scalar(&[
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap()
        .public();
        let binding = HistoricalOwnerBinding {
            p_id: rig.p_id.clone(),
            p_pub: rig.owner_pub.clone(),
            cert_fingerprint: rig.fp,
        };
        let pred_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &other_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 1000,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(rig.fp),
        };
        let curr_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 1100,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(rig.fp),
        };
        let seq2_canonical = CanonicalCheckpoint::from_raw(&seq2).unwrap();
        let basis = crate::machine_roster_authority::VerifiedGenesisRoster {
            epoch: genesis_cp.epoch,
            members: genesis_cp.active.clone(),
        };
        let result = crate::machine_roster_authority::historical_reapply_next(
            &seq2_canonical,
            genesis_cp,
            &basis,
            &pred_ctx,
            &curr_ctx,
        );
        assert!(matches!(
            result,
            Err(HistoricalBridgeError::Crypto(
                RosterCryptoError::HouseholdMismatch
            ))
        ));
    }

    #[test]
    fn guard_bound_fp_none() {
        let rig = make_full_rig();
        let seq2 = sign_seq(&rig, 2, rig.genesis_hash, 1100);
        let genesis_canonical = CanonicalCheckpoint::from_raw(&rig.genesis_bytes).unwrap();
        let genesis_cp = genesis_canonical.checkpoint();
        let binding = HistoricalOwnerBinding {
            p_id: rig.p_id.clone(),
            p_pub: rig.owner_pub.clone(),
            cert_fingerprint: rig.fp,
        };
        let pred_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 1000,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: None,
        };
        let curr_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 1100,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(rig.fp),
        };
        let seq2_canonical = CanonicalCheckpoint::from_raw(&seq2).unwrap();
        let basis = crate::machine_roster_authority::VerifiedGenesisRoster {
            epoch: genesis_cp.epoch,
            members: genesis_cp.active.clone(),
        };
        let result = crate::machine_roster_authority::historical_reapply_next(
            &seq2_canonical,
            genesis_cp,
            &basis,
            &pred_ctx,
            &curr_ctx,
        );
        assert!(matches!(
            result,
            Err(HistoricalBridgeError::Crypto(
                RosterCryptoError::FingerprintMismatch
            ))
        ));
    }

    #[test]
    fn guard_checkpoint_claim_fp_mismatch() {
        let rig = make_full_rig();
        let seq2 = sign_seq(&rig, 2, rig.genesis_hash, 1100);
        let genesis_canonical = CanonicalCheckpoint::from_raw(&rig.genesis_bytes).unwrap();
        let genesis_cp = genesis_canonical.checkpoint();
        let wrong_fp = [0xFFu8; 32];
        let binding = HistoricalOwnerBinding {
            p_id: rig.p_id.clone(),
            p_pub: rig.owner_pub.clone(),
            cert_fingerprint: wrong_fp,
        };
        let pred_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 1000,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(wrong_fp),
        };
        let curr_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 1100,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(wrong_fp),
        };
        let seq2_canonical = CanonicalCheckpoint::from_raw(&seq2).unwrap();
        let basis = crate::machine_roster_authority::VerifiedGenesisRoster {
            epoch: genesis_cp.epoch,
            members: genesis_cp.active.clone(),
        };
        let result = crate::machine_roster_authority::historical_reapply_next(
            &seq2_canonical,
            genesis_cp,
            &basis,
            &pred_ctx,
            &curr_ctx,
        );
        assert!(matches!(
            result,
            Err(HistoricalBridgeError::Crypto(
                RosterCryptoError::FingerprintMismatch
            ))
        ));
    }

    #[test]
    fn guard_checked_add_overflow() {
        let rig = make_full_rig();
        let overflow_issued = u64::MAX - 10;
        let pred_cp = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: rig.genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: overflow_issued,
            not_after: u64::MAX,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let genesis_canonical = CanonicalCheckpoint::from_raw(&rig.genesis_bytes).unwrap();
        let genesis_cp = genesis_canonical.checkpoint();
        let binding = HistoricalOwnerBinding {
            p_id: rig.p_id.clone(),
            p_pub: rig.owner_pub.clone(),
            cert_fingerprint: rig.fp,
        };
        let pred_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: overflow_issued,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(rig.fp),
        };
        let curr_ctx = AdmissionContext {
            authority: RosterAuthorityContext {
                hh_pub: &rig.hh_ctx.hh_pub,
                expected_hh_id: &rig.hh_ctx.hh_id,
                expected_p_id: &binding.p_id,
                expected_p_pub: &binding.p_pub,
                effective_now: 1100,
            },
            clock_available: true,
            bound_owner_cert_fingerprint: Some(rig.fp),
        };
        let seq2 = sign_seq(&rig, 3, rig.genesis_hash, 1100);
        let seq2_canonical = CanonicalCheckpoint::from_raw(&seq2).unwrap();
        let basis = crate::machine_roster_authority::VerifiedGenesisRoster {
            epoch: genesis_cp.epoch,
            members: genesis_cp.active.clone(),
        };
        let result = crate::machine_roster_authority::historical_reapply_next(
            &seq2_canonical,
            &pred_cp,
            &basis,
            &pred_ctx,
            &curr_ctx,
        );
        assert!(matches!(result, Err(HistoricalBridgeError::Temporal)));
    }

    #[test]
    fn rederive_bridge_revocation_weak_provenance() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let rig = make_full_rig();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);

        let mut weak_cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
            &root_kp,
            crate::person_cert::SignOwnerOptions {
                hh_id: hh_id.clone(),
                p_pub: owner_pub.clone(),
                display_name: "Owner".into(),
                issued_at: 500,
            },
            crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
        )
        .unwrap();
        weak_cert.owner_auth_tier = None;
        weak_cert.owner_provenance = None;
        weak_cert.nonce = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        let sb = weak_cert.signing_bytes().unwrap();
        weak_cert.signature = root_kp.sign(&sb).unwrap();
        let weak_cert_bytes = crate::cbor::to_canonical_vec(&weak_cert).unwrap();
        let weak_fp = crate::machine_roster_authority::owner_cert_fingerprint(&weak_cert).unwrap();

        let m_kp = P256Keypair::from_secret_scalar(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();
        let m_pub = m_kp.public();
        let m_id = crate::ids::derive_machine_id(&m_pub);
        let m_cert = crate::machine_cert::MachineCert::sign(
            &root_kp,
            &m_pub,
            &crate::machine_cert::SignOptions {
                hh_id: hh_id.clone(),
                hostname: "test".into(),
                platform: crate::machine_cert::Platform::Macos,
                joined_at: 500,
            },
        )
        .unwrap();
        let m_cert_bytes = crate::cbor::to_canonical_vec(&m_cert).unwrap();
        let m_fp = crate::machine_roster_authority::machine_cert_fingerprint(&m_cert).unwrap();
        let member = crate::machine_roster_authority::MachineRosterMemberV1 {
            m_id: m_id.clone(),
            m_pub: m_pub.clone(),
            machine_cert: m_cert_bytes,
            machine_cert_fingerprint: m_fp,
        };

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![member],
            revocations: vec![],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &rig.p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &rig.owner_kp, &rig.cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
        let genesis_hash = crate::machine_roster_authority::checkpoint_hash(&genesis).unwrap();

        let mut weak_rev = crate::machine_roster_authority::MachineRosterRevocationV1 {
            v: crate::machine_roster_authority::REVOCATION_VERSION,
            kind: crate::machine_roster_authority::REVOCATION_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            sequence: 1,
            prev_event_hash: [0u8; 32],
            m_id,
            m_pub,
            machine_cert_fingerprint: m_fp,
            revoked_at: 1050,
            reason: crate::machine_roster_authority::RevocationReason::OwnerAction,
            cascade: crate::machine_roster_authority::RevocationCascade::MachineOnly,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: weak_fp,
            owner_person_cert: weak_cert_bytes,
            signature: P256Signature([0u8; 64]),
        };
        let rev_preimage = crate::machine_roster_authority::revocation_preimage(&weak_rev).unwrap();
        weak_rev.signature = owner_kp.sign(&rev_preimage).unwrap();

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 1,
            event_head_hash: [0xCC; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![],
            revocations: vec![weak_rev],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx2 = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &rig.p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &rig.owner_kp, &rig.cert_bytes, &ctx2).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let hh_ctx = HistoricalHouseholdContext {
            hh_id,
            hh_pub: root_pub,
        };
        let result = rederive_accepted(&genesis_bytes, &seq2_bytes, Some(&genesis_bytes), &hh_ctx);
        assert!(matches!(result, Err(ChainIntegrityError::OwnerCertificate)));
    }

    #[test]
    fn historical_time_split_cert_fails_later() {
        use crate::machine_roster_authority::derive_owner_binding_from_cert;
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);

        let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
            &root_kp,
            crate::person_cert::SignOwnerOptions {
                hh_id: hh_id.clone(),
                p_pub: owner_pub.clone(),
                display_name: "Owner".into(),
                issued_at: 500,
            },
            crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
        )
        .unwrap();
        cert.not_after = Some(1150);
        cert.nonce = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        let sb = cert.signing_bytes().unwrap();
        cert.signature = root_kp.sign(&sb).unwrap();
        let cert_bytes = crate::cbor::to_canonical_vec(&cert).unwrap();

        let at_1000 = derive_owner_binding_from_cert(&cert_bytes, &hh_id, &root_pub, 1000);
        assert!(at_1000.is_ok());

        let at_1200 = derive_owner_binding_from_cert(&cert_bytes, &hh_id, &root_pub, 1200);
        assert!(at_1200.is_err());
    }

    #[test]
    fn rederive_accepted_kind1_with_revocation_exact() {
        use crate::machine_roster_authority::{
            RosterAuthorityContext, revocation_event_hash, sign_checkpoint, sign_revocation,
        };
        let rig = make_full_rig();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let m_kp = P256Keypair::from_secret_scalar(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();
        let m_pub = m_kp.public();
        let m_id = crate::ids::derive_machine_id(&m_pub);
        let m_cert = crate::machine_cert::MachineCert::sign(
            &root_kp,
            &m_pub,
            &crate::machine_cert::SignOptions {
                hh_id: rig.hh_ctx.hh_id.clone(),
                hostname: "test".into(),
                platform: crate::machine_cert::Platform::Macos,
                joined_at: 500,
            },
        )
        .unwrap();
        let m_cert_bytes = crate::cbor::to_canonical_vec(&m_cert).unwrap();
        let m_fp = crate::machine_roster_authority::machine_cert_fingerprint(&m_cert).unwrap();
        let member = crate::machine_roster_authority::MachineRosterMemberV1 {
            m_id: m_id.clone(),
            m_pub: m_pub.clone(),
            machine_cert: m_cert_bytes,
            machine_cert_fingerprint: m_fp,
        };

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![member.clone()],
            revocations: vec![],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &rig.hh_ctx.hh_pub,
            expected_hh_id: &rig.hh_ctx.hh_id,
            expected_p_id: &rig.p_id,
            expected_p_pub: &rig.owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &rig.owner_kp, &rig.cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
        let genesis_hash = crate::machine_roster_authority::checkpoint_hash(&genesis).unwrap();

        let mut rev = crate::machine_roster_authority::MachineRosterRevocationV1 {
            v: crate::machine_roster_authority::REVOCATION_VERSION,
            kind: crate::machine_roster_authority::REVOCATION_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            sequence: 1,
            prev_event_hash: [0u8; 32],
            m_id: m_id.clone(),
            m_pub: m_pub.clone(),
            machine_cert_fingerprint: m_fp,
            revoked_at: 1050,
            reason: crate::machine_roster_authority::RevocationReason::OwnerAction,
            cascade: crate::machine_roster_authority::RevocationCascade::MachineOnly,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        sign_revocation(&mut rev, &rig.owner_kp, &rig.cert_bytes, &ctx).unwrap();
        let event_head = revocation_event_hash(&rev).unwrap();

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 1,
            event_head_hash: event_head,
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![],
            revocations: vec![rev.clone()],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx2 = RosterAuthorityContext {
            hh_pub: &rig.hh_ctx.hh_pub,
            expected_hh_id: &rig.hh_ctx.hh_id,
            expected_p_id: &rig.p_id,
            expected_p_pub: &rig.owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &rig.owner_kp, &rig.cert_bytes, &ctx2).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let (state, binding) = rederive_accepted(
            &genesis_bytes,
            &seq2_bytes,
            Some(&genesis_bytes),
            &rig.hh_ctx,
        )
        .unwrap();
        assert_eq!(binding.cert_fingerprint, rig.fp);
        let AcceptedRosterChainState::Accepted(data) = state else {
            panic!("expected Accepted");
        };
        assert_eq!(data.epoch, [0xAA; 32]);
        assert_eq!(data.checkpoint_sequence, 2);
        assert_eq!(data.prev_checkpoint_hash, genesis_hash);
        assert_eq!(data.event_sequence, 1);
        assert_eq!(data.event_head_hash, event_head);
        assert_eq!(data.predecessor_event_sequence, 0);
        assert_eq!(data.predecessor_event_head_hash, [0u8; 32]);
        assert_eq!(data.owner_cert_fingerprint, rig.fp);
        assert_eq!(data.genesis_basis.epoch, [0xAA; 32]);
        assert_eq!(data.genesis_basis.members, vec![member]);
        assert_eq!(data.active, vec![]);
        assert_eq!(data.tombstones, vec![rev]);
    }

    #[test]
    fn rederive_fork_kind2_exact_fields() {
        let rig = make_full_rig();
        let conflicting = sign_seq(&rig, 1, [0u8; 32], 1050);
        let result = rederive_fork(
            &rig.genesis_bytes,
            &rig.genesis_bytes,
            None,
            &conflicting,
            ChainStateKind::CheckpointForkConflict,
            &rig.hh_ctx,
        );
        let (state, _) = result.unwrap();
        let AcceptedRosterChainState::CheckpointForkConflict {
            epoch,
            sequence,
            hashes,
        } = state
        else {
            panic!("expected CheckpointForkConflict");
        };
        assert_eq!(epoch, [0xAA; 32]);
        assert_eq!(sequence, 1);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], rig.genesis_hash);
        let conflicting_cp: MachineRosterCheckpointV1 =
            crate::cbor::from_canonical_slice(&conflicting).unwrap();
        let conflicting_hash =
            crate::machine_roster_authority::checkpoint_hash(&conflicting_cp).unwrap();
        assert_eq!(hashes[1], conflicting_hash);
    }

    #[test]
    fn rederive_bridge_revocation_bad_signature() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let rig = make_full_rig();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let m_kp = P256Keypair::from_secret_scalar(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();
        let m_pub = m_kp.public();
        let m_id = crate::ids::derive_machine_id(&m_pub);
        let m_cert = crate::machine_cert::MachineCert::sign(
            &root_kp,
            &m_pub,
            &crate::machine_cert::SignOptions {
                hh_id: rig.hh_ctx.hh_id.clone(),
                hostname: "test".into(),
                platform: crate::machine_cert::Platform::Macos,
                joined_at: 500,
            },
        )
        .unwrap();
        let m_cert_bytes = crate::cbor::to_canonical_vec(&m_cert).unwrap();
        let m_fp = crate::machine_roster_authority::machine_cert_fingerprint(&m_cert).unwrap();
        let member = crate::machine_roster_authority::MachineRosterMemberV1 {
            m_id: m_id.clone(),
            m_pub: m_pub.clone(),
            machine_cert: m_cert_bytes,
            machine_cert_fingerprint: m_fp,
        };

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![member],
            revocations: vec![],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &rig.hh_ctx.hh_pub,
            expected_hh_id: &rig.hh_ctx.hh_id,
            expected_p_id: &rig.p_id,
            expected_p_pub: &rig.owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &rig.owner_kp, &rig.cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
        let genesis_hash = crate::machine_roster_authority::checkpoint_hash(&genesis).unwrap();

        let bad_rev = crate::machine_roster_authority::MachineRosterRevocationV1 {
            v: crate::machine_roster_authority::REVOCATION_VERSION,
            kind: crate::machine_roster_authority::REVOCATION_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            sequence: 1,
            prev_event_hash: [0u8; 32],
            m_id,
            m_pub,
            machine_cert_fingerprint: m_fp,
            revoked_at: 1050,
            reason: crate::machine_roster_authority::RevocationReason::OwnerAction,
            cascade: crate::machine_roster_authority::RevocationCascade::MachineOnly,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0xAB; 64]),
        };

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: rig.hh_ctx.hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 1,
            event_head_hash: [0xCC; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: rig.p_id.clone(),
            owner_cert_fingerprint: rig.fp,
            active: vec![],
            revocations: vec![bad_rev],
            owner_person_cert: rig.cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx2 = RosterAuthorityContext {
            hh_pub: &rig.hh_ctx.hh_pub,
            expected_hh_id: &rig.hh_ctx.hh_id,
            expected_p_id: &rig.p_id,
            expected_p_pub: &rig.owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &rig.owner_kp, &rig.cert_bytes, &ctx2).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let result = rederive_accepted(
            &genesis_bytes,
            &seq2_bytes,
            Some(&genesis_bytes),
            &rig.hh_ctx,
        );
        assert!(matches!(
            result,
            Err(ChainIntegrityError::CheckpointSignature)
        ));
    }

    // ─── DS-CP3 coordinator/latch/floor/provision tests ────────────────────

    #[cfg(test)]
    struct TestClock {
        queue: std::sync::Mutex<std::collections::VecDeque<Result<u64, ClockError>>>,
    }

    #[cfg(test)]
    impl TestClock {
        fn new(results: Vec<Result<u64, ClockError>>) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                queue: std::sync::Mutex::new(results.into()),
            })
        }
    }

    #[cfg(test)]
    impl ClockSource for TestClock {
        fn now_secs(&self) -> Result<u64, ClockError> {
            let mut q = self.queue.lock().map_err(|_| ClockError::Poisoned)?;
            q.pop_front().ok_or(ClockError::Exhausted)?
        }
    }

    struct CoordRig {
        coord: MachineRosterCoordinator,
        genesis_bytes: Vec<u8>,
    }

    fn make_coord_rig_at(state_dir: &Path, clock: std::sync::Arc<dyn ClockSource>) -> CoordRig {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let m_id = crate::ids::derive_machine_id(&owner_pub);

        let record = HouseholdRecord {
            version: 1,
            hh_id: hh_id.clone(),
            hh_pub: root_pub.clone(),
            name: "test-household".to_string(),
            created_at: 500,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![m_id],
            is_follower: false,
        };

        let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
            &root_kp,
            crate::person_cert::SignOwnerOptions {
                hh_id: hh_id.clone(),
                p_pub: owner_pub.clone(),
                display_name: "Owner".into(),
                issued_at: 500,
            },
            crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
        )
        .unwrap();
        cert.nonce = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        let sb = cert.signing_bytes().unwrap();
        cert.signature = root_kp.sign(&sb).unwrap();
        let cert_bytes = crate::cbor::to_canonical_vec(&cert).unwrap();
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(&cert).unwrap();

        let auth_state = HouseholdAuthState::new(&record, cert);

        let coord = MachineRosterCoordinator::from_validated_with_clock(
            state_dir,
            &record,
            &auth_state,
            clock,
        )
        .unwrap();

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: crate::person_cert::derive_person_id(&owner_pub),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &crate::person_cert::derive_person_id(&owner_pub),
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &owner_kp, &cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();

        CoordRig {
            coord,
            genesis_bytes,
        }
    }

    fn make_coord_rig(clock: std::sync::Arc<dyn ClockSource>) -> (CoordRig, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let rig = make_coord_rig_at(dir.path(), clock);
        (rig, dir)
    }

    #[test]
    fn coord_provision_no_genesis() {
        let clock = TestClock::new(vec![]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let result = rig.coord.provision_no_genesis();
        assert!(matches!(result, Err(RosterStoreError::AlreadyInitialized)));
    }

    #[test]
    fn coord_provision_inconsistent_floor_only() {
        let clock = TestClock::new(vec![]);
        let (rig, dir) = make_coord_rig(clock);
        let floor_path = clock_floor_path(dir.path());
        std::fs::create_dir_all(floor_path.parent().unwrap()).unwrap();
        std::fs::write(&floor_path, b"junk").unwrap();
        let result = rig.coord.provision_no_genesis();
        assert!(matches!(
            result,
            Err(RosterStoreError::InconsistentProvisioningState)
        ));
    }

    #[test]
    fn coord_admit_not_initialized() {
        let clock = TestClock::new(vec![Ok(1000)]);
        let (rig, _dir) = make_coord_rig(clock);
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes);
        assert!(matches!(result, Err(RosterStoreError::NotInitialized)));
    }

    #[test]
    fn coord_admit_genesis_accepted() {
        let clock = TestClock::new(vec![Ok(1000)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::Accepted);
    }

    #[test]
    fn coord_admit_genesis_idempotent() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1000)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let r1 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r1, PublicAdmissionOutcome::Accepted);
        let r2 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r2, PublicAdmissionOutcome::IdempotentDuplicate);
    }

    #[test]
    fn coord_floor_rollback_rejected() {
        let clock = TestClock::new(vec![Ok(1000), Ok(900)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let r1 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r1, PublicAdmissionOutcome::Accepted);
        let r2 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r2, PublicAdmissionOutcome::RejectedTemporal);
    }

    #[test]
    fn coord_query_no_genesis_unavailable() {
        let clock = TestClock::new(vec![Ok(1000)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let m_id = crate::ids::derive_machine_id(
            &P256Keypair::from_secret_scalar(&SCALAR_OWNER)
                .unwrap()
                .public(),
        );
        let result = rig.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(result, PublicCurrencyOutcome::UnavailableNoGenesis);
    }

    #[test]
    fn coord_query_accepted_not_listed() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1000)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let m_id = crate::ids::derive_machine_id(
            &P256Keypair::from_secret_scalar(&SCALAR_OWNER)
                .unwrap()
                .public(),
        );
        let result = rig.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(result, PublicCurrencyOutcome::NotListed);
    }

    /// The evidence answer must not vary with the machine id passed in.
    ///
    /// `query_roster_evidence` borrows `derive_machine_currency` only for its
    /// priority order; the three per-machine results collapse to `available`.
    /// The collapse is what this pins, so the two ids must be ones the currency
    /// surface genuinely separates — `make_coord_rig`'s genesis lists nobody, so
    /// reusing it would compare two `NotListed` ids and pass for the wrong
    /// reason. Hence the member-bearing genesis and the currency cross-check
    /// below: that assertion is the control proving the ids differ as inputs.
    #[test]
    fn evidence_outcome_is_independent_of_the_machine_argument() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        use crate::machine_roster_evidence::RosterEvidenceOutcome;

        // provision(0) + admit(1) + currency(2) + evidence(3). An under-budget
        // clock exhausts into `UnavailableClockState`, which fails the
        // `Available` assertions loudly rather than passing vacuously.
        let clock = TestClock::new(vec![Ok(1000); 6]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();

        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let cert_bytes = rig.coord.owner_cert_bytes.clone();
        let fp = rig.coord.owner_cert_fp;

        let member_kp = P256Keypair::from_secret_scalar(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();
        let member_pub = member_kp.public();
        let member_m_id = crate::ids::derive_machine_id(&member_pub);
        let member_cert = crate::machine_cert::MachineCert::sign(
            &root_kp,
            &member_pub,
            &crate::machine_cert::SignOptions {
                hh_id: hh_id.clone(),
                hostname: "listed-member".into(),
                platform: crate::machine_cert::Platform::Macos,
                joined_at: 500,
            },
        )
        .unwrap();
        let member = crate::machine_roster_authority::MachineRosterMemberV1 {
            m_id: member_m_id.clone(),
            m_pub: member_pub.clone(),
            machine_cert: crate::cbor::to_canonical_vec(&member_cert).unwrap(),
            machine_cert_fingerprint: crate::machine_roster_authority::machine_cert_fingerprint(
                &member_cert,
            )
            .unwrap(),
        };

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: crate::person_cert::derive_person_id(&owner_pub),
            owner_cert_fingerprint: fp,
            active: vec![member],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &crate::person_cert::derive_person_id(&owner_pub),
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &owner_kp, &cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
        assert_eq!(
            rig.coord.admit_checkpoint(&genesis_bytes).unwrap(),
            PublicAdmissionOutcome::Accepted
        );

        let stranger_m_id = crate::ids::derive_machine_id(
            &P256Keypair::from_secret_scalar(&[
                4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])
            .unwrap()
            .public(),
        );
        assert_ne!(member_m_id, stranger_m_id);

        // CONTROL — the currency surface separates these two ids. Without this
        // the equality below would hold for two identical inputs.
        assert!(matches!(
            rig.coord.query_machine_currency(&member_m_id).unwrap(),
            PublicCurrencyOutcome::Active { .. }
        ));
        assert_eq!(
            rig.coord.query_machine_currency(&stranger_m_id).unwrap(),
            PublicCurrencyOutcome::NotListed
        );

        // ...and evidence collapses them onto one outcome and one snapshot.
        let (listed_outcome, listed_snapshot) =
            rig.coord.query_roster_evidence(&member_m_id).unwrap();
        let (stranger_outcome, stranger_snapshot) =
            rig.coord.query_roster_evidence(&stranger_m_id).unwrap();
        let (owner_outcome, owner_snapshot) = rig
            .coord
            .query_roster_evidence(&crate::ids::derive_machine_id(&owner_pub))
            .unwrap();

        assert_eq!(listed_outcome, RosterEvidenceOutcome::Available);
        assert_eq!(listed_outcome, stranger_outcome);
        assert_eq!(listed_outcome, owner_outcome);
        assert_eq!(listed_snapshot, stranger_snapshot);
        assert_eq!(listed_snapshot, owner_snapshot);
        assert_eq!(
            listed_snapshot
                .as_ref()
                .expect("available carries a body")
                .state_kind,
            1,
            "an accepted chain is state_kind 1 regardless of the machine asked about"
        );
    }

    /// D-1 (B-ROSTER-ADAPTER v2 CFX-1/CFX-2), POS-R8/RED-R17: an accepted,
    /// fresh, owner-available chain projects a `RosterSnapshotView` whose
    /// `checkpoint_event_head` is exactly the genesis checkpoint's
    /// `event_head_hash`, and whose `lookup_active`/`is_revoked` reflect the
    /// same membership `query_machine_currency` sees for the same machine.
    #[test]
    fn current_snapshot_reflects_active_member_with_exact_checkpoint_event_head() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};

        let clock = TestClock::new(vec![Ok(1000); 4]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();

        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let cert_bytes = rig.coord.owner_cert_bytes.clone();
        let fp = rig.coord.owner_cert_fp;

        let member_kp = P256Keypair::from_secret_scalar(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();
        let member_pub = member_kp.public();
        let member_m_id = crate::ids::derive_machine_id(&member_pub);
        let member_cert = crate::machine_cert::MachineCert::sign(
            &root_kp,
            &member_pub,
            &crate::machine_cert::SignOptions {
                hh_id: hh_id.clone(),
                hostname: "listed-member".into(),
                platform: crate::machine_cert::Platform::Macos,
                joined_at: 500,
            },
        )
        .unwrap();
        let member = crate::machine_roster_authority::MachineRosterMemberV1 {
            m_id: member_m_id.clone(),
            m_pub: member_pub.clone(),
            machine_cert: crate::cbor::to_canonical_vec(&member_cert).unwrap(),
            machine_cert_fingerprint: crate::machine_roster_authority::machine_cert_fingerprint(
                &member_cert,
            )
            .unwrap(),
        };

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: crate::person_cert::derive_person_id(&owner_pub),
            owner_cert_fingerprint: fp,
            active: vec![member],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &crate::person_cert::derive_person_id(&owner_pub),
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &owner_kp, &cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
        assert_eq!(
            rig.coord.admit_checkpoint(&genesis_bytes).unwrap(),
            PublicAdmissionOutcome::Accepted
        );

        let stranger_m_id = crate::ids::derive_machine_id(
            &P256Keypair::from_secret_scalar(&[
                4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])
            .unwrap()
            .public(),
        );

        // RED-R21 control: current_snapshot and query_machine_currency must
        // not diverge on the same chain state — both see the member Active.
        assert!(matches!(
            rig.coord.query_machine_currency(&member_m_id).unwrap(),
            PublicCurrencyOutcome::Active { .. }
        ));

        let view = rig
            .coord
            .current_snapshot()
            .expect("accepted, fresh, owner available");
        assert_eq!(view.hh_id(), &hh_id);
        assert_eq!(view.checkpoint_sequence(), 1);
        assert_eq!(
            view.checkpoint_event_head(),
            genesis.event_head_hash,
            "checkpoint_event_head must be exactly AcceptedRosterData::event_head_hash, not a \
             different field"
        );
        assert!(view.is_active(&member_m_id));
        assert!(view.lookup_active(&stranger_m_id).is_none());
        assert!(!view.is_revoked(&member_m_id));
    }

    /// RED-R11..R16: `current_snapshot()` fails closed through the same six
    /// cases as `derive_machine_currency`'s prefix, before ever looking at
    /// per-machine membership. `NoGenesis` is the cheapest of the six to
    /// reach without a full checkpoint fixture.
    #[test]
    fn current_snapshot_no_genesis_is_unavailable() {
        let clock = TestClock::new(vec![Ok(1000)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let result = rig.coord.current_snapshot();
        assert!(matches!(
            result,
            Err(crate::machine_roster_authority::RosterSnapshotError::NoGenesis)
        ));
    }

    /// RED-R14: a clock read failure must fail `current_snapshot()` closed
    /// with `ClockStateUnavailable`, the same as it already does for
    /// `query_machine_currency` (this test exercises `current_snapshot`
    /// directly rather than relying only on RED-R21's equivalence proof).
    #[test]
    fn current_snapshot_clock_unavailable_is_unavailable() {
        let clock = TestClock::new(vec![Err(ClockError::BeforeEpoch)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let result = rig.coord.current_snapshot();
        assert!(matches!(
            result,
            Err(crate::machine_roster_authority::RosterSnapshotError::ClockStateUnavailable)
        ));
    }

    /// RED-R15 boundary, direct on `current_snapshot()`: `effective_now ==
    /// not_after` is still fresh (`>`, not `>=`, is the staleness test) —
    /// only strictly exceeding `not_after` is stale. Exercises both sides
    /// of the boundary in one test so an off-by-one mutant on the
    /// comparison operator fails one arm or the other.
    #[test]
    fn current_snapshot_stale_boundary_is_exclusive() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};

        let not_after = 1200;
        let clock = TestClock::new(vec![Ok(1000), Ok(not_after), Ok(not_after + 1)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();

        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let cert_bytes = rig.coord.owner_cert_bytes.clone();
        let fp = rig.coord.owner_cert_fp;

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after,
            owner_p_id: crate::person_cert::derive_person_id(&owner_pub),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &crate::person_cert::derive_person_id(&owner_pub),
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &owner_kp, &cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
        assert_eq!(
            rig.coord.admit_checkpoint(&genesis_bytes).unwrap(),
            PublicAdmissionOutcome::Accepted
        );

        // effective_now == not_after: still fresh, Ok.
        assert!(rig.coord.current_snapshot().is_ok());

        // effective_now == not_after + 1: stale, Err(CheckpointStale).
        let result = rig.coord.current_snapshot();
        assert!(matches!(
            result,
            Err(crate::machine_roster_authority::RosterSnapshotError::CheckpointStale)
        ));
    }

    #[test]
    fn coord_clock_before_epoch() {
        let clock = TestClock::new(vec![Err(ClockError::BeforeEpoch)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
    }

    #[test]
    fn coord_clock_exhausted() {
        let clock = TestClock::new(vec![]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
    }

    #[test]
    fn coord_clock_overflow() {
        let clock = TestClock::new(vec![Ok(u64::MAX)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
    }

    #[test]
    fn coord_owner_expired_rejected() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let dir = tempfile::tempdir().unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let m_id = crate::ids::derive_machine_id(&owner_pub);

        let record = HouseholdRecord {
            version: 1,
            hh_id: hh_id.clone(),
            hh_pub: root_pub.clone(),
            name: "test-household".to_string(),
            created_at: 500,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![m_id],
            is_follower: false,
        };

        let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
            &root_kp,
            crate::person_cert::SignOwnerOptions {
                hh_id: hh_id.clone(),
                p_pub: owner_pub.clone(),
                display_name: "Owner".into(),
                issued_at: 500,
            },
            crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
        )
        .unwrap();
        cert.not_after = Some(1150);
        cert.nonce = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        let sb = cert.signing_bytes().unwrap();
        cert.signature = root_kp.sign(&sb).unwrap();
        let cert_bytes = crate::cbor::to_canonical_vec(&cert).unwrap();
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(&cert).unwrap();
        let p_id = crate::person_cert::derive_person_id(&owner_pub);

        let auth_state = HouseholdAuthState::new(&record, cert);
        let clock = TestClock::new(vec![Ok(1175)]);
        let coord = MachineRosterCoordinator::from_validated_with_clock(
            dir.path(),
            &record,
            &auth_state,
            clock,
        )
        .unwrap();

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &owner_kp, &cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();

        coord.provision_no_genesis().unwrap();
        let result = coord.admit_checkpoint(&genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedOwner);
    }

    #[test]
    fn coord_terminal_fork_precedence_over_owner() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1050), Ok(1200)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();

        let mut conflicting = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xEE; 32],
            issued_at: 1050,
            not_after: 1250,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1050,
        };
        sign_checkpoint(&mut conflicting, &owner_kp, &cert_bytes, &ctx).unwrap();
        let conflicting_bytes = crate::cbor::to_canonical_vec(&conflicting).unwrap();

        let r2 = rig.coord.admit_checkpoint(&conflicting_bytes).unwrap();
        assert_eq!(r2, PublicAdmissionOutcome::CheckpointForkConflictRecorded);

        let m_id = crate::ids::derive_machine_id(&owner_pub);
        let query = rig.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(
            query,
            PublicCurrencyOutcome::UnavailableCheckpointForkConflict
        );
    }

    #[test]
    fn coord_high_water_recovery() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100), Ok(1050), Ok(1200)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let r1 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r1, PublicAdmissionOutcome::Accepted);
        let r2 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r2, PublicAdmissionOutcome::IdempotentDuplicate);
        let r3 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r3, PublicAdmissionOutcome::RejectedTemporal);
        let r4 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r4, PublicAdmissionOutcome::IdempotentDuplicate);
    }

    #[test]
    fn coord_provision_chain_only_floor_absent() {
        let clock = TestClock::new(vec![]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let chain_path = accepted_chain_path(dir.path());
        let floor_path = clock_floor_path(dir.path());
        assert!(chain_path.exists());
        assert!(!floor_path.exists());
        let bytes = std::fs::read(&chain_path).unwrap();
        let rec = decode_accepted_chain(&bytes, &rig.coord.hh_id).unwrap();
        assert_eq!(rec.state_kind, ChainStateKind::NoGenesis);
        assert!(rec.genesis_checkpoint.is_none());
        assert!(rec.accepted_checkpoint.is_none());
    }

    #[test]
    fn coord_latch_poison_outer() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1000)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();

        let latch = &rig.coord.latch;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = latch.lock().unwrap();
            panic!("poison");
        }));
        assert!(result.is_err());

        let admit_result = rig.coord.admit_checkpoint(&rig.genesis_bytes);
        assert!(matches!(admit_result, Err(RosterStoreError::LatchPoisoned)));
    }

    #[test]
    fn coord_terminal_fork_admission_zero_rewrite() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let dir = tempfile::tempdir().unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let m_id = crate::ids::derive_machine_id(&owner_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);

        let record = HouseholdRecord {
            version: 1,
            hh_id: hh_id.clone(),
            hh_pub: root_pub.clone(),
            name: "test-household".to_string(),
            created_at: 500,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![m_id],
            is_follower: false,
        };

        let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
            &root_kp,
            crate::person_cert::SignOwnerOptions {
                hh_id: hh_id.clone(),
                p_pub: owner_pub.clone(),
                display_name: "Owner".into(),
                issued_at: 500,
            },
            crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
        )
        .unwrap();
        cert.not_after = Some(1150);
        cert.nonce = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        let sb = cert.signing_bytes().unwrap();
        cert.signature = root_kp.sign(&sb).unwrap();
        let cert_bytes = crate::cbor::to_canonical_vec(&cert).unwrap();
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(&cert).unwrap();

        let auth_state = HouseholdAuthState::new(&record, cert);
        let coord = MachineRosterCoordinator::from_validated_with_clock(
            dir.path(),
            &record,
            &auth_state,
            TestClock::new(vec![Ok(1000), Ok(1050), Ok(1175)]),
        )
        .unwrap();

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &owner_kp, &cert_bytes, &ctx).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();

        coord.provision_no_genesis().unwrap();
        coord.admit_checkpoint(&genesis_bytes).unwrap();

        let mut conflicting = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xEE; 32],
            issued_at: 1050,
            not_after: 1250,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx2 = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1050,
        };
        sign_checkpoint(&mut conflicting, &owner_kp, &cert_bytes, &ctx2).unwrap();
        let conflicting_bytes = crate::cbor::to_canonical_vec(&conflicting).unwrap();

        let r2 = coord.admit_checkpoint(&conflicting_bytes).unwrap();
        assert_eq!(r2, PublicAdmissionOutcome::CheckpointForkConflictRecorded);

        let chain_path = accepted_chain_path(dir.path());
        let floor_path = clock_floor_path(dir.path());
        let chain_after_fork = std::fs::read(&chain_path).unwrap();

        let mut terminal_candidate = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xFF; 32],
            issued_at: 1190,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx3 = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut terminal_candidate, &owner_kp, &cert_bytes, &ctx3).unwrap();
        let terminal_bytes = crate::cbor::to_canonical_vec(&terminal_candidate).unwrap();

        let r3 = coord.admit_checkpoint(&terminal_bytes).unwrap();
        assert_eq!(r3, PublicAdmissionOutcome::CheckpointForkConflictRecorded);

        let chain_after_terminal = std::fs::read(&chain_path).unwrap();
        assert_eq!(chain_after_fork, chain_after_terminal);

        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1175);
    }

    #[test]
    fn coord_missing_floor_accepted_never_init() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        std::fs::remove_file(&floor_path).unwrap();
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert!(!floor_path.exists());
    }

    #[test]
    fn coord_rollback_floor_unchanged_latch_high_water() {
        let clock = TestClock::new(vec![Ok(1000), Ok(900), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let r1 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r1, PublicAdmissionOutcome::Accepted);
        let floor_path = clock_floor_path(dir.path());
        let floor_before = std::fs::read(&floor_path).unwrap();

        let r2 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r2, PublicAdmissionOutcome::RejectedTemporal);
        let floor_after_rollback = std::fs::read(&floor_path).unwrap();
        assert_eq!(floor_before, floor_after_rollback);

        let latch = rig.coord.latch.lock().unwrap();
        assert!(latch.failure_latched);
        assert_eq!(latch.failed_target, Some(1000));
        drop(latch);

        let r3 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r3, PublicAdmissionOutcome::IdempotentDuplicate);
        let latch = rig.coord.latch.lock().unwrap();
        assert!(!latch.failure_latched);
        assert_eq!(latch.failed_target, None);
        assert_eq!(latch.last_verified, Some(1100));
    }

    #[test]
    fn coord_query_clock_failure_unavailable() {
        let clock = TestClock::new(vec![Ok(1000), Err(ClockError::BeforeEpoch)]);
        let (rig, _dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let m_id = crate::ids::derive_machine_id(
            &P256Keypair::from_secret_scalar(&SCALAR_OWNER)
                .unwrap()
                .public(),
        );
        let result = rig.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(result, PublicCurrencyOutcome::UnavailableClockState);
    }

    #[test]
    fn coord_corrupt_floor_rejected() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        std::fs::write(&floor_path, b"corrupt").unwrap();
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
    }

    #[test]
    fn coord_zero_floor_rejected() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let zero_rec = ClockFloorRecordV1 {
            v: RECORD_VERSION,
            hh_id: rig.coord.hh_id.clone(),
            floor_secs: 0,
        };
        let bytes = crate::cbor::to_canonical_vec(&zero_rec).unwrap();
        std::fs::write(&floor_path, &bytes).unwrap();
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
    }

    #[test]
    fn coord_nogenesis_failure_latched_never_reinit() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let floor_path = clock_floor_path(dir.path());
        std::fs::create_dir_all(floor_path.parent().unwrap()).unwrap();
        std::fs::write(&floor_path, b"corrupt").unwrap();
        let r1 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r1, PublicAdmissionOutcome::RejectedTemporal);
        std::fs::remove_file(&floor_path).unwrap();
        let r2 = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r2, PublicAdmissionOutcome::RejectedTemporal);
        assert!(!floor_path.exists());
    }

    #[test]
    fn coord_unsafe_floor_symlink() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        std::fs::remove_file(&floor_path).unwrap();
        let target = dir.path().join("real_file");
        std::fs::write(&target, b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &floor_path).unwrap();
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert!(
            std::fs::symlink_metadata(&floor_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn coord_missing_floor_fork_never_init() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1050), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let mut conflicting = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xEE; 32],
            issued_at: 1050,
            not_after: 1250,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1050,
        };
        sign_checkpoint(&mut conflicting, &owner_kp, &cert_bytes, &ctx).unwrap();
        let conflicting_bytes = crate::cbor::to_canonical_vec(&conflicting).unwrap();
        let fork_result = rig.coord.admit_checkpoint(&conflicting_bytes).unwrap();
        assert_eq!(
            fork_result,
            PublicAdmissionOutcome::CheckpointForkConflictRecorded
        );

        let chain_path = accepted_chain_path(dir.path());
        let chain_bytes = std::fs::read(&chain_path).unwrap();
        let rec = decode_accepted_chain(&chain_bytes, &hh_id).unwrap();
        assert_eq!(rec.state_kind, ChainStateKind::CheckpointForkConflict);

        let floor_path = clock_floor_path(dir.path());
        std::fs::remove_file(&floor_path).unwrap();
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert!(!floor_path.exists());
    }

    #[test]
    fn coord_admit_genesis_seq2_persisted() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let result = rig.coord.admit_checkpoint(&seq2_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::Accepted);

        let chain_path = accepted_chain_path(dir.path());
        let chain_bytes = std::fs::read(&chain_path).unwrap();
        let rec = decode_accepted_chain(&chain_bytes, &hh_id).unwrap();
        assert_eq!(rec.state_kind, ChainStateKind::Accepted);
        assert_eq!(
            rec.genesis_checkpoint.as_deref(),
            Some(rig.genesis_bytes.as_slice())
        );
        assert_eq!(
            rec.accepted_checkpoint.as_deref(),
            Some(seq2_bytes.as_slice())
        );
        assert_eq!(
            rec.predecessor_checkpoint.as_deref(),
            Some(rig.genesis_bytes.as_slice())
        );
        assert!(rec.conflicting_checkpoint.is_none());
    }

    #[test]
    fn coord_kind2_persisted() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1050)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();

        let mut conflicting = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xEE; 32],
            issued_at: 1050,
            not_after: 1250,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1050,
        };
        sign_checkpoint(&mut conflicting, &owner_kp, &cert_bytes, &ctx).unwrap();
        let conflicting_bytes = crate::cbor::to_canonical_vec(&conflicting).unwrap();

        let result = rig.coord.admit_checkpoint(&conflicting_bytes).unwrap();
        assert_eq!(
            result,
            PublicAdmissionOutcome::CheckpointForkConflictRecorded
        );

        let chain_path = accepted_chain_path(dir.path());
        let chain_bytes = std::fs::read(&chain_path).unwrap();
        let rec = decode_accepted_chain(&chain_bytes, &hh_id).unwrap();
        assert_eq!(rec.state_kind, ChainStateKind::CheckpointForkConflict);
        assert_eq!(
            rec.genesis_checkpoint.as_deref(),
            Some(rig.genesis_bytes.as_slice())
        );
        assert_eq!(
            rec.accepted_checkpoint.as_deref(),
            Some(rig.genesis_bytes.as_slice())
        );
        assert_eq!(
            rec.conflicting_checkpoint.as_deref(),
            Some(conflicting_bytes.as_slice())
        );
        assert!(rec.predecessor_checkpoint.is_none());

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: hh_id.clone(),
            hh_pub: root_pub.clone(),
        };
        let genesis_bytes = rec.genesis_checkpoint.clone().unwrap();
        let accepted_bytes = rec.accepted_checkpoint.clone().unwrap();
        let conflicting_stored = rec.conflicting_checkpoint.clone().unwrap();
        let (state, _) = rederive_fork(
            &genesis_bytes,
            &accepted_bytes,
            None,
            &conflicting_stored,
            ChainStateKind::CheckpointForkConflict,
            &hh_ctx,
        )
        .unwrap();
        let AcceptedRosterChainState::CheckpointForkConflict {
            epoch,
            sequence,
            hashes,
        } = state
        else {
            panic!("expected CheckpointForkConflict");
        };
        assert_eq!(epoch, [0xAA; 32]);
        assert_eq!(sequence, 1);
        assert_eq!(hashes.len(), 2);
        let genesis_cp: MachineRosterCheckpointV1 =
            crate::cbor::from_canonical_slice(&genesis_bytes).unwrap();
        let genesis_hash = crate::machine_roster_authority::checkpoint_hash(&genesis_cp).unwrap();
        let conflicting_cp: MachineRosterCheckpointV1 =
            crate::cbor::from_canonical_slice(&conflicting_stored).unwrap();
        let conflicting_hash =
            crate::machine_roster_authority::checkpoint_hash(&conflicting_cp).unwrap();
        assert_eq!(hashes[0], genesis_hash);
        assert_eq!(hashes[1], conflicting_hash);
    }

    #[test]
    fn coord_commit_expected_state_mismatch() {
        let clock = TestClock::new(vec![]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let lock = RosterLock::acquire(dir.path(), &rig.coord.hh_id).unwrap();
        let record = AcceptedChainRecordV1 {
            v: RECORD_VERSION,
            hh_id: rig.coord.hh_id.clone(),
            state_kind: ChainStateKind::Accepted,
            genesis_checkpoint: Some(rig.genesis_bytes.clone()),
            accepted_checkpoint: Some(rig.genesis_bytes.clone()),
            predecessor_checkpoint: None,
            conflicting_checkpoint: None,
        };
        let wrong_expected = AcceptedRosterChainState::CheckpointForkConflict {
            epoch: [0xBB; 32],
            sequence: 99,
            hashes: vec![[0xFF; 32], [0xEE; 32]],
        };
        let result = rig
            .coord
            .commit_chain_record(&lock, &record, &wrong_expected);
        assert!(matches!(result, Err(RosterStoreError::ReadbackMismatch)));
    }

    #[test]
    fn coord_current_fp_mismatch_admit_and_query() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1100), Ok(1100)]);
        let (mut rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        assert_eq!(cert_bytes, rig.coord.owner_cert_bytes);
        assert_eq!(fp, rig.coord.owner_cert_fp);
        assert_eq!(p_id, rig.coord.owner_p_id);
        assert_eq!(owner_pub, rig.coord.owner_p_pub);

        rig.coord.owner_cert_fp = [0xFF; 32];

        let chain_path = accepted_chain_path(dir.path());
        let chain_before = std::fs::read(&chain_path).unwrap();

        let admit_result = rig.coord.admit_checkpoint(&seq2_bytes).unwrap();
        assert_eq!(admit_result, PublicAdmissionOutcome::RejectedOwner);

        let m_id = crate::ids::derive_machine_id(&owner_pub);
        let query_result = rig.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(
            query_result,
            PublicCurrencyOutcome::UnavailableOwnerAuthority
        );

        let chain_after = std::fs::read(&chain_path).unwrap();
        assert_eq!(chain_before, chain_after);
    }

    #[test]
    fn coord_current_p_pub_mismatch_admit_and_query() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1100), Ok(1100)]);
        let (mut rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        assert_eq!(cert_bytes, rig.coord.owner_cert_bytes);
        assert_eq!(fp, rig.coord.owner_cert_fp);
        assert_eq!(p_id, rig.coord.owner_p_id);
        assert_eq!(owner_pub, rig.coord.owner_p_pub);

        let wrong_pub = P256Keypair::from_secret_scalar(&[
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap()
        .public();
        rig.coord.owner_p_pub = wrong_pub;

        let chain_path = accepted_chain_path(dir.path());
        let chain_before = std::fs::read(&chain_path).unwrap();

        let admit_result = rig.coord.admit_checkpoint(&seq2_bytes).unwrap();
        assert_eq!(admit_result, PublicAdmissionOutcome::RejectedOwner);

        let m_id = crate::ids::derive_machine_id(&owner_pub);
        let query_result = rig.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(
            query_result,
            PublicCurrencyOutcome::UnavailableOwnerAuthority
        );

        let chain_after = std::fs::read(&chain_path).unwrap();
        assert_eq!(chain_before, chain_after);
    }

    #[test]
    fn coord_kind3_event_fork_persisted() {
        use crate::machine_roster_authority::{
            RosterAuthorityContext, revocation_event_hash, sign_checkpoint, sign_revocation,
        };
        let clock = TestClock::new(vec![Ok(1000), Ok(1100), Ok(1150)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();

        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();

        let m_kp = P256Keypair::from_secret_scalar(&[
            3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();
        let m_pub = m_kp.public();
        let m_id = crate::ids::derive_machine_id(&m_pub);
        let m_cert = crate::machine_cert::MachineCert::sign(
            &root_kp,
            &m_pub,
            &crate::machine_cert::SignOptions {
                hh_id: hh_id.clone(),
                hostname: "test".into(),
                platform: crate::machine_cert::Platform::Macos,
                joined_at: 500,
            },
        )
        .unwrap();
        let m_cert_bytes = crate::cbor::to_canonical_vec(&m_cert).unwrap();
        let m_fp = crate::machine_roster_authority::machine_cert_fingerprint(&m_cert).unwrap();
        let member = crate::machine_roster_authority::MachineRosterMemberV1 {
            m_id: m_id.clone(),
            m_pub: m_pub.clone(),
            machine_cert: m_cert_bytes,
            machine_cert_fingerprint: m_fp,
        };

        let mut genesis = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1000,
            not_after: 1200,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![member.clone()],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx1 = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1000,
        };
        sign_checkpoint(&mut genesis, &owner_kp, &cert_bytes, &ctx1).unwrap();
        let genesis_bytes = crate::cbor::to_canonical_vec(&genesis).unwrap();
        let genesis_hash = cp_hash(&genesis_bytes);

        let mut rev = crate::machine_roster_authority::MachineRosterRevocationV1 {
            v: crate::machine_roster_authority::REVOCATION_VERSION,
            kind: crate::machine_roster_authority::REVOCATION_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            sequence: 1,
            prev_event_hash: [0u8; 32],
            m_id: m_id.clone(),
            m_pub: m_pub.clone(),
            machine_cert_fingerprint: m_fp,
            revoked_at: 1050,
            reason: crate::machine_roster_authority::RevocationReason::OwnerAction,
            cascade: crate::machine_roster_authority::RevocationCascade::MachineOnly,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        sign_revocation(&mut rev, &owner_kp, &cert_bytes, &ctx1).unwrap();
        let event_head = revocation_event_hash(&rev).unwrap();

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 1,
            event_head_hash: event_head,
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![rev.clone()],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx2 = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx2).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let mut rev_alt = rev.clone();
        rev_alt.revoked_at = 1060;
        sign_revocation(&mut rev_alt, &owner_kp, &cert_bytes, &ctx2).unwrap();
        let event_head_alt = revocation_event_hash(&rev_alt).unwrap();

        let seq2_hash = cp_hash(&seq2_bytes);
        let mut conflicting = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 3,
            prev_checkpoint_hash: seq2_hash,
            event_sequence: 1,
            event_head_hash: event_head_alt,
            mesh_log_digest: [0xDD; 32],
            issued_at: 1150,
            not_after: 1350,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![rev_alt],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx3 = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1150,
        };
        sign_checkpoint(&mut conflicting, &owner_kp, &cert_bytes, &ctx3).unwrap();
        let conflicting_bytes = crate::cbor::to_canonical_vec(&conflicting).unwrap();

        let r_genesis = rig.coord.admit_checkpoint(&genesis_bytes).unwrap();
        assert_eq!(r_genesis, PublicAdmissionOutcome::Accepted);
        let r_seq2 = rig.coord.admit_checkpoint(&seq2_bytes).unwrap();
        assert_eq!(r_seq2, PublicAdmissionOutcome::Accepted);
        let fork_result = rig.coord.admit_checkpoint(&conflicting_bytes).unwrap();
        assert_eq!(
            fork_result,
            PublicAdmissionOutcome::EventForkConflictRecorded
        );

        let chain_path = accepted_chain_path(dir.path());
        let chain_bytes = std::fs::read(&chain_path).unwrap();
        let rec = decode_accepted_chain(&chain_bytes, &hh_id).unwrap();
        assert_eq!(rec.state_kind, ChainStateKind::EventForkConflict);
        assert_eq!(
            rec.genesis_checkpoint.as_deref(),
            Some(genesis_bytes.as_slice())
        );
        assert_eq!(
            rec.accepted_checkpoint.as_deref(),
            Some(seq2_bytes.as_slice())
        );
        assert_eq!(
            rec.predecessor_checkpoint.as_deref(),
            Some(genesis_bytes.as_slice())
        );
        assert_eq!(
            rec.conflicting_checkpoint.as_deref(),
            Some(conflicting_bytes.as_slice())
        );

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: hh_id.clone(),
            hh_pub: root_pub.clone(),
        };
        let (state, _) = rederive_fork(
            rec.genesis_checkpoint.as_deref().unwrap(),
            rec.accepted_checkpoint.as_deref().unwrap(),
            rec.predecessor_checkpoint.as_deref(),
            rec.conflicting_checkpoint.as_deref().unwrap(),
            ChainStateKind::EventForkConflict,
            &hh_ctx,
        )
        .unwrap();
        let AcceptedRosterChainState::EventForkConflict {
            epoch,
            sequence,
            hashes,
        } = state
        else {
            panic!("expected EventForkConflict");
        };
        assert_eq!(epoch, [0xAA; 32]);
        assert_eq!(sequence, 1);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], event_head);
        assert_eq!(hashes[1], event_head_alt);
    }

    // ─── DS-CP4: Failure injection tests ────────────────────────────────────

    #[test]
    fn fail_observe_floor_tmp_open() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let floor_before = std::fs::read(&floor_path).unwrap();
        let tmp_path = floor_path.parent().unwrap().join(format!(
            "{}.tmp",
            floor_path.file_name().unwrap().to_str().unwrap()
        ));

        let _fg = install_fail(
            FailPhase::ObserveFloor,
            FailStage::TmpOpen,
            tmp_path.clone(),
        );
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert_eq!(std::fs::read(&floor_path).unwrap(), floor_before);
        assert!(!tmp_path.exists());
    }

    #[test]
    fn fail_observe_floor_tmp_write() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let floor_before = std::fs::read(&floor_path).unwrap();
        let tmp_path = floor_path.parent().unwrap().join(format!(
            "{}.tmp",
            floor_path.file_name().unwrap().to_str().unwrap()
        ));

        let _fg = install_fail(
            FailPhase::ObserveFloor,
            FailStage::TmpWrite,
            tmp_path.clone(),
        );
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert_eq!(std::fs::read(&floor_path).unwrap(), floor_before);
        assert!(tmp_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let md = std::fs::metadata(&tmp_path).unwrap();
            assert!(md.is_file());
            assert_eq!(md.permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(std::fs::read(&tmp_path).unwrap().len(), 0);

        drop(_fg);
        let retry = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(retry, PublicAdmissionOutcome::IdempotentDuplicate);
        assert!(!tmp_path.exists());
    }

    #[test]
    fn fail_observe_floor_rename_before() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let floor_before = std::fs::read(&floor_path).unwrap();
        let tmp_path = floor_path.parent().unwrap().join(format!(
            "{}.tmp",
            floor_path.file_name().unwrap().to_str().unwrap()
        ));

        let _fg = install_fail(
            FailPhase::ObserveFloor,
            FailStage::RenameBefore,
            floor_path.clone(),
        );
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert_eq!(std::fs::read(&floor_path).unwrap(), floor_before);
        assert!(tmp_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let md = std::fs::metadata(&tmp_path).unwrap();
            assert!(md.is_file());
            assert_eq!(md.permissions().mode() & 0o777, 0o600);
        }

        drop(_fg);
        let retry = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(retry, PublicAdmissionOutcome::IdempotentDuplicate);
        assert!(!tmp_path.exists());
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &rig.coord.hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1100);
    }

    #[test]
    fn fail_observe_floor_readback() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let tmp_path = floor_path.parent().unwrap().join(format!(
            "{}.tmp",
            floor_path.file_name().unwrap().to_str().unwrap()
        ));

        let _fg = install_fail(
            FailPhase::ObserveFloor,
            FailStage::Readback,
            floor_path.clone(),
        );
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &rig.coord.hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1100);
        assert_eq!(floor_rec.v, RECORD_VERSION);
        assert!(!tmp_path.exists());
    }

    #[test]
    fn fail_second_floor_chain_unchanged() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1050)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let chain_path = accepted_chain_path(dir.path());
        let chain_before = std::fs::read(&chain_path).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let tmp_path = floor_path.parent().unwrap().join(format!(
            "{}.tmp",
            floor_path.file_name().unwrap().to_str().unwrap()
        ));

        let _fg = install_fail(FailPhase::SecondFloor, FailStage::TmpOpen, tmp_path);
        let result = rig.coord.admit_checkpoint(&seq2_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert_eq!(std::fs::read(&chain_path).unwrap(), chain_before);
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1050);
    }

    #[test]
    fn fail_chain_commit_rename_before() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let chain_path = accepted_chain_path(dir.path());
        let chain_before = std::fs::read(&chain_path).unwrap();

        let _fg = install_fail(
            FailPhase::ChainCommit,
            FailStage::RenameBefore,
            chain_path.clone(),
        );
        let result = rig.coord.admit_checkpoint(&seq2_bytes);
        assert!(result.is_err());
        assert_eq!(std::fs::read(&chain_path).unwrap(), chain_before);

        let floor_path = clock_floor_path(dir.path());
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1100);
    }

    #[test]
    fn fail_chain_commit_readback_retry_idempotent() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1100), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let chain_path = accepted_chain_path(dir.path());

        let _fg = install_fail(
            FailPhase::ChainCommit,
            FailStage::Readback,
            chain_path.clone(),
        );
        let result = rig.coord.admit_checkpoint(&seq2_bytes);
        assert!(result.is_err());
        // Post-rename: new chain IS on disk
        let chain_bytes = std::fs::read(&chain_path).unwrap();
        let rec = decode_accepted_chain(&chain_bytes, &hh_id).unwrap();
        assert_eq!(rec.state_kind, ChainStateKind::Accepted);
        assert_eq!(
            rec.genesis_checkpoint.as_deref(),
            Some(rig.genesis_bytes.as_slice())
        );
        assert_eq!(
            rec.accepted_checkpoint.as_deref(),
            Some(seq2_bytes.as_slice())
        );
        assert_eq!(
            rec.predecessor_checkpoint.as_deref(),
            Some(rig.genesis_bytes.as_slice())
        );
        assert!(rec.conflicting_checkpoint.is_none());

        let floor_path = clock_floor_path(dir.path());
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1100);

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: hh_id.clone(),
            hh_pub: rig.coord.hh_pub.clone(),
        };
        let (state, _) = rederive_accepted(
            rec.genesis_checkpoint.as_deref().unwrap(),
            rec.accepted_checkpoint.as_deref().unwrap(),
            rec.predecessor_checkpoint.as_deref(),
            &hh_ctx,
        )
        .unwrap();
        let AcceptedRosterChainState::Accepted(data) = state else {
            panic!("expected Accepted");
        };
        assert_eq!(data.checkpoint_sequence, 2);
        let decoded_cp: MachineRosterCheckpointV1 =
            crate::cbor::from_canonical_slice(seq2_bytes.as_slice()).unwrap();
        let expected_hash = crate::machine_roster_authority::checkpoint_hash(&decoded_cp).unwrap();
        assert_eq!(data.checkpoint_hash, expected_hash);
        assert_eq!(data.prev_checkpoint_hash, cp_hash(&rig.genesis_bytes));
        assert_eq!(data.event_sequence, 0);
        assert_eq!(data.event_head_hash, [0u8; 32]);
        assert_eq!(data.predecessor_event_sequence, 0);
        assert_eq!(data.predecessor_event_head_hash, [0u8; 32]);
        assert_eq!(data.epoch, [0xAA; 32]);
        assert_eq!(data.owner_cert_fingerprint, rig.coord.owner_cert_fp);
        assert_eq!(data.active, vec![]);
        assert_eq!(data.tombstones, vec![]);
        assert_eq!(data.genesis_basis.epoch, [0xAA; 32]);
        assert_eq!(data.genesis_basis.members, vec![]);

        // Retry with NEW coordinator (restart) → IdempotentDuplicate
        drop(_fg);
        drop(rig);
        let rig2 = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1100)]));
        let retry = rig2.coord.admit_checkpoint(&seq2_bytes).unwrap();
        assert_eq!(retry, PublicAdmissionOutcome::IdempotentDuplicate);
    }

    #[test]
    fn fail_observe_floor_parent_open_post_rename() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let parent = floor_path.parent().unwrap().to_path_buf();
        let tmp_path = parent.join(format!(
            "{}.tmp",
            floor_path.file_name().unwrap().to_str().unwrap()
        ));

        let _fg = install_fail(FailPhase::ObserveFloor, FailStage::ParentOpen, parent);
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &rig.coord.hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1100);
        assert_eq!(floor_rec.v, RECORD_VERSION);
        assert_eq!(floor_rec.hh_id, rig.coord.hh_id);
        assert!(!tmp_path.exists());
    }

    #[test]
    fn fail_chain_commit_tmp_open_pre_rename() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let chain_path = accepted_chain_path(dir.path());
        let chain_before = std::fs::read(&chain_path).unwrap();
        let chain_tmp = chain_path.parent().unwrap().join(format!(
            "{}.tmp",
            chain_path.file_name().unwrap().to_str().unwrap()
        ));

        let _fg = install_fail(
            FailPhase::ChainCommit,
            FailStage::TmpOpen,
            chain_tmp.clone(),
        );
        let result = rig.coord.admit_checkpoint(&seq2_bytes);
        assert!(result.is_err());
        assert_eq!(std::fs::read(&chain_path).unwrap(), chain_before);
        assert!(!chain_tmp.exists());
    }

    #[test]
    fn crash_window_chain_commit_restart_retry() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1050)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);

        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let chain_path = accepted_chain_path(dir.path());

        let _fg = install_fail(
            FailPhase::ChainCommit,
            FailStage::RenameBefore,
            chain_path.clone(),
        );
        let result = rig.coord.admit_checkpoint(&seq2_bytes);
        assert!(result.is_err());

        let floor_path = clock_floor_path(dir.path());
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1100);

        let chain_bytes = std::fs::read(&chain_path).unwrap();
        let chain_rec = decode_accepted_chain(&chain_bytes, &hh_id).unwrap();
        assert_eq!(chain_rec.state_kind, ChainStateKind::Accepted);
        assert_eq!(
            chain_rec.accepted_checkpoint.as_deref(),
            Some(rig.genesis_bytes.as_slice())
        );

        drop(_fg);
        drop(rig);

        let rig2 = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1100)]));
        let retry = rig2.coord.admit_checkpoint(&seq2_bytes).unwrap();
        assert_eq!(retry, PublicAdmissionOutcome::Accepted);

        let chain_after = std::fs::read(&chain_path).unwrap();
        let chain_rec2 = decode_accepted_chain(&chain_after, &hh_id).unwrap();
        assert_eq!(chain_rec2.state_kind, ChainStateKind::Accepted);
        assert_eq!(
            chain_rec2.genesis_checkpoint.as_deref(),
            Some(rig2.genesis_bytes.as_slice())
        );
        assert_eq!(
            chain_rec2.accepted_checkpoint.as_deref(),
            Some(seq2_bytes.as_slice())
        );
        assert_eq!(
            chain_rec2.predecessor_checkpoint.as_deref(),
            Some(rig2.genesis_bytes.as_slice())
        );
        assert!(chain_rec2.conflicting_checkpoint.is_none());

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: hh_id.clone(),
            hh_pub: rig2.coord.hh_pub.clone(),
        };
        let (state, _) = rederive_accepted(
            chain_rec2.genesis_checkpoint.as_deref().unwrap(),
            chain_rec2.accepted_checkpoint.as_deref().unwrap(),
            chain_rec2.predecessor_checkpoint.as_deref(),
            &hh_ctx,
        )
        .unwrap();
        assert!(matches!(state, AcceptedRosterChainState::Accepted(_)));
    }

    // ─── DS-CP4: Matrix remaining stages ────────────────────────────────────

    fn tmp_path_for_target(target: &Path) -> PathBuf {
        target.parent().unwrap().join(format!(
            "{}.tmp",
            target.file_name().unwrap().to_str().unwrap()
        ))
    }

    #[test]
    fn fail_observe_floor_tmp_flush() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let floor_before = std::fs::read(&floor_path).unwrap();
        let tmp = tmp_path_for_target(&floor_path);

        let expected_floor_rec = ClockFloorRecordV1 {
            v: RECORD_VERSION,
            hh_id: rig.coord.hh_id.clone(),
            floor_secs: 1100,
        };
        let expected_canonical = crate::cbor::to_canonical_vec(&expected_floor_rec).unwrap();

        let _fg = install_fail(FailPhase::ObserveFloor, FailStage::TmpFlush, tmp.clone());
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert_eq!(std::fs::read(&floor_path).unwrap(), floor_before);
        assert!(tmp.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let md = std::fs::metadata(&tmp).unwrap();
            assert!(md.is_file());
            assert_eq!(md.permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(std::fs::read(&tmp).unwrap(), expected_canonical);
        drop(_fg);
        let retry = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(retry, PublicAdmissionOutcome::IdempotentDuplicate);
        assert!(!tmp.exists());
    }

    #[test]
    fn fail_observe_floor_tmp_sync() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let floor_before = std::fs::read(&floor_path).unwrap();
        let tmp = tmp_path_for_target(&floor_path);

        let expected_floor_rec = ClockFloorRecordV1 {
            v: RECORD_VERSION,
            hh_id: rig.coord.hh_id.clone(),
            floor_secs: 1100,
        };
        let expected_canonical = crate::cbor::to_canonical_vec(&expected_floor_rec).unwrap();

        let _fg = install_fail(FailPhase::ObserveFloor, FailStage::TmpSync, tmp.clone());
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert_eq!(std::fs::read(&floor_path).unwrap(), floor_before);
        assert!(tmp.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let md = std::fs::metadata(&tmp).unwrap();
            assert!(md.is_file());
            assert_eq!(md.permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(std::fs::read(&tmp).unwrap(), expected_canonical);
        drop(_fg);
        let retry = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(retry, PublicAdmissionOutcome::IdempotentDuplicate);
        assert!(!tmp.exists());
    }

    #[test]
    fn fail_observe_floor_parent_sync_post_rename() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let parent = floor_path.parent().unwrap().to_path_buf();
        let tmp = tmp_path_for_target(&floor_path);

        let _fg = install_fail(FailPhase::ObserveFloor, FailStage::ParentSync, parent);
        let result = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &rig.coord.hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1100);
        assert!(!tmp.exists());
    }

    #[test]
    fn fail_observe_floor_query_unavailable() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let tmp = tmp_path_for_target(&floor_path);

        let _fg = install_fail(FailPhase::ObserveFloor, FailStage::TmpOpen, tmp);
        let m_id = crate::ids::derive_machine_id(
            &P256Keypair::from_secret_scalar(&SCALAR_OWNER)
                .unwrap()
                .public(),
        );
        let result = rig.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(result, PublicCurrencyOutcome::UnavailableClockState);
    }

    #[test]
    fn fail_second_floor_rename_before() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1050)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);
        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let chain_path = accepted_chain_path(dir.path());
        let chain_before = std::fs::read(&chain_path).unwrap();
        let floor_path = clock_floor_path(dir.path());
        let floor_tmp = tmp_path_for_target(&floor_path);

        let _fg = install_fail(
            FailPhase::SecondFloor,
            FailStage::RenameBefore,
            floor_path.clone(),
        );
        let result = rig.coord.admit_checkpoint(&seq2_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert_eq!(std::fs::read(&chain_path).unwrap(), chain_before);
        assert!(floor_tmp.exists());
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1050);
    }

    #[test]
    fn fail_second_floor_readback_post_rename() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1050)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);
        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();

        let chain_path = accepted_chain_path(dir.path());
        let chain_before = std::fs::read(&chain_path).unwrap();
        let floor_path = clock_floor_path(dir.path());

        let _fg = install_fail(
            FailPhase::SecondFloor,
            FailStage::Readback,
            floor_path.clone(),
        );
        let result = rig.coord.admit_checkpoint(&seq2_bytes).unwrap();
        assert_eq!(result, PublicAdmissionOutcome::RejectedTemporal);
        assert_eq!(std::fs::read(&chain_path).unwrap(), chain_before);
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1100);
    }

    // ─── DS-CP4: Matrix completion (table-driven) ─────────────────────────

    struct Seq2Fixture {
        seq2_bytes: Vec<u8>,
        hh_id: HouseholdId,
    }

    fn make_seq2_fixture(rig: &CoordRig) -> Seq2Fixture {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);
        let mut seq2 = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xDD; 32],
            issued_at: 1100,
            not_after: 1300,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1100,
        };
        sign_checkpoint(&mut seq2, &owner_kp, &cert_bytes, &ctx).unwrap();
        let seq2_bytes = crate::cbor::to_canonical_vec(&seq2).unwrap();
        Seq2Fixture { seq2_bytes, hh_id }
    }

    fn assert_seq2_accepted_exact(
        data: &crate::machine_roster_authority::AcceptedRosterData,
        rig: &CoordRig,
        fix: &Seq2Fixture,
        owner_fp: [u8; 32],
    ) {
        let decoded_cp: MachineRosterCheckpointV1 =
            crate::cbor::from_canonical_slice(fix.seq2_bytes.as_slice()).unwrap();
        let seq2_hash = crate::machine_roster_authority::checkpoint_hash(&decoded_cp).unwrap();
        let genesis_hash = cp_hash(&rig.genesis_bytes);
        assert_eq!(data.checkpoint_sequence, 2);
        assert_eq!(data.checkpoint_hash, seq2_hash);
        assert_eq!(data.prev_checkpoint_hash, genesis_hash);
        assert_eq!(data.epoch, [0xAA; 32]);
        assert_eq!(data.event_sequence, 0);
        assert_eq!(data.event_head_hash, [0u8; 32]);
        assert_eq!(data.predecessor_event_sequence, 0);
        assert_eq!(data.predecessor_event_head_hash, [0u8; 32]);
        assert_eq!(data.owner_cert_fingerprint, owner_fp);
        assert_eq!(data.active, vec![]);
        assert_eq!(data.tombstones, vec![]);
        assert_eq!(data.issued_at, 1100);
        assert_eq!(data.not_after, 1300);
        assert_eq!(data.genesis_basis.epoch, [0xAA; 32]);
        assert_eq!(data.genesis_basis.members, vec![]);
    }

    #[test]
    fn fail_observe_query_matrix() {
        let stages = [
            FailStage::TmpOpen,
            FailStage::TmpWrite,
            FailStage::TmpFlush,
            FailStage::TmpSync,
            FailStage::RenameBefore,
            FailStage::ParentOpen,
            FailStage::ParentSync,
            FailStage::Readback,
        ];
        let is_pre_rename = |s: FailStage| {
            matches!(
                s,
                FailStage::TmpOpen
                    | FailStage::TmpWrite
                    | FailStage::TmpFlush
                    | FailStage::TmpSync
                    | FailStage::RenameBefore
            )
        };
        for stage in stages {
            let clock = TestClock::new(vec![Ok(1000), Ok(1100), Ok(1100)]);
            let (rig, dir) = make_coord_rig(clock);
            rig.coord.provision_no_genesis().unwrap();
            rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
            let floor_path = clock_floor_path(dir.path());
            let chain_path = accepted_chain_path(dir.path());
            let chain_before = std::fs::read(&chain_path).unwrap();
            let floor_before = std::fs::read(&floor_path).unwrap();
            let parent = floor_path.parent().unwrap().to_path_buf();
            let tmp = tmp_path_for_target(&floor_path);
            let fail_path = match stage {
                FailStage::TmpOpen
                | FailStage::TmpWrite
                | FailStage::TmpFlush
                | FailStage::TmpSync => tmp.clone(),
                FailStage::RenameBefore | FailStage::Readback => floor_path.clone(),
                FailStage::ParentOpen | FailStage::ParentSync => parent.clone(),
            };
            let _fg = install_fail(FailPhase::ObserveFloor, stage, fail_path);
            let m_id = crate::ids::derive_machine_id(
                &P256Keypair::from_secret_scalar(&SCALAR_OWNER)
                    .unwrap()
                    .public(),
            );
            let result = rig.coord.query_machine_currency(&m_id).unwrap();
            assert_eq!(
                result,
                PublicCurrencyOutcome::UnavailableClockState,
                "{:?}",
                stage
            );
            assert_eq!(
                std::fs::read(&chain_path).unwrap(),
                chain_before,
                "chain {:?}",
                stage
            );
            if is_pre_rename(stage) {
                assert_eq!(
                    std::fs::read(&floor_path).unwrap(),
                    floor_before,
                    "floor old {:?}",
                    stage
                );
                if stage == FailStage::TmpOpen {
                    assert!(!tmp.exists(), "TmpOpen no tmp");
                } else {
                    assert!(tmp.exists(), "tmp exists {:?}", stage);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let md = std::fs::metadata(&tmp).unwrap();
                        assert!(md.is_file());
                        assert_eq!(md.permissions().mode() & 0o777, 0o600);
                    }
                    if stage == FailStage::TmpWrite {
                        assert_eq!(std::fs::read(&tmp).unwrap().len(), 0, "TmpWrite empty");
                    } else {
                        let expected_floor = ClockFloorRecordV1 {
                            v: RECORD_VERSION,
                            hh_id: rig.coord.hh_id.clone(),
                            floor_secs: 1100,
                        };
                        let expected_bytes =
                            crate::cbor::to_canonical_vec(&expected_floor).unwrap();
                        assert_eq!(
                            std::fs::read(&tmp).unwrap(),
                            expected_bytes,
                            "tmp canonical {:?}",
                            stage
                        );
                    }
                }
            } else {
                let floor_bytes = std::fs::read(&floor_path).unwrap();
                let floor_rec = decode_clock_floor(&floor_bytes, &rig.coord.hh_id).unwrap();
                assert_eq!(floor_rec.floor_secs, 1100, "floor new {:?}", stage);
                assert!(!tmp.exists(), "tmp absent {:?}", stage);
            }
            drop(_fg);
            let retry = rig.coord.query_machine_currency(&m_id).unwrap();
            assert_eq!(retry, PublicCurrencyOutcome::NotListed, "retry {:?}", stage);
            assert!(!tmp.exists(), "tmp removed retry {:?}", stage);
        }
    }

    #[test]
    fn fail_second_floor_matrix() {
        let all_stages = [
            FailStage::TmpOpen,
            FailStage::TmpWrite,
            FailStage::TmpFlush,
            FailStage::TmpSync,
            FailStage::RenameBefore,
            FailStage::ParentOpen,
            FailStage::ParentSync,
            FailStage::Readback,
        ];
        for stage in &all_stages {
            let clock = TestClock::new(vec![Ok(1000), Ok(1050), Ok(1100)]);
            let (rig, dir) = make_coord_rig(clock);
            rig.coord.provision_no_genesis().unwrap();
            rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
            let fix = make_seq2_fixture(&rig);
            let chain_path = accepted_chain_path(dir.path());
            let chain_before = std::fs::read(&chain_path).unwrap();
            let floor_path = clock_floor_path(dir.path());
            let tmp = tmp_path_for_target(&floor_path);
            let parent = floor_path.parent().unwrap().to_path_buf();
            let fail_path = match stage {
                FailStage::TmpOpen
                | FailStage::TmpWrite
                | FailStage::TmpFlush
                | FailStage::TmpSync => tmp.clone(),
                FailStage::RenameBefore | FailStage::Readback => floor_path.clone(),
                FailStage::ParentOpen | FailStage::ParentSync => parent.clone(),
            };
            let _fg = install_fail(FailPhase::SecondFloor, *stage, fail_path);
            let result = rig.coord.admit_checkpoint(&fix.seq2_bytes).unwrap();
            assert_eq!(
                result,
                PublicAdmissionOutcome::RejectedTemporal,
                "{:?}",
                stage
            );
            assert_eq!(
                std::fs::read(&chain_path).unwrap(),
                chain_before,
                "chain {:?}",
                stage
            );
            let floor_bytes = std::fs::read(&floor_path).unwrap();
            let floor_rec = decode_clock_floor(&floor_bytes, &fix.hh_id).unwrap();
            let is_pre = matches!(
                stage,
                FailStage::TmpOpen
                    | FailStage::TmpWrite
                    | FailStage::TmpFlush
                    | FailStage::TmpSync
                    | FailStage::RenameBefore
            );
            if is_pre {
                assert_eq!(floor_rec.floor_secs, 1050, "pre {:?}", stage);
                if *stage == FailStage::TmpOpen {
                    assert!(!tmp.exists(), "TmpOpen no tmp");
                } else {
                    assert!(tmp.exists(), "tmp exists {:?}", stage);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let md = std::fs::metadata(&tmp).unwrap();
                        assert!(md.is_file());
                        assert_eq!(md.permissions().mode() & 0o777, 0o600);
                    }
                    if *stage == FailStage::TmpWrite {
                        assert_eq!(std::fs::read(&tmp).unwrap().len(), 0, "TmpWrite empty");
                    } else {
                        let expected_floor = ClockFloorRecordV1 {
                            v: RECORD_VERSION,
                            hh_id: fix.hh_id.clone(),
                            floor_secs: 1100,
                        };
                        let expected_bytes =
                            crate::cbor::to_canonical_vec(&expected_floor).unwrap();
                        assert_eq!(
                            std::fs::read(&tmp).unwrap(),
                            expected_bytes,
                            "tmp canonical {:?}",
                            stage
                        );
                    }
                }
            } else {
                assert_eq!(floor_rec.floor_secs, 1100, "post {:?}", stage);
                assert!(!tmp.exists(), "tmp absent {:?}", stage);
            }
            drop(_fg);
            let retry = rig.coord.admit_checkpoint(&fix.seq2_bytes).unwrap();
            assert_eq!(retry, PublicAdmissionOutcome::Accepted, "retry {:?}", stage);
            assert!(!tmp.exists(), "tmp removed {:?}", stage);
        }
    }

    #[test]
    fn fail_chain_commit_matrix() {
        let all_stages = [
            FailStage::TmpOpen,
            FailStage::TmpWrite,
            FailStage::TmpFlush,
            FailStage::TmpSync,
            FailStage::RenameBefore,
            FailStage::ParentOpen,
            FailStage::ParentSync,
        ];
        for stage in &all_stages {
            let clock = TestClock::new(vec![Ok(1000), Ok(1050), Ok(1100)]);
            let (rig, dir) = make_coord_rig(clock);
            rig.coord.provision_no_genesis().unwrap();
            rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
            let fix = make_seq2_fixture(&rig);
            let chain_path = accepted_chain_path(dir.path());
            let chain_before = std::fs::read(&chain_path).unwrap();
            let chain_tmp = tmp_path_for_target(&chain_path);
            let parent = chain_path.parent().unwrap().to_path_buf();
            let floor_path = clock_floor_path(dir.path());
            let fail_path = match stage {
                FailStage::TmpOpen
                | FailStage::TmpWrite
                | FailStage::TmpFlush
                | FailStage::TmpSync => chain_tmp.clone(),
                FailStage::RenameBefore => chain_path.clone(),
                FailStage::ParentOpen | FailStage::ParentSync => parent.clone(),
                _ => unreachable!(),
            };
            let _fg = install_fail(FailPhase::ChainCommit, *stage, fail_path);
            let result = rig.coord.admit_checkpoint(&fix.seq2_bytes);
            let err = result.expect_err(&format!("stage {:?} should Err", stage));
            let is_pre = matches!(
                stage,
                FailStage::TmpOpen
                    | FailStage::TmpWrite
                    | FailStage::TmpFlush
                    | FailStage::TmpSync
                    | FailStage::RenameBefore
            );
            match &err {
                RosterStoreError::Io {
                    stage: io_stage,
                    path,
                    source,
                } => {
                    let expected_io = match stage {
                        FailStage::TmpOpen => StoreIoStage::OpenTmp,
                        FailStage::TmpWrite => StoreIoStage::WritePayload,
                        FailStage::TmpFlush => StoreIoStage::Flush,
                        FailStage::TmpSync => StoreIoStage::SyncTmp,
                        FailStage::RenameBefore => StoreIoStage::Rename,
                        FailStage::ParentOpen => StoreIoStage::OpenParent,
                        FailStage::ParentSync => StoreIoStage::SyncParent,
                        _ => unreachable!(),
                    };
                    assert_eq!(*io_stage, expected_io, "io_stage {:?}", stage);
                    let expected_path = match stage {
                        FailStage::TmpOpen
                        | FailStage::TmpWrite
                        | FailStage::TmpFlush
                        | FailStage::TmpSync => &chain_tmp,
                        FailStage::RenameBefore => &chain_path,
                        FailStage::ParentOpen | FailStage::ParentSync => &parent,
                        _ => unreachable!(),
                    };
                    assert_eq!(path, expected_path, "path {:?}", stage);
                    let expected_kind = match stage {
                        FailStage::TmpOpen | FailStage::RenameBefore => {
                            std::io::ErrorKind::PermissionDenied
                        }
                        FailStage::TmpWrite => std::io::ErrorKind::WriteZero,
                        FailStage::TmpFlush | FailStage::TmpSync | FailStage::ParentSync => {
                            std::io::ErrorKind::Other
                        }
                        FailStage::ParentOpen => std::io::ErrorKind::NotFound,
                        _ => unreachable!(),
                    };
                    assert_eq!(source.kind(), expected_kind, "kind {:?}", stage);
                }
                other => panic!("expected Io, got {:?} for {:?}", other, stage),
            }
            let floor_bytes = std::fs::read(&floor_path).unwrap();
            let floor_rec = decode_clock_floor(&floor_bytes, &fix.hh_id).unwrap();
            assert_eq!(floor_rec.floor_secs, 1100, "floor {:?}", stage);
            if is_pre {
                assert_eq!(
                    std::fs::read(&chain_path).unwrap(),
                    chain_before,
                    "chain OLD {:?}",
                    stage
                );
                if *stage == FailStage::TmpOpen {
                    assert!(!chain_tmp.exists(), "TmpOpen no tmp");
                } else {
                    assert!(chain_tmp.exists(), "tmp exists {:?}", stage);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let md = std::fs::metadata(&chain_tmp).unwrap();
                        assert!(md.is_file());
                        assert_eq!(md.permissions().mode() & 0o777, 0o600);
                    }
                    if *stage == FailStage::TmpWrite {
                        assert_eq!(
                            std::fs::read(&chain_tmp).unwrap().len(),
                            0,
                            "TmpWrite empty"
                        );
                    } else {
                        let tmp_bytes = std::fs::read(&chain_tmp).unwrap();
                        let tmp_rec = decode_accepted_chain(&tmp_bytes, &fix.hh_id).unwrap();
                        assert_eq!(tmp_rec.state_kind, ChainStateKind::Accepted);
                        assert_eq!(
                            tmp_rec.genesis_checkpoint.as_deref(),
                            Some(rig.genesis_bytes.as_slice())
                        );
                        assert_eq!(
                            tmp_rec.accepted_checkpoint.as_deref(),
                            Some(fix.seq2_bytes.as_slice())
                        );
                        assert_eq!(
                            tmp_rec.predecessor_checkpoint.as_deref(),
                            Some(rig.genesis_bytes.as_slice())
                        );
                        assert!(tmp_rec.conflicting_checkpoint.is_none());
                    }
                }
                drop(_fg);
                let retry = rig.coord.admit_checkpoint(&fix.seq2_bytes).unwrap();
                assert_eq!(retry, PublicAdmissionOutcome::Accepted, "retry {:?}", stage);
                assert!(!chain_tmp.exists(), "tmp removed {:?}", stage);
            } else {
                let chain_bytes = std::fs::read(&chain_path).unwrap();
                let rec = decode_accepted_chain(&chain_bytes, &fix.hh_id).unwrap();
                assert_eq!(rec.state_kind, ChainStateKind::Accepted);
                assert_eq!(
                    rec.genesis_checkpoint.as_deref(),
                    Some(rig.genesis_bytes.as_slice())
                );
                assert_eq!(
                    rec.accepted_checkpoint.as_deref(),
                    Some(fix.seq2_bytes.as_slice())
                );
                assert_eq!(
                    rec.predecessor_checkpoint.as_deref(),
                    Some(rig.genesis_bytes.as_slice())
                );
                assert!(rec.conflicting_checkpoint.is_none());
                assert!(!chain_tmp.exists(), "tmp absent {:?}", stage);
                let hh_ctx = HistoricalHouseholdContext {
                    hh_id: fix.hh_id.clone(),
                    hh_pub: rig.coord.hh_pub.clone(),
                };
                let (state, binding) = rederive_accepted(
                    rec.genesis_checkpoint.as_deref().unwrap(),
                    rec.accepted_checkpoint.as_deref().unwrap(),
                    rec.predecessor_checkpoint.as_deref(),
                    &hh_ctx,
                )
                .unwrap();
                let AcceptedRosterChainState::Accepted(data) = state else {
                    panic!("expected Accepted {:?}", stage);
                };
                assert_eq!(binding.cert_fingerprint, rig.coord.owner_cert_fp);
                assert_seq2_accepted_exact(&data, &rig, &fix, rig.coord.owner_cert_fp);
                drop(_fg);
                drop(rig);
                let rig2 = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1100)]));
                let retry = rig2.coord.admit_checkpoint(&fix.seq2_bytes).unwrap();
                assert_eq!(
                    retry,
                    PublicAdmissionOutcome::IdempotentDuplicate,
                    "retry {:?}",
                    stage
                );
            }
        }
    }

    #[test]
    fn fail_chain_commit_readback_exact() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1050), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let fix = make_seq2_fixture(&rig);
        let chain_path = accepted_chain_path(dir.path());
        let floor_path = clock_floor_path(dir.path());
        let chain_tmp = tmp_path_for_target(&chain_path);

        let _fg = install_fail(
            FailPhase::ChainCommit,
            FailStage::Readback,
            chain_path.clone(),
        );
        let result = rig.coord.admit_checkpoint(&fix.seq2_bytes);
        let err = result.expect_err("Readback should Err");
        assert!(
            matches!(err, RosterStoreError::ReadbackMismatch),
            "expected ReadbackMismatch, got {:?}",
            err
        );
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &fix.hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1100);
        let chain_bytes = std::fs::read(&chain_path).unwrap();
        let rec = decode_accepted_chain(&chain_bytes, &fix.hh_id).unwrap();
        assert_eq!(rec.state_kind, ChainStateKind::Accepted);
        assert_eq!(
            rec.genesis_checkpoint.as_deref(),
            Some(rig.genesis_bytes.as_slice())
        );
        assert_eq!(
            rec.accepted_checkpoint.as_deref(),
            Some(fix.seq2_bytes.as_slice())
        );
        assert_eq!(
            rec.predecessor_checkpoint.as_deref(),
            Some(rig.genesis_bytes.as_slice())
        );
        assert!(rec.conflicting_checkpoint.is_none());
        assert!(!chain_tmp.exists());
        let hh_ctx = HistoricalHouseholdContext {
            hh_id: fix.hh_id.clone(),
            hh_pub: rig.coord.hh_pub.clone(),
        };
        let (state, binding) = rederive_accepted(
            rec.genesis_checkpoint.as_deref().unwrap(),
            rec.accepted_checkpoint.as_deref().unwrap(),
            rec.predecessor_checkpoint.as_deref(),
            &hh_ctx,
        )
        .unwrap();
        let AcceptedRosterChainState::Accepted(data) = state else {
            panic!("expected Accepted");
        };
        assert_eq!(binding.cert_fingerprint, rig.coord.owner_cert_fp);
        assert_seq2_accepted_exact(&data, &rig, &fix, rig.coord.owner_cert_fp);
        drop(_fg);
        drop(rig);
        let rig2 = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1100)]));
        let retry = rig2.coord.admit_checkpoint(&fix.seq2_bytes).unwrap();
        assert_eq!(retry, PublicAdmissionOutcome::IdempotentDuplicate);
    }

    // ─── DS-CP4: Lifecycle/restart matrix ───────────────────────────────────

    #[test]
    fn lifecycle_restart_rollback_rejected() {
        let clock = TestClock::new(vec![Ok(1000), Ok(1100)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let r = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r, PublicAdmissionOutcome::Accepted);
        let fix = make_seq2_fixture(&rig);
        let r = rig.coord.admit_checkpoint(&fix.seq2_bytes).unwrap();
        assert_eq!(r, PublicAdmissionOutcome::Accepted);
        let floor_path = clock_floor_path(dir.path());
        let chain_path = accepted_chain_path(dir.path());
        let floor_before = std::fs::read(&floor_path).unwrap();
        let floor_decoded = decode_clock_floor(&floor_before, &rig.coord.hh_id).unwrap();
        assert_eq!(floor_decoded.v, RECORD_VERSION);
        assert_eq!(floor_decoded.floor_secs, 1100);
        let chain_before = std::fs::read(&chain_path).unwrap();
        drop(rig);

        let rig2 = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1050), Ok(1050)]));
        let admit = rig2.coord.admit_checkpoint(&rig2.genesis_bytes).unwrap();
        assert_eq!(admit, PublicAdmissionOutcome::RejectedTemporal);
        let m_id = crate::ids::derive_machine_id(
            &P256Keypair::from_secret_scalar(&SCALAR_OWNER)
                .unwrap()
                .public(),
        );
        let query = rig2.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(query, PublicCurrencyOutcome::UnavailableClockState);
        assert_eq!(std::fs::read(&floor_path).unwrap(), floor_before);
        assert_eq!(std::fs::read(&chain_path).unwrap(), chain_before);
    }

    #[test]
    fn lifecycle_restart_nogenesis_floor_init() {
        let clock = TestClock::new(vec![Ok(1000)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let chain_path = accepted_chain_path(dir.path());
        let floor_path = clock_floor_path(dir.path());
        assert!(!floor_path.exists());
        let chain_before = std::fs::read(&chain_path).unwrap();
        drop(rig);

        let rig2 = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1000)]));
        let m_id = crate::ids::derive_machine_id(
            &P256Keypair::from_secret_scalar(&SCALAR_OWNER)
                .unwrap()
                .public(),
        );
        let query = rig2.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(query, PublicCurrencyOutcome::UnavailableNoGenesis);
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &rig2.coord.hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1000);
        assert_eq!(floor_rec.v, RECORD_VERSION);
        let chain_bytes = std::fs::read(&chain_path).unwrap();
        assert_eq!(chain_bytes, chain_before);
        let chain_rec = decode_accepted_chain(&chain_bytes, &rig2.coord.hh_id).unwrap();
        assert_eq!(chain_rec.state_kind, ChainStateKind::NoGenesis);
        assert_eq!(chain_rec.v, RECORD_VERSION);
        assert_eq!(chain_rec.hh_id, rig2.coord.hh_id);
        assert!(chain_rec.genesis_checkpoint.is_none());
        assert!(chain_rec.accepted_checkpoint.is_none());
        assert!(chain_rec.predecessor_checkpoint.is_none());
        assert!(chain_rec.conflicting_checkpoint.is_none());
    }

    #[test]
    fn lifecycle_restart_accepted_missing_floor() {
        let clock = TestClock::new(vec![Ok(1000)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        let r = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r, PublicAdmissionOutcome::Accepted);
        let floor_path = clock_floor_path(dir.path());
        let chain_path = accepted_chain_path(dir.path());
        let chain_before = std::fs::read(&chain_path).unwrap();
        std::fs::remove_file(&floor_path).unwrap();
        drop(rig);

        let rig2 = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1100), Ok(1100)]));
        let admit = rig2.coord.admit_checkpoint(&rig2.genesis_bytes).unwrap();
        assert_eq!(admit, PublicAdmissionOutcome::RejectedTemporal);
        let m_id = crate::ids::derive_machine_id(
            &P256Keypair::from_secret_scalar(&SCALAR_OWNER)
                .unwrap()
                .public(),
        );
        let query = rig2.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(query, PublicCurrencyOutcome::UnavailableClockState);
        assert!(!floor_path.exists());
        assert_eq!(std::fs::read(&chain_path).unwrap(), chain_before);
    }

    #[test]
    fn lifecycle_restart_fork_missing_floor() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let clock = TestClock::new(vec![Ok(1000), Ok(1050)]);
        let (rig, dir) = make_coord_rig(clock);
        rig.coord.provision_no_genesis().unwrap();
        rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let mut conflicting = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 1,
            prev_checkpoint_hash: [0u8; 32],
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xEE; 32],
            issued_at: 1050,
            not_after: 1250,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1050,
        };
        sign_checkpoint(&mut conflicting, &owner_kp, &cert_bytes, &ctx).unwrap();
        let conflicting_bytes = crate::cbor::to_canonical_vec(&conflicting).unwrap();
        let fork_result = rig.coord.admit_checkpoint(&conflicting_bytes).unwrap();
        assert_eq!(
            fork_result,
            PublicAdmissionOutcome::CheckpointForkConflictRecorded
        );

        let floor_path = clock_floor_path(dir.path());
        let chain_path = accepted_chain_path(dir.path());
        let chain_before = std::fs::read(&chain_path).unwrap();
        std::fs::remove_file(&floor_path).unwrap();
        drop(rig);

        let rig2 = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1100), Ok(1100)]));
        let admit = rig2.coord.admit_checkpoint(&rig2.genesis_bytes).unwrap();
        assert_eq!(admit, PublicAdmissionOutcome::RejectedTemporal);
        let m_id = crate::ids::derive_machine_id(&owner_pub);
        let query = rig2.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(query, PublicCurrencyOutcome::UnavailableClockState);
        assert!(!floor_path.exists());
        assert_eq!(std::fs::read(&chain_path).unwrap(), chain_before);
        let rec = decode_accepted_chain(&chain_before, &rig2.coord.hh_id).unwrap();
        assert_eq!(rec.state_kind, ChainStateKind::CheckpointForkConflict);
        assert_eq!(
            rec.genesis_checkpoint.as_deref(),
            Some(rig2.genesis_bytes.as_slice())
        );
        assert_eq!(
            rec.accepted_checkpoint.as_deref(),
            Some(rig2.genesis_bytes.as_slice())
        );
        assert!(rec.predecessor_checkpoint.is_none());
        assert_eq!(
            rec.conflicting_checkpoint.as_deref(),
            Some(conflicting_bytes.as_slice())
        );

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: rig2.coord.hh_id.clone(),
            hh_pub: rig2.coord.hh_pub.clone(),
        };
        let (fork_state, _) = rederive_fork(
            rec.genesis_checkpoint.as_deref().unwrap(),
            rec.accepted_checkpoint.as_deref().unwrap(),
            None,
            rec.conflicting_checkpoint.as_deref().unwrap(),
            ChainStateKind::CheckpointForkConflict,
            &hh_ctx,
        )
        .unwrap();
        let AcceptedRosterChainState::CheckpointForkConflict {
            epoch,
            sequence,
            hashes,
        } = fork_state
        else {
            panic!("expected CheckpointForkConflict");
        };
        assert_eq!(epoch, [0xAA; 32]);
        assert_eq!(sequence, 1);
        let genesis_hash = cp_hash(&rig2.genesis_bytes);
        let conflicting_hash = cp_hash(&conflicting_bytes);
        assert_eq!(hashes, vec![genesis_hash, conflicting_hash]);
    }

    #[test]
    fn lifecycle_full_causal_sequence() {
        use crate::machine_roster_authority::{RosterAuthorityContext, sign_checkpoint};
        let dir = tempfile::tempdir().unwrap();
        let rig = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1000)]));
        rig.coord.provision_no_genesis().unwrap();
        let r = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r, PublicAdmissionOutcome::Accepted);
        let floor_path = clock_floor_path(dir.path());
        let floor_rec =
            decode_clock_floor(&std::fs::read(&floor_path).unwrap(), &rig.coord.hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1000);
        drop(rig);

        let rig = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(900)]));
        let r = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        assert_eq!(r, PublicAdmissionOutcome::RejectedTemporal);
        drop(rig);

        let fix_rig = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1050)]));
        let fix = make_seq2_fixture(&fix_rig);
        let r = fix_rig.coord.admit_checkpoint(&fix.seq2_bytes).unwrap();
        assert_eq!(r, PublicAdmissionOutcome::Accepted);
        let floor_rec =
            decode_clock_floor(&std::fs::read(&floor_path).unwrap(), &fix_rig.coord.hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1100);
        let chain_path = accepted_chain_path(dir.path());
        let chain_bytes = std::fs::read(&chain_path).unwrap();
        let rec = decode_accepted_chain(&chain_bytes, &fix_rig.coord.hh_id).unwrap();
        assert_eq!(
            rec.accepted_checkpoint.as_deref(),
            Some(fix.seq2_bytes.as_slice())
        );
        let saved_genesis_bytes = fix_rig.genesis_bytes.clone();
        let saved_hh_pub = fix_rig.coord.hh_pub.clone();
        let saved_owner_fp = fix_rig.coord.owner_cert_fp;
        drop(fix_rig);

        let owner_kp = P256Keypair::from_secret_scalar(&SCALAR_OWNER).unwrap();
        let root_kp = P256Keypair::from_secret_scalar(&SCALAR_ROOT).unwrap();
        let root_pub = root_kp.public();
        let owner_pub = owner_kp.public();
        let hh_id = derive_household_id(&root_pub);
        let p_id = crate::person_cert::derive_person_id(&owner_pub);
        let cert_bytes = {
            let mut cert = crate::person_cert::PersonCert::sign_owner_with_verified_provenance(
                &root_kp,
                crate::person_cert::SignOwnerOptions {
                    hh_id: hh_id.clone(),
                    p_pub: owner_pub.clone(),
                    display_name: "Owner".into(),
                    issued_at: 500,
                },
                crate::person_cert::VerifiedOwnerProvenance::IosSecureEnclaveOwner,
            )
            .unwrap();
            cert.nonce = vec![
                0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ];
            let sb = cert.signing_bytes().unwrap();
            cert.signature = root_kp.sign(&sb).unwrap();
            crate::cbor::to_canonical_vec(&cert).unwrap()
        };
        let fp = crate::machine_roster_authority::owner_cert_fingerprint(
            &crate::cbor::from_canonical_slice::<crate::person_cert::PersonCert>(&cert_bytes)
                .unwrap(),
        )
        .unwrap();
        let genesis_hash = cp_hash(&saved_genesis_bytes);
        let mut conflicting = MachineRosterCheckpointV1 {
            v: CHECKPOINT_VERSION,
            kind: CHECKPOINT_KIND.to_string(),
            hh_id: hh_id.clone(),
            epoch: [0xAA; 32],
            checkpoint_sequence: 2,
            prev_checkpoint_hash: genesis_hash,
            event_sequence: 0,
            event_head_hash: [0u8; 32],
            mesh_log_digest: [0xEE; 32],
            issued_at: 1150,
            not_after: 1350,
            owner_p_id: p_id.clone(),
            owner_cert_fingerprint: fp,
            active: vec![],
            revocations: vec![],
            owner_person_cert: cert_bytes.clone(),
            signature: P256Signature([0u8; 64]),
        };
        let ctx = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1150,
        };
        sign_checkpoint(&mut conflicting, &owner_kp, &cert_bytes, &ctx).unwrap();
        let conflicting_bytes = crate::cbor::to_canonical_vec(&conflicting).unwrap();

        let rig = make_coord_rig_at(
            dir.path(),
            TestClock::new(vec![Ok(1150), Ok(1150), Ok(1150)]),
        );
        let r = rig.coord.admit_checkpoint(&conflicting_bytes).unwrap();
        assert_eq!(r, PublicAdmissionOutcome::CheckpointForkConflictRecorded);
        let chain_after_fork = std::fs::read(&chain_path).unwrap();
        let floor_after_fork = std::fs::read(&floor_path).unwrap();
        let floor_rec_fork = decode_clock_floor(&floor_after_fork, &rig.coord.hh_id).unwrap();
        assert_eq!(floor_rec_fork.floor_secs, 1150);

        let mut terminal_candidate = conflicting.clone();
        terminal_candidate.issued_at = 1190;
        terminal_candidate.not_after = 1400;
        terminal_candidate.mesh_log_digest = [0xFF; 32];
        let ctx_terminal = RosterAuthorityContext {
            hh_pub: &root_pub,
            expected_hh_id: &hh_id,
            expected_p_id: &p_id,
            expected_p_pub: &owner_pub,
            effective_now: 1190,
        };
        terminal_candidate.signature = P256Signature([0u8; 64]);
        sign_checkpoint(
            &mut terminal_candidate,
            &owner_kp,
            &cert_bytes,
            &ctx_terminal,
        )
        .unwrap();
        let terminal_bytes = crate::cbor::to_canonical_vec(&terminal_candidate).unwrap();

        let r = rig.coord.admit_checkpoint(&terminal_bytes).unwrap();
        assert_eq!(r, PublicAdmissionOutcome::CheckpointForkConflictRecorded);
        assert_eq!(std::fs::read(&chain_path).unwrap(), chain_after_fork);
        assert_eq!(std::fs::read(&floor_path).unwrap(), floor_after_fork);

        let m_id = crate::ids::derive_machine_id(&owner_pub);
        let query = rig.coord.query_machine_currency(&m_id).unwrap();
        assert_eq!(
            query,
            PublicCurrencyOutcome::UnavailableCheckpointForkConflict
        );

        let rec = decode_accepted_chain(&chain_after_fork, &rig.coord.hh_id).unwrap();
        assert_eq!(rec.state_kind, ChainStateKind::CheckpointForkConflict);
        assert_eq!(
            rec.genesis_checkpoint.as_deref(),
            Some(saved_genesis_bytes.as_slice())
        );
        assert_eq!(
            rec.accepted_checkpoint.as_deref(),
            Some(fix.seq2_bytes.as_slice())
        );
        assert_eq!(
            rec.predecessor_checkpoint.as_deref(),
            Some(saved_genesis_bytes.as_slice())
        );
        assert_eq!(
            rec.conflicting_checkpoint.as_deref(),
            Some(conflicting_bytes.as_slice())
        );

        let floor_final = std::fs::read(&floor_path).unwrap();
        let floor_rec_final = decode_clock_floor(&floor_final, &rig.coord.hh_id).unwrap();
        assert_eq!(floor_rec_final.floor_secs, 1150);

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: hh_id.clone(),
            hh_pub: saved_hh_pub.clone(),
        };
        let (fork_state, fork_binding) = rederive_fork(
            rec.genesis_checkpoint.as_deref().unwrap(),
            rec.accepted_checkpoint.as_deref().unwrap(),
            rec.predecessor_checkpoint.as_deref(),
            rec.conflicting_checkpoint.as_deref().unwrap(),
            ChainStateKind::CheckpointForkConflict,
            &hh_ctx,
        )
        .unwrap();
        assert_eq!(fork_binding.cert_fingerprint, saved_owner_fp);
        let AcceptedRosterChainState::CheckpointForkConflict {
            epoch,
            sequence,
            hashes,
        } = fork_state
        else {
            panic!("expected CheckpointForkConflict");
        };
        assert_eq!(epoch, [0xAA; 32]);
        assert_eq!(sequence, 2);
        let seq2_hash = cp_hash(&fix.seq2_bytes);
        let conflicting_hash = cp_hash(&conflicting_bytes);
        assert_eq!(hashes, vec![seq2_hash, conflicting_hash]);
    }

    // ─── DS-CP4: Subprocess helpers ─────────────────────────────────────────

    #[cfg(test)]
    fn terminate_and_reap(
        child: &mut std::process::Child,
        reap_deadline: std::time::Instant,
    ) -> Result<std::process::ExitStatus, String> {
        use std::io::ErrorKind;
        let initial_observation: Option<String> = match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => None,
            Err(e) => Some(format!("initial try_wait: {:?}", e)),
        };
        match child.kill() {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::InvalidInput => {}
            Err(e) => {
                return Err(format!(
                    "kill failed: {:?}{}",
                    e,
                    initial_observation
                        .map(|o| format!("; {}", o))
                        .unwrap_or_default()
                ));
            }
        }
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {
                    if std::time::Instant::now() >= reap_deadline {
                        return Err(format!(
                            "reap deadline{}",
                            initial_observation
                                .map(|o| format!("; {}", o))
                                .unwrap_or_default()
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => {
                    if std::time::Instant::now() >= reap_deadline {
                        return Err(format!(
                            "poll error: {:?}{}",
                            e,
                            initial_observation
                                .map(|o| format!("; {}", o))
                                .unwrap_or_default()
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
    }

    #[cfg(test)]
    fn bounded_wait_status(
        child: &mut std::process::Child,
        deadline: std::time::Instant,
    ) -> Result<std::process::ExitStatus, String> {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let reap_dl = std::time::Instant::now() + std::time::Duration::from_secs(2);
                        let cleanup = terminate_and_reap(child, reap_dl);
                        return Err(format!("poll timeout; cleanup: {:?}", cleanup));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => {
                    let reap_dl = std::time::Instant::now() + std::time::Duration::from_secs(2);
                    let cleanup = terminate_and_reap(child, reap_dl);
                    return Err(format!("try_wait error: {:?}; cleanup: {:?}", e, cleanup));
                }
            }
        }
    }

    #[cfg(test)]
    #[derive(Debug)]
    enum HandshakeOutcome {
        Ready,
        ProtocolError(String),
        TimedOut,
    }

    #[test]
    #[ignore]
    fn subprocess_worker() {
        let state_dir = std::path::PathBuf::from(std::env::var("ROSTER_TEST_STATE_DIR").unwrap());
        let result_path = std::path::PathBuf::from(std::env::var("ROSTER_RESULT_PATH").unwrap());
        let rig = make_coord_rig_at(&state_dir, TestClock::new(vec![Ok(1000)]));
        let outcome = rig.coord.admit_checkpoint(&rig.genesis_bytes).unwrap();
        let result_str = match outcome {
            PublicAdmissionOutcome::Accepted => "Accepted",
            PublicAdmissionOutcome::IdempotentDuplicate => "IdempotentDuplicate",
            other => unreachable!("unexpected: {:?}", other),
        };
        let tmp = result_path.with_extension("tmp");
        std::fs::write(&tmp, result_str).unwrap();
        std::fs::rename(&tmp, &result_path).unwrap();
    }

    #[test]
    fn subprocess_concurrent_admit_lock_contention() {
        use std::time::{Duration, Instant};
        let dir = tempfile::tempdir().unwrap();
        let rig = make_coord_rig_at(dir.path(), TestClock::new(vec![Ok(1000)]));
        rig.coord.provision_no_genesis().unwrap();
        let hh_id = rig.coord.hh_id.clone();
        let hh_pub = rig.coord.hh_pub.clone();
        let owner_fp = rig.coord.owner_cert_fp;

        let parent_lock = RosterLock::acquire(dir.path(), &hh_id).unwrap();

        let exe = std::env::current_exe().unwrap();
        let r1 = dir.path().join("result_1.txt");
        let r2 = dir.path().join("result_2.txt");
        let m1 = dir.path().join("marker_1.txt");
        let m2 = dir.path().join("marker_2.txt");

        let mut child1 = std::process::Command::new(&exe)
            .arg("--ignored")
            .arg("--exact")
            .arg("machine_roster_store::tests::subprocess_worker")
            .arg("--test-threads=1")
            .env("ROSTER_TEST_STATE_DIR", dir.path().to_str().unwrap())
            .env("ROSTER_RESULT_PATH", r1.to_str().unwrap())
            .env("ROSTER_BLOCKED_MARKER_PATH", m1.to_str().unwrap())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();

        let mut child2 = match std::process::Command::new(&exe)
            .arg("--ignored")
            .arg("--exact")
            .arg("machine_roster_store::tests::subprocess_worker")
            .arg("--test-threads=1")
            .env("ROSTER_TEST_STATE_DIR", dir.path().to_str().unwrap())
            .env("ROSTER_RESULT_PATH", r2.to_str().unwrap())
            .env("ROSTER_BLOCKED_MARKER_PATH", m2.to_str().unwrap())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                let reap_dl = Instant::now() + Duration::from_secs(2);
                let reap1 = terminate_and_reap(&mut child1, reap_dl);
                panic!("child2 spawn failed: {:?}; child1 reap: {:?}", e, reap1);
            }
        };

        let deadline = Instant::now() + Duration::from_secs(4);
        let outcome = loop {
            match child1.try_wait() {
                Ok(Some(status)) if !m1.exists() => {
                    break HandshakeOutcome::ProtocolError(format!(
                        "child1 exited early: {:?}",
                        status
                    ));
                }
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(e) => {
                    break HandshakeOutcome::ProtocolError(format!(
                        "child1 try_wait error: {:?}",
                        e
                    ));
                }
            }
            match child2.try_wait() {
                Ok(Some(status)) if !m2.exists() => {
                    break HandshakeOutcome::ProtocolError(format!(
                        "child2 exited early: {:?}",
                        status
                    ));
                }
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(e) => {
                    break HandshakeOutcome::ProtocolError(format!(
                        "child2 try_wait error: {:?}",
                        e
                    ));
                }
            }
            if r1.exists() || r2.exists() {
                break HandshakeOutcome::ProtocolError("result file exists while blocked".into());
            }
            let mc1 = std::fs::read_to_string(&m1);
            let mc2 = std::fs::read_to_string(&m2);
            match (&mc1, &mc2) {
                (Ok(c1), Ok(c2)) if c1 == "blocked" && c2 == "blocked" => {
                    break HandshakeOutcome::Ready;
                }
                (Err(e), _) if e.kind() != std::io::ErrorKind::NotFound => {
                    break HandshakeOutcome::ProtocolError(format!("marker1 read error: {:?}", e));
                }
                (_, Err(e)) if e.kind() != std::io::ErrorKind::NotFound => {
                    break HandshakeOutcome::ProtocolError(format!("marker2 read error: {:?}", e));
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                break HandshakeOutcome::TimedOut;
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        let handshake_failure = match outcome {
            HandshakeOutcome::Ready => None,
            HandshakeOutcome::ProtocolError(message) => {
                Some(format!("protocol error: {}", message))
            }
            HandshakeOutcome::TimedOut => Some("timed out waiting for blocked markers".to_string()),
        };
        if let Some(failure) = handshake_failure {
            drop(parent_lock);
            let reap1_dl = Instant::now() + Duration::from_secs(2);
            let reap1 = terminate_and_reap(&mut child1, reap1_dl);
            let reap2_dl = Instant::now() + Duration::from_secs(2);
            let reap2 = terminate_and_reap(&mut child2, reap2_dl);
            panic!(
                "handshake failed: {}; reap1: {:?}; reap2: {:?}",
                failure, reap1, reap2
            );
        }

        drop(parent_lock);

        let poll1_dl = Instant::now() + Duration::from_secs(4);
        let result1 = bounded_wait_status(&mut child1, poll1_dl);
        let poll2_dl = Instant::now() + Duration::from_secs(4);
        let result2 = bounded_wait_status(&mut child2, poll2_dl);

        match (result1, result2) {
            (Ok(s1), Ok(s2)) => {
                assert!(s1.success(), "child1 non-success: {:?}", s1);
                assert!(s2.success(), "child2 non-success: {:?}", s2);
            }
            (r1, r2) => {
                panic!("child wait failed: child1={:?}; child2={:?}", r1, r2);
            }
        }

        let res1 = std::fs::read_to_string(&r1).unwrap();
        let res2 = std::fs::read_to_string(&r2).unwrap();
        let mut results = vec![res1.as_str(), res2.as_str()];
        results.sort();
        assert_eq!(results, vec!["Accepted", "IdempotentDuplicate"]);

        let floor_path = clock_floor_path(dir.path());
        let floor_bytes = std::fs::read(&floor_path).unwrap();
        let floor_rec = decode_clock_floor(&floor_bytes, &hh_id).unwrap();
        assert_eq!(floor_rec.floor_secs, 1000);

        let chain_path = accepted_chain_path(dir.path());
        let chain_bytes = std::fs::read(&chain_path).unwrap();
        let chain_rec = decode_accepted_chain(&chain_bytes, &hh_id).unwrap();
        assert_eq!(chain_rec.state_kind, ChainStateKind::Accepted);
        assert_eq!(
            chain_rec.genesis_checkpoint,
            Some(rig.genesis_bytes.clone())
        );
        assert_eq!(
            chain_rec.accepted_checkpoint,
            Some(rig.genesis_bytes.clone())
        );
        assert!(chain_rec.predecessor_checkpoint.is_none());
        assert!(chain_rec.conflicting_checkpoint.is_none());

        let hh_ctx = HistoricalHouseholdContext {
            hh_id: hh_id.clone(),
            hh_pub: hh_pub.clone(),
        };
        let (state, binding) = rederive_accepted(
            chain_rec.genesis_checkpoint.as_deref().unwrap(),
            chain_rec.accepted_checkpoint.as_deref().unwrap(),
            None,
            &hh_ctx,
        )
        .unwrap();
        let AcceptedRosterChainState::Accepted(data) = state else {
            panic!("expected Accepted");
        };
        let decoded_cp: MachineRosterCheckpointV1 =
            crate::cbor::from_canonical_slice(&rig.genesis_bytes).unwrap();
        let expected_hash = crate::machine_roster_authority::checkpoint_hash(&decoded_cp).unwrap();
        assert_eq!(data.epoch, [0xAA; 32]);
        assert_eq!(data.checkpoint_sequence, 1);
        assert_eq!(data.checkpoint_hash, expected_hash);
        assert_eq!(data.prev_checkpoint_hash, [0u8; 32]);
        assert_eq!(data.event_sequence, 0);
        assert_eq!(data.event_head_hash, [0u8; 32]);
        assert_eq!(data.owner_cert_fingerprint, owner_fp);
        assert_eq!(data.active, vec![]);
        assert_eq!(data.tombstones, vec![]);
        assert_eq!(data.genesis_basis.epoch, [0xAA; 32]);
        assert_eq!(data.genesis_basis.members, vec![]);
        assert_eq!(binding.cert_fingerprint, owner_fp);
    }
}
