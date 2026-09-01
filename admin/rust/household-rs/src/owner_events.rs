//! Phase 3 owner-events append log + broadcaster + push-token
//! registry (`contracts/owner-events.md`,
//! `contracts/push-token-register.md`).
//!
//! - [`OwnerEvent`] is the signed log entry the iPhone consumes via
//!   long-poll. Each event is signed by the issuer's `M_priv`; the
//!   iPhone verifies the signature against the issuer's
//!   [`crate::MachineCert`] chained to the household root.
//! - [`OwnerEventLog`] is the long-lived, lifecycle-bound handle that retains
//!   state/household/log directory descriptors, the in-memory cursor head, and
//!   broadcaster wiring. Every append holds the stable lifecycle reader before
//!   the cross-process log flock and derives its cursor from the durable tail.
//! - On-disk records are **length-prefixed**: every event is written as
//!   `<u64 BE length><canonical CBOR>`. On boot the log is scanned and
//!   any partial trailing record (e.g., from a torn write) is
//!   truncated. Without the prefix, a single torn append would corrupt
//!   the entire log.
//! - [`OwnerEventsBroadcaster`] wraps a `tokio::sync::broadcast`
//!   channel so the long-poll handler wakes within ~1 ms.
//! - [`OwnerDevicePushToken`] is the persisted push-token registry
//!   entry, written by the PoP-authenticated `push-token` endpoint.

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use fs2::FileExt;
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;
use tokio::sync::broadcast;

use crate::cbor;
use crate::error::{HouseholdError, StorageError};
use crate::household_lifecycle::{
    HouseholdLifecycleGenerationV1, HouseholdLifecycleLockError, LifecycleReadGuard,
    LifecycleWriteGuard,
};
use crate::household_record::HouseholdRecord;
use crate::keys::{IdentityKey, P256Signature};

pub const OWNER_EVENT_VERSION: u8 = 1;

/// Type tag for [`OwnerEvent`] entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerEventType {
    JoinRequest,
    MachineJoined,
    JoinCancelled,
    DevicePairRequest,
    #[serde(rename = "sign_machine_cert_for_proxy")]
    SignMachineCertForProxy,
}

/// Polymorphic event payload. Variant is chosen by `OwnerEvent.type`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum OwnerEventPayload {
    JoinRequest(JoinRequestPayload),
    MachineJoined(MachineJoinedPayload),
    JoinCancelled(JoinCancelledPayload),
    DevicePairRequest(DevicePairRequestPayload),
    SignMachineCertForProxy(SignMachineCertForProxyPayload),
}

impl OwnerEventPayload {
    fn matches_type(&self, t: &OwnerEventType) -> bool {
        matches!(
            (self, t),
            (Self::JoinRequest(_), OwnerEventType::JoinRequest)
                | (Self::MachineJoined(_), OwnerEventType::MachineJoined)
                | (Self::JoinCancelled(_), OwnerEventType::JoinCancelled)
                | (
                    Self::DevicePairRequest(_),
                    OwnerEventType::DevicePairRequest
                )
                | (
                    Self::SignMachineCertForProxy(_),
                    OwnerEventType::SignMachineCertForProxy,
                )
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequestPayload {
    pub join_request_cbor: ByteBuf,
    pub fingerprint: String,
    pub expiry: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineJoinedPayload {
    pub m_pub: ByteBuf,
    pub m_id: String,
    pub hostname: String,
    pub joined_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinCancelledPayload {
    pub m_pub: ByteBuf,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairRequestPayload {
    pub request_id: String,
    pub d_pub: ByteBuf,
    pub device_name: String,
    pub platform: String,
    pub expiry: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignMachineCertForProxyPayload {
    pub actor_person_id: String,
    pub target_m_id: String,
    pub joined_at: u64,
    pub hostname: String,
    pub platform: String,
}

/// Append-log entry per `data-model.md::OwnerEvent`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerEvent {
    #[serde(rename = "v")]
    pub version: u8,
    pub cursor: u64,
    pub ts: u64,
    #[serde(rename = "type")]
    pub event_type: OwnerEventType,
    pub payload: OwnerEventPayload,
    pub issuer_m_id: String,
    pub signature: P256Signature,
}

/// Same shape as [`OwnerEvent`] minus `signature` — used to compute
/// the canonical CBOR bytes the signature covers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerEventUnsigned {
    #[serde(rename = "v")]
    version: u8,
    cursor: u64,
    ts: u64,
    #[serde(rename = "type")]
    event_type: OwnerEventType,
    payload: OwnerEventPayload,
    issuer_m_id: String,
}

#[derive(Debug, Error)]
pub enum EventError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("CBOR shape error: {0}")]
    Cbor(String),
    #[error("signing failed: {0}")]
    Signing(#[from] crate::error::KeystoreError),
    #[error("clock before unix epoch")]
    ClockSkew,
    #[error("event_type / payload variant disagree")]
    PayloadTypeMismatch,
    #[error("machine-joined event conflicts with an existing event for the same machine")]
    MachineJoinedConflict,
    #[error("owner-event lifecycle binding rejected: {0}")]
    Lifecycle(#[from] HouseholdLifecycleLockError),
    #[error("owner-event log is bound to a different household or lifecycle generation")]
    StaleLifecycleBinding,
    #[error("owner-event append may have taken effect at {stage:?}")]
    MayHaveTakenEffect { stage: EventDurabilityStage },
}

/// Last durability step whose acknowledgement was lost after an append may
/// already have changed the log. Callers must reconcile from the durable tail;
/// they must not publish an in-memory head or broadcast from this outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventDurabilityStage {
    Write,
    FileSync,
    ParentSync,
}

const LENGTH_PREFIX_BYTES: usize = 8;
const MAX_RECORD_BYTES: u64 = 1 << 20; // 1 MiB hard cap per event
const MAX_HOUSEHOLD_RECORD_BYTES: u64 = 1 << 20;
const OWNER_EVENTS_SUBDIR: &str = "owner_events";
const OWNER_EVENTS_LOG_FILENAME: &str = "log.cbor";
const OWNER_EVENTS_LOCK_FILENAME: &str = ".append-v2.lock";

/// Long-lived owner-events log handle.
///
/// Owns the retained state-root/household/log descriptors, lifecycle binding,
/// and in-memory cursor head. A fresh cross-process flock serializes each
/// append. Optionally fans appended events out to an attached
/// [`OwnerEventsBroadcaster`] so long-poll subscribers never see a
/// disk-on-its-own state where the broadcaster forgets to publish.
///
/// Construct via [`Self::open_under_lifecycle`] (no broadcaster) or
/// [`Self::open_with_broadcaster_under_lifecycle`]. Both require the lifecycle
/// writer and perform a scan-and-repair pass over `owner_events/log.cbor`.
pub struct OwnerEventLog {
    state_path: PathBuf,
    state_dir: File,
    household_dir: File,
    log_dir: File,
    expected_hh_id: String,
    lifecycle_generation: HouseholdLifecycleGenerationV1,
    head: AtomicU64,
    broadcaster: Option<OwnerEventsBroadcaster>,
}

impl OwnerEventLog {
    /// Open and repair the log while the caller holds the lifecycle writer.
    ///
    /// Construction binds the long-lived handle to the exact retained state
    /// root, installed `household/` inode, household id, and lifecycle
    /// generation. It never creates `household/`; a missing household is a
    /// hard error. Only `owner_events/` and its coordination file may be
    /// created, fd-relative, after the binding checks succeed.
    pub fn open_under_lifecycle(
        lifecycle: &LifecycleWriteGuard,
        state_path: PathBuf,
        expected_hh_id: &str,
    ) -> Result<Arc<Self>, EventError> {
        Self::open_inner(lifecycle, state_path, expected_hh_id, None)
    }

    /// [`Self::open_under_lifecycle`] with broadcaster wiring.
    pub fn open_with_broadcaster_under_lifecycle(
        lifecycle: &LifecycleWriteGuard,
        state_path: PathBuf,
        expected_hh_id: &str,
        broadcaster: OwnerEventsBroadcaster,
    ) -> Result<Arc<Self>, EventError> {
        Self::open_inner(lifecycle, state_path, expected_hh_id, Some(broadcaster))
    }

    fn open_inner(
        lifecycle: &LifecycleWriteGuard,
        state_path: PathBuf,
        expected_hh_id: &str,
        broadcaster: Option<OwnerEventsBroadcaster>,
    ) -> Result<Arc<Self>, EventError> {
        lifecycle.verify_state_root(&state_path)?;
        let lifecycle_generation = lifecycle.ensure_lifecycle_generation()?;
        let state_dir = open_directory_path(&state_path)?;
        let household_dir = open_household_dir(&state_dir)?;
        verify_household_record(&household_dir, expected_hh_id)?;
        let log_dir = open_or_create_log_dir(&household_dir)?;
        ensure_log_lock_durable(&log_dir)?;

        let log = Arc::new(Self {
            state_path,
            state_dir,
            household_dir,
            log_dir,
            expected_hh_id: expected_hh_id.to_owned(),
            lifecycle_generation,
            head: AtomicU64::new(0),
            broadcaster,
        });
        // Startup repair is deliberately writer-only. No request can observe
        // the installed household while a torn tail is being truncated.
        let _lock = log.lock_log_exclusive()?;
        log.verify_binding_write(lifecycle)?;
        repair_legacy_log_mode(&log.log_dir)?;
        let head = scan_and_repair_fd(&log.log_dir)?;
        log.head.store(head, Ordering::Release);
        Ok(log)
    }

    /// Highest cursor written.
    pub fn cursor_head(&self) -> u64 {
        self.head.load(Ordering::Acquire)
    }

    /// Append a fresh event signed by the issuer's `M_priv`. The event
    /// is stamped with the next strictly-increasing cursor and the
    /// current unix timestamp. After the durable disk write returns,
    /// the event is published to the broadcaster (if attached) so the
    /// caller never has to remember a separate `publish` call.
    ///
    pub fn append(
        &self,
        lifecycle: &LifecycleReadGuard,
        issuer_m_id: &str,
        issuer_key: &dyn IdentityKey,
        event_type: OwnerEventType,
        payload: OwnerEventPayload,
    ) -> Result<OwnerEvent, EventError> {
        self.append_with_guard(
            OwnerEventGuard::Read(lifecycle),
            issuer_m_id,
            issuer_key,
            event_type,
            payload,
        )
    }

    /// Append while an enclosing lifecycle writer is already held. This keeps
    /// post-commit audit events in the same lifecycle transaction without
    /// dropping exclusive protection merely to reacquire a reader.
    pub fn append_under_lifecycle_write(
        &self,
        lifecycle: &LifecycleWriteGuard,
        issuer_m_id: &str,
        issuer_key: &dyn IdentityKey,
        event_type: OwnerEventType,
        payload: OwnerEventPayload,
    ) -> Result<OwnerEvent, EventError> {
        self.append_with_guard(
            OwnerEventGuard::Write(lifecycle),
            issuer_m_id,
            issuer_key,
            event_type,
            payload,
        )
    }

    /// Append one exact `MachineJoined` terminal side effect, or prove that
    /// the identical event is already durable.
    ///
    /// The candidate machine id is the idempotency key. An existing event is
    /// accepted only when both its issuer and full payload match exactly; a
    /// different payload for the same machine fails closed. This method scans
    /// and stabilizes the tail while holding the append flock, so retry after
    /// [`EventError::MayHaveTakenEffect`] cannot append a duplicate.
    pub fn append_machine_joined_exactly_once_under_lifecycle_write(
        &self,
        lifecycle: &LifecycleWriteGuard,
        issuer_m_id: &str,
        issuer_key: &dyn IdentityKey,
        payload: MachineJoinedPayload,
    ) -> Result<OwnerEvent, EventError> {
        self.verify_binding_write(lifecycle)?;
        let _lock = self.lock_log_exclusive()?;
        self.verify_binding_write(lifecycle)?;
        let head = scan_and_repair_fd(&self.log_dir)?;
        let bytes = read_log_bytes(&self.log_dir)?;
        let (events, valid_len) = decode_length_prefixed(&bytes);
        if valid_len != bytes.len() {
            return Err(EventError::MayHaveTakenEffect {
                stage: EventDurabilityStage::Write,
            });
        }
        for event in events {
            let OwnerEventPayload::MachineJoined(existing) = &event.payload else {
                continue;
            };
            if existing.m_id != payload.m_id {
                continue;
            }
            if existing != &payload || event.issuer_m_id != issuer_m_id {
                return Err(EventError::MachineJoinedConflict);
            }
            stabilize_log_fd(&self.log_dir)?;
            self.head.store(head, Ordering::Release);
            if let Some(broadcaster) = &self.broadcaster {
                let _ = broadcaster.publish(event.clone());
            }
            return Ok(event);
        }
        self.append_new_locked(
            head,
            issuer_m_id,
            issuer_key,
            OwnerEventType::MachineJoined,
            OwnerEventPayload::MachineJoined(payload),
        )
    }

    fn append_with_guard(
        &self,
        lifecycle: OwnerEventGuard<'_>,
        issuer_m_id: &str,
        issuer_key: &dyn IdentityKey,
        event_type: OwnerEventType,
        payload: OwnerEventPayload,
    ) -> Result<OwnerEvent, EventError> {
        if !payload.matches_type(&event_type) {
            return Err(EventError::PayloadTypeMismatch);
        }
        // Lock order is normative: lifecycle first (owned by the caller), log
        // second. The lifecycle binding is rechecked before signing and before
        // any log pathname can be created/opened.
        self.verify_binding(lifecycle)?;
        let _lock = self.lock_log_exclusive()?;
        self.verify_binding(lifecycle)?;
        // The durable tail, not a process-local atomic, allocates cursors. This
        // is what makes independent processes serialize correctly.
        let head = scan_and_repair_fd(&self.log_dir)?;
        self.append_new_locked(head, issuer_m_id, issuer_key, event_type, payload)
    }

    fn append_new_locked(
        &self,
        head: u64,
        issuer_m_id: &str,
        issuer_key: &dyn IdentityKey,
        event_type: OwnerEventType,
        payload: OwnerEventPayload,
    ) -> Result<OwnerEvent, EventError> {
        let cursor = head
            .checked_add(1)
            .ok_or_else(|| EventError::Cbor("cursor overflow".into()))?;
        let ts = unix_now()?;
        let unsigned = OwnerEventUnsigned {
            version: OWNER_EVENT_VERSION,
            cursor,
            ts,
            event_type: event_type.clone(),
            payload: payload.clone(),
            issuer_m_id: issuer_m_id.to_string(),
        };
        let canonical = cbor::to_canonical_vec(&unsigned)
            .map_err(|e| EventError::Cbor(format!("encode: {e}")))?;
        let signature = issuer_key.sign(&canonical)?;
        let event = OwnerEvent {
            version: OWNER_EVENT_VERSION,
            cursor,
            ts,
            event_type,
            payload,
            issuer_m_id: issuer_m_id.to_string(),
            signature,
        };
        let event_bytes = cbor::to_canonical_vec(&event)
            .map_err(|e| EventError::Cbor(format!("encode signed event: {e}")))?;
        if (event_bytes.len() as u64) > MAX_RECORD_BYTES {
            return Err(EventError::Cbor(format!(
                "owner-event record too large: {} bytes (max {MAX_RECORD_BYTES})",
                event_bytes.len()
            )));
        }
        append_length_prefixed_record_fd(&self.log_dir, &event_bytes)?;
        self.head.store(cursor, Ordering::Release);
        if let Some(b) = &self.broadcaster {
            let _ = b.publish(event.clone());
        }
        Ok(event)
    }

    /// Read every event with `cursor > since`. Decoder is tolerant of a
    /// torn trailing record — those are repaired during [`Self::open`]
    /// and never reached here in the steady state.
    pub fn read_since(
        &self,
        lifecycle: &LifecycleReadGuard,
        since: u64,
    ) -> Result<Vec<OwnerEvent>, EventError> {
        self.verify_binding_read(lifecycle)?;
        let _lock = self.lock_log_exclusive()?;
        self.verify_binding_read(lifecycle)?;
        let bytes = read_log_bytes(&self.log_dir)?;
        let (events, _) = decode_length_prefixed(&bytes);
        Ok(events.into_iter().filter(|e| e.cursor > since).collect())
    }

    /// Repair a torn tail during hot reload/recovery. Only the lifecycle
    /// writer can invoke this; normal read paths never mutate recovery state.
    pub fn repair_under_lifecycle(
        &self,
        lifecycle: &LifecycleWriteGuard,
    ) -> Result<u64, EventError> {
        self.verify_binding_write(lifecycle)?;
        let _lock = self.lock_log_exclusive()?;
        self.verify_binding_write(lifecycle)?;
        let head = scan_and_repair_fd(&self.log_dir)?;
        self.head.store(head, Ordering::Release);
        Ok(head)
    }

    fn verify_binding_read(&self, lifecycle: &LifecycleReadGuard) -> Result<(), EventError> {
        lifecycle.verify_state_root(&self.state_path)?;
        if lifecycle.lifecycle_generation()? != Some(self.lifecycle_generation) {
            return Err(EventError::StaleLifecycleBinding);
        }
        self.verify_retained_binding()
    }

    fn verify_binding(&self, lifecycle: OwnerEventGuard<'_>) -> Result<(), EventError> {
        match lifecycle {
            OwnerEventGuard::Read(guard) => self.verify_binding_read(guard),
            OwnerEventGuard::Write(guard) => self.verify_binding_write(guard),
        }
    }

    fn verify_binding_write(&self, lifecycle: &LifecycleWriteGuard) -> Result<(), EventError> {
        lifecycle.verify_state_root(&self.state_path)?;
        if lifecycle.lifecycle_generation()? != Some(self.lifecycle_generation) {
            return Err(EventError::StaleLifecycleBinding);
        }
        self.verify_retained_binding()
    }

    fn verify_retained_binding(&self) -> Result<(), EventError> {
        let reopened = open_directory_path(&self.state_path)?;
        if !same_file(&self.state_dir, &reopened)
            || !named_directory_matches(&self.state_dir, "household", &self.household_dir)
            || !named_directory_matches(&self.household_dir, OWNER_EVENTS_SUBDIR, &self.log_dir)
        {
            return Err(EventError::StaleLifecycleBinding);
        }
        verify_household_record(&self.household_dir, &self.expected_hh_id)
    }

    fn lock_log_exclusive(&self) -> Result<File, EventError> {
        let file = open_lock_existing(&self.log_dir)?;
        FileExt::lock_exclusive(&file)
            .map_err(|error| io_to_event_err(&error, &log_path(&self.state_path)))?;
        validate_regular_file(&self.log_dir, &file, Some(0))?;
        if !named_file_matches(&self.log_dir, OWNER_EVENTS_LOCK_FILENAME, &file) {
            return Err(EventError::StaleLifecycleBinding);
        }
        Ok(file)
    }
}

#[derive(Clone, Copy)]
enum OwnerEventGuard<'a> {
    Read(&'a LifecycleReadGuard),
    Write(&'a LifecycleWriteGuard),
}

fn append_length_prefixed_record_fd(log_dir: &File, payload: &[u8]) -> Result<(), EventError> {
    let mut record = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    record.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    record.extend_from_slice(payload);
    let fd = rustix::fs::openat(
        log_dir,
        OWNER_EVENTS_LOG_FILENAME,
        OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|error| errno_to_event_err(error, OWNER_EVENTS_LOG_FILENAME))?;
    let mut file = File::from(fd);
    validate_regular_file(log_dir, &file, None)?;
    if let Err(_error) = file.write_all(&record) {
        return Err(EventError::MayHaveTakenEffect {
            stage: EventDurabilityStage::Write,
        });
    }
    if file.sync_all().is_err() {
        return Err(EventError::MayHaveTakenEffect {
            stage: EventDurabilityStage::FileSync,
        });
    }
    if owner_event_fail_injection::fail_parent_sync() || log_dir.sync_all().is_err() {
        return Err(EventError::MayHaveTakenEffect {
            stage: EventDurabilityStage::ParentSync,
        });
    }
    Ok(())
}

/// Re-establish the durability barriers for a complete event found during an
/// idempotent retry. This turns a visible tail after an ambiguous append into
/// durable authority before the outbox may be cleared.
fn stabilize_log_fd(log_dir: &File) -> Result<(), EventError> {
    let fd = rustix::fs::openat(
        log_dir,
        OWNER_EVENTS_LOG_FILENAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| errno_to_event_err(error, OWNER_EVENTS_LOG_FILENAME))?;
    let file = File::from(fd);
    validate_regular_file(log_dir, &file, None)?;
    file.sync_all()
        .map_err(|_| EventError::MayHaveTakenEffect {
            stage: EventDurabilityStage::FileSync,
        })?;
    log_dir
        .sync_all()
        .map_err(|_| EventError::MayHaveTakenEffect {
            stage: EventDurabilityStage::ParentSync,
        })
}

fn decode_length_prefixed(bytes: &[u8]) -> (Vec<OwnerEvent>, usize) {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + LENGTH_PREFIX_BYTES <= bytes.len() {
        let mut len_buf = [0u8; LENGTH_PREFIX_BYTES];
        len_buf.copy_from_slice(&bytes[off..off + LENGTH_PREFIX_BYTES]);
        let payload_len = u64::from_be_bytes(len_buf);
        if payload_len > MAX_RECORD_BYTES {
            // Garbage / corruption: stop here, treat as torn tail.
            break;
        }
        let payload_start = off + LENGTH_PREFIX_BYTES;
        // Safe to narrow: payload_len is bounded above by MAX_RECORD_BYTES
        // (1 MiB), well under usize::MAX even on 32-bit targets.
        #[allow(clippy::cast_possible_truncation)]
        let payload_end = payload_start + (payload_len as usize);
        if payload_end > bytes.len() {
            // Partial trailing record — torn write. Stop.
            break;
        }
        let payload = &bytes[payload_start..payload_end];
        match cbor::from_canonical_slice::<OwnerEvent>(payload) {
            Ok(ev) => {
                if ev.payload.matches_type(&ev.event_type) {
                    out.push(ev);
                    off = payload_end;
                } else {
                    // Decoded but inconsistent. This shape is NOT a
                    // typical torn write — it implies a logic bug
                    // produced a record with `event_type` and
                    // `payload` variant disagreeing. Surface it so
                    // the operator can investigate, then stop the
                    // decode (caller treats the rest as torn tail).
                    tracing::warn!(
                        stage = "owner_events.decode.payload_type_mismatch",
                        cursor = ev.cursor,
                        offset = off,
                        "owner-event record has event_type / payload variant mismatch"
                    );
                    break;
                }
            }
            Err(_) => {
                // Decode failed mid-log. Treat as torn tail.
                break;
            }
        }
    }
    (out, off)
}

/// Tighten a legacy world-readable log in place before it is validated.
///
/// Builds before the `0600` requirement created `owner_events/log.cbor`
/// through a path that left it `0644`, and [`validate_regular_file`] now
/// refuses any `mode & 0o077 != 0`. Every installation that paired a phone
/// under an older build therefore fails to open its own installed log on the
/// first boot after updating, with no listener and no migration. The repair
/// runs under the same exclusive log flock as scan-and-repair, and only on a
/// file that already satisfies the ownership, link-count, and name
/// invariants: anything else is left exactly as found so
/// [`validate_regular_file`] still rejects it.
fn repair_legacy_log_mode(log_dir: &File) -> Result<(), EventError> {
    let fd = match rustix::fs::openat(
        log_dir,
        OWNER_EVENTS_LOG_FILENAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(()),
        Err(error) => return Err(errno_to_event_err(error, OWNER_EVENTS_LOG_FILENAME)),
    };
    let file = File::from(fd);
    let parent_meta = log_dir
        .metadata()
        .map_err(|error| io_to_event_err(&error, Path::new(OWNER_EVENTS_SUBDIR)))?;
    let meta = file
        .metadata()
        .map_err(|error| io_to_event_err(&error, Path::new(OWNER_EVENTS_LOG_FILENAME)))?;
    let mode = meta.permissions().mode();
    // Either there is nothing to repair, or the file fails an invariant the
    // repair must not paper over — a second link, a foreign owner, a name that
    // no longer resolves to these bytes. Leave it exactly as found and let
    // `validate_regular_file` reach its own verdict.
    let repairable = mode & 0o077 != 0
        && meta.is_file()
        && meta.uid() == parent_meta.uid()
        && meta.nlink() == 1
        && named_file_matches(log_dir, OWNER_EVENTS_LOG_FILENAME, &file);
    if !repairable {
        return Ok(());
    }
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR)
        .map_err(|error| errno_to_event_err(error, OWNER_EVENTS_LOG_FILENAME))?;
    // Metadata durability, so a crash right after the repair cannot resurrect
    // the old mode on a log this boot already treated as tightened.
    file.sync_all()
        .map_err(|error| io_to_event_err(&error, Path::new(OWNER_EVENTS_LOG_FILENAME)))?;
    log_dir
        .sync_all()
        .map_err(|error| io_to_event_err(&error, Path::new(OWNER_EVENTS_SUBDIR)))?;
    tracing::warn!(
        stage = "owner_events.open.repaired_legacy_log_mode",
        path = OWNER_EVENTS_LOG_FILENAME,
        previous_mode = %format!("{:o}", mode & 0o7777),
        "tightened a pre-0600 owner-event log left by an older build"
    );
    Ok(())
}

fn scan_and_repair_fd(log_dir: &File) -> Result<u64, EventError> {
    let bytes = read_log_bytes(log_dir)?;
    let (events, valid_len) = decode_length_prefixed(&bytes);
    let head = events.last().map_or(0, |e| e.cursor);
    if valid_len < bytes.len() {
        let truncated_bytes = bytes.len() - valid_len;
        tracing::warn!(
            stage = "owner_events.scan_and_repair.truncated_torn_tail",
            path = OWNER_EVENTS_LOG_FILENAME,
            valid_len = valid_len,
            file_len = bytes.len(),
            truncated_bytes = truncated_bytes,
            head_cursor = head,
            "truncated torn trailing record(s) on owner-events log open"
        );
        // Truncate torn tail. set_len + fsync the file + parent dir.
        let fd = rustix::fs::openat(
            log_dir,
            OWNER_EVENTS_LOG_FILENAME,
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| errno_to_event_err(error, OWNER_EVENTS_LOG_FILENAME))?;
        let f = File::from(fd);
        validate_regular_file(log_dir, &f, None)?;
        if f.set_len(valid_len as u64).is_err() {
            return Err(EventError::MayHaveTakenEffect {
                stage: EventDurabilityStage::Write,
            });
        }
        if f.sync_all().is_err() {
            return Err(EventError::MayHaveTakenEffect {
                stage: EventDurabilityStage::FileSync,
            });
        }
        if log_dir.sync_all().is_err() {
            return Err(EventError::MayHaveTakenEffect {
                stage: EventDurabilityStage::ParentSync,
            });
        }
    }
    Ok(head)
}

fn read_log_bytes(log_dir: &File) -> Result<Vec<u8>, EventError> {
    let fd = match rustix::fs::openat(
        log_dir,
        OWNER_EVENTS_LOG_FILENAME,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(Vec::new()),
        Err(error) => return Err(errno_to_event_err(error, OWNER_EVENTS_LOG_FILENAME)),
    };
    let mut file = File::from(fd);
    validate_regular_file(log_dir, &file, None)?;
    let len = file
        .metadata()
        .map_err(|error| io_to_event_err(&error, Path::new(OWNER_EVENTS_LOG_FILENAME)))?
        .len();
    let max_log_bytes = MAX_RECORD_BYTES.saturating_mul(1_000_000);
    if len > max_log_bytes {
        return Err(EventError::Cbor(
            "owner-event log exceeds safety cap".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.read_to_end(&mut bytes)
        .map_err(|error| io_to_event_err(&error, Path::new(OWNER_EVENTS_LOG_FILENAME)))?;
    Ok(bytes)
}

fn open_directory_path(path: &Path) -> Result<File, EventError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| errno_to_event_err(error, path))?;
    Ok(File::from(fd))
}

fn open_household_dir(state_dir: &File) -> Result<File, EventError> {
    let fd = rustix::fs::openat(
        state_dir,
        "household",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| errno_to_event_err(error, "household"))?;
    let dir = File::from(fd);
    validate_directory(state_dir, &dir)?;
    Ok(dir)
}

fn open_or_create_log_dir(household_dir: &File) -> Result<File, EventError> {
    match rustix::fs::mkdirat(household_dir, OWNER_EVENTS_SUBDIR, Mode::RWXU) {
        Ok(()) => household_dir
            .sync_all()
            .map_err(|error| io_to_event_err(&error, Path::new(OWNER_EVENTS_SUBDIR)))?,
        Err(Errno::EXIST) => {}
        Err(error) => return Err(errno_to_event_err(error, OWNER_EVENTS_SUBDIR)),
    }
    let fd = rustix::fs::openat(
        household_dir,
        OWNER_EVENTS_SUBDIR,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| errno_to_event_err(error, OWNER_EVENTS_SUBDIR))?;
    let dir = File::from(fd);
    validate_directory(household_dir, &dir)?;
    Ok(dir)
}

fn ensure_log_lock_durable(log_dir: &File) -> Result<(), EventError> {
    let lock = match rustix::fs::openat(
        log_dir,
        OWNER_EVENTS_LOCK_FILENAME,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => File::from(fd),
        Err(Errno::EXIST) => open_lock_existing(log_dir)?,
        Err(error) => return Err(errno_to_event_err(error, OWNER_EVENTS_LOCK_FILENAME)),
    };
    validate_regular_file(log_dir, &lock, Some(0))?;
    lock.sync_all()
        .map_err(|error| io_to_event_err(&error, Path::new(OWNER_EVENTS_LOCK_FILENAME)))?;
    // Unconditional. A previous creator may have made the lock visible and
    // lost the parent acknowledgement.
    log_dir
        .sync_all()
        .map_err(|error| io_to_event_err(&error, Path::new(OWNER_EVENTS_SUBDIR)))?;
    if !named_file_matches(log_dir, OWNER_EVENTS_LOCK_FILENAME, &lock) {
        return Err(EventError::StaleLifecycleBinding);
    }
    Ok(())
}

fn open_lock_existing(log_dir: &File) -> Result<File, EventError> {
    let fd = rustix::fs::openat(
        log_dir,
        OWNER_EVENTS_LOCK_FILENAME,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| errno_to_event_err(error, OWNER_EVENTS_LOCK_FILENAME))?;
    Ok(File::from(fd))
}

fn verify_household_record(household_dir: &File, expected_hh_id: &str) -> Result<(), EventError> {
    let fd = rustix::fs::openat(
        household_dir,
        "household_record.cbor",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| errno_to_event_err(error, "household_record.cbor"))?;
    let mut file = File::from(fd);
    validate_regular_file(household_dir, &file, None)?;
    let len = file
        .metadata()
        .map_err(|error| io_to_event_err(&error, Path::new("household_record.cbor")))?
        .len();
    if len > MAX_HOUSEHOLD_RECORD_BYTES {
        return Err(EventError::Cbor(
            "household record exceeds safety cap".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    file.read_to_end(&mut bytes)
        .map_err(|error| io_to_event_err(&error, Path::new("household_record.cbor")))?;
    let record: HouseholdRecord = cbor::from_canonical_slice(&bytes)
        .map_err(|error| EventError::Cbor(format!("household record: {error}")))?;
    record
        .validate()
        .map_err(|error| EventError::Cbor(format!("household record: {error}")))?;
    if record.hh_id.to_string() != expected_hh_id {
        return Err(EventError::StaleLifecycleBinding);
    }
    Ok(())
}

fn validate_directory(parent: &File, dir: &File) -> Result<(), EventError> {
    let parent_meta = parent
        .metadata()
        .map_err(|error| io_to_event_err(&error, Path::new("parent")))?;
    let meta = dir
        .metadata()
        .map_err(|error| io_to_event_err(&error, Path::new("directory")))?;
    if !meta.is_dir() || meta.uid() != parent_meta.uid() || meta.permissions().mode() & 0o022 != 0 {
        return Err(EventError::StaleLifecycleBinding);
    }
    Ok(())
}

fn validate_regular_file(
    parent: &File,
    file: &File,
    expected_len: Option<u64>,
) -> Result<(), EventError> {
    let parent_meta = parent
        .metadata()
        .map_err(|error| io_to_event_err(&error, Path::new("parent")))?;
    let meta = file
        .metadata()
        .map_err(|error| io_to_event_err(&error, Path::new("file")))?;
    if !meta.is_file()
        || meta.uid() != parent_meta.uid()
        || meta.nlink() != 1
        || meta.permissions().mode() & 0o077 != 0
        || expected_len.is_some_and(|len| meta.len() != len)
    {
        return Err(EventError::StaleLifecycleBinding);
    }
    Ok(())
}

fn named_directory_matches(parent: &File, name: &str, dir: &File) -> bool {
    let Ok(named) = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return false;
    };
    let Ok(opened) = rustix::fs::fstat(dir) else {
        return false;
    };
    named.st_dev == opened.st_dev && named.st_ino == opened.st_ino
}

fn named_file_matches(parent: &File, name: &str, file: &File) -> bool {
    named_directory_matches(parent, name, file)
}

fn same_file(left: &File, right: &File) -> bool {
    left.metadata()
        .ok()
        .zip(right.metadata().ok())
        .is_some_and(|(left, right)| left.dev() == right.dev() && left.ino() == right.ino())
}

fn errno_to_event_err(error: Errno, path: impl AsRef<Path>) -> EventError {
    let io = std::io::Error::from_raw_os_error(error.raw_os_error());
    io_to_event_err(&io, path.as_ref())
}

#[cfg(test)]
mod owner_event_fail_injection {
    use std::cell::Cell;

    thread_local! {
        static FAIL_PARENT_SYNC: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn force_parent_sync_failure_once() {
        FAIL_PARENT_SYNC.with(|value| value.set(true));
    }

    pub(super) fn fail_parent_sync() -> bool {
        FAIL_PARENT_SYNC.with(|value| value.replace(false))
    }
}

#[cfg(not(test))]
mod owner_event_fail_injection {
    pub(super) const fn fail_parent_sync() -> bool {
        false
    }
}

fn io_to_event_err(e: &std::io::Error, path: &Path) -> EventError {
    EventError::Storage(StorageError::Io {
        path: path.to_path_buf(),
        kind: format!("{:?}", e.kind()),
        hint: e.to_string(),
    })
}

#[must_use]
pub fn log_dir(state_dir: &Path) -> PathBuf {
    crate::storage::household_dir(state_dir).join("owner_events")
}

#[must_use]
pub fn log_path(state_dir: &Path) -> PathBuf {
    log_dir(state_dir).join("log.cbor")
}

fn unix_now() -> Result<u64, EventError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| EventError::ClockSkew)
}

#[cfg(test)]
mod lifecycle_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;
    use crate::household_lifecycle::HouseholdLifecycleLock;
    use crate::ids::{derive_household_id, derive_machine_id};
    use crate::keys::P256Keypair;

    const CHILD_STATE_ENV: &str = "THEYOS_OWNER_EVENT_CHILD_STATE";
    const CHILD_HH_ENV: &str = "THEYOS_OWNER_EVENT_CHILD_HH";
    const CHILD_INDEX_ENV: &str = "THEYOS_OWNER_EVENT_CHILD_INDEX";
    const CHILD_TEST: &str = "owner_events::lifecycle_tests::multiprocess_append_worker";

    struct Fixture {
        state: TempDir,
        lifecycle: HouseholdLifecycleLock,
        hh_id: String,
        log: Arc<OwnerEventLog>,
    }

    fn record() -> HouseholdRecord {
        let household = P256Keypair::generate();
        let machine = P256Keypair::generate();
        let hh_pub = household.public();
        let m_pub = machine.public();
        HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: derive_household_id(&hh_pub),
            hh_pub,
            name: "Owner Event Test".into(),
            created_at: 1_714_972_800,
            shamir_k: 1,
            shamir_n: 1,
            members: vec![derive_machine_id(&m_pub)],
            is_follower: false,
        }
    }

    fn install_record(state: &Path, record: &HouseholdRecord) {
        let household = crate::storage::household_dir(state);
        fs::create_dir(&household).unwrap();
        fs::set_permissions(&household, fs::Permissions::from_mode(0o700)).unwrap();
        crate::storage::atomic_write_cbor(&crate::storage::household_record_path(state), record)
            .unwrap();
    }

    fn fixture(broadcaster: Option<OwnerEventsBroadcaster>) -> Fixture {
        let state = TempDir::new().unwrap();
        let record = record();
        let hh_id = record.hh_id.to_string();
        install_record(state.path(), &record);
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        let log = match broadcaster {
            Some(broadcaster) => OwnerEventLog::open_with_broadcaster_under_lifecycle(
                &write,
                state.path().to_path_buf(),
                &hh_id,
                broadcaster,
            )
            .unwrap(),
            None => OwnerEventLog::open_under_lifecycle(&write, state.path().to_path_buf(), &hh_id)
                .unwrap(),
        };
        drop(write);
        Fixture {
            state,
            lifecycle,
            hh_id,
            log,
        }
    }

    fn payload() -> OwnerEventPayload {
        OwnerEventPayload::JoinRequest(JoinRequestPayload {
            join_request_cbor: ByteBuf::from(vec![0xa1, 0x01, 0x01]),
            fingerprint: "owner-event-test".into(),
            expiry: 1_714_972_800,
        })
    }

    #[test]
    fn stale_generation_handle_cannot_recreate_owner_events_in_reinstalled_household() {
        let fixture = fixture(None);
        let stale_log = Arc::clone(&fixture.log);
        let original: HouseholdRecord = crate::storage::read_optional_cbor(
            &crate::storage::household_record_path(fixture.state.path()),
        )
        .unwrap()
        .unwrap();

        let write = fixture.lifecycle.lock_exclusive().unwrap();
        assert!(write.rename_household_to_tearing_down().unwrap());
        assert!(write.remove_tearing_down().unwrap());
        // Reinstall the original canonical record bytes under a fresh
        // lifecycle generation. Same hh_id, same public root: only the
        // generation distinguishes the authority instance.
        write.reserve_household_install_generation().unwrap();
        install_record(fixture.state.path(), &original);
        drop(write);

        let read = fixture.lifecycle.lock_shared().unwrap();
        let err = stale_log
            .append(
                &read,
                "m_test_issuer",
                &P256Keypair::generate(),
                OwnerEventType::JoinRequest,
                payload(),
            )
            .unwrap_err();
        assert!(matches!(err, EventError::StaleLifecycleBinding));
        assert!(!log_dir(fixture.state.path()).exists());
    }

    #[test]
    fn parent_sync_indeterminate_does_not_publish_head_or_broadcast() {
        let broadcaster = OwnerEventsBroadcaster::new();
        let mut subscriber = broadcaster.subscribe();
        let fixture = fixture(Some(broadcaster));
        let read = fixture.lifecycle.lock_shared().unwrap();
        owner_event_fail_injection::force_parent_sync_failure_once();
        let error = fixture
            .log
            .append(
                &read,
                "m_test_issuer",
                &P256Keypair::generate(),
                OwnerEventType::JoinRequest,
                payload(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            EventError::MayHaveTakenEffect {
                stage: EventDurabilityStage::ParentSync
            }
        ));
        assert_eq!(fixture.log.cursor_head(), 0);
        assert!(matches!(
            subscriber.receiver_mut().try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn machine_joined_retry_after_ambiguous_append_stabilizes_without_duplicate() {
        let fixture = fixture(None);
        let issuer = P256Keypair::generate();
        let payload = MachineJoinedPayload {
            m_pub: ByteBuf::from(vec![2; 33]),
            m_id: "m_exact_candidate".into(),
            hostname: "candidate".into(),
            joined_at: 1_714_972_801,
        };
        let write = fixture.lifecycle.lock_exclusive().unwrap();
        owner_event_fail_injection::force_parent_sync_failure_once();
        let first = fixture
            .log
            .append_machine_joined_exactly_once_under_lifecycle_write(
                &write,
                "m_test_issuer",
                &issuer,
                payload.clone(),
            )
            .unwrap_err();
        assert!(matches!(
            first,
            EventError::MayHaveTakenEffect {
                stage: EventDurabilityStage::ParentSync
            }
        ));
        let recovered = fixture
            .log
            .append_machine_joined_exactly_once_under_lifecycle_write(
                &write,
                "m_test_issuer",
                &issuer,
                payload,
            )
            .expect("retry must find, stabilize, and reuse the exact tail event");
        assert_eq!(recovered.cursor, 1);
        drop(write);

        let read = fixture.lifecycle.lock_shared().unwrap();
        let events = fixture.log.read_since(&read, 0).unwrap();
        assert_eq!(
            events.len(),
            1,
            "ambiguous retry must not duplicate the event"
        );
    }

    #[test]
    fn machine_joined_same_machine_with_different_payload_fails_closed() {
        let fixture = fixture(None);
        let issuer = P256Keypair::generate();
        let payload = MachineJoinedPayload {
            m_pub: ByteBuf::from(vec![2; 33]),
            m_id: "m_exact_candidate".into(),
            hostname: "candidate".into(),
            joined_at: 1_714_972_801,
        };
        let write = fixture.lifecycle.lock_exclusive().unwrap();
        fixture
            .log
            .append_machine_joined_exactly_once_under_lifecycle_write(
                &write,
                "m_test_issuer",
                &issuer,
                payload.clone(),
            )
            .unwrap();
        let mut divergent = payload;
        divergent.hostname = "replacement".into();
        let error = fixture
            .log
            .append_machine_joined_exactly_once_under_lifecycle_write(
                &write,
                "m_test_issuer",
                &issuer,
                divergent,
            )
            .unwrap_err();
        assert!(matches!(error, EventError::MachineJoinedConflict));
    }

    #[test]
    fn household_id_mismatch_is_rejected_before_log_path_creation() {
        let state = TempDir::new().unwrap();
        let installed = record();
        install_record(state.path(), &installed);
        let lifecycle = HouseholdLifecycleLock::open_verified(state.path()).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        let result = OwnerEventLog::open_under_lifecycle(
            &write,
            state.path().to_path_buf(),
            "hh_intentionally-not-the-installed-household",
        );
        let Err(error) = result else {
            panic!("mismatched household id must not open the log");
        };
        assert!(matches!(error, EventError::StaleLifecycleBinding));
        assert!(!log_dir(state.path()).exists());
    }

    /// A log written by a build that predates the `0600` requirement. Every
    /// installation that paired a phone before that change carries one, and
    /// without the in-place repair the first boot after updating cannot open
    /// its own installed log — which is exactly the fixture that was missing
    /// when the requirement landed.
    #[test]
    fn legacy_world_readable_log_is_repaired_instead_of_rejected() {
        let fixture = fixture(None);
        let read = fixture.lifecycle.lock_shared().unwrap();
        let appended = fixture
            .log
            .append(
                &read,
                "m_test_issuer",
                &P256Keypair::generate(),
                OwnerEventType::JoinRequest,
                payload(),
            )
            .unwrap();
        drop(read);

        let path = log_path(fixture.state.path());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let write = fixture.lifecycle.lock_exclusive().unwrap();
        let reopened = OwnerEventLog::open_under_lifecycle(
            &write,
            fixture.state.path().to_path_buf(),
            &fixture.hh_id,
        )
        .expect("a pre-0600 log left by an older build must be repaired, not refused");
        drop(write);

        assert_eq!(reopened.cursor_head(), appended.cursor);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600,
            "the repair must tighten the log in place",
        );
    }

    /// The repair is not a way around the invariant. A second link means the
    /// mode cannot be tightened for every name the bytes answer to, so the
    /// file is left as found and validation still refuses it.
    #[test]
    fn multiply_linked_world_readable_log_is_left_alone_and_still_rejected() {
        let fixture = fixture(None);
        let read = fixture.lifecycle.lock_shared().unwrap();
        fixture
            .log
            .append(
                &read,
                "m_test_issuer",
                &P256Keypair::generate(),
                OwnerEventType::JoinRequest,
                payload(),
            )
            .unwrap();
        drop(read);

        let path = log_path(fixture.state.path());
        let second_link = log_dir(fixture.state.path()).join("log.cbor.link");
        fs::hard_link(&path, &second_link).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let write = fixture.lifecycle.lock_exclusive().unwrap();
        let result = OwnerEventLog::open_under_lifecycle(
            &write,
            fixture.state.path().to_path_buf(),
            &fixture.hh_id,
        );
        drop(write);

        let Err(error) = result else {
            panic!("a multiply linked log must not be opened");
        };
        assert!(matches!(error, EventError::StaleLifecycleBinding));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o644,
            "a log that fails the guard must not be touched",
        );
    }

    #[test]
    fn multiprocess_append_worker() {
        let Ok(state) = std::env::var(CHILD_STATE_ENV) else {
            return;
        };
        let hh_id = std::env::var(CHILD_HH_ENV).unwrap();
        let index = std::env::var(CHILD_INDEX_ENV).unwrap();
        let state = PathBuf::from(state);
        let lifecycle = HouseholdLifecycleLock::open_verified(&state).unwrap();
        let write = lifecycle.lock_exclusive().unwrap();
        let log = OwnerEventLog::open_under_lifecycle(&write, state.clone(), &hh_id).unwrap();
        drop(write);
        fs::write(state.join(format!("ready-{index}")), b"ready").unwrap();
        while !state.join("go").exists() {
            thread::sleep(Duration::from_millis(2));
        }
        let read = lifecycle.lock_shared().unwrap();
        log.append(
            &read,
            "m_test_issuer",
            &P256Keypair::generate(),
            OwnerEventType::JoinRequest,
            payload(),
        )
        .unwrap();
    }

    #[test]
    fn multiprocess_append_allocates_unique_durable_cursors() {
        if std::env::var_os(CHILD_STATE_ENV).is_some() {
            return;
        }
        let fixture = fixture(None);
        drop(fixture.log);
        let executable = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        for index in 0..6 {
            children.push(
                Command::new(&executable)
                    .arg("--exact")
                    .arg(CHILD_TEST)
                    .arg("--nocapture")
                    .env(CHILD_STATE_ENV, fixture.state.path())
                    .env(CHILD_HH_ENV, &fixture.hh_id)
                    .env(CHILD_INDEX_ENV, index.to_string())
                    .spawn()
                    .unwrap(),
            );
        }
        while (0..6)
            .filter(|index| fixture.state.path().join(format!("ready-{index}")).exists())
            .count()
            != 6
        {
            thread::sleep(Duration::from_millis(2));
        }
        fs::write(fixture.state.path().join("go"), b"go").unwrap();
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }

        let write = fixture.lifecycle.lock_exclusive().unwrap();
        let log = OwnerEventLog::open_under_lifecycle(
            &write,
            fixture.state.path().to_path_buf(),
            &fixture.hh_id,
        )
        .unwrap();
        drop(write);
        let read = fixture.lifecycle.lock_shared().unwrap();
        let events = log.read_since(&read, 0).unwrap();
        assert_eq!(events.len(), 6);
        assert_eq!(
            events.iter().map(|event| event.cursor).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5, 6]
        );
    }
}

// ---------------------------------------------------------------------------
// Broadcaster
// ---------------------------------------------------------------------------

const BROADCAST_CAPACITY: usize = 32;

/// In-process broadcaster fed by [`OwnerEventLog::append`]. Long-poll
/// subscribers wake within ~1 ms. Lagged subscribers re-poll from disk
/// via [`OwnerEventLog::read_since`].
#[derive(Clone)]
pub struct OwnerEventsBroadcaster {
    inner: Arc<OwnerEventsBroadcasterInner>,
}

struct OwnerEventsBroadcasterInner {
    tx: broadcast::Sender<OwnerEvent>,
    /// Number of currently-active subscribers, used by the APNS
    /// dispatcher to decide whether the iPhone needs a push tickle.
    /// Atomic so the [`SubscriptionGuard`] can decrement on `Drop`
    /// without spawning a tokio task — that pattern was found to leak
    /// the count on shutdown when the runtime was already torn down.
    subscriber_count: AtomicUsize,
}

impl OwnerEventsBroadcaster {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            inner: Arc::new(OwnerEventsBroadcasterInner {
                tx,
                subscriber_count: AtomicUsize::new(0),
            }),
        }
    }

    /// Subscribe and return a [`SubscriptionGuard`] that decrements
    /// the active-subscriber counter on drop.
    #[must_use]
    pub fn subscribe(&self) -> SubscriptionGuard {
        let rx = self.inner.tx.subscribe();
        self.inner.subscriber_count.fetch_add(1, Ordering::AcqRel);
        SubscriptionGuard {
            rx: Some(rx),
            inner: Arc::clone(&self.inner),
            decremented: false,
        }
    }

    /// Snapshot the current active-subscriber count.
    #[must_use]
    pub fn active_subscribers(&self) -> usize {
        self.inner.subscriber_count.load(Ordering::Acquire)
    }

    /// Publish an event. Returns the number of receivers the message
    /// reached (lagged subscribers do not count). Best-effort — the
    /// disk write must already have happened.
    #[must_use]
    pub fn publish(&self, event: OwnerEvent) -> usize {
        self.inner.tx.send(event).unwrap_or(0)
    }
}

impl Default for OwnerEventsBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII handle returned by [`OwnerEventsBroadcaster::subscribe`].
pub struct SubscriptionGuard {
    rx: Option<broadcast::Receiver<OwnerEvent>>,
    inner: Arc<OwnerEventsBroadcasterInner>,
    decremented: bool,
}

impl SubscriptionGuard {
    /// Borrow the underlying broadcast receiver.
    ///
    /// # Panics
    ///
    /// Panics if called after this guard has been moved out of (the
    /// inner receiver is taken on `Drop`). In normal use the guard
    /// lives for the duration of a long-poll request, so this never
    /// fires.
    pub fn receiver_mut(&mut self) -> &mut broadcast::Receiver<OwnerEvent> {
        self.rx.as_mut().expect("subscription not yet dropped")
    }
}

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        if !self.decremented && self.rx.take().is_some() {
            self.decremented = true;
            // Atomic decrement: never spawns a task, runs even after the
            // tokio runtime has been shut down.
            self.inner
                .subscriber_count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    if n == 0 { None } else { Some(n - 1) }
                })
                .ok();
        }
    }
}

// ---------------------------------------------------------------------------
// Owner device push-token registry (T023/T024)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerDevicePushToken {
    #[serde(rename = "v")]
    pub version: u8,
    pub p_id: String,
    pub platform: String,
    pub push_token: ByteBuf,
    pub updated_at: u64,
}

#[derive(Debug, Error)]
pub enum PushTokenError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("unsupported platform: {0:?} (only \"ios\" is accepted in Phase 3)")]
    UnsupportedPlatform(String),
    #[error("invalid v: {0}")]
    BadVersion(u8),
}

#[must_use]
pub fn owner_push_token_path(state_dir: &Path) -> PathBuf {
    crate::storage::household_dir(state_dir).join("owner_device_push_token.cbor")
}

pub fn put_owner_push_token(
    state_dir: &Path,
    token: &OwnerDevicePushToken,
) -> Result<(), PushTokenError> {
    if token.version != OWNER_EVENT_VERSION {
        return Err(PushTokenError::BadVersion(token.version));
    }
    if token.platform != "ios" {
        return Err(PushTokenError::UnsupportedPlatform(token.platform.clone()));
    }
    crate::storage::atomic_write_cbor(&owner_push_token_path(state_dir), token)?;
    Ok(())
}

pub fn get_owner_push_token(
    state_dir: &Path,
) -> Result<Option<OwnerDevicePushToken>, PushTokenError> {
    let token: Option<OwnerDevicePushToken> =
        crate::storage::read_optional_cbor(&owner_push_token_path(state_dir))?;
    if let Some(ref t) = token {
        if t.platform != "ios" {
            return Err(PushTokenError::UnsupportedPlatform(t.platform.clone()));
        }
    }
    Ok(token)
}

#[allow(dead_code)]
fn _unused_household_error_anchor(_: HouseholdError) {}

// Suppress unused-import warning for `Read` on platforms where the
// trait method is reached only via blanket impls.
#[allow(dead_code)]
fn _force_read_trait_in_use<R: Read>(_: R) {}
