//! Phase 3 owner-events append log + broadcaster + push-token
//! registry (`contracts/owner-events.md`,
//! `contracts/push-token-register.md`).
//!
//! - [`OwnerEvent`] is the signed log entry the iPhone consumes via
//!   long-poll. Each event is signed by the issuer's `M_priv`; the
//!   iPhone verifies the signature against the issuer's
//!   [`crate::MachineCert`] chained to the household root.
//! - [`OwnerEventLog`] is the long-lived handle that owns the
//!   serialization mutex, the in-memory cursor head, and the
//!   broadcaster wiring. Every append goes through it so concurrent
//!   producers cannot race the cursor.
//! - On-disk records are **length-prefixed**: every event is written as
//!   `<u64 BE length><canonical CBOR>`. On boot the log is scanned and
//!   any partial trailing record (e.g., from a torn write) is
//!   truncated. Without the prefix, a single torn append would corrupt
//!   the entire log.
//! - [`OwnerEventsBroadcaster`] wraps a `tokio::sync::broadcast`
//!   channel so the long-poll handler wakes within ~1 ms.
//! - [`OwnerDevicePushToken`] is the persisted push-token registry
//!   entry, written by the PoP-authenticated `push-token` endpoint.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;
use tokio::sync::broadcast;

use crate::cbor;
use crate::error::{HouseholdError, StorageError};
use crate::keys::{IdentityKey, P256Signature};

pub const OWNER_EVENT_VERSION: u8 = 1;

/// Type tag for [`OwnerEvent`] entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerEventType {
    JoinRequest,
    MachineJoined,
    JoinCancelled,
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
}

const LENGTH_PREFIX_BYTES: usize = 8;
const MAX_RECORD_BYTES: u64 = 1 << 20; // 1 MiB hard cap per event

/// Long-lived owner-events log handle.
///
/// Owns the per-state-dir append serialization (a [`std::sync::Mutex`]
/// held briefly across one disk write per call) and the in-memory
/// cursor head. Optionally fans appended events out to an attached
/// [`OwnerEventsBroadcaster`] so long-poll subscribers never see a
/// disk-on-its-own state where the broadcaster forgets to publish.
///
/// Construct via [`Self::open`] (no broadcaster) or
/// [`Self::open_with_broadcaster`]. Both perform a one-shot scan-and-
/// repair pass over `owner_events/log.cbor` so the daemon recovers from
/// a torn-write left by an unclean shutdown.
pub struct OwnerEventLog {
    state_dir: PathBuf,
    head: AtomicU64,
    append_mu: std::sync::Mutex<()>,
    broadcaster: Option<OwnerEventsBroadcaster>,
}

impl OwnerEventLog {
    /// Open the log without a broadcaster.
    pub fn open(state_dir: PathBuf) -> Result<Arc<Self>, EventError> {
        let head = scan_and_repair(&state_dir)?;
        Ok(Arc::new(Self {
            state_dir,
            head: AtomicU64::new(head),
            append_mu: std::sync::Mutex::new(()),
            broadcaster: None,
        }))
    }

    /// Open the log with a broadcaster pre-wired.
    pub fn open_with_broadcaster(
        state_dir: PathBuf,
        broadcaster: OwnerEventsBroadcaster,
    ) -> Result<Arc<Self>, EventError> {
        let head = scan_and_repair(&state_dir)?;
        Ok(Arc::new(Self {
            state_dir,
            head: AtomicU64::new(head),
            append_mu: std::sync::Mutex::new(()),
            broadcaster: Some(broadcaster),
        }))
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
        issuer_m_id: &str,
        issuer_key: &dyn IdentityKey,
        event_type: OwnerEventType,
        payload: OwnerEventPayload,
    ) -> Result<OwnerEvent, EventError> {
        if !payload.matches_type(&event_type) {
            return Err(EventError::PayloadTypeMismatch);
        }
        // Serialize concurrent appenders. Critical section is short:
        // one canonical encode + one fsync. Held with std mutex (not
        // tokio) — caller is async but the wait is bounded.
        //
        // Mutex-poison recovery: a panic inside this critical section
        // does NOT corrupt mutable state (we hold no `&mut` invariant
        // outside the lock — the file is append-only and the cursor
        // moves only on success). So `into_inner()` on a poisoned
        // guard is safe and prevents a single panic from bricking the
        // log for the rest of process lifetime.
        let _guard = self
            .append_mu
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let head = self.head.load(Ordering::Acquire);
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
        append_length_prefixed_record(&self.state_dir, &event_bytes)?;
        self.head.store(cursor, Ordering::Release);
        if let Some(b) = &self.broadcaster {
            let _ = b.publish(event.clone());
        }
        Ok(event)
    }

    /// Read every event with `cursor > since`. Decoder is tolerant of a
    /// torn trailing record — those are repaired during [`Self::open`]
    /// and never reached here in the steady state.
    pub fn read_since(&self, since: u64) -> Result<Vec<OwnerEvent>, EventError> {
        let path = log_path(&self.state_dir);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_to_event_err(&e, &path)),
        };
        let (events, _) = decode_length_prefixed(&bytes);
        Ok(events.into_iter().filter(|e| e.cursor > since).collect())
    }
}

fn append_length_prefixed_record(state_dir: &Path, payload: &[u8]) -> Result<(), EventError> {
    let dir = log_dir(state_dir);
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| io_to_event_err(&e, &dir))?;
    }
    let path = log_path(state_dir);
    let mut record = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    record.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    record.extend_from_slice(payload);

    // Capture pre-write file length so we can truncate back to it on
    // any partial-write failure. Without this rollback, an ENOSPC
    // (or any I/O error) midway through `write_all` would leave a
    // torn tail on disk that no other reader trims until the next
    // process boot's `scan_and_repair`. Subsequent successful
    // appends would land *after* the torn bytes, and `read_since`
    // (which stops at the first decode failure) would silently lose
    // every event that came after the partial write.
    let pre_size: u64 = match std::fs::metadata(&path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(io_to_event_err(&e, &path)),
    };

    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .map_err(|e| io_to_event_err(&e, &path))?;
    if let Err(e) = f.write_all(&record) {
        // Roll back any partially-written bytes. Best-effort: if the
        // truncate or fsync below also fails, we still return the
        // original error so the caller knows the append failed.
        if let Ok(rw) = std::fs::OpenOptions::new().write(true).open(&path) {
            let _ = rw.set_len(pre_size);
            let _ = rw.sync_all();
        }
        if let Ok(parent) = std::fs::File::open(&dir) {
            let _ = parent.sync_all();
        }
        return Err(io_to_event_err(&e, &path));
    }
    if let Err(e) = f.sync_all() {
        if let Ok(rw) = std::fs::OpenOptions::new().write(true).open(&path) {
            let _ = rw.set_len(pre_size);
            let _ = rw.sync_all();
        }
        if let Ok(parent) = std::fs::File::open(&dir) {
            let _ = parent.sync_all();
        }
        return Err(io_to_event_err(&e, &path));
    }
    drop(f);
    // Parent-dir fsync so the new file size is durable.
    if let Ok(parent) = std::fs::File::open(&dir) {
        let _ = parent.sync_all();
    }
    Ok(())
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

fn scan_and_repair(state_dir: &Path) -> Result<u64, EventError> {
    let path = log_path(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(io_to_event_err(&e, &path)),
    };
    let (events, valid_len) = decode_length_prefixed(&bytes);
    let head = events.last().map_or(0, |e| e.cursor);
    if valid_len < bytes.len() {
        let truncated_bytes = bytes.len() - valid_len;
        tracing::warn!(
            stage = "owner_events.scan_and_repair.truncated_torn_tail",
            path = %path.display(),
            valid_len = valid_len,
            file_len = bytes.len(),
            truncated_bytes = truncated_bytes,
            head_cursor = head,
            "truncated torn trailing record(s) on owner-events log open"
        );
        // Truncate torn tail. set_len + fsync the file + parent dir.
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| io_to_event_err(&e, &path))?;
        f.set_len(valid_len as u64)
            .map_err(|e| io_to_event_err(&e, &path))?;
        f.sync_all().map_err(|e| io_to_event_err(&e, &path))?;
        drop(f);
        if let Ok(parent) = std::fs::File::open(log_dir(state_dir)) {
            let _ = parent.sync_all();
        }
    }
    Ok(head)
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

// ---------------------------------------------------------------------------
// Backwards-compat free functions (process-wide shared registry)
// ---------------------------------------------------------------------------
//
// These wrappers exist for tests and migration. They MUST share state
// across calls — otherwise two concurrent `append_event(state_dir,
// ...)` invocations would each open a fresh `OwnerEventLog` with its
// own AtomicU64 + Mutex, and the cursor TOCTOU we just fixed inside
// the handle would re-emerge at the API boundary.
//
// Solution: a process-wide registry keyed by canonical `state_dir`.
// Every free-function call resolves the same `Arc<OwnerEventLog>` and
// thus the same lock + cursor head. Production code (T035+) should
// inject the `Arc<OwnerEventLog>` explicitly into request handlers
// rather than going through this registry; the registry exists so the
// safe path is the default for tests and ad-hoc callers.

use std::collections::HashMap;
use std::sync::OnceLock;

static OWNER_EVENT_LOG_REGISTRY: OnceLock<std::sync::Mutex<HashMap<PathBuf, Arc<OwnerEventLog>>>> =
    OnceLock::new();

fn registry() -> &'static std::sync::Mutex<HashMap<PathBuf, Arc<OwnerEventLog>>> {
    OWNER_EVENT_LOG_REGISTRY.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn shared_log_for(state_dir: &Path) -> Result<Arc<OwnerEventLog>, EventError> {
    // Canonicalize so two paths that resolve to the same directory
    // (e.g., one with a trailing slash, or via a symlink) share the
    // same log handle. Falls back to the literal path if
    // canonicalize fails (path may not yet exist on first use).
    let canonical = std::fs::canonicalize(state_dir).unwrap_or_else(|_| state_dir.to_path_buf());
    {
        // Recover from poisoning: the only mutation is inserting into
        // the map, so a poisoned guard is still safe to read.
        let map = registry()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(log) = map.get(&canonical) {
            return Ok(Arc::clone(log));
        }
    }
    // Slow path: open and insert. Re-check after acquiring the lock to
    // race-free against another caller doing the same.
    let mut map = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(log) = map.get(&canonical) {
        return Ok(Arc::clone(log));
    }
    let log = OwnerEventLog::open(canonical.clone())?;
    map.insert(canonical, Arc::clone(&log));
    Ok(log)
}

/// Append an event via the process-shared log handle for `state_dir`.
/// Concurrent free-function callers see the same `AtomicU64` cursor
/// and the same append mutex.
pub fn append_event(
    state_dir: &Path,
    issuer_m_id: &str,
    issuer_key: &dyn IdentityKey,
    event_type: OwnerEventType,
    payload: OwnerEventPayload,
) -> Result<OwnerEvent, EventError> {
    let log = shared_log_for(state_dir)?;
    log.append(issuer_m_id, issuer_key, event_type, payload)
}

/// Read every event with `cursor > since`. Routes through the shared
/// per-state-dir handle.
pub fn read_events_since(state_dir: &Path, since: u64) -> Result<Vec<OwnerEvent>, EventError> {
    let log = shared_log_for(state_dir)?;
    log.read_since(since)
}

/// Return the highest cursor (in-memory snapshot from the shared
/// handle). The log itself is the authoritative source of truth.
pub fn cursor_head(state_dir: &Path) -> Result<u64, EventError> {
    let log = shared_log_for(state_dir)?;
    Ok(log.cursor_head())
}

/// Test-only helper: drain the process-wide free-fn registry so a
/// test that recreates `state_dir` after deleting it doesn't see a
/// stale `OwnerEventLog` from a previous test in the same process.
#[doc(hidden)]
pub fn _reset_registry_for_tests() {
    if let Some(m) = OWNER_EVENT_LOG_REGISTRY.get() {
        let mut map = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        map.clear();
    }
}

/// Read the raw on-disk log bytes (test-only helper).
#[doc(hidden)]
pub fn read_raw_log(state_dir: &Path) -> Result<Vec<u8>, EventError> {
    let path = log_path(state_dir);
    match std::fs::read(&path) {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(io_to_event_err(&e, &path)),
    }
}

/// Append raw bytes to the log without going through the encoder. Used
/// by torn-write tests to simulate corruption.
#[doc(hidden)]
pub fn append_raw_for_test(state_dir: &Path, bytes: &[u8]) -> Result<(), EventError> {
    let dir = log_dir(state_dir);
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| io_to_event_err(&e, &dir))?;
    }
    let path = log_path(state_dir);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .map_err(|e| io_to_event_err(&e, &path))?;
    f.write_all(bytes).map_err(|e| io_to_event_err(&e, &path))?;
    f.sync_all().map_err(|e| io_to_event_err(&e, &path))?;
    Ok(())
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
