//! Phase 3 machine-join ceremony types and state machine.
//!
//! - [`JoinChallenge`] / [`JoinRequest`] — wire shapes per
//!   `specs/003-machine-join/data-model.md`.
//! - [`verify_join_request`] — canonical-CBOR + signature validation
//!   used by the founding machine before staging the ceremony.
//! - [`PairMachineWindow`] — single-active-ceremony state machine on
//!   M1, persisted in the current generation-scoped pair-window namespace.

use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;
use tokio::sync::{Mutex, watch};

use crate::cbor;
use crate::error::{HouseholdError, KeystoreError, StorageError};
use crate::household_lifecycle::HouseholdLifecycleGenerationV1;
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};
use crate::machine_cert::Platform;
use crate::pair_window_namespace::PairWindowNamespaceV2;

/// Wire schema version of the join-ceremony types.
pub const PAIR_MACHINE_VERSION: u8 = 1;
const PAIR_MACHINE_SNAPSHOT_VERSION: u8 = 2;

/// Maximum transport-string field length, mirroring Bonjour TXT
/// constraints. Keeps the QR query string compact.
pub const HOSTNAME_MAX_BYTES: usize = 64;

/// Maximum `host:port` hint length accepted from a candidate. This
/// keeps owner-facing event payloads compact and rejects prompt-spoofing
/// strings before they are persisted.
pub const ADDR_MAX_BYTES: usize = 128;

/// Recovery polling deadline. Past this point M1 stops polling, but retains
/// the exact request and every recovery artifact: a launched finalize POST is
/// `MayHaveTakenEffect`, so timeout alone can never authorize rollback to N=1.
pub const RECOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Canonical delay advertised by a candidate that has durably installed the
/// household but must restart before it can return the retained finalize Ack.
pub const FINALIZE_RESTART_RETRY_AFTER_SECS: u64 = 1;

const FINALIZE_RETRY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);
const FINALIZE_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_FINALIZE_RESPONSE_BYTES: u64 = 65_536;
const MAX_JOIN_REQUEST_WIRE_BYTES: u64 = 65_536;

/// Transport carrier of the QR / Bonjour announcement. Reflects the
/// contract's `transport=tailscale|lan` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JoinTransport {
    Tailscale,
    Lan,
}

/// Signed payload binding `m_pub`, `nonce`, `hostname`, and
/// `platform`. Computed at install time on the candidate; the
/// signature travels through the QR (Story 1) or the candidate's
/// `local/seed` HTTP endpoint (Story 2) inside the [`JoinRequest`].
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct JoinChallenge {
    #[serde(rename = "v")]
    pub version: u8,
    pub purpose: String,
    pub m_pub: ByteBuf,
    pub nonce: ByteBuf,
    pub hostname: String,
    pub platform: Platform,
}

impl JoinChallenge {
    pub const PURPOSE: &'static str = "machine-join-request";

    #[must_use]
    pub fn build(m_pub: &[u8; 33], nonce: &[u8; 32], hostname: &str, platform: Platform) -> Self {
        Self {
            version: PAIR_MACHINE_VERSION,
            purpose: Self::PURPOSE.to_string(),
            m_pub: ByteBuf::from(m_pub.to_vec()),
            nonce: ByteBuf::from(nonce.to_vec()),
            hostname: hostname.to_string(),
            platform,
        }
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        cbor::to_canonical_vec(self)
    }
}

/// On-the-wire join request the owner iPhone posts to M1 (Story 1) or
/// M1 fetches from M2's pre-household listener (Story 2). Both stories
/// produce byte-identical bytes for the same ceremony.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    #[serde(rename = "v")]
    pub version: u8,
    pub m_pub: ByteBuf,
    pub hostname: String,
    pub platform: Platform,
    pub nonce: ByteBuf,
    pub addr: String,
    pub transport: JoinTransport,
    pub challenge_sig: ByteBuf,
}

impl JoinRequest {
    /// Re-encode this request as canonical CBOR. The bytes are stored
    /// verbatim in `OwnerEvent.payload.join_request_cbor` and used for
    /// the transitive-binding cross-check at owner-approve time.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        cbor::to_canonical_vec(self)
    }

    /// Reconstruct the [`JoinChallenge`] this request's signature
    /// covers, using the request's own (already-validated) fields.
    pub fn challenge(&self) -> Result<JoinChallenge, JoinError> {
        let m_pub_arr = <[u8; 33]>::try_from(self.m_pub.as_ref())
            .map_err(|_| JoinError::BadField("m_pub length"))?;
        let nonce_arr = <[u8; 32]>::try_from(self.nonce.as_ref())
            .map_err(|_| JoinError::BadField("nonce length"))?;
        Ok(JoinChallenge::build(
            &m_pub_arr,
            &nonce_arr,
            &self.hostname,
            self.platform.clone(),
        ))
    }
}

/// All `verify_join_request` failure modes collapse to a single
/// generic-401 surface at the HTTP boundary (R14 / FR-019a). The
/// typed enum here is for `tracing::warn!` payloads on the M1 side
/// only — never returned to a client.
#[derive(Debug, Error)]
pub enum JoinError {
    #[error("CBOR shape error: {0}")]
    Cbor(String),
    #[error("invalid field: {0}")]
    BadField(&'static str),
    #[error("m_pub failed SEC1 decode: {0}")]
    BadMPub(#[from] HouseholdError),
    #[error("challenge_sig did not verify under m_pub")]
    BadSignature,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("purpose mismatch: expected machine-join-request, got {0:?}")]
    BadPurpose(String),
    #[error("invalid hostname: {0}")]
    BadHostname(&'static str),
    #[error("invalid addr: {0}")]
    BadAddr(&'static str),
}

/// Validate a [`JoinRequest`] received from the owner iPhone (Story 1)
/// or fetched from M2's `local/seed` endpoint (Story 2). All
/// validation failures are reported via the typed [`JoinError`]; the
/// HTTP boundary collapses every variant to `401 {"error":"unauthenticated"}`.
pub fn verify_join_request(req: &JoinRequest) -> Result<(), JoinError> {
    if req.version != PAIR_MACHINE_VERSION {
        return Err(JoinError::UnsupportedVersion(req.version));
    }
    if req.m_pub.len() != 33 {
        return Err(JoinError::BadField("m_pub length"));
    }
    if req.nonce.len() != 32 {
        return Err(JoinError::BadField("nonce length"));
    }
    if req.challenge_sig.len() != 64 {
        return Err(JoinError::BadField("challenge_sig length"));
    }
    validate_join_hostname(&req.hostname)?;
    validate_join_addr(&req.addr)?;

    let m_pub_arr: [u8; 33] = <[u8; 33]>::try_from(req.m_pub.as_ref())
        .map_err(|_| JoinError::BadField("m_pub length"))?;
    let m_pub = P256PublicKey::from_bytes(&m_pub_arr)?;

    // Reconstruct the JoinChallenge and verify the signature over its
    // canonical CBOR. Mutating any of m_pub/nonce/hostname/platform
    // upstream therefore invalidates challenge_sig.
    let challenge = req.challenge()?;
    if challenge.purpose != JoinChallenge::PURPOSE {
        return Err(JoinError::BadPurpose(challenge.purpose));
    }
    let canonical = challenge
        .to_canonical_bytes()
        .map_err(|e| JoinError::Cbor(format!("encode challenge: {e}")))?;
    let sig_arr: [u8; 64] = <[u8; 64]>::try_from(req.challenge_sig.as_ref())
        .map_err(|_| JoinError::BadField("challenge_sig length"))?;
    let sig = P256Signature(sig_arr);
    verify_signature(&m_pub, &canonical, &sig).map_err(|_| JoinError::BadSignature)?;

    Ok(())
}

/// Validate the owner-facing hostname embedded in a join request. The
/// candidate installer already sanitizes honest hostnames; M1 enforces
/// the same shape because a malicious candidate signs its own prompt text.
pub fn validate_join_hostname(hostname: &str) -> Result<(), JoinError> {
    if hostname.is_empty() {
        return Err(JoinError::BadHostname("empty"));
    }
    if hostname.len() > HOSTNAME_MAX_BYTES {
        return Err(JoinError::BadHostname("too long"));
    }
    validate_dnsish_host(hostname, HOSTNAME_MAX_BYTES).map_err(JoinError::BadHostname)
}

/// Validate the candidate's `host:port` hint. Accepted forms are:
/// canonical IPv4 (`192.168.1.5:8091`), canonical bracketed IPv6
/// (`[fd7a:115c:a1e0::1]:8091`), or lowercase DNS-style hostnames
/// (`studio.local:8091`).
pub fn validate_join_addr(addr: &str) -> Result<(), JoinError> {
    if addr.is_empty() {
        return Err(JoinError::BadAddr("empty"));
    }
    if addr.len() > ADDR_MAX_BYTES {
        return Err(JoinError::BadAddr("too long"));
    }

    if let Some(rest) = addr.strip_prefix('[') {
        let Some((host, port_part)) = rest.split_once("]:") else {
            return Err(JoinError::BadAddr("invalid bracketed IPv6 host:port"));
        };
        if host.is_empty() || port_part.is_empty() || port_part.contains(':') {
            return Err(JoinError::BadAddr("invalid bracketed IPv6 host:port"));
        }
        let port = parse_port(port_part)?;
        let ip = Ipv6Addr::from_str(host).map_err(|_| JoinError::BadAddr("invalid IPv6 host"))?;
        let canonical = format!("[{ip}]:{port}");
        if canonical != addr {
            return Err(JoinError::BadAddr("non-canonical IPv6 host:port"));
        }
        return Ok(());
    }

    let Some((host, port_part)) = addr.rsplit_once(':') else {
        return Err(JoinError::BadAddr("missing port"));
    };
    if host.is_empty() || port_part.is_empty() || host.contains(':') {
        return Err(JoinError::BadAddr("invalid host:port"));
    }
    let port = parse_port(port_part)?;

    if let Ok(ip) = Ipv4Addr::from_str(host) {
        let canonical = format!("{ip}:{port}");
        if canonical != addr {
            return Err(JoinError::BadAddr("non-canonical IPv4 host:port"));
        }
        return Ok(());
    }
    if looks_like_dotted_quad(host) {
        return Err(JoinError::BadAddr("invalid IPv4 host"));
    }

    validate_dnsish_host(host, ADDR_MAX_BYTES).map_err(JoinError::BadAddr)
}

fn parse_port(port_part: &str) -> Result<u16, JoinError> {
    if port_part.len() > 1 && port_part.starts_with('0') {
        return Err(JoinError::BadAddr("non-canonical port"));
    }
    let port = port_part
        .parse::<u16>()
        .map_err(|_| JoinError::BadAddr("invalid port"))?;
    if port == 0 {
        return Err(JoinError::BadAddr("port must be non-zero"));
    }
    Ok(port)
}

fn validate_dnsish_host(host: &str, max_len: usize) -> Result<(), &'static str> {
    if host.is_empty() {
        return Err("empty");
    }
    if host.len() > max_len {
        return Err("too long");
    }
    if host
        .as_bytes()
        .first()
        .is_some_and(|b| *b == b'.' || *b == b'-')
        || host
            .as_bytes()
            .last()
            .is_some_and(|b| *b == b'.' || *b == b'-')
    {
        return Err("bad boundary");
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err("invalid character");
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("empty label");
        }
        if label.len() > 63 {
            return Err("label too long");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("bad label boundary");
        }
    }
    Ok(())
}

fn looks_like_dotted_quad(host: &str) -> bool {
    let mut parts = host.split('.');
    let Some(a) = parts.next() else { return false };
    let Some(b) = parts.next() else { return false };
    let Some(c) = parts.next() else { return false };
    let Some(d) = parts.next() else { return false };
    parts.next().is_none()
        && [a, b, c, d]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

// ---------------------------------------------------------------------------
// PairMachineWindow state machine
// ---------------------------------------------------------------------------

/// Lifecycle states for the founding-machine pair-machine window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairMachineState {
    Idle,
    Staging,
    AwaitingOwner,
    Committed,
    Aborted,
}

/// Optional, durable single-flight claim for an owner approval that has passed
/// live-window revalidation and is about to prepare the Phase 3 transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairMachineApprovalClaim {
    #[serde(with = "serde_bytes")]
    pub claim_id: ByteBuf,
    pub owner_event_cursor: u64,
    pub claimed_at: u64,
}

/// Persisted snapshot mirroring `data-model.md::PairMachineWindow`.
///
/// This is on-disk format, not a wire type. The asymmetry with the
/// wire structs (`LocalAnchor`, `JoinRequest`, `JoinResponse`, etc.,
/// which all retain `#[serde(deny_unknown_fields)]`) is intentional:
///
/// - Wire types must reject unknown fields to prevent silent
///   acceptance of attacker-crafted bodies and to keep cross-repo
///   contracts byte-equal.
/// - On-disk snapshots must accept unknown fields so a binary rolled
///   back to a prior release can still load a snapshot written by a
///   newer release. With `deny_unknown_fields` here, a mid-ceremony
///   pin written by a newer binary would refuse to load on the prior
///   binary, stranding the ceremony (this is the rollback regression
///   surfaced in PR #28 R4 against the `pinned_hh_pub` /
///   `pinned_hh_id` additions). See `feedback_rollback_prebuilt`.
///
/// Forward additions therefore use `#[serde(default,
/// skip_serializing_if = "Option::is_none")]` so the snapshot stays
/// byte-stable when fields are absent and absent fields decode as
/// `None` on older binaries. The schema version (`v`) bumps only on
/// breaking changes, not on additive ones.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairMachineWindowSnapshot {
    #[serde(rename = "v")]
    pub version: u8,
    pub state: PairMachineState,
    pub m_pub: Option<ByteBuf>,
    pub nonce: Option<ByteBuf>,
    pub expiry: Option<u64>,
    pub transport: Option<JoinTransport>,
    pub addr_hint: Option<String>,
    pub fingerprint: Option<String>,
    pub owner_event_cursor: Option<u64>,
    pub cached_join_request: Option<ByteBuf>,
    pub cached_response: Option<ByteBuf>,
    /// 32-byte iPhone-anchor authenticator embedded in the QR but
    /// **never** returned from `local/seed`. Used by the candidate's
    /// `local/anchor` endpoint to authenticate iPhone-delivered
    /// `(hh_id, hh_pub)`. See `contracts/local-anchor.md` (B7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_secret: Option<ByteBuf>,
    /// `hh_pub` (33 bytes SEC1 compressed) pinned by a successful
    /// `local/anchor` POST. `local/finalize` refuses any
    /// `JoinResponse` whose `household_record.hh_pub` does not bit-equal
    /// this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_hh_pub: Option<ByteBuf>,
    /// `hh_id` pinned alongside `pinned_hh_pub`. Defense-in-depth
    /// cross-check against the response's `household_record.hh_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_hh_id: Option<String>,
    /// Optional single-flight claim for an in-progress owner approval. This is
    /// additive and rollback-friendly: older binaries ignore it, newer binaries
    /// reject a second approval while the first one is between prepare and commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_claim: Option<PairMachineApprovalClaim>,
    /// State-root lifecycle generation observed when this candidate ceremony
    /// was staged. Candidate anchor/finalize must bit-equal the current token;
    /// a legacy snapshot without this witness is deliberately not resumable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_generation: Option<ByteBuf>,
}

impl PairMachineWindowSnapshot {
    #[must_use]
    pub fn idle() -> Self {
        Self {
            version: PAIR_MACHINE_SNAPSHOT_VERSION,
            state: PairMachineState::Idle,
            m_pub: None,
            nonce: None,
            expiry: None,
            transport: None,
            addr_hint: None,
            fingerprint: None,
            owner_event_cursor: None,
            cached_join_request: None,
            cached_response: None,
            anchor_secret: None,
            pinned_hh_pub: None,
            pinned_hh_id: None,
            approval_claim: None,
            lifecycle_generation: None,
        }
    }

    fn idle_for_generation(generation: HouseholdLifecycleGenerationV1) -> Self {
        let mut snapshot = Self::idle();
        snapshot.lifecycle_generation = Some(ByteBuf::from(generation.token_bytes().to_vec()));
        snapshot
    }
}

#[derive(Debug, Error)]
pub enum WindowError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("transition rejected: cannot move from {from:?} to {to:?}")]
    Transition {
        from: PairMachineState,
        to: PairMachineState,
    },
    #[error("a different ceremony is already active")]
    AlreadyActive,
    #[error("the supplied join request does not match the active ceremony")]
    MismatchedCeremony,
    #[error("window expired")]
    Expired,
    #[error("owner approval is already claimed")]
    AlreadyClaimed,
}

/// Shared, mutable pair-machine window. Cloning the handle shares state via an
/// `Arc`. Persisted in the current generation-scoped namespace on every
/// transition so a daemon restart picks up the live ceremony.
#[derive(Clone)]
pub struct PairMachineWindow {
    inner: Arc<PairMachineWindowInner>,
}

struct PairMachineWindowInner {
    state: Mutex<PairMachineWindowSnapshot>,
    notifier: watch::Sender<PairMachineState>,
    namespace: Option<PairWindowNamespaceV2>,
}

impl PairMachineWindow {
    /// Construct an in-memory-only window (used by tests).
    #[must_use]
    pub fn new_in_memory() -> Self {
        let snapshot = PairMachineWindowSnapshot::idle();
        let (tx, _) = watch::channel(snapshot.state);
        Self {
            inner: Arc::new(PairMachineWindowInner {
                state: Mutex::new(snapshot),
                notifier: tx,
                namespace: None,
            }),
        }
    }

    /// Construct a generation-scoped window in a standalone synchronous site.
    /// This may block up to the lifecycle lock deadline.
    pub fn with_persistence(state_dir: PathBuf) -> Result<Self, StorageError> {
        let namespace = PairWindowNamespaceV2::current(state_dir)?;
        Self::with_namespace(namespace)
    }

    /// Construct without reacquiring a lifecycle lock held by the caller.
    pub fn with_persistence_under_lifecycle(
        state_dir: PathBuf,
        lifecycle: &crate::household_lifecycle::LifecycleWriteGuard,
    ) -> Result<Self, StorageError> {
        let namespace = PairWindowNamespaceV2::current_under_lifecycle(state_dir, lifecycle)?;
        Self::with_namespace_under_lifecycle(namespace, lifecycle)
    }

    /// Load only the snapshot belonging to `namespace`'s current generation.
    pub fn with_namespace(namespace: PairWindowNamespaceV2) -> Result<Self, StorageError> {
        let mut snapshot: PairMachineWindowSnapshot =
            namespace.read_pair_machine()?.unwrap_or_else(|| {
                PairMachineWindowSnapshot::idle_for_generation(namespace.generation())
            });
        validate_snapshot_generation(&snapshot, &namespace)?;
        clear_stale_approval_claim_on_load(&namespace, &mut snapshot, None)?;
        let (tx, _) = watch::channel(snapshot.state);
        Ok(Self {
            inner: Arc::new(PairMachineWindowInner {
                state: Mutex::new(snapshot),
                notifier: tx,
                namespace: Some(namespace),
            }),
        })
    }

    /// Load from a namespace while reusing lifecycle-exclusive.
    pub fn with_namespace_under_lifecycle(
        namespace: PairWindowNamespaceV2,
        lifecycle: &crate::household_lifecycle::LifecycleWriteGuard,
    ) -> Result<Self, StorageError> {
        let mut snapshot: PairMachineWindowSnapshot = namespace
            .read_pair_machine_under_lifecycle(lifecycle)?
            .unwrap_or_else(|| {
                PairMachineWindowSnapshot::idle_for_generation(namespace.generation())
            });
        validate_snapshot_generation(&snapshot, &namespace)?;
        clear_stale_approval_claim_on_load(&namespace, &mut snapshot, Some(lifecycle))?;
        let (tx, _) = watch::channel(snapshot.state);
        Ok(Self {
            inner: Arc::new(PairMachineWindowInner {
                state: Mutex::new(snapshot),
                notifier: tx,
                namespace: Some(namespace),
            }),
        })
    }

    /// Stage a multi-file commit through the retained generation capability.
    pub fn stage_commit_under_lifecycle<'a>(
        &'a self,
        lifecycle: &'a crate::household_lifecycle::LifecycleWriteGuard,
        pre_commit_items: Vec<(PathBuf, Vec<u8>)>,
        committed_window_bytes: Vec<u8>,
        commit_marker: (PathBuf, Vec<u8>),
    ) -> Result<crate::pair_window_namespace::PairWindowStagedCommit<'a>, StorageError> {
        self.inner
            .namespace
            .as_ref()
            .ok_or_else(|| {
                StorageError::Encoding(HouseholdError::InvalidRecord(
                    "in-memory pair-machine window cannot join a disk commit".into(),
                ))
            })?
            .stage_pair_machine_commit_under_lifecycle(
                lifecycle,
                pre_commit_items,
                committed_window_bytes,
                commit_marker,
            )
    }

    /// Read the durable snapshot for this handle's exact lifecycle
    /// generation without consulting process-local state.
    pub fn read_persisted_snapshot_under_lifecycle(
        &self,
        lifecycle: &crate::household_lifecycle::LifecycleWriteGuard,
    ) -> Result<Option<PairMachineWindowSnapshot>, StorageError> {
        self.inner
            .namespace
            .as_ref()
            .ok_or_else(|| {
                StorageError::Encoding(HouseholdError::InvalidRecord(
                    "in-memory pair-machine window has no durable snapshot".into(),
                ))
            })?
            .read_pair_machine_under_lifecycle(lifecycle)
    }

    /// Test-only: overwrite the durable snapshot for this handle's exact
    /// lifecycle generation, through the same scoped namespace and the
    /// same lifecycle guard production writes go through — never a raw
    /// path, never `atomic_write_cbor` called directly against a
    /// hand-built location. Exists so tests that need to simulate time
    /// passing on an already-committed window (e.g. an expired grace
    /// period) produce that state through the real write path instead of
    /// reaching around it.
    ///
    /// `test-support`-gated, same discipline as
    /// `D1MembershipKey::new_for_test`: an escape hatch a test needs is
    /// still a capability, and capabilities get a named gate rather than
    /// a wider default visibility.
    #[cfg(feature = "test-support")]
    pub fn write_persisted_snapshot_under_lifecycle_for_test(
        &self,
        snapshot: &PairMachineWindowSnapshot,
        lifecycle: &crate::household_lifecycle::LifecycleWriteGuard,
    ) -> Result<(), StorageError> {
        self.inner
            .namespace
            .as_ref()
            .ok_or_else(|| {
                StorageError::Encoding(HouseholdError::InvalidRecord(
                    "in-memory pair-machine window has no durable snapshot".into(),
                ))
            })?
            .write_pair_machine_under_lifecycle(snapshot, lifecycle)
    }

    /// Clear an interrupted staged snapshot in this exact generation.
    pub fn clear_staged_snapshot_under_lifecycle(
        &self,
        lifecycle: &crate::household_lifecycle::LifecycleWriteGuard,
    ) -> Result<(), StorageError> {
        self.inner
            .namespace
            .as_ref()
            .ok_or_else(|| {
                StorageError::Encoding(HouseholdError::InvalidRecord(
                    "in-memory pair-machine window has no durable snapshot".into(),
                ))
            })?
            .clear_pair_machine_staged_under_lifecycle(lifecycle)
    }

    /// Run Phase-3 recovery through this window's retained generation
    /// capability without reacquiring the lifecycle lock. Startup callers
    /// holding lifecycle-exclusive must use this method rather than opening a
    /// second namespace capability by path.
    pub async fn recover_phase3_under_lifecycle(
        &self,
        state_dir: &Path,
        lifecycle: &crate::household_lifecycle::LifecycleWriteGuard,
        recovery_timeout: Duration,
    ) -> Result<RecoveryOutcome, RecoveryError> {
        let namespace = self
            .inner
            .namespace
            .as_ref()
            .ok_or(RecoveryError::PersistentNamespaceUnavailable)?;
        recover_phase3_ceremony_under_lifecycle(state_dir, namespace, lifecycle, recovery_timeout)
            .await
    }

    /// Subscribe to state changes (used by `bonjour_publisher.rs` for
    /// the Phase 5 TXT-record reflection).
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<PairMachineState> {
        self.inner.notifier.subscribe()
    }

    /// Return a clone of the current snapshot.
    pub async fn snapshot(&self) -> PairMachineWindowSnapshot {
        self.inner.state.lock().await.clone()
    }

    /// Bind transition methods to a lifecycle-exclusive guard without
    /// reacquiring the cross-process lock.
    #[must_use]
    pub fn under_lifecycle<'a>(
        &'a self,
        lifecycle: &'a crate::household_lifecycle::LifecycleWriteGuard,
    ) -> PairMachineWindowUnderLifecycle<'a> {
        PairMachineWindowUnderLifecycle {
            window: self,
            lifecycle,
        }
    }

    /// Open the window in `staging` after a verified [`JoinRequest`]
    /// has been received. The supplied `cached_join_request_bytes`
    /// MUST be the bit-identical canonical CBOR bytes of the request
    /// (used at owner-approve time for transitive binding).
    ///
    /// `anchor_secret`, if `Some`, is the candidate-side authenticator
    /// for `local/anchor` POSTs from the owner iPhone (B7 /
    /// `contracts/local-anchor.md`). Story 2 (founder-side staging via
    /// the Bonjour browser) passes `None` because the founder has no
    /// pre-household trust anchor to deliver. Story 1 (candidate-side
    /// install) passes `Some(<32 random bytes>)` and embeds the same
    /// bytes in the QR.
    #[allow(clippy::too_many_arguments)]
    pub async fn enter_staging(
        &self,
        m_pub: [u8; 33],
        nonce: [u8; 32],
        transport: JoinTransport,
        addr_hint: String,
        fingerprint: String,
        cached_join_request_bytes: Vec<u8>,
        ttl_seconds: u64,
        anchor_secret: Option<[u8; 32]>,
    ) -> Result<u64, WindowError> {
        self.enter_staging_with(
            m_pub,
            nonce,
            transport,
            addr_hint,
            fingerprint,
            cached_join_request_bytes,
            ttl_seconds,
            anchor_secret,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn enter_staging_with(
        &self,
        m_pub: [u8; 33],
        nonce: [u8; 32],
        transport: JoinTransport,
        addr_hint: String,
        fingerprint: String,
        cached_join_request_bytes: Vec<u8>,
        ttl_seconds: u64,
        anchor_secret: Option<[u8; 32]>,
        lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    ) -> Result<u64, WindowError> {
        let mut guard = self.inner.state.lock().await;
        match guard.state {
            PairMachineState::Idle | PairMachineState::Aborted | PairMachineState::Committed => {}
            PairMachineState::Staging | PairMachineState::AwaitingOwner => {
                return Err(WindowError::AlreadyActive);
            }
        }
        let now = unix_now()?;
        let expiry = now.saturating_add(ttl_seconds);
        *guard = PairMachineWindowSnapshot {
            version: PAIR_MACHINE_SNAPSHOT_VERSION,
            state: PairMachineState::Staging,
            m_pub: Some(ByteBuf::from(m_pub.to_vec())),
            nonce: Some(ByteBuf::from(nonce.to_vec())),
            expiry: Some(expiry),
            transport: Some(transport),
            addr_hint: Some(addr_hint),
            fingerprint: Some(fingerprint),
            owner_event_cursor: None,
            cached_join_request: Some(ByteBuf::from(cached_join_request_bytes)),
            cached_response: None,
            anchor_secret: anchor_secret.map(|s| ByteBuf::from(s.to_vec())),
            pinned_hh_pub: None,
            pinned_hh_id: None,
            approval_claim: None,
            lifecycle_generation: self
                .inner
                .namespace
                .as_ref()
                .map(|namespace| ByteBuf::from(namespace.generation().token_bytes().to_vec())),
        };
        self.persist_with(&guard, lifecycle)?;
        let _ = self.inner.notifier.send(guard.state);
        // Positive observability gate (T093): the founder window has
        // transitioned `idle → staging`. Audit consumers count this
        // against `enter_awaiting_owner` to detect ceremonies that
        // started but never reached the owner-event append stage.
        tracing::info!(stage = "pair_machine.window_opened", expiry = expiry,);
        Ok(expiry)
    }

    /// Bind a staged candidate ceremony to the exact state-root generation
    /// observed under lifecycle-exclusive.
    ///
    /// This is separate from [`Self::enter_staging`] so founder-side windows
    /// remain source-compatible. Production candidate entry points call it
    /// before releasing the lifecycle guard and before exposing any QR or
    /// listener. A crash between the two writes leaves a legacy-shaped window
    /// that finalize rejects and the operator restages.
    pub async fn bind_lifecycle_generation(
        &self,
        generation: HouseholdLifecycleGenerationV1,
    ) -> Result<(), WindowError> {
        self.bind_lifecycle_generation_with(generation, None).await
    }

    async fn bind_lifecycle_generation_with(
        &self,
        generation: HouseholdLifecycleGenerationV1,
        lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    ) -> Result<(), WindowError> {
        let mut guard = self.inner.state.lock().await;
        if !matches!(
            guard.state,
            PairMachineState::Staging | PairMachineState::AwaitingOwner
        ) {
            return Err(WindowError::Transition {
                from: guard.state,
                to: guard.state,
            });
        }
        let bytes = generation.token_bytes();
        match guard.lifecycle_generation.as_ref() {
            Some(existing) if existing.as_ref() == bytes.as_slice() => return Ok(()),
            Some(_) => return Err(WindowError::MismatchedCeremony),
            None => {}
        }
        guard.lifecycle_generation = Some(ByteBuf::from(bytes.to_vec()));
        if let Err(error) = self.persist_with(&guard, lifecycle) {
            guard.lifecycle_generation = None;
            return Err(error);
        }
        Ok(())
    }

    /// Pin `(hh_id, hh_pub)` after a successful `local/anchor` POST per
    /// `contracts/local-anchor.md`. Idempotent on identical re-pinning;
    /// rejects divergent re-pinning with `WindowError::MismatchedCeremony`.
    /// Refuses to run unless the window is in `Staging` or
    /// `AwaitingOwner`. Persists atomically.
    pub async fn pin_household_anchor(
        &self,
        hh_id: String,
        hh_pub: [u8; 33],
    ) -> Result<(), WindowError> {
        self.pin_household_anchor_with(hh_id, hh_pub, None).await
    }

    async fn pin_household_anchor_with(
        &self,
        hh_id: String,
        hh_pub: [u8; 33],
        lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    ) -> Result<(), WindowError> {
        let mut guard = self.inner.state.lock().await;
        match guard.state {
            PairMachineState::Staging | PairMachineState::AwaitingOwner => {}
            other => {
                return Err(WindowError::Transition {
                    from: other,
                    to: other,
                });
            }
        }
        if let Some(prev_pub) = guard.pinned_hh_pub.as_ref() {
            // Idempotent re-pin only if both `hh_id` and `hh_pub` match.
            let prev_id = guard.pinned_hh_id.as_deref();
            if prev_pub.as_ref() == hh_pub.as_slice() && prev_id == Some(hh_id.as_str()) {
                return Ok(());
            }
            return Err(WindowError::MismatchedCeremony);
        }
        // Mutate in-memory FIRST so we hold the canonical state, then
        // persist. If persist fails we MUST roll back the in-memory
        // mutation: otherwise a retry from the caller would hit the
        // idempotent short-circuit above against an in-memory pin that
        // never reached disk, and a daemon restart before
        // `local/finalize` would surface as `trust_anchor_missing`
        // because the on-disk snapshot has no pin.
        guard.pinned_hh_pub = Some(ByteBuf::from(hh_pub.to_vec()));
        guard.pinned_hh_id = Some(hh_id);
        if let Err(e) = self.persist_with(&guard, lifecycle) {
            guard.pinned_hh_pub = None;
            guard.pinned_hh_id = None;
            return Err(e);
        }
        Ok(())
    }

    /// Promote a staged window to `awaiting_owner` once the
    /// `OwnerEvent{type=join-request}` has been appended.
    pub async fn enter_awaiting_owner(&self, owner_event_cursor: u64) -> Result<(), WindowError> {
        self.enter_awaiting_owner_with(owner_event_cursor, None)
            .await
    }

    async fn enter_awaiting_owner_with(
        &self,
        owner_event_cursor: u64,
        lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    ) -> Result<(), WindowError> {
        let mut guard = self.inner.state.lock().await;
        if guard.state != PairMachineState::Staging {
            return Err(WindowError::Transition {
                from: guard.state,
                to: PairMachineState::AwaitingOwner,
            });
        }
        guard.state = PairMachineState::AwaitingOwner;
        guard.owner_event_cursor = Some(owner_event_cursor);
        guard.approval_claim = None;
        self.persist_with(&guard, lifecycle)?;
        let _ = self.inner.notifier.send(guard.state);
        Ok(())
    }

    /// Claim the awaiting-owner window for a single in-flight v2 owner approval.
    ///
    /// The caller holds `BOOTSTRAP_MUTATION_LOCK` while calling this. The claim is
    /// persisted before the lock is released, so another valid `WebAuthn` approval
    /// for the same window cannot re-enter `CeremonyTxn::prepare`.
    pub async fn claim_owner_approval(
        &self,
        owner_event_cursor: u64,
        claim_id: [u8; 32],
        claimed_at: u64,
    ) -> Result<PairMachineApprovalClaim, WindowError> {
        self.claim_owner_approval_with(owner_event_cursor, claim_id, claimed_at, None)
            .await
    }

    async fn claim_owner_approval_with(
        &self,
        owner_event_cursor: u64,
        claim_id: [u8; 32],
        claimed_at: u64,
        lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    ) -> Result<PairMachineApprovalClaim, WindowError> {
        let mut guard = self.inner.state.lock().await;
        if guard.state != PairMachineState::AwaitingOwner
            || guard.owner_event_cursor != Some(owner_event_cursor)
        {
            return Err(WindowError::MismatchedCeremony);
        }
        if guard.approval_claim.is_some() {
            return Err(WindowError::AlreadyClaimed);
        }
        let claim = PairMachineApprovalClaim {
            claim_id: ByteBuf::from(claim_id.to_vec()),
            owner_event_cursor,
            claimed_at,
        };
        guard.approval_claim = Some(claim.clone());
        if let Err(e) = self.persist_with(&guard, lifecycle) {
            guard.approval_claim = None;
            return Err(e);
        }
        Ok(claim)
    }

    /// Advance to `committed` after a successful 2PC. The supplied
    /// `cached_response_bytes` are returned to a duplicate
    /// `JoinRequest` within the replay grace window (R7 / FR-015).
    pub async fn enter_committed(&self, cached_response_bytes: Vec<u8>) -> Result<(), WindowError> {
        self.enter_committed_with(cached_response_bytes, None).await
    }

    async fn enter_committed_with(
        &self,
        cached_response_bytes: Vec<u8>,
        lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    ) -> Result<(), WindowError> {
        let mut guard = self.inner.state.lock().await;
        if !matches!(
            guard.state,
            PairMachineState::Staging | PairMachineState::AwaitingOwner
        ) {
            return Err(WindowError::Transition {
                from: guard.state,
                to: PairMachineState::Committed,
            });
        }
        guard.state = PairMachineState::Committed;
        guard.cached_response = Some(ByteBuf::from(cached_response_bytes));
        guard.approval_claim = None;
        self.persist_with(&guard, lifecycle)?;
        let _ = self.inner.notifier.send(guard.state);
        Ok(())
    }

    /// Update only the in-memory snapshot after another atomic write path has
    /// already persisted `pair_machine_window.cbor` as committed.
    ///
    /// M2's `local/finalize` stages the committed window snapshot together with
    /// the certs, household record, self marker, and shard. Re-persisting the
    /// same window afterward can turn an already-committed disk state into a
    /// misleading 401 if that second write fails. This method keeps memory in
    /// sync with the disk-authoritative staged commit and performs no I/O.
    pub async fn note_committed_after_external_persist(&self, cached_response_bytes: Vec<u8>) {
        let mut guard = self.inner.state.lock().await;
        guard.state = PairMachineState::Committed;
        guard.cached_response = Some(ByteBuf::from(cached_response_bytes));
        guard.approval_claim = None;
        let _ = self.inner.notifier.send(guard.state);
    }

    /// Force-abort the active window (decline / timeout / failure).
    pub async fn enter_aborted(&self) -> Result<(), WindowError> {
        self.enter_aborted_with(None).await
    }

    async fn enter_aborted_with(
        &self,
        lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    ) -> Result<(), WindowError> {
        let mut guard = self.inner.state.lock().await;
        guard.state = PairMachineState::Aborted;
        guard.approval_claim = None;
        self.persist_with(&guard, lifecycle)?;
        let _ = self.inner.notifier.send(guard.state);
        Ok(())
    }

    /// Return the window to `idle` after the replay grace window
    /// elapses. Drops cached request/response bytes.
    pub async fn return_to_idle(&self) -> Result<(), WindowError> {
        self.return_to_idle_with(None).await
    }

    async fn return_to_idle_with(
        &self,
        lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    ) -> Result<(), WindowError> {
        let mut guard = self.inner.state.lock().await;
        *guard = self
            .inner
            .namespace
            .as_ref()
            .map_or_else(PairMachineWindowSnapshot::idle, |namespace| {
                PairMachineWindowSnapshot::idle_for_generation(namespace.generation())
            });
        self.persist_with(&guard, lifecycle)?;
        let _ = self.inner.notifier.send(guard.state);
        Ok(())
    }

    fn persist_with(
        &self,
        snapshot: &PairMachineWindowSnapshot,
        lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    ) -> Result<(), WindowError> {
        if let Some(namespace) = &self.inner.namespace {
            validate_snapshot_generation(snapshot, namespace)?;
            match lifecycle {
                Some(lifecycle) => {
                    namespace.write_pair_machine_under_lifecycle(snapshot, lifecycle)
                }
                None => namespace.write_pair_machine(snapshot),
            }?;
        }
        Ok(())
    }
}

/// Pair-machine transition facade tied to one retained lifecycle-exclusive
/// guard. It exposes no raw path and cannot outlive either input.
pub struct PairMachineWindowUnderLifecycle<'a> {
    window: &'a PairMachineWindow,
    lifecycle: &'a crate::household_lifecycle::LifecycleWriteGuard,
}

impl PairMachineWindowUnderLifecycle<'_> {
    #[allow(clippy::too_many_arguments)]
    pub async fn enter_staging(
        &self,
        m_pub: [u8; 33],
        nonce: [u8; 32],
        transport: JoinTransport,
        addr_hint: String,
        fingerprint: String,
        cached_join_request_bytes: Vec<u8>,
        ttl_seconds: u64,
        anchor_secret: Option<[u8; 32]>,
    ) -> Result<u64, WindowError> {
        self.window
            .enter_staging_with(
                m_pub,
                nonce,
                transport,
                addr_hint,
                fingerprint,
                cached_join_request_bytes,
                ttl_seconds,
                anchor_secret,
                Some(self.lifecycle),
            )
            .await
    }

    pub async fn bind_lifecycle_generation(
        &self,
        generation: HouseholdLifecycleGenerationV1,
    ) -> Result<(), WindowError> {
        self.window
            .bind_lifecycle_generation_with(generation, Some(self.lifecycle))
            .await
    }

    pub async fn pin_household_anchor(
        &self,
        hh_id: String,
        hh_pub: [u8; 33],
    ) -> Result<(), WindowError> {
        self.window
            .pin_household_anchor_with(hh_id, hh_pub, Some(self.lifecycle))
            .await
    }

    pub async fn enter_awaiting_owner(&self, owner_event_cursor: u64) -> Result<(), WindowError> {
        self.window
            .enter_awaiting_owner_with(owner_event_cursor, Some(self.lifecycle))
            .await
    }

    pub async fn claim_owner_approval(
        &self,
        owner_event_cursor: u64,
        claim_id: [u8; 32],
        claimed_at: u64,
    ) -> Result<PairMachineApprovalClaim, WindowError> {
        self.window
            .claim_owner_approval_with(
                owner_event_cursor,
                claim_id,
                claimed_at,
                Some(self.lifecycle),
            )
            .await
    }

    pub async fn enter_committed(&self, cached_response_bytes: Vec<u8>) -> Result<(), WindowError> {
        self.window
            .enter_committed_with(cached_response_bytes, Some(self.lifecycle))
            .await
    }

    pub async fn enter_aborted(&self) -> Result<(), WindowError> {
        self.window.enter_aborted_with(Some(self.lifecycle)).await
    }

    pub async fn return_to_idle(&self) -> Result<(), WindowError> {
        self.window.return_to_idle_with(Some(self.lifecycle)).await
    }
}

/// Legacy unscoped location. It is never a current-window lookup API.
/// Lifecycle-exclusive namespace construction removes it without adoption.
#[must_use]
pub(crate) fn legacy_pair_machine_window_path(state_dir: &Path) -> PathBuf {
    crate::storage::household_dir(state_dir).join("pair_machine_window.cbor")
}

pub(crate) fn pair_machine_window_path(state_dir: &Path) -> PathBuf {
    legacy_pair_machine_window_path(state_dir)
}

fn clear_stale_approval_claim_on_load(
    namespace: &PairWindowNamespaceV2,
    snapshot: &mut PairMachineWindowSnapshot,
    lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
) -> Result<(), StorageError> {
    if snapshot.approval_claim.is_none() {
        return Ok(());
    }
    let snapshot_path = namespace.pair_machine_snapshot_path();
    let state_dir = snapshot_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| {
            StorageError::Encoding(HouseholdError::InvalidRecord(
                "namespace path missing root".into(),
            ))
        })?;
    if crate::storage::phase3_recovery_manifest_exists(state_dir)
        || crate::storage::phase3_finalize_ack_marker_exists(state_dir)
    {
        return Ok(());
    }

    // A durable claim only protects the prepare/finalize race while a process is
    // actively driving the approval. After restart, no in-memory owner approval
    // can still be alive. Without the Phase-3 manifest (or legacy finalize
    // marker), recovery has no intent to preserve, so the claim is stale and
    // must not wedge the window.
    snapshot.approval_claim = None;
    crate::storage::clear_phase3_pending_join_response(state_dir)?;
    match lifecycle {
        Some(lifecycle) => namespace.write_pair_machine_under_lifecycle(snapshot, lifecycle),
        None => namespace.write_pair_machine(snapshot),
    }?;
    Ok(())
}

fn mark_window_committed_after_recovery(
    namespace: &PairWindowNamespaceV2,
    lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    cached_response_bytes: Vec<u8>,
) -> Result<(), StorageError> {
    let snapshot = match lifecycle {
        Some(lifecycle) => namespace.read_pair_machine_under_lifecycle(lifecycle),
        None => namespace.read_pair_machine(),
    }?;
    let Some(mut snapshot): Option<PairMachineWindowSnapshot> = snapshot else {
        return Ok(());
    };
    validate_snapshot_generation(&snapshot, namespace)?;
    snapshot.state = PairMachineState::Committed;
    snapshot.cached_response = Some(ByteBuf::from(cached_response_bytes));
    snapshot.approval_claim = None;
    match lifecycle {
        Some(lifecycle) => namespace.write_pair_machine_under_lifecycle(&snapshot, lifecycle),
        None => namespace.write_pair_machine(&snapshot),
    }?;
    Ok(())
}

fn validate_snapshot_generation(
    snapshot: &PairMachineWindowSnapshot,
    namespace: &PairWindowNamespaceV2,
) -> Result<(), StorageError> {
    if snapshot.version != PAIR_MACHINE_SNAPSHOT_VERSION
        || snapshot.lifecycle_generation.as_ref().map(ByteBuf::as_ref)
            != Some(namespace.generation().token_bytes().as_slice())
    {
        return Err(StorageError::Encoding(HouseholdError::InvalidRecord(
            "pair-machine snapshot version/generation does not match its namespace".into(),
        )));
    }
    Ok(())
}

fn unix_now() -> Result<u64, WindowError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| {
            WindowError::Storage(StorageError::Encoding(HouseholdError::Cbor(
                "system clock before unix epoch".into(),
            )))
        })
}

// ---------------------------------------------------------------------------
// CeremonyTxn (T032/T033) — in-memory 2PC handle
// ---------------------------------------------------------------------------

use crate::household_record::HouseholdRecord;
use crate::ids::{HouseholdId, MachineId, derive_machine_id};
use crate::machine_cert::{MachineCert, issue_for_candidate};
use crate::owner_events::OwnerDevicePushToken;
use crate::shamir::{SHARD_X_M1, SHARD_X_M2, split_2_of_2};
use crate::shard_at_rest::{EncryptedShard, encrypt_for_peer, encrypt_for_self};
use zeroize::Zeroizing;

/// Inputs the ceremony driver hands `CeremonyTxn::prepare` to admit
/// the candidate machine M2. `hh_priv` and `m1_priv_scalar` are
/// **consumed** by `prepare` and dropped before the function returns —
/// they never survive into the long-lived `CeremonyTxn` handle.
pub struct CeremonyInputs {
    pub hh_priv: Zeroizing<[u8; 32]>,
    pub hh_id: HouseholdId,
    pub hh_pub_sec1: [u8; 33],
    pub m1_priv_scalar: Zeroizing<[u8; 32]>,
    pub m1_pub_sec1: [u8; 33],
    pub m1_id: String,
    pub candidate_m_pub_sec1: [u8; 33],
    pub candidate_hostname: String,
    pub candidate_platform: Platform,
    pub joined_at: u64,
    pub state_dir: PathBuf,
    /// Pre-join household record (`shamir_k=1, shamir_n=1, members=[m1_id]`).
    /// Used to construct the post-join record (`shamir_k=2, shamir_n=2,
    /// members=[m1_id, m2_id]`) staged atomically as part of the 2PC.
    pub existing_record: HouseholdRecord,
    /// Keystore policy under which `HH_priv` was originally persisted.
    /// `commit()` uses it to pick the right destruction backend
    /// (Linux/Secret-Service, macOS/SE Keychain, or software-fallback file).
    pub policy: crate::bootstrap::KeyBackingPolicy,
}

#[derive(Debug, Error)]
pub enum CeremonyError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("CBOR encode error: {0}")]
    Cbor(String),
    #[error("signing failed: {0}")]
    Sign(#[from] KeystoreError),
    #[error("cert issuance failed: {0}")]
    Cert(#[from] crate::machine_cert::CertError),
    #[error("shard wrap failed: {0}")]
    Shard(#[from] crate::shard_at_rest::ShardError),
    #[error("finalize HTTP failed: {0}")]
    Http(String),
    #[error("finalize rejected: {0}")]
    FinalizeRejected(String),
    #[error("invalid finalize ack: {0}")]
    FinalizeAck(String),
    #[error("ceremony already committed or rolled back")]
    AlreadyClosed,
    #[error("candidate machine '{0}' is already a household member")]
    AlreadyMember(String),
}

impl CeremonyError {
    /// Whether M1 sent the finalize request far enough that M2 may have
    /// durably committed even though M1 did not receive a valid ack.
    #[must_use]
    pub fn is_ambiguous_finalize_outcome(&self) -> bool {
        matches!(self, Self::Http(_) | Self::FinalizeAck(_))
    }
}

fn finalize_http_status_error(action: &str, code: u16) -> CeremonyError {
    if code >= 500 {
        CeremonyError::Http(format!("{action}: indeterminate server status {code}"))
    } else {
        CeremonyError::FinalizeRejected(format!("{action}: status {code}"))
    }
}

/// Outcome returned by the post-staged-rename hook injected into
/// [`CeremonyTxn::commit_preserve_on_error_with_hook`]. Decoupled from
/// the `server-rs::failure_injection` registry so `household-rs`
/// stays free of the `server-rs` dependency edge.
#[derive(Debug)]
pub enum PostRenameHookOutcome {
    /// Continue with the post-rename cleanup (keystore destroy,
    /// sole-shard unlink). Default for production.
    Continue,
    /// Abort the cleanup with `CeremonyError::FinalizeRejected`. The
    /// staged-rename has already promoted the household record to
    /// `shamir_n=2`; the sole-shard is still on disk (boot-time
    /// `recover_post_join_sole_shard` will unlink it on next boot).
    EarlyReject(&'static str),
}

/// In-memory 2PC handle held by M1 during a Phase 3 join ceremony.
///
/// **Crucially**, this struct never carries `hh_priv` or `m1_priv_scalar`.
/// Both plaintext scalars are consumed and dropped inside `prepare`
/// once the at-rest and peer-bound shards have been encrypted. Holding
/// them across `prepare → owner_approve → commit` would leave the
/// household root in heap for seconds-to-minutes; that contradicts
/// `data-model.md::CeremonyTxn` and was flagged as a critical issue.
///
/// `commit` promotes every staged file (candidate `MachineCert`,
/// updated `HouseholdRecord`, M1's at-rest shard) and deletes
/// `household_root_sole.cbor` as the **last** step (sole-shard
/// destruction).
#[must_use]
pub struct CeremonyTxn {
    candidate_cert: MachineCert,
    self_encrypted_shard: EncryptedShard,
    peer_encrypted_shard: EncryptedShard,
    /// Updated household record (post-join: `shamir_k=2, shamir_n=2,
    /// members=[m1_id, m2_id]`). Carried so callers can inspect it
    /// before/after commit.
    new_household_record: HouseholdRecord,
    preinstall_household_record_hash: [u8; 32],
    staged: Option<crate::storage::StagedCommit>,
    sole_shard_path: PathBuf,
    /// Carried so `commit()` can destroy the keystore custody of `HH_priv`
    /// (B1) at the right moment in the 2PC sequence.
    state_dir: PathBuf,
    hh_id: HouseholdId,
    policy: crate::bootstrap::KeyBackingPolicy,
    closed: bool,
}

/// One peer the candidate should know about after commit.
///
/// `machine_cert` is optional for forward compatibility, but Phase 3 includes
/// M1's existing self-cert here so M2 can persist
/// `machine_certs/<m1_id>.cbor` during `local/finalize`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct PeerEntry {
    pub m_id: String,
    pub m_pub: ByteBuf,
    pub hostname: String,
    pub tailscale_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_cert: Option<MachineCert>,
}

/// Signed portion of the wire CBOR returned to the candidate on successful
/// owner approval.
///
/// The `response_sig` field in [`JoinResponse`] signs the deterministic CBOR
/// encoding of this struct. That signature authenticates every mutable field
/// M2 persists from the unauthenticated pre-household `local/finalize` body.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct JoinResponseUnsigned {
    #[serde(rename = "v")]
    pub version: u8,
    pub join_request_hash: ByteBuf,
    pub machine_cert: MachineCert,
    pub encrypted_shard: EncryptedShard,
    pub household_record: HouseholdRecord,
    pub peer_list: Vec<PeerEntry>,
    pub push_token_seed: Option<OwnerDevicePushToken>,
}

impl JoinResponseUnsigned {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        crate::cbor::to_canonical_vec(self)
    }

    pub fn sign(self, signer: &dyn IdentityKey) -> Result<JoinResponse, KeystoreError> {
        let canonical = self
            .to_canonical_bytes()
            .map_err(|e| KeystoreError::SigningFailed(format!("encode JoinResponse: {e}")))?;
        let response_sig = signer.sign(&canonical)?;
        Ok(JoinResponse {
            version: self.version,
            join_request_hash: self.join_request_hash,
            machine_cert: self.machine_cert,
            encrypted_shard: self.encrypted_shard,
            household_record: self.household_record,
            peer_list: self.peer_list,
            push_token_seed: self.push_token_seed,
            response_sig,
        })
    }
}

/// Wire CBOR returned to the candidate on successful owner approval.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct JoinResponse {
    #[serde(rename = "v")]
    pub version: u8,
    pub join_request_hash: ByteBuf,
    pub machine_cert: MachineCert,
    pub encrypted_shard: EncryptedShard,
    pub household_record: HouseholdRecord,
    pub peer_list: Vec<PeerEntry>,
    pub push_token_seed: Option<OwnerDevicePushToken>,
    pub response_sig: P256Signature,
}

impl JoinResponse {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        crate::cbor::to_canonical_vec(self)
    }

    #[must_use]
    pub fn unsigned(&self) -> JoinResponseUnsigned {
        JoinResponseUnsigned {
            version: self.version,
            join_request_hash: self.join_request_hash.clone(),
            machine_cert: self.machine_cert.clone(),
            encrypted_shard: self.encrypted_shard.clone(),
            household_record: self.household_record.clone(),
            peer_list: self.peer_list.clone(),
            push_token_seed: self.push_token_seed.clone(),
        }
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        self.unsigned().to_canonical_bytes()
    }

    pub fn verify_response_sig(&self, founder_cert: &MachineCert) -> Result<(), HouseholdError> {
        verify_signature(
            &founder_cert.m_pub,
            &self.signing_bytes()?,
            &self.response_sig,
        )
    }
}

/// Deterministic ack returned by M2's `local/finalize` endpoint.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct FinalizeAck {
    #[serde(rename = "v")]
    pub version: u8,
    pub m_id: String,
    pub machine_cert_hash: ByteBuf,
}

impl FinalizeAck {
    pub fn for_machine_cert(cert: &MachineCert) -> Result<Self, HouseholdError> {
        let hash = machine_cert_hash(cert)?;
        Ok(Self {
            version: PAIR_MACHINE_VERSION,
            m_id: cert.m_id.to_string(),
            machine_cert_hash: ByteBuf::from(hash.to_vec()),
        })
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        crate::cbor::to_canonical_vec(self)
    }
}

/// Typed response emitted by M2 after it has durably installed the household
/// but before its fresh G1 listener is ready to return the retained
/// [`FinalizeAck`].
///
/// The fields are private so callers cannot manufacture a look-alike with a
/// different version or error discriminator. [`Self::from_canonical_bytes`]
/// additionally rejects non-canonical CBOR and every unknown field.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct FinalizeRestartRequired {
    #[serde(rename = "v")]
    version: u8,
    error: String,
}

impl FinalizeRestartRequired {
    const ERROR: &'static str = "restart_required";

    #[must_use]
    pub fn new() -> Self {
        Self {
            version: PAIR_MACHINE_VERSION,
            error: Self::ERROR.to_string(),
        }
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        crate::cbor::to_canonical_vec(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, HouseholdError> {
        let decoded: Self = crate::cbor::from_canonical_slice_strict(bytes)?;
        if decoded.version != PAIR_MACHINE_VERSION || decoded.error != Self::ERROR {
            return Err(HouseholdError::InvalidCert(
                "finalize restart-required shape mismatch".into(),
            ));
        }
        Ok(decoded)
    }
}

impl Default for FinalizeRestartRequired {
    fn default() -> Self {
        Self::new()
    }
}

/// Optional response header on M2's `local/finalize` response carrying the
/// candidate's current Tailnet address.
///
/// This stays outside [`FinalizeAck`] so the deterministic 2PC body remains
/// byte-compatible with older peers. The value is an unsigned,
/// non-authoritative reachability hint: callers must validate it before
/// placing it in a liveness cache, and must never use it as identity or
/// membership authority.
pub const FINALIZE_CANDIDATE_TAILSCALE_ADDR_HEADER: &str = "x-soyeht-candidate-tailscale-addr";

/// Wire body submitted by the owner iPhone to approve a pending join event.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct OwnerApproval {
    #[serde(rename = "v")]
    pub version: u8,
    pub cursor: u64,
    pub approval_sig: P256Signature,
}

impl OwnerApproval {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        crate::cbor::to_canonical_vec(self)
    }
}

/// Signed owner approval context per `data-model.md::OwnerApprovalContext`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct OwnerApprovalContext {
    #[serde(rename = "v")]
    pub version: u8,
    pub purpose: String,
    pub hh_id: HouseholdId,
    pub p_id: crate::machine_cert::PersonId,
    pub cursor: u64,
    pub challenge_sig: ByteBuf,
    pub timestamp: u64,
}

impl OwnerApprovalContext {
    pub const PURPOSE: &'static str = "owner-approve-join";

    #[must_use]
    pub fn build(
        hh_id: HouseholdId,
        p_id: crate::machine_cert::PersonId,
        cursor: u64,
        challenge_sig: ByteBuf,
        timestamp: u64,
    ) -> Self {
        Self {
            version: PAIR_MACHINE_VERSION,
            purpose: Self::PURPOSE.to_string(),
            hh_id,
            p_id,
            cursor,
            challenge_sig,
            timestamp,
        }
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        crate::cbor::to_canonical_vec(self)
    }

    pub fn verify(
        &self,
        owner_pub: &P256PublicKey,
        approval_sig: &P256Signature,
    ) -> Result<(), HouseholdError> {
        if self.version != PAIR_MACHINE_VERSION || self.purpose != Self::PURPOSE {
            return Err(HouseholdError::InvalidCert(
                "owner approval context shape mismatch".into(),
            ));
        }
        verify_signature(owner_pub, &self.to_canonical_bytes()?, approval_sig)
    }
}

/// Inputs for M1's 2PC step 10 (`local/finalize` POST to M2).
pub struct FinalizeWithM2Options<'a> {
    pub addr: &'a str,
    pub join_request_cbor: &'a [u8],
    pub founder_cert: &'a MachineCert,
    pub founder_tailscale_addr: Option<String>,
    pub push_token_seed: Option<OwnerDevicePushToken>,
    pub response_signer: &'a dyn IdentityKey,
}

/// Single durable authority for founder-side Phase-3 recovery.
///
/// Recovery never reconstructs or mixes these values from independent marker,
/// pending-response, and staged-file records. The manifest binds one lifecycle
/// generation, the exact request/response/Ack, both machine identities, and
/// every staged artifact that founder recovery is authorized to promote.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Phase3RecoveryManifestV1 {
    #[serde(rename = "v")]
    version: u8,
    lifecycle_generation: ByteBuf,
    hh_id: String,
    candidate_m_id: String,
    founder_m_id: String,
    founder_cert_hash: ByteBuf,
    cached_join_request_hash: ByteBuf,
    exact_join_response: ByteBuf,
    exact_finalize_ack: ByteBuf,
    staged_candidate_cert_hash: ByteBuf,
    staged_self_shard_hash: ByteBuf,
    staged_household_record_hash: ByteBuf,
    preinstall_household_record_hash: ByteBuf,
}

impl Phase3RecoveryManifestV1 {
    pub const VERSION: u8 = 1;

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        crate::cbor::to_canonical_vec(self)
    }

    #[must_use]
    pub fn lifecycle_generation(&self) -> &[u8] {
        self.lifecycle_generation.as_ref()
    }

    #[must_use]
    pub fn candidate_m_id(&self) -> &str {
        &self.candidate_m_id
    }

    #[must_use]
    pub fn hh_id(&self) -> &str {
        &self.hh_id
    }

    #[must_use]
    pub fn founder_m_id(&self) -> &str {
        &self.founder_m_id
    }

    #[must_use]
    pub fn exact_join_response(&self) -> &[u8] {
        self.exact_join_response.as_ref()
    }

    #[must_use]
    pub fn exact_finalize_ack(&self) -> &[u8] {
        self.exact_finalize_ack.as_ref()
    }

    fn join_response(&self) -> Result<JoinResponse, CeremonyError> {
        crate::cbor::from_canonical_slice_strict(self.exact_join_response.as_ref())
            .map_err(|error| CeremonyError::Cbor(format!("manifest JoinResponse: {error}")))
    }

    fn expected_ack(&self) -> Result<FinalizeAck, CeremonyError> {
        crate::cbor::from_canonical_slice_strict(self.exact_finalize_ack.as_ref())
            .map_err(|error| CeremonyError::Cbor(format!("manifest FinalizeAck: {error}")))
    }

    fn validate_hash(name: &str, encoded: &ByteBuf, exact: &[u8]) -> Result<(), CeremonyError> {
        if encoded.as_ref() != blake3::hash(exact).as_bytes() {
            return Err(CeremonyError::Cbor(format!(
                "manifest {name} hash mismatch"
            )));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CeremonyError> {
        if self.version != Self::VERSION
            || self.lifecycle_generation.len() != 32
            || self.founder_cert_hash.len() != 32
            || self.cached_join_request_hash.len() != 32
            || self.staged_candidate_cert_hash.len() != 32
            || self.staged_self_shard_hash.len() != 32
            || self.staged_household_record_hash.len() != 32
            || self.preinstall_household_record_hash.len() != 32
        {
            return Err(CeremonyError::Cbor(
                "Phase3 recovery manifest fixed-width shape mismatch".into(),
            ));
        }
        let join_response = self.join_response()?;
        let expected_ack = self.expected_ack()?;
        join_response
            .household_record
            .validate()
            .map_err(|error| CeremonyError::Cbor(format!("manifest household record: {error}")))?;
        if join_response.version != PAIR_MACHINE_VERSION
            || join_response.machine_cert.m_id.to_string() != self.candidate_m_id
            || join_response.household_record.hh_id.to_string() != self.hh_id
            || join_response.join_request_hash.as_ref() != self.cached_join_request_hash.as_ref()
        {
            return Err(CeremonyError::Cbor(
                "Phase3 recovery manifest response binding mismatch".into(),
            ));
        }
        validate_finalize_ack_bytes(
            self.exact_finalize_ack.as_ref(),
            &join_response.machine_cert,
        )?;
        if expected_ack.m_id != self.candidate_m_id {
            return Err(CeremonyError::Cbor(
                "Phase3 recovery manifest Ack identity mismatch".into(),
            ));
        }

        let candidate_cert_bytes = crate::cbor::to_canonical_vec(&join_response.machine_cert)
            .map_err(|error| CeremonyError::Cbor(format!("manifest candidate cert: {error}")))?;
        Self::validate_hash(
            "candidate cert",
            &self.staged_candidate_cert_hash,
            &candidate_cert_bytes,
        )?;
        let record_bytes = crate::cbor::to_canonical_vec(&join_response.household_record)
            .map_err(|error| CeremonyError::Cbor(format!("manifest household record: {error}")))?;
        Self::validate_hash(
            "household record",
            &self.staged_household_record_hash,
            &record_bytes,
        )?;

        if !join_response
            .household_record
            .members
            .iter()
            .any(|member| member.to_string() == self.candidate_m_id)
            || !join_response
                .household_record
                .members
                .iter()
                .any(|member| member.to_string() == self.founder_m_id)
        {
            return Err(CeremonyError::Cbor(
                "manifest candidate absent from staged household record".into(),
            ));
        }
        let mut founder_entries = join_response.peer_list.iter().filter(|peer| {
            peer.m_id == self.founder_m_id
                && peer
                    .machine_cert
                    .as_ref()
                    .is_some_and(|cert| cert.m_id.to_string() == self.founder_m_id)
        });
        let founder_entry = founder_entries.next().ok_or_else(|| {
            CeremonyError::Cbor("manifest founder certificate missing from peer list".into())
        })?;
        if founder_entries.next().is_some() {
            return Err(CeremonyError::Cbor(
                "manifest founder certificate duplicated in peer list".into(),
            ));
        }
        let founder_cert = founder_entry
            .machine_cert
            .as_ref()
            .ok_or_else(|| CeremonyError::Cbor("manifest founder certificate missing".into()))?;
        if founder_entry.m_pub.as_ref() != founder_cert.m_pub.as_bytes()
            || founder_entry.hostname != founder_cert.hostname
        {
            return Err(CeremonyError::Cbor(
                "manifest founder peer entry differs from certificate".into(),
            ));
        }
        let founder_hash = machine_cert_hash(founder_cert)
            .map_err(|error| CeremonyError::Cbor(format!("manifest founder cert: {error}")))?;
        if self.founder_cert_hash.as_ref() != founder_hash {
            return Err(CeremonyError::Cbor(
                "manifest founder certificate hash mismatch".into(),
            ));
        }
        founder_cert
            .verify(&join_response.household_record.hh_pub)
            .map_err(|error| CeremonyError::Cbor(format!("manifest founder cert: {error}")))?;
        join_response
            .machine_cert
            .verify(&join_response.household_record.hh_pub)
            .map_err(|error| CeremonyError::Cbor(format!("manifest candidate cert: {error}")))?;
        join_response
            .verify_response_sig(founder_cert)
            .map_err(|error| {
                CeremonyError::Cbor(format!("manifest response signature: {error}"))
            })?;
        Ok(())
    }
}

/// Successful result of M1's call to M2's `local/finalize`.
pub struct FinalizeWithM2Outcome {
    pub ack: FinalizeAck,
    pub join_response: JoinResponse,
    pub join_response_bytes: Vec<u8>,
    /// Unsigned, optional reachability hint read from
    /// [`FINALIZE_CANDIDATE_TAILSCALE_ADDR_HEADER`].
    ///
    /// This is surfaced only after the deterministic [`FinalizeAck`] body has
    /// passed its version, machine-id, and cert-hash checks.
    pub candidate_tailscale_addr: Option<String>,
}

#[derive(Debug)]
struct VerifiedFinalizeAck {
    ack: FinalizeAck,
    candidate_tailscale_addr: Option<String>,
}

enum FinalizePostOutcome {
    Ack(VerifiedFinalizeAck),
    RestartRequired(Duration),
}

enum FinalizePostError {
    Transport(CeremonyError),
    RetryableServer(CeremonyError),
    Protocol(CeremonyError),
}

impl FinalizePostError {
    fn into_ceremony(self) -> CeremonyError {
        match self {
            Self::Transport(error) | Self::RetryableServer(error) | Self::Protocol(error) => error,
        }
    }
}

#[derive(Clone, Copy)]
struct FinalizeRetryPolicy {
    budget: Duration,
    request_timeout: Duration,
    maximum_sleep: Duration,
}

impl FinalizeRetryPolicy {
    const PRODUCTION: Self = Self {
        budget: RECOVERY_TIMEOUT,
        request_timeout: FINALIZE_HTTP_TIMEOUT,
        maximum_sleep: Duration::from_secs(FINALIZE_RESTART_RETRY_AFTER_SECS),
    };

    /// The production policy, with the retry budget read from the test-only
    /// [`RECOVERY_TIMEOUT_ENV`] env var (clamped, defaulting to
    /// [`RECOVERY_TIMEOUT`]). Non-`const` on purpose: a `const` cannot read the
    /// process environment, and making the budget injectable is the whole point.
    /// Every other field is the production value; only `budget` is affected.
    ///
    /// Safety of the knob: a launched finalize POST is `MayHaveTakenEffect`, so
    /// an elapsed budget fails closed (`FinalizeOutcomeIndeterminate`, all
    /// recovery evidence retained) and can never authorize a rollback to N=1.
    /// The ceiling IS the production value, so even if the env reaches a
    /// production process it can only shorten the wait — never extend it past
    /// what production allows. The floor keeps the budget large enough that at
    /// least one probe happens: a budget nobody can spend probing is not a
    /// timeout, it is a skipped question.
    ///
    /// The env path is test-only in fact — production never sets
    /// [`RECOVERY_TIMEOUT_ENV`]; it exists to drop the ~300s finalize retry the
    /// three `phase3_atomic_rollback` tests each wait out against an unreachable
    /// M2 (before the handler returns 500) to ~1-2s, which is what those tests
    /// actually prove.
    ///
    /// Discovered property (negative control, falsifies "only shortens"): on the
    /// `recovers_to_commit` path, a budget exhausted WITHOUT a finalize-POST
    /// attempt classifies differently from an attempt that was made and rejected,
    /// and the handler takes a different branch — so shortening the budget can
    /// change the outcome there, not just its latency. That test is therefore
    /// run at the production budget (it is fast there); only the three slow
    /// "unreachable M2" tests run with the injected budget, where the verdict is
    /// the same fail-closed either way. If the production budget ever changes,
    /// that test is the alarm for this sensitivity.
    ///
    /// Floor caveat: at the 1s floor, a pathologically slow runner could spend
    /// the whole budget before any probe happens (zero attempts). That is
    /// acceptable for the test-only path this knob serves; it must never apply
    /// to production, where the budget is [`RECOVERY_TIMEOUT`] (300s) regardless.
    #[must_use]
    fn production() -> Self {
        Self {
            budget: recovery_timeout_from_env(),
            ..Self::PRODUCTION
        }
    }
}

/// Env var carrying the Phase-3 finalize-retry budget, in seconds. Test-only:
/// absent means [`RECOVERY_TIMEOUT`], byte for byte the behaviour that shipped
/// before this knob existed.
const RECOVERY_TIMEOUT_ENV: &str = "THEYOS_PHASE3_RECOVERY_TIMEOUT_SECS";

/// Floor for the injected budget (seconds). See [`FinalizeRetryPolicy::production`].
const RECOVERY_TIMEOUT_MIN_SECS: u64 = 1;

/// Ceiling for the injected budget: the production value. The knob can only
/// shorten the wait, never extend it.
const RECOVERY_TIMEOUT_MAX_SECS: u64 = RECOVERY_TIMEOUT.as_secs();

/// Clamp a parsed Phase-3 finalize-retry budget: in-range passes through;
/// `None` or out-of-range falls back to [`RECOVERY_TIMEOUT`]. Split from the
/// env read so the parse/clamp/default policy is unit-testable without mutating
/// process env.
#[must_use]
fn clamp_recovery_timeout(parsed: Option<u64>) -> Duration {
    parsed
        .filter(|secs| (RECOVERY_TIMEOUT_MIN_SECS..=RECOVERY_TIMEOUT_MAX_SECS).contains(secs))
        .map_or(RECOVERY_TIMEOUT, Duration::from_secs)
}

/// Read the Phase-3 finalize-retry budget from [`RECOVERY_TIMEOUT_ENV`],
/// clamped to [`RECOVERY_TIMEOUT_MIN_SECS`]..=[`RECOVERY_TIMEOUT_MAX_SECS`] and
/// defaulting to [`RECOVERY_TIMEOUT`]. Single owner for that read — do not
/// re-implement the parse/clamp/default at call sites.
#[must_use]
fn recovery_timeout_from_env() -> Duration {
    clamp_recovery_timeout(
        std::env::var(RECOVERY_TIMEOUT_ENV)
            .ok()
            .and_then(|s| s.parse::<u64>().ok()),
    )
}

pub fn machine_cert_hash(cert: &MachineCert) -> Result<[u8; 32], HouseholdError> {
    let bytes = crate::cbor::to_canonical_vec(cert)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn read_finalize_response_body(
    response: ureq::Response,
    action: &str,
) -> Result<Vec<u8>, FinalizePostError> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_FINALIZE_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| {
            FinalizePostError::Transport(CeremonyError::Http(format!(
                "{action}: read response body: {e}"
            )))
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FINALIZE_RESPONSE_BYTES {
        return Err(FinalizePostError::Protocol(CeremonyError::FinalizeAck(
            format!("{action}: response body exceeds {MAX_FINALIZE_RESPONSE_BYTES} bytes"),
        )));
    }
    Ok(bytes)
}

fn validate_finalize_ack_bytes(
    bytes: &[u8],
    expected_cert: &MachineCert,
) -> Result<FinalizeAck, CeremonyError> {
    let ack: FinalizeAck = crate::cbor::from_canonical_slice_strict(bytes)
        .map_err(|e| CeremonyError::FinalizeAck(format!("decode: {e}")))?;
    if ack.version != PAIR_MACHINE_VERSION {
        return Err(CeremonyError::FinalizeAck(format!(
            "unsupported version {}",
            ack.version
        )));
    }
    if ack.m_id != expected_cert.m_id.to_string() {
        return Err(CeremonyError::FinalizeAck(format!(
            "m_id mismatch: expected {}, got {}",
            expected_cert.m_id, ack.m_id
        )));
    }
    let expected_hash = machine_cert_hash(expected_cert)
        .map_err(|e| CeremonyError::FinalizeAck(format!("hash MachineCert: {e}")))?;
    if ack.machine_cert_hash.as_ref() != expected_hash.as_slice() {
        return Err(CeremonyError::FinalizeAck(
            "machine_cert_hash mismatch".into(),
        ));
    }
    Ok(ack)
}

fn post_finalize_once(
    action: &str,
    url: &str,
    body: &[u8],
    expected_cert: &MachineCert,
    request_timeout: Duration,
) -> Result<FinalizePostOutcome, FinalizePostError> {
    let agent = ureq::AgentBuilder::new().timeout(request_timeout).build();
    let response = match agent
        .post(url)
        .set("Content-Type", "application/cbor")
        .send_bytes(body)
    {
        Ok(response) => response,
        Err(ureq::Error::Status(503, response)) => {
            let retry_after = response.header("Retry-After");
            if retry_after != Some("1") {
                return Err(FinalizePostError::Protocol(CeremonyError::Http(format!(
                    "{action}: unrecognized 503 without Retry-After: 1"
                ))));
            }
            let bytes = read_finalize_response_body(response, action)?;
            FinalizeRestartRequired::from_canonical_bytes(&bytes).map_err(|e| {
                FinalizePostError::Protocol(CeremonyError::Http(format!(
                    "{action}: unrecognized 503 restart-required body: {e}"
                )))
            })?;
            return Ok(FinalizePostOutcome::RestartRequired(Duration::from_secs(
                FINALIZE_RESTART_RETRY_AFTER_SECS,
            )));
        }
        Err(ureq::Error::Status(code, _)) => {
            let error = finalize_http_status_error(action, code);
            return if code >= 500 {
                Err(FinalizePostError::RetryableServer(error))
            } else {
                Err(FinalizePostError::Protocol(error))
            };
        }
        Err(other @ ureq::Error::Transport(_)) => {
            return Err(FinalizePostError::Transport(CeremonyError::Http(format!(
                "{action}: {other}"
            ))));
        }
    };
    if response.status() != 200 {
        return Err(FinalizePostError::Protocol(CeremonyError::FinalizeAck(
            format!(
                "{action}: unexpected successful status {}",
                response.status()
            ),
        )));
    }
    let candidate_tailscale_addr = response
        .header(FINALIZE_CANDIDATE_TAILSCALE_ADDR_HEADER)
        .map(str::to_owned);
    let bytes = read_finalize_response_body(response, action)?;
    let ack =
        validate_finalize_ack_bytes(&bytes, expected_cert).map_err(FinalizePostError::Protocol)?;
    Ok(FinalizePostOutcome::Ack(VerifiedFinalizeAck {
        ack,
        candidate_tailscale_addr,
    }))
}

fn post_finalize_until_ack(
    url: &str,
    body: &[u8],
    expected_cert: &MachineCert,
    policy: FinalizeRetryPolicy,
) -> Result<VerifiedFinalizeAck, CeremonyError> {
    let started = std::time::Instant::now();
    // Once any request may have reached M2 without a trustworthy terminal
    // response, no later rejection can prove the earlier request had no
    // effect. Keep that evidence monotonic across exact-body retries.
    let mut ambiguous_attempt_observed = false;
    loop {
        let remaining = policy.budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(CeremonyError::Http(format!(
                "POST {url}: finalize restart recovery timed out"
            )));
        }
        let request_timeout = policy.request_timeout.min(remaining);
        match post_finalize_once(
            &format!("POST {url}"),
            url,
            body,
            expected_cert,
            request_timeout,
        ) {
            Ok(FinalizePostOutcome::Ack(verified)) => return Ok(verified),
            Ok(FinalizePostOutcome::RestartRequired(server_delay)) => {
                ambiguous_attempt_observed = true;
                let remaining = policy.budget.saturating_sub(started.elapsed());
                let delay = server_delay.min(policy.maximum_sleep).min(remaining);
                std::thread::sleep(delay);
            }
            Err(
                FinalizePostError::Transport(CeremonyError::Http(error))
                | FinalizePostError::RetryableServer(CeremonyError::Http(error)),
            ) => {
                ambiguous_attempt_observed = true;
                let remaining = policy.budget.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(CeremonyError::Http(format!(
                        "POST {url}: finalize restart recovery timed out after: {error}"
                    )));
                }
                std::thread::sleep(
                    FINALIZE_RETRY_POLL_INTERVAL
                        .min(policy.maximum_sleep)
                        .min(remaining),
                );
            }
            Err(FinalizePostError::Protocol(error @ CeremonyError::Http(_)))
                if ambiguous_attempt_observed =>
            {
                let remaining = policy.budget.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(CeremonyError::Http(format!(
                        "POST {url}: finalize restart recovery timed out after: {error}"
                    )));
                }
                std::thread::sleep(
                    FINALIZE_RETRY_POLL_INTERVAL
                        .min(policy.maximum_sleep)
                        .min(remaining),
                );
            }
            Err(FinalizePostError::Protocol(error @ CeremonyError::FinalizeRejected(_)))
                if ambiguous_attempt_observed =>
            {
                return Err(CeremonyError::Http(format!(
                    "POST {url}: candidate rejected exact finalize replay after restart: {error}"
                )));
            }
            Err(error) => return Err(error.into_ceremony()),
        }
    }
}

#[must_use]
pub fn join_request_hash(join_request_cbor: &[u8]) -> [u8; 32] {
    *blake3::hash(join_request_cbor).as_bytes()
}

/// Path to the legacy single-shard plaintext file kept on a 1-machine
/// household. Phase 3's commit deletes this file as the very last
/// step of the 2PC, completing the destructive sole-shard transition.
#[must_use]
pub fn household_root_sole_path(state_dir: &Path) -> PathBuf {
    crate::storage::household_dir(state_dir).join("household_root_sole.cbor")
}

#[must_use]
pub fn shamir_self_shard_path(state_dir: &Path) -> PathBuf {
    crate::storage::household_dir(state_dir)
        .join("shamir")
        .join("self_shard.cbor")
}

impl CeremonyTxn {
    /// Build the candidate's `MachineCert`, split the household
    /// scalar into 2-of-2 Shamir shards, encrypt M1's shard for at-
    /// rest storage, encrypt M2's shard for peer-delivery, build the
    /// post-join `HouseholdRecord`, and stage every persisted file via
    /// [`crate::storage::stage_commit_files`].
    ///
    /// **Lifetime invariant**: `inputs.hh_priv` and `inputs.m1_priv_scalar`
    /// are consumed inside this function. They are dropped (and zeroized)
    /// before return — the resulting [`CeremonyTxn`] never carries them.
    pub fn prepare(inputs: CeremonyInputs) -> Result<Self, CeremonyError> {
        // Move the scalars out of `inputs` immediately and into local
        // bindings whose scope ends before this function returns. This
        // is what enforces the "hh_priv lives only during prepare"
        // invariant — the value is destructured and dropped inline.
        let CeremonyInputs {
            hh_priv,
            hh_id,
            hh_pub_sec1: _,
            m1_priv_scalar,
            m1_pub_sec1,
            m1_id,
            candidate_m_pub_sec1,
            candidate_hostname,
            candidate_platform,
            joined_at,
            state_dir,
            existing_record,
            policy,
        } = inputs;

        let candidate_cert = issue_for_candidate(
            &hh_priv,
            &hh_id,
            &candidate_m_pub_sec1,
            &candidate_hostname,
            candidate_platform,
            joined_at,
        )?;
        let candidate_m_pub = P256PublicKey::from_bytes(&candidate_m_pub_sec1)
            .map_err(|e| CeremonyError::Cbor(format!("candidate m_pub: {e}")))?;
        let candidate_m_id: MachineId = derive_machine_id(&candidate_m_pub);
        let candidate_m_id_str = candidate_m_id.to_string();

        // Split + encrypt. `shards[0]` belongs to M1 (x=1) and
        // `shards[1]` to M2 (x=2).
        let shards = split_2_of_2(&hh_priv);
        let m1_pub = P256PublicKey::from_bytes(&m1_pub_sec1)
            .map_err(|e| CeremonyError::Cbor(format!("m1 pub: {e}")))?;
        let self_es = encrypt_for_self(&shards[0], &m1_priv_scalar, &m1_pub, &m1_id, SHARD_X_M1)?;
        let peer_es = encrypt_for_peer(
            &shards[1],
            &m1_priv_scalar,
            &candidate_m_pub,
            &candidate_m_id_str,
            SHARD_X_M2,
        )?;

        // Build the post-join HouseholdRecord. Members go in stable
        // lexicographic order so the on-disk bytes are deterministic
        // independent of which side ran the ceremony.
        //
        // If the candidate is already a member, we error rather than
        // silently dedup. The two ways this can happen are both
        // programming errors that the operator should know about:
        //   1. Idempotency bug (a duplicate JoinRequest from M2 was
        //      already promoted into membership).
        //   2. Caller didn't gate the ceremony on "candidate not yet
        //      a member" before invoking prepare.
        // The HTTP wrapper for `/api/v1/household/join-request`
        // collapses EVERY failure (including this one) to the
        // deterministic-CBOR 401 `{"error":"unauthenticated"}`
        // surface mandated by R14 / FR-019a / T044 / T077 — no 409,
        // no breakdown of "already member" vs "bad signature" vs
        // "no window". The typed `AlreadyMember` here exists for
        // structured `tracing::warn!` payloads on M1 only and never
        // reaches the wire.
        if existing_record.members.iter().any(|m| m == &candidate_m_id) {
            return Err(CeremonyError::AlreadyMember(candidate_m_id_str.clone()));
        }
        let mut new_members: Vec<MachineId> = existing_record.members.clone();
        new_members.push(candidate_m_id);
        new_members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let preinstall_household_record_hash = *blake3::hash(
            &crate::cbor::to_canonical_vec(&existing_record).map_err(|error| {
                CeremonyError::Cbor(format!("encode preinstall household record: {error}"))
            })?,
        )
        .as_bytes();
        let new_record = HouseholdRecord {
            version: existing_record.version,
            hh_id: existing_record.hh_id.clone(),
            hh_pub: existing_record.hh_pub.clone(),
            name: existing_record.name.clone(),
            created_at: existing_record.created_at,
            shamir_k: 2,
            shamir_n: 2,
            members: new_members,
            is_follower: false,
        };
        new_record
            .validate()
            .map_err(|e| CeremonyError::Cbor(format!("post-join record validation failed: {e}")))?;

        // Stage M1-side files atomically: candidate's MachineCert,
        // updated HouseholdRecord, and M1's encrypted shard.
        let candidate_cert_bytes = crate::cbor::to_canonical_vec(&candidate_cert)
            .map_err(|e| CeremonyError::Cbor(format!("encode candidate cert: {e}")))?;
        let new_record_bytes = crate::cbor::to_canonical_vec(&new_record)
            .map_err(|e| CeremonyError::Cbor(format!("encode new record: {e}")))?;
        let self_shard_bytes = self_es
            .to_canonical_bytes()
            .map_err(|e| CeremonyError::Cbor(format!("encode self shard: {e}")))?;
        // The promotion order matters for crash-consistency. The
        // `household_record.cbor` rename to `shamir_n=2` is the
        // canonical "this ceremony is committed" marker. Putting it
        // LAST means:
        //   - Crash before the record rename → record on disk still
        //     reports `shamir_n=1`. Any `.staged` files are orphans
        //     belonging to a logically rolled-back ceremony, which
        //     `recover_partial_phase3_commit` cleans up at boot.
        //   - Crash after the record rename → household is logically
        //     post-Shamir (`shamir_n=2`). Any `.staged` files are
        //     for a roll-forward that crashed mid-promotion;
        //     `recover_partial_phase3_commit` finishes them on the
        //     next boot.
        // Without this ordering, a crash between intermediate renames
        // could leave the household record in a state inconsistent
        // with the cert/shard files actually on disk, requiring
        // operator intervention.
        let staged_files = vec![
            (
                crate::storage::machine_cert_for(&state_dir, &candidate_m_id_str),
                candidate_cert_bytes,
            ),
            (shamir_self_shard_path(&state_dir), self_shard_bytes),
            (
                crate::storage::household_record_path(&state_dir),
                new_record_bytes,
            ),
        ];
        let staged = crate::storage::stage_commit_files(&staged_files)?;

        let sole_shard_path = household_root_sole_path(&state_dir);

        // hh_priv, m1_priv_scalar, shards drop here (Zeroizing erases
        // them from heap). Nothing in CeremonyTxn references them.
        drop(hh_priv);
        drop(m1_priv_scalar);
        drop(shards);

        Ok(Self {
            candidate_cert,
            self_encrypted_shard: self_es,
            peer_encrypted_shard: peer_es,
            new_household_record: new_record,
            preinstall_household_record_hash,
            staged: Some(staged),
            sole_shard_path,
            state_dir,
            hh_id,
            policy,
            closed: false,
        })
    }

    /// Borrow the post-join `HouseholdRecord` (used by callers that
    /// need to reload it into memory after commit without re-reading
    /// the disk).
    #[must_use]
    pub fn new_household_record(&self) -> &HouseholdRecord {
        &self.new_household_record
    }

    /// Borrow the candidate's signed `MachineCert`.
    #[must_use]
    pub fn candidate_cert(&self) -> &MachineCert {
        &self.candidate_cert
    }

    /// Borrow the encrypted shard delivered to the candidate as part
    /// of the `JoinResponse`.
    #[must_use]
    pub fn peer_encrypted_shard(&self) -> &EncryptedShard {
        &self.peer_encrypted_shard
    }

    /// Borrow M1's at-rest encrypted shard.
    #[must_use]
    pub fn self_encrypted_shard(&self) -> &EncryptedShard {
        &self.self_encrypted_shard
    }

    /// Build the authenticated `JoinResponse` M1 sends to M2.
    ///
    /// This assembles the Phase 3 `peer_list` with M1's `MachineCert`,
    /// binds the response to the cached `JoinRequest`, and signs the
    /// deterministic CBOR envelope with M1's machine key.
    pub fn build_join_response(
        &self,
        opts: &FinalizeWithM2Options<'_>,
    ) -> Result<JoinResponse, CeremonyError> {
        JoinResponseUnsigned {
            version: PAIR_MACHINE_VERSION,
            join_request_hash: ByteBuf::from(join_request_hash(opts.join_request_cbor).to_vec()),
            machine_cert: self.candidate_cert.clone(),
            encrypted_shard: self.peer_encrypted_shard.clone(),
            household_record: self.new_household_record.clone(),
            peer_list: vec![PeerEntry {
                m_id: opts.founder_cert.m_id.to_string(),
                m_pub: ByteBuf::from(opts.founder_cert.m_pub.as_bytes().to_vec()),
                hostname: opts.founder_cert.hostname.clone(),
                tailscale_addr: opts.founder_tailscale_addr.clone(),
                machine_cert: Some(opts.founder_cert.clone()),
            }],
            push_token_seed: opts.push_token_seed.clone(),
        }
        .sign(opts.response_signer)
        .map_err(CeremonyError::Sign)
    }

    /// Build the one durable authority consumed by founder restart recovery.
    /// The returned manifest contains the exact bytes later `POSTed` by
    /// [`Self::finalize_manifest_with_m2`]; callers must durably commit it
    /// before launching that method.
    pub fn build_phase3_recovery_manifest(
        &self,
        opts: &FinalizeWithM2Options<'_>,
        lifecycle_generation: &HouseholdLifecycleGenerationV1,
    ) -> Result<Phase3RecoveryManifestV1, CeremonyError> {
        let join_request: JoinRequest =
            crate::cbor::from_canonical_slice_strict(opts.join_request_cbor)
                .map_err(|error| CeremonyError::Cbor(format!("cached JoinRequest: {error}")))?;
        verify_join_request(&join_request)
            .map_err(|error| CeremonyError::Cbor(format!("cached JoinRequest: {error}")))?;
        if join_request.m_pub.as_ref() != self.candidate_cert.m_pub.as_bytes() {
            return Err(CeremonyError::Cbor(
                "cached JoinRequest candidate key mismatch".into(),
            ));
        }
        let join_response = self.build_join_response(opts)?;
        let exact_join_response = join_response
            .to_canonical_bytes()
            .map_err(|error| CeremonyError::Cbor(format!("encode JoinResponse: {error}")))?;
        let exact_finalize_ack = FinalizeAck::for_machine_cert(&self.candidate_cert)
            .map_err(|error| CeremonyError::Cbor(format!("build FinalizeAck: {error}")))?
            .to_canonical_bytes()
            .map_err(|error| CeremonyError::Cbor(format!("encode FinalizeAck: {error}")))?;
        let candidate_cert_bytes = crate::cbor::to_canonical_vec(&self.candidate_cert)
            .map_err(|error| CeremonyError::Cbor(format!("encode candidate cert: {error}")))?;
        let self_shard_bytes = self
            .self_encrypted_shard
            .to_canonical_bytes()
            .map_err(|error| CeremonyError::Cbor(format!("encode self shard: {error}")))?;
        let record_bytes = crate::cbor::to_canonical_vec(&self.new_household_record)
            .map_err(|error| CeremonyError::Cbor(format!("encode household record: {error}")))?;
        let founder_cert_hash = machine_cert_hash(opts.founder_cert)
            .map_err(|error| CeremonyError::Cbor(format!("hash founder cert: {error}")))?;
        let manifest = Phase3RecoveryManifestV1 {
            version: Phase3RecoveryManifestV1::VERSION,
            lifecycle_generation: ByteBuf::from(lifecycle_generation.token_bytes().to_vec()),
            hh_id: self.hh_id.to_string(),
            candidate_m_id: self.candidate_cert.m_id.to_string(),
            founder_m_id: opts.founder_cert.m_id.to_string(),
            founder_cert_hash: ByteBuf::from(founder_cert_hash.to_vec()),
            cached_join_request_hash: ByteBuf::from(
                join_request_hash(opts.join_request_cbor).to_vec(),
            ),
            exact_join_response: ByteBuf::from(exact_join_response),
            exact_finalize_ack: ByteBuf::from(exact_finalize_ack),
            staged_candidate_cert_hash: ByteBuf::from(
                blake3::hash(&candidate_cert_bytes).as_bytes().to_vec(),
            ),
            staged_self_shard_hash: ByteBuf::from(
                blake3::hash(&self_shard_bytes).as_bytes().to_vec(),
            ),
            staged_household_record_hash: ByteBuf::from(
                blake3::hash(&record_bytes).as_bytes().to_vec(),
            ),
            preinstall_household_record_hash: ByteBuf::from(
                self.preinstall_household_record_hash.to_vec(),
            ),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// POST only the exact bytes already committed in `manifest` and accept
    /// only its exact Ack. No ceremony bytes are rebuilt on this path.
    pub fn finalize_manifest_with_m2(
        &self,
        addr: &str,
        manifest: &Phase3RecoveryManifestV1,
    ) -> Result<FinalizeWithM2Outcome, CeremonyError> {
        manifest.validate()?;
        let join_response = manifest.join_response()?;
        if join_response.machine_cert != self.candidate_cert {
            return Err(CeremonyError::Cbor(
                "manifest candidate certificate does not belong to transaction".into(),
            ));
        }
        let url = local_finalize_url(addr);
        let verified = post_finalize_until_ack(
            &url,
            manifest.exact_join_response(),
            &self.candidate_cert,
            FinalizeRetryPolicy::production(),
        )?;
        let returned_ack_bytes = verified
            .ack
            .to_canonical_bytes()
            .map_err(|error| CeremonyError::FinalizeAck(format!("encode: {error}")))?;
        if returned_ack_bytes != manifest.exact_finalize_ack() {
            return Err(CeremonyError::FinalizeAck(
                "Ack differs from the exact durable recovery manifest".into(),
            ));
        }
        Ok(FinalizeWithM2Outcome {
            ack: verified.ack,
            join_response,
            join_response_bytes: manifest.exact_join_response().to_vec(),
            candidate_tailscale_addr: verified.candidate_tailscale_addr,
        })
    }

    /// POST the authenticated `JoinResponse` to M2 and verify its ack.
    pub fn finalize_with_m2(
        &self,
        opts: &FinalizeWithM2Options<'_>,
    ) -> Result<FinalizeWithM2Outcome, CeremonyError> {
        let join_response = self.build_join_response(opts)?;
        let join_response_bytes = join_response
            .to_canonical_bytes()
            .map_err(|e| CeremonyError::Cbor(format!("encode JoinResponse: {e}")))?;
        let url = local_finalize_url(opts.addr);
        let verified = post_finalize_until_ack(
            &url,
            &join_response_bytes,
            &self.candidate_cert,
            FinalizeRetryPolicy::production(),
        )?;
        Ok(FinalizeWithM2Outcome {
            ack: verified.ack,
            join_response,
            join_response_bytes,
            candidate_tailscale_addr: verified.candidate_tailscale_addr,
        })
    }

    /// Promote every staged file, then destroy the **two** remaining sources
    /// of `HH_priv` plaintext custody:
    ///
    /// 1. The keystore entry (`SE` Keychain on macOS, Secret-Service on
    ///    Linux, or the file fallback under `THEYOS_FORCE_SOFTWARE_KEYS=1`).
    /// 2. `household_root_sole.cbor` — the on-disk plaintext sole shard
    ///    from the 1-machine household.
    ///
    /// Both destructions are idempotent (post-condition is "the entry is
    /// absent", not "we unlinked it ourselves").
    ///
    /// Crash semantics:
    /// - Before `staged.commit()`: full rollback to sole-shard.
    /// - Between `staged.commit()` and keystore-destroy: both copies still
    ///   present → recovery may rollback OR continue forward depending on
    ///   the M2-side probe (per `contracts/shamir-transition.md`).
    /// - Between keystore-destroy and sole-shard-delete: the keystore copy
    ///   is gone → recovery MUST continue forward (delete the orphan
    ///   sole-shard, finish step 13/14 of the 2PC).
    /// - After sole-shard-delete: fully committed.
    ///
    /// Returns the canonical CBOR bytes of the candidate's `MachineCert`.
    pub fn commit(mut self) -> Result<Vec<u8>, CeremonyError> {
        if self.closed {
            return Err(CeremonyError::AlreadyClosed);
        }
        let staged = self.staged.take().ok_or(CeremonyError::AlreadyClosed)?;
        staged.commit()?;

        // Once `staged.commit()` returns Ok, the household has logically
        // grown to N=2 (M1's shard, M2's cert and shard, the new
        // `HouseholdRecord`, and the committed window snapshot are all
        // on disk). Cleanup of the now-redundant HH_priv custody —
        // keystore entry and sole-shard plaintext — is BEST-EFFORT
        // from this point on. Failures here MUST NOT be propagated:
        //   - the post-commit invariant is "household is N=2", not
        //     "every cleanup primitive succeeded";
        //   - propagating an error after `staged.commit()` would mask
        //     the successful commit and confuse the caller into
        //     treating the ceremony as failed when it is in fact
        //     committed (creating a worse split-brain than any
        //     leftover key material);
        //   - both primitives are idempotent (`NotFound -> Ok(())`),
        //     so a future boot-time recovery pass (T073/T074) can
        //     re-attempt them without harm.
        // We log at ERROR with structured fields so on-host operators
        // can detect the residue and clean it up if recovery is not
        // yet wired.
        if let Err(e) = crate::bootstrap::destroy_household_keystore_material(
            &self.state_dir,
            &self.hh_id,
            self.policy,
        ) {
            tracing::error!(
                target: "household.ceremony.commit",
                hh_id = %self.hh_id.as_str(),
                policy = ?self.policy,
                error = %e,
                "post-commit keystore HH_priv destruction failed; \
                 household is N=2 but residual keystore entry remains \
                 until boot-time recovery re-attempts destruction"
            );
        }

        if self.sole_shard_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.sole_shard_path) {
                tracing::error!(
                    target: "household.ceremony.commit",
                    hh_id = %self.hh_id.as_str(),
                    path = %self.sole_shard_path.display(),
                    error = %e,
                    "post-commit sole-shard unlink failed; household is \
                     N=2 but residual sole-shard plaintext remains until \
                     boot-time recovery re-attempts unlink"
                );
            }
        }

        let bytes = crate::cbor::to_canonical_vec(&self.candidate_cert)
            .map_err(|e| CeremonyError::Cbor(format!("encode cert: {e}")))?;
        self.closed = true;
        Ok(bytes)
    }

    /// Like [`commit`], but on partial promotion failure does NOT
    /// unlink the surviving `.staged` set. Used post-FinalizeAck on
    /// M1 where the staged evidence MUST survive for boot-time
    /// recovery to reconcile M2 (T073/T074). The exact Phase-3 recovery
    /// manifest committed by the caller before `finalize_manifest_with_m2`
    /// is the recovery-driver authority; this method honours it by
    /// guaranteeing the staged set stays on disk on commit error.
    ///
    /// On Ok, behaviour is identical to [`commit`].
    /// On Err, the staged set survives on disk; the caller MUST
    /// leave that manifest on disk too (it is how recovery distinguishes an
    /// in-flight ceremony from unrelated orphaned staged files).
    ///
    /// [`commit`]: Self::commit
    pub fn commit_preserve_on_error(self) -> Result<Vec<u8>, CeremonyError> {
        self.commit_preserve_on_error_with_hook(|| PostRenameHookOutcome::Continue)
    }

    /// Like [`commit_preserve_on_error`](Self::commit_preserve_on_error),
    /// but runs `hook` synchronously AFTER
    /// `staged.commit_preserve_on_error()` returns Ok and BEFORE the
    /// keystore destroy + sole-shard unlink (i.e., between 2PC step 12
    /// and step 13). The hook is the extension point the
    /// failure-injection harness uses to model "M1 crash between step
    /// 12 (rename) and step 13 (sole-shard delete)".
    ///
    /// `Continue` proceeds with cleanup. `EarlyReject(msg)` returns
    /// `CeremonyError::FinalizeRejected("post-rename hook abort: <msg>")`
    /// and skips the cleanup so boot-time recovery picks up the
    /// half-committed state (post-Shamir record on disk + sole-shard
    /// still present + keystore destroy not run). A test arming
    /// `Panic` panics from inside the hook, aborting the surrounding
    /// `tokio::task::spawn_blocking` task.
    pub fn commit_preserve_on_error_with_hook<F>(
        mut self,
        hook: F,
    ) -> Result<Vec<u8>, CeremonyError>
    where
        F: FnOnce() -> PostRenameHookOutcome,
    {
        if self.closed {
            return Err(CeremonyError::AlreadyClosed);
        }
        let staged = self.staged.take().ok_or(CeremonyError::AlreadyClosed)?;
        staged.commit_preserve_on_error()?;
        match hook() {
            PostRenameHookOutcome::Continue => {}
            PostRenameHookOutcome::EarlyReject(msg) => {
                self.closed = true;
                return Err(CeremonyError::FinalizeRejected(format!(
                    "post-rename hook abort: {msg}"
                )));
            }
        }

        // Once the staged promotion landed Ok, remaining cleanup is
        // best-effort. Same semantics as `commit()` — see the long
        // doc comment there for why these errors are not propagated.
        if let Err(e) = crate::bootstrap::destroy_household_keystore_material(
            &self.state_dir,
            &self.hh_id,
            self.policy,
        ) {
            tracing::error!(
                target: "household.ceremony.commit",
                hh_id = %self.hh_id.as_str(),
                policy = ?self.policy,
                error = %e,
                "post-commit keystore HH_priv destruction failed; \
                 household is N=2 but residual keystore entry remains \
                 until boot-time recovery re-attempts destruction"
            );
        }
        if self.sole_shard_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.sole_shard_path) {
                tracing::error!(
                    target: "household.ceremony.commit",
                    hh_id = %self.hh_id.as_str(),
                    path = %self.sole_shard_path.display(),
                    error = %e,
                    "post-commit sole-shard unlink failed; household is \
                     N=2 but residual sole-shard plaintext remains until \
                     boot-time recovery re-attempts unlink"
                );
            }
        }

        let bytes = crate::cbor::to_canonical_vec(&self.candidate_cert)
            .map_err(|e| CeremonyError::Cbor(format!("encode cert: {e}")))?;
        self.closed = true;
        Ok(bytes)
    }

    /// Drop every staged file. The sole-shard at
    /// `household_root_sole.cbor` is left intact, restoring the
    /// 1-machine household exactly as before `prepare`.
    pub fn rollback(mut self) {
        if let Some(staged) = self.staged.take() {
            staged.rollback();
        }
        self.closed = true;
    }

    /// Preserve the prepared M1 staged set for boot-time recovery.
    ///
    /// Used when M1 cannot prove whether M2 committed after the
    /// finalize POST was launched. The caller must leave the exact Phase-3
    /// recovery manifest on disk so recovery can identify this as an
    /// in-flight ceremony instead of ordinary orphaned staged files.
    pub fn preserve_staged_for_recovery(mut self) {
        if let Some(staged) = self.staged.take() {
            staged.preserve_for_recovery();
        }
        self.closed = true;
    }

    /// Permanently disarm rollback-on-Drop after the exact recovery manifest
    /// is durable, while retaining this transaction's read-only finalize API.
    ///
    /// This must run before spawning or performing any external effect. A
    /// panic after the remote POST may have committed M2; unwinding must never
    /// erase the staged evidence named by the manifest.
    pub fn arm_manifest_recovery(&mut self) {
        if let Some(staged) = self.staged.take() {
            staged.preserve_for_recovery();
        }
        self.closed = true;
    }
}

impl Drop for CeremonyTxn {
    fn drop(&mut self) {
        if !self.closed {
            // Best-effort rollback is safe only while the transaction remains
            // armed. `arm_manifest_recovery` consumes the staged handle and
            // closes the transaction before any finalize I/O can escape.
            if let Some(staged) = self.staged.take() {
                staged.rollback();
            }
        }
    }
}

/// Build the URL the founder POSTs `JoinResponse` to on the candidate's
/// pre-household listener.
///
/// The scheme defaults to `http://` because the pre-household listener
/// runs `axum::serve` directly without TLS (B2): the candidate has no
/// household-rooted cert chain to terminate TLS with, and adding a
/// self-signed cert would only move the trust problem somewhere else.
/// Confidentiality is provided by the network underlay — production
/// traffic flows over Tailscale's `WireGuard` overlay (encrypted
/// end-to-end at the network layer) or a trusted LAN segment.
/// Authenticity is provided by the
/// `JoinResponse.response_sig` (signed under M1's `m_priv` and verified
/// against the founder cert pinned by the trust-anchor delivery, see B7
/// in `contracts/local-anchor.md`); confidentiality of the shard is
/// provided by the at-rest AEAD encryption to M2's `m_pub`.
///
/// Tests pass `addr` already prefixed (e.g., `http://127.0.0.1:1234`),
/// in which case the helper preserves the explicit scheme.
fn local_finalize_url(addr: &str) -> String {
    let trimmed = addr.trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        format!("{trimmed}/pair-machine/local/finalize")
    } else {
        format!("http://{trimmed}/pair-machine/local/finalize")
    }
}

// ---------------------------------------------------------------------------
// Candidate-side install helper (T035)
// ---------------------------------------------------------------------------

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use rand::RngCore;
use std::time::Duration;

/// Conservative URL-component encoder set for the QR query string.
/// Reserves `:`/`/` (so `addr=host:port` survives unescaped), but escapes
/// every reserved char that has structural meaning in a URL query.
const URI_COMPONENT_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'|')
    .add(b'\\')
    .add(b'^')
    .add(b'+')
    .add(b'%')
    .add(b'&')
    .add(b'=');

impl JoinRequest {
    /// Render the canonical `soyeht://household/pair-machine?…` URI per
    /// `specs/003-machine-join/contracts/pair-machine-url.md`.
    ///
    /// `ttl_unix` is the absolute expiry timestamp (unix seconds), MUST be
    /// ≤ 300 from issuance per the contract. Caller is responsible for
    /// computing it from `now + Duration::from_secs(300)` (or shorter).
    #[must_use]
    pub fn to_pair_machine_uri(&self, ttl_unix: u64) -> String {
        let mut uri = String::from("soyeht://household/pair-machine?v=1");

        uri.push_str("&m_pub=");
        uri.push_str(&B64URL.encode(self.m_pub.as_ref()));

        uri.push_str("&nonce=");
        uri.push_str(&B64URL.encode(self.nonce.as_ref()));

        uri.push_str("&hostname=");
        uri.extend(utf8_percent_encode(&self.hostname, URI_COMPONENT_SET));

        uri.push_str("&platform=");
        uri.push_str(match self.platform {
            crate::machine_cert::Platform::Macos => "macos",
            crate::machine_cert::Platform::LinuxNix => "linux-nix",
            crate::machine_cert::Platform::LinuxOther => "linux-other",
        });

        uri.push_str("&transport=");
        uri.push_str(match self.transport {
            JoinTransport::Tailscale => "tailscale",
            JoinTransport::Lan => "lan",
        });

        uri.push_str("&addr=");
        uri.extend(utf8_percent_encode(&self.addr, URI_COMPONENT_SET));

        uri.push_str("&challenge_sig=");
        uri.push_str(&B64URL.encode(self.challenge_sig.as_ref()));

        uri.push_str("&ttl=");
        uri.push_str(&ttl_unix.to_string());

        uri
    }

    /// Render the canonical pair-machine URI with the additional
    /// `anchor_secret` query parameter introduced in
    /// `contracts/local-anchor.md` (B7).
    ///
    /// The QR is the only carrier of `anchor_secret` — it is NOT
    /// embedded in the signed CBOR `JoinRequest`, so a network
    /// attacker who fetches `local/seed` cannot learn it.
    #[must_use]
    pub fn to_pair_machine_uri_with_anchor(
        &self,
        ttl_unix: u64,
        anchor_secret: &[u8; 32],
    ) -> String {
        let mut uri = self.to_pair_machine_uri(ttl_unix);
        uri.push_str("&anchor_secret=");
        uri.push_str(&B64URL.encode(anchor_secret));
        uri
    }
}

/// Result of a candidate-side install preparation. Returned by
/// [`prepare_candidate`] so the install CLI can render the QR alongside
/// the fingerprint and persist the keypair handle for re-runs.
pub struct PreparedCandidate {
    /// Machine private key handle. On macOS-SE this is an
    /// SE-resident reference; on Linux/`ForceSoftware` it wraps the
    /// 32-byte scalar persisted in the keystore.
    pub m_priv: Box<dyn crate::keys::IdentityKey>,
    pub m_id: crate::ids::MachineId,
    pub m_pub_sec1: [u8; 33],
    /// Signed `JoinRequest` ready to be embedded in the QR (Story 1) or
    /// served via the candidate's `local/seed` endpoint (Story 2). The
    /// canonical-CBOR bytes of this request are cached in
    /// `pair_machine_window.cbor` for that purpose.
    pub join_request: JoinRequest,
    /// The deterministic-CBOR bytes of `join_request`. Stored verbatim
    /// in `PairMachineWindow.cached_join_request` so M2's `local/seed`
    /// endpoint can hand them back byte-for-byte to M1.
    pub join_request_cbor: Vec<u8>,
    /// 6-word BIP-39 fingerprint of `m_pub` per
    /// `contracts/fingerprint-derivation.md`. Printed above the QR
    /// alongside the explicit "verify these words on your iPhone"
    /// prompt.
    pub fingerprint: String,
    /// Absolute unix-seconds expiry of the join window (issuance + ttl).
    pub ttl_unix: u64,
    /// 32-byte iPhone-anchor authenticator (B7). Embedded into the QR
    /// by `to_pair_machine_uri_with_anchor`; the iPhone presents it
    /// back via `POST /pair-machine/local/anchor` to authorize a
    /// `(hh_id, hh_pub)` pin in the candidate's window. Never returned
    /// from `local/seed` so it cannot be learned from the network.
    pub anchor_secret: [u8; 32],
}

/// Inputs for [`prepare_candidate`]. Defaults that are NOT in this
/// struct (the keystore label, the BIP-39 wordlist, the canonical CBOR
/// encoder) are project-fixed.
pub struct PrepareCandidateOpts {
    pub state_dir: std::path::PathBuf,
    pub transport: JoinTransport,
    /// `host:port` of the candidate's reachable address. The candidate's
    /// pre-household listener (T037) must bind to this address so M1
    /// can deliver `JoinResponse` in the 2PC step.
    pub addr: String,
    /// Validated host label (1..=64 UTF-8 bytes; project-internal
    /// sanitization is the caller's responsibility).
    pub hostname: String,
    pub platform: crate::machine_cert::Platform,
    pub policy: crate::bootstrap::KeyBackingPolicy,
    /// Duration of the join window, capped at 300 s by the URI contract.
    pub ttl: Duration,
    /// Current unix-seconds clock from the caller. The persisted
    /// `PairMachineWindow` remains the source of truth for the final
    /// expiry surfaced in [`PreparedCandidate::ttl_unix`].
    pub now_unix: u64,
}

#[derive(Debug, Error)]
pub enum CandidateError {
    #[error("hostname must be 1..=64 UTF-8 bytes; got {0}")]
    BadHostname(usize),
    #[error("join request validation failed: {0}")]
    JoinRequest(#[from] JoinError),
    #[error("ttl must be 1..=3600 seconds; got {0}")]
    BadTtl(u64),
    #[error("bootstrap error: {0}")]
    Bootstrap(#[from] crate::error::BootstrapError),
    #[error("CBOR encode error: {0}")]
    Cbor(String),
    #[error("sign failed: {0}")]
    Sign(#[from] crate::error::KeystoreError),
    #[error("window error: {0}")]
    Window(#[from] WindowError),
}

/// Mint or load the candidate's machine keypair, sign a fresh
/// `JoinRequest` over a CSPRNG-generated nonce, persist the
/// `PairMachineWindow` in `staging` carrying the request's canonical
/// CBOR bytes, and return the artifacts needed by the install CLI to
/// render the QR.
///
/// The function is idempotent across re-runs ONLY in the keystore path:
/// the `M_priv` is reused if a marker is present. The nonce is fresh on
/// every invocation (re-running the install command intentionally
/// invalidates any prior QR).
pub async fn prepare_candidate(
    window: &PairMachineWindow,
    opts: PrepareCandidateOpts,
) -> Result<PreparedCandidate, CandidateError> {
    prepare_candidate_inner(window, opts, None).await
}

/// Candidate preparation while the caller retains lifecycle-exclusive.
pub async fn prepare_candidate_under_lifecycle(
    window: &PairMachineWindow,
    opts: PrepareCandidateOpts,
    lifecycle: &crate::household_lifecycle::LifecycleWriteGuard,
) -> Result<PreparedCandidate, CandidateError> {
    prepare_candidate_inner(window, opts, Some(lifecycle)).await
}

async fn prepare_candidate_inner(
    window: &PairMachineWindow,
    opts: PrepareCandidateOpts,
    lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
) -> Result<PreparedCandidate, CandidateError> {
    if opts.hostname.is_empty() || opts.hostname.len() > HOSTNAME_MAX_BYTES {
        return Err(CandidateError::BadHostname(opts.hostname.len()));
    }
    validate_join_hostname(&opts.hostname)?;
    validate_join_addr(&opts.addr)?;
    // Upper bound widened from 300 to 3600 to support operator-driven
    // e2e validation walks that exceed the production budget. Production
    // callers still pass 300s by default; only opt-in env-var overrides
    // (THEYOS_PAIR_MACHINE_TTL_SECS) reach values above 300. Same
    // rationale and upper bound as the pair-device window.
    let ttl_secs = opts.ttl.as_secs();
    if ttl_secs == 0 || ttl_secs > 3600 {
        return Err(CandidateError::BadTtl(ttl_secs));
    }

    let m_priv = crate::bootstrap::ensure_candidate_machine_keypair(&opts.state_dir, opts.policy)?;
    let m_pub = m_priv.public();
    let m_pub_sec1: [u8; 33] = *m_pub.as_bytes();
    let m_id: crate::ids::MachineId = crate::ids::derive_machine_id(&m_pub);
    let fingerprint = crate::fingerprint::fingerprint(&m_pub_sec1);

    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut anchor_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut anchor_secret);

    let challenge =
        JoinChallenge::build(&m_pub_sec1, &nonce, &opts.hostname, opts.platform.clone());
    let canonical_challenge = challenge
        .to_canonical_bytes()
        .map_err(|e| CandidateError::Cbor(format!("encode JoinChallenge: {e}")))?;
    let challenge_sig = m_priv.sign(&canonical_challenge)?;

    let join_request = JoinRequest {
        version: PAIR_MACHINE_VERSION,
        m_pub: serde_bytes::ByteBuf::from(m_pub_sec1.to_vec()),
        hostname: opts.hostname.clone(),
        platform: opts.platform,
        nonce: serde_bytes::ByteBuf::from(nonce.to_vec()),
        addr: opts.addr.clone(),
        transport: opts.transport,
        challenge_sig: serde_bytes::ByteBuf::from(challenge_sig.0.to_vec()),
    };
    // Defense-in-depth: re-verify the just-signed request before
    // exposing it to disk / the wire. Catches signing-API regressions.
    verify_join_request(&join_request)?;
    let join_request_cbor = join_request
        .to_canonical_bytes()
        .map_err(|e| CandidateError::Cbor(format!("encode JoinRequest: {e}")))?;

    // Any non-idle candidate window belongs to an older QR. Re-running
    // install intentionally invalidates it so the operator sees one
    // current nonce/fingerprint pair.
    let snap = window.snapshot().await;
    if !matches!(snap.state, PairMachineState::Idle) {
        match lifecycle {
            Some(lifecycle) => window.under_lifecycle(lifecycle).return_to_idle().await?,
            None => window.return_to_idle().await?,
        }
    }

    let ttl_unix_from_window = match lifecycle {
        Some(lifecycle) => {
            window
                .under_lifecycle(lifecycle)
                .enter_staging(
                    m_pub_sec1,
                    nonce,
                    opts.transport,
                    opts.addr,
                    fingerprint.clone(),
                    join_request_cbor.clone(),
                    ttl_secs,
                    Some(anchor_secret),
                )
                .await?
        }
        None => {
            window
                .enter_staging(
                    m_pub_sec1,
                    nonce,
                    opts.transport,
                    opts.addr,
                    fingerprint.clone(),
                    join_request_cbor.clone(),
                    ttl_secs,
                    Some(anchor_secret),
                )
                .await?
        }
    };

    Ok(PreparedCandidate {
        m_priv,
        m_id,
        m_pub_sec1,
        join_request,
        join_request_cbor,
        fingerprint,
        ttl_unix: ttl_unix_from_window,
        anchor_secret,
    })
}

// ---------------------------------------------------------------------------
// T073: recover_phase3_ceremony — boot-time two-state probe driver
// ---------------------------------------------------------------------------

/// Outcome of a [`recover_phase3_ceremony`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// No Phase-3 manifest — there is nothing for this driver to do. Legacy
    /// Phase-3 evidence without a valid manifest fails closed instead.
    NotApplicable,
    /// The founder's exact manifest-bound post-Shamir record was already
    /// durable. This is local terminal evidence from a prior verified-Ack
    /// promotion, never inferred from remote household-identity visibility.
    RolledForwardPostCommit,
    /// M2 was reachable in pre-household mode AND the staged
    /// `JoinResponse` re-POST landed an ack. M1 finished step 12+13+14.
    RolledForwardPreCommit,
    /// Legacy compatibility variant. Once the finalize intent has been
    /// durably launched, timeout cannot prove that M2 did not commit, so the
    /// current recovery driver never rolls the founder back on reachability
    /// failure alone.
    RolledBack,
}

/// Errors surfaced from [`recover_phase3_ceremony`].
#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("CBOR decode error: {0}")]
    Cbor(String),
    #[error("staged record missing while marker present: {0}")]
    StagedRecordMissing(String),
    #[error("pending JoinResponse missing while marker present: {0}")]
    PendingJoinResponseMissing(String),
    #[error("Phase-3 recovery evidence exists without one valid manifest")]
    RecoveryManifestMissing,
    #[error("cached JoinRequest unavailable: {0}")]
    CachedJoinRequestUnavailable(String),
    #[error("post-commit promotion failed: {0}")]
    Promotion(String),
    #[error("phase-3 recovery requires a persistent generation namespace")]
    PersistentNamespaceUnavailable,
    #[error(
        "finalize outcome remains indeterminate after the recovery deadline; retained manifest and staged state for exact replay or manual recovery"
    )]
    FinalizeOutcomeIndeterminate,
}

/// Boot-time recovery driver for an in-flight Phase-3 join ceremony
/// per `contracts/shamir-transition.md` §"Recovery on M1 boot".
///
/// Runs unconditionally at server startup before any household-scoped
/// listener binds. If the on-disk state has no Phase-3 manifest, this returns
/// [`RecoveryOutcome::NotApplicable`] unless incompatible legacy evidence is
/// present, in which case it fails closed.
///
/// Otherwise the driver loops on a two-state probe of M2 until:
/// * the pre-commit probe (`GET /pair-machine/local/seed`) lands, in
///   which case M1 re-POSTs the staged `JoinResponse` (idempotent on
///   M2's side) and finishes step 12+;
/// * `recovery_timeout` elapses, in which case M1 fails closed and retains all
///   recovery evidence. A launched exact POST is `MayHaveTakenEffect`, so mere
///   unreachability never authorizes returning the founder to N=1.
///
/// `recovery_timeout` is `RECOVERY_TIMEOUT` in production (5 minutes).
/// Tests pass a shorter deadline.
///
/// The driver is idempotent: re-running it after partial completion
/// converges to the same outcome.
pub async fn recover_phase3_ceremony(
    state_dir: &Path,
    recovery_timeout: Duration,
) -> Result<RecoveryOutcome, RecoveryError> {
    let namespace = PairWindowNamespaceV2::current(state_dir.to_path_buf())?;
    recover_phase3_ceremony_inner(state_dir, &namespace, None, recovery_timeout).await
}

/// Recover Phase 3 using a namespace resolved under the caller's retained
/// lifecycle-exclusive guard. Startup must use this form to avoid reacquiring
/// the same cross-process lock.
pub async fn recover_phase3_ceremony_under_lifecycle(
    state_dir: &Path,
    namespace: &PairWindowNamespaceV2,
    lifecycle: &crate::household_lifecycle::LifecycleWriteGuard,
    recovery_timeout: Duration,
) -> Result<RecoveryOutcome, RecoveryError> {
    recover_phase3_ceremony_inner(state_dir, namespace, Some(lifecycle), recovery_timeout).await
}

/// Complete the exact manifest-bound founder promotion after the live handler
/// has received M2's strict Ack. This is the same idempotent disk-only path
/// used by boot recovery; the manifest deliberately remains as the terminal
/// `MachineJoined` outbox.
pub async fn finish_phase3_manifest_under_lifecycle(
    state_dir: &Path,
    namespace: &PairWindowNamespaceV2,
    lifecycle: &crate::household_lifecycle::LifecycleWriteGuard,
    manifest: Phase3RecoveryManifestV1,
) -> Result<(), RecoveryError> {
    finish_phase3_locally(state_dir, namespace, Some(lifecycle), manifest, || {
        PostRenameHookOutcome::Continue
    })
    .await
}

/// Like [`finish_phase3_manifest_under_lifecycle`], but runs `hook`
/// synchronously AFTER the household record is promoted (the manifest
/// equivalent of 2PC step 12 -- the record hits `shamir_n=2`, the
/// canonical commit marker) and BEFORE the sole-shard unlink (step 13).
/// The hook is the extension point the failure-injection harness uses to
/// model "M1 crash between step 12 and step 13" -- the same window
/// `commit_preserve_on_error_with_hook` covers for the legacy staged-commit
/// path. `EarlyReject` skips the unlink so boot-time recovery observes the
/// half-committed state (post-Shamir record on disk, sole-shard still
/// present).
pub async fn finish_phase3_manifest_under_lifecycle_with_hook<F>(
    state_dir: &Path,
    namespace: &PairWindowNamespaceV2,
    lifecycle: &crate::household_lifecycle::LifecycleWriteGuard,
    manifest: Phase3RecoveryManifestV1,
    hook: F,
) -> Result<(), RecoveryError>
where
    F: FnOnce() -> PostRenameHookOutcome + Send + 'static,
{
    finish_phase3_locally(state_dir, namespace, Some(lifecycle), manifest, hook).await
}

async fn recover_phase3_ceremony_inner(
    state_dir: &Path,
    namespace: &PairWindowNamespaceV2,
    lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    recovery_timeout: Duration,
) -> Result<RecoveryOutcome, RecoveryError> {
    use crate::storage as st;

    // A single manifest is the only recovery authority. Legacy marker,
    // pending-response, or staged evidence without it is quarantined rather
    // than mixed or inferred across ceremonies.
    let manifest = st::read_phase3_recovery_manifest(state_dir)?;
    let Some(manifest) = manifest else {
        if legacy_phase3_evidence_without_manifest(state_dir) {
            return Err(RecoveryError::RecoveryManifestMissing);
        }
        return Ok(RecoveryOutcome::NotApplicable);
    };
    manifest
        .validate()
        .map_err(|error| RecoveryError::Cbor(format!("validate recovery manifest: {error}")))?;
    if manifest.lifecycle_generation() != namespace.generation().token_bytes() {
        return Err(RecoveryError::Cbor(
            "recovery manifest lifecycle generation mismatch".into(),
        ));
    }

    let snap_path = namespace.pair_machine_snapshot_path();
    let snap_opt: Option<PairMachineWindowSnapshot> = match lifecycle {
        Some(lifecycle) => namespace.read_pair_machine_under_lifecycle(lifecycle),
        None => namespace.read_pair_machine(),
    }?;
    let snap = snap_opt.ok_or_else(|| {
        RecoveryError::CachedJoinRequestUnavailable(snap_path.display().to_string())
    })?;
    validate_snapshot_generation(&snap, namespace)?;
    let cached_join_request_bytes = snap.cached_join_request.as_ref().ok_or_else(|| {
        RecoveryError::CachedJoinRequestUnavailable("snapshot.cached_join_request".into())
    })?;
    let cached_join_request: JoinRequest =
        cbor::from_canonical_slice_strict(cached_join_request_bytes)
            .map_err(|e| RecoveryError::Cbor(format!("decode cached JoinRequest: {e}")))?;
    verify_join_request(&cached_join_request)
        .map_err(|error| RecoveryError::Cbor(format!("verify cached JoinRequest: {error}")))?;
    if blake3::hash(cached_join_request_bytes).as_bytes()
        != manifest.cached_join_request_hash.as_ref()
    {
        return Err(RecoveryError::Cbor(
            "cached JoinRequest differs from recovery manifest".into(),
        ));
    }
    let manifest_response = manifest
        .join_response()
        .map_err(|error| RecoveryError::Cbor(format!("manifest response: {error}")))?;
    if cached_join_request.m_pub.as_ref() != manifest_response.machine_cert.m_pub.as_bytes() {
        return Err(RecoveryError::Cbor(
            "cached JoinRequest candidate key differs from manifest certificate".into(),
        ));
    }
    validate_phase3_recovery_artifacts(state_dir, &manifest)?;

    let record_path = crate::storage::household_record_path(state_dir);
    let record_is_manifest_final =
        read_phase3_recovery_artifact(&record_path)?.is_some_and(|bytes| {
            blake3::hash(&bytes).as_bytes() == manifest.staged_household_record_hash.as_ref()
        });
    if record_is_manifest_final {
        finish_phase3_locally(state_dir, namespace, lifecycle, manifest, || {
            PostRenameHookOutcome::Continue
        })
        .await?;
        return Ok(RecoveryOutcome::RolledForwardPostCommit);
    }

    let m2_addr = cached_join_request.addr.clone();
    let nonce_bytes: Vec<u8> = cached_join_request.nonce.to_vec();
    if nonce_bytes.len() < 8 {
        return Err(RecoveryError::Cbor(format!(
            "cached JoinRequest nonce too short: {}",
            nonce_bytes.len()
        )));
    }
    let nonce_short = crate::ids::base32_lower_nopad_encode(&nonce_bytes[..8]);

    let started = std::time::Instant::now();
    let mut attempt: u32 = 0;
    loop {
        attempt = attempt.saturating_add(1);
        // Strategy: the most direct success signal is "POST the staged
        // `JoinResponse` to M2 again and see what happens".
        //   - If M2 is in pre-household mode (window = Staging /
        //     AwaitingOwner) and the body matches a not-yet-cached
        //     `JoinRequest`, M2 commits and returns 200.
        //   - If M2 already committed and `cached_response` bit-equals
        //     this body, M2 short-circuits to the cached
        //     `FinalizeAck` and returns 200.
        //   - If M2 is unreachable, ureq returns a transport error.
        //   - If M2 rejected the body for some other reason, we get a
        //     non-2xx and fall through to the post-commit probe.
        // A 200 from either branch is sufficient evidence that M2 is
        // logically committed; we finish step 12+ on M1.
        match repost_finalize(&m2_addr, &manifest).await {
            Ok(()) => {
                tracing::info!(
                    stage = "recovery.phase3.repost_finalize_ok",
                    attempt = attempt,
                    addr = %m2_addr,
                    "M2 ack'd JoinResponse re-POST; finishing M1 step 12+ locally"
                );
                finish_phase3_locally(state_dir, namespace, lifecycle, manifest.clone(), || {
                    PostRenameHookOutcome::Continue
                })
                .await?;
                return Ok(RecoveryOutcome::RolledForwardPreCommit);
            }
            Err(e) => {
                tracing::warn!(
                    stage = "recovery.phase3.repost_finalize_failed",
                    attempt = attempt,
                    error = %e,
                );
            }
        }

        // Surface the pre-commit probe's outcome via tracing only —
        // its only useful state is "M2 is in pre-household mode with
        // a matching `m_pub`", which the re-POST above already
        // exercises (re-POST succeeds when local/finalize accepts the
        // body). Keeping the probe as a diagnostic helps operators
        // distinguish "M2 hasn't committed yet" from "network broken".
        let pre_commit =
            probe_pre_commit(&m2_addr, &nonce_short, cached_join_request.m_pub.as_ref()).await;
        tracing::debug!(
            stage = "recovery.phase3.pre_commit_outcome",
            attempt = attempt,
            outcome = ?pre_commit,
        );

        if started.elapsed() >= recovery_timeout {
            tracing::error!(
                stage = "recovery.phase3.timeout_indeterminate",
                timeout_secs = recovery_timeout.as_secs(),
                attempts = attempt,
                addr = %m2_addr,
                "RECOVERY_TIMEOUT elapsed; retaining MayHaveTakenEffect evidence and failing closed"
            );
            return finalize_recovery_timeout();
        }

        // Backoff. 250 ms is short enough for tests to drive multiple
        // attempts; production passes a 5-minute timeout, which yields
        // ~1200 attempts — overkill but harmless given the probes are
        // single-request HTTP.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn legacy_phase3_evidence_without_manifest(state_dir: &Path) -> bool {
    crate::storage::phase3_finalize_ack_marker_exists(state_dir)
        || crate::storage::phase3_pending_join_response_exists(state_dir)
}

fn finalize_recovery_timeout() -> Result<RecoveryOutcome, RecoveryError> {
    // Deliberately accepts no path/capability: this terminal branch is not
    // authorized to mutate or clear any MayHaveTakenEffect evidence.
    Err(RecoveryError::FinalizeOutcomeIndeterminate)
}

const MAX_PHASE3_RECOVERY_ARTIFACT_BYTES: u64 = 1_048_576;

fn read_phase3_recovery_artifact(path: &Path) -> Result<Option<Vec<u8>>, RecoveryError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(RecoveryError::Promotion(format!(
                "inspect recovery artifact {}: {error}",
                path.display()
            )));
        }
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_PHASE3_RECOVERY_ARTIFACT_BYTES {
        return Err(RecoveryError::Promotion(format!(
            "unsafe recovery artifact shape: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(RecoveryError::Promotion(format!(
                "recovery artifact is group/world writable: {}",
                path.display()
            )));
        }
    }
    let bytes = std::fs::read(path).map_err(|error| {
        RecoveryError::Promotion(format!(
            "read recovery artifact {}: {error}",
            path.display()
        ))
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PHASE3_RECOVERY_ARTIFACT_BYTES {
        return Err(RecoveryError::Promotion(format!(
            "recovery artifact grew beyond bound while reading: {}",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

fn require_phase3_artifact_hash(
    description: &str,
    path: &Path,
    bytes: &[u8],
    expected_hash: &[u8],
) -> Result<(), RecoveryError> {
    if blake3::hash(bytes).as_bytes() != expected_hash {
        return Err(RecoveryError::Promotion(format!(
            "{description} differs from recovery manifest: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_phase3_artifact_pair(
    description: &str,
    final_path: &Path,
    expected_hash: &[u8],
    allow_preinstall_final_while_staged_exists: bool,
) -> Result<(), RecoveryError> {
    let staged_path = crate::storage::staged_path_for(final_path);
    let staged = read_phase3_recovery_artifact(&staged_path)?;
    let final_bytes = read_phase3_recovery_artifact(final_path)?;
    match (&staged, &final_bytes) {
        (None, None) => Err(RecoveryError::Promotion(format!(
            "{description} is absent at both staged and final paths"
        ))),
        (Some(bytes), _) => {
            require_phase3_artifact_hash(description, &staged_path, bytes, expected_hash)?;
            if let Some(final_bytes) = final_bytes
                && !allow_preinstall_final_while_staged_exists
            {
                require_phase3_artifact_hash(description, final_path, &final_bytes, expected_hash)?;
            }
            Ok(())
        }
        (None, Some(bytes)) => {
            require_phase3_artifact_hash(description, final_path, bytes, expected_hash)
        }
    }
}

fn validate_phase3_recovery_artifacts(
    state_dir: &Path,
    manifest: &Phase3RecoveryManifestV1,
) -> Result<(), RecoveryError> {
    let response = manifest
        .join_response()
        .map_err(|error| RecoveryError::Cbor(format!("manifest response: {error}")))?;
    let record_path = crate::storage::household_record_path(state_dir);
    validate_phase3_artifact_pair(
        "staged household record",
        &record_path,
        manifest.staged_household_record_hash.as_ref(),
        true,
    )?;
    let candidate_cert_path = crate::storage::machine_cert_for(state_dir, &manifest.candidate_m_id);
    validate_phase3_artifact_pair(
        "candidate certificate",
        &candidate_cert_path,
        manifest.staged_candidate_cert_hash.as_ref(),
        false,
    )?;
    let self_shard_path = shamir_self_shard_path(state_dir);
    validate_phase3_artifact_pair(
        "founder self shard",
        &self_shard_path,
        manifest.staged_self_shard_hash.as_ref(),
        false,
    )?;

    let founder_cert_path = crate::storage::machine_cert_for(state_dir, &manifest.founder_m_id);
    let founder_cert_bytes =
        read_phase3_recovery_artifact(&founder_cert_path)?.ok_or_else(|| {
            RecoveryError::Promotion("founder certificate missing during recovery".into())
        })?;
    require_phase3_artifact_hash(
        "founder certificate",
        &founder_cert_path,
        &founder_cert_bytes,
        manifest.founder_cert_hash.as_ref(),
    )?;
    let founder_cert: MachineCert =
        crate::cbor::from_canonical_slice_strict(&founder_cert_bytes)
            .map_err(|error| RecoveryError::Cbor(format!("founder certificate: {error}")))?;
    response
        .verify_response_sig(&founder_cert)
        .map_err(|error| RecoveryError::Cbor(format!("response signature: {error}")))?;

    let current_record_bytes = read_phase3_recovery_artifact(&record_path)?.ok_or_else(|| {
        RecoveryError::Promotion("founder household record missing during recovery".into())
    })?;
    let current_record_hash = blake3::hash(&current_record_bytes);
    if current_record_hash.as_bytes() != manifest.preinstall_household_record_hash.as_ref()
        && current_record_hash.as_bytes() != manifest.staged_household_record_hash.as_ref()
    {
        return Err(RecoveryError::Promotion(
            "current household record is neither manifest preinstall nor exact staged state".into(),
        ));
    }
    let current_record: HouseholdRecord =
        crate::cbor::from_canonical_slice_strict(&current_record_bytes)
            .map_err(|error| RecoveryError::Cbor(format!("current household record: {error}")))?;
    if current_record.hh_id != response.household_record.hh_id
        || current_record.hh_pub != response.household_record.hh_pub
        || !current_record
            .members
            .iter()
            .any(|member| member.to_string() == manifest.founder_m_id)
    {
        return Err(RecoveryError::Cbor(
            "current founder household does not bind recovery manifest".into(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
enum ProbeOutcome {
    Match,
    Mismatch,
    WrongShape,
    Unreachable,
}

/// `GET /pair-machine/local/seed?nonce=<short>` to detect M2 is still
/// in pre-household mode and serving its cached `JoinRequest`. A
/// 200 OK whose `m_pub` matches the staged candidate's `m_pub` means
/// M2 has not yet committed.
async fn probe_pre_commit(addr: &str, nonce_short: &str, expected_m_pub: &[u8]) -> ProbeOutcome {
    let url = local_seed_url(addr, nonce_short);
    let expected = expected_m_pub.to_vec();
    let owned = url.clone();
    let result = tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .build();
        agent.get(&owned).call().map_err(|_| ())
    })
    .await;
    let Ok(Ok(response)) = result else {
        return ProbeOutcome::Unreachable;
    };
    let mut bytes = Vec::new();
    if response
        .into_reader()
        .take(MAX_JOIN_REQUEST_WIRE_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_JOIN_REQUEST_WIRE_BYTES
    {
        return ProbeOutcome::WrongShape;
    }
    let req: JoinRequest = match cbor::from_canonical_slice_strict(&bytes) {
        Ok(r) => r,
        Err(_) => return ProbeOutcome::WrongShape,
    };
    if req.m_pub.as_ref() != expected {
        return ProbeOutcome::Mismatch;
    }
    ProbeOutcome::Match
}

fn local_seed_url(addr: &str, nonce: &str) -> String {
    let trimmed = addr.trim_end_matches('/');
    let base = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    format!("{base}/pair-machine/local/seed?nonce={nonce}")
}

async fn repost_finalize(
    addr: &str,
    manifest: &Phase3RecoveryManifestV1,
) -> Result<(), CeremonyError> {
    manifest.validate()?;
    let expected_cert = manifest.join_response()?.machine_cert;
    let url = local_finalize_url(addr);
    let body = manifest.exact_join_response().to_vec();
    let owned = url.clone();
    tokio::task::spawn_blocking(move || {
        match post_finalize_once(
            &format!("re-POST {owned}"),
            &owned,
            &body,
            &expected_cert,
            FINALIZE_HTTP_TIMEOUT,
        )
        .map_err(FinalizePostError::into_ceremony)?
        {
            FinalizePostOutcome::Ack(_) => Ok(()),
            FinalizePostOutcome::RestartRequired(_) => Err(CeremonyError::Http(format!(
                "re-POST {owned}: candidate restart still in progress"
            ))),
        }
    })
    .await
    .map_err(|e| CeremonyError::Http(format!("repost_finalize task failed: {e}")))?
}

#[cfg(test)]
mod phase3_recovery_failpoint {
    use std::cell::Cell;

    thread_local! {
        static FAIL_NEXT_PARENT_BARRIER: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn arm_parent_barrier() {
        FAIL_NEXT_PARENT_BARRIER.with(|armed| armed.set(true));
    }

    pub(super) fn take_parent_barrier() -> bool {
        FAIL_NEXT_PARENT_BARRIER.with(|armed| armed.replace(false))
    }
}

#[cfg(not(test))]
mod phase3_recovery_failpoint {
    pub(super) const fn take_parent_barrier() -> bool {
        false
    }
}

fn sync_phase3_parent(path: &Path) -> Result<(), RecoveryError> {
    let parent = path.parent().ok_or_else(|| {
        RecoveryError::Promotion(format!("recovery path has no parent: {}", path.display()))
    })?;
    if phase3_recovery_failpoint::take_parent_barrier() {
        return Err(RecoveryError::Promotion(format!(
            "injected parent barrier failure for {}",
            path.display()
        )));
    }
    let dir = std::fs::File::open(parent).map_err(|error| {
        RecoveryError::Promotion(format!(
            "open recovery parent {}: {error}",
            parent.display()
        ))
    })?;
    dir.sync_all().map_err(|error| {
        RecoveryError::Promotion(format!(
            "fsync recovery parent {}: {error}",
            parent.display()
        ))
    })
}

fn phase3_promote_temp_path(final_path: &Path) -> PathBuf {
    let mut path = final_path.as_os_str().to_owned();
    path.push(".phase3-promote-v1");
    PathBuf::from(path)
}

fn promote_phase3_artifact_exact(
    description: &str,
    final_path: &Path,
    expected_hash: &[u8],
    replace_existing: bool,
) -> Result<(), RecoveryError> {
    let staged_path = crate::storage::staged_path_for(final_path);
    let staged = read_phase3_recovery_artifact(&staged_path)?;
    if let Some(staged_bytes) = staged.as_ref() {
        require_phase3_artifact_hash(description, &staged_path, staged_bytes, expected_hash)?;
    }

    if replace_existing && staged.is_some() {
        // Preserve the `.staged` evidence while replacing the pre-Shamir
        // household record: link its exact inode to a deterministic recovery
        // temp, fsync that direntry, then rename the temp over the old record.
        let promote_path = phase3_promote_temp_path(final_path);
        match std::fs::hard_link(&staged_path, &promote_path) {
            Ok(()) => sync_phase3_parent(&promote_path)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let promote_bytes =
                    read_phase3_recovery_artifact(&promote_path)?.ok_or_else(|| {
                        RecoveryError::Promotion(format!(
                            "recovery promote temp vanished: {}",
                            promote_path.display()
                        ))
                    })?;
                require_phase3_artifact_hash(
                    description,
                    &promote_path,
                    &promote_bytes,
                    expected_hash,
                )?;
            }
            Err(error) => {
                return Err(RecoveryError::Promotion(format!(
                    "link exact {description} {} -> {}: {error}",
                    staged_path.display(),
                    promote_path.display()
                )));
            }
        }
        std::fs::rename(&promote_path, final_path).map_err(|error| {
            RecoveryError::Promotion(format!(
                "replace exact {description} {}: {error}",
                final_path.display()
            ))
        })?;
        sync_phase3_parent(final_path)?;
    } else if staged.is_some() {
        match std::fs::hard_link(&staged_path, final_path) {
            Ok(()) => sync_phase3_parent(final_path)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(RecoveryError::Promotion(format!(
                    "link exact {description} {} -> {}: {error}",
                    staged_path.display(),
                    final_path.display()
                )));
            }
        }
    }

    let final_bytes = read_phase3_recovery_artifact(final_path)?.ok_or_else(|| {
        RecoveryError::Promotion(format!(
            "{description} final path absent after recovery promotion: {}",
            final_path.display()
        ))
    })?;
    require_phase3_artifact_hash(description, final_path, &final_bytes, expected_hash)?;
    // Re-run the barrier even when a prior attempt already installed the exact
    // bytes but lost the parent-fsync acknowledgement.
    sync_phase3_parent(final_path)
}

fn remove_phase3_file_durably(path: &Path) -> Result<(), RecoveryError> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(RecoveryError::Promotion(format!(
                "remove recovery file {}: {error}",
                path.display()
            )));
        }
    }
    // Absence is not durable authority until the containing directory is
    // synchronized, including the retry path that observed NotFound.
    sync_phase3_parent(path)
}

/// Promote M1's exact manifest-bound staged files to their final paths and
/// durably delete the sole-shard plaintext.
/// This is the disk-only finishing logic for steps 12+13+17 of the
/// 2PC; `OwnerEvent` append (step 14) is not done here because the
/// recovery driver runs before the owner-events broadcaster is wired.
/// The manifest remains as a durable terminal outbox until the startup/handler
/// layer appends the exact `MachineJoined` event and explicitly clears it.
async fn finish_phase3_locally<F>(
    state_dir: &Path,
    namespace: &PairWindowNamespaceV2,
    lifecycle: Option<&crate::household_lifecycle::LifecycleWriteGuard>,
    manifest: Phase3RecoveryManifestV1,
    hook: F,
) -> Result<(), RecoveryError>
where
    F: FnOnce() -> PostRenameHookOutcome + Send + 'static,
{
    let state_dir_owned = state_dir.to_path_buf();
    let state_dir_for_promotion = state_dir_owned.clone();
    let manifest_for_promotion = manifest.clone();
    tokio::task::spawn_blocking(move || -> Result<(), RecoveryError> {
        validate_phase3_recovery_artifacts(&state_dir_for_promotion, &manifest_for_promotion)?;
        let candidate_cert_path = crate::storage::machine_cert_for(
            &state_dir_for_promotion,
            &manifest_for_promotion.candidate_m_id,
        );
        promote_phase3_artifact_exact(
            "candidate certificate",
            &candidate_cert_path,
            manifest_for_promotion.staged_candidate_cert_hash.as_ref(),
            false,
        )?;
        let self_shard_path = shamir_self_shard_path(&state_dir_for_promotion);
        promote_phase3_artifact_exact(
            "founder self shard",
            &self_shard_path,
            manifest_for_promotion.staged_self_shard_hash.as_ref(),
            false,
        )?;
        let record_path = crate::storage::household_record_path(&state_dir_for_promotion);
        promote_phase3_artifact_exact(
            "household record",
            &record_path,
            manifest_for_promotion.staged_household_record_hash.as_ref(),
            true,
        )?;
        // The manifest equivalent of 2PC step 12: the household record is
        // now at shamir_n=2, the canonical commit marker. `hook` is the
        // failure-injection extension point that models "M1 crash between
        // step 12 and step 13 (sole-shard unlink)" -- same window
        // `commit_preserve_on_error_with_hook` covers for the legacy
        // staged-commit path.
        match hook() {
            PostRenameHookOutcome::Continue => {}
            PostRenameHookOutcome::EarlyReject(msg) => {
                return Err(RecoveryError::Promotion(format!(
                    "post-rename hook abort: {msg}"
                )));
            }
        }
        remove_phase3_file_durably(&household_root_sole_path(&state_dir_for_promotion))?;
        Ok(())
    })
    .await
    .map_err(|e| RecoveryError::Promotion(format!("blocking task failed: {e}")))??;
    mark_window_committed_after_recovery(
        namespace,
        lifecycle,
        manifest.exact_join_response().to_vec(),
    )?;
    let staged_paths = [
        crate::storage::staged_path_for(&crate::storage::machine_cert_for(
            &state_dir_owned,
            &manifest.candidate_m_id,
        )),
        crate::storage::staged_path_for(&shamir_self_shard_path(&state_dir_owned)),
        crate::storage::staged_path_for(&crate::storage::household_record_path(&state_dir_owned)),
    ];
    tokio::task::spawn_blocking(move || {
        for path in &staged_paths {
            remove_phase3_file_durably(path)?;
        }
        Ok::<(), RecoveryError>(())
    })
    .await
    .map_err(|error| RecoveryError::Promotion(format!("blocking cleanup failed: {error}")))??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::derive_household_id;
    use crate::keys::{IdentityKey, P256Keypair};
    use crate::machine_cert::SignOptions;
    use std::io::Write as _;
    use std::net::{Shutdown, TcpListener, TcpStream};

    enum TestFinalizeReply {
        DropConnection,
        PartialResponse {
            status: u16,
            body_prefix: Vec<u8>,
            declared_length: usize,
        },
        Response {
            status: u16,
            body: Vec<u8>,
            retry_after: bool,
            delay: Duration,
        },
    }

    fn test_candidate_cert() -> MachineCert {
        let household_key = P256Keypair::generate();
        let candidate_key = P256Keypair::generate();
        MachineCert::sign(
            &household_key,
            &candidate_key.public(),
            &SignOptions {
                hh_id: derive_household_id(&household_key.public()),
                hostname: "candidate-mac".into(),
                platform: Platform::Macos,
                joined_at: 1_714_972_800,
            },
        )
        .unwrap()
    }

    fn test_recovery_manifest() -> Phase3RecoveryManifestV1 {
        let household_key = P256Keypair::generate();
        let founder_key = P256Keypair::generate();
        let candidate_key = P256Keypair::generate();
        let hh_id = derive_household_id(&household_key.public());
        let founder_cert = MachineCert::sign(
            &household_key,
            &founder_key.public(),
            &SignOptions {
                hh_id: hh_id.clone(),
                hostname: "founder-mac".into(),
                platform: Platform::Macos,
                joined_at: 1,
            },
        )
        .unwrap();
        let candidate_cert = MachineCert::sign(
            &household_key,
            &candidate_key.public(),
            &SignOptions {
                hh_id: hh_id.clone(),
                hostname: "candidate-mac".into(),
                platform: Platform::Macos,
                joined_at: 2,
            },
        )
        .unwrap();
        let mut members = vec![founder_cert.m_id.clone(), candidate_cert.m_id.clone()];
        members.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let record = HouseholdRecord {
            version: HouseholdRecord::SCHEMA_VERSION,
            hh_id: hh_id.clone(),
            hh_pub: household_key.public(),
            name: "Test Household".into(),
            created_at: 1,
            shamir_k: 2,
            shamir_n: 2,
            members,
            is_follower: false,
        };
        record.validate().unwrap();
        let request_hash = [0x11; 32];
        let peer_shard = crate::shard_at_rest::EncryptedShard {
            version: crate::shard_at_rest::ENCRYPTED_SHARD_VERSION,
            index: crate::shamir::SHARD_X_M2,
            nonce: [0x22; 12],
            ciphertext: ByteBuf::from(vec![0x33; 48]),
        };
        let response = JoinResponseUnsigned {
            version: PAIR_MACHINE_VERSION,
            join_request_hash: ByteBuf::from(request_hash.to_vec()),
            machine_cert: candidate_cert.clone(),
            encrypted_shard: peer_shard,
            household_record: record.clone(),
            peer_list: vec![PeerEntry {
                m_id: founder_cert.m_id.to_string(),
                m_pub: ByteBuf::from(founder_cert.m_pub.as_bytes().to_vec()),
                hostname: founder_cert.hostname.clone(),
                tailscale_addr: None,
                machine_cert: Some(founder_cert.clone()),
            }],
            push_token_seed: None,
        }
        .sign(&founder_key)
        .unwrap();
        let response_bytes = response.to_canonical_bytes().unwrap();
        let ack_bytes = FinalizeAck::for_machine_cert(&candidate_cert)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        let candidate_cert_bytes = crate::cbor::to_canonical_vec(&candidate_cert).unwrap();
        let record_bytes = crate::cbor::to_canonical_vec(&record).unwrap();
        let self_shard = crate::shard_at_rest::EncryptedShard {
            version: crate::shard_at_rest::ENCRYPTED_SHARD_VERSION,
            index: crate::shamir::SHARD_X_M1,
            nonce: [0x44; 12],
            ciphertext: ByteBuf::from(vec![0x55; 48]),
        }
        .to_canonical_bytes()
        .unwrap();
        Phase3RecoveryManifestV1 {
            version: Phase3RecoveryManifestV1::VERSION,
            lifecycle_generation: ByteBuf::from(vec![0x66; 32]),
            hh_id: hh_id.to_string(),
            candidate_m_id: candidate_cert.m_id.to_string(),
            founder_m_id: founder_cert.m_id.to_string(),
            founder_cert_hash: ByteBuf::from(machine_cert_hash(&founder_cert).unwrap().to_vec()),
            cached_join_request_hash: ByteBuf::from(request_hash.to_vec()),
            exact_join_response: ByteBuf::from(response_bytes),
            exact_finalize_ack: ByteBuf::from(ack_bytes),
            staged_candidate_cert_hash: ByteBuf::from(
                blake3::hash(&candidate_cert_bytes).as_bytes().to_vec(),
            ),
            staged_self_shard_hash: ByteBuf::from(blake3::hash(&self_shard).as_bytes().to_vec()),
            staged_household_record_hash: ByteBuf::from(
                blake3::hash(&record_bytes).as_bytes().to_vec(),
            ),
            preinstall_household_record_hash: ByteBuf::from(vec![0x77; 32]),
        }
    }

    fn read_test_http_body(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut received = Vec::new();
        let header_end = loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).unwrap();
            assert_ne!(read, 0, "request ended before its HTTP headers");
            received.extend_from_slice(&chunk[..read]);
            if let Some(index) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = std::str::from_utf8(&received[..header_end]).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .expect("ureq request must carry Content-Length");
        while received.len() - header_end < content_length {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).unwrap();
            assert_ne!(read, 0, "request ended before its declared body");
            received.extend_from_slice(&chunk[..read]);
        }
        received[header_end..header_end + content_length].to_vec()
    }

    /// A write failure that means "the client already left". Several tests
    /// drive EXACTLY that: the client gives up — a timeout below the server's
    /// delayed reply, which is the behaviour under test — and closes the
    /// socket while this thread still owes it bytes. The reset or broken pipe
    /// that then kills these writes is the expected end of that exchange;
    /// panicking on it turns the product being RIGHT (giving up fast) into a
    /// test failure, so the more correct the client, the more the old unwrap
    /// flaked. Any OTHER write error still fails the test.
    fn client_gone(error: &std::io::Error) -> bool {
        matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
        )
    }

    fn spawn_finalize_server(
        replies: Vec<TestFinalizeReply>,
    ) -> (String, std::thread::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut bodies = Vec::new();
            for reply in replies {
                let (mut stream, _) = listener.accept().unwrap();
                bodies.push(read_test_http_body(&mut stream));
                match reply {
                    TestFinalizeReply::DropConnection => {
                        stream.shutdown(Shutdown::Both).unwrap();
                    }
                    TestFinalizeReply::PartialResponse {
                        status,
                        body_prefix,
                        declared_length,
                    } => {
                        let head = format!(
                            "HTTP/1.1 {status} OK\r\nContent-Type: application/cbor\r\nContent-Length: {declared_length}\r\nConnection: close\r\n\r\n"
                        );
                        let delivered = stream
                            .write_all(head.as_bytes())
                            .and_then(|_| stream.write_all(&body_prefix))
                            .and_then(|_| stream.flush());
                        match delivered {
                            Ok(()) => stream.shutdown(Shutdown::Both).unwrap(),
                            Err(error) => {
                                assert!(
                                    client_gone(&error),
                                    "fake finalize server write failed: {error}"
                                );
                            }
                        }
                    }
                    TestFinalizeReply::Response {
                        status,
                        body,
                        retry_after,
                        delay,
                    } => {
                        std::thread::sleep(delay);
                        let reason = match status {
                            200 => "OK",
                            401 => "Unauthorized",
                            503 => "Service Unavailable",
                            _ => "Test",
                        };
                        let retry_header = if retry_after {
                            "Retry-After: 1\r\n"
                        } else {
                            ""
                        };
                        let head = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\n{retry_header}Connection: close\r\n\r\n",
                            body.len()
                        );
                        let delivered = stream
                            .write_all(head.as_bytes())
                            .and_then(|_| stream.write_all(&body))
                            .and_then(|_| stream.flush());
                        if let Err(error) = delivered {
                            assert!(
                                client_gone(&error),
                                "fake finalize server write failed: {error}"
                            );
                        }
                    }
                }
            }
            bodies
        });
        (
            format!("http://{address}/pair-machine/local/finalize"),
            handle,
        )
    }

    fn fast_retry_policy() -> FinalizeRetryPolicy {
        FinalizeRetryPolicy {
            budget: Duration::from_secs(2),
            request_timeout: Duration::from_millis(200),
            maximum_sleep: Duration::from_millis(5),
        }
    }

    #[test]
    fn clamp_recovery_timeout_defaults_when_absent_or_out_of_range() {
        // Absent is the production path, and it must be the production value.
        assert_eq!(clamp_recovery_timeout(None), RECOVERY_TIMEOUT);
        // Zero is the dangerous input this clamp exists for: a budget nobody can
        // spend probing is not a timeout, it is a skipped question.
        assert_eq!(clamp_recovery_timeout(Some(0)), RECOVERY_TIMEOUT);
        // Above the ceiling falls back to production.
        assert_eq!(
            clamp_recovery_timeout(Some(RECOVERY_TIMEOUT_MAX_SECS + 1)),
            RECOVERY_TIMEOUT
        );
        // In range passes through — the whole point of the knob.
        assert_eq!(
            clamp_recovery_timeout(Some(RECOVERY_TIMEOUT_MIN_SECS)),
            Duration::from_secs(1)
        );
        // The ceiling IS production: the knob can only shorten, never extend.
        assert_eq!(
            Duration::from_secs(RECOVERY_TIMEOUT_MAX_SECS),
            RECOVERY_TIMEOUT
        );
    }

    #[test]
    fn finalize_server_errors_preserve_recovery_evidence() {
        for code in [500, 503, 599] {
            let error = finalize_http_status_error("POST candidate", code);
            assert!(
                error.is_ambiguous_finalize_outcome(),
                "server status {code} may follow a durable candidate commit"
            );
        }
        assert!(matches!(
            finalize_http_status_error("POST candidate", 401),
            CeremonyError::FinalizeRejected(_)
        ));
    }

    #[test]
    fn recovery_manifest_rejects_cross_ceremony_mixes() {
        let first = test_recovery_manifest();
        first.validate().unwrap();
        let second = test_recovery_manifest();
        second.validate().unwrap();

        let mut response_mix = first.clone();
        response_mix.exact_join_response = second.exact_join_response.clone();
        assert!(response_mix.validate().is_err());

        let mut record_mix = first.clone();
        record_mix.staged_household_record_hash = second.staged_household_record_hash.clone();
        assert!(record_mix.validate().is_err());

        let mut ack_mix = first;
        ack_mix.exact_finalize_ack = second.exact_finalize_ack;
        assert!(ack_mix.validate().is_err());
    }

    #[test]
    fn terminal_m2_offline_timeout_retains_all_recovery_evidence() {
        let state = tempfile::tempdir().unwrap();
        crate::storage::write_phase3_pending_join_response(state.path(), b"exact request").unwrap();
        crate::storage::write_phase3_finalize_ack_marker(state.path(), "m_candidate").unwrap();
        let staged =
            crate::storage::staged_path_for(&crate::storage::household_record_path(state.path()));
        std::fs::write(&staged, b"staged founder N=2 record").unwrap();

        assert!(matches!(
            finalize_recovery_timeout(),
            Err(RecoveryError::FinalizeOutcomeIndeterminate)
        ));
        assert_eq!(
            crate::storage::read_phase3_pending_join_response(state.path())
                .unwrap()
                .unwrap(),
            b"exact request"
        );
        assert!(crate::storage::phase3_finalize_ack_marker_exists(
            state.path()
        ));
        assert_eq!(std::fs::read(staged).unwrap(), b"staged founder N=2 record");
    }

    #[test]
    fn unrelated_staged_file_is_not_phase3_evidence_without_manifest() {
        let state = tempfile::tempdir().unwrap();
        let unrelated = crate::storage::staged_path_for(
            &crate::storage::household_dir(state.path()).join("self_m_id"),
        );
        std::fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
        std::fs::write(&unrelated, b"other subsystem recovery evidence").unwrap();
        assert!(!legacy_phase3_evidence_without_manifest(state.path()));
        assert_eq!(
            std::fs::read(unrelated).unwrap(),
            b"other subsystem recovery evidence"
        );
    }

    #[test]
    fn exact_promotion_parent_barrier_failure_preserves_staged_and_retries() {
        let state = tempfile::tempdir().unwrap();
        let final_path = state.path().join("machine_certs/candidate.cbor");
        std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        let staged_path = crate::storage::staged_path_for(&final_path);
        let exact = b"exact candidate certificate";
        std::fs::write(&staged_path, exact).unwrap();
        let expected = *blake3::hash(exact).as_bytes();

        phase3_recovery_failpoint::arm_parent_barrier();
        assert!(
            promote_phase3_artifact_exact("candidate certificate", &final_path, &expected, false,)
                .is_err()
        );
        assert_eq!(std::fs::read(&staged_path).unwrap(), exact);
        promote_phase3_artifact_exact("candidate certificate", &final_path, &expected, false)
            .unwrap();
        assert_eq!(std::fs::read(final_path).unwrap(), exact);
        assert_eq!(std::fs::read(staged_path).unwrap(), exact);
    }

    #[test]
    fn stale_final_destination_never_discards_exact_staged_evidence() {
        let state = tempfile::tempdir().unwrap();
        let final_path = state.path().join("shamir/self_shard.cbor");
        std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        let staged_path = crate::storage::staged_path_for(&final_path);
        let exact = b"exact encrypted self shard";
        std::fs::write(&staged_path, exact).unwrap();
        std::fs::write(&final_path, b"foreign stale destination").unwrap();
        let expected = *blake3::hash(exact).as_bytes();

        assert!(
            promote_phase3_artifact_exact("founder self shard", &final_path, &expected, false)
                .is_err()
        );
        assert_eq!(std::fs::read(&staged_path).unwrap(), exact);
        assert_eq!(
            std::fs::read(&final_path).unwrap(),
            b"foreign stale destination"
        );
    }

    #[test]
    fn record_replace_crash_keeps_evidence_and_final_exact_can_resume_without_staged() {
        let state = tempfile::tempdir().unwrap();
        let final_path = state.path().join("household_record.cbor");
        let staged_path = crate::storage::staged_path_for(&final_path);
        let exact = b"exact post-Shamir record";
        std::fs::write(&final_path, b"pre-Shamir record").unwrap();
        std::fs::write(&staged_path, exact).unwrap();
        let expected = *blake3::hash(exact).as_bytes();

        phase3_recovery_failpoint::arm_parent_barrier();
        assert!(
            promote_phase3_artifact_exact("household record", &final_path, &expected, true)
                .is_err()
        );
        assert_eq!(std::fs::read(&staged_path).unwrap(), exact);
        promote_phase3_artifact_exact("household record", &final_path, &expected, true).unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), exact);

        remove_phase3_file_durably(&staged_path).unwrap();
        validate_phase3_artifact_pair("household record", &final_path, &expected, true).unwrap();
        promote_phase3_artifact_exact("household record", &final_path, &expected, true).unwrap();
    }

    #[test]
    fn finalize_restart_required_is_strict_canonical_cbor() {
        let canonical = FinalizeRestartRequired::new().to_canonical_bytes().unwrap();
        assert_eq!(
            FinalizeRestartRequired::from_canonical_bytes(&canonical).unwrap(),
            FinalizeRestartRequired::new()
        );

        let mut trailing = canonical;
        trailing.push(0);
        assert!(FinalizeRestartRequired::from_canonical_bytes(&trailing).is_err());

        let wrong = FinalizeRestartRequired {
            version: PAIR_MACHINE_VERSION,
            error: "temporarily_unavailable".into(),
        };
        assert!(
            FinalizeRestartRequired::from_canonical_bytes(
                &crate::cbor::to_canonical_vec(&wrong).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn transport_reset_then_typed_restart_and_gap_replay_exact_bytes_until_ack() {
        let cert = test_candidate_cert();
        let ack_bytes = FinalizeAck::for_machine_cert(&cert)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        let restart_bytes = FinalizeRestartRequired::new().to_canonical_bytes().unwrap();
        let (url, server) = spawn_finalize_server(vec![
            TestFinalizeReply::DropConnection,
            TestFinalizeReply::Response {
                status: 503,
                body: restart_bytes,
                retry_after: true,
                delay: Duration::ZERO,
            },
            TestFinalizeReply::DropConnection,
            TestFinalizeReply::Response {
                status: 200,
                body: ack_bytes,
                retry_after: false,
                delay: Duration::ZERO,
            },
        ]);
        let request = b"exact-durable-join-response";
        let verified = post_finalize_until_ack(&url, request, &cert, fast_retry_policy()).unwrap();
        assert_eq!(verified.ack.m_id, cert.m_id.to_string());
        assert_eq!(
            server.join().unwrap(),
            vec![
                request.to_vec(),
                request.to_vec(),
                request.to_vec(),
                request.to_vec()
            ]
        );
    }

    #[test]
    fn delayed_restart_response_never_sleeps_against_a_stale_budget() {
        let cert = test_candidate_cert();
        let restart_bytes = FinalizeRestartRequired::new().to_canonical_bytes().unwrap();
        let (url, server) = spawn_finalize_server(vec![TestFinalizeReply::Response {
            status: 503,
            body: restart_bytes,
            retry_after: true,
            delay: Duration::from_millis(200),
        }]);
        let policy = FinalizeRetryPolicy {
            budget: Duration::from_millis(250),
            request_timeout: Duration::from_millis(240),
            maximum_sleep: Duration::from_secs(1),
        };
        let started = std::time::Instant::now();
        let error = post_finalize_until_ack(&url, b"request", &cert, policy).unwrap_err();
        let elapsed = started.elapsed();
        assert!(matches!(error, CeremonyError::Http(_)));
        assert!(
            elapsed < Duration::from_millis(375),
            "stale pre-request budget caused an oversleep: {elapsed:?}"
        );
        assert_eq!(server.join().unwrap(), vec![b"request".to_vec()]);
    }

    #[test]
    fn partial_success_body_is_transport_ambiguity_and_exactly_retried() {
        let cert = test_candidate_cert();
        let ack_bytes = FinalizeAck::for_machine_cert(&cert)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        let (url, server) = spawn_finalize_server(vec![
            TestFinalizeReply::PartialResponse {
                status: 200,
                body_prefix: ack_bytes[..ack_bytes.len() / 2].to_vec(),
                declared_length: ack_bytes.len(),
            },
            TestFinalizeReply::Response {
                status: 200,
                body: ack_bytes,
                retry_after: false,
                delay: Duration::ZERO,
            },
        ]);
        let request = b"exact-request";
        let verified = post_finalize_until_ack(&url, request, &cert, fast_retry_policy()).unwrap();
        assert_eq!(verified.ack.m_id, cert.m_id.to_string());
        assert_eq!(
            server.join().unwrap(),
            vec![request.to_vec(), request.to_vec()]
        );
    }

    #[test]
    fn initial_server_error_is_ambiguous_and_exactly_retried() {
        let cert = test_candidate_cert();
        let ack_bytes = FinalizeAck::for_machine_cert(&cert)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        let (url, server) = spawn_finalize_server(vec![
            TestFinalizeReply::Response {
                status: 500,
                body: Vec::new(),
                retry_after: false,
                delay: Duration::ZERO,
            },
            TestFinalizeReply::Response {
                status: 200,
                body: ack_bytes,
                retry_after: false,
                delay: Duration::ZERO,
            },
        ]);
        let request = b"exact-request";
        let verified = post_finalize_until_ack(&url, request, &cert, fast_retry_policy()).unwrap();
        assert_eq!(verified.ack.m_id, cert.m_id.to_string());
        assert_eq!(
            server.join().unwrap(),
            vec![request.to_vec(), request.to_vec()]
        );
    }

    #[test]
    fn malformed_503_does_not_enter_restart_retry() {
        let cert = test_candidate_cert();
        let (url, server) = spawn_finalize_server(vec![TestFinalizeReply::Response {
            status: 503,
            body: b"not canonical restart CBOR".to_vec(),
            retry_after: true,
            delay: Duration::ZERO,
        }]);
        let error =
            post_finalize_until_ack(&url, b"request", &cert, fast_retry_policy()).unwrap_err();
        assert!(matches!(error, CeremonyError::Http(_)));
        assert_eq!(server.join().unwrap(), vec![b"request".to_vec()]);
    }

    #[test]
    fn rejection_after_typed_restart_is_always_ambiguous() {
        let cert = test_candidate_cert();
        let restart_bytes = FinalizeRestartRequired::new().to_canonical_bytes().unwrap();
        let (url, server) = spawn_finalize_server(vec![
            TestFinalizeReply::Response {
                status: 503,
                body: restart_bytes,
                retry_after: true,
                delay: Duration::ZERO,
            },
            TestFinalizeReply::Response {
                status: 401,
                body: Vec::new(),
                retry_after: false,
                delay: Duration::ZERO,
            },
        ]);
        let error =
            post_finalize_until_ack(&url, b"request", &cert, fast_retry_policy()).unwrap_err();
        assert!(matches!(error, CeremonyError::Http(_)));
        assert!(error.is_ambiguous_finalize_outcome());
        assert_eq!(server.join().unwrap().len(), 2);
    }

    #[test]
    fn rejection_after_transport_ambiguity_never_authorizes_rollback() {
        let cert = test_candidate_cert();
        let (url, server) = spawn_finalize_server(vec![
            TestFinalizeReply::DropConnection,
            TestFinalizeReply::Response {
                status: 401,
                body: Vec::new(),
                retry_after: false,
                delay: Duration::ZERO,
            },
        ]);
        let request = b"exact-request";
        let error = post_finalize_until_ack(&url, request, &cert, fast_retry_policy()).unwrap_err();
        assert!(matches!(error, CeremonyError::Http(_)));
        assert!(error.is_ambiguous_finalize_outcome());
        assert_eq!(
            server.join().unwrap(),
            vec![request.to_vec(), request.to_vec()]
        );
    }

    #[test]
    fn every_success_ack_is_strictly_bound_to_candidate_cert() {
        let cert = test_candidate_cert();
        assert!(validate_finalize_ack_bytes(&[], &cert).is_err());

        let mut wrong_m_id = FinalizeAck::for_machine_cert(&cert).unwrap();
        wrong_m_id.m_id = "m_wrong".into();
        assert!(
            validate_finalize_ack_bytes(&wrong_m_id.to_canonical_bytes().unwrap(), &cert).is_err()
        );

        let mut wrong_hash = FinalizeAck::for_machine_cert(&cert).unwrap();
        wrong_hash.machine_cert_hash = ByteBuf::from(vec![0xAA; 32]);
        assert!(
            validate_finalize_ack_bytes(&wrong_hash.to_canonical_bytes().unwrap(), &cert).is_err()
        );

        let mut wrong_version = FinalizeAck::for_machine_cert(&cert).unwrap();
        wrong_version.version = PAIR_MACHINE_VERSION + 1;
        assert!(
            validate_finalize_ack_bytes(&wrong_version.to_canonical_bytes().unwrap(), &cert)
                .is_err()
        );

        let mut trailing = FinalizeAck::for_machine_cert(&cert)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        trailing.push(0);
        assert!(validate_finalize_ack_bytes(&trailing, &cert).is_err());
    }

    fn signed_request(kp: &P256Keypair) -> JoinRequest {
        let m_pub_arr = *kp.public().as_bytes();
        let nonce: [u8; 32] = [0x42; 32];
        let challenge =
            JoinChallenge::build(&m_pub_arr, &nonce, "studio-linux", Platform::LinuxNix);
        let canonical = challenge.to_canonical_bytes().unwrap();
        let sig = kp.sign(&canonical).unwrap();
        JoinRequest {
            version: PAIR_MACHINE_VERSION,
            m_pub: ByteBuf::from(m_pub_arr.to_vec()),
            hostname: "studio-linux".into(),
            platform: Platform::LinuxNix,
            nonce: ByteBuf::from(nonce.to_vec()),
            addr: "100.1.2.3:5040".into(),
            transport: JoinTransport::Tailscale,
            challenge_sig: ByteBuf::from(sig.0.to_vec()),
        }
    }

    #[test]
    fn happy_path_verifies() {
        let kp = P256Keypair::generate();
        let req = signed_request(&kp);
        verify_join_request(&req).unwrap();
    }

    #[test]
    fn mutated_hostname_invalidates_signature() {
        let kp = P256Keypair::generate();
        let mut req = signed_request(&kp);
        req.hostname = "studio-pwned".into();
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadSignature));
    }

    #[test]
    fn owner_facing_hostname_shape_is_enforced() {
        let kp = P256Keypair::generate();
        let mut req = signed_request(&kp);
        req.hostname = "studio\nlinux".into();
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadHostname(_)));

        let mut req = signed_request(&kp);
        req.hostname = "Studio-Linux".into();
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadHostname(_)));

        let mut req = signed_request(&kp);
        req.hostname = "studio.-linux".into();
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadHostname(_)));
    }

    #[test]
    fn addr_must_be_bounded_canonical_host_port() {
        let kp = P256Keypair::generate();
        let mut req = signed_request(&kp);
        req.addr = "evil\nhost:8091".into();
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadAddr(_)));

        let mut req = signed_request(&kp);
        req.addr = "fd7a:115c:a1e0::1:8091".into();
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadAddr(_)));

        let mut req = signed_request(&kp);
        req.addr = "192.168.001.005:8091".into();
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadAddr(_)));

        let mut req = signed_request(&kp);
        req.addr = format!("{}:8091", "a".repeat(129));
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadAddr(_)));
    }

    #[test]
    fn canonical_ip_and_dns_addrs_verify() {
        let kp = P256Keypair::generate();
        let mut req = signed_request(&kp);
        req.addr = "[fd7a:115c:a1e0::1]:8091".into();
        verify_join_request(&req).unwrap();

        let mut req = signed_request(&kp);
        req.addr = "studio-linux.local:8091".into();
        verify_join_request(&req).unwrap();
    }

    #[test]
    fn mutated_nonce_invalidates_signature() {
        let kp = P256Keypair::generate();
        let mut req = signed_request(&kp);
        req.nonce.as_mut()[0] ^= 0x80;
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadSignature));
    }

    #[test]
    fn mutated_platform_invalidates_signature() {
        let kp = P256Keypair::generate();
        let mut req = signed_request(&kp);
        req.platform = Platform::Macos;
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadSignature));
    }

    #[test]
    fn mutated_m_pub_invalidates_signature() {
        let kp = P256Keypair::generate();
        let mut req = signed_request(&kp);
        // Flip a non-prefix byte to keep the SEC1 decode valid but break
        // the binding to the original keypair.
        req.m_pub.as_mut()[3] ^= 0x40;
        let err = verify_join_request(&req).unwrap_err();
        // Either the SEC1 decode rejects the off-curve point or the
        // signature fails to verify — both are valid generic-401 paths.
        assert!(matches!(
            err,
            JoinError::BadSignature | JoinError::BadMPub(_)
        ));
    }

    #[test]
    fn truncated_m_pub_rejected() {
        let kp = P256Keypair::generate();
        let mut req = signed_request(&kp);
        let mut bytes = req.m_pub.to_vec();
        bytes.pop();
        req.m_pub = ByteBuf::from(bytes);
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::BadField(_)));
    }

    #[test]
    fn unsupported_version_rejected() {
        let kp = P256Keypair::generate();
        let mut req = signed_request(&kp);
        req.version = 9;
        let err = verify_join_request(&req).unwrap_err();
        assert!(matches!(err, JoinError::UnsupportedVersion(9)));
    }

    #[test]
    fn deterministic_canonical_bytes_for_challenge() {
        let kp = P256Keypair::generate();
        let req = signed_request(&kp);
        let challenge = req.challenge().unwrap();
        let a = challenge.to_canonical_bytes().unwrap();
        let b = challenge.to_canonical_bytes().unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn window_idle_to_staging_to_awaiting_to_committed() {
        let win = PairMachineWindow::new_in_memory();
        let s = win.snapshot().await;
        assert_eq!(s.state, PairMachineState::Idle);

        win.enter_staging(
            [0x02; 33],
            [0x42; 32],
            JoinTransport::Tailscale,
            "100.64.0.10:5040".into(),
            "fp test".into(),
            vec![0xAA, 0xBB],
            300,
            None,
        )
        .await
        .unwrap();
        assert_eq!(win.snapshot().await.state, PairMachineState::Staging);

        win.enter_awaiting_owner(7).await.unwrap();
        let s = win.snapshot().await;
        assert_eq!(s.state, PairMachineState::AwaitingOwner);
        assert_eq!(s.owner_event_cursor, Some(7));

        win.enter_committed(vec![0xCC]).await.unwrap();
        assert_eq!(win.snapshot().await.state, PairMachineState::Committed);
        assert!(win.snapshot().await.approval_claim.is_none());
    }

    #[tokio::test]
    async fn owner_approval_claim_is_exclusive_and_stale_claim_clears_on_reload() {
        let td = tempfile::tempdir().unwrap();
        let win = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();
        win.enter_staging(
            [0x02; 33],
            [0x42; 32],
            JoinTransport::Tailscale,
            "100.64.0.10:5040".into(),
            "fp test".into(),
            vec![0xAA, 0xBB],
            300,
            None,
        )
        .await
        .unwrap();
        win.enter_awaiting_owner(7).await.unwrap();

        let claim = win
            .claim_owner_approval(7, [0xA5; 32], 1_800)
            .await
            .unwrap();
        assert_eq!(claim.owner_event_cursor, 7);
        assert_eq!(claim.claimed_at, 1_800);
        assert_eq!(claim.claim_id.as_ref(), &[0xA5; 32]);
        let err = win
            .claim_owner_approval(7, [0x5A; 32], 1_801)
            .await
            .unwrap_err();
        assert!(matches!(err, WindowError::AlreadyClaimed));

        let persisted: PairMachineWindowSnapshot = win
            .inner
            .namespace
            .as_ref()
            .unwrap()
            .read_pair_machine()
            .unwrap()
            .unwrap();
        assert_eq!(persisted.approval_claim, Some(claim));

        let reloaded = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();
        let snapshot = reloaded.snapshot().await;
        assert!(snapshot.approval_claim.is_none());
        reloaded
            .claim_owner_approval(7, [0x5A; 32], 1_801)
            .await
            .unwrap();
        reloaded.enter_aborted().await.unwrap();
        assert!(reloaded.snapshot().await.approval_claim.is_none());

        reloaded
            .enter_staging(
                [0x03; 33],
                [0x24; 32],
                JoinTransport::Tailscale,
                "100.64.0.11:5040".into(),
                "fp retry".into(),
                vec![0xCC, 0xDD],
                300,
                None,
            )
            .await
            .unwrap();
        reloaded.enter_awaiting_owner(8).await.unwrap();
        let retry_claim = reloaded
            .claim_owner_approval(8, [0xC3; 32], 1_900)
            .await
            .unwrap();
        assert_eq!(retry_claim.owner_event_cursor, 8);
    }

    #[tokio::test]
    async fn owner_approval_claim_with_phase3_marker_survives_reload() {
        let td = tempfile::tempdir().unwrap();
        let win = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();
        win.enter_staging(
            [0x02; 33],
            [0x42; 32],
            JoinTransport::Tailscale,
            "100.64.0.10:5040".into(),
            "fp test".into(),
            vec![0xAA, 0xBB],
            300,
            None,
        )
        .await
        .unwrap();
        win.enter_awaiting_owner(7).await.unwrap();

        let claim = win
            .claim_owner_approval(7, [0xA5; 32], 1_800)
            .await
            .unwrap();
        crate::storage::write_phase3_finalize_ack_marker(td.path(), "m_marker").unwrap();

        let reloaded = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();
        assert_eq!(reloaded.snapshot().await.approval_claim, Some(claim));
        let err = reloaded
            .claim_owner_approval(7, [0x5A; 32], 1_801)
            .await
            .unwrap_err();
        assert!(matches!(err, WindowError::AlreadyClaimed));

        crate::storage::clear_phase3_finalize_ack_marker(td.path()).unwrap();
        let cleaned = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();
        assert!(cleaned.snapshot().await.approval_claim.is_none());
    }

    #[tokio::test]
    async fn owner_approval_claim_with_phase3_manifest_survives_reload() {
        let td = tempfile::tempdir().unwrap();
        let win = PairMachineWindow::with_persistence(td.path().to_path_buf()).unwrap();
        win.enter_staging(
            [0x02; 33],
            [0x42; 32],
            JoinTransport::Tailscale,
            "100.64.0.10:5040".into(),
            "fp test".into(),
            vec![0xAA, 0xBB],
            300,
            None,
        )
        .await
        .unwrap();
        win.enter_awaiting_owner(7).await.unwrap();
        let claim = win
            .claim_owner_approval(7, [0xA5; 32], 1_800)
            .await
            .unwrap();

        let lifecycle =
            crate::household_lifecycle::HouseholdLifecycleLock::open_verified(td.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let generation = guard.ensure_lifecycle_generation().unwrap();
        let mut manifest = test_recovery_manifest();
        manifest.lifecycle_generation = ByteBuf::from(generation.token_bytes().to_vec());
        crate::storage::write_phase3_recovery_manifest(&guard, td.path(), &manifest).unwrap();

        let reloaded =
            PairMachineWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
                .unwrap();
        assert_eq!(reloaded.snapshot().await.approval_claim, Some(claim));
        assert!(matches!(
            reloaded
                .under_lifecycle(&guard)
                .claim_owner_approval(7, [0x5A; 32], 1_801)
                .await,
            Err(WindowError::AlreadyClaimed)
        ));
    }

    #[tokio::test]
    async fn stale_generation_abort_and_idle_cannot_touch_current_window() {
        let td = tempfile::tempdir().unwrap();
        let lifecycle =
            crate::household_lifecycle::HouseholdLifecycleLock::open_verified(td.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let old =
            PairMachineWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
                .unwrap();
        old.under_lifecycle(&guard)
            .enter_staging(
                [2; 33],
                [9; 32],
                JoinTransport::Lan,
                "127.0.0.1:5040".into(),
                "old".into(),
                vec![1, 2, 3],
                60,
                None,
            )
            .await
            .unwrap();
        guard.rotate_lifecycle_generation().unwrap();
        let current =
            PairMachineWindow::with_persistence_under_lifecycle(td.path().to_path_buf(), &guard)
                .unwrap();
        drop(guard);
        assert!(old.enter_aborted().await.is_err());
        assert!(old.return_to_idle().await.is_err());
        assert_eq!(current.snapshot().await.state, PairMachineState::Idle);
    }

    #[test]
    fn snapshot_missing_generation_is_never_loaded_as_current() {
        let td = tempfile::tempdir().unwrap();
        let lifecycle =
            crate::household_lifecycle::HouseholdLifecycleLock::open_verified(td.path()).unwrap();
        let guard = lifecycle.lock_exclusive().unwrap();
        let namespace =
            PairWindowNamespaceV2::current_under_lifecycle(td.path().to_path_buf(), &guard)
                .unwrap();
        let legacy_shaped = PairMachineWindowSnapshot::idle();
        namespace
            .write_pair_machine_under_lifecycle(&legacy_shaped, &guard)
            .unwrap();
        assert!(PairMachineWindow::with_namespace_under_lifecycle(namespace, &guard).is_err());
    }

    #[tokio::test]
    async fn second_concurrent_staging_rejected() {
        let win = PairMachineWindow::new_in_memory();
        win.enter_staging(
            [0x02; 33],
            [0x42; 32],
            JoinTransport::Tailscale,
            "addr".into(),
            "fp".into(),
            vec![],
            300,
            None,
        )
        .await
        .unwrap();
        let err = win
            .enter_staging(
                [0x03; 33],
                [0x99; 32],
                JoinTransport::Lan,
                "addr2".into(),
                "fp2".into(),
                vec![],
                300,
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WindowError::AlreadyActive));
    }

    #[tokio::test]
    async fn invalid_transition_rejected() {
        let win = PairMachineWindow::new_in_memory();
        // From idle → committed is invalid.
        let err = win.enter_committed(vec![]).await.unwrap_err();
        assert!(matches!(err, WindowError::Transition { .. }));
    }
}
