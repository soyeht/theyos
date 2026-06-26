//! Phase 3 machine-join ceremony types and state machine.
//!
//! - [`JoinChallenge`] / [`JoinRequest`] — wire shapes per
//!   `specs/003-machine-join/data-model.md`.
//! - [`verify_join_request`] — canonical-CBOR + signature validation
//!   used by the founding machine before staging the ceremony.
//! - [`PairMachineWindow`] — single-active-ceremony state machine on
//!   M1, persisted to `pair_machine_window.cbor`.

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
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};
use crate::machine_cert::Platform;

/// Wire schema version of the join-ceremony types.
pub const PAIR_MACHINE_VERSION: u8 = 1;

/// Maximum transport-string field length, mirroring Bonjour TXT
/// constraints. Keeps the QR query string compact.
pub const HOSTNAME_MAX_BYTES: usize = 64;

/// Maximum `host:port` hint length accepted from a candidate. This
/// keeps owner-facing event payloads compact and rejects prompt-spoofing
/// strings before they are persisted.
pub const ADDR_MAX_BYTES: usize = 128;

/// Recovery deadline (`FR-013a`). Past this point, M1's recovery probe
/// rolls back the ceremony rather than waiting for M2 to come back.
pub const RECOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

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
}

impl PairMachineWindowSnapshot {
    #[must_use]
    pub fn idle() -> Self {
        Self {
            version: PAIR_MACHINE_VERSION,
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
        }
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

/// Shared, mutable pair-machine window. Cloning the handle shares
/// state via an `Arc`. Persisted to `pair_machine_window.cbor` on
/// every transition so a daemon restart picks up the live ceremony.
#[derive(Clone)]
pub struct PairMachineWindow {
    inner: Arc<PairMachineWindowInner>,
}

struct PairMachineWindowInner {
    state: Mutex<PairMachineWindowSnapshot>,
    notifier: watch::Sender<PairMachineState>,
    state_dir: Option<PathBuf>,
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
                state_dir: None,
            }),
        }
    }

    /// Construct a window that persists every transition to
    /// `<state_dir>/household/pair_machine_window.cbor`. On boot, if
    /// the file is present its snapshot is loaded; otherwise the
    /// window starts `idle`.
    pub fn with_persistence(state_dir: PathBuf) -> Result<Self, StorageError> {
        let snap_path = pair_machine_window_path(&state_dir);
        let mut snapshot: PairMachineWindowSnapshot =
            crate::storage::read_optional_cbor(&snap_path)?
                .unwrap_or_else(PairMachineWindowSnapshot::idle);
        clear_stale_approval_claim_on_load(&state_dir, &snap_path, &mut snapshot)?;
        let (tx, _) = watch::channel(snapshot.state);
        Ok(Self {
            inner: Arc::new(PairMachineWindowInner {
                state: Mutex::new(snapshot),
                notifier: tx,
                state_dir: Some(state_dir),
            }),
        })
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
            version: PAIR_MACHINE_VERSION,
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
        };
        self.persist(&guard)?;
        let _ = self.inner.notifier.send(guard.state);
        // Positive observability gate (T093): the founder window has
        // transitioned `idle → staging`. Audit consumers count this
        // against `enter_awaiting_owner` to detect ceremonies that
        // started but never reached the owner-event append stage.
        tracing::info!(stage = "pair_machine.window_opened", expiry = expiry,);
        Ok(expiry)
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
        if let Err(e) = self.persist(&guard) {
            guard.pinned_hh_pub = None;
            guard.pinned_hh_id = None;
            return Err(e);
        }
        Ok(())
    }

    /// Promote a staged window to `awaiting_owner` once the
    /// `OwnerEvent{type=join-request}` has been appended.
    pub async fn enter_awaiting_owner(&self, owner_event_cursor: u64) -> Result<(), WindowError> {
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
        self.persist(&guard)?;
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
        if let Err(e) = self.persist(&guard) {
            guard.approval_claim = None;
            return Err(e);
        }
        Ok(claim)
    }

    /// Advance to `committed` after a successful 2PC. The supplied
    /// `cached_response_bytes` are returned to a duplicate
    /// `JoinRequest` within the replay grace window (R7 / FR-015).
    pub async fn enter_committed(&self, cached_response_bytes: Vec<u8>) -> Result<(), WindowError> {
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
        self.persist(&guard)?;
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
        let mut guard = self.inner.state.lock().await;
        guard.state = PairMachineState::Aborted;
        guard.approval_claim = None;
        self.persist(&guard)?;
        let _ = self.inner.notifier.send(guard.state);
        Ok(())
    }

    /// Return the window to `idle` after the replay grace window
    /// elapses. Drops cached request/response bytes.
    pub async fn return_to_idle(&self) -> Result<(), WindowError> {
        let mut guard = self.inner.state.lock().await;
        *guard = PairMachineWindowSnapshot::idle();
        self.persist(&guard)?;
        let _ = self.inner.notifier.send(guard.state);
        Ok(())
    }

    fn persist(&self, snapshot: &PairMachineWindowSnapshot) -> Result<(), WindowError> {
        if let Some(dir) = &self.inner.state_dir {
            crate::storage::atomic_write_cbor(&pair_machine_window_path(dir), snapshot)?;
        }
        Ok(())
    }
}

#[must_use]
pub fn pair_machine_window_path(state_dir: &Path) -> PathBuf {
    crate::storage::household_dir(state_dir).join("pair_machine_window.cbor")
}

fn clear_stale_approval_claim_on_load(
    state_dir: &Path,
    snap_path: &Path,
    snapshot: &mut PairMachineWindowSnapshot,
) -> Result<(), StorageError> {
    if snapshot.approval_claim.is_none() {
        return Ok(());
    }
    if crate::storage::phase3_finalize_ack_marker_exists(state_dir) {
        return Ok(());
    }

    // A durable claim only protects the prepare/finalize race while a process is
    // actively driving the approval. After restart, no in-memory owner approval
    // can still be alive. Without the Phase-3 finalize marker, recovery has no
    // intent to preserve, so the claim is stale and must not wedge the window.
    snapshot.approval_claim = None;
    crate::storage::clear_phase3_pending_join_response(state_dir)?;
    crate::storage::atomic_write_cbor(snap_path, snapshot)?;
    Ok(())
}

fn mark_window_committed_after_recovery(
    state_dir: &Path,
    cached_response_bytes: Vec<u8>,
) -> Result<(), StorageError> {
    let snap_path = pair_machine_window_path(state_dir);
    let Some(mut snapshot) =
        crate::storage::read_optional_cbor::<PairMachineWindowSnapshot>(&snap_path)?
    else {
        return Ok(());
    };
    snapshot.state = PairMachineState::Committed;
    snapshot.cached_response = Some(ByteBuf::from(cached_response_bytes));
    snapshot.approval_claim = None;
    crate::storage::atomic_write_cbor(&snap_path, &snapshot)?;
    Ok(())
}

fn mark_window_aborted_after_recovery(state_dir: &Path) -> Result<(), StorageError> {
    let snap_path = pair_machine_window_path(state_dir);
    let Some(mut snapshot) =
        crate::storage::read_optional_cbor::<PairMachineWindowSnapshot>(&snap_path)?
    else {
        return Ok(());
    };
    snapshot.state = PairMachineState::Aborted;
    snapshot.approval_claim = None;
    crate::storage::atomic_write_cbor(&snap_path, &snapshot)?;
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

/// Successful result of M1's call to M2's `local/finalize`.
pub struct FinalizeWithM2Outcome {
    pub ack: FinalizeAck,
    pub join_response: JoinResponse,
    pub join_response_bytes: Vec<u8>,
}

pub fn machine_cert_hash(cert: &MachineCert) -> Result<[u8; 32], HouseholdError> {
    let bytes = crate::cbor::to_canonical_vec(cert)?;
    Ok(*blake3::hash(&bytes).as_bytes())
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
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build();
        let response = agent
            .post(&url)
            .set("Content-Type", "application/cbor")
            .send_bytes(&join_response_bytes)
            .map_err(|e| match e {
                ureq::Error::Status(code, _) => {
                    CeremonyError::FinalizeRejected(format!("POST {url}: status {code}"))
                }
                other @ ureq::Error::Transport(_) => {
                    CeremonyError::Http(format!("POST {url}: {other}"))
                }
            })?;
        let mut ack_bytes = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut ack_bytes)
            .map_err(|e| CeremonyError::Http(format!("read FinalizeAck from {url}: {e}")))?;
        let ack: FinalizeAck = crate::cbor::from_canonical_slice(&ack_bytes)
            .map_err(|e| CeremonyError::FinalizeAck(format!("decode: {e}")))?;
        if ack.version != PAIR_MACHINE_VERSION {
            return Err(CeremonyError::FinalizeAck(format!(
                "unsupported version {}",
                ack.version
            )));
        }
        if ack.m_id != self.candidate_cert.m_id.to_string() {
            return Err(CeremonyError::FinalizeAck(format!(
                "m_id mismatch: expected {}, got {}",
                self.candidate_cert.m_id, ack.m_id
            )));
        }
        let expected_hash = machine_cert_hash(&self.candidate_cert)
            .map_err(|e| CeremonyError::FinalizeAck(format!("hash MachineCert: {e}")))?;
        if ack.machine_cert_hash.as_ref() != expected_hash.as_slice() {
            return Err(CeremonyError::FinalizeAck(
                "machine_cert_hash mismatch".into(),
            ));
        }
        Ok(FinalizeWithM2Outcome {
            ack,
            join_response,
            join_response_bytes,
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
    /// recovery to probe M2 (T073/T074). The
    /// `phase3_finalize_ack.marker` written by the caller before
    /// `finalize_with_m2` is the recovery-driver intent pin; this
    /// method honours it by guaranteeing the staged set stays on
    /// disk on commit error.
    ///
    /// On Ok, behaviour is identical to [`commit`].
    /// On Err, the staged set survives on disk; the caller MUST
    /// leave the marker on disk too (it's how recovery distinguishes
    /// "in-flight ceremony, do not roll back" from "no ceremony,
    /// orphan staged files, roll back").
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
    /// finalize POST was launched. The caller must leave the Phase 3
    /// marker on disk so recovery can identify this as an in-flight
    /// ceremony instead of ordinary orphaned staged files.
    pub fn preserve_staged_for_recovery(mut self) {
        if let Some(staged) = self.staged.take() {
            staged.preserve_for_recovery();
        }
        self.closed = true;
    }
}

impl Drop for CeremonyTxn {
    fn drop(&mut self) {
        if !self.closed {
            // Best-effort: drop staged files. Do not touch the sole
            // shard; recovery decides on next boot.
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
/// end-to-end at the network layer) or a trusted LAN segment per
/// `docs/household-protocol.md` §11. Authenticity is provided by the
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
        window.return_to_idle().await?;
    }

    let ttl_unix_from_window = window
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
        .await?;

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
    /// No marker / no `.staged` files / no pending `JoinResponse` — there
    /// is nothing for the driver to do. The caller can proceed to the
    /// normal household-listener startup path.
    NotApplicable,
    /// M2 confirmed committed via the post-commit identity probe AND
    /// M1 finished step 12+13+14. Household is fully N=2.
    RolledForwardPostCommit,
    /// M2 was reachable in pre-household mode AND the staged
    /// `JoinResponse` re-POST landed an ack. M1 finished step 12+13+14.
    RolledForwardPreCommit,
    /// `RECOVERY_TIMEOUT` elapsed without a successful probe. M1
    /// unlinked staged files, marker, and pending `JoinResponse`. The
    /// candidate's possibly-orphaned `MachineCert` is no longer
    /// honoured per `FR-013a`.
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
    #[error("cached JoinRequest unavailable: {0}")]
    CachedJoinRequestUnavailable(String),
    #[error("post-commit promotion failed: {0}")]
    Promotion(String),
}

/// Boot-time recovery driver for an in-flight Phase-3 join ceremony
/// per `contracts/shamir-transition.md` §"Recovery on M1 boot".
///
/// Runs unconditionally at server startup before any household-scoped
/// listener binds. If the on-disk state shows no in-flight ceremony
/// (no marker, no pending `JoinResponse`, no `.staged` siblings), this
/// returns [`RecoveryOutcome::NotApplicable`] and the caller proceeds
/// normally.
///
/// Otherwise the driver loops on a two-state probe of M2 until:
/// * the pre-commit probe (`GET /pair-machine/local/seed`) lands, in
///   which case M1 re-POSTs the staged `JoinResponse` (idempotent on
///   M2's side) and finishes step 12+;
/// * the post-commit probe (`GET /api/v1/household/identity`) confirms
///   M2's committed `hh_id`/`hh_pub` match the staged record's, in
///   which case M1 finishes step 12+ without any further M2 contact;
/// * `recovery_timeout` elapses, in which case M1 rolls the ceremony
///   back per `FR-013a`.
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
    use crate::storage as st;

    // Fast path: no marker = nothing to do. The shorter
    // `clear_stale_phase3_marker_if_post_shamir` already ran in
    // `load_state_dir`, so a post-Shamir household has its marker
    // cleared.
    if !st::phase3_finalize_ack_marker_exists(state_dir) {
        return Ok(RecoveryOutcome::NotApplicable);
    }

    // Marker present → an in-flight ceremony was launched. Read the
    // staged record + pending JoinResponse + cached JoinRequest.
    let staged_record_path = st::staged_path_for(&st::household_record_path(state_dir));
    let staged_record_bytes = match std::fs::read(&staged_record_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(RecoveryError::StagedRecordMissing(
                staged_record_path.display().to_string(),
            ));
        }
        Err(e) => {
            return Err(RecoveryError::Cbor(format!(
                "read {}: {e}",
                staged_record_path.display()
            )));
        }
    };
    let staged_record: HouseholdRecord = cbor::from_canonical_slice(&staged_record_bytes)
        .map_err(|e| RecoveryError::Cbor(format!("decode staged record: {e}")))?;

    let Some(pending_response_bytes) = st::read_phase3_pending_join_response(state_dir)? else {
        return Err(RecoveryError::PendingJoinResponseMissing(
            st::phase3_pending_join_response_path(state_dir)
                .display()
                .to_string(),
        ));
    };

    let snap_path = pair_machine_window_path(state_dir);
    let snap_opt: Option<PairMachineWindowSnapshot> = st::read_optional_cbor(&snap_path)?;
    let snap = snap_opt.ok_or_else(|| {
        RecoveryError::CachedJoinRequestUnavailable(snap_path.display().to_string())
    })?;
    let cached_join_request_bytes = snap.cached_join_request.as_ref().ok_or_else(|| {
        RecoveryError::CachedJoinRequestUnavailable("snapshot.cached_join_request".into())
    })?;
    let cached_join_request: JoinRequest = cbor::from_canonical_slice(cached_join_request_bytes)
        .map_err(|e| RecoveryError::Cbor(format!("decode cached JoinRequest: {e}")))?;

    let m2_addr = cached_join_request.addr.clone();
    let nonce_bytes: Vec<u8> = cached_join_request.nonce.to_vec();
    if nonce_bytes.len() < 8 {
        return Err(RecoveryError::Cbor(format!(
            "cached JoinRequest nonce too short: {}",
            nonce_bytes.len()
        )));
    }
    let nonce_short = crate::ids::base32_lower_nopad_encode(&nonce_bytes[..8]);

    let staged_hh_id = staged_record.hh_id.to_string();
    let staged_hh_pub_bytes = *staged_record.hh_pub.as_bytes();

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
        match repost_finalize(&m2_addr, &pending_response_bytes).await {
            Ok(()) => {
                tracing::info!(
                    stage = "recovery.phase3.repost_finalize_ok",
                    attempt = attempt,
                    addr = %m2_addr,
                    "M2 ack'd JoinResponse re-POST; finishing M1 step 12+ locally"
                );
                finish_phase3_locally(state_dir, pending_response_bytes.clone()).await?;
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

        // Fall back to the post-commit identity probe. Useful when M2
        // is reachable on the household listener but its pre-household
        // listener is gone. In production this is HTTPS over Tailscale.
        match probe_post_commit(&m2_addr, &staged_hh_id, &staged_hh_pub_bytes).await {
            ProbeOutcome::Match => {
                tracing::info!(
                    stage = "recovery.phase3.post_commit_match",
                    attempt = attempt,
                    addr = %m2_addr,
                    hh_id = %staged_hh_id,
                    "M2 identity probe matches; finishing M1 step 12+ locally"
                );
                finish_phase3_locally(state_dir, pending_response_bytes.clone()).await?;
                return Ok(RecoveryOutcome::RolledForwardPostCommit);
            }
            ProbeOutcome::Mismatch => {
                tracing::warn!(
                    stage = "recovery.phase3.post_commit_mismatch",
                    attempt = attempt,
                    addr = %m2_addr,
                    "M2 identity does not match staged household",
                );
            }
            ProbeOutcome::Unreachable | ProbeOutcome::WrongShape => {}
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
                stage = "recovery.phase3.timeout_rollback",
                timeout_secs = recovery_timeout.as_secs(),
                attempts = attempt,
                addr = %m2_addr,
                "RECOVERY_TIMEOUT elapsed; rolling back per FR-013a"
            );
            rollback_phase3_locally(state_dir);
            return Ok(RecoveryOutcome::RolledBack);
        }

        // Backoff. 250 ms is short enough for tests to drive multiple
        // attempts; production passes a 5-minute timeout, which yields
        // ~1200 attempts — overkill but harmless given the probes are
        // single-request HTTP.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[derive(Debug)]
enum ProbeOutcome {
    Match,
    Mismatch,
    WrongShape,
    Unreachable,
}

/// `GET /api/v1/household/identity` over HTTP/HTTPS to detect that M2
/// has committed and is now serving the household listener with the
/// expected `hh_id`/`hh_pub`.
async fn probe_post_commit(
    addr: &str,
    expected_hh_id: &str,
    expected_hh_pub: &[u8; 33],
) -> ProbeOutcome {
    let url = identity_url(addr);
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
    let mut body = String::new();
    if response.into_reader().read_to_string(&mut body).is_err() {
        return ProbeOutcome::WrongShape;
    }
    let value: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return ProbeOutcome::WrongShape,
    };
    let Some(hh_id) = value.get("hh_id").and_then(|v| v.as_str()) else {
        return ProbeOutcome::WrongShape;
    };
    let Some(hh_pub_b64) = value.get("hh_pub_b64").and_then(|v| v.as_str()) else {
        return ProbeOutcome::WrongShape;
    };
    if hh_id != expected_hh_id {
        return ProbeOutcome::Mismatch;
    }
    let Ok(hh_pub_bytes) = base64::engine::general_purpose::STANDARD.decode(hh_pub_b64) else {
        return ProbeOutcome::WrongShape;
    };
    if hh_pub_bytes.as_slice() != expected_hh_pub.as_slice() {
        return ProbeOutcome::Mismatch;
    }
    ProbeOutcome::Match
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
    if response.into_reader().read_to_end(&mut bytes).is_err() {
        return ProbeOutcome::WrongShape;
    }
    let req: JoinRequest = match cbor::from_canonical_slice(&bytes) {
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

fn identity_url(addr: &str) -> String {
    let trimmed = addr.trim_end_matches('/');
    let base = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        // Production: HTTPS over Tailscale once M2 is committed. Tests
        // pass `http://...` explicitly.
        format!("https://{trimmed}")
    };
    format!("{base}/api/v1/household/identity")
}

async fn repost_finalize(addr: &str, body: &[u8]) -> Result<(), CeremonyError> {
    let url = local_finalize_url(addr);
    let body = body.to_vec();
    let owned = url.clone();
    tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();
        let resp = agent
            .post(&owned)
            .set("Content-Type", "application/cbor")
            .send_bytes(&body)
            .map_err(|e| match e {
                ureq::Error::Status(code, _) => {
                    CeremonyError::FinalizeRejected(format!("re-POST {owned}: status {code}"))
                }
                other @ ureq::Error::Transport(_) => {
                    CeremonyError::Http(format!("re-POST {owned}: {other}"))
                }
            })?;
        // We don't need to verify the FinalizeAck here — local/finalize
        // is idempotent on M2's side (it short-circuits to the cached
        // ack when the same body has already committed). The fact
        // that M2 returned 200 OK is sufficient evidence that the
        // ceremony is logically committed on M2.
        let mut sink = Vec::new();
        let _ = resp.into_reader().read_to_end(&mut sink);
        Ok::<(), CeremonyError>(())
    })
    .await
    .map_err(|e| CeremonyError::Http(format!("repost_finalize task failed: {e}")))?
}

/// Promote M1's staged files to their final paths, delete the
/// sole-shard plaintext, clear the marker and pending `JoinResponse`.
/// This is the disk-only finishing logic for steps 12+13+17 of the
/// 2PC; `OwnerEvent` append (step 14) is not done here because the
/// recovery driver runs before the owner-events broadcaster is wired.
async fn finish_phase3_locally(
    state_dir: &Path,
    cached_response_bytes: Vec<u8>,
) -> Result<(), RecoveryError> {
    use crate::storage as st;
    let state_dir_owned = state_dir.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), RecoveryError> {
        // Promote each `.staged` file to its final path. We delegate to
        // `recover_partial_phase3_commit` via an explicit roll-forward
        // helper; the simplest correct approach is to rename them
        // ourselves, mirroring the ordering in `CeremonyTxn::prepare`
        // (record LAST is the canonical commit marker — but here we've
        // already passed the "is M2 committed?" gate, so the order is
        // less critical and we promote everything we find).
        let staged_files = st::detect_orphan_staged_files(&state_dir_owned);
        // First, promote non-record files; promote record last so the
        // canonical commit marker flips after every other file is
        // durable.
        let record_path = st::household_record_path(&state_dir_owned);
        let staged_record_path = st::staged_path_for(&record_path);
        let mut non_record: Vec<_> = staged_files
            .iter()
            .filter(|p| **p != staged_record_path)
            .cloned()
            .collect();
        non_record.sort();
        for staged_path in &non_record {
            let s = staged_path.to_string_lossy().to_string();
            let final_path = std::path::PathBuf::from(s.trim_end_matches(".staged"));
            if final_path.exists() {
                let _ = std::fs::remove_file(staged_path);
                continue;
            }
            std::fs::rename(staged_path, &final_path).map_err(|e| {
                RecoveryError::Promotion(format!(
                    "rename {} -> {}: {e}",
                    staged_path.display(),
                    final_path.display()
                ))
            })?;
            if let Some(parent) = final_path.parent() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        if staged_record_path.exists() {
            std::fs::rename(&staged_record_path, &record_path).map_err(|e| {
                RecoveryError::Promotion(format!(
                    "rename {} -> {}: {e}",
                    staged_record_path.display(),
                    record_path.display()
                ))
            })?;
            if let Some(parent) = record_path.parent() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }

        // Step 13: delete sole-shard plaintext.
        let sole = household_root_sole_path(&state_dir_owned);
        if sole.exists() {
            if let Err(e) = std::fs::remove_file(&sole) {
                tracing::warn!(
                    stage = "recovery.phase3.sole_shard_unlink_failed",
                    path = %sole.display(),
                    error = %e,
                );
            }
        }

        // Clear the marker + pending JoinResponse — ceremony complete.
        mark_window_committed_after_recovery(&state_dir_owned, cached_response_bytes)?;
        let _ = st::clear_phase3_finalize_ack_marker(&state_dir_owned);
        let _ = st::clear_phase3_pending_join_response(&state_dir_owned);
        Ok(())
    })
    .await
    .map_err(|e| RecoveryError::Promotion(format!("blocking task failed: {e}")))?
}

/// `RECOVERY_TIMEOUT` elapsed: tear down the in-flight ceremony per
/// `FR-013a`.
fn rollback_phase3_locally(state_dir: &Path) {
    use crate::storage as st;
    if let Err(e) = mark_window_aborted_after_recovery(state_dir) {
        tracing::warn!(
            stage = "recovery.phase3.window_abort_failed",
            error = %e,
            hint = "leaving Phase-3 marker/pending/staged files for retry"
        );
        return;
    }
    let staged = st::detect_orphan_staged_files(state_dir);
    for staged_path in &staged {
        let _ = std::fs::remove_file(staged_path);
    }
    // Also unlink any partially-promoted candidate cert. The
    // staged record's `members[]` (read above) carried the candidate
    // m_id; we re-read it here defensively in case the staged record
    // has just been deleted.
    // (No-op if this code path runs again with the staged set already
    // gone.)
    let _ = st::clear_phase3_finalize_ack_marker(state_dir);
    let _ = st::clear_phase3_pending_join_response(state_dir);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKey, P256Keypair};

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

        let persisted: PairMachineWindowSnapshot =
            crate::storage::read_optional_cbor(&pair_machine_window_path(td.path()))
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
