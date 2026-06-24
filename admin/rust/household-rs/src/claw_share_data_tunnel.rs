//! Claw-share **data tunnel**: an authenticated, routed transport.
//!
//! Authenticates a friend's session (credential + proof-of-possession
//! token) and routes packet frames to a real target service. The engine
//! wires [`serve_connection`] onto a TCP listener; the iOS bridge dials
//! it with [`client_authenticate`] + [`client_health`] +
//! [`client_packet_round_trip`].
//!
//! ## Wire protocol (length-prefixed frames)
//!
//! Each frame is a 4-byte big-endian length followed by that many
//! payload bytes (`MAX_FRAME_LEN` cap). Sequence:
//!
//! 1. client → server: auth frame = canonical-CBOR [`AuthEnvelope`]
//!    (credential + [`SessionAuthToken`]).
//! 2. server → client: [`TunnelAck`] — `Ok { mesh_ipv6, mtu, session_id }`
//!    or `Rejected { reason }`. On reject the server closes.
//! 3. typed [`TunnelFrame`]s: `Health` echoes (liveness → the bridge
//!    reports `connected`); `Open` opens a PERSISTENT stream to the target
//!    via [`ClawStreamRouter`] and `Data` is piped both ways until
//!    `Close`/`Error`/EOF (the bridge reports `stream-ready`). No
//!    packet-echo path.
//!
//! ## Authentication — never trusts the network
//!
//! [`authorize_session`] = [`authorize_credential`] (owner signature +
//! expiry, household binding, claw binding, slot revocation, consumed-slot
//! device binding) PLUS proof-of-possession: [`SessionAuthToken::verify`]
//! checks the token was signed by the credential's `guest_device_pub`,
//! binds to the credential hash + endpoint, and is within a 300s TTL; plus
//! a `target_id` binding (must equal the claw) and single-use replay
//! rejection ([`ReplayGuard`]). So a stolen credential alone — or a
//! replayed / wrong-target token — cannot open a session. Revoking the
//! slot mid-session blocks the next frame.
//!
//! ## Interactive sessions (PTY)
//!
//! The target is whatever [`ClawTargetRouter`] opens: a [`TcpStreamRouter`]
//! TCP fixture in this crate's tests, or — in the daemon — a real
//! policy-controlled local PTY (`server-rs::claw_share_pty_target`) running
//! an interactive shell. The stream is genuinely interactive: `Data` carries
//! terminal stdin/stdout both ways, [`TunnelFrame::Resize`] propagates the
//! client's terminal dimensions to the PTY (`TIOCSWINSZ`), and when the
//! target process exits the engine emits a typed [`TunnelFrame::Exit`]
//! ([`TargetExit`]) before closing. A target that has no terminal (raw TCP)
//! treats resize as a no-op and has no exit status.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cbor;
use crate::claw_share::{ClawShareSlotStore, GuestCredential, SlotState};
use crate::ids::HouseholdId;
use crate::keys::{P256PublicKey, P256Signature, verify_signature};

/// Frame size cap. Health probes are tiny; this guards against a peer
/// announcing an absurd length and forcing a huge allocation.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Canonical health probe the bridge sends. The server echoes it; the
/// bridge only advances to `connected` on a byte-exact match.
pub const HEALTH_PROBE: &[u8] = b"claw-share/health/v1";

fn short_str(value: &str) -> String {
    value.chars().take(24).collect()
}

fn short_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().min(8) * 2);
    for b in bytes.iter().take(8) {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DataTunnelError {
    #[error("io error: {0}")]
    Io(String),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("connection closed during {0}")]
    Closed(&'static str),
    #[error("auth timeout")]
    AuthTimeout,
    #[error("cbor: {0}")]
    Cbor(String),
    #[error("credential rejected: {0}")]
    Rejected(String),
    #[error("server returned an unexpected ack")]
    UnexpectedAck,
    #[error("health echo did not match the probe")]
    HealthMismatch,
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("session token rejected: {0}")]
    TokenRejected(String),
    #[error("target service unavailable: {0}")]
    TargetUnavailable(String),
}

/// Server's reply to the auth frame.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TunnelAck {
    /// Credential accepted. Carries the mesh address + MTU the extension
    /// would apply to `NEPacketTunnelNetworkSettings`, plus a `session_id`
    /// (stable per credential/slot) the host can use to correlate logs
    /// and recovery across reconnects.
    Ok {
        mesh_ipv6: String,
        mtu: u16,
        session_id: String,
    },
    /// Credential rejected with a stable, non-secret reason string.
    Rejected { reason: String },
}

// ─── Typed data frames (post-auth) ─────────────────────────────────────────────

/// Frame kind byte prefixed to every post-auth payload.
///
/// `Health` is a liveness probe (echoed → tunnel ready). The rest drive a
/// PERSISTENT bidirectional stream to the target (claw SSH/terminal): the
/// engine holds one target connection per session and pipes `Data` both
/// ways until `Close`/`Error`/EOF. `Window` carries a backpressure credit.
/// `Resize` (client → engine) carries the terminal dimensions; `Exit`
/// (engine → client) carries the target process's typed exit status.
pub const FRAME_HEALTH: u8 = 0x01;
pub const FRAME_OPEN: u8 = 0x10;
pub const FRAME_DATA: u8 = 0x11;
pub const FRAME_CLOSE: u8 = 0x12;
pub const FRAME_ERROR: u8 = 0x13;
pub const FRAME_WINDOW: u8 = 0x14;
pub const FRAME_RESIZE: u8 = 0x15;
pub const FRAME_EXIT: u8 = 0x16;

/// Typed exit status of an interactive target process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetExit {
    /// Normal exit with this status code.
    Code(i32),
    /// Terminated by this signal number.
    Signal(i32),
    /// The target ended without a recoverable status (killed/dropped).
    Lost,
}

impl TargetExit {
    const TAG_CODE: u8 = 0x01;
    const TAG_SIGNAL: u8 = 0x02;
    const TAG_LOST: u8 = 0x03;

    fn encode(self) -> [u8; 5] {
        let (tag, val): (u8, i32) = match self {
            Self::Code(c) => (Self::TAG_CODE, c),
            Self::Signal(s) => (Self::TAG_SIGNAL, s),
            Self::Lost => (Self::TAG_LOST, 0),
        };
        let v = val.to_be_bytes();
        [tag, v[0], v[1], v[2], v[3]]
    }

    fn decode(payload: &[u8]) -> Result<Self, DataTunnelError> {
        let arr: [u8; 5] = payload
            .try_into()
            .map_err(|_| DataTunnelError::InvalidFrame("bad exit frame".into()))?;
        let val = i32::from_be_bytes([arr[1], arr[2], arr[3], arr[4]]);
        match arr[0] {
            Self::TAG_CODE => Ok(Self::Code(val)),
            Self::TAG_SIGNAL => Ok(Self::Signal(val)),
            Self::TAG_LOST => Ok(Self::Lost),
            other => Err(DataTunnelError::InvalidFrame(format!(
                "unknown exit tag {other:#04x}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelFrame {
    /// Liveness probe / echo.
    Health(Vec<u8>),
    /// Open the persistent stream to the session's target.
    Open,
    /// Bidirectional stream bytes.
    Data(Vec<u8>),
    /// Clean close of the stream (either direction).
    Close,
    /// Typed error; payload is a stable reason string.
    Error(String),
    /// Backpressure credit: the peer may send up to `n` more bytes.
    Window(u32),
    /// Terminal resize (client → engine): the target PTY's column/row count.
    Resize { cols: u16, rows: u16 },
    /// Target process exit (engine → client): the typed exit status, sent
    /// just before the closing [`TunnelFrame::Close`].
    Exit(TargetExit),
}

impl TunnelFrame {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Health(p) => {
                out.push(FRAME_HEALTH);
                out.extend_from_slice(p);
            }
            Self::Open => out.push(FRAME_OPEN),
            Self::Data(p) => {
                out.push(FRAME_DATA);
                out.extend_from_slice(p);
            }
            Self::Close => out.push(FRAME_CLOSE),
            Self::Error(reason) => {
                out.push(FRAME_ERROR);
                out.extend_from_slice(reason.as_bytes());
            }
            Self::Window(n) => {
                out.push(FRAME_WINDOW);
                out.extend_from_slice(&n.to_be_bytes());
            }
            Self::Resize { cols, rows } => {
                out.push(FRAME_RESIZE);
                out.extend_from_slice(&cols.to_be_bytes());
                out.extend_from_slice(&rows.to_be_bytes());
            }
            Self::Exit(status) => {
                out.push(FRAME_EXIT);
                out.extend_from_slice(&status.encode());
            }
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, DataTunnelError> {
        let (&kind, payload) = bytes
            .split_first()
            .ok_or_else(|| DataTunnelError::InvalidFrame("empty frame".into()))?;
        match kind {
            FRAME_HEALTH => Ok(Self::Health(payload.to_vec())),
            FRAME_OPEN => Ok(Self::Open),
            FRAME_DATA => Ok(Self::Data(payload.to_vec())),
            FRAME_CLOSE => Ok(Self::Close),
            FRAME_ERROR => Ok(Self::Error(String::from_utf8_lossy(payload).into_owned())),
            FRAME_WINDOW => {
                let arr: [u8; 4] = payload
                    .try_into()
                    .map_err(|_| DataTunnelError::InvalidFrame("bad window frame".into()))?;
                Ok(Self::Window(u32::from_be_bytes(arr)))
            }
            FRAME_RESIZE => {
                let arr: [u8; 4] = payload
                    .try_into()
                    .map_err(|_| DataTunnelError::InvalidFrame("bad resize frame".into()))?;
                Ok(Self::Resize {
                    cols: u16::from_be_bytes([arr[0], arr[1]]),
                    rows: u16::from_be_bytes([arr[2], arr[3]]),
                })
            }
            FRAME_EXIT => Ok(Self::Exit(TargetExit::decode(payload)?)),
            other => Err(DataTunnelError::InvalidFrame(format!(
                "unknown frame kind {other:#04x}"
            ))),
        }
    }
}

// ─── Frame IO ────────────────────────────────────────────────────────────────

async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
) -> Result<(), DataTunnelError> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(DataTunnelError::FrameTooLarge(payload.len()));
    }
    let len =
        u32::try_from(payload.len()).map_err(|_| DataTunnelError::FrameTooLarge(payload.len()))?;
    w.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| DataTunnelError::Io(e.to_string()))?;
    w.write_all(payload)
        .await
        .map_err(|e| DataTunnelError::Io(e.to_string()))?;
    w.flush()
        .await
        .map_err(|e| DataTunnelError::Io(e.to_string()))?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    what: &'static str,
) -> Result<Vec<u8>, DataTunnelError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|_| DataTunnelError::Closed(what))?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > MAX_FRAME_LEN {
        return Err(DataTunnelError::FrameTooLarge(n));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .await
        .map_err(|_| DataTunnelError::Closed(what))?;
    Ok(buf)
}

// ─── Authorization ───────────────────────────────────────────────────────────

/// Authorize a credential for this engine. This is the policy the engine
/// applies on every data-tunnel connection. Pure: takes the engine's
/// household id + slot store, returns `Ok` or a typed `Rejected`.
pub fn authorize_credential(
    cred: &GuestCredential,
    hh_id: &HouseholdId,
    slots: &ClawShareSlotStore,
    now_unix: u64,
) -> Result<(), DataTunnelError> {
    // 1. Owner signature + not-expired (the credential's own invariant).
    cred.verify(now_unix)
        .map_err(|e| DataTunnelError::Rejected(e.to_string()))?;

    // 2. Household binding — the credential must be for THIS engine.
    if &cred.hh_id != hh_id {
        return Err(DataTunnelError::Rejected("household-mismatch".into()));
    }

    // 3. Slot lookup → claw binding + revocation + device binding.
    let record = slots
        .get(&cred.slot_id)
        .ok_or_else(|| DataTunnelError::Rejected("slot-not-found".into()))?;
    if record.claw_id != cred.claw_id {
        return Err(DataTunnelError::Rejected("claw-binding-mismatch".into()));
    }
    match record.state {
        SlotState::Revoked { .. } => return Err(DataTunnelError::Rejected("slot-revoked".into())),
        SlotState::Consumed {
            guest_device_pub, ..
        } => {
            // The credential must belong to the device that consumed the
            // invite — a different device's credential for this slot is
            // rejected even if otherwise well-formed.
            if guest_device_pub != cred.guest_device_pub {
                return Err(DataTunnelError::Rejected("guest-device-mismatch".into()));
            }
        }
        // Open: invite not yet consumed. The owner signature still binds
        // the credential, so accept; the consume CAS happens on the
        // control plane.
        SlotState::Open => {}
    }
    Ok(())
}

/// Deterministic ULA-style mesh address from the credential. Placeholder
/// until the engine routes a real mesh address; stable + collision-free
/// against real allocations.
fn derive_mesh_ipv6(cred: &GuestCredential) -> String {
    let s = cred.slot_id.0;
    format!(
        "fd00:c1aw::{:02x}{:02x}:{:02x}{:02x}",
        s[0], s[1], s[2], s[3]
    )
}

/// Stable session id for a credential: hex of the slot id. Stable across
/// reconnects (same slot → same id), which the host uses to correlate
/// logs + recovery.
fn derive_session_id(cred: &GuestCredential) -> String {
    use std::fmt::Write as _;
    cred.slot_id.0.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// What the data-tunnel serve loop needs from an authorized session value: the
/// stable `session_id` and `mesh_ipv6` surfaced in the [`TunnelAck`].
///
/// Implemented by [`GuestCredential`] (the Device path, delegating verbatim to
/// the existing `derive_*` so its ack is byte-identical) and, in `server-rs`, by
/// the `relay_stream` Group/Public session (credential-less). Generalizing the
/// serve core over this trait lets credential-less audiences share the exact same
/// authenticated pipe without a synthetic credential (Fase E2.5/E3, panel choice A).
pub trait DataTunnelSession {
    /// Stable, non-truncated session id surfaced in the ack + correlation logs.
    fn session_id(&self) -> String;
    /// Placeholder ULA-style mesh address surfaced in the ack.
    fn mesh_ipv6(&self) -> String;
}

impl DataTunnelSession for GuestCredential {
    // Device path: byte-identical to the pre-refactor ack — delegates VERBATIM to
    // the existing slot-derived helpers and never re-derives.
    fn session_id(&self) -> String {
        derive_session_id(self)
    }
    fn mesh_ipv6(&self) -> String {
        derive_mesh_ipv6(self)
    }
}

// ─── Session proof-of-possession ───────────────────────────────────────────────

/// Short-lived token proving the connecting party holds the guest device
/// private key bound to the `GuestCredential`. Signed by that key (on iOS
/// the host app signs it via the Secure-Enclave guest identity before
/// starting the tunnel, because the extension can't reach the SE key).
/// Bound to `(session_id, credential_hash, endpoint, expires_at)` so a
/// stolen credential blob alone — or a token replayed to a different
/// endpoint / after expiry — cannot open a session.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionAuthToken {
    pub session_id: String,
    #[serde(with = "serde_bytes")]
    pub credential_hash: Vec<u8>,
    pub endpoint: String,
    /// The claw/target this session may reach — a token minted for one
    /// claw cannot open a stream to another.
    pub target_id: String,
    /// Single-use nonce — the engine rejects a second use (replay).
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub expires_at: u64,
    pub signature: P256Signature,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SessionAuthTokenUnsigned<'a> {
    session_id: &'a str,
    #[serde(with = "serde_bytes")]
    credential_hash: &'a [u8],
    endpoint: &'a str,
    target_id: &'a str,
    #[serde(with = "serde_bytes")]
    nonce: &'a [u8],
    expires_at: u64,
}

const SESSION_TOKEN_MAX_TTL_SECS: u64 = 300;

/// BLAKE3 of the canonical credential CBOR — what the token binds to.
#[must_use]
pub fn credential_hash(credential_cbor: &[u8]) -> Vec<u8> {
    blake3::hash(credential_cbor).as_bytes().to_vec()
}

impl SessionAuthToken {
    /// Sign a token with the guest device key. Used by the host app (and
    /// tests). `now_unix + ttl` must be within the max TTL.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        session_id: String,
        credential_cbor: &[u8],
        endpoint: String,
        target_id: String,
        nonce: Vec<u8>,
        expires_at: u64,
        guest_key: &dyn crate::keys::IdentityKey,
    ) -> Result<Self, DataTunnelError> {
        let hash = credential_hash(credential_cbor);
        let unsigned = SessionAuthTokenUnsigned {
            session_id: &session_id,
            credential_hash: &hash,
            endpoint: &endpoint,
            target_id: &target_id,
            nonce: &nonce,
            expires_at,
        };
        let bytes =
            cbor::to_canonical_vec(&unsigned).map_err(|e| DataTunnelError::Cbor(e.to_string()))?;
        let signature = guest_key
            .sign(&bytes)
            .map_err(|e| DataTunnelError::TokenRejected(format!("sign: {e}")))?;
        Ok(Self {
            session_id,
            credential_hash: hash,
            endpoint,
            target_id,
            nonce,
            expires_at,
            signature,
        })
    }

    /// Verify the token signature against the credential's guest device
    /// key, plus expiry + the credential-hash binding. `guest_device_pub`
    /// comes from the verified `GuestCredential` — so a token signed by a
    /// different device is rejected.
    pub fn verify(
        &self,
        guest_device_pub: &P256PublicKey,
        expected_credential_hash: &[u8],
        now_unix: u64,
    ) -> Result<(), DataTunnelError> {
        if self.credential_hash != expected_credential_hash {
            return Err(DataTunnelError::TokenRejected(
                "credential-hash-mismatch".into(),
            ));
        }
        if self.expires_at <= now_unix {
            return Err(DataTunnelError::TokenRejected("token-expired".into()));
        }
        if self.expires_at > now_unix.saturating_add(SESSION_TOKEN_MAX_TTL_SECS) {
            return Err(DataTunnelError::TokenRejected("token-ttl-too-long".into()));
        }
        let unsigned = SessionAuthTokenUnsigned {
            session_id: &self.session_id,
            credential_hash: &self.credential_hash,
            endpoint: &self.endpoint,
            target_id: &self.target_id,
            nonce: &self.nonce,
            expires_at: self.expires_at,
        };
        let bytes =
            cbor::to_canonical_vec(&unsigned).map_err(|e| DataTunnelError::Cbor(e.to_string()))?;
        verify_signature(guest_device_pub, &bytes, &self.signature)
            .map_err(|_| DataTunnelError::TokenRejected("signature-invalid".into()))
    }
}

/// Single-use-nonce tracker — the engine rejects a token whose nonce it
/// has already accepted (replay), pruning entries past their expiry.
#[derive(Default)]
pub struct ReplayGuard {
    seen: std::sync::Mutex<std::collections::HashMap<Vec<u8>, u64>>,
}

impl ReplayGuard {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `nonce` (expiring at `expires_at`). Returns
    /// `TokenRejected("token-replayed")` if it was already recorded.
    ///
    /// # Panics
    /// Panics only if the internal mutex is poisoned.
    pub fn check_and_record(
        &self,
        nonce: &[u8],
        expires_at: u64,
        now_unix: u64,
    ) -> Result<(), DataTunnelError> {
        let mut seen = self.seen.lock().expect("replay guard mutex poisoned");
        seen.retain(|_, exp| *exp > now_unix);
        if seen.contains_key(nonce) {
            return Err(DataTunnelError::TokenRejected("token-replayed".into()));
        }
        seen.insert(nonce.to_vec(), expires_at);
        Ok(())
    }
}

/// The auth frame: the credential bytes + the proof-of-possession token.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthEnvelope {
    #[serde(with = "serde_bytes")]
    pub credential_cbor: Vec<u8>,
    pub token: SessionAuthToken,
}

/// Full session authorization: credential (sig/expiry/binding/revocation),
/// proof-of-possession of the guest device key, the token's `target_id`
/// binding (must equal the credential's `claw_id`), and single-use replay
/// rejection. Returns the verified credential. A stolen credential without
/// a valid token — or a replayed / wrong-target token — is rejected here.
pub fn authorize_session(
    envelope: &AuthEnvelope,
    hh_id: &HouseholdId,
    slots: &ClawShareSlotStore,
    replay: &ReplayGuard,
    now_unix: u64,
) -> Result<GuestCredential, DataTunnelError> {
    let cred: GuestCredential = cbor::from_canonical_slice(&envelope.credential_cbor)
        .map_err(|e| DataTunnelError::Cbor(e.to_string()))?;
    authorize_credential(&cred, hh_id, slots, now_unix)?;
    let expected = credential_hash(&envelope.credential_cbor);
    envelope
        .token
        .verify(&cred.guest_device_pub, &expected, now_unix)?;
    // Target binding: the token may only open the claw it was minted for.
    if envelope.token.target_id != cred.claw_id {
        return Err(DataTunnelError::TokenRejected("target-mismatch".into()));
    }
    // Single-use: reject replays.
    replay.check_and_record(&envelope.token.nonce, envelope.token.expires_at, now_unix)?;
    Ok(cred)
}

// ─── Interactive target (engine side) ─────────────────────────────────────────

/// One opened, PERSISTENT interactive target the engine pipes a session to.
///
/// The byte halves (`reader`/`writer`) carry terminal stdout/stdin; `resize`
/// applies the client's terminal dimensions to the target (a PTY honours it,
/// a raw socket ignores it); `exit` resolves with the target process's typed
/// status when it terminates (a socket target has no process, so its `exit`
/// stays pending and the stream ends on EOF instead). Owned, so the serve
/// loop drives all four concurrently; dropping the session tears the target
/// down (the PTY child is killed on drop).
pub struct TargetSession {
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    pub resize: Box<dyn Fn(u16, u16) -> Result<(), DataTunnelError> + Send>,
    pub exit: std::pin::Pin<Box<dyn std::future::Future<Output = TargetExit> + Send>>,
}

impl TargetSession {
    /// Build a session over a plain byte stream (raw TCP target): resize is a
    /// no-op (no terminal) and there is no process exit status (the stream
    /// ends on EOF). Used by [`TcpStreamRouter`] and tests.
    pub fn from_stream<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Box::new(reader),
            writer: Box::new(writer),
            resize: Box::new(|_, _| Ok(())),
            exit: Box::pin(std::future::pending()),
        }
    }
}

/// Opens a PERSISTENT interactive target for a session. One target per
/// session, reused for the whole stream; the engine pipes bytes both ways
/// (plus resize / exit) until close.
pub trait ClawTargetRouter: Send + Sync {
    fn open(
        &self,
        target_id: &str,
    ) -> impl std::future::Future<Output = Result<TargetSession, DataTunnelError>> + Send;
}

/// Connects to a fixed TCP target address (e.g. a fake-banner fixture in
/// tests, or an SSH endpoint). Raw bytes only — no terminal resize, no exit
/// status (the persistent PTY target lives in `server-rs`).
pub struct TcpStreamRouter {
    target_addr: String,
}

impl TcpStreamRouter {
    #[must_use]
    pub fn new(target_addr: impl Into<String>) -> Self {
        Self {
            target_addr: target_addr.into(),
        }
    }
}

impl ClawTargetRouter for TcpStreamRouter {
    async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
        let stream = tokio::net::TcpStream::connect(&self.target_addr)
            .await
            .map_err(|e| DataTunnelError::TargetUnavailable(e.to_string()))?;
        Ok(TargetSession::from_stream(stream))
    }
}

/// Idle timeout: if the client sends no stream frame for this long, the
/// session is closed rather than leaking a zombie. Generous so an
/// interactive terminal that's merely quiet stays open.
const STREAM_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

const STREAM_READ_CHUNK: usize = 16 * 1024;

/// Default wall-clock budget for the pre-auth phase, from the first auth-frame
/// read through the auth ack/reject write. A peer that completes the transport
/// but never sends a full [`AuthEnvelope`] must not hold a claw session forever.
pub const DEFAULT_AUTH_DEADLINE: Duration = Duration::from_secs(15);

/// How often the stream loop re-checks the revocation predicate so an IDLE
/// session (no inbound `Data` frames to trigger the per-frame check) is still
/// torn down promptly after a revoke. 500ms keeps revoke→close well under the
/// 2s SLA even allowing for the daemon's own revoke-processing latency.
const REVOKE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// After the target's output reaches EOF, how long to wait for its process
/// exit status before closing the stream. A shell exits within milliseconds
/// of its PTY closing; this is a generous ceiling. A socket target (whose
/// `exit` is pending) just hits this timeout and closes with no status.
const TARGET_EXIT_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

// ─── Server ──────────────────────────────────────────────────────────────────

/// Serve one data-tunnel connection: authenticate (credential +
/// proof-of-possession token via `verify`, usually [`authorize_session`]),
/// answer health probes, then on `Open` open a PERSISTENT interactive target
/// via `router` and pipe `Data` both ways until close/EOF/error.
///
/// Interactive control: a client `Resize` frame is applied to the target's
/// terminal (best-effort); when the target process exits, its output reaches
/// EOF and a typed [`TunnelFrame::Exit`] is sent before the closing `Close`.
///
/// `is_revoked(claw_id) -> bool` is consulted before forwarding each client
/// `Data` frame, so revoking the slot mid-session blocks the next frame and
/// tears the session down. Backpressure is await-based: each direction
/// blocks on its write, so a slow target/tunnel naturally throttles the
/// other side (no unbounded buffering, no busy loop). Clean close on EOF,
/// `Close`, error, idle timeout, or tunnel drop — dropping the target session
/// tears the target down (the PTY child is killed on drop).
pub async fn serve_connection<R, V, Rev>(
    stream: tokio::net::TcpStream,
    now_unix: u64,
    verify: V,
    router: &R,
    is_revoked: Rev,
) -> Result<(), DataTunnelError>
where
    R: ClawTargetRouter,
    V: Fn(&AuthEnvelope, u64) -> Result<GuestCredential, DataTunnelError>,
    Rev: Fn(&GuestCredential) -> bool + Send + 'static,
{
    serve_connection_io(stream, now_unix, verify, router, is_revoked).await
}

/// Generic [`serve_connection`] core for already-established byte streams.
///
/// This preserves the TCP listener API while allowing test-only/local relay
/// stream endpoints to run the same authenticated data-tunnel protocol over a
/// Noise-protected `AsyncRead + AsyncWrite`.
pub async fn serve_connection_io<S, R, V, Rev>(
    stream: S,
    now_unix: u64,
    verify: V,
    router: &R,
    is_revoked: Rev,
) -> Result<(), DataTunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: ClawTargetRouter,
    V: Fn(&AuthEnvelope, u64) -> Result<GuestCredential, DataTunnelError>,
    Rev: Fn(&GuestCredential) -> bool + Send + 'static,
{
    serve_connection_io_with_auth_deadline(
        stream,
        now_unix,
        verify,
        router,
        is_revoked,
        DEFAULT_AUTH_DEADLINE,
    )
    .await
}

/// Generic [`serve_connection_io`] variant with an injected pre-auth deadline.
///
/// The deadline is one wall-clock budget for the whole auth phase. It does not
/// reset when a peer trickles partial frame bytes.
pub async fn serve_connection_io_with_auth_deadline<S, R, V, Rev, Sess>(
    stream: S,
    now_unix: u64,
    verify: V,
    router: &R,
    is_revoked: Rev,
    auth_deadline: Duration,
) -> Result<(), DataTunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: ClawTargetRouter,
    Sess: DataTunnelSession + Send + 'static,
    V: Fn(&AuthEnvelope, u64) -> Result<Sess, DataTunnelError>,
    Rev: Fn(&Sess) -> bool + Send + 'static,
{
    let (mut tunnel_r, mut tunnel_w) = tokio::io::split(stream);

    // 1. Authenticate.
    let (cred, target_id) = if let Ok(result) = tokio::time::timeout(auth_deadline, async {
        tracing::debug!(stage = "claw_share.data_tunnel.auth_read_start");
        let auth = read_frame(&mut tunnel_r, "auth").await?;
        tracing::debug!(
            stage = "claw_share.data_tunnel.auth_frame_read",
            auth_len = auth.len()
        );
        let envelope: AuthEnvelope =
            cbor::from_canonical_slice(&auth).map_err(|e| DataTunnelError::Cbor(e.to_string()))?;
        tracing::debug!(
            stage = "claw_share.data_tunnel.auth_envelope_decoded",
            credential_len = envelope.credential_cbor.len(),
            token_session = %short_str(&envelope.token.session_id),
            token_target = %short_str(&envelope.token.target_id),
            token_endpoint = %envelope.token.endpoint,
            nonce_trunc = %short_hex(&envelope.token.nonce),
            expires_at = envelope.token.expires_at,
        );
        let cred = match verify(&envelope, now_unix) {
            Ok(cred) => {
                tracing::debug!(
                    stage = "claw_share.data_tunnel.auth_verified",
                    session_id_trunc = %short_str(&cred.session_id()),
                );
                let ack = TunnelAck::Ok {
                    mesh_ipv6: cred.mesh_ipv6(),
                    mtu: 1280,
                    session_id: cred.session_id(),
                };
                let bytes = cbor::to_canonical_vec(&ack)
                    .map_err(|e| DataTunnelError::Cbor(e.to_string()))?;
                write_frame(&mut tunnel_w, &bytes).await?;
                tracing::debug!(
                    stage = "claw_share.data_tunnel.auth_ack_sent",
                    ack_len = bytes.len(),
                    session_id_trunc = %short_str(&cred.session_id()),
                );
                cred
            }
            Err(rejected) => {
                let reason = match &rejected {
                    DataTunnelError::Rejected(r) | DataTunnelError::TokenRejected(r) => r.clone(),
                    other => other.to_string(),
                };
                tracing::debug!(
                    stage = "claw_share.data_tunnel.auth_rejected",
                    reason = %reason,
                );
                if let Ok(bytes) = cbor::to_canonical_vec(&TunnelAck::Rejected { reason }) {
                    let _ = write_frame(&mut tunnel_w, &bytes).await;
                    tracing::debug!(
                        stage = "claw_share.data_tunnel.reject_ack_sent",
                        ack_len = bytes.len()
                    );
                }
                return Err(rejected);
            }
        };
        Ok::<_, DataTunnelError>((cred, envelope.token.target_id.clone()))
    })
    .await
    {
        result?
    } else {
        tracing::debug!(
            stage = "claw_share.data_tunnel.auth_timeout",
            timeout_ms = auth_deadline.as_millis(),
        );
        return Err(DataTunnelError::AuthTimeout);
    };

    // 2. Pre-stream: answer Health (liveness) until the client opens.
    loop {
        match recv_frame(&mut tunnel_r).await {
            Ok(TunnelFrame::Health(p)) => {
                tracing::debug!(
                    stage = "claw_share.data_tunnel.health_received",
                    len = p.len()
                );
                send_frame(&mut tunnel_w, &TunnelFrame::Health(p)).await?;
                tracing::debug!(stage = "claw_share.data_tunnel.health_echo_sent");
            }
            Ok(TunnelFrame::Open) => {
                tracing::debug!(stage = "claw_share.data_tunnel.open_received", target_id = %short_str(&target_id));
                break;
            }
            Ok(frame) => {
                tracing::debug!(stage = "claw_share.data_tunnel.pre_stream_unexpected", frame = ?frame);
                return Err(DataTunnelError::InvalidFrame(
                    "expected health or open before stream".into(),
                ));
            }
            Err(DataTunnelError::Closed(_)) => return Ok(()),
            Err(other) => return Err(other),
        }
    }

    // 3. Open the PERSISTENT interactive target.
    let TargetSession {
        mut reader,
        mut writer,
        resize,
        mut exit,
    } = match router.open(&target_id).await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(stage = "claw_share.data_tunnel.target_open_failed", target_id = %short_str(&target_id), error = %e);
            let _ = send_frame(&mut tunnel_w, &TunnelFrame::Error(e.to_string())).await;
            return Err(e);
        }
    };
    send_frame(&mut tunnel_w, &TunnelFrame::Open).await?; // stream-ready ack
    tracing::debug!(stage = "claw_share.data_tunnel.open_ack_sent", target_id = %short_str(&target_id));

    // 4. Bidirectional interactive pipe, driven from a single task so the two
    //    directions, resize, and process exit share the target without
    //    contending. First terminal condition ends the session.
    //    (`AsyncReadExt`/`AsyncWriteExt` are imported at module scope.)
    let mut rbuf = vec![0u8; STREAM_READ_CHUNK];
    // Idle revocation: a quiet interactive session sends no `Data` frames, so
    // the per-`Data` `is_revoked` check below never fires and the only other
    // client traffic (e.g. a `Window` credit/keepalive) is a no-op. Poll the
    // revocation predicate on a short interval so revoking the slot tears an
    // IDLE session down within the tick — well under the <2s revocation SLA —
    // regardless of whether the client is sending. The first tick fires
    // immediately (a fresh, just-authorized session is not revoked, so it is a
    // cheap no-op); subsequent ticks every `REVOKE_POLL`.
    // SECURITY INVARIANT (audit D4 — load-bearing ordering; do not reorder).
    // For the Group/Public audience `is_revoked` is the FULL live authorization gate
    // (relay_stream_offer_session_revoked: not_after + machine-issuer-active +
    // membership/published on the live projection), not merely a slot check. Two
    // orderings enforce mid-session deauthorization and MUST be preserved across
    // refactors: (1) the revoke_poll first tick fires IMMEDIATELY (below), so a
    // principal deauthorized between authorize and the first loop turn is cut before
    // any data flows; (2) the per-`Data` `is_revoked` check PRECEDES the
    // forward/write below, so no frame is delivered after deauthorization. Removing
    // the immediate first tick, or moving the per-`Data` check after the write,
    // would open a forward-after-revoke window.
    let mut revoke_poll = tokio::time::interval(REVOKE_POLL_INTERVAL);
    revoke_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            // Revocation watcher: closes an idle (or active) session promptly
            // once the slot is revoked, independent of inbound `Data` frames.
            _ = revoke_poll.tick() => {
                if is_revoked(&cred) {
                    let _ = writer.shutdown().await;
                    return Err(DataTunnelError::Rejected("slot-revoked".into()));
                }
            }
            // tunnel → target (revocation-checked per Data frame)
            inbound = tokio::time::timeout(STREAM_IDLE_TIMEOUT, recv_frame(&mut tunnel_r)) => {
                let Ok(frame) = inbound else {
                    return Err(DataTunnelError::Closed("idle-timeout"));
                };
                match frame {
                    Ok(TunnelFrame::Data(d)) => {
                        if is_revoked(&cred) {
                            return Err(DataTunnelError::Rejected("slot-revoked".into()));
                        }
                        writer.write_all(&d).await.map_err(|e| DataTunnelError::Io(e.to_string()))?;
                        writer.flush().await.map_err(|e| DataTunnelError::Io(e.to_string()))?;
                    }
                    // Apply the client's terminal size to the target. Best
                    // effort: a resize hiccup must not tear down the session.
                    Ok(TunnelFrame::Resize { cols, rows }) => { let _ = resize(cols, rows); }
                    Ok(TunnelFrame::Window(_)) => {} // credit ack; await-based backpressure governs
                    Ok(TunnelFrame::Close) | Err(DataTunnelError::Closed(_)) => {
                        let _ = writer.shutdown().await;
                        return Ok(());
                    }
                    Ok(_) => return Err(DataTunnelError::InvalidFrame("unexpected frame in stream".into())),
                    Err(other) => return Err(other),
                }
            }
            // target → tunnel
            read = reader.read(&mut rbuf) => {
                match read {
                    Ok(n) if n > 0 => {
                        send_frame(&mut tunnel_w, &TunnelFrame::Data(rbuf[..n].to_vec())).await?;
                    }
                    // End of the target's output: either a clean EOF (`Ok(0)`,
                    // e.g. a closed socket or macOS PTY) OR a read error — on
                    // Linux a PTY master returns `EIO` when the child exits
                    // rather than EOF, so both mean "the target is done".
                    // Capture the process exit status (if it has one and
                    // resolves promptly) and propagate it typed before Close.
                    _ => {
                        if let Ok(status) = tokio::time::timeout(TARGET_EXIT_GRACE, &mut exit).await {
                            let _ = send_frame(&mut tunnel_w, &TunnelFrame::Exit(status)).await;
                        }
                        let _ = send_frame(&mut tunnel_w, &TunnelFrame::Close).await;
                        return Ok(());
                    }
                }
            }
        }
    }
}

// ─── Client (used by the iOS bridge) ───────────────────────────────────────────

/// Send the auth frame and read the server's [`TunnelAck`].
pub async fn client_authenticate<S>(
    stream: &mut S,
    credential_cbor: &[u8],
    token: SessionAuthToken,
) -> Result<TunnelAck, DataTunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client_authenticate_traced(stream, credential_cbor, token, |_| {}).await
}

/// Send the auth frame and read the server's [`TunnelAck`], reporting
/// byte-level progress to the caller without exposing credential/token bytes.
pub async fn client_authenticate_traced<S, F>(
    stream: &mut S,
    credential_cbor: &[u8],
    token: SessionAuthToken,
    mut trace: F,
) -> Result<TunnelAck, DataTunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(&str),
{
    let envelope = AuthEnvelope {
        credential_cbor: credential_cbor.to_vec(),
        token,
    };
    let bytes =
        cbor::to_canonical_vec(&envelope).map_err(|e| DataTunnelError::Cbor(e.to_string()))?;
    trace(&format!("auth_frame_write_start bytes={}", bytes.len()));
    write_frame(stream, &bytes).await?;
    trace(&format!("auth_frame_write_ok bytes={}", bytes.len()));
    trace("ack_read_start");
    let ack_bytes = read_frame(stream, "ack").await?;
    trace(&format!("ack_read_ok bytes={}", ack_bytes.len()));
    cbor::from_canonical_slice(&ack_bytes).map_err(|e| DataTunnelError::Cbor(e.to_string()))
}

/// Write one typed frame (full stream or write half).
pub async fn send_frame<W>(w: &mut W, frame: &TunnelFrame) -> Result<(), DataTunnelError>
where
    W: AsyncWrite + Unpin,
{
    write_frame(w, &frame.encode()).await
}

/// Read one typed frame (full stream or read half).
pub async fn recv_frame<R>(r: &mut R) -> Result<TunnelFrame, DataTunnelError>
where
    R: AsyncRead + Unpin,
{
    TunnelFrame::decode(&read_frame(r, "frame").await?)
}

/// Health probe round-trip; returns the echoed bytes.
pub async fn client_health<S>(stream: &mut S, probe: &[u8]) -> Result<Vec<u8>, DataTunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_frame(stream, &TunnelFrame::Health(probe.to_vec())).await?;
    match recv_frame(stream).await? {
        TunnelFrame::Health(echo) => Ok(echo),
        _ => Err(DataTunnelError::InvalidFrame("expected health echo".into())),
    }
}

/// Open the persistent stream: send `Open`, await the engine's `Open` ack
/// (or a typed `Error` if the target is unreachable).
pub async fn client_open_stream<S>(stream: &mut S) -> Result<(), DataTunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_frame(stream, &TunnelFrame::Open).await?;
    match recv_frame(stream).await? {
        TunnelFrame::Open => Ok(()),
        TunnelFrame::Error(reason) => Err(DataTunnelError::TargetUnavailable(reason)),
        _ => Err(DataTunnelError::InvalidFrame("expected open ack".into())),
    }
}

/// Send a terminal resize to the engine (applied to the target PTY). Pure
/// write — the engine does not ack a resize.
pub async fn client_resize<W>(w: &mut W, cols: u16, rows: u16) -> Result<(), DataTunnelError>
where
    W: AsyncWrite + Unpin,
{
    send_frame(w, &TunnelFrame::Resize { cols, rows }).await
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claw_share::{SLOT_ID_LEN, SlotId, SlotRecord};
    use crate::ids::derive_household_id;
    use crate::keys::{IdentityKey, P256Keypair};
    use crate::person_cert::derive_person_id;
    use tokio::net::{TcpListener, TcpStream};

    const ISSUED: u64 = 1_800_000_000;
    const EXPIRES: u64 = 1_800_086_400; // 24h
    const NOW: u64 = 1_800_000_002;
    const SLOT: SlotId = SlotId([0x22u8; SLOT_ID_LEN]);

    fn owner() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
    }
    fn guest() -> P256Keypair {
        P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap()
    }

    /// Owner-signed credential for `(claw_id, guest_device_pub)`.
    fn credential(claw_id: &str, guest_pub: crate::keys::P256PublicKey) -> GuestCredential {
        let owner_key = owner();
        let owner_pub = owner_key.public();
        let hh_id = derive_household_id(&owner_pub);
        let owner_p_id = derive_person_id(&owner_pub);
        GuestCredential::sign(
            hh_id,
            owner_p_id,
            owner_pub,
            claw_id.to_string(),
            guest_pub,
            SLOT,
            ISSUED,
            EXPIRES,
            &owner_key,
        )
        .expect("sign credential")
    }

    fn engine_hh() -> HouseholdId {
        derive_household_id(&owner().public())
    }

    #[test]
    fn guest_credential_data_tunnel_session_delegates_byte_identical() {
        // Device byte-identity guard (Fase E2.5 serve-core generalization): the
        // DataTunnelSession impl for GuestCredential MUST delegate VERBATIM to the
        // existing slot-derived helpers, so a Device TunnelAck's session_id +
        // mesh_ipv6 are byte-identical before/after generalizing the serve core
        // over the trait. The trait method == the free function, and the exact
        // bytes for SLOT = [0x22;16] are pinned so any drift on either path fails.
        let cred = credential("claw_test", guest().public());
        assert_eq!(cred.session_id(), derive_session_id(&cred));
        assert_eq!(cred.mesh_ipv6(), derive_mesh_ipv6(&cred));
        assert_eq!(cred.session_id(), "22222222222222222222222222222222");
        assert_eq!(cred.mesh_ipv6(), "fd00:c1aw::2222:2222");
    }

    /// Slot store with `SLOT` open then consumed by `guest`, for `claw_test`.
    fn consumed_store(claw_id: &str) -> ClawShareSlotStore {
        let store = ClawShareSlotStore::new();
        store
            .insert(SlotRecord {
                slot_id: SLOT,
                claw_id: claw_id.to_string(),
                expires_at: EXPIRES,
                state: SlotState::Open,
            })
            .unwrap();
        store
            .consume_atomic(&SLOT, claw_id, guest().public(), ISSUED + 1)
            .unwrap();
        store
    }

    #[test]
    fn accepts_valid_credential() {
        let store = consumed_store("claw_test");
        assert!(
            authorize_credential(
                &credential("claw_test", guest().public()),
                &engine_hh(),
                &store,
                NOW
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_expired_credential() {
        let store = consumed_store("claw_test");
        let err = authorize_credential(
            &credential("claw_test", guest().public()),
            &engine_hh(),
            &store,
            EXPIRES + 1,
        )
        .unwrap_err();
        assert!(
            matches!(err, DataTunnelError::Rejected(_)),
            "expired must be rejected: {err:?}"
        );
    }

    #[test]
    fn rejects_revoked_slot() {
        let store = consumed_store("claw_test");
        store.revoke(&SLOT, NOW).unwrap();
        let err = authorize_credential(
            &credential("claw_test", guest().public()),
            &engine_hh(),
            &store,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, DataTunnelError::Rejected("slot-revoked".into()));
    }

    #[test]
    fn rejects_wrong_claw() {
        // Slot is for `claw_test`; the credential names a different claw.
        let store = consumed_store("claw_test");
        let err = authorize_credential(
            &credential("claw_evil", guest().public()),
            &engine_hh(),
            &store,
            NOW,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DataTunnelError::Rejected("claw-binding-mismatch".into())
        );
    }

    #[test]
    fn rejects_wrong_household() {
        let store = consumed_store("claw_test");
        let other_hh = derive_household_id(
            &P256Keypair::from_secret_scalar(&[0x77; 32])
                .unwrap()
                .public(),
        );
        let err = authorize_credential(
            &credential("claw_test", guest().public()),
            &other_hh,
            &store,
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, DataTunnelError::Rejected("household-mismatch".into()));
    }

    #[test]
    fn rejects_other_device_credential_for_consumed_slot() {
        // Slot consumed by `guest`; a credential for a DIFFERENT device key.
        let store = consumed_store("claw_test");
        let other_device = P256Keypair::from_secret_scalar(&[0x44; 32])
            .unwrap()
            .public();
        let err = authorize_credential(
            &credential("claw_test", other_device),
            &engine_hh(),
            &store,
            NOW,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DataTunnelError::Rejected("guest-device-mismatch".into())
        );
    }

    // ─── Proof-of-possession (unit) ──────────────────────────────────────

    use std::sync::Arc;

    fn token_full(
        cred_cbor: &[u8],
        signer: &P256Keypair,
        target_id: &str,
        nonce: &[u8],
    ) -> SessionAuthToken {
        SessionAuthToken::sign(
            "sess-test".into(),
            cred_cbor,
            "127.0.0.1:7423".into(),
            target_id.into(),
            nonce.to_vec(),
            NOW + 60,
            signer,
        )
        .expect("sign token")
    }

    fn cred_cbor() -> Vec<u8> {
        cbor::to_canonical_vec(&credential("claw_test", guest().public())).unwrap()
    }

    fn valid_token(nonce: &[u8]) -> SessionAuthToken {
        token_full(&cred_cbor(), &guest(), "claw_test", nonce)
    }

    fn envelope_with(token: SessionAuthToken) -> AuthEnvelope {
        AuthEnvelope {
            credential_cbor: cred_cbor(),
            token,
        }
    }

    #[test]
    fn session_accepts_valid_credential_and_token() {
        let store = consumed_store("claw_test");
        let env = envelope_with(valid_token(b"n1"));
        assert!(authorize_session(&env, &engine_hh(), &store, &ReplayGuard::new(), NOW).is_ok());
    }

    #[test]
    fn stolen_credential_with_token_from_other_device_is_rejected() {
        let store = consumed_store("claw_test");
        let attacker = P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap();
        let env = envelope_with(token_full(&cred_cbor(), &attacker, "claw_test", b"n1"));
        let err =
            authorize_session(&env, &engine_hh(), &store, &ReplayGuard::new(), NOW).unwrap_err();
        assert_eq!(
            err,
            DataTunnelError::TokenRejected("signature-invalid".into())
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        let store = consumed_store("claw_test");
        let token = SessionAuthToken::sign(
            "s".into(),
            &cred_cbor(),
            "e".into(),
            "claw_test".into(),
            b"n1".to_vec(),
            NOW - 1,
            &guest(),
        )
        .unwrap();
        let err = authorize_session(
            &envelope_with(token),
            &engine_hh(),
            &store,
            &ReplayGuard::new(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, DataTunnelError::TokenRejected("token-expired".into()));
    }

    #[test]
    fn token_for_other_target_is_rejected() {
        // Token minted for a different claw — must not open this one.
        let store = consumed_store("claw_test");
        let token = token_full(&cred_cbor(), &guest(), "claw_other", b"n1");
        let err = authorize_session(
            &envelope_with(token),
            &engine_hh(),
            &store,
            &ReplayGuard::new(),
            NOW,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DataTunnelError::TokenRejected("target-mismatch".into())
        );
    }

    #[test]
    fn replayed_token_is_rejected() {
        let store = consumed_store("claw_test");
        let guard = ReplayGuard::new();
        let env = envelope_with(valid_token(b"once"));
        assert!(authorize_session(&env, &engine_hh(), &store, &guard, NOW).is_ok());
        // Same nonce again → replay.
        let err = authorize_session(&env, &engine_hh(), &store, &guard, NOW).unwrap_err();
        assert_eq!(err, DataTunnelError::TokenRejected("token-replayed".into()));
    }

    #[test]
    fn session_rejects_revoked_even_with_valid_token() {
        let store = consumed_store("claw_test");
        store.revoke(&SLOT, NOW).unwrap();
        let env = envelope_with(valid_token(b"n1"));
        let err =
            authorize_session(&env, &engine_hh(), &store, &ReplayGuard::new(), NOW).unwrap_err();
        assert_eq!(err, DataTunnelError::Rejected("slot-revoked".into()));
    }

    // ─── Persistent stream (wire) ────────────────────────────────────────

    /// A fake interactive target: on connect it sends a banner, then for
    /// every line it receives it replies `ACK:<line>`. Proves a PERSISTENT
    /// bidirectional stream (unsolicited banner + multiple request/replies
    /// on the same connection).
    async fn spawn_banner_target() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut sock, _) = target.accept().await.unwrap();
            sock.write_all(b"FAKE-SSH-BANNER").await.unwrap();
            let mut buf = vec![0u8; 1024];
            loop {
                let n = match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut reply = b"ACK:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                if sock.write_all(&reply).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    fn spawn_engine(
        store: Arc<ClawShareSlotStore>,
        target_addr: String,
        guard: Arc<ReplayGuard>,
    ) -> std::net::SocketAddr {
        let hh = engine_hh();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = TcpListener::from_std(listener).unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let router = TcpStreamRouter::new(target_addr);
            let rev_store = store.clone();
            let _ = serve_connection(
                sock,
                NOW,
                move |e, n| authorize_session(e, &hh, &store, &guard, n),
                &router,
                move |cred| {
                    matches!(
                        rev_store.get(&cred.slot_id).map(|r| r.state),
                        Some(SlotState::Revoked { .. })
                    )
                },
            )
            .await;
        });
        addr
    }

    async fn serve_with_short_auth_deadline<S>(
        stream: S,
        deadline: Duration,
    ) -> Result<(), DataTunnelError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let store = Arc::new(consumed_store("claw_test"));
        let hh = engine_hh();
        let guard = Arc::new(ReplayGuard::new());
        let router = TcpStreamRouter::new("127.0.0.1:1");
        let rev_store = Arc::clone(&store);
        serve_connection_io_with_auth_deadline(
            stream,
            NOW,
            move |e, n| authorize_session(e, &hh, &store, &guard, n),
            &router,
            move |cred| {
                matches!(
                    rev_store.get(&cred.slot_id).map(|r| r.state),
                    Some(SlotState::Revoked { .. })
                )
            },
            deadline,
        )
        .await
    }

    #[tokio::test]
    async fn auth_deadline_times_out_when_peer_sends_no_auth() {
        let (server, _client) = tokio::io::duplex(64);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            serve_with_short_auth_deadline(server, std::time::Duration::from_millis(50)),
        )
        .await
        .unwrap();

        assert_eq!(result.unwrap_err(), DataTunnelError::AuthTimeout);
    }

    #[tokio::test]
    async fn auth_deadline_does_not_reset_for_partial_auth_frame() {
        let (server, mut client) = tokio::io::duplex(64);
        let server_task = tokio::spawn(serve_with_short_auth_deadline(
            server,
            std::time::Duration::from_millis(50),
        ));

        client.write_all(&[0x00, 0x00]).await.unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.unwrap_err(), DataTunnelError::AuthTimeout);
    }

    #[tokio::test]
    async fn persistent_stream_carries_multiple_frames_both_ways() {
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_engine(
            store,
            spawn_banner_target().await,
            Arc::new(ReplayGuard::new()),
        );

        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert!(matches!(
            client_authenticate(&mut client, &cbor, valid_token(b"n1"))
                .await
                .unwrap(),
            TunnelAck::Ok { .. }
        ));
        assert_eq!(
            client_health(&mut client, HEALTH_PROBE).await.unwrap(),
            HEALTH_PROBE
        );

        // Open the persistent stream; the target's banner arrives first.
        client_open_stream(&mut client).await.unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"FAKE-SSH-BANNER".to_vec())
        );

        // Multiple request/replies on the SAME session — persistent.
        for line in [
            b"ls\n".as_slice(),
            b"pwd\n".as_slice(),
            b"whoami\n".as_slice(),
        ] {
            send_frame(&mut client, &TunnelFrame::Data(line.to_vec()))
                .await
                .unwrap();
            let mut expected = b"ACK:".to_vec();
            expected.extend_from_slice(line);
            assert_eq!(
                recv_frame(&mut client).await.unwrap(),
                TunnelFrame::Data(expected)
            );
        }

        send_frame(&mut client, &TunnelFrame::Close).await.unwrap();
    }

    #[tokio::test]
    async fn target_close_propagates_to_client() {
        use tokio::io::AsyncWriteExt;
        // Target sends a banner then closes immediately.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut sock, _) = target.accept().await.unwrap();
            sock.write_all(b"BYE").await.unwrap();
            drop(sock); // close
        });

        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_engine(store, target_addr, Arc::new(ReplayGuard::new()));
        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(&mut client, &cbor, valid_token(b"n1"))
            .await
            .unwrap();
        client_open_stream(&mut client).await.unwrap();

        // Banner, then Close.
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"BYE".to_vec())
        );
        assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);
    }

    #[tokio::test]
    async fn revoking_slot_mid_session_blocks_next_frame() {
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_engine(
            store.clone(),
            spawn_banner_target().await,
            Arc::new(ReplayGuard::new()),
        );

        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(&mut client, &cbor, valid_token(b"n1"))
            .await
            .unwrap();
        client_open_stream(&mut client).await.unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"FAKE-SSH-BANNER".to_vec())
        );

        // Revoke mid-session; the next data frame must be blocked + the
        // session torn down (client sees EOF/close).
        store.revoke(&SLOT, NOW).unwrap();
        send_frame(&mut client, &TunnelFrame::Data(b"ls\n".to_vec()))
            .await
            .unwrap();
        // The engine stops forwarding and drops the session → the client's
        // next read sees the closed tunnel.
        let after = recv_frame(&mut client).await;
        assert!(
            after.is_err(),
            "session must be torn down after revocation, got {after:?}"
        );
    }

    #[tokio::test]
    async fn revoking_idle_session_tears_down_without_client_traffic() {
        // The cold-5G idle revocation gate: an interactive session that is
        // simply QUIET (no inbound Data frames — the iPhone bridge only emits a
        // no-op Window keepalive) must STILL be cut promptly when the slot is
        // revoked. Before the revoke-poll branch, is_revoked was only consulted
        // on inbound Data, so an idle session lingered until the next keystroke.
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_engine(
            store.clone(),
            spawn_banner_target().await,
            Arc::new(ReplayGuard::new()),
        );

        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(&mut client, &cbor, valid_token(b"n1"))
            .await
            .unwrap();
        client_open_stream(&mut client).await.unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"FAKE-SSH-BANNER".to_vec())
        );

        // Revoke, then send NOTHING. The idle revocation poll must tear the
        // session down on its own — and within the <2s SLA — not wait for a
        // client frame. The client's next read must see the closed tunnel.
        store.revoke(&SLOT, NOW).unwrap();
        match tokio::time::timeout(std::time::Duration::from_secs(2), recv_frame(&mut client)).await
        {
            Ok(res) => assert!(
                res.is_err(),
                "idle session must be torn down after revoke, got {res:?}"
            ),
            Err(_) => {
                panic!("idle session NOT torn down within 2s of revoke (idle-revoke <2s gate)")
            }
        }
    }

    #[tokio::test]
    async fn replayed_token_rejected_over_the_wire() {
        let guard = Arc::new(ReplayGuard::new());
        let store = Arc::new(consumed_store("claw_test"));
        let cbor = cred_cbor();

        // First connection with nonce "once" succeeds.
        let addr1 = spawn_engine(store.clone(), spawn_banner_target().await, guard.clone());
        let mut c1 = TcpStream::connect(addr1).await.unwrap();
        assert!(matches!(
            client_authenticate(&mut c1, &cbor, valid_token(b"once"))
                .await
                .unwrap(),
            TunnelAck::Ok { .. }
        ));

        // Second connection reusing the SAME token nonce → rejected.
        let addr2 = spawn_engine(store, spawn_banner_target().await, guard);
        let mut c2 = TcpStream::connect(addr2).await.unwrap();
        match client_authenticate(&mut c2, &cbor, valid_token(b"once"))
            .await
            .unwrap()
        {
            TunnelAck::Rejected { reason } => assert_eq!(reason, "token-replayed"),
            other => panic!("replayed token must be rejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_frame_before_open_tears_down_session() {
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_engine(
            store,
            spawn_banner_target().await,
            Arc::new(ReplayGuard::new()),
        );
        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert!(matches!(
            client_authenticate(&mut client, &cbor, valid_token(b"n1"))
                .await
                .unwrap(),
            TunnelAck::Ok { .. }
        ));
        // Unknown frame kind before opening the stream.
        write_frame(&mut client, &[0xFF, 0x01]).await.unwrap();
        let after = recv_frame(&mut client).await;
        assert!(after.is_err(), "unknown frame must tear down the session");
    }

    #[tokio::test]
    async fn revoked_at_auth_is_rejected_over_the_wire() {
        let store = Arc::new(consumed_store("claw_test"));
        store.revoke(&SLOT, NOW).unwrap();
        let addr = spawn_engine(
            store,
            spawn_banner_target().await,
            Arc::new(ReplayGuard::new()),
        );
        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        match client_authenticate(&mut client, &cbor, valid_token(b"n1"))
            .await
            .unwrap()
        {
            TunnelAck::Rejected { reason } => assert_eq!(reason, "slot-revoked"),
            other => panic!("revoked slot must be rejected at auth, got {other:?}"),
        }
    }

    // ─── Interactive frames (resize / exit) ──────────────────────────────

    #[test]
    fn resize_frame_round_trips() {
        let f = TunnelFrame::Resize {
            cols: 120,
            rows: 40,
        };
        assert_eq!(TunnelFrame::decode(&f.encode()).unwrap(), f);
        // Boundary values.
        let f0 = TunnelFrame::Resize { cols: 0, rows: 0 };
        assert_eq!(TunnelFrame::decode(&f0.encode()).unwrap(), f0);
        let fmax = TunnelFrame::Resize {
            cols: u16::MAX,
            rows: u16::MAX,
        };
        assert_eq!(TunnelFrame::decode(&fmax.encode()).unwrap(), fmax);
    }

    #[test]
    fn exit_frame_round_trips_all_variants() {
        for status in [
            TargetExit::Code(0),
            TargetExit::Code(127),
            TargetExit::Code(-1),
            TargetExit::Signal(9),
            TargetExit::Lost,
        ] {
            let f = TunnelFrame::Exit(status);
            assert_eq!(
                TunnelFrame::decode(&f.encode()).unwrap(),
                f,
                "exit {status:?}"
            );
        }
    }

    #[test]
    fn malformed_resize_and_exit_frames_are_rejected() {
        // Resize needs exactly 4 payload bytes; Exit needs exactly 5.
        assert!(TunnelFrame::decode(&[FRAME_RESIZE, 0x01]).is_err());
        assert!(TunnelFrame::decode(&[FRAME_EXIT, 0x01, 0x00]).is_err());
        // Unknown exit tag.
        assert!(TunnelFrame::decode(&[FRAME_EXIT, 0x09, 0, 0, 0, 0]).is_err());
    }

    /// A mid-stream `Resize` is applied (no-op for a raw TCP target) and must
    /// NOT disturb the stream: data still round-trips on the same session.
    #[tokio::test]
    async fn resize_mid_stream_keeps_session_alive() {
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_engine(
            store,
            spawn_banner_target().await,
            Arc::new(ReplayGuard::new()),
        );

        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(&mut client, &cbor, valid_token(b"n1"))
            .await
            .unwrap();
        client_open_stream(&mut client).await.unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"FAKE-SSH-BANNER".to_vec())
        );

        // Resize before and after data — neither breaks the pipe.
        client_resize(&mut client, 100, 30).await.unwrap();
        send_frame(&mut client, &TunnelFrame::Data(b"ls\n".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"ACK:ls\n".to_vec())
        );
        client_resize(&mut client, 80, 24).await.unwrap();
        send_frame(&mut client, &TunnelFrame::Data(b"pwd\n".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"ACK:pwd\n".to_vec())
        );
    }
}
