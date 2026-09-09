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
use std::fmt;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cbor;
use crate::claw_share::{ClawShareSlotStore, GuestCredential, SlotState};
use crate::ids::HouseholdId;
use crate::keys::{P256PublicKey, P256Signature, verify_signature};

// The frame-size cap moved to the `tunnel-wire-rs` crate (S0): a length bound is
// mechanics. Re-exported so consumer imports are unchanged.
pub use tunnel_wire_rs::tunnel_wire::MAX_FRAME_LEN;

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
    /// The peer closed BETWEEN frames, with nothing of the next one consumed.
    /// Split out of `Closed` because the two are the same event to a reader that
    /// only has `read_exact`: it reports `UnexpectedEof` without saying how many
    /// bytes it took, so an orderly end of exchange and a stream cut mid-frame
    /// arrived indistinguishable. A caller that must not accept a truncated
    /// frame can now say so; one that treats any close as the end keeps matching
    /// both.
    #[error("connection closed at a {0} boundary")]
    ClosedAtFrameBoundary(&'static str),
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

// `MeshIpv4` is neutral (S0): `addr` / `prefix_len` / `peer` are topology, not
// identity, and its `route_scope_violation` travels with it — the design is
// explicit that extracting the wire shape without the route-scope rule would
// leave a decoder yielding settings a consumer could install as a default route.
pub use tunnel_wire_rs::tunnel_wire::{MeshIpv4, NetworkSettingsBody, RouteScopeViolation};

/// Server → client typed settings carried in a dedicated post-Open
/// [`TunnelFrame::NetworkSettings`] frame, `IpTunnel` path only. The auth
/// [`TunnelAck`] stays address-free for ALL paths; the real, pool-allocated
/// address only exists after `router.open`, so it is delivered here, after the
/// Open-ack. Consumed entirely by the client FFI before any packet pump; a
/// missing / duplicated / invalid frame fails the connection closed before any
/// interface is configured.
///
/// **This struct is product-side on purpose, and that is a correction.** An
/// earlier S0 generation moved it into the neutral module because the codec is
/// byte-identical either way. But `session_id` is stamped by the serve loop to
/// match the one in the auth ack, and the design classifies that stamping as
/// authority: *a neutral type may not carry a field whose only legitimate
/// producer is an authority.* That rule is what expelled [`TunnelAck`]; this
/// type carries the same field for the same reason. The measurement confirmed
/// it is identity in use, not transport — `claw-share-bridge-rs` compares
/// `ns.session_id != expected` as an equality check on identity.
///
/// The neutral module therefore owns the 0x17 *frame* and treats the body as
/// opaque bytes. The wire is unchanged: the body is the same canonical CBOR, and
/// the frozen vectors keep proving it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct NetworkSettings {
    pub mesh_ipv4: MeshIpv4,
    pub mtu: u16,
    pub session_id: String,
}

/// Private wire mirrors used ONLY by the 0x17 decode path.
///
/// `#[serde(deny_unknown_fields)]` is a property of the TYPE, not of a decode
/// call. Putting it on the public [`NetworkSettings`] / [`MeshIpv4`] would make
/// it a standing policy for every present and future holder of those types —
/// the T1 dev runner, the bridge and the iOS FFI all carry them — rather than a
/// rule of this one frame, and nothing at those sites would signal that the
/// rule had been inherited.
///
/// These private mirrors hold the strictness instead, so it cannot escape
/// [`decode_network_settings_body`]. Field names and types match the public
/// structs exactly, so the two encode to identical canonical bytes and the
/// strict re-encode comparison means the same thing for both.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictMeshIpv4Wire {
    addr: String,
    prefix_len: u8,
    peer: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictNetworkSettingsWire {
    mesh_ipv4: StrictMeshIpv4Wire,
    mtu: u16,
    session_id: String,
}

impl From<StrictNetworkSettingsWire> for NetworkSettings {
    fn from(wire: StrictNetworkSettingsWire) -> Self {
        Self {
            mesh_ipv4: MeshIpv4 {
                addr: wire.mesh_ipv4.addr,
                prefix_len: wire.mesh_ipv4.prefix_len,
                peer: wire.mesh_ipv4.peer,
            },
            mtu: wire.mtu,
            session_id: wire.session_id,
        }
    }
}

impl fmt::Debug for NetworkSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkSettings")
            .field("mesh_ipv4", &self.mesh_ipv4)
            .field("mtu", &self.mtu)
            .field("session_id", &"<redacted>")
            .finish()
    }
}

/// Canonical CBOR body for a 0x17 frame.
///
/// A CBOR encode failure of this small struct is effectively impossible; on
/// failure the empty body decodes to `InvalidFrame` and the connection fails
/// closed, with no interface configured — the same fail-closed outcome the
/// pre-extraction encoder had.
#[must_use]
pub fn encode_network_settings_body(settings: &NetworkSettings) -> NetworkSettingsBody {
    // Byte-for-byte the pre-extraction expression: the fallback is the EMPTY
    // body, exactly as `to_canonical_vec(..).unwrap_or_default()` produced.
    NetworkSettingsBody::encode_canonical_or_empty(settings)
}

/// Strictly decode a 0x17 body.
///
/// This body configures a VPN interface and is consumed before any packet pump,
/// so only the exact canonical encoding is admitted: non-canonical key order, an
/// unmodelled key, or trailing bytes fail the connection closed before any
/// interface exists. Every other frame kind keeps the lenient decoder.
///
/// This is the product's path, and it is fully strict: an unmodelled key, a
/// non-canonical key order or trailing bytes all fail here, before any interface
/// exists.
///
/// **It is NOT the only way to read a body, and an earlier revision of this
/// comment said it was.** [`NetworkSettingsBody::decode_strict`] is generic in a
/// caller-chosen type, and a structurally universal one — `ciborium::value::Value`
/// satisfies its bounds — recovers the content, including for a body this
/// function would reject, because an unmodelled key survives into `Value` and so
/// the canonical re-encode still matches. What survives for every caller is
/// canonicity; what does not survive is "only this decoder can read one".
///
/// Stated plainly because a comment asserting an unbypassable property that is
/// bypassable is worse than no comment: the next reader builds on it. The
/// structural fix is filed as its own slice — Rust has no negative trait bound,
/// and a sealed one would exclude this crate's own types too.
pub fn decode_network_settings_body(
    body: &NetworkSettingsBody,
) -> Result<NetworkSettings, DataTunnelError> {
    Ok(body
        .decode_strict::<StrictNetworkSettingsWire>()
        .map_err(|_| DataTunnelError::InvalidFrame("bad network_settings frame".into()))?
        .into())
}

// ─── Typed data frames (post-auth) ─────────────────────────────────────────────

// Frame opcodes and the typed exit status moved to the `tunnel-wire-rs` crate
// (S0): they are wire bytes and carry no decision. Re-exported so consumer
// imports are unchanged.
pub use tunnel_wire_rs::tunnel_wire::{
    FRAME_CLOSE, FRAME_DATA, FRAME_ERROR, FRAME_EXIT, FRAME_HEALTH, FRAME_NETWORK_SETTINGS,
    FRAME_OPEN, FRAME_OPEN_PERSISTENT, FRAME_RESIZE, FRAME_WINDOW, TargetExit,
};

// The frame codec itself moved to the `tunnel-wire-rs` crate (S0), redaction included
// — a neutral codec that printed payloads would be a new leak, not a neutral
// move. `TunnelFrame::decode` now yields the transport-only `WireError`; the
// `From` impl below lets every existing `?` site keep working unchanged, which
// is why 156 error sites across 14 files did not have to be touched.
pub use tunnel_wire_rs::tunnel_wire::{TunnelFrame, WireError};

/// Aggregate safety budget for sequential target streams inside one
/// authenticated connection. The relay remains opaque and cannot count HTTP
/// requests, so the endpoint owns this authorization/resource boundary.
pub const PERSISTENT_MAX_TARGET_OPENS: u32 = 128;
pub const PERSISTENT_MAX_BYTES_PER_DIRECTION: u64 = 64 * 1024 * 1024;

/// Widen a transport failure into this product's error.
///
/// The mechanic/authority line runs *inside* the old enum, not around it: the
/// neutral module owns the framing/I-O arms, and the four authorization arms
/// (`AuthTimeout`, `Rejected`, `TokenRejected`, `HealthMismatch`) stay here.
/// Conversion — not a type parameter and not an open payload variant — is what
/// joins them, so neither side gains a caller-chosen position.
impl From<WireError> for DataTunnelError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Io(m) => Self::Io(m),
            WireError::FrameTooLarge(n) => Self::FrameTooLarge(n),
            WireError::Closed(w) => Self::Closed(w),
            WireError::Cbor(m) => Self::Cbor(m),
            WireError::UnexpectedAck => Self::UnexpectedAck,
            WireError::InvalidFrame(m) => Self::InvalidFrame(m),
            WireError::TargetUnavailable(m) => Self::TargetUnavailable(m),
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
    // The first byte is taken alone, and not because the prefix wants reading in
    // pieces. `read_exact` reports a shortfall as `UnexpectedEof` without saying
    // how much it consumed, so a peer that closed cleanly between frames and one
    // that cut a frame in half both landed on `Closed(what)` and read the same.
    // `Ok(0)` on a single-byte read is EOF with nothing consumed -- a frame
    // boundary, and the only case that earns the softer variant. A partial
    // prefix, or an EOF inside the body below, stays `Closed` and stays fatal.
    if r.read(&mut len_buf[..1])
        .await
        .map_err(|_| DataTunnelError::Closed(what))?
        == 0
    {
        return Err(DataTunnelError::ClosedAtFrameBoundary(what));
    }
    r.read_exact(&mut len_buf[1..])
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

    /// Whether this authorized session may reuse its authenticated Noise
    /// connection for sequential target streams.
    ///
    /// This is denied by default. The first product cut enables it only for a
    /// relay-stream offer whose signed resource is `ClawSite`; direct Device
    /// credentials, PTY, and `IpTunnel` retain the legacy single-target shape.
    fn allows_persistent_targets(&self) -> bool {
        false
    }
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

/// One opened target stream the engine pipes inside an authenticated session.
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
    /// `IpTunnel` path only: the guest's real, pool-allocated VPN IPv4 address.
    /// When `Some`, the serve loop assembles a [`NetworkSettings`] (stamping the
    /// SAME `session_id` it put in the auth [`TunnelAck`], plus the shared MTU)
    /// and delivers it in a [`TunnelFrame::NetworkSettings`] frame right after
    /// the Open-ack. `None` for PTY/ClawSite/Device (no VPN interface, no frame).
    pub vpn_mesh_ipv4: Option<MeshIpv4>,
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
            vpn_mesh_ipv4: None,
        }
    }

    /// Attach the guest's real pool-allocated VPN IPv4 address (`IpTunnel` path).
    /// The serve loop turns it into a [`NetworkSettings`] frame immediately after
    /// the Open-ack; every other path leaves this `None` and sends no such frame.
    #[must_use]
    pub fn with_vpn_mesh_ipv4(mut self, mesh_ipv4: MeshIpv4) -> Self {
        self.vpn_mesh_ipv4 = Some(mesh_ipv4);
        self
    }
}

/// Opens one target stream. Legacy sessions call this once; an explicitly
/// authorized persistent `ClawSite` session may call it again sequentially after
/// the previous target closes. The engine pipes bytes both ways (plus resize /
/// exit) until that target closes.
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
/// answer health probes, then either open one legacy target with `Open`, or a
/// bounded sequence of `ClawSite` targets with `OpenPersistent`. Each target is
/// piped bidirectionally until close/EOF/error; only the explicit persistent
/// mode returns to the authenticated pre-target loop.
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

    let mut persistent_negotiated = false;
    let mut persistent_target_opens = 0_u32;
    let mut persistent_bytes_to_target = 0_u64;
    let mut persistent_bytes_from_target = 0_u64;

    // 2. One authenticated connection may carry either the legacy single
    // target stream (`Open`) or a sequence of target streams
    // (`OpenPersistent`). Persistent streams are strictly sequential: this
    // loop does not accept the next Open until the current target has closed.
    loop {
        let persistent = loop {
            match recv_frame(&mut tunnel_r).await {
                Ok(TunnelFrame::Health(p)) => {
                    tracing::debug!(
                        stage = "claw_share.data_tunnel.health_received",
                        len = p.len()
                    );
                    send_frame(&mut tunnel_w, &TunnelFrame::Health(p)).await?;
                    tracing::debug!(stage = "claw_share.data_tunnel.health_echo_sent");
                }
                Ok(TunnelFrame::Open) if !persistent_negotiated => {
                    tracing::debug!(stage = "claw_share.data_tunnel.open_received", target_id = %short_str(&target_id), persistent = false);
                    break false;
                }
                Ok(TunnelFrame::OpenPersistent) => {
                    if !cred.allows_persistent_targets() {
                        let _ = send_frame(
                            &mut tunnel_w,
                            &TunnelFrame::Error("persistent-target-not-authorized".into()),
                        )
                        .await;
                        return Err(DataTunnelError::TargetUnavailable(
                            "persistent-target-not-authorized".into(),
                        ));
                    }
                    persistent_negotiated = true;
                    persistent_target_opens = persistent_target_opens.saturating_add(1);
                    if persistent_target_opens > PERSISTENT_MAX_TARGET_OPENS {
                        let _ = send_frame(
                            &mut tunnel_w,
                            &TunnelFrame::Error("session-open-budget-exhausted".into()),
                        )
                        .await;
                        return Err(DataTunnelError::TargetUnavailable(
                            "session-open-budget-exhausted".into(),
                        ));
                    }
                    tracing::debug!(stage = "claw_share.data_tunnel.open_received", target_id = %short_str(&target_id), persistent = true, target_open = persistent_target_opens);
                    break true;
                }
                Ok(TunnelFrame::Open) => {
                    return Err(DataTunnelError::InvalidFrame(
                        "legacy open is forbidden after persistent mode".into(),
                    ));
                }
                // A persistent target can close from either side. If the
                // target reached EOF just before the client sent its own
                // Close, the server has already emitted the authoritative
                // Close notification and returned here; the client's Close
                // is then an exact retry racing that notification. Treat it
                // as an idempotent no-op. Do NOT emit a second Close ack: the
                // original target-close notification is already ordered on
                // the wire, and a duplicate ack would be mistaken for the
                // next target's lifecycle frame.
                Ok(TunnelFrame::Close) if persistent_negotiated => {
                    tracing::debug!(
                        stage = "claw_share.data_tunnel.persistent_close_retry_ignored",
                        target_id = %short_str(&target_id),
                    );
                }
                Ok(frame) => {
                    tracing::debug!(stage = "claw_share.data_tunnel.pre_stream_unexpected", frame = ?frame);
                    return Err(DataTunnelError::InvalidFrame(
                        "expected health or open before stream".into(),
                    ));
                }
                // Both closes end the connection here: a client that goes away
                // before opening a stream has nothing to hand over either way.
                Err(DataTunnelError::Closed(_) | DataTunnelError::ClosedAtFrameBoundary(_)) => {
                    return Ok(());
                }
                Err(other) => return Err(other),
            }
        };

        // 3. Open one target stream.
        //
        // Fence: re-check revocation AFTER Open and BEFORE `router.open`. The client
        // may sit in the Health loop indefinitely, so authorization can lapse in
        // that window — and until now the first `is_revoked` call happened only on
        // the per-`Data` path, i.e. AFTER the target was opened and the Open-ack
        // (and any `NetworkSettings`) had already been sent. For the Group/Public
        // audience this predicate is the FULL live gate, so it also covers a wall
        // clock that became unusable mid-wait. Same static deny as elsewhere; no
        // new frame, kind, codec, or callback.
        if is_revoked(&cred) {
            tracing::debug!(
                stage = "claw_share.data_tunnel.revoked_before_open",
                target_id = %short_str(&target_id),
            );
            return Err(DataTunnelError::TargetUnavailable("revoked".into()));
        }

        let TargetSession {
            mut reader,
            mut writer,
            resize,
            mut exit,
            vpn_mesh_ipv4,
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

        // IpTunnel path only: deliver the real, pool-allocated VPN interface settings
        // in a typed frame IMMEDIATELY after the Open-ack.
        //
        // RATCHET (inert -> live): this is the point at which a real, routable IPv4
        // address first reaches the client. The allocation only exists after
        // `router.open` (§step 3), which is exactly why it cannot ride the auth
        // `TunnelAck` — that ack stays address-free for ALL paths. PTY/ClawSite/Device
        // leave `network_settings` = None and send no such frame (unchanged). A send
        // failure here just closes the connection: fail-closed, no interface set.
        if let Some(mesh_ipv4) = vpn_mesh_ipv4 {
            // Stamp the SAME session_id we put in the auth TunnelAck (cred.session_id()).
            // The client stored the ack's session_id and fail-closes if this differs —
            // an explicit cross-phase binding beyond the Noise channel. mtu matches the
            // ack's, and the address is the real pool allocation (route-scope validated
            // at the router before it ever reaches here).
            let settings = NetworkSettings {
                mesh_ipv4,
                mtu: 1280,
                session_id: cred.session_id(),
            };
            // The product encodes its identity-bearing body; the neutral frame
            // carries it opaque. This remains byte-identical on the wire.
            let body = encode_network_settings_body(&settings);
            send_frame(&mut tunnel_w, &TunnelFrame::NetworkSettings(body)).await?;
            tracing::debug!(stage = "claw_share.data_tunnel.network_settings_sent", target_id = %short_str(&target_id));
        }

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
        'target: loop {
            // CANCEL SAFETY (load-bearing; do not inline this back into the
            // `select!`). `recv_frame` is a sequence of awaits — the 4-byte length
            // prefix, then the body — so it is NOT cancel-safe. When
            // it was built inline as a `select!` arm it was reconstructed every
            // turn, which means every sibling win DROPPED it; if it was parked
            // between the two reads, the prefix bytes were already off the socket
            // and were lost with the future, and the next read consumed body bytes
            // as a length. That desynchronises the stream and surfaces to the peer
            // as `connection closed during frame`.
            //
            // Instead the future is built ONCE per inbound frame and pinned here,
            // then held across the inner loop. A sibling arm winning merely stops
            // polling it; the partially-read state lives in the future, which is
            // still alive, so the next turn RESUMES the same read. It is dropped
            // and rebuilt only after it has produced a value — completion, error,
            // or idle timeout. Covered by
            // `sibling_select_arm_cannot_desync_a_partially_read_frame`.
            //
            // The sibling arms are cancel-safe by construction and unaffected:
            // `interval.tick()` and `AsyncReadExt::read` both document that no
            // progress is lost when they are dropped un-polled.
            let mut inbound = std::pin::pin!(tokio::time::timeout(
                STREAM_IDLE_TIMEOUT,
                recv_frame(&mut tunnel_r)
            ));
            let inbound_result = loop {
                tokio::select! {
                    // Revocation watcher: closes an idle (or active) session promptly
                    // once the slot is revoked, independent of inbound `Data` frames.
                    _ = revoke_poll.tick() => {
                        if is_revoked(&cred) {
                            let _ = writer.shutdown().await;
                            return Err(DataTunnelError::Rejected("slot-revoked".into()));
                        }
                    }
                    // tunnel → target: resumed, never restarted, across sibling wins.
                    res = &mut inbound => break res,
                    // target → tunnel
                    read = reader.read(&mut rbuf) => {
                        match read {
                            Ok(n) if n > 0 => {
                                if persistent {
                                    persistent_bytes_from_target = persistent_bytes_from_target
                                        .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
                                    if persistent_bytes_from_target
                                        > PERSISTENT_MAX_BYTES_PER_DIRECTION
                                    {
                                        let _ = send_frame(
                                            &mut tunnel_w,
                                            &TunnelFrame::Error(
                                                "session-byte-budget-exhausted".into(),
                                            ),
                                        )
                                        .await;
                                        return Err(DataTunnelError::TargetUnavailable(
                                            "session-byte-budget-exhausted".into(),
                                        ));
                                    }
                                }
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
                                if persistent {
                                    break 'target;
                                }
                                return Ok(());
                            }
                        }
                    }
                }
            };
            let Ok(frame) = inbound_result else {
                return Err(DataTunnelError::Closed("idle-timeout"));
            };
            match frame {
                Ok(TunnelFrame::Data(d)) => {
                    if is_revoked(&cred) {
                        return Err(DataTunnelError::Rejected("slot-revoked".into()));
                    }
                    if persistent {
                        persistent_bytes_to_target = persistent_bytes_to_target
                            .saturating_add(u64::try_from(d.len()).unwrap_or(u64::MAX));
                        if persistent_bytes_to_target > PERSISTENT_MAX_BYTES_PER_DIRECTION {
                            let _ = send_frame(
                                &mut tunnel_w,
                                &TunnelFrame::Error("session-byte-budget-exhausted".into()),
                            )
                            .await;
                            return Err(DataTunnelError::TargetUnavailable(
                                "session-byte-budget-exhausted".into(),
                            ));
                        }
                    }
                    writer
                        .write_all(&d)
                        .await
                        .map_err(|e| DataTunnelError::Io(e.to_string()))?;
                    writer
                        .flush()
                        .await
                        .map_err(|e| DataTunnelError::Io(e.to_string()))?;
                }
                // Apply the client's terminal size to the target. Best
                // effort: a resize hiccup must not tear down the session.
                Ok(TunnelFrame::Resize { cols, rows }) => {
                    let _ = resize(cols, rows);
                }
                Ok(TunnelFrame::Window(_)) => {} // credit ack; await-based backpressure governs
                // Both closes end the stream here, as they did when they were one
                // variant: the client is gone, and the target gets its shutdown
                // whether the last frame arrived whole or not.
                Ok(TunnelFrame::Close)
                | Err(DataTunnelError::Closed(_) | DataTunnelError::ClosedAtFrameBoundary(_)) => {
                    let _ = writer.shutdown().await;
                    if persistent {
                        send_frame(&mut tunnel_w, &TunnelFrame::Close).await?;
                        break 'target;
                    }
                    return Ok(());
                }
                Ok(_) => {
                    return Err(DataTunnelError::InvalidFrame(
                        "unexpected frame in stream".into(),
                    ));
                }
                Err(other) => return Err(other),
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
    // `?` is what applies `From<WireError>`; a bare tail expression would not.
    Ok(TunnelFrame::decode(&read_frame(r, "frame").await?)?)
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

/// Open one target stream while retaining the authenticated connection for a
/// later sequential target. The server acknowledges with the legacy `Open`
/// frame so existing ready/error handling stays byte-identical after the new
/// request mode is selected.
pub async fn client_open_persistent_stream<S>(stream: &mut S) -> Result<(), DataTunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_frame(stream, &TunnelFrame::OpenPersistent).await?;
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
mod tests;
