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
                Err(DataTunnelError::Closed(_)) => return Ok(()),
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
            // `select!`). `recv_frame` is two sequential `read_exact` awaits — the
            // 4-byte length prefix, then the body — so it is NOT cancel-safe. When
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
                Ok(TunnelFrame::Close) | Err(DataTunnelError::Closed(_)) => {
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

    // ── S0 oracle: frozen claw wire vectors ────────────────────────────────
    //
    // These assert the wire bytes of every `TunnelFrame` variant against a
    // fixture that lives in `tests/data/`, NOT in this file. That separation is
    // the point: S0 will move this codec into a neutral module, and an oracle
    // living in the file under test would move with it and could be regenerated
    // by the very commit it is supposed to judge. The fixture lands in an
    // EARLIER commit, so its blob belongs to a prior generation and
    // `git diff --name-only <vectors-commit> <extraction-commit> -- <fixture>`
    // being empty is a fact about history rather than a promise.
    //
    // The vectors were emitted from the live encoder, not hand-written.

    fn s0_wire_vectors() -> Vec<(String, Vec<u8>)> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/s0_claw_wire_vectors_v1.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("S0 wire-vector fixture unreadable at {path:?}: {e}"));
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("fixture is JSON");
        let cases = doc["vectors"].as_array().expect("vectors array");
        assert!(!cases.is_empty(), "the fixture must not be empty");
        cases
            .iter()
            .map(|c| {
                let name = c["name"].as_str().expect("name").to_string();
                let bytes = hex_decode(c["hex"].as_str().expect("hex"));
                (name, bytes)
            })
            .collect()
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex must be even-length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// Every frozen vector must still decode, and re-encode to the SAME bytes.
    ///
    /// This is the byte-equality oracle S0 is measured against. It runs
    /// identically before and after the neutral extraction; if the move changes
    /// a single wire byte of claw behaviour, this fails.
    #[test]
    fn s0_claw_wire_vectors_round_trip_byte_identical() {
        let vectors = s0_wire_vectors();
        assert_eq!(
            vectors.len(),
            11,
            "the frozen set covers every TunnelFrame variant; losing one \
             silently narrows the oracle"
        );
        for (name, bytes) in vectors {
            let frame = TunnelFrame::decode(&bytes)
                .unwrap_or_else(|e| panic!("{name}: frozen vector no longer decodes: {e:?}"));
            let re = frame.encode();
            assert_eq!(
                re, bytes,
                "{name}: re-encoding the frozen vector produced different wire bytes"
            );
        }
    }

    /// Non-vacuity control for the oracle above.
    ///
    /// A round-trip test passes trivially if the fixture is empty, if the
    /// decoder accepts anything, or if `encode` and `decode` are inverses of
    /// each other while both drifting together. This pins the opcode byte of
    /// each vector against the `FRAME_*` constants independently of the codec,
    /// and proves the decoder rejects a corrupted vector.
    #[test]
    fn s0_wire_vector_oracle_can_actually_fail() {
        let vectors = s0_wire_vectors();
        let expected_opcode: std::collections::BTreeMap<&str, u8> = [
            ("health", FRAME_HEALTH),
            ("open", FRAME_OPEN),
            ("data", FRAME_DATA),
            ("close", FRAME_CLOSE),
            ("error", FRAME_ERROR),
            ("window", FRAME_WINDOW),
            ("resize", FRAME_RESIZE),
            ("exit_code", FRAME_EXIT),
            ("exit_signal", FRAME_EXIT),
            ("exit_lost", FRAME_EXIT),
            ("network_settings", FRAME_NETWORK_SETTINGS),
        ]
        .into_iter()
        .collect();

        for (name, bytes) in &vectors {
            let want = expected_opcode
                .get(name.as_str())
                .unwrap_or_else(|| panic!("{name}: vector not covered by the opcode control"));
            assert_eq!(
                bytes[0], *want,
                "{name}: frozen vector's opcode byte drifted from the FRAME_* constant"
            );
        }

        // The needle: a corrupted opcode must be rejected, so "it decoded" is
        // information and not a foregone conclusion.
        let mut corrupt = vectors[0].1.clone();
        corrupt[0] = 0xEE;
        assert!(
            TunnelFrame::decode(&corrupt).is_err(),
            "the decoder accepts an unknown opcode; the round-trip oracle would \
             then pass for the wrong reason"
        );
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
        assert!(
            !cred.allows_persistent_targets(),
            "Device credentials must retain the legacy single-target protocol"
        );
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
                app_presentation: None,
                created_at: None,
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

    /// A request/response target that closes each accepted TCP connection.
    /// Two accepts prove that the data-tunnel can reopen a fresh ClawSite
    /// backend without repeating rendezvous, Noise, or auth.
    async fn spawn_two_request_target() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            for index in 1..=2 {
                let (mut sock, _) = target.accept().await.unwrap();
                let mut request = vec![0_u8; 1024];
                let n = sock.read(&mut request).await.unwrap();
                assert!(n > 0, "request {index} must reach the target");
                sock.write_all(format!("response-{index}").as_bytes())
                    .await
                    .unwrap();
                sock.shutdown().await.unwrap();
            }
        });
        addr
    }

    /// Two keep-alive-style request targets. Each accepted target stays open
    /// after its response until the data-tunnel explicitly closes it. This
    /// pins the opposite lifecycle ordering from `spawn_two_request_target`:
    /// client-close first rather than target-EOF first.
    async fn spawn_two_keepalive_targets() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            for index in 1..=2 {
                let (mut sock, _) = target.accept().await.unwrap();
                let mut request = vec![0_u8; 1024];
                let n = sock.read(&mut request).await.unwrap();
                assert!(n > 0, "request {index} must reach the target");
                sock.write_all(format!("response-{index}").as_bytes())
                    .await
                    .unwrap();
                let mut drain = [0_u8; 1];
                assert_eq!(
                    sock.read(&mut drain).await.unwrap(),
                    0,
                    "target {index} must remain open until the client closes it"
                );
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

    struct PersistentTestSession(GuestCredential);

    impl DataTunnelSession for PersistentTestSession {
        fn session_id(&self) -> String {
            self.0.session_id()
        }

        fn mesh_ipv6(&self) -> String {
            self.0.mesh_ipv6()
        }

        fn allows_persistent_targets(&self) -> bool {
            true
        }
    }

    fn spawn_persistent_engine_with_router<R>(
        store: Arc<ClawShareSlotStore>,
        guard: Arc<ReplayGuard>,
        router: R,
    ) -> std::net::SocketAddr
    where
        R: ClawTargetRouter + Send + Sync + 'static,
    {
        let hh = engine_hh();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = TcpListener::from_std(listener).unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let rev_store = Arc::clone(&store);
            let _ = serve_connection_io_with_auth_deadline(
                sock,
                NOW,
                move |e, n| authorize_session(e, &hh, &store, &guard, n).map(PersistentTestSession),
                &router,
                move |session: &PersistentTestSession| {
                    matches!(
                        rev_store.get(&session.0.slot_id).map(|r| r.state),
                        Some(SlotState::Revoked { .. })
                    )
                },
                DEFAULT_AUTH_DEADLINE,
            )
            .await;
        });
        addr
    }

    fn spawn_persistent_engine(
        store: Arc<ClawShareSlotStore>,
        target_addr: String,
        guard: Arc<ReplayGuard>,
    ) -> std::net::SocketAddr {
        spawn_persistent_engine_with_router(store, guard, TcpStreamRouter::new(target_addr))
    }

    struct ImmediateCloseRouter {
        opens: Arc<std::sync::atomic::AtomicU32>,
    }

    impl ClawTargetRouter for ImmediateCloseRouter {
        async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
            self.opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (stream, peer) = tokio::io::duplex(1);
            drop(peer);
            let (reader, writer) = tokio::io::split(stream);
            Ok(TargetSession {
                reader: Box::new(reader),
                writer: Box::new(writer),
                resize: Box::new(|_, _| Ok(())),
                exit: Box::pin(std::future::ready(TargetExit::Code(0))),
                vpn_mesh_ipv4: None,
            })
        }
    }

    struct DrainRouter;

    impl ClawTargetRouter for DrainRouter {
        async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
            use tokio::io::AsyncReadExt as _;
            let (stream, mut peer) = tokio::io::duplex(MAX_FRAME_LEN * 2);
            tokio::spawn(async move {
                let mut buf = vec![0_u8; MAX_FRAME_LEN];
                while peer.read(&mut buf).await.is_ok_and(|n| n > 0) {}
            });
            Ok(TargetSession::from_stream(stream))
        }
    }

    struct FloodRouter;

    impl ClawTargetRouter for FloodRouter {
        async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
            use tokio::io::AsyncWriteExt as _;
            let (stream, mut peer) = tokio::io::duplex(STREAM_READ_CHUNK * 2);
            tokio::spawn(async move {
                let chunk = vec![0xa5; STREAM_READ_CHUNK];
                let full_chunks = PERSISTENT_MAX_BYTES_PER_DIRECTION / STREAM_READ_CHUNK as u64;
                for _ in 0..full_chunks {
                    peer.write_all(&chunk).await.unwrap();
                }
                let remainder = PERSISTENT_MAX_BYTES_PER_DIRECTION % STREAM_READ_CHUNK as u64;
                if remainder > 0 {
                    peer.write_all(&chunk[..remainder as usize]).await.unwrap();
                }
                peer.write_all(&[0xa5]).await.unwrap();
            });
            Ok(TargetSession::from_stream(stream))
        }
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
    async fn persistent_connection_reopens_two_sequential_target_streams() {
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_persistent_engine(
            store,
            spawn_two_request_target().await,
            Arc::new(ReplayGuard::new()),
        );

        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(&mut client, &cbor, valid_token(b"persistent-reopen"))
            .await
            .unwrap();

        for index in 1..=2 {
            client_open_persistent_stream(&mut client).await.unwrap();
            send_frame(
                &mut client,
                &TunnelFrame::Data(format!("request-{index}").into_bytes()),
            )
            .await
            .unwrap();
            assert_eq!(
                recv_frame(&mut client).await.unwrap(),
                TunnelFrame::Data(format!("response-{index}").into_bytes())
            );
            assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);
        }
    }

    #[tokio::test]
    async fn persistent_close_retry_after_target_race_is_idempotent_and_does_not_poison_next_open()
    {
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_persistent_engine(
            store,
            spawn_two_keepalive_targets().await,
            Arc::new(ReplayGuard::new()),
        );

        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(
            &mut client,
            &cbor,
            valid_token(b"persistent-idempotent-close"),
        )
        .await
        .unwrap();

        client_open_persistent_stream(&mut client).await.unwrap();
        send_frame(&mut client, &TunnelFrame::Data(b"request-1".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"response-1".to_vec())
        );

        // The first Close ends target 1 and produces exactly one Close ack.
        // The second models the legitimate race where the target had already
        // reached EOF and the client independently closes the same target.
        // It must be ignored in pre-stream state and must not produce a second
        // ack that could poison target 2.
        send_frame(&mut client, &TunnelFrame::Close).await.unwrap();
        send_frame(&mut client, &TunnelFrame::Close).await.unwrap();
        assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);

        client_open_persistent_stream(&mut client).await.unwrap();
        send_frame(&mut client, &TunnelFrame::Data(b"request-2".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"response-2".to_vec()),
            "a duplicate Close must not leave a stale ack ahead of target 2"
        );
        send_frame(&mut client, &TunnelFrame::Close).await.unwrap();
        assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);
    }

    #[tokio::test]
    async fn device_session_rejects_persistent_target_before_backend_open() {
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_engine(
            store,
            "127.0.0.1:1".to_string(),
            Arc::new(ReplayGuard::new()),
        );

        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(
            &mut client,
            &cred_cbor(),
            valid_token(b"device-persistent-denied"),
        )
        .await
        .unwrap();
        let denied = client_open_persistent_stream(&mut client)
            .await
            .unwrap_err();
        assert_eq!(
            denied,
            DataTunnelError::TargetUnavailable("persistent-target-not-authorized".into())
        );
    }

    #[tokio::test]
    async fn persistent_mode_rejects_legacy_open_downgrade() {
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_persistent_engine(
            store,
            spawn_two_request_target().await,
            Arc::new(ReplayGuard::new()),
        );

        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(
            &mut client,
            &cred_cbor(),
            valid_token(b"persistent-no-downgrade"),
        )
        .await
        .unwrap();
        client_open_persistent_stream(&mut client).await.unwrap();
        send_frame(&mut client, &TunnelFrame::Data(b"request-1".to_vec()))
            .await
            .unwrap();
        assert!(matches!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(_)
        ));
        assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);

        send_frame(&mut client, &TunnelFrame::Open).await.unwrap();
        assert!(
            recv_frame(&mut client).await.is_err(),
            "persistent mode must not silently downgrade to legacy Open"
        );
    }

    #[tokio::test]
    async fn persistent_open_budget_rejects_129th_before_target_allocation() {
        let store = Arc::new(consumed_store("claw_test"));
        let opens = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let addr = spawn_persistent_engine_with_router(
            store,
            Arc::new(ReplayGuard::new()),
            ImmediateCloseRouter {
                opens: Arc::clone(&opens),
            },
        );

        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(
            &mut client,
            &cred_cbor(),
            valid_token(b"persistent-open-budget"),
        )
        .await
        .unwrap();

        for index in 1..=PERSISTENT_MAX_TARGET_OPENS {
            client_open_persistent_stream(&mut client).await.unwrap();
            assert_eq!(
                recv_frame(&mut client).await.unwrap(),
                TunnelFrame::Exit(TargetExit::Code(0)),
                "target {index} must close normally"
            );
            assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);
        }

        let exhausted = client_open_persistent_stream(&mut client)
            .await
            .unwrap_err();
        assert_eq!(
            exhausted,
            DataTunnelError::TargetUnavailable("session-open-budget-exhausted".into())
        );
        assert_eq!(
            opens.load(std::sync::atomic::Ordering::SeqCst),
            PERSISTENT_MAX_TARGET_OPENS,
            "the rejected 129th open must allocate no target"
        );
    }

    #[tokio::test]
    async fn persistent_revocation_blocks_second_open_before_target_allocation() {
        // §3 baseline item 4 / §7.1: "before every new persistent target
        // open" must be a PINNED ordering property, not an accident of the
        // 500 ms revoke-poll interval. A test that only observes the client
        // eventually seeing an error cannot tell "the fence ran before
        // `router.open`" (correct) apart from "the fence ran after
        // `router.open`, but something else — the poll, or the next Data
        // check — tore the session down anyway" (a real regression that
        // would still look green). `ImmediateCloseRouter`'s open counter
        // makes the two distinguishable: if the fence ever moves after
        // `router.open`, this test goes red because `opens` reaches 2, even
        // though the client-observed outcome (rejection) looks unchanged.
        let store = Arc::new(consumed_store("claw_test"));
        let opens = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let addr = spawn_persistent_engine_with_router(
            Arc::clone(&store),
            Arc::new(ReplayGuard::new()),
            ImmediateCloseRouter {
                opens: Arc::clone(&opens),
            },
        );

        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(
            &mut client,
            &cred_cbor(),
            valid_token(b"persistent-revocation-ordering"),
        )
        .await
        .unwrap();

        // Target #1: opens and closes normally, exactly once.
        client_open_persistent_stream(&mut client).await.unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Exit(TargetExit::Code(0))
        );
        assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);
        assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Revoke between the two opens, then ask for target #2. The fence
        // returns before sending any frame (unlike a `router.open` failure,
        // which does send `TunnelFrame::Error` first) — the connection is
        // simply dropped, so the client observes EOF here, matching the
        // `is_err()`-only assertion already used by the sibling tests
        // (`revoking_during_health_wait_blocks_open_before_the_target_is_opened`
        // and the responder-level
        // `relay_stream_responder_device_clawsite_revocation_blocks_next_persistent_open`).
        store.revoke(&SLOT, NOW).unwrap();
        assert!(
            client_open_persistent_stream(&mut client).await.is_err(),
            "revocation between persistent targets must reject the second open"
        );

        // The pin: `router.open` must never have run a second time. A
        // count of 2 here means the fence ran too late — the target was
        // already allocated before the rejection reached the client.
        assert_eq!(
            opens.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "revocation must block the second open before target allocation, not just \
             eventually close the connection"
        );
    }

    #[tokio::test]
    async fn persistent_upload_budget_accepts_exact_boundary_and_rejects_one_more_byte() {
        let store = Arc::new(consumed_store("claw_test"));
        let addr =
            spawn_persistent_engine_with_router(store, Arc::new(ReplayGuard::new()), DrainRouter);

        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(
            &mut client,
            &cred_cbor(),
            valid_token(b"persistent-byte-budget"),
        )
        .await
        .unwrap();
        client_open_persistent_stream(&mut client).await.unwrap();

        let chunk_len = MAX_FRAME_LEN - 1;
        let full_chunks = PERSISTENT_MAX_BYTES_PER_DIRECTION / chunk_len as u64;
        let remainder = PERSISTENT_MAX_BYTES_PER_DIRECTION % chunk_len as u64;
        let chunk = vec![0x5a; chunk_len];
        for _ in 0..full_chunks {
            send_frame(&mut client, &TunnelFrame::Data(chunk.clone()))
                .await
                .unwrap();
        }
        if remainder > 0 {
            send_frame(
                &mut client,
                &TunnelFrame::Data(vec![0x5a; remainder as usize]),
            )
            .await
            .unwrap();
        }

        send_frame(&mut client, &TunnelFrame::Data(vec![0x5a]))
            .await
            .unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Error("session-byte-budget-exhausted".into())
        );
    }

    #[tokio::test]
    async fn persistent_download_budget_accepts_exact_boundary_and_rejects_one_more_byte() {
        let store = Arc::new(consumed_store("claw_test"));
        let addr =
            spawn_persistent_engine_with_router(store, Arc::new(ReplayGuard::new()), FloodRouter);

        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(
            &mut client,
            &cred_cbor(),
            valid_token(b"persistent-download-budget"),
        )
        .await
        .unwrap();
        client_open_persistent_stream(&mut client).await.unwrap();

        let mut received = 0_u64;
        loop {
            match recv_frame(&mut client).await.unwrap() {
                TunnelFrame::Data(bytes) => {
                    received = received.saturating_add(bytes.len() as u64);
                }
                TunnelFrame::Error(reason) => {
                    assert_eq!(reason, "session-byte-budget-exhausted");
                    break;
                }
                frame => panic!("unexpected frame at download boundary: {frame:?}"),
            }
        }
        assert_eq!(received, PERSISTENT_MAX_BYTES_PER_DIRECTION);
    }

    #[tokio::test]
    async fn revocation_between_persistent_targets_blocks_the_next_open() {
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_persistent_engine(
            Arc::clone(&store),
            spawn_two_request_target().await,
            Arc::new(ReplayGuard::new()),
        );

        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(
            &mut client,
            &cbor,
            valid_token(b"persistent-revoke-between"),
        )
        .await
        .unwrap();
        client_open_persistent_stream(&mut client).await.unwrap();
        send_frame(&mut client, &TunnelFrame::Data(b"request-1".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"response-1".to_vec())
        );
        assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);

        store.revoke(&SLOT, NOW).unwrap();
        send_frame(&mut client, &TunnelFrame::OpenPersistent)
            .await
            .unwrap();
        let after = recv_frame(&mut client).await;
        assert!(
            after.is_err(),
            "revocation between targets must close before a second backend opens: {after:?}"
        );
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
    async fn revoking_during_health_wait_blocks_open_before_the_target_is_opened() {
        // The Health→Open window: a client may sit in the Health loop for as
        // long as it likes, so authorization can lapse in between. Before the
        // pre-`router.open` fence, the first `is_revoked` call happened only on
        // the per-`Data` path — i.e. AFTER the target had been opened and the
        // Open-ack (and, on the IpTunnel path, `NetworkSettings` carrying a real
        // pool-allocated address) had already been sent.
        //
        // Here the slot is revoked while the client is still in Health. The
        // engine must refuse at Open and never reach the target, so the client
        // sees the tunnel close INSTEAD of an Open-ack.
        let store = Arc::new(consumed_store("claw_test"));
        let addr = spawn_engine(
            store.clone(),
            spawn_banner_target().await,
            Arc::new(ReplayGuard::new()),
        );

        let cbor = cred_cbor();
        let mut client = TcpStream::connect(addr).await.unwrap();
        client_authenticate(&mut client, &cbor, valid_token(b"n-health-revoke"))
            .await
            .unwrap();

        // Still pre-Open: exercise the Health loop, proving the session is live
        // and simply waiting.
        client_health(&mut client, HEALTH_PROBE).await.unwrap();

        // Authorization lapses in the window.
        store.revoke(&SLOT, NOW).unwrap();

        // Now ask to Open. The fence must reject before `router.open`.
        send_frame(&mut client, &TunnelFrame::Open).await.unwrap();

        let after = recv_frame(&mut client).await;
        assert!(
            after.is_err(),
            "Open after revocation must be refused before the target is opened, got {after:?}"
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
    fn tunnel_frame_debug_redacts_payloads() {
        let data_debug = format!("{:?}", TunnelFrame::Data(b"SECRET-PACKET-DATA!!".to_vec()));
        assert!(data_debug.contains("Data"));
        assert!(data_debug.contains("<redacted>"));
        assert!(data_debug.contains("len: 20"));
        assert!(!data_debug.contains("SECRET-PACKET-DATA"));
        assert!(!data_debug.contains("83, 69, 67, 82, 69, 84"));

        let health_debug = format!("{:?}", TunnelFrame::Health(b"SECRET-HEALTH".to_vec()));
        assert!(health_debug.contains("Health"));
        assert!(health_debug.contains("<redacted>"));
        assert!(health_debug.contains("len: 13"));
        assert!(!health_debug.contains("SECRET-HEALTH"));
        assert!(!health_debug.contains("83, 69, 67, 82, 69, 84"));

        let error_debug = format!(
            "{:?}",
            TunnelFrame::Error("SECRET-TARGET-ERROR".to_string())
        );
        assert!(error_debug.contains("Error"));
        assert!(error_debug.contains("<redacted>"));
        assert!(error_debug.contains("len: 19"));
        assert!(!error_debug.contains("SECRET-TARGET-ERROR"));

        let resize_debug = format!(
            "{:?}",
            TunnelFrame::Resize {
                cols: 120,
                rows: 40
            }
        );
        assert!(resize_debug.contains("cols"));
        assert!(resize_debug.contains("rows"));
    }

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
    fn open_persistent_frame_round_trips() {
        let frame = TunnelFrame::OpenPersistent;
        assert_eq!(frame.encode(), vec![FRAME_OPEN_PERSISTENT]);
        assert_eq!(TunnelFrame::decode(&frame.encode()).unwrap(), frame);
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

    // ─── Cancel-safety of the inbound frame reader ──────────────────────────
    //
    // `read_frame` is two sequential `read_exact` awaits: the 4-byte length
    // prefix, then the body. If the future holding it is DROPPED between them,
    // the prefix bytes are gone from the socket and the next read interprets
    // body bytes as a length — the stream desynchronises. The serve loop's
    // `select!` has two sibling arms (`revoke_poll.tick`, `reader.read`) that
    // can win at exactly that moment.
    //
    // Making that deterministic needs an answer to "has the server consumed the
    // prefix YET?", which the wire cannot give: a half-read frame produces no
    // output to synchronise against. `PrefixProbe` creates that observation
    // point inside the test by intercepting `poll_read` on the SERVER endpoint
    // and signalling once exactly the prefix has been delivered. No clock, no
    // sleep, no production API, no new dependency.

    /// Test-only tunnel wrapper that reports when the inbound length prefix has
    /// been consumed. Counting is armed by the test so the auth/health/open
    /// frames, which also flow through here, are not mistaken for the frame
    /// under test.
    struct PrefixProbe<S> {
        inner: S,
        armed: Arc<std::sync::atomic::AtomicBool>,
        seen: Arc<std::sync::atomic::AtomicUsize>,
        prefix_consumed: Arc<tokio::sync::Notify>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for PrefixProbe<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            use std::sync::atomic::Ordering;
            let me = self.get_mut();
            let before = buf.filled().len();
            let polled = std::pin::Pin::new(&mut me.inner).poll_read(cx, buf);
            if matches!(polled, std::task::Poll::Ready(Ok(()))) {
                let n = buf.filled().len() - before;
                if n > 0 && me.armed.load(Ordering::SeqCst) {
                    let total = me.seen.fetch_add(n, Ordering::SeqCst) + n;
                    if total >= 4 {
                        // `notify_one` stores a permit, so the signal is not
                        // lost if the test has not reached its await yet.
                        me.prefix_consumed.notify_one();
                    }
                }
            }
            polled
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixProbe<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// A target that sends a banner on connect, then a second chunk only when
    /// the test releases it, then echoes `ACK:<bytes>`. The gated second chunk
    /// is what makes the competing `reader.read` arm fire at a moment the test
    /// chooses.
    async fn spawn_gated_target(release: tokio::sync::oneshot::Receiver<()>) -> String {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = target.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut sock, _) = target.accept().await.unwrap();
            sock.write_all(b"BANNER").await.unwrap();
            if release.await.is_err() {
                return;
            }
            sock.write_all(b"SECOND").await.unwrap();
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

    /// A sibling `select!` arm winning while the inbound reader sits BETWEEN the
    /// length prefix and the body must not cost the connection its framing.
    ///
    /// Causality is enforced, not assumed: the test only fires the competing arm
    /// after `PrefixProbe` has reported that exactly the prefix was consumed, so
    /// the interleaving under test is the one that actually occurs. Every wait
    /// is bounded and a lapsed bound fails the test as INCONCLUSIVE rather than
    /// passing — a timeout is not evidence of either behaviour.
    #[tokio::test]
    async fn sibling_select_arm_cannot_desync_a_partially_read_frame() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        const BOUND: Duration = Duration::from_secs(10);

        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let target_addr = spawn_gated_target(release_rx).await;

        let armed = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let prefix_consumed = Arc::new(tokio::sync::Notify::new());

        let (server_raw, mut client) = tokio::io::duplex(64 * 1024);
        let server = PrefixProbe {
            inner: server_raw,
            armed: Arc::clone(&armed),
            seen: Arc::clone(&seen),
            prefix_consumed: Arc::clone(&prefix_consumed),
        };

        let store = Arc::new(consumed_store("claw_test"));
        let hh = engine_hh();
        let guard = Arc::new(ReplayGuard::new());
        let rev_store = Arc::clone(&store);
        tokio::spawn(async move {
            let router = TcpStreamRouter::new(target_addr);
            serve_connection_io(
                server,
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
            .await
        });

        let cbor = cred_cbor();
        client_authenticate(&mut client, &cbor, valid_token(b"n1"))
            .await
            .unwrap();
        client_open_stream(&mut client).await.unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(b"BANNER".to_vec())
        );

        // Arm only now: the frames above already went through the probe.
        armed.store(true, Ordering::SeqCst);

        // A `Data("PING")` frame, split. `encode()` is [kind][body] = 5 bytes,
        // so the prefix is 5 — the body is withheld, which is what parks the
        // reader between its two `read_exact` calls.
        let body = TunnelFrame::Data(b"PING".to_vec()).encode();
        assert_eq!(
            body.len(),
            5,
            "frame layout changed; the split is no longer mid-frame"
        );
        client
            .write_all(&(u32::try_from(body.len()).unwrap()).to_be_bytes())
            .await
            .unwrap();
        client.flush().await.unwrap();

        // NON-VACUITY: the interleaving only exists if the prefix really landed.
        tokio::time::timeout(BOUND, prefix_consumed.notified())
            .await
            .expect("probe never saw the prefix consumed — the test proves nothing");
        assert_eq!(
            seen.load(Ordering::SeqCst),
            4,
            "probe must have seen exactly the 4 prefix bytes"
        );

        // Now let the competing `reader.read` arm win, with the reader parked
        // mid-frame, and confirm it actually ran by observing its output.
        release_tx.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(BOUND, recv_frame(&mut client))
                .await
                .expect("target chunk never arrived — competing arm did not run")
                .unwrap(),
            TunnelFrame::Data(b"SECOND".to_vec())
        );

        // Deliver the withheld body. Before the fix the prefix is gone, so this
        // is read as a length (0x11504_94E, past MAX_FRAME_LEN) and the
        // connection dies; after it, the frame completes and reaches the target.
        client.write_all(&body).await.unwrap();
        client.flush().await.unwrap();

        let echoed = tokio::time::timeout(BOUND, recv_frame(&mut client))
            .await
            .expect("no verdict within bound — inconclusive, not a pass");
        assert_eq!(
            echoed.unwrap(),
            TunnelFrame::Data(b"ACK:PING".to_vec()),
            "the partially-read frame must survive a sibling arm winning"
        );
    }

    // ─── 0x17 canonical-form admission ──────────────────────────────────────
    //
    // The `NetworkSettings` body configures a VPN interface and is consumed
    // before any packet pump, so the bytes that reach the typed value must be
    // exactly the ones the encoder would have produced. Three malformed shapes
    // decode cleanly today: a map whose keys are not in RFC 8949 canonical
    // order, a map carrying a key the struct does not model, and a well-formed
    // item followed by trailing bytes inside the same length-delimited frame.
    //
    // Every case asserts BOTH halves. The control — that the LENIENT helper
    // still accepts the mutant — is not decoration: without it a passing
    // rejection proves nothing, because an unreachable, mistyped or otherwise
    // broken fixture also "rejects". The control pins that the bytes really do
    // reach a decoder that currently tolerates them, so the rejection is the
    // new rule firing and not the fixture failing.
    //
    // Bodies are built with the crate's own encoders, never from a
    // hand-derived hex constant: a hand-written vector would pin my arithmetic
    // rather than the encoder's behaviour.

    fn network_settings_fixture() -> NetworkSettings {
        // TEST-NET-1 (RFC 5737) documentation addresses only.
        NetworkSettings {
            mesh_ipv4: MeshIpv4 {
                addr: "192.0.2.2".into(),
                prefix_len: 24,
                peer: "192.0.2.3".into(),
            },
            mtu: 1280,
            session_id: "session-alpha_1".into(),
        }
    }

    fn network_settings_frame(body: &[u8]) -> Vec<u8> {
        let mut framed = vec![FRAME_NETWORK_SETTINGS];
        framed.extend_from_slice(body);
        framed
    }

    /// The same three fields emitted in DECLARATION order through raw
    /// `ciborium`, bypassing the canonicalizing encoder. Declaration order is
    /// `mesh_ipv4, mtu, session_id`; canonical order is `mtu, mesh_ipv4,
    /// session_id`. The nested `MeshIpv4` is likewise emitted `addr,
    /// prefix_len, peer` against a canonical `addr, peer, prefix_len`, so both
    /// map levels are non-canonical.
    #[derive(Serialize)]
    struct NetworkSettingsDeclarationOrder {
        mesh_ipv4: MeshIpv4,
        mtu: u16,
        session_id: String,
    }

    /// Every modelled field PLUS one the struct does not declare, encoded
    /// through the canonicalizing encoder. `unknown_extra` sorts last, so the
    /// first three entries keep their canonical order and no trailing bytes
    /// exist: the ONLY defect is the extra key.
    #[derive(Serialize)]
    struct NetworkSettingsUnknownKey {
        mesh_ipv4: MeshIpv4,
        mtu: u16,
        session_id: String,
        unknown_extra: bool,
    }

    #[test]
    // ── S0 relocation notice, for the four 0x17 strictness tests ────────────
    //
    // These four are X2's, and they are CHANGED by S0 — declared, not hidden.
    // They used to assert rejection at `TunnelFrame::decode`, because the strict
    // mirrors lived beside the codec and the strictness "could not escape" it.
    // S0 had to move the settings struct product-side: it carries a `session_id`
    // stamped by the serve loop, and a neutral type may not hold a field whose
    // only legitimate producer is an authority.
    //
    // So the assertion point moves to `decode_network_settings_body`, which is
    // now the only public way to interpret a sealed `NetworkSettingsBody`. Every
    // mutant and every positive control is preserved byte for byte; only the
    // call path changed. The claim "the existing claw tests pass unmodified" is
    // therefore NOT made for these four — the frozen wire vectors under
    // `tests/data/`, untouched since an earlier commit, carry the byte-identity
    // proof instead.
    fn network_settings_canonical_body_is_accepted() {
        let settings = network_settings_fixture();
        let body = cbor::to_canonical_vec(&settings).expect("canonical encode");

        // The frame still decodes, and the sealed body still yields the settings
        // through the strict door.
        let frame = TunnelFrame::decode(&network_settings_frame(&body)).expect("frame decodes");
        let TunnelFrame::NetworkSettings(sealed) = frame else {
            panic!("expected a NetworkSettings frame");
        };
        assert_eq!(
            decode_network_settings_body(&sealed).expect("canonical body decodes"),
            settings,
        );
    }

    /// Helper for the three mutant tests: run a body through the frame and then
    /// the strict door, which is where rejection now lives.
    fn strict_decode_via_frame(body: &[u8]) -> Result<NetworkSettings, DataTunnelError> {
        let frame = TunnelFrame::decode(&network_settings_frame(body))?;
        let TunnelFrame::NetworkSettings(sealed) = frame else {
            panic!("expected a NetworkSettings frame");
        };
        decode_network_settings_body(&sealed)
    }

    #[test]
    fn network_settings_non_canonical_key_order_is_rejected() {
        let settings = network_settings_fixture();
        let canonical = cbor::to_canonical_vec(&settings).expect("canonical encode");

        let mut body = Vec::new();
        ciborium::ser::into_writer(
            &NetworkSettingsDeclarationOrder {
                mesh_ipv4: settings.mesh_ipv4.clone(),
                mtu: settings.mtu,
                session_id: settings.session_id.clone(),
            },
            &mut body,
        )
        .expect("declaration-order encode");
        assert_ne!(
            body, canonical,
            "fixture is not actually non-canonical — the mutation did nothing"
        );

        // CONTROL: the lenient helper accepts these bytes today.
        assert!(
            cbor::from_canonical_slice::<NetworkSettings>(&body).is_ok(),
            "control failed: lenient decode must still accept the mutant"
        );

        assert!(
            strict_decode_via_frame(&body).is_err(),
            "non-canonical key order must be rejected"
        );
    }

    #[test]
    fn network_settings_unknown_key_is_rejected() {
        let settings = network_settings_fixture();
        let body = cbor::to_canonical_vec(&NetworkSettingsUnknownKey {
            mesh_ipv4: settings.mesh_ipv4.clone(),
            mtu: settings.mtu,
            session_id: settings.session_id.clone(),
            unknown_extra: true,
        })
        .expect("unknown-key encode");

        // CONTROL: the PUBLIC type still ignores the unmodelled key, because
        // the strictness lives on the private wire mirror and not on
        // `NetworkSettings`. This is the load-bearing scope assertion: it
        // fails the moment `deny_unknown_fields` migrates onto the public
        // type and starts binding the dev runner, the bridge and the FFI.
        assert!(
            cbor::from_canonical_slice::<NetworkSettings>(&body).is_ok(),
            "control failed: the public type must NOT carry the 0x17 policy"
        );

        // The strict helper catches an unmodelled key ON ITS OWN, with no
        // `deny_unknown_fields` in play: the key does not survive into the
        // typed value, so the canonical re-encode comes out shorter. The
        // mirror's attribute and the helper genuinely overlap here rather
        // than one silently carrying the other.
        assert!(
            cbor::from_canonical_slice_strict::<NetworkSettings>(&body).is_err(),
            "the strict helper must reject an unmodelled key unaided"
        );

        assert!(
            strict_decode_via_frame(&body).is_err(),
            "an unmodelled key must be rejected"
        );
    }

    #[test]
    fn network_settings_trailing_byte_is_rejected() {
        let settings = network_settings_fixture();
        let mut body = cbor::to_canonical_vec(&settings).expect("canonical encode");
        body.push(0x00);

        // CONTROL: the decoder stops at the end of the item and ignores the
        // rest of the frame today.
        assert!(
            cbor::from_canonical_slice::<NetworkSettings>(&body).is_ok(),
            "control failed: lenient decode must still accept the mutant"
        );

        assert!(
            strict_decode_via_frame(&body).is_err(),
            "trailing bytes inside the frame must be rejected"
        );
    }
}
