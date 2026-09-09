#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::uninlined_format_args)]

//! UniFFI bridge for the iOS claw-share data plane.
//!
//! `ClawSession` owns a real TCP connection to the engine's claw data
//! tunnel and exposes a concrete (no `dyn Trait`) UniFFI surface the
//! host app + `NEPacketTunnelProvider` extension drive:
//!
//! - `load_credential` — decode + verify the owner-signed credential.
//! - `start_session(config, token)` — dial + authenticate (PoP token); → `AwaitingFirstPacket`.
//! - `health_ping` — liveness round-trip; → `Connected` (TUNNEL READY).
//! - `open_stream` — open a PERSISTENT stream to the target AND wait for the
//!   target's first output (a real shell's prompt/banner); → `InteractiveReady`
//!   (the only state the UI may treat as openable — a real interactive
//!   terminal session has produced output).
//! - `network_settings` — the engine's server-allocated per-Claw VPN IPv4
//!   interface parameters, delivered in a post-Open `NetworkSettings` frame on
//!   the `IpTunnel` path. This is the ONLY address authority; the bridge never
//!   derives an address locally. `None` on every other path.
//! - `resize` — propagate the local terminal's column/row count to the
//!   remote PTY.
//! - `send_data` / `receive_data` — the steady-state stream pump the
//!   terminal read/write loops use. The tunnel socket is split into
//!   independent read/write halves so the two loops run concurrently
//!   without contending. `receive_data` surfaces a typed target exit.
//!
//! Apple-grade gate (enforced here, mirrored in Swift):
//! - `Connected` = the tunnel handshake + a health echo succeeded. This
//!   is readiness, NOT "the user can open the claw".
//! - `StreamReady` = a persistent stream to the target is open, but the
//!   target has not yet spoken. Still NOT openable.
//! - `InteractiveReady` = the stream is open AND the remote interactive
//!   session produced its first output. Only this is openable.
//!
//! The engine pipes `Data` to a persistent target — in the daemon a real,
//! policy-controlled interactive PTY shell (`server-rs::claw_share_pty_target`);
//! an in-process banner/echo fixture in these bridge tests, which exercises
//! the same client protocol (open → first output → interactive, resize, data,
//! exit) without spawning a host shell inside the iOS sandbox.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use household_rs::cbor;
use household_rs::claw_share::data_tunnel as dt;
use household_rs::claw_share::{ClawShareError, GuestCredential};
use thiserror::Error;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::Mutex;
use tokio::time::timeout;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum BridgeError {
    #[error("credential CBOR decode failed: {0}")]
    CredentialDecode(String),
    #[error("credential expired or revoked")]
    CredentialInvalid,
    #[error("no session is currently active")]
    NoSession,
    #[error("data plane handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("health ping round-trip failed")]
    HealthRoundTripFailed,
    #[error("packet round-trip failed")]
    PacketRoundTripFailed,
    #[error("session token invalid: {0}")]
    TokenInvalid(String),
    #[error("target service unavailable: {0}")]
    TargetUnavailable(String),
    #[error("transport failed: {0}")]
    TransportFailed(String),
    /// The post-Open `NetworkSettings` frame did not satisfy the engine's
    /// stated client contract (see [`ClawSession::accept_network_settings`]).
    /// Fail-closed: the session is unusable for an IP tunnel. The payload is a
    /// static label — it never echoes an address or a session id.
    #[error("network settings rejected: {0}")]
    NetworkSettingsInvalid(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl From<ClawShareError> for BridgeError {
    fn from(e: ClawShareError) -> Self {
        Self::Internal(e.to_string())
    }
}

// ─── Public types ────────────────────────────────────────────────────────────

/// Lifecycle of a claw session as observed by the bridge.
///
/// `Connected` (after `health_ping`) means the tunnel is READY.
/// `StreamReady` (after the engine's open ack) means a persistent stream to
/// the target is open but it has not spoken yet. `InteractiveReady` (after
/// the target's first output) means a real interactive session is live — the
/// ONLY openable state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum SessionStatus {
    Idle,
    CredentialReady,
    Dialing,
    /// Handshake done; no health round-trip yet.
    AwaitingFirstPacket,
    /// Health echo succeeded — tunnel ready + transport works, but NOT
    /// openable (the tunnel echoing bytes is not proof a target exists).
    Connected {
        since_unix: u64,
    },
    /// The engine acked `Open`: a persistent stream to the target is
    /// established, but the target has not produced output yet. NOT openable
    /// — an open socket is not proof of a live interactive session.
    StreamReady {
        since_unix: u64,
    },
    /// The stream is open AND the remote interactive session produced its
    /// first output (a real shell prompt/banner). The ONLY openable state —
    /// the iPhone can drive a real terminal over it.
    InteractiveReady {
        since_unix: u64,
    },
    Stopped {
        reason: String,
    },
    Failed {
        reason: String,
    },
}

/// Where the engine's claw data tunnel is reachable.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone)]
pub struct DataPlaneConfig {
    pub host: String,
    pub port: u16,
}

/// Handshake result the bridge reports back after `start_session`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone)]
pub struct StartSessionOutcome {
    pub mesh_ipv6: String,
    pub mtu: u16,
    /// Engine-assigned session id (stable per credential/slot).
    pub session_id: String,
    /// Always `AwaitingFirstPacket`.
    pub status: SessionStatus,
}

/// The guest's REAL, server-allocated per-Claw VPN interface parameters,
/// delivered by the engine in a post-Open [`dt::TunnelFrame::NetworkSettings`]
/// frame (`IpTunnel` path only).
///
/// This is the sole address authority for the tunnel. It is NOT derived on the
/// client and it is NOT the `mesh_ipv6` string in [`StartSessionOutcome`]: that
/// field comes from the auth ack, which stays address-free for every path. The
/// allocation only exists after the engine's `router.open`, which is exactly why
/// it arrives in its own frame after the Open-ack.
///
/// `prefix_len` scopes the route. A consumer installs a route for exactly
/// `network(addr, prefix_len)` and never a default route.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone, PartialEq, Eq)]
pub struct VpnNetworkSettings {
    /// The guest's assigned tunnel address.
    pub addr: String,
    /// CIDR prefix length that scopes the installed route.
    pub prefix_len: u8,
    /// The claw-side tunnel-remote address, inside the same prefix.
    pub peer: String,
    pub mtu: u16,
    /// Engine-assigned session id, already verified to equal the one carried by
    /// the auth ack. Retained so a consumer can re-assert the binding.
    pub session_id: String,
}

/// Mirrors the redaction the engine applies to `dt::MeshIpv4` /
/// `dt::NetworkSettings`: addresses reveal VPN topology and the session id is
/// bearer-adjacent, so neither may reach a log through a formatter. A derived
/// `Debug` here would silently undo the engine-side redaction.
impl std::fmt::Debug for VpnNetworkSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpnNetworkSettings")
            .field("addr", &"<redacted>")
            .field("prefix_len", &self.prefix_len)
            .field("peer", &"<redacted>")
            .field("mtu", &self.mtu)
            .field("session_id", &"<redacted>")
            .finish()
    }
}

// ─── Session state ───────────────────────────────────────────────────────────

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ClawSession {
    inner: Mutex<ClawSessionInner>,
    diag_events: Mutex<Vec<String>>,
    /// Tunnel write half — `send_packet` + outbound frames.
    writer: Mutex<Option<OwnedWriteHalf>>,
    /// Tunnel read half — `receive_packet` + inbound frames. Held
    /// separately from `writer` so the read and write loops the
    /// NEPacketTunnel runs do not contend.
    reader: Mutex<Option<OwnedReadHalf>>,
}

struct ClawSessionInner {
    credential: Option<GuestCredential>,
    credential_cbor: Option<Vec<u8>>,
    status: SessionStatus,
    session_id: Option<String>,
    last_health_ok_at: Option<u64>,
    stream_ready_at: Option<u64>,
    interactive_ready_at: Option<u64>,
    /// The target's first output, captured during `open_stream` (it is what
    /// flips the session to `InteractiveReady`). The first `receive_data`
    /// returns it so no output is lost.
    pending_output: Option<Vec<u8>>,
    /// The server-allocated VPN interface settings, once the post-Open
    /// `NetworkSettings` frame has been received AND validated. `None` on every
    /// non-`IpTunnel` path (PTY / ClawSite / Device), which send no such frame.
    network_settings: Option<VpnNetworkSettings>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const AUTH_TIMEOUT: Duration = Duration::from_secs(15);

fn elapsed_ms(start: Instant) -> u128 {
    start.elapsed().as_millis()
}

/// Map a transport error to a STATIC discriminant label for diagnostics.
///
/// `DataTunnelError`'s `Display` interpolates free-form `String` payloads —
/// `Io(String)` in particular is built from an `io::Error`, whose text can carry
/// the address that failed. Formatting the error into a diag event would
/// therefore reintroduce exactly the endpoint material the diag channel must not
/// hold. Only the variant is emitted; the full error still reaches the caller
/// through the returned `BridgeError`, which is the channel that may carry it.
fn dt_error_label(e: &dt::DataTunnelError) -> &'static str {
    match e {
        dt::DataTunnelError::Io(_) => "io",
        dt::DataTunnelError::FrameTooLarge(_) => "frame_too_large",
        dt::DataTunnelError::Closed(_) => "closed",
        // A distinct label, not a fold into "closed": the split exists so a
        // reader can tell an orderly end of exchange from a cut stream, and a
        // diag channel that erases it back to one word cannot answer the
        // question the variant was added for.
        dt::DataTunnelError::ClosedAtFrameBoundary(_) => "closed_at_frame_boundary",
        dt::DataTunnelError::AuthTimeout => "auth_timeout",
        dt::DataTunnelError::Cbor(_) => "cbor",
        dt::DataTunnelError::Rejected(_) => "rejected",
        dt::DataTunnelError::UnexpectedAck => "unexpected_ack",
        dt::DataTunnelError::HealthMismatch => "health_mismatch",
        dt::DataTunnelError::InvalidFrame(_) => "invalid_frame",
        dt::DataTunnelError::TokenRejected(_) => "token_rejected",
        dt::DataTunnelError::TargetUnavailable(_) => "target_unavailable",
    }
}

/// Reduce an engine-side auth trace string to an ALLOWLISTED static label.
///
/// The base's `client_authenticate_traced` currently emits only static labels
/// plus byte counts, so passing the string through would be safe *today*. It is
/// not passed through anyway: it is a payload this crate does not control, so an
/// upstream change that added an identifier to a trace event would silently
/// widen this crate's diag surface. Allowlisting fails closed instead — an
/// unrecognised event degrades to a bare label and drops its payload.
fn auth_trace_label(event: &str) -> &'static str {
    if event.starts_with("auth_frame_write_start") {
        "auth_frame_write_start"
    } else if event.starts_with("auth_frame_write_ok") {
        "auth_frame_write_ok"
    } else if event.starts_with("ack_read_start") {
        "ack_read_start"
    } else if event.starts_with("ack_read_ok") {
        "ack_read_ok"
    } else {
        "auth_trace_other"
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl ClawSession {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(ClawSessionInner {
                credential: None,
                credential_cbor: None,
                status: SessionStatus::Idle,
                session_id: None,
                last_health_ok_at: None,
                stream_ready_at: None,
                interactive_ready_at: None,
                pending_output: None,
                network_settings: None,
            }),
            diag_events: Mutex::new(Vec::new()),
            writer: Mutex::new(None),
            reader: Mutex::new(None),
        })
    }

    async fn diag(&self, event: String) {
        let mut events = self.diag_events.lock().await;
        events.push(format!("R160_BRIDGE {}", event));
        if events.len() > 128 {
            let excess = events.len() - 128;
            events.drain(0..excess);
        }
    }

    /// Drain bridge-internal diagnostic events. The events never include raw
    /// credentials or auth tokens.
    pub async fn drain_diag_events(self: Arc<Self>) -> Vec<String> {
        let mut events = self.diag_events.lock().await;
        std::mem::take(&mut *events)
    }

    /// Decode + accept a credential as canonical CBOR. Refuses on parse
    /// failure OR on a failed owner-signature / expiry check.
    pub async fn load_credential(
        self: Arc<Self>,
        credential_cbor: Vec<u8>,
        now_unix: u64,
    ) -> Result<SessionStatus, BridgeError> {
        let credential: GuestCredential = cbor::from_canonical_slice(&credential_cbor)
            .map_err(|e| BridgeError::CredentialDecode(e.to_string()))?;
        credential
            .verify(now_unix)
            .map_err(|_| BridgeError::CredentialInvalid)?;
        let mut inner = self.inner.lock().await;
        inner.credential = Some(credential);
        inner.credential_cbor = Some(credential_cbor);
        inner.status = SessionStatus::CredentialReady;
        Ok(inner.status.clone())
    }

    /// Dial the engine data tunnel + authenticate. Splits the socket into
    /// read/write halves for the concurrent packet loops. Enters
    /// `AwaitingFirstPacket`.
    /// `session_token_cbor` is the host-signed proof-of-possession token
    /// (canonical CBOR of a `SessionAuthToken`, signed by the guest device
    /// key). The bridge forwards it in the auth envelope; the engine
    /// verifies it against the credential's `guest_device_pub`, so a
    /// stolen credential without this token is rejected.
    pub async fn start_session(
        self: Arc<Self>,
        config: DataPlaneConfig,
        session_token_cbor: Vec<u8>,
    ) -> Result<StartSessionOutcome, BridgeError> {
        let token: dt::SessionAuthToken = cbor::from_canonical_slice(&session_token_cbor)
            .map_err(|e| BridgeError::TokenInvalid(e.to_string()))?;
        // No host/port: the diag channel is drained by the app and can reach a
        // log, and an engine endpoint is a private operator value. Lengths and
        // durations stay — they are not identifiers.
        self.diag(format!(
            "start_session_enter token_len={}",
            session_token_cbor.len()
        ))
        .await;
        let cred_cbor = {
            let mut inner = self.inner.lock().await;
            let cbor = inner
                .credential_cbor
                .clone()
                .ok_or(BridgeError::CredentialInvalid)?;
            inner.status = SessionStatus::Dialing;
            cbor
        };
        self.diag(format!("credential_loaded bytes={}", cred_cbor.len()))
            .await;

        let resolve_start = Instant::now();
        self.diag("resolve_start".to_string()).await;
        match lookup_host((config.host.as_str(), config.port)).await {
            Ok(addrs) => {
                // Count, not addresses. "DNS returned N answers" is the whole
                // diagnostic value here; the addresses themselves are the
                // infrastructure identifiers this channel must never hold.
                let addr_count = addrs.take(8).count();
                self.diag(format!(
                    "resolve_ok elapsed_ms={} addr_count={}",
                    elapsed_ms(resolve_start),
                    addr_count
                ))
                .await;
            }
            Err(_) => {
                // A resolver `io::Error` routinely embeds the hostname it failed
                // to look up, so not even the error kind is formatted here.
                self.diag(format!(
                    "resolve_err elapsed_ms={}",
                    elapsed_ms(resolve_start)
                ))
                .await;
            }
        }

        let connect_start = Instant::now();
        self.diag(format!(
            "connect_start timeout_ms={}",
            CONNECT_TIMEOUT.as_millis()
        ))
        .await;
        let mut stream = match timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((config.host.as_str(), config.port)),
        )
        .await
        {
            Ok(Ok(stream)) => {
                // The local and peer socket addresses are not read at all: a
                // value that is never obtained cannot be formatted into an event
                // by a later edit.
                self.diag(format!(
                    "connect_ok elapsed_ms={}",
                    elapsed_ms(connect_start)
                ))
                .await;
                stream
            }
            Ok(Err(e)) => {
                // `ErrorKind` is a closed std enum (`ConnectionRefused`,
                // `TimedOut`, …) and carries no address, so it is the one part
                // of the error safe to keep — and it is the part that makes the
                // event actionable. The full `e` is not formatted.
                self.diag(format!(
                    "connect_err elapsed_ms={} kind={:?}",
                    elapsed_ms(connect_start),
                    e.kind()
                ))
                .await;
                return Err(BridgeError::TransportFailed(e.to_string()));
            }
            Err(_) => {
                self.diag(format!(
                    "connect_timeout elapsed_ms={} timeout_ms={}",
                    elapsed_ms(connect_start),
                    CONNECT_TIMEOUT.as_millis()
                ))
                .await;
                return Err(BridgeError::TransportFailed(format!(
                    "connect timeout after {}ms",
                    CONNECT_TIMEOUT.as_millis()
                )));
            }
        };

        let auth_start = Instant::now();
        self.diag(format!(
            "client_authenticate_start timeout_ms={}",
            AUTH_TIMEOUT.as_millis()
        ))
        .await;
        let mut auth_events = Vec::new();
        let auth = timeout(
            AUTH_TIMEOUT,
            dt::client_authenticate_traced(&mut stream, &cred_cbor, token, |event| {
                auth_events.push(event.to_string());
            }),
        )
        .await;
        for event in auth_events {
            self.diag(format!(
                "{} elapsed_ms={}",
                auth_trace_label(&event),
                elapsed_ms(auth_start)
            ))
            .await;
        }
        let ack = match auth {
            Ok(Ok(ack)) => {
                self.diag(format!(
                    "client_authenticate_ok elapsed_ms={}",
                    elapsed_ms(auth_start)
                ))
                .await;
                ack
            }
            Ok(Err(e)) => {
                self.diag(format!(
                    "client_authenticate_err elapsed_ms={} kind={}",
                    elapsed_ms(auth_start),
                    dt_error_label(&e)
                ))
                .await;
                return Err(BridgeError::HandshakeFailed(e.to_string()));
            }
            Err(_) => {
                self.diag(format!(
                    "client_authenticate_timeout elapsed_ms={} timeout_ms={}",
                    elapsed_ms(auth_start),
                    AUTH_TIMEOUT.as_millis()
                ))
                .await;
                return Err(BridgeError::HandshakeFailed(format!(
                    "auth timeout after {}ms",
                    AUTH_TIMEOUT.as_millis()
                )));
            }
        };

        match ack {
            dt::TunnelAck::Ok {
                mesh_ipv6,
                mtu,
                session_id,
            } => {
                // No session id, not even a prefix: a prefix is a partial
                // identifier and still correlates a drained log to a session.
                // Presence booleans carry the diagnostic value instead.
                self.diag(format!(
                    "ack_ok mtu={} session_id_present={} mesh_ipv6_present={}",
                    mtu,
                    !session_id.is_empty(),
                    !mesh_ipv6.is_empty()
                ))
                .await;
                let (read_half, write_half) = stream.into_split();
                *self.writer.lock().await = Some(write_half);
                *self.reader.lock().await = Some(read_half);
                let mut inner = self.inner.lock().await;
                inner.status = SessionStatus::AwaitingFirstPacket;
                inner.session_id = Some(session_id.clone());
                Ok(StartSessionOutcome {
                    mesh_ipv6,
                    mtu,
                    session_id,
                    status: inner.status.clone(),
                })
            }
            dt::TunnelAck::Rejected { reason } => {
                // The reason is server-controlled free text. It still reaches
                // the caller through `SessionStatus::Failed` / `BridgeError`;
                // it just does not enter the drainable diag channel.
                self.diag("ack_rejected".to_string()).await;
                self.inner.lock().await.status = SessionStatus::Failed {
                    reason: reason.clone(),
                };
                Err(BridgeError::HandshakeFailed(reason))
            }
        }
    }

    /// Liveness round-trip → `Connected` (tunnel ready). NOT openable.
    pub async fn health_ping(self: Arc<Self>) -> Result<SessionStatus, BridgeError> {
        self.send_health().await?;
        let echo = self.recv_health().await?;
        if echo != dt::HEALTH_PROBE {
            return Err(BridgeError::HealthRoundTripFailed);
        }
        let mut inner = self.inner.lock().await;
        let now = now_unix();
        inner.last_health_ok_at = Some(now);
        inner.status = SessionStatus::Connected { since_unix: now };
        Ok(inner.status.clone())
    }

    /// Open the PERSISTENT interactive session: send `Open`, await the
    /// engine's `Open` ack (→ `StreamReady`), then wait for the target's
    /// FIRST output — a real shell's prompt/banner — before reporting
    /// `InteractiveReady` (the only openable state). Gating on first output
    /// means an open-but-silent socket can never present as a usable
    /// terminal. The first output is buffered and returned by the first
    /// `receive_data`. A target failure comes back as a typed error. Call
    /// after `health_ping`.
    pub async fn open_stream(self: Arc<Self>) -> Result<SessionStatus, BridgeError> {
        {
            let mut wguard = self.writer.lock().await;
            let w = wguard.as_mut().ok_or(BridgeError::NoSession)?;
            dt::send_frame(w, &dt::TunnelFrame::Open)
                .await
                .map_err(|e| BridgeError::TransportFailed(e.to_string()))?;
        }
        let mut rguard = self.reader.lock().await;
        let r = rguard.as_mut().ok_or(BridgeError::NoSession)?;
        // 1. Engine's open ack — the stream to the target is established.
        match dt::recv_frame(r).await {
            Ok(dt::TunnelFrame::Open) => {}
            Ok(dt::TunnelFrame::Error(reason)) => {
                return Err(BridgeError::TargetUnavailable(reason));
            }
            _ => return Err(BridgeError::PacketRoundTripFailed),
        }
        {
            let mut inner = self.inner.lock().await;
            let now = now_unix();
            inner.stream_ready_at = Some(now);
            inner.status = SessionStatus::StreamReady { since_unix: now };
        }
        // 2. The target's first output — proof of a live interactive session.
        let first = loop {
            match dt::recv_frame(r).await {
                Ok(dt::TunnelFrame::Data(p)) => break p,
                Ok(dt::TunnelFrame::Health(_)) => {}
                // `IpTunnel` path: the engine sends this IMMEDIATELY after the
                // Open-ack, so it lands here, before the target's first output.
                // Validate + store and keep waiting; a rejection aborts the open
                // rather than proceeding with an unbound allocation.
                Ok(dt::TunnelFrame::NetworkSettings(sealed)) => {
                    // S0: the frame body is sealed, so the ONLY way to read it is
                    // the strict canonical decoder. That is deliberate — the
                    // strictness used to be unbypassable inside
                    // `TunnelFrame::decode`, and sealing is what keeps it
                    // unbypassable now that the struct is product-side.
                    // Static label: this variant's contract is that the payload
                    // never echoes an address or a session id, so the decode
                    // error is NOT stringified into it.
                    let ns = dt::decode_network_settings_body(&sealed).map_err(|_| {
                        BridgeError::NetworkSettingsInvalid("malformed body".into())
                    })?;
                    self.accept_network_settings(ns).await?;
                }
                Ok(dt::TunnelFrame::Close) => {
                    return Err(BridgeError::TargetUnavailable(
                        "target closed before first output".into(),
                    ));
                }
                Ok(dt::TunnelFrame::Exit(status)) => {
                    return Err(BridgeError::TargetUnavailable(format!(
                        "target exited before first output: {status:?}"
                    )));
                }
                Ok(dt::TunnelFrame::Error(reason)) => {
                    return Err(BridgeError::TargetUnavailable(reason));
                }
                Ok(_) => {
                    return Err(BridgeError::TransportFailed(
                        "unexpected frame before first output".into(),
                    ));
                }
                Err(e) => return Err(BridgeError::TransportFailed(e.to_string())),
            }
        };
        drop(rguard);
        let status = {
            let mut inner = self.inner.lock().await;
            let now = now_unix();
            inner.interactive_ready_at = Some(now);
            inner.pending_output = Some(first);
            inner.status = SessionStatus::InteractiveReady { since_unix: now };
            inner.status.clone()
        };
        // Do not send an application-level interactive keepalive here. Live
        // 5G testing showed the previous Window(0) keepalive could arrive at
        // the engine as an un-prefixed typed frame (0x14...), which the engine
        // correctly interpreted as an absurd length prefix and closed as
        // fail-closed. The mesh underlay has its own keepalive; terminal
        // liveness is surfaced by the read/write paths.
        Ok(status)
    }

    /// Open a PASSIVE byte stream — for a non-interactive target that is SILENT
    /// until it is spoken to (an HTTP ClawSite responds only after it receives a
    /// request). Sends `Open`, awaits the engine's `Open` ack (→ `StreamReady`),
    /// and returns WITHOUT waiting for first output (unlike `open_stream`, which
    /// gates on a PTY's prompt). The caller then drives the exchange:
    /// `send_data`(request) → `receive_data`(response). No interactive keepalive
    /// is started (the HTTP request/response is immediate and short-lived); the
    /// SAME authenticated session (credential + proof-of-possession token +
    /// per-claw binding) gates it — there is no unauthenticated path. Call after
    /// `health_ping`. Used by the iOS authed ClawSite loopback proxy (R77).
    pub async fn open_stream_passive(self: Arc<Self>) -> Result<SessionStatus, BridgeError> {
        {
            let mut wguard = self.writer.lock().await;
            let w = wguard.as_mut().ok_or(BridgeError::NoSession)?;
            dt::send_frame(w, &dt::TunnelFrame::Open)
                .await
                .map_err(|e| BridgeError::TransportFailed(e.to_string()))?;
        }
        let mut rguard = self.reader.lock().await;
        let r = rguard.as_mut().ok_or(BridgeError::NoSession)?;
        // Engine's open ack — the stream to the target is established. We do NOT
        // wait for first output: a byte-stream target legitimately stays silent
        // until the request arrives.
        match dt::recv_frame(r).await {
            Ok(dt::TunnelFrame::Open) => {}
            Ok(dt::TunnelFrame::Error(reason)) => {
                return Err(BridgeError::TargetUnavailable(reason));
            }
            _ => return Err(BridgeError::PacketRoundTripFailed),
        }
        drop(rguard);
        let status = {
            let mut inner = self.inner.lock().await;
            let now = now_unix();
            inner.stream_ready_at = Some(now);
            inner.status = SessionStatus::StreamReady { since_unix: now };
            inner.status.clone()
        };
        Ok(status)
    }

    /// Send stream bytes to the target (terminal stdin / write loop).
    pub async fn send_data(self: Arc<Self>, data: Vec<u8>) -> Result<(), BridgeError> {
        let mut guard = self.writer.lock().await;
        let w = guard.as_mut().ok_or(BridgeError::NoSession)?;
        dt::send_frame(w, &dt::TunnelFrame::Data(data))
            .await
            .map_err(|e| BridgeError::TransportFailed(e.to_string()))
    }

    /// Propagate the local terminal size (columns × rows) to the remote PTY.
    /// Safe to call repeatedly as the device rotates / the keyboard shows.
    pub async fn resize(self: Arc<Self>, cols: u16, rows: u16) -> Result<(), BridgeError> {
        let mut guard = self.writer.lock().await;
        let w = guard.as_mut().ok_or(BridgeError::NoSession)?;
        dt::client_resize(w, cols, rows)
            .await
            .map_err(|e| BridgeError::TransportFailed(e.to_string()))
    }

    /// Block until the next stream `Data` arrives (terminal stdout / read
    /// loop). Returns the buffered first output once, then live frames. A
    /// clean `Close`/EOF, or a typed target `Exit` (which also marks the
    /// session `Stopped`), surfaces as `NoSession` so the loop exits; an
    /// `Error` frame surfaces as a typed transport failure.
    pub async fn receive_data(self: Arc<Self>) -> Result<Vec<u8>, BridgeError> {
        // Drain the first output captured during open_stream (if any).
        {
            let mut inner = self.inner.lock().await;
            if let Some(p) = inner.pending_output.take() {
                return Ok(p);
            }
        }
        let mut guard = self.reader.lock().await;
        let r = guard.as_mut().ok_or(BridgeError::NoSession)?;
        loop {
            match dt::recv_frame(r).await {
                Ok(dt::TunnelFrame::Data(p)) => return Ok(p),
                Ok(dt::TunnelFrame::Health(_)) => {} // liveness — skip
                // `open_stream_passive` returns right after the Open-ack without
                // draining, so on the `IpTunnel` path the settings frame is
                // still queued and surfaces on the first read. Same validation,
                // same fail-closed outcome.
                Ok(dt::TunnelFrame::NetworkSettings(sealed)) => {
                    // Same strict door as the open path; see the note there.
                    // Static label: this variant's contract is that the payload
                    // never echoes an address or a session id, so the decode
                    // error is NOT stringified into it.
                    let ns = dt::decode_network_settings_body(&sealed).map_err(|_| {
                        BridgeError::NetworkSettingsInvalid("malformed body".into())
                    })?;
                    self.accept_network_settings(ns).await?;
                }
                Ok(dt::TunnelFrame::Exit(status)) => {
                    drop(guard);
                    let mut inner = self.inner.lock().await;
                    inner.status = SessionStatus::Stopped {
                        reason: format!("target-exited:{status:?}"),
                    };
                    inner.interactive_ready_at = None;
                    inner.stream_ready_at = None;
                    return Err(BridgeError::NoSession);
                }
                Ok(dt::TunnelFrame::Close) => return Err(BridgeError::NoSession),
                Ok(dt::TunnelFrame::Error(reason)) => {
                    return Err(BridgeError::TargetUnavailable(reason));
                }
                Ok(_) => return Err(BridgeError::TransportFailed("unexpected frame".into())),
                Err(e) => return Err(BridgeError::TransportFailed(e.to_string())),
            }
        }
    }

    pub async fn status(self: Arc<Self>) -> SessionStatus {
        self.inner.lock().await.status.clone()
    }

    /// The server-allocated VPN interface settings for this session, or `None`.
    ///
    /// `Some` only after the engine sent a post-Open `NetworkSettings` frame AND
    /// it passed validation. `None` means one of two things, which this bridge
    /// deliberately does not distinguish: the session is on a non-`IpTunnel`
    /// path (no frame is ever sent), or the frame has not arrived yet.
    ///
    /// CONSUMER CONTRACT: an IP-tunnel caller MUST fail closed on `None` and
    /// MUST NOT configure an interface, install a route, or start a packet pump
    /// without these values. There is no fallback and no client-side derivation
    /// — a locally computed address is not an allocation.
    pub async fn network_settings(self: Arc<Self>) -> Option<VpnNetworkSettings> {
        self.inner.lock().await.network_settings.clone()
    }

    /// Stop the session. Idempotent. Sends a best-effort `Close`, then
    /// drops both tunnel halves so any in-flight `receive_data` exits.
    pub async fn stop_session(self: Arc<Self>, reason: String) -> SessionStatus {
        {
            let mut wguard = self.writer.lock().await;
            if let Some(w) = wguard.as_mut() {
                let _ = dt::send_frame(w, &dt::TunnelFrame::Close).await;
            }
        }
        *self.writer.lock().await = None;
        *self.reader.lock().await = None;
        let mut inner = self.inner.lock().await;
        inner.status = SessionStatus::Stopped { reason };
        inner.last_health_ok_at = None;
        inner.stream_ready_at = None;
        inner.interactive_ready_at = None;
        inner.pending_output = None;
        // Drop the allocation with the session: it is bound to this session id,
        // so a later reconnect must receive (and re-validate) a fresh frame
        // rather than inherit a stale address.
        inner.network_settings = None;
        // Drop the session id with it. Leaving it set would keep the binding
        // check in `accept_network_settings` satisfiable by the OLD id after the
        // transport is gone: a settings frame arriving before the next handshake
        // would validate against a dead session, and a reconnect would inherit
        // an id it never negotiated. Clearing makes that path fail closed via
        // the "settings before handshake" arm.
        inner.session_id = None;
        inner.status.clone()
    }
}

// Non-exported helpers (split-half health IO).
impl ClawSession {
    /// Validate + store a post-Open `NetworkSettings` frame, fail-closed.
    ///
    /// The engine's contract (`claw_share::data_tunnel::NetworkSettings`) is that
    /// a *missing, duplicated, or invalid* frame fails the connection closed
    /// before any interface is configured. This enforces the two halves the
    /// client owns:
    ///
    /// * **invalid** — `session_id` must equal the one the auth `TunnelAck`
    ///   carried. The engine stamps the same `cred.session_id()` into both, so a
    ///   mismatch means the settings are not bound to this authenticated
    ///   session. This is a cross-phase binding *in addition to* the transport
    ///   channel, so it must be checked even though the bytes arrived in-band.
    /// * **duplicated** — a second frame is refused rather than allowed to
    ///   overwrite an accepted allocation, which would let a later frame
    ///   re-point an already-configured interface.
    ///
    /// "Missing" is not enforceable here (the bridge cannot know whether the
    /// path is `IpTunnel`); it is the consumer's obligation, stated on
    /// [`ClawSession::network_settings`].
    ///
    /// Lock order is reader → inner, matching every other path in this file;
    /// no path holds `inner` while taking `reader`, so this cannot deadlock.
    async fn accept_network_settings(
        self: &Arc<Self>,
        ns: dt::NetworkSettings,
    ) -> Result<(), BridgeError> {
        let mut inner = self.inner.lock().await;
        let Some(expected) = inner.session_id.as_deref() else {
            return Err(BridgeError::NetworkSettingsInvalid(
                "settings before handshake".into(),
            ));
        };
        if ns.session_id != expected {
            return Err(BridgeError::NetworkSettingsInvalid(
                "session id mismatch".into(),
            ));
        }
        if inner.network_settings.is_some() {
            return Err(BridgeError::NetworkSettingsInvalid(
                "duplicate frame".into(),
            ));
        }
        // Client-side route scope, enforced HERE because this is the last place
        // it can be. Everything above checks the frame's *provenance* — that a
        // handshake happened, that the session id matches, that this is the
        // first such frame. None of them looks at the addresses, so without
        // this call a well-provenanced frame carrying `prefix_len = 0` reached
        // `VpnNetworkSettings` unexamined, and the consumer that installs a
        // route from it is a NetworkExtension in another repository — past the
        // point where anything in this workspace can still say no.
        //
        // `route_scope_violation` is the neutral rule that travels with
        // `MeshIpv4` itself (`tunnel_wire_rs`, re-exported through `dt`), so
        // this consumer rejects the same set the dev runner does — default
        // route, prefix > 32, non-IPv4 addr or peer, peer equal to addr, peer
        // outside the prefix — rather than an open-coded subset that drifts
        // from it. The server enforces the same invariant in
        // `build_vpn_mesh_ipv4` before the session opens; this is the client
        // half, and a client that trusts the server to have checked is a client
        // with no check.
        if let Some(violation) = ns.mesh_ipv4.route_scope_violation() {
            // The violation variant names a topology property, not an address:
            // safe to surface, and it is what makes a failure diagnosable
            // without logging the addresses this type is redacted to protect.
            return Err(BridgeError::NetworkSettingsInvalid(format!(
                "route scope: {violation}"
            )));
        }
        inner.network_settings = Some(VpnNetworkSettings {
            addr: ns.mesh_ipv4.addr,
            prefix_len: ns.mesh_ipv4.prefix_len,
            peer: ns.mesh_ipv4.peer,
            mtu: ns.mtu,
            session_id: ns.session_id,
        });
        Ok(())
    }

    async fn send_health(self: &Arc<Self>) -> Result<(), BridgeError> {
        let mut guard = self.writer.lock().await;
        let w = guard.as_mut().ok_or(BridgeError::HealthRoundTripFailed)?;
        dt::send_frame(w, &dt::TunnelFrame::Health(dt::HEALTH_PROBE.to_vec()))
            .await
            .map_err(|_| BridgeError::HealthRoundTripFailed)
    }

    async fn recv_health(self: &Arc<Self>) -> Result<Vec<u8>, BridgeError> {
        let mut guard = self.reader.lock().await;
        let r = guard.as_mut().ok_or(BridgeError::HealthRoundTripFailed)?;
        match dt::recv_frame(r).await {
            Ok(dt::TunnelFrame::Health(p)) => Ok(p),
            _ => Err(BridgeError::HealthRoundTripFailed),
        }
    }
}

/// Spin up an in-process loopback tunnel on `127.0.0.1:0` and return its
/// port. Self-test helper running the REAL [`dt::serve_connection`]:
/// health echoes, `Open` connects a PERSISTENT in-process target that
/// sends a banner then replies `ACK:<bytes>` to each data frame. So a
/// Swift test can drive the full path — health → open → multiple
/// data frames ↔ target — without a real engine. Credential
/// *authorization* is permissive (the token/credential/replay matrix is
/// covered by the engine-side tests); but data genuinely traverses to the
/// separate persistent target socket, so `open_stream` + `send_data`
/// exercise a real stream, not a tunnel echo.
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
pub async fn start_loopback_echo_server() -> Result<u16, BridgeError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A persistent target: banner on connect, then `ACK:<bytes>` per read.
    let target = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| BridgeError::TransportFailed(e.to_string()))?;
    let target_addr = target
        .local_addr()
        .map_err(|e| BridgeError::TransportFailed(e.to_string()))?
        .to_string();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = target.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = sock.write_all(b"FAKE-SSH-BANNER").await;
                let mut buf = vec![0u8; 2048];
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
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| BridgeError::TransportFailed(e.to_string()))?;
    let port = listener
        .local_addr()
        .map_err(|e| BridgeError::TransportFailed(e.to_string()))?
        .port();
    tokio::spawn(async move {
        let replay = std::sync::Arc::new(dt::ReplayGuard::new());
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let router = dt::TcpStreamRouter::new(target_addr.clone());
            let _replay = replay.clone();
            tokio::spawn(async move {
                // Accept-all auth: decode the credential, skip token/replay
                // verification (covered by engine-side tests).
                let verify = |env: &dt::AuthEnvelope, _now: u64| {
                    cbor::from_canonical_slice::<GuestCredential>(&env.credential_cbor)
                        .map_err(|e| dt::DataTunnelError::Cbor(e.to_string()))
                };
                let _ = dt::serve_connection(sock, 0, verify, &router, |_cred| false).await;
            });
        }
    });
    Ok(port)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
