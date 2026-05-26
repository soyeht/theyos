//! Daemon-side staging of a `pair-machine` candidate ceremony.
//!
//! This is the HTTP-handler counterpart to the existing
//! `theyos install --pair-machine` CLI path (see `install_cli.rs`). It
//! lets the `SoyehtMac`.app expose a "join my existing house" choice in
//! the welcome flow without requiring the user to drop into a shell to
//! run `theyos install`.
//!
//! What happens:
//!
//!   1. Pick a reachable bind address for the requested transport
//!      (Tailscale 100.64.0.0/10 or LAN RFC1918), same logic as the
//!      CLI.
//!   2. Open a `PairMachineWindow` with persistence under
//!      `<state_dir>/pair_machine_window.json`. Idempotent: if a
//!      window already exists from a previous staging within its TTL,
//!      we reuse it rather than minting a new keypair (so the QR the
//!      user already showed to their iPhone stays valid).
//!   3. Run `prepare_candidate` to mint the P-256 keypair, the signed
//!      `JoinRequest`, and the per-ceremony `anchor_secret`.
//!   4. Bind a TCP listener on the chosen address and spawn the
//!      pre-household HTTP listener that serves `/pair-machine/local/seed`,
//!      `/.../anchor`, and `/.../finalize`. This is the SAME listener the
//!      CLI installs — once it's up, the founder Mac can deliver the
//!      trust anchor + signed `JoinResponse` and the candidate can
//!      finalize its membership.
//!   5. Optionally spawn the Bonjour publisher (B8) so founder
//!      discovery works on LAN.
//!   6. Render the canonical `pair-machine` URI via
//!      `JoinRequest::to_pair_machine_uri_with_anchor` and return it.
//!      The iPhone's `QRScannerView` consumes this URI shape directly
//!      via `HouseholdMachineJoinRuntime.stageScannedMachineJoin`.
//!
//! Lifecycle: tokio tasks spawned here are NOT tracked by a shared
//! handle registry — they run until the engine process exits, the
//! candidate finalizes its membership (window state transitions out
//! of `Staging` → listeners' handlers naturally start rejecting), or
//! the TTL elapses. A future revision may add an explicit teardown
//! endpoint; v0.1.19 ships with the simpler "live-for-process" model
//! because the candidate Mac is freshly installed and has no other
//! workload to protect.
//!
//! See `specs/006-pair-machine-daemon-stage/` for the contract.

use crate::handlers_pair_machine::{PreHouseholdRouterState, pre_household_router};
use crate::household_listener::{InterfaceClass, enumerate_bind_targets};
use crate::install_cli::{pick_addr_for_transport, probe_mdns_available, sanitize_hostname};
use crate::bonjour_publisher::{
    PairMachineBonjourRole, PublishParams, publish_candidate_joiner_bonjour,
};
use household_rs::KeyBackingPolicy;
use household_rs::machine_cert::Platform;
use household_rs::pair_machine::{
    JoinTransport, PairMachineWindow, PrepareCandidateOpts, prepare_candidate,
};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tracing::{info, warn};

/// What the daemon staging returns to the `SoyehtMac`.app caller.
///
/// The iPhone never sees this struct directly — it consumes the QR
/// rendered from `pair_machine_uri`. The other three fields are for
/// `SoyehtMac` itself (UI surface: "show this QR for ~5 minutes", optional
/// fingerprint reassurance display).
#[derive(Debug, serde::Serialize)]
pub struct StageOutcome {
    /// The canonical `soyeht://household/pair-machine?...` URI with
    /// every required query parameter (`m_pub, nonce, hostname,
    /// platform, transport, addr, challenge_sig, ttl, anchor_secret`).
    /// `SoyehtMac` renders this directly as a QR — do NOT remount the
    /// fields on the Swift side.
    pub pair_machine_uri: String,

    /// Short trust-anchor fingerprint for the user-visible "this QR
    /// shows code XXXX" hint. Lower-case hex, 12 chars.
    pub fingerprint: String,

    /// Unix timestamp (seconds) when this window expires. After this
    /// time the listener handlers will reject finalize attempts. The
    /// iPhone side converts to `Date(timeIntervalSince1970:)` for
    /// display.
    pub ttl_unix: u64,
}

/// Errors surfaced to the HTTP handler caller. All shapes carry an
/// English diagnostic suitable for logging and developer-facing UI.
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    #[error("no {transport} interface address available")]
    NoTransportAddress { transport: &'static str },

    #[error("unsupported platform: {os}")]
    UnsupportedPlatform { os: &'static str },

    #[error("hostname must be 1..=64 sanitized bytes (got {got})")]
    BadHostname { got: usize },

    #[error("system clock is before unix epoch")]
    ClockBeforeEpoch,

    #[error("failed to load pair-machine window state: {0}")]
    WindowLoad(String),

    #[error("failed to prepare candidate keypair: {0}")]
    Prepare(String),

    #[error("invalid candidate addr {addr:?}: {source}")]
    InvalidBindAddr { addr: String, source: std::net::AddrParseError },

    #[error("failed to bind pre-household listener on {addr}: {source}")]
    BindFailed { addr: SocketAddr, source: std::io::Error },
}

/// Stage a fresh pair-machine candidate ceremony from the daemon.
/// Idempotent across calls within a window's TTL — if a window already
/// exists on disk, its existing `JoinRequest` is re-rendered to the
/// same URI rather than minting fresh keys.
///
/// `state_dir` must be the same directory the CLI uses
/// (`<household_state_dir>` per `resolve_household_state_dir`), so a
/// later teardown / finalize lands in the right place.
pub async fn stage(
    state_dir: &Path,
    transport: JoinTransport,
    key_policy: KeyBackingPolicy,
) -> Result<StageOutcome, StageError> {
    let port: u16 = std::env::var("THEYOS_HOUSEHOLD_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8091);

    let addr = pick_addr_for_transport(transport, port).ok_or(StageError::NoTransportAddress {
        transport: match transport {
            JoinTransport::Tailscale => "Tailscale",
            JoinTransport::Lan => "LAN",
        },
    })?;

    let platform = Platform::detect().ok_or(StageError::UnsupportedPlatform {
        os: std::env::consts::OS,
    })?;

    let hostname = sanitize_hostname(&gethostname::gethostname().to_string_lossy());
    if hostname.is_empty() || hostname.len() > 64 {
        return Err(StageError::BadHostname { got: hostname.len() });
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StageError::ClockBeforeEpoch)?
        .as_secs();

    let window = PairMachineWindow::with_persistence(state_dir.to_path_buf())
        .map_err(|e| StageError::WindowLoad(format!("{e}")))?;

    let ttl_secs = std::env::var("THEYOS_PAIR_MACHINE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|secs| (60..=3600).contains(secs))
        .unwrap_or(300);

    let opts = PrepareCandidateOpts {
        state_dir: state_dir.to_path_buf(),
        transport,
        addr: addr.clone(),
        hostname,
        platform,
        policy: key_policy,
        ttl: Duration::from_secs(ttl_secs),
        now_unix,
    };

    let prepared = prepare_candidate(&window, opts)
        .await
        .map_err(|e| StageError::Prepare(format!("{e}")))?;

    let uri = prepared
        .join_request
        .to_pair_machine_uri_with_anchor(prepared.ttl_unix, &prepared.anchor_secret);

    info!(
        stage = "pair_machine_window.opened",
        source = "daemon_stage",
        m_id = %prepared.m_id,
        transport = match transport {
            JoinTransport::Tailscale => "tailscale",
            JoinTransport::Lan => "lan",
        },
        ttl_unix = prepared.ttl_unix,
        fingerprint = %prepared.fingerprint,
    );

    let bind_addr: SocketAddr = addr.parse().map_err(|e| StageError::InvalidBindAddr {
        addr: addr.clone(),
        source: e,
    })?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| StageError::BindFailed { addr: bind_addr, source: e })?;

    let window = Arc::new(window);
    let router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: state_dir.to_path_buf(),
        key_policy,
        finalize_lock: Arc::new(tokio::sync::Mutex::new(())),
    });

    // Spawn the listener — task runs until the process exits or the
    // listener fails. Same lifecycle the CLI uses.
    tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        {
            warn!(stage = "pair_machine.daemon_listener_exited", error = %e);
        }
    });

    // Best-effort Bonjour publish for LAN auto-discovery. Tailscale
    // joins work fine without it (iPhone scans the QR directly), so we
    // log + carry on if `mdns-sd` fails (e.g. firewall blocks 5353).
    let lan_unavailable = transport == JoinTransport::Lan && !probe_mdns_available().await;
    if !lan_unavailable {
        let publish_targets = enumerate_bind_targets()
            .into_iter()
            .filter(|(_, class)| *class != InterfaceClass::Loopback)
            .collect::<Vec<_>>();
        let publish = publish_candidate_joiner_bonjour(
            PublishParams {
                hh_id: String::new(),
                hh_name: String::new(),
                m_id: String::new(),
                port: bind_addr.port(),
                host_label: prepared.m_id.to_string(),
                host_dns: gethostname::gethostname().to_string_lossy().into_owned(),
                pair_machine_role: Some(PairMachineBonjourRole::Joiner),
                owner_display_name: String::new(),
                device_count: 0,
                bootstrap_state: String::new(),
            },
            Arc::clone(&window),
            publish_targets,
        )
        .await;
        if let Err(e) = publish {
            warn!(
                stage = "pair_machine.daemon_bonjour_publish_failed",
                error = %e,
                hint = "candidate falls back to QR-only path",
            );
        }
    }

    Ok(StageOutcome {
        pair_machine_uri: uri,
        fingerprint: prepared.fingerprint.clone(),
        ttl_unix: prepared.ttl_unix,
    })
}
