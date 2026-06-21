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
//!      `<state_dir>/pair_machine_window.json`. **NOT idempotent across
//!      calls** — see step 3.
//!   3. Run `prepare_candidate` to mint the P-256 keypair, the signed
//!      `JoinRequest`, and the per-ceremony `anchor_secret`. The
//!      `M_priv` is reused via keystore marker, but the nonce and
//!      `anchor_secret` are freshly drawn from CSPRNG on every call
//!      and any pre-existing non-Idle window is reset to Idle before
//!      restaging. Re-invoking `stage()` therefore **invalidates the
//!      previous QR**: the prior URI's `nonce`/`anchor_secret` pair no
//!      longer matches the persisted window, so the iPhone scan of the
//!      old QR will be rejected at `local/anchor` time. Callers (the
//!      `SoyehtMac`.app welcome flow) MUST treat this endpoint as
//!      "user confirmed they want to join now" — never as a probe.
//!   4. Render the canonical `pair-machine` URI via
//!      `JoinRequest::to_pair_machine_uri_with_anchor` and return it.
//!      The iPhone's `QRScannerView` consumes this URI shape directly
//!      via `HouseholdMachineJoinRuntime.stageScannedMachineJoin`.
//!   5. Optionally spawn the Bonjour publisher (B8) so founder
//!      discovery works on LAN. Bonjour publish is best-effort and
//!      happens outside the bootstrap-mutation critical section.
//!
//! Why no listener bind here: the founder-facing `local/seed`, `local/anchor`,
//! and `local/finalize` routes are mounted on the running daemon's main
//! `household_router` (see `household_bootstrap::bootstrap_household`) and
//! share the same `Arc<PairMachineWindow>` this function mutates. Re-binding
//! the daemon's address on a new `TcpListener` would collide with the
//! daemon's existing bind; routing through the shared listener also avoids
//! duplicating the auth boundary. The CLI install path (`install_cli.rs`)
//! continues to bind its own pre-household listener because in that flow
//! the daemon does not yet exist.
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

use crate::bonjour_publisher::{
    PairMachineBonjourRole, PublishParams, publish_candidate_joiner_bonjour,
};
use crate::household_listener::{InterfaceClass, enumerate_bind_targets};
use crate::install_cli::{pick_addr_for_transport, probe_mdns_available, sanitize_hostname};
use household_rs::KeyBackingPolicy;
use household_rs::machine_cert::Platform;
use household_rs::pair_machine::{
    JoinTransport, PairMachineWindow, PrepareCandidateOpts, prepare_candidate,
};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// What the daemon staging returns to the `SoyehtMac`.app caller.
///
/// The iPhone never sees this struct directly — it consumes the QR
/// rendered from `pair_machine_uri`. The other three fields are for
/// `SoyehtMac` itself (UI surface: "show this QR for ~5 minutes", optional
/// fingerprint reassurance display).
///
/// Wire format: encoded as canonical CBOR (`application/cbor`) by the
/// HTTP handler — matches the sibling bootstrap endpoints. The
/// `SoyehtMac`.app and iOS clients decode via `household_rs::cbor`.
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

    #[error("failed to prepare candidate keypair: {0}")]
    Prepare(String),

    #[error("invalid candidate addr {addr:?}: {source}")]
    InvalidBindAddr {
        addr: String,
        source: std::net::AddrParseError,
    },
}

/// Prepare a fresh pair-machine candidate ceremony from the daemon and
/// open the candidate's `PairMachineWindow` in `Staging`.
///
/// **No listener bind here.** The daemon already serves the pre-household
/// `/pair-machine/local/*` routes on its main `household_router` (wired
/// in `household_bootstrap::bootstrap_household`); this function only
/// mutates the shared `Arc<PairMachineWindow>` and returns the URI
/// material. Binding a second listener at the daemon's address would
/// collide; that is why this entry point exists as a separate function
/// from the CLI install path (which still owns its own bind because the
/// daemon does not exist when the operator runs `theyos install
/// --pair-machine`).
///
/// **Not idempotent.** Every call mints a new CSPRNG `nonce` and
/// `anchor_secret`, returns the existing `PairMachineWindow` to Idle if
/// it was not already, and restages with the fresh material. Any QR
/// rendered from a previous `stage()` call is therefore invalidated —
/// the prior URI's `nonce`/`anchor_secret` pair no longer matches the
/// persisted window and the iPhone scan of the old QR will be rejected
/// at `local/anchor` time. The candidate's `M_priv` IS reused across
/// calls because the keystore marker is persistent; only the ceremony
/// secrets rotate. Callers MUST treat this entry point as an explicit
/// user-initiated action (the `SoyehtMac`.app welcome flow), never as
/// a probe.
///
/// Concurrency: the caller (`post_pair_machine_local_stage`) MUST hold
/// `bootstrap_mutation_lock::BOOTSTRAP_MUTATION_LOCK` across this call
/// AND have re-validated the engine `BootstrapState` inside that critical
/// section immediately before invoking, so that `accept_household_confirm`
/// and `local_finalize_handler` cannot interleave writes to
/// `household_record.cbor` / `machine_cert.cbor` / the self-shard.
///
/// `state_dir` must be the same directory the CLI uses
/// (`<household_state_dir>` per `resolve_household_state_dir`), so a
/// later teardown / finalize lands in the right place. `window` is the
/// same `Arc<PairMachineWindow>` the daemon shares with
/// `pre_household_router` (constructed once at bootstrap time) so the
/// `/pair-machine/local/seed` lookup reads the freshly staged bytes
/// without a disk round-trip.
pub async fn stage(
    state_dir: &Path,
    window: Arc<PairMachineWindow>,
    transport: JoinTransport,
    key_policy: KeyBackingPolicy,
) -> Result<StageOutcome, StageError> {
    let port: u16 = crate::household_bootstrap::household_port_from_env();

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
        return Err(StageError::BadHostname {
            got: hostname.len(),
        });
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StageError::ClockBeforeEpoch)?
        .as_secs();

    let ttl_secs =
        crate::household_bootstrap::pair_window_ttl_secs_from_env("THEYOS_PAIR_MACHINE_TTL_SECS");

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

    // Parse + validate the bind addr early so a malformed pick is
    // surfaced as an explicit error rather than leaking through a
    // later Bonjour publish step.
    let advertised_addr: SocketAddr = addr.parse().map_err(|e| StageError::InvalidBindAddr {
        addr: addr.clone(),
        source: e,
    })?;

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

    // Best-effort Bonjour publish for LAN auto-discovery. Spawned to a
    // detached task so the caller can drop `BOOTSTRAP_MUTATION_LOCK` the
    // moment `stage()` returns. The publisher only reads
    // `PairMachineWindow` (no mutation) and does not touch household
    // identity files, so it is safe to run unsynchronised with the next
    // mutation-lock acquirer. mDNS publish can take seconds on
    // misbehaving networks; holding the lock through it would block
    // sibling `accept_household_*` calls unnecessarily.
    let bonjour_port = advertised_addr.port();
    let bonjour_host_label = prepared.m_id.to_string();
    let bonjour_window = Arc::clone(&window);
    tokio::spawn(async move {
        let lan_unavailable = transport == JoinTransport::Lan && !probe_mdns_available().await;
        if lan_unavailable {
            return;
        }
        let publish_targets = enumerate_bind_targets()
            .into_iter()
            .filter(|(_, class)| *class != InterfaceClass::Loopback)
            .collect::<Vec<_>>();
        let publish = publish_candidate_joiner_bonjour(
            PublishParams {
                hh_id: String::new(),
                hh_name: String::new(),
                m_id: String::new(),
                port: bonjour_port,
                host_label: bonjour_host_label,
                host_dns: gethostname::gethostname().to_string_lossy().into_owned(),
                pair_machine_role: Some(PairMachineBonjourRole::Joiner),
                owner_display_name: String::new(),
                device_count: 0,
                bootstrap_state: String::new(),
            },
            bonjour_window,
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
    });

    Ok(StageOutcome {
        pair_machine_uri: uri,
        fingerprint: prepared.fingerprint.clone(),
        ttl_unix: prepared.ttl_unix,
    })
}
