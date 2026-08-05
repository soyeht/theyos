//! `theyos install` subcommand — fresh-bootstrap, idempotent rerun,
//! `--reissue-pair-qr` (Phase 2 owner-pairing QR), and `--pair-machine`
//! (Phase 3 candidate-machine join QR) paths.
//!
//! Self-contained CLI dispatcher for the install flow:
//!
//! 1. Parse args (`--household-name`, `--hostname-label`, `--reissue-pair-qr`,
//!    `--pair-machine`, `--transport`).
//! 2. Resolve the household state dir (via [`crate::household_bootstrap`]).
//! 3. Either:
//!    - load existing identity (idempotent rerun → exit 0, or
//!      `--reissue-pair-qr` → mint a fresh pair window + render QR), or
//!    - `--pair-machine` → mint candidate keypair, sign `JoinRequest`,
//!      open pair-machine window, render the
//!      `soyeht://household/pair-machine` QR with the 6-word BIP-39
//!      fingerprint above it (Phase 3 / FR-002, FR-004, FR-007), or
//!    - perform a fresh bootstrap and render the install-time pair-device QR.
//!
//! The pair-window mint persists `pair_device_window.cbor` (Phase 2) or
//! `pair_machine_window.cbor` (Phase 3) atomically so the daemon picks up
//! the same nonce on restart.

use crate::bonjour_browser::SOYEHT_HOUSEHOLD_SERVICE;
use crate::bonjour_publisher::{
    PairMachineBonjourRole, PublishParams, publish_candidate_joiner_bonjour,
};
use crate::handlers_pair_machine::{
    PreHouseholdRouterState, PreHouseholdRuntimeSignal, pre_household_router,
};
use crate::household_bootstrap::resolve_household_state_dir;
use crate::household_listener::{InterfaceClass, enumerate_bind_targets};
use household_rs::keys::P256PublicKey;
use household_rs::machine_cert::Platform;
use household_rs::pair_device::PairDeviceWindow;
use household_rs::pair_machine::{
    JoinTransport, PairMachineState, PairMachineWindow, PrepareCandidateOpts,
    prepare_candidate_under_lifecycle,
};
use household_rs::{
    BootstrapError,
    household_lifecycle::{HouseholdLifecycleLock, LifecycleWriteGuard},
};
use mdns_sd::ServiceDaemon;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tracing::{info, warn};

const INSTALL_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(30);
const PRE_HOUSEHOLD_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
enum InstallCliError {
    Bootstrap(BootstrapError),
    Other(String),
}

impl From<BootstrapError> for InstallCliError {
    fn from(error: BootstrapError) -> Self {
        Self::Bootstrap(error)
    }
}

struct MintedPairDeviceWindow {
    uri: String,
    expires_at_unix: u64,
    host_fallback: Option<String>,
}

enum FreshInstallOutcome {
    AlreadyInstalled,
    HouseholdNameRequired,
    InvalidHostname(usize),
    PairDevice(MintedPairDeviceWindow),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PairMachineWaitOutcome {
    RestartRequired,
    AckDelivered,
    Failed,
}

enum ColdTerminalRecovery {
    /// A terminal G1 install is active. The ordinary daemon owns the exact
    /// supervised replay listener in both RestartRequired and Ready, so a cold
    /// invocation must start it immediately instead of making daemon liveness
    /// depend on another Ack arriving within a finite CLI timeout.
    ReadyForDaemon,
}

fn report_install_error(error: InstallCliError) -> i32 {
    match error {
        InstallCliError::Bootstrap(error) => household_rs::bootstrap::log_error(&error),
        InstallCliError::Other(error) => eprintln!("error: {error}"),
    }
    1
}

/// Replace this process with a cold invocation using the same executable,
/// arguments, and inherited environment. Successful `exec` never returns;
/// every return value is therefore a hard restart failure.
#[cfg(unix)]
fn cold_reexec_current_process() -> std::io::Error {
    use std::os::unix::process::CommandExt as _;

    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => return error,
    };
    let mut command = std::process::Command::new(executable);
    command.args(std::env::args_os().skip(1));
    command.exec()
}

/// Replace a cold terminal-install process with the ordinary daemon.
///
/// The daemon itself owns the exact terminal-only replay endpoint. Starting it
/// immediately is therefore required even when the retained Ack has not yet
/// been retried: otherwise a transient bind/serve timeout in this CLI would
/// strand both the Ack and the durable Phase-3 outbox. The successful path
/// never returns; any return is a fail-stop install failure.
#[cfg(unix)]
fn cold_exec_daemon_current_process() -> std::io::Error {
    use std::os::unix::process::CommandExt as _;

    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => return error,
    };
    daemon_exec_command(executable.as_path()).exec()
}

#[cfg(not(unix))]
fn cold_exec_daemon_current_process() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "cold daemon exec is not implemented on this platform",
    )
}

fn daemon_exec_command(executable: &Path) -> std::process::Command {
    // Deliberately no arguments: carrying `install --pair-machine` forward
    // would start a third replay process instead of the ordinary daemon.
    std::process::Command::new(executable)
}

fn launch_daemon_for_cold_terminal(launch: impl FnOnce() -> std::io::Error) -> i32 {
    let error = launch();
    tracing::error!(
        stage = "pair_machine.cold_daemon_exec_failed",
        error = %error,
        "terminal install is durable but the installed daemon did not start"
    );
    eprintln!("error: failed to start the installed daemon for terminal replay: {error}");
    1
}

#[cfg(not(unix))]
fn cold_reexec_current_process() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "cold re-exec is not implemented on this platform",
    )
}

fn acquire_install_lifecycle_exclusive_blocking(
    state_dir: &Path,
) -> Result<LifecycleWriteGuard, InstallCliError> {
    let lifecycle = HouseholdLifecycleLock::open_verified(state_dir).map_err(|error| {
        InstallCliError::Other(format!("failed to open household lifecycle: {error}"))
    })?;
    let deadline = Instant::now()
        .checked_add(INSTALL_LIFECYCLE_TIMEOUT)
        .ok_or_else(|| InstallCliError::Other("household lifecycle deadline overflow".into()))?;
    let guard = lifecycle.lock_exclusive_until(deadline).map_err(|error| {
        InstallCliError::Other(format!("failed to acquire household lifecycle: {error}"))
    })?;
    let recovered =
        household_rs::bootstrap::recover_interrupted_household_teardown_under_lifecycle(
            &guard, state_dir,
        )
        .map_err(|error| {
            InstallCliError::Other(format!(
                "failed to recover interrupted household teardown: {error}"
            ))
        })?;
    if recovered {
        return Err(InstallCliError::Other(
            "recovered an interrupted household teardown; refusing this stale install invocation"
                .into(),
        ));
    }
    Ok(guard)
}

async fn acquire_install_lifecycle_exclusive(
    state_dir: &Path,
) -> Result<LifecycleWriteGuard, InstallCliError> {
    let state_dir = state_dir.to_path_buf();
    tokio::task::spawn_blocking(move || acquire_install_lifecycle_exclusive_blocking(&state_dir))
        .await
        .map_err(|error| {
            InstallCliError::Other(format!("household lifecycle worker failed: {error}"))
        })?
}

fn pair_device_host_fallback() -> Option<String> {
    let port = crate::household_bootstrap::household_port_from_env();
    pick_addr_for_transport(JoinTransport::Lan, port)
        .or_else(|| crate::tailnet_address::current_tailnet_ipv4().map(|ip| format!("{ip}:{port}")))
}

async fn prepare_reissued_pair_device_window(
    state_dir: &Path,
    policy: household_rs::KeyBackingPolicy,
    host_fallback: Option<String>,
) -> Result<MintedPairDeviceWindow, InstallCliError> {
    let guard = acquire_install_lifecycle_exclusive(state_dir).await?;
    let loaded = household_rs::bootstrap::try_load_existing_under_lifecycle(
        &guard, state_dir, policy,
    )?
    .ok_or_else(|| {
        InstallCliError::Other(
            "--reissue-pair-qr requires an already-bootstrapped install; run `theyos install --household-name <name>` first"
                .into(),
        )
    })?;
    let m_cert_fp = household_rs::machine_cert::fingerprint(&loaded.cert).map_err(|error| {
        InstallCliError::Other(format!("cannot fingerprint this machine's cert: {error}"))
    })?;
    let (uri, expires_at_unix) = mint_pair_device_uri(
        &guard,
        state_dir,
        &loaded.record.hh_pub,
        Some(&loaded.record.name),
        host_fallback.clone(),
        &m_cert_fp,
    )
    .await
    .map_err(InstallCliError::Other)?;
    drop(guard);
    Ok(MintedPairDeviceWindow {
        uri,
        expires_at_unix,
        host_fallback,
    })
}

async fn prepare_fresh_install(
    state_dir: &Path,
    household_name: Option<String>,
    hostname_label: Option<String>,
    policy: household_rs::KeyBackingPolicy,
    host_fallback: Option<String>,
) -> Result<FreshInstallOutcome, InstallCliError> {
    let guard = acquire_install_lifecycle_exclusive(state_dir).await?;
    if household_rs::bootstrap::try_load_existing_under_lifecycle(&guard, state_dir, policy)?
        .is_some()
    {
        return Ok(FreshInstallOutcome::AlreadyInstalled);
    }

    let Some(household_name) = household_name else {
        return Ok(FreshInstallOutcome::HouseholdNameRequired);
    };
    if let Some(label) = &hostname_label
        && (label.is_empty() || label.len() > 255)
    {
        return Ok(FreshInstallOutcome::InvalidHostname(label.len()));
    }

    let loaded = household_rs::bootstrap::bootstrap_or_load_under_lifecycle(
        &guard,
        state_dir,
        household_rs::BootstrapOpts {
            household_name,
            hostname_label,
        },
        policy,
    )?;
    let m_cert_fp = household_rs::machine_cert::fingerprint(&loaded.cert).map_err(|error| {
        InstallCliError::Other(format!("cannot fingerprint this machine's cert: {error}"))
    })?;
    let (uri, expires_at_unix) = mint_pair_device_uri(
        &guard,
        state_dir,
        &loaded.record.hh_pub,
        Some(&loaded.record.name),
        host_fallback.clone(),
        &m_cert_fp,
    )
    .await
    .map_err(InstallCliError::Other)?;
    drop(guard);
    info!(
        stage = "bootstrap.complete",
        hh_id = %loaded.record.hh_id,
        name = %loaded.record.name,
    );
    Ok(FreshInstallOutcome::PairDevice(MintedPairDeviceWindow {
        uri,
        expires_at_unix,
        host_fallback,
    }))
}

/// Entry point for `theyos install …`. Returns the process exit code.
pub async fn run(args: &[String]) -> i32 {
    let mut household_name: Option<String> = None;
    let mut hostname_label: Option<String> = None;
    let mut reissue_pair_qr = false;
    let mut pair_machine = false;
    let mut transport: Option<JoinTransport> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--household-name" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("error: --household-name requires a value");
                    return 2;
                };
                household_name = Some(v.clone());
                i += 2;
            }
            "--hostname-label" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("error: --hostname-label requires a value");
                    return 2;
                };
                hostname_label = Some(v.clone());
                i += 2;
            }
            "--reissue-pair-qr" => {
                reissue_pair_qr = true;
                i += 1;
            }
            "--pair-machine" => {
                pair_machine = true;
                i += 1;
            }
            "--transport" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("error: --transport requires a value (tailscale|lan)");
                    return 2;
                };
                transport = match v.as_str() {
                    "tailscale" => Some(JoinTransport::Tailscale),
                    "lan" => Some(JoinTransport::Lan),
                    other => {
                        eprintln!(
                            "error: --transport must be 'tailscale' or 'lan' (got {other:?})"
                        );
                        return 2;
                    }
                };
                i += 2;
            }
            "--help" | "-h" => {
                print_usage();
                return 0;
            }
            other => {
                eprintln!("error: unknown argument `{other}`");
                print_usage();
                return 2;
            }
        }
    }

    let state_dir = resolve_household_state_dir();
    if let Err(e) = std::fs::create_dir_all(&state_dir) {
        eprintln!(
            "error: failed to create household state dir {}: {e}",
            state_dir.display()
        );
        return 1;
    }

    let key_policy = household_rs::KeyBackingPolicy::from_env();

    if pair_machine {
        let Some(transport) = transport else {
            eprintln!(
                "error: --pair-machine requires --transport tailscale|lan. \
                Re-run as `theyos install --pair-machine --transport tailscale`."
            );
            return 2;
        };
        return run_pair_machine(&state_dir, transport, hostname_label.as_deref(), key_policy)
            .await;
    }

    if reissue_pair_qr {
        let host_fallback = pair_device_host_fallback();
        return match prepare_reissued_pair_device_window(&state_dir, key_policy, host_fallback)
            .await
        {
            Ok(minted) => emit_minted_pair_device_window(minted),
            Err(error) => report_install_error(error),
        };
    }

    let host_fallback = pair_device_host_fallback();
    match prepare_fresh_install(
        &state_dir,
        household_name,
        hostname_label,
        key_policy,
        host_fallback,
    )
    .await
    {
        Ok(FreshInstallOutcome::AlreadyInstalled) => 0,
        Ok(FreshInstallOutcome::HouseholdNameRequired) => {
            eprintln!(
                "error: fresh install requires --household-name <name>. \
                Re-run as `theyos install --household-name \"Sample Home\"`."
            );
            2
        }
        Ok(FreshInstallOutcome::InvalidHostname(length)) => {
            eprintln!("error: --hostname-label must be 1..=255 bytes (got {length} bytes)");
            2
        }
        Ok(FreshInstallOutcome::PairDevice(minted)) => emit_minted_pair_device_window(minted),
        Err(error) => report_install_error(error),
    }
}

fn print_usage() {
    eprintln!(
        "Usage: theyos install [options]\n\n\
         Options:\n\
           --household-name <name>     1-64 character household name (required on first install)\n\
           --hostname-label <label>    Override OS hostname for the MachineCert\n\
           --reissue-pair-qr           Skip bootstrap, mint a fresh owner-pair window, render QR\n\
           --pair-machine              Run as a join candidate: mint a machine keypair,\n\
                                       sign a JoinRequest, render the pair-machine QR.\n\
                                       Requires --transport.\n\
           --transport <kind>          Reachable network for the candidate (tailscale|lan)\n\
           --help, -h                  Show this help"
    );
}

/// Mint a fresh owner pair-device token on a persistent [`PairDeviceWindow`]
/// rooted at `state_dir`, and render the canonical
/// `soyeht://household/pair-device?…` URI.
///
/// Pure async helper — NO stdout, NO `process::exit`. The reachable `host`
/// fallback is passed IN by the caller (it must NOT call
/// `current_tailnet_ipv4` itself) so callers can resolve a LAN-first address
/// that works with Tailscale OFF. Returns `(uri, expires_at_unix)`.
///
/// The caller must retain the same lifecycle-exclusive transaction that
/// established the household identity supplied below; the guard parameter
/// makes that coupling explicit and rejects a different state root.
///
/// The engine's in-process reissue route mints on its shared
/// `Arc<PairDeviceWindow>` instead (for liveness), but renders via the same
/// `to_uri_with_host_and_name` path.
/// `m_cert_fp` is required and must come from the caller's already-validated
/// `MachineCert` — the helper deliberately cannot fetch one itself, so no
/// caller can render a QR off a cert that was merely decodable rather than
/// admitted.
pub(crate) async fn mint_pair_device_uri(
    lifecycle_guard: &LifecycleWriteGuard,
    state_dir: &Path,
    hh_pub: &P256PublicKey,
    household_name: Option<&str>,
    host_fallback: Option<String>,
    m_cert_fp: &[u8; 32],
) -> Result<(String, u64), String> {
    lifecycle_guard
        .verify_state_root(state_dir)
        .map_err(|error| format!("pair-device lifecycle binding changed: {error}"))?;
    let ttl = Duration::from_secs(crate::household_bootstrap::pair_window_ttl_secs_from_env(
        "THEYOS_PAIR_DEVICE_TTL_SECS",
    ));
    // The fingerprint arrives resolved, so minting is the last fallible step:
    // this helper persists a window snapshot, and failing after that would
    // leave a live window behind an error return.
    let window = PairDeviceWindow::with_persistence_under_lifecycle(
        state_dir.to_path_buf(),
        lifecycle_guard,
    )
    .map_err(|e| format!("failed to open pair-device namespace: {e}"))?;
    let token = window
        .mint_token_under_lifecycle(ttl, None, lifecycle_guard)
        .await
        .map_err(|e| format!("failed to mint pair token: {e}"))?;
    let uri = token.to_uri_with_host_and_name(
        hh_pub,
        host_fallback.as_deref(),
        household_name,
        m_cert_fp,
    );
    Ok((uri, token.expires_at_unix))
}

/// Render a pair-device window that was already minted and durably persisted
/// while the install lifecycle transaction was held. This function performs
/// only observability/UI work, after the lifecycle guard has been released.
fn emit_minted_pair_device_window(minted: MintedPairDeviceWindow) -> i32 {
    let MintedPairDeviceWindow {
        uri,
        expires_at_unix,
        host_fallback,
    } = minted;
    info!(
        stage = "pair_device_window.opened",
        source = "install",
        ttl_secs = crate::household_bootstrap::pair_window_ttl_secs_from_env(
            "THEYOS_PAIR_DEVICE_TTL_SECS",
        ),
        expires_at_unix = expires_at_unix,
        host_fallback = host_fallback.as_deref().unwrap_or(""),
    );

    let qr = match household_rs::qr_render::render_ansi_qr(&uri) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to render pair QR: {e}");
            // Snapshot is still persisted; print the URI so the operator
            // can recover via a manual scan.
            eprintln!("URI: {uri}");
            return 1;
        }
    };
    println!();
    println!("Scan with Soyeht on your iPhone within 5 minutes to claim owner role:");
    println!();
    print!("{qr}");
    println!();
    println!("URI: {uri}");
    println!();
    0
}

/// Phase 3 candidate-side install path (T035, T036, FR-002 / FR-004 / FR-007).
///
/// Mints (or reloads) the candidate's `M_priv`/`M_pub`, signs a `JoinRequest`
/// over a fresh CSPRNG nonce, opens the local `PairMachineWindow` so M2's
/// pre-household `local/seed` endpoint can serve the same bytes back to M1
/// (Story 2), and prints the `soyeht://household/pair-machine?…` QR alongside
/// the 6-word BIP-39 fingerprint that the owner iPhone will render.
/// Resolve a retained G1 terminal install before any fresh-network discovery.
///
/// Both terminal states converge immediately to the ordinary daemon, which
/// supervises replay on the address signed into the original JoinRequest.
/// Re-enumerating interfaces during a cold exec could silently authorize a
/// different coordinate, so this path validates the exact persisted socket
/// address before exec and the daemon repeats that validation at startup.
async fn load_cold_terminal_replay(
    state_dir: &Path,
    policy: household_rs::KeyBackingPolicy,
) -> Result<Option<ColdTerminalRecovery>, InstallCliError> {
    let guard = acquire_install_lifecycle_exclusive(state_dir).await?;
    crate::handlers_pair_machine::recover_candidate_install_under_lifecycle(
        state_dir, &guard, policy,
    )
    .await
    .map_err(InstallCliError::Other)?;
    let loaded =
        household_rs::bootstrap::try_load_existing_under_lifecycle(&guard, state_dir, policy)?;
    let Some(loaded) = loaded else {
        return Ok(None);
    };
    let bootstrap = household_rs::bootstrap_state::load(state_dir).map_err(|error| {
        InstallCliError::Other(format!(
            "failed to read cold-replay bootstrap state: {error}"
        ))
    })?;
    let active_terminal = household_rs::household_install_transaction::load_active_finalize_terminal_result_under_lifecycle(&guard)
        .map_err(|error| InstallCliError::Other(format!("failed to inspect retained finalize result: {error}")))?;
    if let Some(terminal) = active_terminal.as_ref()
        && (loaded.record.hh_id != *terminal.hh_id() || loaded.cert.m_id != *terminal.m_id())
    {
        return Err(InstallCliError::Other(
            "retained finalize result differs from the installed local identity".into(),
        ));
    }
    if active_terminal.is_none() {
        return Err(InstallCliError::Other(format!(
            "this machine is already a member of household {} ({}); refusing to mint a candidate keypair",
            loaded.record.name, loaded.record.hh_id
        )));
    }
    if !matches!(
        bootstrap,
        household_rs::bootstrap_state::BootstrapState::PairMachineInstallRestartRequired
            | household_rs::bootstrap_state::BootstrapState::Ready
    ) {
        return Err(InstallCliError::Other(format!(
            "retained pair-machine terminal result has invalid bootstrap state {}",
            bootstrap.as_str()
        )));
    }
    let delivery =
        household_rs::household_install_transaction::load_finalize_ack_delivery_under_lifecycle(
            &guard,
        )
        .map_err(|error| {
            InstallCliError::Other(format!(
                "failed to inspect finalize delivery boundary: {error}"
            ))
        })?;
    match (&bootstrap, &delivery, active_terminal.as_ref()) {
        (
            household_rs::bootstrap_state::BootstrapState::Ready,
            household_rs::household_install_transaction::FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(delivered),
            Some(active),
        ) if delivered.as_ref() == active => {}
        (
            household_rs::bootstrap_state::BootstrapState::PairMachineInstallRestartRequired,
            household_rs::household_install_transaction::FinalizeAckDeliveryRecoveryOutcome::Absent,
            Some(_),
        ) => {}
        (
            household_rs::bootstrap_state::BootstrapState::PairMachineInstallRestartRequired,
            household_rs::household_install_transaction::FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(delivered),
            Some(active),
        ) if delivered.as_ref() == active => {}
        _ => {
            return Err(InstallCliError::Other(
                "bootstrap state and exact finalize delivery boundary diverged".into(),
            ));
        }
    }
    // Validate the exact listener coordinate before replacing this process.
    // The daemon repeats this check under its own startup lifecycle guard and
    // owns the current-generation PairMachineWindow plus supervised listener.
    let (addr, _) = crate::handlers_pair_machine::exact_terminal_replay_endpoint(
        active_terminal
            .as_ref()
            .expect("active terminal was checked above"),
    )
    .map_err(InstallCliError::Other)?;
    addr.parse::<SocketAddr>().map_err(|error| {
        InstallCliError::Other(format!("terminal replay address is invalid: {error}"))
    })?;
    Ok(Some(ColdTerminalRecovery::ReadyForDaemon))
}

async fn run_pair_machine(
    state_dir: &Path,
    transport: JoinTransport,
    hostname_label: Option<&str>,
    policy: household_rs::KeyBackingPolicy,
) -> i32 {
    // A successful G0 install re-execs this exact CLI invocation. Detect the
    // retained G1 result before platform, hostname, clock, or interface
    // discovery. Cold replay must never require a currently discoverable
    // interface and must never mint a second key, window, or QR.
    match load_cold_terminal_replay(state_dir, policy).await {
        Ok(Some(ColdTerminalRecovery::ReadyForDaemon)) => {
            return launch_daemon_for_cold_terminal(cold_exec_daemon_current_process);
        }
        Ok(None) => {}
        Err(error) => return report_install_error(error),
    }

    // Resolve a reachable address for the requested transport.
    let port: u16 = crate::household_bootstrap::household_port_from_env();
    let Some(addr) = pick_addr_for_transport(transport, port) else {
        eprintln!(
            "error: no {} interface address available; \
             cannot advertise a reachable candidate addr.",
            match transport {
                JoinTransport::Tailscale => "Tailscale (100.64.0.0/10 or fd7a:115c:a1e0::/48)",
                JoinTransport::Lan => "LAN (192.168/10/172.16-31)",
            }
        );
        return 1;
    };

    let Some(platform) = Platform::detect() else {
        eprintln!("error: unsupported platform: {}", std::env::consts::OS);
        return 1;
    };

    let raw_hostname = hostname_label.map_or_else(
        || gethostname::gethostname().to_string_lossy().into_owned(),
        str::to_owned,
    );
    let hostname = sanitize_hostname(&raw_hostname);
    if hostname.is_empty() || hostname.len() > 64 {
        eprintln!(
            "error: hostname must be 1..=64 ASCII host-label bytes after sanitization \
             (got {} bytes from {raw_hostname:?})",
            hostname.len()
        );
        return 2;
    }

    let Ok(now_unix) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
    else {
        eprintln!("error: system clock is before unix epoch");
        return 1;
    };

    let opts = PrepareCandidateOpts {
        state_dir: state_dir.to_path_buf(),
        transport,
        addr: addr.clone(),
        hostname,
        platform,
        policy,
        // Pair-machine ceremony TTL. Same owner/rationale as
        // `THEYOS_PAIR_DEVICE_TTL_SECS` above: prod default 5 min, operator-override
        // env var for e2e validation walks that exceed the production budget (Mac
        // engine listener + iPhone owner Face ID approval can collectively burn
        // >5 min during manual / appium-driven sessions).
        ttl: Duration::from_secs(crate::household_bootstrap::pair_window_ttl_secs_from_env(
            "THEYOS_PAIR_MACHINE_TTL_SECS",
        )),
        now_unix,
    };

    // The candidate's key material and persistent window are one lifecycle
    // transaction. Address/platform/hostname discovery happened above; the
    // guard is released before mDNS probing, QR rendering, listener bind, or
    // the ceremony long-poll below.
    let prepared_transaction: Result<_, InstallCliError> = async {
        let guard = acquire_install_lifecycle_exclusive(state_dir).await?;
        if let Some(loaded) = household_rs::bootstrap::try_load_existing_under_lifecycle(
            &guard, state_dir, policy,
        )? {
            return Err(InstallCliError::Other(format!(
                "this machine is already a member of household {} ({}); refusing to mint a candidate keypair",
                loaded.record.name, loaded.record.hh_id
            )));
        }
        let window = PairMachineWindow::with_persistence_under_lifecycle(
            state_dir.to_path_buf(),
            &guard,
        )
        .map_err(|error| {
            InstallCliError::Other(format!(
                "failed to load pair-machine window state: {error}"
            ))
        })?;
        let prepared = prepare_candidate_under_lifecycle(&window, opts, &guard)
            .await
            .map_err(|error| {
                InstallCliError::Other(format!(
                    "failed to prepare candidate keypair / JoinRequest: {error}"
                ))
            })?;
        drop(guard);
        Ok((window, prepared))
    }
    .await;
    let (window, prepared) = match prepared_transaction {
        Ok(prepared) => prepared,
        Err(error) => return report_install_error(error),
    };
    let lan_discovery_unavailable =
        transport == JoinTransport::Lan && !probe_mdns_available().await;

    let uri = prepared
        .join_request
        .to_pair_machine_uri_with_anchor(prepared.ttl_unix, &prepared.anchor_secret);

    info!(
        stage = "pair_machine_window.opened",
        source = "install",
        m_id = %prepared.m_id,
        transport = match transport {
            JoinTransport::Tailscale => "tailscale",
            JoinTransport::Lan => "lan",
        },
        ttl_unix = prepared.ttl_unix,
        fingerprint = %prepared.fingerprint,
    );

    let qr = match household_rs::qr_render::render_ansi_qr(&uri) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to render pair-machine QR: {e}");
            eprintln!("URI: {uri}");
            return 1;
        }
    };

    // Wrap the window in `Arc` so it can be shared with the listener and
    // the Bonjour publisher.
    let window = Arc::new(window);

    // Spawn the pre-household HTTP listener (B3). The candidate has no
    // household identity yet, so we cannot mount the regular household
    // stack — only `local/seed` and `local/finalize` are exposed. The
    // listener runs over plain HTTP because confidentiality is provided
    // by the Tailscale/LAN underlay (see B2 docstring on
    // `local_finalize_url`); the `JoinResponse` is signed under M1's
    // `m_priv` and verified at finalize time, and the trust anchor for
    // `hh_pub` is delivered out-of-band by the iPhone (B7,
    // `contracts/local-anchor.md`).
    let bind_addr: SocketAddr = match addr.parse() {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("error: candidate addr {addr:?} is not a valid SocketAddr: {e}");
            return 1;
        }
    };
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: failed to bind pre-household listener on {bind_addr}: {e}");
            return 1;
        }
    };
    let (runtime_signal, mut runtime_signal_rx) =
        tokio::sync::watch::channel(PreHouseholdRuntimeSignal::Running);
    let router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: state_dir.to_path_buf(),
        key_policy: policy,
        // The CLI install path has no daemon bootstrap state machine. The
        // dedicated runtime signal is the only success notification allowed
        // to escape after terminal G0→G1 rotation.
        bootstrap: None,
        runtime_signal: Some(runtime_signal),
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let mut listener_handle = tokio::spawn(async move {
        if let Err(e) =
            core_rs::phase0_axum_serve!(listener, router, connect_info = std::net::SocketAddr)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
        {
            warn!(stage = "pair_machine.listener_exited", error = %e);
        }
    });

    // Publish Bonjour for LAN auto-discovery (B8). For Tailscale joins
    // the iPhone scans the QR directly; the Bonjour publisher gracefully
    // degrades to a no-op when `mDNS` is unreachable and is otherwise
    // safe to leave running on Tailscale-only networks (mDNS just won't
    // be observed).
    let publish_targets = enumerate_bind_targets()
        .into_iter()
        .filter(|(_, class)| *class != InterfaceClass::Loopback)
        .collect::<Vec<_>>();
    let bonjour_handle = match publish_candidate_joiner_bonjour(
        PublishParams {
            // Empty `hh_id` / `hh_name` / `m_id` → `base_txt` skips
            // those keys, producing the protocol-§13 joiner shape.
            hh_id: String::new(),
            hh_name: String::new(),
            m_id: String::new(),
            port: bind_addr.port(),
            host_label: prepared.m_id.to_string(),
            host_dns: gethostname::gethostname().to_string_lossy().into_owned(),
            // Joiner announcements carry no household engine to dial.
            tailnet_addr: None,
            pair_machine_role: Some(PairMachineBonjourRole::Joiner),
            owner_display_name: String::new(),
            device_count: 0,
            bootstrap_state: String::new(),
        },
        Arc::clone(&window),
        publish_targets,
    )
    .await
    {
        Ok(h) => Some(h),
        Err(e) => {
            warn!(
                stage = "pair_machine.bonjour_publish_failed",
                error = %e,
                hint = "candidate falls back to QR-only path",
            );
            None
        }
    };

    println!();
    println!("This machine wants to join an existing household.");
    println!();
    println!("Verify these six words match what your iPhone shows before approving:");
    println!();
    println!("    {}", prepared.fingerprint);
    println!();
    println!("Scan with Soyeht on the household owner's iPhone within 5 minutes:");
    println!();
    if let Some(prompt) = lan_fallback_prompt(lan_discovery_unavailable) {
        println!("{prompt}");
        println!();
    }
    print!("{qr}");
    println!();
    println!("URI: {uri}");
    println!();
    println!("Listening on {bind_addr} for the founder's join-finalize request…");
    println!();

    // The successful install commit rotates the lifecycle from G0 to G1.
    // This process still owns G0-scoped handles, so success is communicated on
    // a dedicated control-plane channel rather than by mutating the stale
    // PairMachineWindow to Committed.
    let outcome =
        wait_for_window_terminal(&window, &mut runtime_signal_rx, prepared.ttl_unix).await;

    // Tear down the publisher first so peers see the goodbye records. Then
    // stop accepting new connections but let the in-flight terminal response
    // drain completely; aborting here can cut the typed 503/Ack body after the
    // handler has already committed its durable state.
    if let Some(h) = bonjour_handle {
        h.shutdown().await;
    }
    let _ = shutdown_tx.send(());
    if tokio::time::timeout(PRE_HOUSEHOLD_DRAIN_TIMEOUT, &mut listener_handle)
        .await
        .is_err()
    {
        listener_handle.abort();
        let _ = listener_handle.await;
        eprintln!("error: pre-household listener did not drain the terminal response in time");
        return 1;
    }

    match outcome {
        PairMachineWaitOutcome::RestartRequired => {
            println!();
            println!("Household installation committed. Restarting the service is required.");
            println!();
            info!(
                stage = "pair_machine.restart_required",
                "terminal G1 result is durable; all G0 capabilities have been dropped"
            );
            let error = cold_reexec_current_process();
            tracing::error!(
                stage = "pair_machine.cold_reexec_failed",
                error = %error,
                "terminal result remains fail-stop; refusing a successful install exit"
            );
            eprintln!("error: failed to cold-restart the install process: {error}");
            1
        }
        PairMachineWaitOutcome::AckDelivered => 0,
        PairMachineWaitOutcome::Failed => 1,
    }
}

/// Wait until the install rotates to G1 and requests a cold restart, the
/// candidate window aborts, or its wall-clock TTL expires.
async fn wait_for_window_terminal(
    window: &PairMachineWindow,
    runtime_signal: &mut tokio::sync::watch::Receiver<PreHouseholdRuntimeSignal>,
    ttl_unix: u64,
) -> PairMachineWaitOutcome {
    let mut rx = window.subscribe();
    loop {
        match *runtime_signal.borrow() {
            PreHouseholdRuntimeSignal::RestartRequired => {
                return PairMachineWaitOutcome::RestartRequired;
            }
            PreHouseholdRuntimeSignal::AckDeliveryStarted => {
                return PairMachineWaitOutcome::AckDelivered;
            }
            PreHouseholdRuntimeSignal::Running => {}
        }
        let snap = window.snapshot().await;
        match snap.state {
            PairMachineState::Committed => {
                eprintln!();
                eprintln!(
                    "error: stale G0 window reported Committed without a durable restart signal."
                );
                return PairMachineWaitOutcome::Failed;
            }
            PairMachineState::Aborted => {
                eprintln!();
                eprintln!("error: ceremony aborted (owner declined or TTL expired).");
                return PairMachineWaitOutcome::Failed;
            }
            _ => {}
        }
        // Compute remaining time-to-live and gate on whichever fires
        // first: a state change or the absolute expiry.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(Duration::from_secs(0), |d| d);
        let now_secs = now.as_secs();
        if now_secs >= ttl_unix {
            eprintln!();
            eprintln!("error: ceremony timed out (TTL elapsed before the founder approved).");
            return PairMachineWaitOutcome::Failed;
        }
        let until_expiry = Duration::from_secs(ttl_unix - now_secs);
        tokio::select! {
            biased;
            changed = runtime_signal.changed() => {
                if changed.is_err() {
                    eprintln!();
                    eprintln!("error: restart signal channel closed unexpectedly.");
                    return PairMachineWaitOutcome::Failed;
                }
            }
            changed = rx.changed() => {
                if changed.is_err() {
                    // Sender dropped — window state can no longer
                    // change. Treat as an internal abort.
                    eprintln!();
                    eprintln!("error: window state channel closed unexpectedly.");
                    return PairMachineWaitOutcome::Failed;
                }
            }
            () = tokio::time::sleep(until_expiry) => {
                eprintln!();
                eprintln!("error: ceremony timed out (TTL elapsed before the founder approved).");
                return PairMachineWaitOutcome::Failed;
            }
        }
    }
}

/// Sanitize an OS hostname to the host-label charset
/// (`[A-Za-z0-9.-]`). Replaces every other byte with `-` and lowercases.
/// Truncates to 64 bytes if the OS hostname is longer.
pub(crate) fn sanitize_hostname(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    // Trim leading/trailing dots and dashes — RFC 1123 hostname labels
    // forbid those at boundaries.
    while out.starts_with('-') || out.starts_with('.') {
        out.remove(0);
    }
    while out.ends_with('-') || out.ends_with('.') {
        out.pop();
    }
    if out.len() > 64 {
        out.truncate(64);
        // After truncation, retrim trailing chars.
        while out.ends_with('-') || out.ends_with('.') {
            out.pop();
        }
    }
    out
}

pub(crate) fn pick_addr_for_transport(transport: JoinTransport, port: u16) -> Option<String> {
    let want = match transport {
        JoinTransport::Tailscale => InterfaceClass::Tailscale,
        JoinTransport::Lan => InterfaceClass::Lan,
    };
    enumerate_bind_targets()
        .into_iter()
        .find(|(_, class)| *class == want)
        .map(|(ip, _)| format_addr(ip, port))
}

pub(crate) fn format_addr(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

pub(crate) async fn probe_mdns_available() -> bool {
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(|| {
            let daemon = ServiceDaemon::new()?;
            let receiver = daemon.browse(SOYEHT_HOUSEHOLD_SERVICE)?;
            drop(receiver);
            let _ = daemon.stop_browse(SOYEHT_HOUSEHOLD_SERVICE);
            let _ = daemon.shutdown();
            Ok::<(), mdns_sd::Error>(())
        }),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .is_some_and(|result| result.is_ok())
}

fn lan_fallback_prompt(lan_discovery_unavailable: bool) -> Option<&'static str> {
    lan_discovery_unavailable.then_some("LAN discovery unavailable - scan the QR with your iPhone.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lifecycle_recovery_refuses_the_stale_install_invocation() {
        let state_dir = tempfile::tempdir().unwrap();
        household_rs::bootstrap_or_load(
            state_dir.path(),
            household_rs::BootstrapOpts {
                household_name: "Interrupted Install".into(),
                hostname_label: Some("interrupted-install".into()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap identity");

        let guard = acquire_install_lifecycle_exclusive(state_dir.path())
            .await
            .unwrap();
        assert!(guard.rename_household_to_tearing_down().unwrap());
        drop(guard);

        let error = acquire_install_lifecycle_exclusive(state_dir.path())
            .await
            .unwrap_err();
        assert!(
            matches!(error, InstallCliError::Other(message) if message.contains("refusing this stale install invocation"))
        );
        assert!(!state_dir.path().join("household").exists());
        assert!(!state_dir.path().join("household.tearing-down").exists());
    }

    #[tokio::test]
    async fn cold_replay_uses_only_the_exact_persisted_join_request_address() {
        use axum::{body::to_bytes, extract::State};
        use household_rs::pair_machine::{
            CeremonyInputs, CeremonyTxn, JoinResponseUnsigned, PeerEntry, join_request_hash,
        };
        use serde_bytes::ByteBuf;
        use zeroize::Zeroizing;

        core_rs::env::set_test_env("THEYOS_FORCE_SOFTWARE_KEYS", "1");
        let founder_dir = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let address_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let exact_socket = address_probe.local_addr().unwrap();
        drop(address_probe);
        let exact_address = exact_socket.to_string();
        let founder = household_rs::bootstrap_or_load(
            founder_dir.path(),
            household_rs::BootstrapOpts {
                household_name: "Cold replay founder".into(),
                hostname_label: Some("cold-replay-founder".into()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();

        let guard = acquire_install_lifecycle_exclusive(state_dir.path())
            .await
            .unwrap();
        let window = Arc::new(
            PairMachineWindow::with_persistence_under_lifecycle(
                state_dir.path().to_path_buf(),
                &guard,
            )
            .unwrap(),
        );
        let g0 = window.snapshot().await.lifecycle_generation.unwrap();
        let prepared = prepare_candidate_under_lifecycle(
            &window,
            PrepareCandidateOpts {
                state_dir: state_dir.path().to_path_buf(),
                transport: JoinTransport::Lan,
                addr: exact_address.clone(),
                hostname: "cold-replay".into(),
                platform: Platform::LinuxNix,
                policy: household_rs::KeyBackingPolicy::ForceSoftware,
                ttl: Duration::from_secs(300),
                now_unix: 1_800_000_000,
            },
            &guard,
        )
        .await
        .unwrap();
        drop(guard);

        let txn = CeremonyTxn::prepare(CeremonyInputs {
            hh_priv: Zeroizing::new(
                *founder
                    .hh_priv
                    .as_ref()
                    .and_then(|key| key.as_software_secret())
                    .unwrap(),
            ),
            hh_id: founder.record.hh_id.clone(),
            hh_pub_sec1: *founder.record.hh_pub.as_bytes(),
            m1_priv_scalar: Zeroizing::new(*founder.m_priv.as_software_secret().unwrap()),
            m1_pub_sec1: *founder.cert.m_pub.as_bytes(),
            m1_id: founder.cert.m_id.to_string(),
            candidate_m_pub_sec1: prepared.m_pub_sec1,
            candidate_hostname: prepared.join_request.hostname.clone(),
            candidate_platform: prepared.join_request.platform.clone(),
            joined_at: 1_800_000_001,
            state_dir: founder_dir.path().to_path_buf(),
            existing_record: founder.record.clone(),
            policy: household_rs::KeyBackingPolicy::ForceSoftware,
        })
        .unwrap();
        let join_response = JoinResponseUnsigned {
            version: 1,
            join_request_hash: ByteBuf::from(
                join_request_hash(&prepared.join_request_cbor).to_vec(),
            ),
            machine_cert: txn.candidate_cert().clone(),
            encrypted_shard: txn.peer_encrypted_shard().clone(),
            household_record: txn.new_household_record().clone(),
            peer_list: vec![PeerEntry {
                m_id: founder.cert.m_id.to_string(),
                m_pub: ByteBuf::from(founder.cert.m_pub.as_bytes().to_vec()),
                hostname: founder.cert.hostname.clone(),
                tailscale_addr: None,
                machine_cert: Some(founder.cert.clone()),
            }],
            push_token_seed: None,
        }
        .sign(founder.m_priv.as_ref())
        .unwrap();
        let join_response_bytes = join_response.to_canonical_bytes().unwrap();
        window
            .pin_household_anchor(
                founder.record.hh_id.to_string(),
                *founder.record.hh_pub.as_bytes(),
            )
            .await
            .unwrap();

        let first = crate::handlers_pair_machine::local_finalize_handler(
            State(PreHouseholdRouterState {
                window: Arc::clone(&window),
                state_dir: state_dir.path().to_path_buf(),
                key_policy: household_rs::KeyBackingPolicy::ForceSoftware,
                bootstrap: None,
                runtime_signal: None,
            }),
            join_response_bytes.clone().into(),
        )
        .await;
        assert_eq!(first.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        to_bytes(first.into_body(), 65_536).await.unwrap();
        drop(window);

        // This is a real G0 committed install followed by the production
        // rotation and cold loader. No test mutates a snapshot into Committed.
        // RestartRequired must launch the ordinary daemon immediately: the
        // daemon's supervised terminal-only listener, not a 300-second CLI
        // wait, owns both the retained Ack and the Phase-3 outbox liveness.
        assert!(matches!(
            load_cold_terminal_replay(
                state_dir.path(),
                household_rs::KeyBackingPolicy::ForceSoftware,
            )
            .await
            .unwrap()
            .expect("active cold terminal replay"),
            ColdTerminalRecovery::ReadyForDaemon
        ));
        let guard = acquire_install_lifecycle_exclusive(state_dir.path())
            .await
            .unwrap();
        let cold_window = Arc::new(
            PairMachineWindow::with_persistence_under_lifecycle(
                state_dir.path().to_path_buf(),
                &guard,
            )
            .unwrap(),
        );
        let cold_snapshot = cold_window.snapshot().await;
        assert_eq!(cold_snapshot.state, PairMachineState::Idle);
        assert_ne!(cold_snapshot.lifecycle_generation.unwrap(), g0);
        drop(guard);

        // Model the daemon that starts immediately in RestartRequired. Its
        // exact listener remains available across the indistinguishable cut
        // where Ready persisted but the first Ack body was not drained. It
        // exposes only finalize, never the full household/LAN router.
        let bootstrap = Arc::new(tokio::sync::RwLock::new(
            household_rs::bootstrap_state::BootstrapState::PairMachineInstallRestartRequired,
        ));
        let (listener, terminal_router) =
            crate::household_bootstrap::bind_terminal_replay_listener(
                exact_socket,
                PreHouseholdRouterState {
                    window: Arc::clone(&cold_window),
                    state_dir: state_dir.path().to_path_buf(),
                    key_policy: household_rs::KeyBackingPolicy::ForceSoftware,
                    bootstrap: Some(Arc::clone(&bootstrap)),
                    runtime_signal: None,
                },
            )
            .await
            .unwrap();
        let shutdown_state_dir = state_dir.path().to_path_buf();
        let shutdown_bootstrap = Arc::clone(&bootstrap);
        let server = tokio::spawn(async move {
            core_rs::phase0_axum_serve!(
                listener,
                terminal_router,
                connect_info = std::net::SocketAddr
            )
            .with_graceful_shutdown(
                crate::household_bootstrap::wait_until_terminal_replay_is_inactive(
                    shutdown_state_dir,
                    exact_socket,
                    JoinTransport::Lan,
                    shutdown_bootstrap,
                ),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::new();
        crate::failure_injection::arm(
            crate::failure_injection::InjectionPoint::M2AfterAckDeliveryBreadcrumb,
            crate::failure_injection::InjectionAction::early_reject(
                "crash after durable delivery boundary",
            ),
        );
        let pre_flush_cut = client
            .post(format!("http://{exact_socket}/pair-machine/local/finalize"))
            .header("content-type", "application/cbor")
            .body(join_response_bytes.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(pre_flush_cut.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(
            *bootstrap.read().await,
            household_rs::bootstrap_state::BootstrapState::PairMachineInstallRestartRequired
        );
        let delivery_guard = acquire_install_lifecycle_exclusive(state_dir.path())
            .await
            .unwrap();
        let active = household_rs::household_install_transaction::load_active_finalize_terminal_result_under_lifecycle(&delivery_guard)
            .unwrap()
            .unwrap();
        assert!(matches!(
            household_rs::household_install_transaction::load_finalize_ack_delivery_under_lifecycle(&delivery_guard)
                .unwrap(),
            household_rs::household_install_transaction::FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(ref retained)
                if retained.as_ref() == &active
        ));
        drop(delivery_guard);

        crate::failure_injection::arm(
            crate::failure_injection::InjectionPoint::M2BeforeAckEncode,
            crate::failure_injection::InjectionAction::early_reject(
                "crash after durable Ready before body",
            ),
        );
        let post_ready_pre_body_cut = client
            .post(format!("http://{exact_socket}/pair-machine/local/finalize"))
            .header("content-type", "application/cbor")
            .body(join_response_bytes.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            post_ready_pre_body_cut.status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            *bootstrap.read().await,
            household_rs::bootstrap_state::BootstrapState::Ready
        );

        let replay = client
            .post(format!("http://{exact_socket}/pair-machine/local/finalize"))
            .header("content-type", "application/cbor")
            .body(join_response_bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), reqwest::StatusCode::OK);
        let retained_ack =
            household_rs::pair_machine::FinalizeAck::for_machine_cert(&join_response.machine_cert)
                .unwrap()
                .to_canonical_bytes()
                .unwrap();
        assert_eq!(
            replay.bytes().await.unwrap().as_ref(),
            retained_ack.as_slice()
        );
        let post_flush_guard = acquire_install_lifecycle_exclusive(state_dir.path())
            .await
            .unwrap();
        assert!(matches!(
            household_rs::household_install_transaction::load_finalize_ack_delivery_under_lifecycle(&post_flush_guard)
                .unwrap(),
            household_rs::household_install_transaction::FinalizeAckDeliveryRecoveryOutcome::MayHaveTakenEffect(_)
        ), "a completed local HTTP write is still not proof that the peer processed the Ack");
        drop(post_flush_guard);
        assert!(matches!(
            load_cold_terminal_replay(
                state_dir.path(),
                household_rs::KeyBackingPolicy::ForceSoftware,
            )
            .await
            .unwrap()
            .unwrap(),
            ColdTerminalRecovery::ReadyForDaemon
        ));
        assert_eq!(
            client
                .get(format!("http://{exact_socket}/pair-machine/local/seed"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            client
                .get(format!("http://{exact_socket}/identity"))
                .send()
                .await
                .unwrap()
                .status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        *bootstrap.write().await = household_rs::bootstrap_state::BootstrapState::Uninitialized;
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn cold_terminal_launches_an_argument_free_daemon_that_is_reachable() {
        use std::io::{Read as _, Write as _};

        let command = daemon_exec_command(Path::new("/test/theyos"));
        assert!(
            command.get_args().next().is_none(),
            "daemon exec must not inherit install --pair-machine arguments"
        );

        let (addr_tx, addr_rx) = std::sync::mpsc::sync_channel(1);
        let rc = launch_daemon_for_cold_terminal(move || {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            addr_tx.send(listener.local_addr().unwrap()).unwrap();
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream.write_all(b"daemon-ready").unwrap();
            });
            // A real exec never returns. Returning here deliberately exercises
            // the production fail-stop branch after proving the launch hook
            // established a reachable terminal listener.
            std::io::Error::other("test launcher returned")
        });
        assert_eq!(rc, 1);
        let addr = addr_rx.recv().unwrap();
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"daemon-ready");
    }

    #[test]
    fn sanitize_hostname_lowercases_and_strips() {
        assert_eq!(sanitize_hostname("Studio Linux"), "studio-linux");
        assert_eq!(sanitize_hostname("studio.local"), "studio.local");
        assert_eq!(sanitize_hostname("--studio--"), "studio");
        assert_eq!(sanitize_hostname("STUDIO_LINUX!"), "studio-linux");
    }

    #[test]
    fn sanitize_hostname_truncates_at_64() {
        let long = "a".repeat(80);
        let s = sanitize_hostname(&long);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c == 'a'));
    }

    #[test]
    fn format_addr_v4_v6() {
        assert_eq!(
            format_addr("100.1.2.3".parse().unwrap(), 8091),
            "100.1.2.3:8091"
        );
        assert_eq!(
            format_addr("fd7a:115c:a1e0::1".parse().unwrap(), 8091),
            "[fd7a:115c:a1e0::1]:8091"
        );
    }

    #[test]
    fn lan_fallback_prompt_is_qr_only_copy() {
        assert_eq!(
            lan_fallback_prompt(true),
            Some("LAN discovery unavailable - scan the QR with your iPhone.")
        );
        assert_eq!(lan_fallback_prompt(false), None);
    }

    // A throwaway, deterministic household public key for URI-render tests.
    // 33-byte SEC1 compressed point; bootstrap a software-keyed identity in a
    // tempdir to obtain a valid `P256PublicKey` without touching the network.
    /// Stand-in for a validated machine cert fingerprint. These tests are
    /// about host/URI shape, not provenance — the real callers derive this
    /// from `loaded.cert`.
    const TEST_M_CERT_FP: [u8; 32] = [0x5au8; 32];

    fn test_hh_pub() -> P256PublicKey {
        let td = tempfile::tempdir().unwrap();
        let loaded = household_rs::bootstrap_or_load(
            td.path(),
            household_rs::BootstrapOpts {
                household_name: "Reissue Test Home".into(),
                hostname_label: Some("reissue-test".into()),
            },
            household_rs::KeyBackingPolicy::ForceSoftware,
        )
        .expect("bootstrap");
        loaded.record.hh_pub.clone()
    }

    #[tokio::test]
    async fn mint_pair_device_uri_includes_host_when_some() {
        let state_dir = tempfile::tempdir().unwrap();
        let hh_pub = test_hh_pub();
        let guard = acquire_install_lifecycle_exclusive(state_dir.path())
            .await
            .unwrap();
        let (uri, expires_at_unix) = mint_pair_device_uri(
            &guard,
            state_dir.path(),
            &hh_pub,
            Some("Reissue Test Home"),
            Some("192.0.2.10:8091".to_string()),
            &TEST_M_CERT_FP,
        )
        .await
        .expect("mint");

        assert!(
            uri.starts_with("soyeht://household/pair-device?"),
            "uri={uri}"
        );
        assert!(uri.contains("v=1"), "uri={uri}");
        assert!(uri.contains("&hh_pub="), "uri={uri}");
        assert!(uri.contains("&nonce="), "uri={uri}");
        assert!(uri.contains("&ttl="), "uri={uri}");
        // host is percent-encoded (the ':' is preserved per the encoder).
        assert!(
            uri.contains("&host=192.0.2.10:8091"),
            "host fallback must be present: uri={uri}"
        );

        // expires_at_unix matches the current generation-scoped snapshot.
        // The legacy unscoped storage path is intentionally never consulted.
        let window = PairDeviceWindow::with_persistence_under_lifecycle(
            state_dir.path().to_path_buf(),
            &guard,
        )
        .expect("open current pair-device namespace");
        let snap = window
            .read_persisted_snapshot_under_lifecycle(&guard)
            .expect("read snapshot")
            .expect("snapshot present");
        assert_eq!(snap.expires_at_unix, expires_at_unix);
    }

    #[tokio::test]
    async fn mint_pair_device_uri_omits_host_when_none() {
        let state_dir = tempfile::tempdir().unwrap();
        let hh_pub = test_hh_pub();
        let guard = acquire_install_lifecycle_exclusive(state_dir.path())
            .await
            .unwrap();
        let (uri, _expires) = mint_pair_device_uri(
            &guard,
            state_dir.path(),
            &hh_pub,
            Some("Reissue Test Home"),
            None,
            &TEST_M_CERT_FP,
        )
        .await
        .expect("mint");
        assert!(
            !uri.contains("&host="),
            "host must be omitted when None: uri={uri}"
        );
        assert!(uri.contains("v=1") && uri.contains("&nonce="), "uri={uri}");
    }

    #[tokio::test]
    async fn pair_device_mint_rejects_a_guard_for_another_state_root() {
        let guarded_state = tempfile::tempdir().unwrap();
        let target_state = tempfile::tempdir().unwrap();
        let hh_pub = test_hh_pub();
        let guard = acquire_install_lifecycle_exclusive(guarded_state.path())
            .await
            .unwrap();

        let error = mint_pair_device_uri(
            &guard,
            target_state.path(),
            &hh_pub,
            Some("Wrong Root"),
            None,
            &TEST_M_CERT_FP,
        )
        .await
        .unwrap_err();

        assert!(error.contains("lifecycle binding changed"));
        assert!(
            !household_rs::storage::pair_device_window_path(target_state.path()).exists(),
            "a mismatched lifecycle guard must reject before publishing a window"
        );
    }
}
