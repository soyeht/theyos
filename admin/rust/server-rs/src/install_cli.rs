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
use crate::handlers_pair_machine::{PreHouseholdRouterState, pre_household_router};
use crate::household_bootstrap::resolve_household_state_dir;
use crate::household_listener::{InterfaceClass, enumerate_bind_targets};
use household_rs::keys::P256PublicKey;
use household_rs::machine_cert::Platform;
use household_rs::pair_device::PairDeviceWindow;
use household_rs::pair_machine::{
    JoinTransport, PairMachineState, PairMachineWindow, PrepareCandidateOpts, prepare_candidate,
};
use mdns_sd::ServiceDaemon;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tracing::{info, warn};

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
        return match household_rs::try_load_existing(&state_dir, key_policy) {
            Ok(Some(loaded)) => {
                emit_fresh_pair_device_window(
                    &state_dir,
                    &loaded.record.hh_pub,
                    Some(&loaded.record.name),
                )
                .await
            }
            Ok(None) => {
                eprintln!(
                    "error: --reissue-pair-qr requires an already-bootstrapped install. \
                    Run `theyos install --household-name <name>` first."
                );
                1
            }
            Err(e) => {
                household_rs::bootstrap::log_error(&e);
                1
            }
        };
    }

    match household_rs::try_load_existing(&state_dir, key_policy) {
        Ok(Some(_loaded)) => 0,
        Ok(None) => {
            let Some(name) = household_name else {
                eprintln!(
                    "error: fresh install requires --household-name <name>. \
                    Re-run as `theyos install --household-name \"Sample Home\"`."
                );
                return 2;
            };
            if let Some(label) = &hostname_label {
                if label.is_empty() || label.len() > 255 {
                    eprintln!(
                        "error: --hostname-label must be 1..=255 bytes (got {} bytes)",
                        label.len()
                    );
                    return 2;
                }
            }
            let opts = household_rs::BootstrapOpts {
                household_name: name,
                hostname_label,
            };
            match household_rs::bootstrap_or_load(&state_dir, opts, key_policy) {
                Ok(loaded) => {
                    info!(
                        stage = "bootstrap.complete",
                        hh_id = %loaded.record.hh_id,
                        name = %loaded.record.name,
                    );
                    emit_fresh_pair_device_window(
                        &state_dir,
                        &loaded.record.hh_pub,
                        Some(&loaded.record.name),
                    )
                    .await
                }
                Err(e) => {
                    household_rs::bootstrap::log_error(&e);
                    1
                }
            }
        }
        Err(e) => {
            household_rs::bootstrap::log_error(&e);
            1
        }
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

/// Mint a fresh pair-receiving window, persist it via `PairDeviceWindow`, and
/// render the QR to stdout. Returns a process exit code (0 on success,
/// 1 on render failure).
async fn emit_fresh_pair_device_window(
    state_dir: &Path,
    hh_pub: &P256PublicKey,
    household_name: Option<&str>,
) -> i32 {
    // Pair-device QR window TTL. Production default is 5 minutes — short enough
    // that a leaked QR doesn't sit valid in chat logs / screenshots for hours.
    // Operators running validation pass an override via THEYOS_PAIR_DEVICE_TTL_SECS
    // to handle manual / appium-driven walks (Welcome carousel + permission alerts +
    // Face ID) that routinely exceed the 5-minute window during e2e sessions. The
    // parse/clamp/default policy lives in one owner — see
    // household_bootstrap::pair_window_ttl_secs_from_env.
    let ttl_secs: u64 =
        crate::household_bootstrap::pair_window_ttl_secs_from_env("THEYOS_PAIR_DEVICE_TTL_SECS");
    let ttl = Duration::from_secs(ttl_secs);

    let window = PairDeviceWindow::with_persistence(state_dir.to_path_buf());
    let token = match window.mint_token(ttl, None).await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("error: failed to mint pair token: {e}");
            return 1;
        }
    };
    // Include a Tailnet host fallback in the URI so peers whose Bonjour
    // implementation does not interoperate with the engine's mDNS publisher
    // (observed cross-platform with `mdns-sd` 0.10/0.13 → macOS/iOS
    // NWBrowser) can connect directly. Bonjour discovery remains the gold
    // path when it works; the `host` field is consulted as a fallback only.
    let port: u16 = crate::household_bootstrap::household_port_from_env();
    let host_fallback =
        crate::tailnet_address::current_tailnet_ipv4().map(|ip| format!("{ip}:{port}"));
    let uri = token.to_uri_with_host_and_name(hh_pub, host_fallback.as_deref(), household_name);

    info!(
        stage = "pair_device_window.opened",
        source = "install",
        ttl_secs = ttl.as_secs(),
        expires_at_unix = token.expires_at_unix,
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
async fn run_pair_machine(
    state_dir: &Path,
    transport: JoinTransport,
    hostname_label: Option<&str>,
    policy: household_rs::KeyBackingPolicy,
) -> i32 {
    // Refuse to run as a candidate on a machine that already holds a
    // household identity. The Phase 3 candidate path mints fresh
    // identity material; allowing it on a machine that is already a
    // household member would invalidate the existing membership without
    // operator awareness.
    match household_rs::try_load_existing(state_dir, policy) {
        Ok(Some(loaded)) => {
            eprintln!(
                "error: this machine is already a member of household {} ({}). \
                 Refusing to mint a candidate keypair.",
                loaded.record.name, loaded.record.hh_id
            );
            return 1;
        }
        Ok(None) => {}
        Err(e) => {
            household_rs::bootstrap::log_error(&e);
            return 1;
        }
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

    let window = match PairMachineWindow::with_persistence(state_dir.to_path_buf()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: failed to load pair-machine window state: {e}");
            return 1;
        }
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

    let prepared = match prepare_candidate(&window, opts).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to prepare candidate keypair / JoinRequest: {e}");
            return 1;
        }
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
    let router = pre_household_router(PreHouseholdRouterState {
        window: Arc::clone(&window),
        state_dir: state_dir.to_path_buf(),
        key_policy: policy,
        // The CLI install path has no daemon bootstrap state machine —
        // the candidate process is itself the pre-household phase, so
        // `local_finalize_handler` falls through to its window-state
        // checks without an extra bootstrap-state revalidation.
        bootstrap: None,
    });
    let listener_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
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

    // Block until the window transitions to a terminal state (Committed
    // or Aborted), or the TTL expires.
    let exit_code = wait_for_window_terminal(&window, prepared.ttl_unix).await;

    // Tear down the publisher first so peers see the goodbye records,
    // then cancel the listener task.
    if let Some(h) = bonjour_handle {
        h.shutdown().await;
    }
    listener_handle.abort();
    let _ = listener_handle.await;

    if exit_code == 0 {
        println!();
        println!(
            "{}",
            crate::handlers_pair_machine::POST_COMMIT_REDUNDANCY_NOTICE
        );
        println!();
        info!(
            stage = "pair_machine.listener_swap",
            "candidate committed; starting household listener"
        );
        // Install CLI runs without a SharedState — skip mounting the
        // household-namespaced Claw Store routes here. Identity/snapshot/
        // pair-device/bootstrap remain available; the main daemon picks up
        // and provides Claws once it boots with full state.
        crate::household_bootstrap::bootstrap_household(None).await;
        info!(
            stage = "pair_machine.listener_swap",
            "household listener is now serving"
        );
        println!("Household listener is running. Press Ctrl-C to stop.");
        crate::shutdown::shutdown_signal().await;
    }
    exit_code
}

/// Wait until the candidate's `PairMachineWindow` reaches a terminal
/// state (Committed or Aborted) or its wall-clock TTL expires.
///
/// Returns 0 on a clean commit, 1 on Aborted / TTL expiry — the install
/// command's exit code surface for the caller (operator or NixOS module).
async fn wait_for_window_terminal(window: &PairMachineWindow, ttl_unix: u64) -> i32 {
    let mut rx = window.subscribe();
    loop {
        let snap = window.snapshot().await;
        match snap.state {
            PairMachineState::Committed => return 0,
            PairMachineState::Aborted => {
                eprintln!();
                eprintln!("error: ceremony aborted (owner declined or TTL expired).");
                return 1;
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
            return 1;
        }
        let until_expiry = Duration::from_secs(ttl_unix - now_secs);
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    // Sender dropped — window state can no longer
                    // change. Treat as an internal abort.
                    eprintln!();
                    eprintln!("error: window state channel closed unexpectedly.");
                    return 1;
                }
            }
            () = tokio::time::sleep(until_expiry) => {
                eprintln!();
                eprintln!("error: ceremony timed out (TTL elapsed before the founder approved).");
                return 1;
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
}
