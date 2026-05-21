//! Bonjour browsers for pair-machine discovery and setup-invitation observation.
//!
//! Two browsers are provided:
//! - [`spawn_bonjour_browser`] — founder-side `_soyeht-household._tcp.` browser
//!   for Phase 3 pair-machine discovery. Bonjour is only a discovery hint; the
//!   fetched `JoinRequest` is still verified and staged through the same
//!   owner-event path as the remote QR flow.
//! - [`spawn_setup_invitation_browser_with_cache`] — `_soyeht-setup._tcp.`
//!   observer that records discovered iPhone invitations into the bootstrap
//!   cache used by `POST /bootstrap/claim-setup-invitation`. Only
//!   Tailnet-sourced services are accepted by default (FR-015).
//!
//! I/O is delegated to [`crate::bonjour_impl_mdns_sd`] so a parallel
//! macOS-native backend (Apple's `dns_sd.h` system bridge) can be wired in
//! later without touching this facade.

use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use household_rs::pair_machine::{JoinRequest, PairMachineState};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

#[cfg(target_os = "macos")]
use crate::bonjour_impl_dns_sd as backend;
#[cfg(not(target_os = "macos"))]
use crate::bonjour_impl_mdns_sd as backend;
use crate::bonjour_trust::{BrowserConfig, should_emit_with_txt_hint};
use crate::handlers_pair_machine::{
    FounderStageError, FounderStageOutcome, JoinSource, PairMachineRouterState,
    founder_stage_join_request,
};
use crate::setup_invitation::{self, SetupInvitationCache};
use crate::time_util;

pub const SOYEHT_HOUSEHOLD_SERVICE: &str = "_soyeht-household._tcp.local.";
const SOYEHT_SETUP_SERVICE: &str = "_soyeht-setup._tcp.local.";
const LOCAL_SEED_TIMEOUT: Duration = Duration::from_secs(5);

/// One observed Bonjour announcement from a candidate machine M2 advertising
/// itself as `pair_role=joiner` per `docs/household-protocol.md` §13.
///
/// `hh_id` is `Option`al because the candidate has not yet joined any
/// household — the protocol mandates that the joiner publishes WITHOUT
/// `hh_id`. The previous implementation required `hh_id` and silently
/// dropped every conforming announcement; the founder browser now matches
/// the joiner by having the candidate fetch its own signed `JoinRequest`
/// (which carries `m_pub` and `nonce`) and verifying that against the
/// founder's local `hh_id`. The TXT-level `hh_id` field is treated as an
/// observability-only hint when present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinerAnnouncement {
    pub hh_id: Option<String>,
    pub addr: String,
    pub pair_nonce: String,
    pub m_pub_b32: Option<String>,
}

#[derive(Debug)]
pub enum BonjourBrowserError {
    ClockUnavailable,
    Fetch(String),
    Cbor(String),
    Stage(FounderStageError),
}

/// Start the production mDNS browser. The task exits once the household is no
/// longer a one-machine idle founder, or when the mDNS daemon closes.
#[must_use]
pub fn spawn_bonjour_browser(state: PairMachineRouterState) -> JoinHandle<()> {
    tokio::spawn(async move {
        if !browser_should_run(&state).await {
            return;
        }
        let handle = match backend::BrowserHandle::new() {
            Ok(handle) => handle,
            Err(e) => {
                warn!(
                    stage = "bonjour_browser.start_failed",
                    error = %e,
                );
                return;
            }
        };
        let stream = match handle.browse(SOYEHT_HOUSEHOLD_SERVICE) {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    stage = "bonjour_browser.browse_failed",
                    error = %e,
                );
                handle.shutdown();
                return;
            }
        };
        run_mdns_events(state, stream).await;
        handle.stop_browse(SOYEHT_HOUSEHOLD_SERVICE);
        handle.shutdown();
    })
}

/// Test hook: run the browser against a simulated mDNS event source.
#[must_use]
pub fn spawn_bonjour_browser_with_source(
    state: PairMachineRouterState,
    source: mpsc::Receiver<JoinerAnnouncement>,
) -> JoinHandle<()> {
    tokio::spawn(run_simulated_events(state, source))
}

async fn run_mdns_events(state: PairMachineRouterState, stream: backend::BrowseStream) {
    let mut window_rx = state.window.subscribe();
    let mut seen = HashSet::new();
    loop {
        tokio::select! {
            resolved = stream.next() => {
                let Some(resolved) = resolved else {
                    break;
                };
                let Some(announcement) = announcement_from_resolved(&resolved) else {
                    continue;
                };
                handle_announcement(&state, &mut seen, announcement).await;
            }
            changed = window_rx.changed() => {
                if changed.is_err() || !browser_should_run(&state).await {
                    info!(stage = "bonjour_browser.stopped", reason = "window_or_membership_changed");
                    break;
                }
            }
        }
    }
}

async fn run_simulated_events(
    state: PairMachineRouterState,
    mut source: mpsc::Receiver<JoinerAnnouncement>,
) {
    if !browser_should_run(&state).await {
        return;
    }
    let mut window_rx = state.window.subscribe();
    let mut seen = HashSet::new();
    loop {
        tokio::select! {
            announcement = source.recv() => {
                let Some(announcement) = announcement else {
                    break;
                };
                handle_announcement(&state, &mut seen, announcement).await;
            }
            changed = window_rx.changed() => {
                if changed.is_err() || !browser_should_run(&state).await {
                    break;
                }
            }
        }
    }
}

async fn handle_announcement(
    state: &PairMachineRouterState,
    seen: &mut HashSet<String>,
    announcement: JoinerAnnouncement,
) {
    match try_handle_announcement(state, seen, announcement).await {
        Ok(Some(FounderStageOutcome::Accepted(accepted))) => {
            info!(
                stage = "bonjour_browser.staged",
                owner_event_cursor = accepted.owner_event_cursor,
                expiry = accepted.expiry,
            );
        }
        Ok(Some(FounderStageOutcome::Replay(_))) => {
            info!(stage = "bonjour_browser.replay_returned");
        }
        Ok(None) => {}
        Err(e) => {
            warn!(
                stage = "bonjour_browser.rejected",
                error = ?e,
            );
        }
    }
}

async fn try_handle_announcement(
    state: &PairMachineRouterState,
    seen: &mut HashSet<String>,
    announcement: JoinerAnnouncement,
) -> Result<Option<FounderStageOutcome>, BonjourBrowserError> {
    let Some(identity) = state.household.current().await else {
        return Ok(None);
    };
    // The joiner's TXT MUST NOT carry `hh_id` per §13 (it has not joined
    // any household yet). When `hh_id` is observed (e.g., during a
    // protocol violation by an attacker spoofing `pair_role=joiner` on a
    // founder host), reject only if it is present AND mismatched. The
    // authoritative identity check happens after we fetch the signed
    // `JoinRequest` from `local/seed` — that body carries the candidate's
    // `m_pub` over which the owner verifies the fingerprint, and the
    // ceremony itself binds to our local `identity.record.hh_id`.
    if let Some(observed) = announcement.hh_id.as_deref() {
        if observed != identity.record.hh_id.as_str() {
            return Ok(None);
        }
    }
    let seen_key = format!("{}|{}", announcement.addr, announcement.pair_nonce);
    if !seen.insert(seen_key) {
        return Ok(None);
    }
    let body =
        fetch_join_request_cbor(announcement.addr.clone(), announcement.pair_nonce.clone()).await?;
    let request: JoinRequest = household_rs::cbor::from_canonical_slice(&body)
        .map_err(|e| BonjourBrowserError::Cbor(e.to_string()))?;
    log_m_pub_hint_mismatch(&announcement, &request);
    let now = time_util::unix_now_secs_checked("bonjour_browser.clock")
        .ok_or(BonjourBrowserError::ClockUnavailable)?;
    founder_stage_join_request(state, request, JoinSource::Bonjour, now)
        .await
        .map(Some)
        .map_err(BonjourBrowserError::Stage)
}

fn announcement_from_resolved(resolved: &backend::ResolvedService) -> Option<JoinerAnnouncement> {
    if resolved.service_type() != SOYEHT_HOUSEHOLD_SERVICE {
        return None;
    }
    if resolved.txt("pairing")? != "machine" {
        return None;
    }
    if resolved.txt("pair_role")? != "joiner" {
        return None;
    }
    // `hh_id` is intentionally optional — the candidate joiner publishes
    // without it per protocol §13. When some other publisher (e.g., an
    // already-paired founder serving the same service type) leaks `hh_id`,
    // we record it only as an observability hint.
    let hh_id = resolved.txt("hh_id").map(str::to_string);
    let pair_nonce = resolved.txt("pair_nonce")?.to_string();
    let m_pub_b32 = resolved.txt("m_pub_b32").map(str::to_string);
    let ip = preferred_addr(resolved.addresses())?;
    let addr = format_addr_for_https(ip, resolved.port());
    Some(JoinerAnnouncement {
        hh_id,
        addr,
        pair_nonce,
        m_pub_b32,
    })
}

fn preferred_addr(addrs: &HashSet<IpAddr>) -> Option<IpAddr> {
    addrs
        .iter()
        .find(|ip| ip.is_ipv4())
        .copied()
        .or_else(|| addrs.iter().next().copied())
}

fn format_addr_for_https(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

fn log_m_pub_hint_mismatch(announcement: &JoinerAnnouncement, request: &JoinRequest) {
    let Some(expected) = announcement.m_pub_b32.as_ref() else {
        return;
    };
    let Ok(m_pub) = <[u8; 33]>::try_from(request.m_pub.as_ref()) else {
        return;
    };
    let actual = household_rs::ids::m_pub_short(&m_pub);
    if &actual != expected {
        warn!(
            stage = "bonjour_browser.m_pub_hint_mismatch",
            expected = %expected,
            actual = %actual,
            "Bonjour m_pub_b32 differed from fetched JoinRequest; using verified JoinRequest fingerprint for owner prompt",
        );
    }
}

async fn browser_should_run(state: &PairMachineRouterState) -> bool {
    let Some(identity) = state.household.current().await else {
        return false;
    };
    if identity.record.shamir_n != 1 {
        return false;
    }
    state.window.snapshot().await.state == PairMachineState::Idle
}

async fn fetch_join_request_cbor(
    addr: String,
    nonce: String,
) -> Result<Vec<u8>, BonjourBrowserError> {
    tokio::task::spawn_blocking(move || fetch_join_request_cbor_blocking(&addr, &nonce))
        .await
        .map_err(|e| BonjourBrowserError::Fetch(format!("fetch task failed: {e}")))?
}

fn fetch_join_request_cbor_blocking(
    addr: &str,
    nonce: &str,
) -> Result<Vec<u8>, BonjourBrowserError> {
    let url = local_seed_url(addr, nonce);
    let agent = ureq::AgentBuilder::new()
        .timeout(LOCAL_SEED_TIMEOUT)
        .build();
    let response = agent
        .get(&url)
        .set("Accept", "application/cbor")
        .call()
        .map_err(|e| BonjourBrowserError::Fetch(format!("GET {url}: {e}")))?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| BonjourBrowserError::Fetch(format!("read {url}: {e}")))?;
    Ok(bytes)
}

// ── Setup invitation browser (T015) ──────────────────────────────────────────

/// Spawn a passive `_soyeht-setup._tcp.` browser for audit/debug only.
#[must_use]
pub fn spawn_setup_invitation_browser(config: BrowserConfig) -> tokio::task::JoinHandle<()> {
    spawn_setup_invitation_browser_with_cache(setup_invitation::new_cache(), config)
}

/// Spawn the production `_soyeht-setup._tcp.` browser.
///
/// Discovered iPhone invitations are inserted into `cache`; claiming remains
/// the responsibility of `POST /bootstrap/claim-setup-invitation`.
#[must_use]
pub fn spawn_setup_invitation_browser_with_cache(
    cache: SetupInvitationCache,
    config: BrowserConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let handle = match backend::BrowserHandle::new() {
            Ok(h) => h,
            Err(e) => {
                warn!(stage = "setup_browser.start_failed", error = %e);
                return;
            }
        };
        let stream = match handle.browse(SOYEHT_SETUP_SERVICE) {
            Ok(s) => s,
            Err(e) => {
                warn!(stage = "setup_browser.browse_failed", error = %e);
                handle.shutdown();
                return;
            }
        };
        loop {
            let Some(resolved) = stream.next().await else {
                break;
            };
            if resolved.service_type() != SOYEHT_SETUP_SERVICE {
                continue;
            }
            // iOS mDNSResponder announces NWListener.service on every
            // interface (LAN + Tailnet). `NWParameters.requiredInterfaceType`
            // restricts the socket but NOT the announcement, so an iPhone
            // on WiFi+Tailscale ends up advertising with only LAN
            // addresses even when it IS reachable on Tailnet. Parse the
            // publisher's self-reported `tailnet_addr` TXT field and feed
            // it to the trust filter as a per-service hint.
            let txt_tailnet_hint: Option<IpAddr> = resolved
                .txt("tailnet_addr")
                .and_then(|s| s.parse::<IpAddr>().ok());
            if !should_emit_with_txt_hint(resolved.addresses(), txt_tailnet_hint.as_ref(), config) {
                info!(
                    stage = "setup_browser.suppressed",
                    reason = "non_tailnet",
                    host = resolved.txt("host_label").unwrap_or("?"),
                    txt_tailnet_addr = ?txt_tailnet_hint,
                );
                continue;
            }
            // Include the publisher's self-reported `tailnet_addr` in the
            // cached address set so `validate_initialize_source` accepts the
            // iPhone connecting from its Tailscale CGNAT IP. The mDNSResponder
            // resolution gives only LAN/link-local addresses (per the comment
            // above), which makes the source-IP guard reject otherwise-valid
            // Tailnet POSTs to `/bootstrap/initialize`. (Confirmed live-debug
            // 2026-05-20: rejected `src_ip:100.66.202.16` with
            // `iphone_addrs:[192.168.15.7, ...]` when the TXT carried
            // `tailnet_addr=100.66.202.16`.)
            let mut addrs = resolved.addresses().iter().copied().collect::<Vec<_>>();
            if let Some(tailnet_ip) = txt_tailnet_hint {
                if !addrs.contains(&tailnet_ip) {
                    addrs.push(tailnet_ip);
                }
            }
            let txt = |key: &str| resolved.txt(key).map(str::to_string);
            if let Some(entry) = setup_invitation::cache_setup_txt(
                &cache,
                resolved.hostname(),
                resolved.port(),
                addrs,
                &txt,
            )
            .await
            {
                let iphone_endpoint = entry.iphone_endpoint.clone();
                let owner_display_name = entry.owner_display_name.clone();
                let expires_at = entry.expires_at;
                let has_hh_id = entry.hh_id.is_some();
                info!(
                    stage = "setup_browser.cached",
                    iphone_endpoint = %iphone_endpoint,
                    owner_display_name = %owner_display_name,
                    has_hh_id,
                    expires_at,
                );
                continue;
            }
            info!(
                stage = "setup_browser.discovered",
                setup_role = resolved.txt("setup_role").unwrap_or("?"),
                host_label = resolved.txt("host_label").unwrap_or("?"),
                version = resolved.txt("version").unwrap_or("?"),
                port = resolved.port(),
            );
        }
        handle.stop_browse(SOYEHT_SETUP_SERVICE);
        handle.shutdown();
    })
}

fn local_seed_url(addr: &str, nonce: &str) -> String {
    let trimmed = addr.trim_end_matches('/');
    // Default schemeless `host:port` to `http://`. The pre-household
    // listener `theyos install --pair-machine` mounts is HTTP-only:
    // TLS is unnecessary because (a) the underlay is Tailscale
    // WireGuard or LAN with the host fingerprint already verified
    // out-of-band, (b) the response body is signed via `response_sig`
    // under the founder cert, and (c) the encrypted shard is AEAD-
    // sealed under the candidate's public key. Mismatching the
    // scheme used to surface as a TLS handshake failure on Story 2,
    // breaking Bonjour discovery before `local/seed` could even
    // return. Same default as `local_finalize_url` (B2).
    let base = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    format!("{base}/pair-machine/local/seed?nonce={nonce}")
}
