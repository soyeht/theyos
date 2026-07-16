//! Bonjour publisher for `_soyeht-household._tcp` (FR-017).
//!
//! Publishes one announcement per non-loopback bind target (LAN +
//! Tailscale). TXT records, per `docs/household-protocol.md` §13:
//!
//! - Always present (base):
//!   - `hh_id`   — household identifier (omitted when the publisher is a
//!     candidate joiner that has not joined any household yet)
//!   - `hh_name` — human-readable household name
//!   - `m_id`    — local machine identifier
//!   - `host`    — DNS hostname the device answers on (e.g.
//!     `macStudio.local`); helps browsers that don't expose the
//!     resolved SRV target build the confirm-URL directly
//!   - `proto=1` — protocol version
//! - Window-gated (exactly one of these layered on top, per the
//!   "exactly one of pairing=device|machine" invariant in
//!   [`HouseholdBonjour::txt_for_state`]):
//!   - **Pair-device (Phase 2)**: `pairing=device`,
//!     `pair_nonce=<short>`.
//!   - **Pair-machine (Phase 3)**: `pairing=machine`,
//!     `pair_role=founder|joiner`, `pair_nonce=<short>`, plus
//!     `m_pub_b32=<short pubkey hash>` when `pair_role=joiner`.
//!
//! When the [`PairDeviceWindow`] flips to `Open`/`Closed` the publisher updates
//! the TXT records in real time so devices on the same Wi-Fi can auto-detect
//! a fresh pair-receiving window.
//!
//! On shutdown the service is unregistered cleanly via
//! [`shutdown_household_bonjour`].
//!
//! I/O is delegated to [`crate::bonjour_impl_mdns_sd`] so a parallel
//! macOS-native backend (Apple's `dns_sd.h` system bridge) can be wired in
//! later without touching this facade.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use household_rs::bootstrap_state::BootstrapState;
use household_rs::pair_device::{PairDeviceWindow, PairToken};
use household_rs::pair_machine::{PairMachineState, PairMachineWindow, PairMachineWindowSnapshot};
use tokio::sync::Mutex;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Duration, MissedTickBehavior};
use tracing::{info, warn};

#[cfg(target_os = "macos")]
use crate::bonjour_impl_dns_sd as backend;
#[cfg(not(target_os = "macos"))]
use crate::bonjour_impl_mdns_sd as backend;
use crate::household_listener::{HouseholdExposurePolicy, InterfaceClass};

/// Service type per FR-017.
const SERVICE_TYPE: &str = "_soyeht-household._tcp.local.";
const SHUTDOWN_WAIT: Duration = Duration::from_secs(2);
const TXT_RECONCILE_INTERVAL: Duration = Duration::from_secs(1);

/// Active publisher handle. Keep alive for the lifetime of the daemon
/// process; drop / call [`shutdown`](Self::shutdown) to unregister cleanly.
pub struct HouseholdBonjour {
    daemon: backend::PublisherHandle,
    fullnames: Arc<Mutex<Vec<String>>>,
}

static HOUSEHOLD_BONJOUR: OnceLock<Arc<HouseholdBonjour>> = OnceLock::new();

pub fn install_household_bonjour(handle: HouseholdBonjour) {
    if HOUSEHOLD_BONJOUR.set(Arc::new(handle)).is_err() {
        warn!(
            stage = "bonjour.handle_already_installed",
            "household Bonjour handle already installed; keeping the first handle"
        );
    }
}

pub async fn shutdown_household_bonjour() {
    if let Some(handle) = HOUSEHOLD_BONJOUR.get() {
        handle.shutdown().await;
    }
}

/// Static identity material the publisher needs.
#[derive(Clone)]
pub struct PublishParams {
    pub hh_id: String,
    pub hh_name: String,
    pub m_id: String,
    pub port: u16,
    /// Sanitized host fragment used to build the Bonjour instance name
    /// and SRV host record (`<host_label>.local.`). Dots and spaces are
    /// pre-replaced with `-` for safe inclusion in instance/host strings.
    /// Also emitted as TXT key `host_label` (≤32 bytes, per FR-012).
    pub host_label: String,
    /// Un-sanitized DNS hostname the device actually answers on (e.g.
    /// `macStudio.local`). Published as TXT key `host` so that Phase 2
    /// owner-pairing browsers (notably iSoyehtTerm `NWBrowser`, which
    /// does not expose the resolved SRV target via its public API) can
    /// build the `pair-device/confirm` URL without re-deriving the
    /// hostname from the sanitized instance name. Optional from the
    /// protocol's perspective: when empty no `host` TXT key is emitted
    /// and the browser falls back to its own inference.
    pub host_dns: String,
    pub pair_machine_role: Option<PairMachineBonjourRole>,

    // ── FR-012/FR-013 enrichment fields (NEW, additive-only) ─────────────
    /// Owner's first name from iCloud / display name. UTF-8, ≤32 bytes.
    /// Empty if unavailable (e.g. Linux, pre-auth).
    pub owner_display_name: String,
    /// Number of paired personal devices (iPhones). 0 in `named_awaiting_pair`.
    pub device_count: u32,
    /// `BootstrapState` string, e.g. `"named_awaiting_pair"` or `"ready"`.
    /// Only emitted when engine is NOT in `uninitialized`/`ready_for_naming`
    /// (those states publish `_soyeht-setup._tcp.` instead).
    pub bootstrap_state: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairMachineBonjourRole {
    Founder,
    Joiner,
}

impl PairMachineBonjourRole {
    #[must_use]
    fn as_str(self) -> &'static str {
        match self {
            Self::Founder => "founder",
            Self::Joiner => "joiner",
        }
    }
}

impl HouseholdBonjour {
    /// Build base TXT records. Pairing-state TXTs are layered on top by
    /// [`Self::txt_for_state`].
    fn base_txt(params: &PublishParams) -> HashMap<String, String> {
        let mut txt = HashMap::new();
        if !params.hh_id.is_empty() {
            txt.insert("hh_id".to_string(), params.hh_id.clone());
        }
        if !params.hh_name.is_empty() {
            txt.insert("hh_name".to_string(), params.hh_name.clone());
        }
        if !params.m_id.is_empty() {
            txt.insert("m_id".to_string(), params.m_id.clone());
        }
        if !params.host_dns.is_empty() {
            txt.insert("host".to_string(), params.host_dns.clone());
        }
        txt.insert("proto".to_string(), "1".to_string());

        // ── FR-012 enrichment: new additive keys ─────────────────────────
        // host_label — human-readable machine model (≤32 bytes, sanitized).
        let hl = Self::sanitize_txt_value(&params.host_label, 32);
        if !hl.is_empty() {
            txt.insert("host_label".to_string(), hl);
        }
        // owner_display_name — optional, ≤32 bytes.
        let odn = Self::sanitize_txt_value(&params.owner_display_name, 32);
        if !odn.is_empty() {
            txt.insert("owner_display_name".to_string(), odn);
        }
        // device_count — numeric, always present.
        txt.insert("device_count".to_string(), params.device_count.to_string());
        // platform — static per binary.
        txt.insert(
            "platform".to_string(),
            if cfg!(target_os = "macos") {
                "macos"
            } else {
                "linux"
            }
            .to_string(),
        );
        // bootstrap_state — only emitted when set (non-empty).
        if !params.bootstrap_state.is_empty() {
            txt.insert(
                "bootstrap_state".to_string(),
                params.bootstrap_state.clone(),
            );
        }
        // version — engine version string.
        txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());

        txt
    }

    /// Sanitize a TXT value: strip ASCII control chars < 0x20 (except space),
    /// enforce UTF-8, and truncate to `max_bytes` bytes at a char boundary.
    fn sanitize_txt_value(s: &str, max_bytes: usize) -> String {
        // Strip forbidden chars.
        let clean: String = s.chars().filter(|&c| c >= ' ' || c == '\t').collect();
        // Truncate at char boundary.
        let mut end = 0;
        for (i, _) in clean.char_indices() {
            if i >= max_bytes {
                break;
            }
            end = i + clean[i..].chars().next().map_or(0, char::len_utf8);
        }
        clean[..end.min(clean.len())].to_string()
    }

    /// Build TXT records for the current pair-device / pair-machine state.
    ///
    /// If both windows are active, pair-machine wins. This preserves the
    /// contract's "exactly one of pairing=device|machine" invariant.
    #[must_use]
    pub fn txt_for_state(
        params: &PublishParams,
        pair_device_token: Option<PairToken>,
        pair_machine_snapshot: Option<&PairMachineWindowSnapshot>,
    ) -> HashMap<String, String> {
        let mut txt = Self::base_txt(params);
        if let (Some(role), Some(snapshot)) = (params.pair_machine_role, pair_machine_snapshot) {
            if matches!(
                snapshot.state,
                PairMachineState::Staging | PairMachineState::AwaitingOwner
            ) {
                if let Some(nonce) = snapshot.nonce.as_ref() {
                    if nonce.len() >= 8 {
                        txt.insert("pairing".to_string(), "machine".to_string());
                        txt.insert("pair_role".to_string(), role.as_str().to_string());
                        txt.insert(
                            "pair_nonce".to_string(),
                            household_rs::ids::base32_lower_nopad_encode(&nonce.as_ref()[..8]),
                        );
                        if role == PairMachineBonjourRole::Joiner {
                            if let Some(m_pub) = snapshot.m_pub.as_ref() {
                                if let Ok(m_pub) = <[u8; 33]>::try_from(m_pub.as_ref()) {
                                    txt.insert(
                                        "m_pub_b32".to_string(),
                                        household_rs::ids::m_pub_short(&m_pub),
                                    );
                                }
                            }
                        }
                        return txt;
                    }
                }
            }
        }
        if let Some(token) = pair_device_token {
            txt.insert("pairing".to_string(), "device".to_string());
            txt.insert("pair_nonce".to_string(), token.nonce.as_short_b64());
        }
        txt
    }

    fn instance_name(params: &PublishParams) -> String {
        // Per RFC 6763 §4: instance names should be unique on the local link.
        // We use the hh_id (truncated for log readability) — collisions are
        // possible but cosmetic; the TXT carries the full identifier.
        let short = params
            .hh_id
            .strip_prefix("hh_")
            .unwrap_or(&params.hh_id)
            .chars()
            .take(8)
            .collect::<String>();
        format!("Soyeht-{}-{}", params.host_label, short)
    }

    fn host_label(params: &PublishParams) -> String {
        format!("{}.local.", params.host_label)
    }
}

/// Publish `_soyeht-household._tcp` on the supplied set of (address,
/// interface-class) targets allowed by [`HouseholdExposurePolicy`]. Loopback
/// entries are filtered out — Bonjour only advertises peer-reachable addresses.
///
/// Spawns a background task that reflects [`PairDeviceWindow`] state changes into
/// the TXT records. Returns a [`HouseholdBonjour`] handle that owns the
/// daemon for the lifetime of the process.
pub async fn publish_household_bonjour(
    params: PublishParams,
    pair_device_window: Arc<PairDeviceWindow>,
    pair_machine_window: Arc<PairMachineWindow>,
    targets: Vec<(IpAddr, InterfaceClass)>,
    exposure_state: BootstrapState,
) -> Result<HouseholdBonjour, backend::BackendError> {
    let daemon = backend::PublisherHandle::new()?;
    let fullnames: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Pre-fill the pairing-state TXTs from the current window snapshot so
    // the very first publish reflects reality, including short nonces.
    let base_txt = HouseholdBonjour::txt_for_state(
        &params,
        pair_device_window.current_token().await,
        Some(&pair_machine_window.snapshot().await),
    );

    let instance = HouseholdBonjour::instance_name(&params);
    let host = HouseholdBonjour::host_label(&params);

    let mut bound = 0usize;
    let targets = HouseholdExposurePolicy::bonjour_targets(exposure_state, targets);
    for (ip, class) in &targets {
        if !class.is_bonjour_advertisable() {
            continue;
        }
        let spec = backend::ServiceSpec {
            service_type: SERVICE_TYPE,
            instance: &instance,
            host: &host,
            ip: *ip,
            port: params.port,
            txt: &base_txt,
        };
        match daemon.register(&spec) {
            Ok(fullname) => {
                info!(
                    stage = "bonjour.published",
                    address = %ip,
                    interface_class = class.as_str(),
                    fullname = %fullname,
                );
                fullnames.lock().await.push(fullname);
                bound += 1;
            }
            Err(e) => {
                warn!(
                    stage = "bonjour.register_failed",
                    address = %ip,
                    interface_class = class.as_str(),
                    error = %e,
                );
            }
        }
    }
    info!(
        stage = "bonjour.ready",
        bound_count = bound,
        port = params.port
    );

    // Spawn a task that reflects PairDeviceWindow state into TXT records in real
    // time. We unregister every previously published service first, then
    // re-register with the new TXT — this is mDNS-RFC-correct (a record
    // update is "goodbye" + "hello") and avoids the duplicate-announcement
    // problem callers reported.
    let mut pair_device_rx = pair_device_window.subscribe();
    let mut pair_machine_rx = pair_machine_window.subscribe();
    let daemon_clone = daemon.clone();
    let fullnames_clone = Arc::clone(&fullnames);
    let params_clone = params.clone();
    let targets_clone = targets.clone();
    let pair_device_window_clone = Arc::clone(&pair_device_window);
    let pair_machine_window_clone = Arc::clone(&pair_machine_window);
    let instance_clone = instance.clone();
    let host_clone = host.clone();
    let mut last_txt = base_txt.clone();
    tokio::spawn(async move {
        let mut reconcile = tokio::time::interval(TXT_RECONCILE_INTERVAL);
        reconcile.set_missed_tick_behavior(MissedTickBehavior::Delay);
        reconcile.tick().await;

        loop {
            tokio::select! {
                _ = reconcile.tick() => {}
                device_state = pair_device_rx.recv() => {
                    match device_state {
                        Ok(_) => {}
                        Err(RecvError::Lagged(skipped)) => {
                            warn!(
                                stage = "bonjour.txt_update_lagged",
                                skipped, "pair-device update subscriber lagged; waiting for next state"
                            );
                            continue;
                        }
                        Err(RecvError::Closed) => break,
                    }
                }
                changed = pair_machine_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
            let pair_device_token = pair_device_window_clone.current_token().await;
            let pair_machine_snapshot = pair_machine_window_clone.snapshot().await;
            let txt = HouseholdBonjour::txt_for_state(
                &params_clone,
                pair_device_token,
                Some(&pair_machine_snapshot),
            );
            if txt == last_txt {
                continue;
            }

            // Unregister-then-register so peers see a clean transition
            // instead of duplicate records with conflicting TXTs.
            let mut full_guard = fullnames_clone.lock().await;
            for full in full_guard.drain(..) {
                if let Err(e) = daemon_clone.unregister(&full) {
                    warn!(
                        stage = "bonjour.unregister_failed",
                        fullname = %full,
                        error = %e,
                    );
                }
            }
            for (ip, class) in &targets_clone {
                if !class.is_bonjour_advertisable() {
                    continue;
                }
                let spec = backend::ServiceSpec {
                    service_type: SERVICE_TYPE,
                    instance: &instance_clone,
                    host: &host_clone,
                    ip: *ip,
                    port: params_clone.port,
                    txt: &txt,
                };
                match daemon_clone.register(&spec) {
                    Ok(fullname) => full_guard.push(fullname),
                    Err(e) => warn!(
                        stage = "bonjour.txt_update_failed",
                        address = %ip,
                        error = %e,
                    ),
                }
            }
            if !full_guard.is_empty() {
                last_txt = txt;
            }
            info!(
                stage = "bonjour.txt_updated",
                pairing = last_txt.get("pairing").map_or("none", String::as_str),
            );
        }
    });

    Ok(HouseholdBonjour { daemon, fullnames })
}

/// Publish `_soyeht-household._tcp` for a candidate machine M2 that has
/// not yet joined any household.
///
/// Used by `theyos install --pair-machine` (B8). Per
/// `docs/household-protocol.md` §13 the candidate joiner publishes:
/// - `pairing=machine`, `pair_role=joiner`
/// - `pair_nonce=<short>`, `m_pub_b32=<short hash>`
/// - **NO** `hh_id` (the candidate has not joined any household yet)
///
/// `params.hh_id`, `params.hh_name`, and `params.m_id` MUST be empty
/// strings — `base_txt` skips them when empty, which produces the
/// protocol-correct TXT shape. `params.pair_machine_role` MUST be
/// [`PairMachineBonjourRole::Joiner`].
///
/// Unlike [`publish_household_bonjour`], this helper does NOT subscribe
/// to the window watcher. The candidate's window stays in
/// `Staging`/`AwaitingOwner` for the lifetime of the install command,
/// then transitions atomically to `Committed` (or `Aborted`) at which
/// point the install command returns and the caller invokes
/// [`HouseholdBonjour::shutdown`].
pub async fn publish_candidate_joiner_bonjour(
    params: PublishParams,
    pair_machine_window: Arc<PairMachineWindow>,
    targets: Vec<(IpAddr, InterfaceClass)>,
) -> Result<HouseholdBonjour, backend::BackendError> {
    debug_assert!(
        params.hh_id.is_empty(),
        "candidate joiner MUST publish without hh_id per protocol §13"
    );
    debug_assert!(
        matches!(
            params.pair_machine_role,
            Some(PairMachineBonjourRole::Joiner)
        ),
        "candidate joiner MUST advertise pair_role=joiner"
    );
    let daemon = backend::PublisherHandle::new()?;
    let fullnames: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let snapshot = pair_machine_window.snapshot().await;
    let txt = HouseholdBonjour::txt_for_state(&params, None, Some(&snapshot));

    let instance = HouseholdBonjour::instance_name(&params);
    let host = HouseholdBonjour::host_label(&params);

    let mut bound = 0usize;
    for (ip, class) in &targets {
        if !class.is_bonjour_advertisable() {
            continue;
        }
        let spec = backend::ServiceSpec {
            service_type: SERVICE_TYPE,
            instance: &instance,
            host: &host,
            ip: *ip,
            port: params.port,
            txt: &txt,
        };
        match daemon.register(&spec) {
            Ok(fullname) => {
                info!(
                    stage = "bonjour.candidate_published",
                    address = %ip,
                    interface_class = class.as_str(),
                    fullname = %fullname,
                );
                fullnames.lock().await.push(fullname);
                bound += 1;
            }
            Err(e) => {
                warn!(
                    stage = "bonjour.candidate_register_failed",
                    address = %ip,
                    interface_class = class.as_str(),
                    error = %e,
                );
            }
        }
    }
    info!(
        stage = "bonjour.candidate_ready",
        bound_count = bound,
        port = params.port
    );
    Ok(HouseholdBonjour { daemon, fullnames })
}

impl HouseholdBonjour {
    /// Unregister all published services and shut down the daemon.
    pub async fn shutdown(&self) {
        let fullnames = self.fullnames.lock().await.clone();
        for full in fullnames {
            match self.daemon.unregister_and_wait(&full, SHUTDOWN_WAIT).await {
                backend::UnregisterOutcome::Ok => {
                    info!(stage = "bonjour.unregistered", fullname = %full);
                }
                backend::UnregisterOutcome::NotFound => {
                    warn!(stage = "bonjour.unregister_not_found", fullname = %full);
                }
                backend::UnregisterOutcome::Failed(e) => warn!(
                    stage = "bonjour.unregister_failed",
                    fullname = %full,
                    error = %e,
                ),
                backend::UnregisterOutcome::TimedOut => warn!(
                    stage = "bonjour.unregister_timeout",
                    fullname = %full,
                    timeout_ms = SHUTDOWN_WAIT.as_millis(),
                ),
            }
        }
        match self.daemon.shutdown_and_wait(SHUTDOWN_WAIT).await {
            backend::ShutdownOutcome::Ok => {
                info!(stage = "bonjour.shutdown_complete");
            }
            backend::ShutdownOutcome::Unexpected(status) => {
                warn!(stage = "bonjour.shutdown_unexpected_status", status = %status);
            }
            backend::ShutdownOutcome::Failed(e) => {
                warn!(stage = "bonjour.shutdown_failed", error = %e);
            }
            backend::ShutdownOutcome::TimedOut => {
                warn!(
                    stage = "bonjour.shutdown_timeout",
                    timeout_ms = SHUTDOWN_WAIT.as_millis(),
                );
            }
        }
        self.fullnames.lock().await.clear();
    }
}
