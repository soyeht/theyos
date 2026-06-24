//! FR-013 `_soyeht-setup._tcp.` Bonjour publisher.
//!
//! Publishes a setup beacon while the engine is in `uninitialized` or
//! `ready_for_naming` so SoyehtMac.app and the iOS app can discover a fresh
//! engine and initiate the onboarding flow without a QR scan.
//!
//! ## Role determination (per FR-013 + tasks.md T014)
//!
//! Before publishing, the engine browses `_soyeht-household._tcp.` for up to
//! 5 seconds:
//! - **Any existing household found** → `member_candidate`
//!   (this machine is joining an existing casa).
//! - **No results** → `founder_candidate`
//!   (this machine will create the first casa).
//!
//! ## Withdrawal
//!
//! A background task polls the `BootstrapStateArc` every 500 ms. When the
//! state advances to `named_awaiting_pair` or beyond, all published instances
//! are unregistered and the task exits.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio::time::{self, MissedTickBehavior, timeout};
use tracing::{info, warn};

#[cfg(target_os = "macos")]
use crate::bonjour_impl_dns_sd as backend;
#[cfg(not(target_os = "macos"))]
use crate::bonjour_impl_mdns_sd as backend;

use crate::bonjour_browser::SOYEHT_HOUSEHOLD_SERVICE;
use crate::handlers_bootstrap::BootstrapStateArc;
use crate::household_listener::{BoundSet, HouseholdExposurePolicy, InterfaceClass};
use household_rs::bootstrap_state::BootstrapState;
use household_rs::pair_machine::{PairMachineState, PairMachineWindow};

const SETUP_SERVICE_TYPE: &str = "_soyeht-setup._tcp.local.";
const ROLE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const STATE_POLL_INTERVAL: Duration = Duration::from_millis(500);

// ── Role ─────────────────────────────────────────────────────────────────────

/// TXT `setup_role` values per FR-013.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupRole {
    /// No existing casa detected; this machine will create the first casa.
    FounderCandidate,
    /// An existing `_soyeht-household._tcp.` service was found; this machine
    /// is joining as a member.
    MemberCandidate,
}

impl SetupRole {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FounderCandidate => "founder_candidate",
            Self::MemberCandidate => "member_candidate",
        }
    }
}

// ── Params ────────────────────────────────────────────────────────────────────

/// Parameters for the setup beacon publisher.
#[derive(Clone)]
pub struct SetupBeaconParams {
    /// Sanitized host label (e.g. `"macStudio"`). Used for instance name + SRV host.
    pub host_label: String,
    /// Full DNS hostname (e.g. `"macStudio.local"`). Emitted as TXT `host` key.
    pub host_dns: String,
    pub port: u16,
    /// When `Some`, skip the Bonjour probe: if window is Staging/AwaitingOwner,
    /// publish `member_candidate` immediately (T042 / Story 2 disambiguation).
    pub pair_machine_window: Option<Arc<PairMachineWindow>>,
}

// ── Handle ────────────────────────────────────────────────────────────────────

struct SetupBeaconInner {
    daemon: backend::PublisherHandle,
    fullnames: Mutex<HashMap<IpAddr, String>>,
}

/// Active setup beacon handle.
///
/// The `_task` background task monitors bootstrap state and unregisters the
/// beacon automatically. Dropping the handle aborts the task.
pub struct SetupBeacon {
    inner: Arc<SetupBeaconInner>,
    _task: tokio::task::JoinHandle<()>,
}

impl SetupBeacon {
    /// Eagerly unregister all published instances without waiting for the
    /// background task to detect the state change.
    pub async fn withdraw(&self) {
        let guard = self.inner.fullnames.lock().await;
        for name in guard.values() {
            if let Err(e) = self.inner.daemon.unregister(name) {
                warn!(
                    stage = "setup_beacon.withdraw_failed",
                    fullname = %name,
                    error = %e,
                );
            }
        }
        info!(stage = "setup_beacon.withdrawn", count = guard.len());
    }
}

// ── Role probe ────────────────────────────────────────────────────────────────

/// Determine the setup role for the `_soyeht-setup._tcp.` TXT record.
///
/// - If `pair_machine_window` is `Some` and in `Staging | AwaitingOwner` state,
///   returns `MemberCandidate` immediately — the machine has already been staged
///   for joining an existing casa (Story 2: Linux candidate). No Bonjour probe needed.
/// - Otherwise, browses `_soyeht-household._tcp.` for [`ROLE_PROBE_TIMEOUT`]:
///   - Any existing household found → `MemberCandidate` (Story 2 fallback)
///   - No results → `FounderCandidate` (Story 4: Linux founder)
async fn determine_role(pair_machine_window: Option<&PairMachineWindow>) -> SetupRole {
    // Fast path: active pair_machine_window → this machine is already staged
    // as a member candidate, skip the 5-second Bonjour probe.
    if let Some(window) = pair_machine_window {
        let snap = window.snapshot().await;
        if matches!(
            snap.state,
            PairMachineState::Staging | PairMachineState::AwaitingOwner
        ) {
            info!(
                stage = "setup_beacon.role_determined",
                role = "member_candidate",
                source = "pair_machine_window",
            );
            return SetupRole::MemberCandidate;
        }
    }

    let handle = match backend::BrowserHandle::new() {
        Ok(h) => h,
        Err(e) => {
            warn!(stage = "setup_beacon.role_probe_backend_failed", error = %e);
            return SetupRole::FounderCandidate;
        }
    };
    let stream = match handle.browse(SOYEHT_HOUSEHOLD_SERVICE) {
        Ok(s) => s,
        Err(e) => {
            warn!(stage = "setup_beacon.role_probe_browse_failed", error = %e);
            handle.shutdown();
            return SetupRole::FounderCandidate;
        }
    };

    let found = timeout(ROLE_PROBE_TIMEOUT, stream.next())
        .await
        .is_ok_and(|r| r.is_some());

    handle.stop_browse(SOYEHT_HOUSEHOLD_SERVICE);
    handle.shutdown();

    let role = if found {
        SetupRole::MemberCandidate
    } else {
        SetupRole::FounderCandidate
    };
    info!(stage = "setup_beacon.role_determined", role = role.as_str());
    role
}

// ── TXT helpers ───────────────────────────────────────────────────────────────

fn build_txt(params: &SetupBeaconParams, role: SetupRole) -> HashMap<String, String> {
    let mut txt = HashMap::new();
    txt.insert("v".to_string(), "1".to_string());
    txt.insert("setup_role".to_string(), role.as_str().to_string());
    if !params.host_label.is_empty() {
        txt.insert("host_label".to_string(), params.host_label.clone());
    }
    if !params.host_dns.is_empty() {
        txt.insert("host".to_string(), params.host_dns.clone());
    }
    txt.insert(
        "platform".to_string(),
        if cfg!(target_os = "macos") {
            "macos"
        } else {
            "linux"
        }
        .to_string(),
    );
    txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    txt
}

fn beacon_instance(params: &SetupBeaconParams) -> String {
    format!("SoyehtSetup-{}", params.host_label)
}

fn beacon_host(params: &SetupBeaconParams) -> String {
    let host = params.host_dns.trim().trim_end_matches('.');
    if host.is_empty() {
        format!("{}.local.", params.host_label)
    } else {
        format!("{host}.")
    }
}

fn should_publish(state: BootstrapState) -> bool {
    matches!(
        state,
        BootstrapState::Uninitialized | BootstrapState::ReadyForNaming
    )
}

// ── Publisher ─────────────────────────────────────────────────────────────────

struct SetupBeaconPublishSpec<'a> {
    instance: &'a str,
    host: &'a str,
    port: u16,
    txt: &'a HashMap<String, String>,
    role: SetupRole,
}

fn publish_targets(
    daemon: &backend::PublisherHandle,
    fullnames: &mut HashMap<IpAddr, String>,
    targets: &[(IpAddr, InterfaceClass)],
    spec: &SetupBeaconPublishSpec<'_>,
    state: BootstrapState,
    source: &'static str,
) -> usize {
    let mut bound = 0usize;
    let targets = HouseholdExposurePolicy::allowed_targets(state, targets.iter().copied());
    for (ip, class) in targets {
        if class == InterfaceClass::Loopback || fullnames.contains_key(&ip) {
            continue;
        }
        let service = backend::ServiceSpec {
            service_type: SETUP_SERVICE_TYPE,
            instance: spec.instance,
            host: spec.host,
            ip,
            port: spec.port,
            txt: spec.txt,
        };
        match daemon.register(&service) {
            Ok(fullname) => {
                info!(
                    stage = "setup_beacon.published",
                    address = %ip,
                    setup_role = spec.role.as_str(),
                    fullname = %fullname,
                    source,
                );
                fullnames.insert(ip, fullname);
                bound += 1;
            }
            Err(e) => {
                warn!(
                    stage = "setup_beacon.register_failed",
                    address = %ip,
                    error = %e,
                    source,
                );
            }
        }
    }
    bound
}

fn unregister_fullnames(
    daemon: &backend::PublisherHandle,
    fullnames: impl IntoIterator<Item = String>,
) {
    for name in fullnames {
        if let Err(e) = daemon.unregister(&name) {
            warn!(
                stage = "setup_beacon.auto_withdraw_failed",
                fullname = %name,
                error = %e,
            );
        }
    }
}

async fn sync_bound_targets(
    inner: &SetupBeaconInner,
    targets: Vec<(IpAddr, InterfaceClass)>,
    spec: &SetupBeaconPublishSpec<'_>,
    state: BootstrapState,
) {
    let policy_targets = HouseholdExposurePolicy::allowed_targets(state, targets);
    let live: HashSet<IpAddr> = policy_targets
        .iter()
        .filter_map(|(ip, class)| (*class != InterfaceClass::Loopback).then_some(*ip))
        .collect();
    let stale = {
        let mut guard = inner.fullnames.lock().await;
        let stale: Vec<IpAddr> = guard
            .keys()
            .copied()
            .filter(|ip| !live.contains(ip))
            .collect();
        stale
            .into_iter()
            .filter_map(|ip| guard.remove(&ip).map(|name| (ip, name)))
            .collect::<Vec<_>>()
    };

    for (ip, fullname) in stale {
        if let Err(e) = inner.daemon.unregister(&fullname) {
            warn!(
                stage = "setup_beacon.refresh_unpublish_failed",
                address = %ip,
                fullname = %fullname,
                error = %e,
            );
        } else {
            info!(
                stage = "setup_beacon.refresh_unpublished",
                address = %ip,
                fullname = %fullname,
            );
        }
    }

    let added = {
        let mut guard = inner.fullnames.lock().await;
        publish_targets(
            &inner.daemon,
            &mut guard,
            &policy_targets,
            spec,
            state,
            "refresh",
        )
    };
    if added > 0 {
        info!(
            stage = "setup_beacon.refresh_published",
            added_count = added
        );
    }
}

/// Publish `_soyeht-setup._tcp.` on all non-loopback targets.
///
/// Returns `None` if the engine is already past `ready_for_naming` — no
/// beacon needed. Returns `Some(SetupBeacon)` otherwise.
pub async fn publish_setup_beacon(
    params: SetupBeaconParams,
    bootstrap: BootstrapStateArc,
    targets: Vec<(IpAddr, InterfaceClass)>,
) -> Result<Option<SetupBeacon>, backend::BackendError> {
    publish_setup_beacon_with_bound_set(params, bootstrap, targets, None).await
}

/// Publish `_soyeht-setup._tcp.` and keep it aligned with the live listener set.
///
/// When `bound_set` is provided, the background task registers newly-bound
/// LAN/Tailnet interfaces and unregisters interfaces that disappear while the
/// bootstrap state is still fresh.
pub async fn publish_setup_beacon_with_bound_set(
    params: SetupBeaconParams,
    bootstrap: BootstrapStateArc,
    targets: Vec<(IpAddr, InterfaceClass)>,
    bound_set: Option<BoundSet>,
) -> Result<Option<SetupBeacon>, backend::BackendError> {
    let initial_state = {
        let state = bootstrap.read().await;
        let initial_state = *state;
        if !should_publish(initial_state) {
            info!(
                stage = "setup_beacon.skipped",
                reason = "state_already_advanced",
                state = state.as_str(),
            );
            return Ok(None);
        }
        initial_state
    };

    let t0 = Instant::now();
    let daemon = backend::PublisherHandle::new()?;

    // Determine role before first publish so TXT is correct on the first announcement.
    let role = determine_role(params.pair_machine_window.as_deref()).await;
    let txt = build_txt(&params, role);
    let instance = beacon_instance(&params);
    let host = beacon_host(&params);

    let fullnames: Mutex<HashMap<IpAddr, String>> = Mutex::new(HashMap::new());
    let spec = SetupBeaconPublishSpec {
        instance: &instance,
        host: &host,
        port: params.port,
        txt: &txt,
        role,
    };
    let bound = {
        let mut guard = fullnames.lock().await;
        publish_targets(
            &daemon,
            &mut guard,
            &targets,
            &spec,
            initial_state,
            "startup",
        )
    };
    // elapsed_ms: as_millis() returns u128 but a u64 holds ~585 millennia;
    // truncation is impossible in practice.
    #[allow(clippy::cast_possible_truncation)]
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    info!(
        stage = "setup_beacon.ready",
        bound_count = bound,
        setup_role = role.as_str(),
        elapsed_ms,
    );

    let inner = Arc::new(SetupBeaconInner { daemon, fullnames });
    let inner_clone = Arc::clone(&inner);
    let task = tokio::spawn(async move {
        let spec = SetupBeaconPublishSpec {
            instance: &instance,
            host: &host,
            port: params.port,
            txt: &txt,
            role,
        };
        let mut interval = time::interval(STATE_POLL_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let state = bootstrap.read().await;
            let current_state = *state;
            if !should_publish(current_state) {
                let new_state = state.as_str().to_string();
                drop(state);
                info!(stage = "setup_beacon.withdrawing", new_state = %new_state);
                let names = {
                    let mut guard = inner_clone.fullnames.lock().await;
                    guard.drain().map(|(_, name)| name).collect::<Vec<_>>()
                };
                unregister_fullnames(&inner_clone.daemon, names);
                info!(stage = "setup_beacon.auto_withdrawn");
                break;
            }
            drop(state);
            if let Some(bound_set) = &bound_set {
                sync_bound_targets(
                    &inner_clone,
                    bound_set.snapshot_targets().await,
                    &spec,
                    current_state,
                )
                .await;
            }
        }
    });

    Ok(Some(SetupBeacon { inner, _task: task }))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_role_strings() {
        assert_eq!(SetupRole::FounderCandidate.as_str(), "founder_candidate");
        assert_eq!(SetupRole::MemberCandidate.as_str(), "member_candidate");
    }

    #[test]
    fn should_publish_states() {
        assert!(should_publish(BootstrapState::Uninitialized));
        assert!(should_publish(BootstrapState::ReadyForNaming));
        assert!(!should_publish(BootstrapState::NamedAwaitingPair));
        assert!(!should_publish(BootstrapState::Ready));
        assert!(!should_publish(BootstrapState::Recovering));
    }

    #[test]
    fn txt_has_required_keys() {
        let params = SetupBeaconParams {
            host_label: "macStudio".to_string(),
            host_dns: "macStudio.local".to_string(),
            port: 8091,
            pair_machine_window: None,
        };
        let txt = build_txt(&params, SetupRole::FounderCandidate);
        assert_eq!(txt.get("v").map(String::as_str), Some("1"));
        assert_eq!(
            txt.get("setup_role").map(String::as_str),
            Some("founder_candidate")
        );
        assert_eq!(txt.get("host_label").map(String::as_str), Some("macStudio"));
        assert_eq!(txt.get("host").map(String::as_str), Some("macStudio.local"));
        assert!(txt.contains_key("platform"));
        assert!(txt.contains_key("version"));
    }

    #[test]
    fn txt_member_candidate() {
        let params = SetupBeaconParams {
            host_label: "mbp".to_string(),
            host_dns: "mbp.local".to_string(),
            port: 8091,
            pair_machine_window: None,
        };
        let txt = build_txt(&params, SetupRole::MemberCandidate);
        assert_eq!(
            txt.get("setup_role").map(String::as_str),
            Some("member_candidate")
        );
    }

    #[test]
    fn beacon_host_uses_host_dns() {
        let params = SetupBeaconParams {
            host_label: "Developer Mac".to_string(),
            host_dns: "caio-mac-studio.local".to_string(),
            port: 8091,
            pair_machine_window: None,
        };

        assert_eq!(beacon_host(&params), "caio-mac-studio.local.");
    }

    #[test]
    fn beacon_instance_name() {
        let params = SetupBeaconParams {
            host_label: "studio".to_string(),
            host_dns: "studio.local".to_string(),
            port: 8091,
            pair_machine_window: None,
        };
        assert_eq!(beacon_instance(&params), "SoyehtSetup-studio");
        assert_eq!(beacon_host(&params), "studio.local.");
    }

    #[test]
    fn empty_host_label_omitted_from_txt() {
        let params = SetupBeaconParams {
            host_label: String::new(),
            host_dns: String::new(),
            port: 8091,
            pair_machine_window: None,
        };
        let txt = build_txt(&params, SetupRole::FounderCandidate);
        assert!(!txt.contains_key("host_label"));
        assert!(!txt.contains_key("host"));
    }

    #[tokio::test]
    async fn determine_role_member_candidate_from_staging_window() {
        let window = Arc::new(PairMachineWindow::new_in_memory());
        window
            .enter_staging(
                [0x02u8; 33],
                [0xAAu8; 32],
                household_rs::pair_machine::JoinTransport::Tailscale,
                "100.100.1.2".into(),
                "🦊🌙🔑🎯🌊🦋".into(),
                vec![],
                300,
                Some([0xBBu8; 32]),
            )
            .await
            .unwrap();
        let role = determine_role(Some(&window)).await;
        assert_eq!(role, SetupRole::MemberCandidate);
    }
}
