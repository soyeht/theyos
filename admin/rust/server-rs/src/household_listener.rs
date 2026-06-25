//! Household-endpoint listener.
//!
//! Binds a fresh axum router to concrete loopback / LAN / Tailnet addresses,
//! then narrows the live set by [`HouseholdExposurePolicy`]:
//! - onboarding (`uninitialized`, `ready_for_naming`) allows loopback + LAN +
//!   Tailnet so first-launch setup can work on the local network;
//! - post-onboarding (`named_awaiting_pair`, `ready`, `recovering`) allows only
//!   loopback + Tailnet so the Ready control plane is not exposed over LAN HTTP.
//!
//! Refuses wildcard `0.0.0.0` / `::` per FR-008. Refreshes the active address
//! set every 60 s and reconciles state-policy changes every 500 ms.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use household_rs::bootstrap_state::BootstrapState;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, oneshot};
use tracing::{info, warn};

const INTERFACE_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const POLICY_SYNC_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceClass {
    Loopback,
    Lan,
    Tailscale,
}

impl InterfaceClass {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Lan => "lan",
            Self::Tailscale => "tailscale",
        }
    }
}

/// Pure transport exposure policy for household listener and Bonjour surfaces.
///
/// This is intentionally independent from interface names and socket binding:
/// callers provide already-classified targets, and the policy only decides which
/// classes are allowed for the current bootstrap state.
pub struct HouseholdExposurePolicy;

impl HouseholdExposurePolicy {
    #[must_use]
    pub fn allows(state: BootstrapState, class: InterfaceClass) -> bool {
        match state {
            BootstrapState::Uninitialized | BootstrapState::ReadyForNaming => matches!(
                class,
                InterfaceClass::Loopback | InterfaceClass::Lan | InterfaceClass::Tailscale
            ),
            BootstrapState::NamedAwaitingPair
            | BootstrapState::Ready
            | BootstrapState::Recovering => {
                matches!(class, InterfaceClass::Loopback | InterfaceClass::Tailscale)
            }
        }
    }

    #[must_use]
    pub fn allowed_targets(
        state: BootstrapState,
        targets: impl IntoIterator<Item = (IpAddr, InterfaceClass)>,
    ) -> Vec<(IpAddr, InterfaceClass)> {
        targets
            .into_iter()
            .filter(|(_, class)| Self::allows(state, *class))
            .collect()
    }
}

/// Enumerate the active concrete interface addresses we want to bind.
#[must_use]
pub fn enumerate_bind_targets() -> Vec<(IpAddr, InterfaceClass)> {
    let mut targets: Vec<(IpAddr, InterfaceClass)> = vec![
        (IpAddr::V4(Ipv4Addr::LOCALHOST), InterfaceClass::Loopback),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), InterfaceClass::Loopback),
    ];

    if let Ok(addrs) = if_addrs::get_if_addrs() {
        for ifa in addrs {
            if ifa.is_loopback() {
                continue;
            }
            let name = ifa.name.clone();
            let ip = ifa.ip();
            // Reject link-local IPv4 169.254/16 and IPv6 fe80::/10 — neither
            // is suitable for our listener.
            if is_link_local(&ip) {
                continue;
            }
            let class = classify(&name, &ip);
            // Skip everything else (public/wireguard) for now — Phase 1 only
            // supports loopback/LAN/Tailscale per spec.
            if let Some(class) = class {
                targets.push((ip, class));
            }
        }
    }

    targets
}

/// Refuse-wildcard guard: assert the bound socket's local addr is not a
/// wildcard. Returns the resolved listener.
async fn bind_concrete(addr: SocketAddr) -> Result<TcpListener, std::io::Error> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    if local.ip().is_unspecified() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to listen on wildcard 0.0.0.0/::",
        ));
    }
    Ok(listener)
}

/// Shared bookkeeping for the spawn / refresh loop. The set of currently
/// bound addresses is exposed via a clone-able handle so the Bonjour
/// publisher can advertise exactly the addresses a peer can actually
/// reach.
struct BoundTarget {
    class: InterfaceClass,
    shutdown: oneshot::Sender<()>,
}

#[derive(Clone, Default)]
pub struct BoundSet {
    inner: Arc<Mutex<HashMap<IpAddr, BoundTarget>>>,
}

impl BoundSet {
    /// Snapshot of currently bound addresses paired with the interface
    /// class enumerator's classification at the moment of binding.
    pub async fn snapshot(&self) -> Vec<IpAddr> {
        self.inner.lock().await.keys().copied().collect()
    }

    /// Snapshot of currently bound addresses with their interface classes.
    pub async fn snapshot_targets(&self) -> Vec<(IpAddr, InterfaceClass)> {
        self.inner
            .lock()
            .await
            .iter()
            .map(|(ip, target)| (*ip, target.class))
            .collect()
    }

    async fn contains(&self, ip: IpAddr) -> bool {
        self.inner.lock().await.contains_key(&ip)
    }

    async fn insert(&self, ip: IpAddr, class: InterfaceClass, shutdown: oneshot::Sender<()>) {
        self.inner
            .lock()
            .await
            .insert(ip, BoundTarget { class, shutdown });
    }

    async fn remove(&self, ip: IpAddr) -> Option<BoundTarget> {
        self.inner.lock().await.remove(&ip)
    }
}

fn spawn_listener_task(
    router: Router,
    listener: TcpListener,
    addr: SocketAddr,
    shutdown_rx: oneshot::Receiver<()>,
) {
    tokio::spawn(async move {
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        if let Err(e) = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await
        {
            warn!(
                stage = "household_listener.serve_failed",
                address = %addr,
                error = %e,
            );
        }
    });
}

async fn bind_allowed_target(
    router: &Router,
    port: u16,
    bound: &BoundSet,
    ip: IpAddr,
    class: InterfaceClass,
    source: &'static str,
) -> Option<(IpAddr, InterfaceClass)> {
    let addr = SocketAddr::new(ip, port);
    match bind_concrete(addr).await {
        Ok(listener) => {
            info!(
                stage = "bootstrap.endpoint.live",
                address = %addr,
                interface_class = class.as_str(),
                result = "ok",
                source,
            );
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            bound.insert(ip, class, shutdown_tx).await;
            spawn_listener_task(router.clone(), listener, addr, shutdown_rx);
            Some((ip, class))
        }
        Err(e) => {
            warn!(
                stage = "bootstrap.endpoint.bind_failed",
                address = %addr,
                interface_class = class.as_str(),
                error = %e,
                source,
            );
            None
        }
    }
}

async fn shutdown_bound_target(bound: &BoundSet, ip: IpAddr, reason: &'static str) {
    if let Some(target) = bound.remove(ip).await {
        let class = target.class;
        let _ = target.shutdown.send(());
        info!(
            stage = "household_listener.address_removed",
            address = %ip,
            interface_class = class.as_str(),
            reason,
        );
    }
}

async fn bootstrap_state(bootstrap: &Arc<RwLock<BootstrapState>>) -> BootstrapState {
    *bootstrap.read().await
}

async fn sync_interface_targets(
    router: &Router,
    port: u16,
    bootstrap: &Arc<RwLock<BootstrapState>>,
    bound: &BoundSet,
    source: &'static str,
) -> Vec<(IpAddr, InterfaceClass)> {
    let state = bootstrap_state(bootstrap).await;
    let live = HouseholdExposurePolicy::allowed_targets(state, enumerate_bind_targets());
    let live_set: HashSet<IpAddr> = live.iter().map(|(ip, _)| *ip).collect();

    for (ip, class) in &live {
        if bound.contains(*ip).await {
            continue;
        }
        let _ = bind_allowed_target(router, port, bound, *ip, *class, source).await;
    }

    let stale_ips: Vec<IpAddr> = bound
        .snapshot()
        .await
        .into_iter()
        .filter(|ip| !live_set.contains(ip))
        .collect();
    for ip in stale_ips {
        shutdown_bound_target(bound, ip, "interface_or_policy_removed").await;
    }

    bound.snapshot_targets().await
}

async fn sync_exposure_policy(bootstrap: &Arc<RwLock<BootstrapState>>, bound: &BoundSet) {
    let state = bootstrap_state(bootstrap).await;
    let disallowed: Vec<IpAddr> = bound
        .snapshot_targets()
        .await
        .into_iter()
        .filter_map(|(ip, class)| (!HouseholdExposurePolicy::allows(state, class)).then_some(ip))
        .collect();
    for ip in disallowed {
        shutdown_bound_target(bound, ip, "bootstrap_state_policy").await;
    }
}

/// Spawn one `axum::serve` per bind target. Returns the set of addresses
/// that actually bound, so the Bonjour publisher can advertise only what's
/// reachable. Servers run in background tasks owned by tokio.
pub async fn spawn_household_listeners(
    router: Router,
    port: u16,
    bootstrap: Arc<RwLock<BootstrapState>>,
    bound: &BoundSet,
) -> Vec<(IpAddr, InterfaceClass)> {
    sync_interface_targets(&router, port, &bootstrap, bound, "startup").await
}

/// Periodic refresh task — every 60 s re-enumerates the local interfaces
/// and binds any newly discovered LAN/Tailscale address (e.g. a Tailscale
/// interface coming up after boot, Wi-Fi reconnect). Removed addresses are
/// dropped from the bound set so the Bonjour publisher stops advertising
/// them on the next state event.
pub async fn refresh_loop(
    router: Router,
    port: u16,
    bootstrap: Arc<RwLock<BootstrapState>>,
    bound: BoundSet,
) {
    let mut refresh = tokio::time::interval(INTERFACE_REFRESH_INTERVAL);
    refresh.tick().await; // skip the immediate first tick
    let mut policy_sync = tokio::time::interval(POLICY_SYNC_INTERVAL);
    policy_sync.tick().await; // skip the immediate first tick
    loop {
        tokio::select! {
            _ = refresh.tick() => {
                let live = sync_interface_targets(&router, port, &bootstrap, &bound, "refresh").await;
                info!(
                    stage = "household_listener.refresh",
                    target_count = live.len(),
                );
            }
            _ = policy_sync.tick() => {
                sync_exposure_policy(&bootstrap, &bound).await;
            }
        }
    }
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            // fe80::/10 link-local
            v6.segments()[0] & 0xffc0 == 0xfe80
        }
    }
}

fn classify(_name: &str, ip: &IpAddr) -> Option<InterfaceClass> {
    if crate::tailnet_address::is_tailnet_ip(*ip) {
        return Some(InterfaceClass::Tailscale);
    }
    if is_lan(ip) {
        return Some(InterfaceClass::Lan);
    }
    None
}

fn is_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => {
            // ULA fc00::/7. Tailscale's ULA prefix is filtered first.
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tailscale_v4() {
        let ip: IpAddr = "100.64.1.2".parse().unwrap();
        assert_eq!(classify("eth0", &ip), Some(InterfaceClass::Tailscale));
    }

    #[test]
    fn classify_tailscale_v6() {
        let ip: IpAddr = "fd7a:115c:a1e0::1234".parse().unwrap();
        assert_eq!(classify("utun7", &ip), Some(InterfaceClass::Tailscale));
    }

    #[test]
    fn classify_tailscale_named_non_tailnet_as_lan() {
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        assert_eq!(classify("tailscale0", &ip), Some(InterfaceClass::Lan));
    }

    #[test]
    fn classify_lan_v4() {
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(classify("en0", &ip), Some(InterfaceClass::Lan));
    }

    #[test]
    fn classify_public_v4_is_not_bound() {
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        assert_eq!(classify("en0", &ip), None);
    }

    #[test]
    fn classify_link_local_skipped() {
        let ip: IpAddr = "169.254.1.5".parse().unwrap();
        assert!(is_link_local(&ip));
    }

    #[tokio::test]
    async fn enumerate_includes_loopback() {
        let targets = enumerate_bind_targets();
        assert!(
            targets
                .iter()
                .any(|(ip, c)| { ip.is_loopback() && *c == InterfaceClass::Loopback })
        );
    }

    #[tokio::test]
    async fn bind_concrete_rejects_wildcard_addresses() {
        for addr in ["0.0.0.0:0", "[::]:0"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let err = bind_concrete(addr)
                .await
                .err()
                .expect("wildcard bind must be rejected");
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                err.to_string()
                    .contains("refusing to listen on wildcard 0.0.0.0/::"),
                "unexpected wildcard reject error: {err}"
            );
        }
    }

    #[tokio::test]
    async fn bound_set_preserves_interface_class() {
        let bound = BoundSet::default();
        let ip: IpAddr = "100.64.1.2".parse().unwrap();

        let (shutdown, _rx) = oneshot::channel();
        bound.insert(ip, InterfaceClass::Tailscale, shutdown).await;

        assert_eq!(bound.snapshot().await, vec![ip]);
        assert_eq!(
            bound.snapshot_targets().await,
            vec![(ip, InterfaceClass::Tailscale)]
        );
    }

    #[test]
    fn exposure_policy_onboarding_keeps_lan() {
        assert!(HouseholdExposurePolicy::allows(
            BootstrapState::Uninitialized,
            InterfaceClass::Lan
        ));
        assert!(HouseholdExposurePolicy::allows(
            BootstrapState::ReadyForNaming,
            InterfaceClass::Lan
        ));
    }

    #[test]
    fn exposure_policy_ready_excludes_lan_and_keeps_loopback_tailnet() {
        let targets = vec![
            (IpAddr::V4(Ipv4Addr::LOCALHOST), InterfaceClass::Loopback),
            ("192.0.2.10".parse().unwrap(), InterfaceClass::Lan),
            ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
        ];

        let allowed = HouseholdExposurePolicy::allowed_targets(BootstrapState::Ready, targets);
        assert_eq!(
            allowed,
            vec![
                (IpAddr::V4(Ipv4Addr::LOCALHOST), InterfaceClass::Loopback),
                ("100.64.0.10".parse().unwrap(), InterfaceClass::Tailscale),
            ]
        );
    }

    #[test]
    fn exposure_policy_transitional_states_exclude_lan() {
        for state in [
            BootstrapState::NamedAwaitingPair,
            BootstrapState::Recovering,
        ] {
            assert!(!HouseholdExposurePolicy::allows(state, InterfaceClass::Lan));
            assert!(HouseholdExposurePolicy::allows(
                state,
                InterfaceClass::Loopback
            ));
            assert!(HouseholdExposurePolicy::allows(
                state,
                InterfaceClass::Tailscale
            ));
        }
    }

    #[tokio::test]
    async fn exposure_policy_sync_shutdowns_disallowed_lan_listener() {
        let bound = BoundSet::default();
        let lan_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let tailnet_ip: IpAddr = "100.64.0.10".parse().unwrap();
        let (lan_shutdown, lan_rx) = oneshot::channel();
        let (tailnet_shutdown, _tailnet_rx) = oneshot::channel();
        bound
            .insert(lan_ip, InterfaceClass::Lan, lan_shutdown)
            .await;
        bound
            .insert(tailnet_ip, InterfaceClass::Tailscale, tailnet_shutdown)
            .await;

        let bootstrap = Arc::new(RwLock::new(BootstrapState::Ready));
        sync_exposure_policy(&bootstrap, &bound).await;

        assert_eq!(
            bound.snapshot_targets().await,
            vec![(tailnet_ip, InterfaceClass::Tailscale)]
        );
        tokio::time::timeout(Duration::from_secs(1), lan_rx)
            .await
            .expect("LAN listener shutdown signal should be sent")
            .expect("LAN listener shutdown sender should not be dropped before send");
    }

    #[test]
    fn listener_entry_points_route_enumeration_through_policy() {
        let source = include_str!("household_listener.rs");
        let sync_start = source
            .find("async fn sync_interface_targets")
            .expect("sync_interface_targets not found");
        let sync_end = source[sync_start..]
            .find("\nasync fn sync_exposure_policy")
            .map_or(source.len(), |offset| sync_start + offset);
        let sync_body = &source[sync_start..sync_end];
        assert!(
            sync_body.contains("HouseholdExposurePolicy::allowed_targets"),
            "sync_interface_targets must filter enumerated bind targets through HouseholdExposurePolicy"
        );

        let spawn_start = source
            .find("pub async fn spawn_household_listeners")
            .expect("spawn_household_listeners not found");
        let spawn_end = source[spawn_start..]
            .find("\n/// Periodic refresh task")
            .map_or(source.len(), |offset| spawn_start + offset);
        let spawn_body = &source[spawn_start..spawn_end];
        assert!(
            spawn_body.contains("sync_interface_targets"),
            "spawn_household_listeners must route initial binds through the policy-aware sync helper"
        );
    }
}
