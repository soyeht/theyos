//! Household-endpoint listener.
//!
//! Binds a fresh axum router to:
//! - `127.0.0.1` and `::1` (always),
//! - every active LAN-class address (`192.168/16`, `10/8`, `172.16/12`, IPv6
//!   global), excluding link-local `169.254/16` / `fe80::/10`,
//! - every Tailscale address (interface name `tailscale*` OR address in
//!   `100.64.0.0/10` / `fd7a:115c:a1e0::/48`).
//!
//! Refuses wildcard `0.0.0.0` / `::` per FR-008. Refreshes the active address
//! set every 60 s.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{info, warn};

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
#[derive(Clone, Default)]
pub struct BoundSet {
    inner: Arc<Mutex<HashMap<IpAddr, InterfaceClass>>>,
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
            .map(|(ip, class)| (*ip, *class))
            .collect()
    }

    async fn contains(&self, ip: IpAddr) -> bool {
        self.inner.lock().await.contains_key(&ip)
    }

    async fn insert(&self, ip: IpAddr, class: InterfaceClass) {
        self.inner.lock().await.insert(ip, class);
    }

    async fn remove(&self, ip: IpAddr) {
        self.inner.lock().await.remove(&ip);
    }
}

/// Spawn one `axum::serve` per bind target. Returns the set of addresses
/// that actually bound, so the Bonjour publisher can advertise only what's
/// reachable. Servers run in background tasks owned by tokio.
pub async fn spawn_household_listeners(
    router: Router,
    port: u16,
    bound: &BoundSet,
) -> Vec<(IpAddr, InterfaceClass)> {
    let targets = enumerate_bind_targets();
    let mut bound_targets = Vec::new();
    for (ip, class) in targets {
        let addr = SocketAddr::new(ip, port);
        match bind_concrete(addr).await {
            Ok(listener) => {
                info!(
                    stage = "bootstrap.endpoint.live",
                    address = %addr,
                    interface_class = class.as_str(),
                    result = "ok",
                );
                bound.insert(ip, class).await;
                bound_targets.push((ip, class));
                let app = router.clone();
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(
                        listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
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
            Err(e) => {
                warn!(
                    stage = "bootstrap.endpoint.bind_failed",
                    address = %addr,
                    interface_class = class.as_str(),
                    error = %e,
                );
            }
        }
    }
    bound_targets
}

/// Periodic refresh task — every 60 s re-enumerates the local interfaces
/// and binds any newly discovered LAN/Tailscale address (e.g. a Tailscale
/// interface coming up after boot, Wi-Fi reconnect). Removed addresses are
/// dropped from the bound set so the Bonjour publisher stops advertising
/// them on the next state event.
pub async fn refresh_loop(router: Router, port: u16, bound: BoundSet) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.tick().await; // skip the immediate first tick
    loop {
        interval.tick().await;
        let live = enumerate_bind_targets();
        let live_set: HashSet<IpAddr> = live.iter().map(|(ip, _)| *ip).collect();

        // Bind newly available addresses.
        for (ip, class) in &live {
            if bound.contains(*ip).await {
                continue;
            }
            let addr = SocketAddr::new(*ip, port);
            match bind_concrete(addr).await {
                Ok(listener) => {
                    info!(
                        stage = "bootstrap.endpoint.live",
                        address = %addr,
                        interface_class = class.as_str(),
                        result = "ok",
                        source = "refresh",
                    );
                    bound.insert(*ip, *class).await;
                    let app = router.clone();
                    tokio::spawn(async move {
                        if let Err(e) = axum::serve(
                            listener,
                            app.into_make_service_with_connect_info::<SocketAddr>(),
                        )
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
                Err(e) => warn!(
                    stage = "bootstrap.endpoint.bind_failed",
                    address = %addr,
                    interface_class = class.as_str(),
                    error = %e,
                    source = "refresh",
                ),
            }
        }

        // Drop addresses that disappeared. The axum::serve task associated
        // with the gone address will fail on its own once the underlying
        // socket closes; we only update the bookkeeping so Bonjour stops
        // advertising it on the next TXT event.
        let stale: Vec<IpAddr> = bound
            .snapshot()
            .await
            .into_iter()
            .filter(|ip| !live_set.contains(ip))
            .collect();
        for ip in stale {
            bound.remove(ip).await;
            info!(
                stage = "household_listener.address_removed",
                address = %ip,
            );
        }

        info!(
            stage = "household_listener.refresh",
            target_count = live.len(),
        );
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
    async fn bound_set_preserves_interface_class() {
        let bound = BoundSet::default();
        let ip: IpAddr = "100.64.1.2".parse().unwrap();

        bound.insert(ip, InterfaceClass::Tailscale).await;

        assert_eq!(bound.snapshot().await, vec![ip]);
        assert_eq!(
            bound.snapshot_targets().await,
            vec![(ip, InterfaceClass::Tailscale)]
        );
    }
}
