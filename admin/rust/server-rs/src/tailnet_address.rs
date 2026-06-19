//! Local Tailnet IPv4 detection for the engine.
//!
//! Walks the system's interface list and returns the first IPv4 address that
//! belongs to a Tailscale-managed interface (`utun*` on macOS, `tailscale*`
//! on Linux) AND falls within Tailscale's CGNAT range `100.64.0.0/10`.
//!
//! Used by `post_claim_setup_invitation` to advertise the engine's OWN
//! Tailnet address as the `mac_engine_url` returned to the iPhone in the
//! claim ACK. This is the symmetric companion to the iPhone's
//! `tailnet_addr` TXT hint (PR #75): if the iPhone connects to the engine
//! via the LAN hostname, the source IP will be a LAN address and the
//! `tailnet_required` guard on `POST /bootstrap/initialize` will reject the
//! request. By steering the iPhone to the engine's Tailnet IP we guarantee
//! the source IP is also a Tailnet address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Resolver function type — returns the engine's local Tailnet IPv4 if any.
///
/// Stored in `BootstrapHandlerState` so contract tests can swap in a
/// deterministic resolver without touching process-wide env vars (which
/// would race other tests under the default parallel test runner).
pub type TailnetResolver = fn() -> Option<Ipv4Addr>;

/// Default well-known Tailscale interface name prefixes.
///
/// macOS: Tailscale's userspace `tun` device shows up as `utunN`. We accept
/// any `utun*` interface and rely on the CGNAT range filter below to discard
/// other userspace tuns that don't carry Tailnet addresses.
///
/// Linux: the Tailscale kernel module names its interface `tailscaleN`.
const TAILSCALE_INTERFACE_PREFIXES: &[&str] = &["utun", "tailscale"];

/// `true` if `ip` is in Tailscale's CGNAT range `100.64.0.0/10`.
///
/// The CGNAT block is `100.64.0.0` through `100.127.255.255` (the first
/// octet is `100` and the second octet's high six bits are `010000xx` —
/// i.e. the second octet is in `64..=127`).
#[must_use]
pub fn is_tailnet_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

/// `true` if `ip` is in Tailscale's IPv6 ULA range
/// `fd7a:115c:a1e0::/48`.
#[must_use]
pub fn is_tailnet_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
}

/// `true` if `ip` is in one of Tailscale's well-known address ranges.
#[must_use]
pub fn is_tailnet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_tailnet_ipv4(v4),
        IpAddr::V6(v6) => is_tailnet_ipv6(v6),
    }
}

/// Scan the local interface list and return the first IPv4 address that
/// belongs to a Tailscale-managed interface AND sits inside the
/// `100.64.0.0/10` CGNAT range.
///
/// Returns `None` if no such address is present — the engine is either not
/// on a Tailnet, or the Tailscale userspace daemon has not finished
/// configuring its tun interface yet.
#[must_use]
pub fn current_tailnet_ipv4() -> Option<Ipv4Addr> {
    let addrs = if_addrs::get_if_addrs().ok()?;
    for ifa in addrs {
        if !is_tailscale_interface_name(&ifa.name) {
            continue;
        }
        if let std::net::IpAddr::V4(v4) = ifa.ip() {
            if is_tailnet_ipv4(v4) {
                return Some(v4);
            }
        }
    }
    None
}

fn is_tailscale_interface_name(name: &str) -> bool {
    TAILSCALE_INTERFACE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Source label for `mac_engine_url` — used in structured logs so operators
/// can tell whether the engine handed the iPhone its Tailnet IP or fell back
/// to the legacy LAN URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacEngineUrlSource {
    /// URL was built from the engine's own Tailnet IPv4 — the iPhone will
    /// connect via Tailnet, source IP will pass the `tailnet_required`
    /// guard on `POST /bootstrap/initialize`.
    Tailnet,
    /// No Tailnet IP available — caller should fall back to whatever URL
    /// the iPhone would otherwise discover (e.g. via Bonjour mDNS).
    Fallback,
}

impl MacEngineUrlSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tailnet => "tailnet",
            Self::Fallback => "fallback",
        }
    }
}

/// Build `http://<tailnet_ip>:<port>` using `resolver` to discover the
/// engine's Tailnet IPv4.
///
/// Returns `(None, Fallback)` when no Tailnet address is present so the
/// caller can keep its existing (LAN / mDNS) URL.
#[must_use]
pub fn build_mac_engine_url(
    port: u16,
    resolver: TailnetResolver,
) -> (Option<String>, MacEngineUrlSource) {
    match resolver() {
        Some(ip) => (
            Some(format!("http://{ip}:{port}")),
            MacEngineUrlSource::Tailnet,
        ),
        None => (None, MacEngineUrlSource::Fallback),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgnat_lower_bound_is_tailnet() {
        assert!(is_tailnet_ipv4(Ipv4Addr::new(100, 64, 0, 0)));
    }

    #[test]
    fn cgnat_upper_bound_is_tailnet() {
        assert!(is_tailnet_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
    }

    #[test]
    fn mid_cgnat_is_tailnet() {
        assert!(is_tailnet_ipv4(Ipv4Addr::new(100, 64, 0, 10)));
    }

    #[test]
    fn tailscale_ula_is_tailnet() {
        assert!(is_tailnet_ipv6("fd7a:115c:a1e0::10".parse().unwrap()));
        assert!(is_tailnet_ip("100.64.0.10".parse().unwrap()));
        assert!(is_tailnet_ip("fd7a:115c:a1e0::10".parse().unwrap()));
    }

    #[test]
    fn non_tailscale_ipv6_is_not_tailnet() {
        assert!(!is_tailnet_ipv6("fd7a:115c:a1e1::10".parse().unwrap()));
        assert!(!is_tailnet_ip("2001:db8::10".parse().unwrap()));
    }

    #[test]
    fn second_octet_63_is_not_tailnet() {
        assert!(!is_tailnet_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
    }

    #[test]
    fn second_octet_128_is_not_tailnet() {
        assert!(!is_tailnet_ipv4(Ipv4Addr::new(100, 128, 0, 0)));
    }

    #[test]
    fn first_octet_not_100_is_not_tailnet() {
        assert!(!is_tailnet_ipv4(Ipv4Addr::new(99, 64, 0, 0)));
        assert!(!is_tailnet_ipv4(Ipv4Addr::new(101, 64, 0, 0)));
    }

    #[test]
    fn rfc1918_is_not_tailnet() {
        assert!(!is_tailnet_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_tailnet_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_tailnet_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
    }

    #[test]
    fn public_address_is_not_tailnet() {
        assert!(!is_tailnet_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn loopback_is_not_tailnet() {
        assert!(!is_tailnet_ipv4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn macos_tailscale_interface_name_matches() {
        assert!(is_tailscale_interface_name("utun4"));
        assert!(is_tailscale_interface_name("utun10"));
    }

    #[test]
    fn linux_tailscale_interface_name_matches() {
        assert!(is_tailscale_interface_name("tailscale0"));
        assert!(is_tailscale_interface_name("tailscale1"));
    }

    #[test]
    fn ethernet_interface_name_does_not_match() {
        assert!(!is_tailscale_interface_name("en0"));
        assert!(!is_tailscale_interface_name("eth0"));
        assert!(!is_tailscale_interface_name("lo0"));
        assert!(!is_tailscale_interface_name("wlan0"));
    }

    #[test]
    fn source_label_string() {
        assert_eq!(MacEngineUrlSource::Tailnet.as_str(), "tailnet");
        assert_eq!(MacEngineUrlSource::Fallback.as_str(), "fallback");
    }

    // Resolvers must match the `TailnetResolver` fn-pointer signature
    // exactly, so they have to return `Option<Ipv4Addr>` even when the
    // body is unconditionally `Some(_)` / `None`.
    #[allow(clippy::unnecessary_wraps)]
    fn resolver_present() -> Option<Ipv4Addr> {
        Some(Ipv4Addr::new(100, 64, 0, 10))
    }

    fn resolver_absent() -> Option<Ipv4Addr> {
        None
    }

    #[test]
    fn build_url_when_resolver_returns_tailnet_ip() {
        let (url, source) = build_mac_engine_url(8091, resolver_present);
        assert_eq!(url.as_deref(), Some("http://100.64.0.10:8091"));
        assert_eq!(source, MacEngineUrlSource::Tailnet);
    }

    #[test]
    fn build_url_when_resolver_returns_none_falls_back() {
        let (url, source) = build_mac_engine_url(8091, resolver_absent);
        assert!(url.is_none());
        assert_eq!(source, MacEngineUrlSource::Fallback);
    }

    #[test]
    fn no_experimental_transport_bleed_in_household_sources() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let relative_paths = [
            "src/handlers_household_claws.rs",
            "src/household_listener.rs",
            "src/tailnet_address.rs",
            "tests/household_instances.rs",
            "tests/claim_setup_invitation_contract.rs",
        ];
        let forbidden_tokens = [
            ["10", ".", "44"].concat(),
            ["Product", " ", "A"].concat(),
            ["n", "v", "p", "n"].concat(),
            ["Claw", "Share", "Bridge"].concat(),
            ["is_household_", "mesh"].concat(),
            ["mesh", "-only"].concat(),
            ["mesh_", "peer"].concat(),
        ];

        for relative_path in relative_paths {
            let source = std::fs::read_to_string(crate_root.join(relative_path))
                .unwrap_or_else(|e| panic!("read {relative_path}: {e}"));
            for token in &forbidden_tokens {
                assert!(
                    !source.contains(token),
                    "{relative_path} must not reintroduce {token}"
                );
            }
        }
    }
}
