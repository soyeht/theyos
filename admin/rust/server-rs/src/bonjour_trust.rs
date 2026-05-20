//! Tailnet trust filter for the Bonjour browser layer (FR-015).
//!
//! Every resolved Bonjour service carries one or more IP addresses. This
//! module classifies those addresses as coming from the **Tailnet** (safe,
//! always emitted to consumers) or from the **local network** (LAN bruta;
//! suppressed unless explicitly opted-in via [`BrowserConfig`]).
//!
//! ## Tailnet address ranges (Tailscale CGNAT)
//!
//! - IPv4 `100.64.0.0/10` (RFC 6598 shared address space, used by Tailscale)
//! - IPv6 `fd7a:115c:a1e0::/48` (Tailscale's permanent ULA prefix)
//! - IPv6 `fc00::/7` (RFC 4193 ULA range — covers `fc00::/8` and `fd00::/8`;
//!   Tailscale uses the `fd7a:115c:a1e0::/48` subset; other Tailnet
//!   implementations may use any prefix in this range)
//!
//! Anything outside these ranges is treated as `LocalNetwork`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where a discovered service's address originates from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Address is within Tailscale CGNAT or ULA ranges → trusted.
    Tailnet,
    /// Address is on the local LAN or any other non-Tailnet range → untrusted
    /// unless [`BrowserConfig::include_local_network`] is enabled.
    LocalNetwork,
}

/// Configuration for the Bonjour browser trust filter.
#[derive(Clone, Copy, Debug, Default)]
pub struct BrowserConfig {
    /// When `false` (default), only `Tailnet` discoveries are forwarded to
    /// consumers. When `true`, `LocalNetwork` discoveries are also forwarded.
    /// Enable only for explicit fallback flows where the user has opted in.
    pub include_local_network: bool,
}

// ── Classification ────────────────────────────────────────────────────────────

const TAILSCALE_IPV4_BASE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 0);
const TAILSCALE_IPV4_PREFIX_BITS: u32 = 10;

const TAILSCALE_ULA_BASE: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0);
const TAILSCALE_ULA_PREFIX_BITS: u32 = 48;

/// Classify a single IP address by its source.
///
/// ```
/// use std::net::IpAddr;
/// use server_rs::bonjour_trust::{DiscoverySource, classify_source};
///
/// // Tailscale CGNAT address
/// let ts_ip: IpAddr = "100.100.1.2".parse().unwrap();
/// assert_eq!(classify_source(ts_ip), DiscoverySource::Tailnet);
///
/// // Plain LAN address
/// let lan_ip: IpAddr = "192.168.1.10".parse().unwrap();
/// assert_eq!(classify_source(lan_ip), DiscoverySource::LocalNetwork);
/// ```
#[must_use]
pub fn classify_source(addr: IpAddr) -> DiscoverySource {
    match addr {
        IpAddr::V4(v4) => {
            if in_ipv4_prefix(v4, TAILSCALE_IPV4_BASE, TAILSCALE_IPV4_PREFIX_BITS) {
                DiscoverySource::Tailnet
            } else {
                DiscoverySource::LocalNetwork
            }
        }
        IpAddr::V6(v6) => {
            // Unwrap ::ffff:100.64.x.x (IPv4-mapped) and reclassify as IPv4.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_source(IpAddr::V4(v4));
            }
            if in_ipv6_prefix(v6, TAILSCALE_ULA_BASE, TAILSCALE_ULA_PREFIX_BITS) {
                DiscoverySource::Tailnet
            } else if v6.is_loopback() {
                // ::1 — loopback; treat as local in tests, suppressed in production.
                DiscoverySource::LocalNetwork
            } else if is_ula(v6) {
                // Broader fc00::/7 ULA (RFC 4193) — may be another Tailnet implementation.
                DiscoverySource::Tailnet
            } else {
                DiscoverySource::LocalNetwork
            }
        }
    }
}

fn in_ipv4_prefix(addr: Ipv4Addr, base: Ipv4Addr, prefix_bits: u32) -> bool {
    if prefix_bits == 0 {
        return true;
    }
    let shift = 32u32.saturating_sub(prefix_bits);
    (u32::from_be_bytes(addr.octets()) >> shift) == (u32::from_be_bytes(base.octets()) >> shift)
}

fn in_ipv6_prefix(addr: Ipv6Addr, base: Ipv6Addr, prefix_bits: u32) -> bool {
    if prefix_bits == 0 {
        return true;
    }
    let addr_u = u128::from_be_bytes(addr.octets());
    let base_u = u128::from_be_bytes(base.octets());
    let shift = 128u32.saturating_sub(prefix_bits);
    (addr_u >> shift) == (base_u >> shift)
}

fn is_ula(addr: Ipv6Addr) -> bool {
    // fc00::/7 (fc00:: - fdff::) are ULA; Tailscale uses fd00::/8 subset.
    let first_byte = addr.octets()[0];
    first_byte == 0xfc || first_byte == 0xfd
}

// ── Filter helper ─────────────────────────────────────────────────────────────

/// Return `true` if the given addresses should be forwarded to consumers
/// under `config`.
///
/// A service is forwarded if **at least one** of its addresses is Tailnet,
/// or if `include_local_network` is set and it has any address at all.
#[must_use]
pub fn should_emit<'a>(addrs: impl IntoIterator<Item = &'a IpAddr>, config: BrowserConfig) -> bool {
    let mut any_tailnet = false;
    let mut any_addr = false;
    for addr in addrs {
        any_addr = true;
        if classify_source(*addr) == DiscoverySource::Tailnet {
            any_tailnet = true;
            break;
        }
    }
    any_tailnet || (config.include_local_network && any_addr)
}

/// Like [`should_emit`], but also consults a TXT-advertised Tailnet hint.
///
/// iOS `mDNSResponder` announces `NWListener.service` on every interface
/// (LAN + Tailnet). `NWParameters.requiredInterfaceType` restricts only
/// the SOCKET, not the mDNS announcement. Pure mDNS-address filtering
/// therefore rejects iPhones on the same Wi-Fi as the Mac even when the
/// iPhone IS reachable on Tailnet.
///
/// To recover those services, the iPhone publisher self-reports its
/// Tailnet address in the TXT record under the `tailnet_addr` key. We
/// only trust that hint if it parses to an IP in a Tailnet range
/// (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`, or broader `fc00::/7` ULA —
/// the same set [`classify_source`] uses).
///
/// Order of decision:
/// 1. If any of the resolved mDNS addresses is Tailnet → emit.
/// 2. Else if `txt_tailnet_hint` is `Some(ip)` and the IP classifies as
///    Tailnet → emit (the iPhone vouched for itself).
/// 3. Else fall back to [`should_emit`]'s `include_local_network` branch
///    (i.e. emit only if the operator opted in to LAN bruta).
///
/// The TXT hint is an **additive, per-service** trust signal. It does not
/// relax the default global posture — [`BrowserConfig::default()`] still
/// rejects LAN-only services that carry no hint or a non-Tailnet hint.
#[must_use]
pub fn should_emit_with_txt_hint<'a>(
    addrs: impl IntoIterator<Item = &'a IpAddr>,
    txt_tailnet_hint: Option<&IpAddr>,
    config: BrowserConfig,
) -> bool {
    // Materialize the iterator so we can both classify it and re-use it
    // in the `include_local_network` fallback without consuming twice.
    let collected: Vec<IpAddr> = addrs.into_iter().copied().collect();

    let mut any_tailnet = false;
    let any_addr = !collected.is_empty();
    for addr in &collected {
        if classify_source(*addr) == DiscoverySource::Tailnet {
            any_tailnet = true;
            break;
        }
    }
    if any_tailnet {
        return true;
    }
    if let Some(hint) = txt_tailnet_hint {
        if classify_source(*hint) == DiscoverySource::Tailnet {
            return true;
        }
    }
    config.include_local_network && any_addr
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }
    fn ip6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn tailscale_cgnat_is_tailnet() {
        assert_eq!(classify_source(ip4("100.64.0.1")), DiscoverySource::Tailnet);
        assert_eq!(
            classify_source(ip4("100.100.200.50")),
            DiscoverySource::Tailnet
        );
        assert_eq!(
            classify_source(ip4("100.127.255.255")),
            DiscoverySource::Tailnet
        );
    }

    #[test]
    fn addresses_outside_cgnat_are_local() {
        assert_eq!(
            classify_source(ip4("192.168.1.10")),
            DiscoverySource::LocalNetwork
        );
        assert_eq!(
            classify_source(ip4("10.0.0.1")),
            DiscoverySource::LocalNetwork
        );
        assert_eq!(
            classify_source(ip4("172.16.0.1")),
            DiscoverySource::LocalNetwork
        );
        assert_eq!(
            classify_source(ip4("100.63.255.255")),
            DiscoverySource::LocalNetwork
        );
        assert_eq!(
            classify_source(ip4("100.128.0.0")),
            DiscoverySource::LocalNetwork
        );
    }

    #[test]
    fn tailscale_ula_is_tailnet() {
        assert_eq!(
            classify_source(ip6("fd7a:115c:a1e0::1")),
            DiscoverySource::Tailnet
        );
        assert_eq!(
            classify_source(ip6("fd7a:115c:a1e0:ab12::1")),
            DiscoverySource::Tailnet
        );
    }

    #[test]
    fn broader_ula_is_tailnet() {
        assert_eq!(classify_source(ip6("fd00::1")), DiscoverySource::Tailnet);
        assert_eq!(
            classify_source(ip6("fd12:3456:7890::1")),
            DiscoverySource::Tailnet
        );
        assert_eq!(classify_source(ip6("fc00::1")), DiscoverySource::Tailnet);
    }

    #[test]
    fn global_ipv6_is_local() {
        assert_eq!(
            classify_source(ip6("2001:db8::1")),
            DiscoverySource::LocalNetwork
        );
        assert_eq!(
            classify_source(ip6("fe80::1")),
            DiscoverySource::LocalNetwork
        );
    }

    #[test]
    fn loopback_is_local() {
        assert_eq!(
            classify_source(ip4("127.0.0.1")),
            DiscoverySource::LocalNetwork
        );
        assert_eq!(classify_source(ip6("::1")), DiscoverySource::LocalNetwork);
    }

    #[test]
    fn ipv4_mapped_tailscale_is_tailnet() {
        // ::ffff:100.64.1.2 — IPv4-mapped Tailscale CGNAT address
        assert_eq!(
            classify_source(ip6("::ffff:100.64.1.2")),
            DiscoverySource::Tailnet
        );
    }

    #[test]
    fn ipv4_mapped_lan_is_local() {
        // ::ffff:192.168.1.5 — IPv4-mapped LAN address
        assert_eq!(
            classify_source(ip6("::ffff:192.168.1.5")),
            DiscoverySource::LocalNetwork
        );
    }

    #[test]
    fn should_emit_tailnet_only() {
        let addrs = vec![ip4("100.64.1.1"), ip4("192.168.0.1")];
        let config = BrowserConfig {
            include_local_network: false,
        };
        assert!(should_emit(&addrs, config), "Tailnet addr present → emit");
    }

    #[test]
    fn should_emit_lan_suppressed_by_default() {
        let addrs = vec![ip4("192.168.0.1")];
        let config = BrowserConfig {
            include_local_network: false,
        };
        assert!(!should_emit(&addrs, config), "LAN-only → suppressed");
    }

    #[test]
    fn should_emit_lan_when_opted_in() {
        let addrs = vec![ip4("192.168.0.1")];
        let config = BrowserConfig {
            include_local_network: true,
        };
        assert!(should_emit(&addrs, config), "LAN with opt-in → emit");
    }

    #[test]
    fn should_emit_ipv6_tailnet() {
        let addrs = vec![ip6("fd7a:115c:a1e0::2")];
        let config = BrowserConfig {
            include_local_network: false,
        };
        assert!(should_emit(&addrs, config), "IPv6 Tailnet → emit");
    }

    #[test]
    fn should_emit_ipv6_lan_suppressed() {
        let addrs = vec![ip6("fe80::1")];
        let config = BrowserConfig {
            include_local_network: false,
        };
        assert!(!should_emit(&addrs, config), "IPv6 link-local → suppressed");
    }

    #[test]
    fn should_emit_empty_addrs_is_false() {
        let addrs: Vec<IpAddr> = vec![];
        assert!(!should_emit(&addrs, BrowserConfig::default()));
        assert!(!should_emit(
            &addrs,
            BrowserConfig {
                include_local_network: true
            }
        ));
    }

    // ── should_emit_with_txt_hint ─────────────────────────────────────────

    #[test]
    fn should_emit_with_txt_hint_promotes_lan_when_tailnet_txt_present() {
        // mDNS announced only on LAN, but the iPhone vouches for its own
        // Tailnet address via TXT. We must trust that hint and emit.
        let addrs = vec![ip4("192.168.1.42"), ip6("fe80::1")];
        let hint = ip4("100.100.55.7");
        let config = BrowserConfig::default(); // include_local_network=false
        assert!(
            should_emit_with_txt_hint(&addrs, Some(&hint), config),
            "LAN-only addrs + Tailnet TXT hint → emit"
        );
    }

    #[test]
    fn should_emit_with_txt_hint_rejects_lan_txt_value() {
        // TXT carries an IP, but it's a LAN address — not Tailnet. Hint
        // must be ignored and the service stays suppressed under default
        // config (no opt-in to LAN bruta).
        let addrs = vec![ip4("192.168.1.42")];
        let bogus_hint = ip4("10.0.0.5");
        let config = BrowserConfig::default();
        assert!(
            !should_emit_with_txt_hint(&addrs, Some(&bogus_hint), config),
            "LAN TXT hint must not promote a LAN-only service"
        );

        // IPv6 link-local hint also rejected.
        let bogus_v6_hint = ip6("fe80::dead");
        assert!(
            !should_emit_with_txt_hint(&addrs, Some(&bogus_v6_hint), config),
            "IPv6 link-local TXT hint must not promote"
        );
    }

    #[test]
    fn should_emit_with_txt_hint_rejects_garbage_txt() {
        // The browser parses `resolved.txt("tailnet_addr")` via
        // `IpAddr::from_str`; a non-IP value yields `None`. We model that
        // here: `txt_tailnet_hint = None`. Service stays suppressed.
        let addrs = vec![ip4("192.168.1.42")];
        let config = BrowserConfig::default();
        assert!(
            !should_emit_with_txt_hint(&addrs, None, config),
            "Garbage / missing TXT (None hint) must not promote"
        );
    }

    #[test]
    fn should_emit_with_txt_hint_no_hint_falls_back_to_should_emit() {
        // Without a hint, behaviour must match `should_emit` exactly for
        // every combination of (Tailnet-in-addrs, opt-in flag).
        let tailnet_addrs = vec![ip4("100.64.1.1")];
        let lan_addrs = vec![ip4("192.168.0.1")];
        let no_addrs: Vec<IpAddr> = vec![];

        for &include_local in &[false, true] {
            let config = BrowserConfig {
                include_local_network: include_local,
            };
            assert_eq!(
                should_emit_with_txt_hint(&tailnet_addrs, None, config),
                should_emit(&tailnet_addrs, config),
                "Tailnet addrs, include_local={include_local}: hinted=None must match should_emit",
            );
            assert_eq!(
                should_emit_with_txt_hint(&lan_addrs, None, config),
                should_emit(&lan_addrs, config),
                "LAN addrs, include_local={include_local}: hinted=None must match should_emit",
            );
            assert_eq!(
                should_emit_with_txt_hint(&no_addrs, None, config),
                should_emit(&no_addrs, config),
                "Empty addrs, include_local={include_local}: hinted=None must match should_emit",
            );
        }
    }

    #[test]
    fn should_emit_with_txt_hint_does_not_override_tailnet_in_addrs() {
        // Sanity: if addrs already contain a Tailnet IP, we emit
        // regardless of the hint (including garbage or absent).
        let addrs = vec![ip4("100.64.1.1"), ip4("192.168.0.1")];
        let config = BrowserConfig::default();
        assert!(should_emit_with_txt_hint(&addrs, None, config));
        let lan_hint = ip4("10.0.0.5");
        assert!(should_emit_with_txt_hint(&addrs, Some(&lan_hint), config));
    }

    #[test]
    fn should_emit_with_txt_hint_respects_include_local_when_no_tailnet_signal() {
        // No Tailnet in addrs, no usable TXT hint, but operator opted into
        // LAN bruta. Should emit because there is at least one address.
        let addrs = vec![ip4("192.168.0.1")];
        let config = BrowserConfig {
            include_local_network: true,
        };
        assert!(should_emit_with_txt_hint(&addrs, None, config));
        let bogus_hint = ip4("10.0.0.5");
        assert!(should_emit_with_txt_hint(&addrs, Some(&bogus_hint), config));
    }
}
