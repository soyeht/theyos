//! M0a — NAT mapping probe.
//!
//! Sends an RFC 5389 binding request to **two different STUN servers from one
//! UDP socket** and records what each reported. Its output is telemetry for
//! deciding where relays go and how much direct traffic to expect; it is not an
//! input to any datapath.
//!
//! # It records observations, never a verdict
//!
//! There is deliberately no `direct_possible` field. RFC 5780 §2 separates
//! *mapping* behaviour (does the external port depend on the destination?) from
//! *filtering* behaviour (who may send back?), and is explicit that both are
//! momentary observations which vary with load and destination. This probe
//! measures mapping only — it never sends from a second server address, which
//! is what a filtering test requires.
//!
//! So [`NatObservation::mapping_consistent`] reads as:
//!
//! * `Some(true)` — both servers saw the same external address. A *good sign*
//!   for hole punching, not a guarantee.
//! * `Some(false)` — the mapping varied by destination. Direct paths are
//!   *harder*, not impossible.
//! * `None` — at least one server did not answer, so the comparison was never
//!   made. Distinct from `Some(false)`, which is a real measurement.
//!
//! A failed server is recorded with its reason rather than dropped: a row that
//! vanishes on failure biases the sample toward networks that work.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

pub mod stun;

use stun::{TRANSACTION_ID_BYTES, TransactionId};

/// Public STUN servers run by two independent operators.
///
/// Two operators rather than two addresses of one deployment: a single operator
/// may answer both from the same NAT-facing prefix, which can make a mapping
/// look destination-independent when it only ever saw one destination.
pub const DEFAULT_STUN_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

/// Per-server timeout. UDP is lossy, so the probe retries within this budget.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Binding requests sent per server before giving up.
pub const DEFAULT_ATTEMPTS: u32 = 3;

/// Operator-supplied context that cannot be measured from the host.
///
/// `country` and `asn` are taken from the operator rather than looked up: an
/// automatic lookup means sending this machine's public address to a third-party
/// geolocation service on every probe run, which is a data-sharing decision the
/// probe should not make on its own.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProbeLabels {
    /// ISO country code of the vantage point, e.g. `BR`.
    pub country: Option<String>,
    /// Autonomous system of the uplink, e.g. `AS28573`.
    pub asn: Option<String>,
    /// How this host is attached: `ethernet`, `wifi`, `wifi-cafe`, `5g`.
    pub network_type: Option<String>,
}

/// What one STUN server reported.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ServerOutcome {
    /// The server answered with a reflexive transport address.
    Observed {
        /// The server queried.
        server: String,
        /// The external address it saw.
        mapped: SocketAddr,
        /// Round trip of the request that answered.
        rtt_ms: f64,
    },
    /// The server did not answer, or answered unusably.
    Failed {
        /// The server queried.
        server: String,
        /// Why, in operator-readable terms.
        reason: String,
    },
}

impl ServerOutcome {
    /// The mapped address, when one was observed.
    #[must_use]
    pub fn mapped(&self) -> Option<SocketAddr> {
        match self {
            Self::Observed { mapped, .. } => Some(*mapped),
            Self::Failed { .. } => None,
        }
    }

    /// The round trip, when the server answered.
    #[must_use]
    pub fn rtt_ms(&self) -> Option<f64> {
        match self {
            Self::Observed { rtt_ms, .. } => Some(*rtt_ms),
            Self::Failed { .. } => None,
        }
    }
}

/// One probe run: every field recorded, no conclusion drawn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatObservation {
    /// Seconds since the Unix epoch. A measurement without a time cannot be
    /// compared against a later one from the same vantage point.
    pub observed_at: u64,
    /// Operator-supplied country code.
    pub country: Option<String>,
    /// Operator-supplied autonomous system.
    pub asn: Option<String>,
    /// Operator-supplied attachment type.
    pub network_type: Option<String>,
    /// Round trip to the first server that answered.
    pub rtt_ms: Option<f64>,
    /// Whether this host holds a global-unicast IPv6 address.
    #[serde(rename = "ipv6_disponivel")]
    pub ipv6_available: bool,
    /// Local port both requests were sent from.
    #[serde(rename = "porta_local")]
    pub local_port: u16,
    /// External address reported by the first server.
    pub mapped_ip_1: Option<IpAddr>,
    /// External port reported by the first server.
    pub mapped_port_1: Option<u16>,
    /// External address reported by the second server.
    pub mapped_ip_2: Option<IpAddr>,
    /// External port reported by the second server.
    pub mapped_port_2: Option<u16>,
    /// Whether both servers saw the same external address. `None` when one did
    /// not answer — see the module doc; this is not `false`.
    pub mapping_consistent: Option<bool>,
    /// Full per-server detail, including failures.
    pub servers: Vec<ServerOutcome>,
}

/// Where and how to probe.
#[derive(Debug, Clone)]
pub struct ProbeSettings {
    /// The two STUN servers, as `host:port`.
    pub servers: [String; 2],
    /// Per-server budget across all attempts.
    pub timeout: Duration,
    /// Requests per server before giving up.
    pub attempts: u32,
}

impl Default for ProbeSettings {
    fn default() -> Self {
        Self {
            servers: [
                DEFAULT_STUN_SERVERS[0].to_owned(),
                DEFAULT_STUN_SERVERS[1].to_owned(),
            ],
            timeout: DEFAULT_TIMEOUT,
            attempts: DEFAULT_ATTEMPTS,
        }
    }
}

/// Run one probe.
///
/// # Errors
///
/// Returns an error only when the local socket cannot be created or its port
/// read. A server that fails to answer is recorded in the observation, not
/// raised — losing those rows would bias the sample toward working networks.
pub fn observe(settings: &ProbeSettings, labels: &ProbeLabels) -> io::Result<NatObservation> {
    // One socket for both servers. This is the entire point of the probe: two
    // requests from two *different* sockets would be two unrelated mappings and
    // could never answer whether the mapping depends on the destination.
    //
    // IPv4 specifically: the mapping question this probe asks only exists under
    // NAT44. IPv6 reachability is a separate field, measured from the interface
    // list, and needs no STUN round trip to establish.
    let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))?;
    let local_port = socket.local_addr()?.port();

    let outcomes: Vec<ServerOutcome> = settings
        .servers
        .iter()
        .map(|server| query_server(&socket, server, settings.timeout, settings.attempts))
        .collect();

    let first = outcomes[0].mapped();
    let second = outcomes[1].mapped();
    let mapping_consistent = match (first, second) {
        (Some(a), Some(b)) => Some(a == b),
        _ => None,
    };

    Ok(NatObservation {
        observed_at: unix_seconds(),
        country: labels.country.clone(),
        asn: labels.asn.clone(),
        network_type: labels.network_type.clone(),
        rtt_ms: outcomes.iter().find_map(ServerOutcome::rtt_ms),
        ipv6_available: has_global_unicast_ipv6(),
        local_port,
        mapped_ip_1: first.map(|addr| addr.ip()),
        mapped_port_1: first.map(|addr| addr.port()),
        mapped_ip_2: second.map(|addr| addr.ip()),
        mapped_port_2: second.map(|addr| addr.port()),
        mapping_consistent,
        servers: outcomes,
    })
}

fn query_server(
    socket: &UdpSocket,
    server: &str,
    timeout: Duration,
    attempts: u32,
) -> ServerOutcome {
    let failed = |reason: String| ServerOutcome::Failed {
        server: server.to_owned(),
        reason,
    };

    // Take the server's IPv4 address specifically, not simply the first one
    // resolution offers. The socket is v4-bound (see `observe`), and on a host
    // with IPv6 these servers resolve to their AAAA first — sending there from
    // a v4 socket fails `EINVAL` and every row comes back empty.
    let resolved = match server.to_socket_addrs() {
        Ok(mut addrs) => addrs.find(SocketAddr::is_ipv4),
        Err(error) => return failed(format!("resolution failed: {error}")),
    };
    let Some(destination) = resolved else {
        return failed("resolved to no IPv4 address".to_owned());
    };

    let mut last = "no attempt completed".to_owned();
    for _ in 0..attempts.max(1) {
        match attempt(socket, destination, timeout) {
            Ok(Some((mapped, rtt))) => {
                return ServerOutcome::Observed {
                    server: server.to_owned(),
                    mapped,
                    rtt_ms: rtt.as_secs_f64() * 1_000.0,
                };
            }
            Ok(None) => last = format!("no answer within {timeout:?}"),
            Err(error) => last = format!("socket error: {error}"),
        }
    }
    failed(last)
}

fn attempt(
    socket: &UdpSocket,
    destination: SocketAddr,
    timeout: Duration,
) -> io::Result<Option<(SocketAddr, Duration)>> {
    let transaction_id = new_transaction_id();
    let request = stun::encode_binding_request(&transaction_id);

    let sent_at = Instant::now();
    socket.send_to(&request, destination)?;

    let deadline = sent_at + timeout;
    let mut buffer = [0u8; 1500];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        socket.set_read_timeout(Some(remaining))?;

        let received = match socket.recv_from(&mut buffer) {
            Ok((len, _from)) => len,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };

        // A wildcard-bound socket receives unrelated traffic. Anything that is
        // not an answer to *this* transaction is discarded and the wait
        // continues, rather than being reported as the observed mapping.
        if let Ok(mapped) = stun::decode_mapped_address(&buffer[..received], &transaction_id) {
            return Ok(Some((mapped, sent_at.elapsed())));
        }
    }
}

fn new_transaction_id() -> TransactionId {
    let mut id = [0u8; TRANSACTION_ID_BYTES];
    OsRng.fill_bytes(&mut id);
    id
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Whether any interface holds a global-unicast IPv6 address.
///
/// Global unicast specifically: a link-local or unique-local address does not
/// give an easier path to a peer, and the overlay's own ULA prefix must never
/// be read as "this host has IPv6 connectivity".
#[must_use]
pub fn has_global_unicast_ipv6() -> bool {
    if_addrs::get_if_addrs().is_ok_and(|interfaces| {
        interfaces.iter().any(|interface| match interface.addr {
            if_addrs::IfAddr::V6(ref v6) => is_global_unicast_ipv6(v6.ip),
            if_addrs::IfAddr::V4(_) => false,
        })
    })
}

fn is_global_unicast_ipv6(addr: Ipv6Addr) -> bool {
    let octets = addr.octets();
    let link_local = (u16::from_be_bytes([octets[0], octets[1]]) & 0xFFC0) == 0xFE80;
    let unique_local = (octets[0] & 0xFE) == 0xFC;

    !addr.is_loopback()
        && !addr.is_unspecified()
        && !addr.is_multicast()
        && !link_local
        && !unique_local
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn defaults_name_two_independent_operators() {
        let settings = ProbeSettings::default();
        assert_ne!(
            settings.servers[0], settings.servers[1],
            "one server cannot answer whether a mapping depends on the destination"
        );
        assert_eq!(settings.attempts, DEFAULT_ATTEMPTS);
    }

    #[test]
    fn global_unicast_excludes_loopback_link_local_and_ula() {
        // Both from 2001:db8::/32, the reserved documentation prefix, which
        // sits inside global unicast 2000::/3. A real ISP allocation would test
        // nothing extra here and reads as somebody's actual address.
        assert!(is_global_unicast_ipv6("2001:db8::1".parse().unwrap()));
        assert!(is_global_unicast_ipv6(
            "2001:db8:9842:7a01::1".parse().unwrap()
        ));

        assert!(!is_global_unicast_ipv6(Ipv6Addr::LOCALHOST));
        assert!(!is_global_unicast_ipv6(Ipv6Addr::UNSPECIFIED));
        assert!(!is_global_unicast_ipv6("fe80::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("febf::1".parse().unwrap()));
        assert!(!is_global_unicast_ipv6("ff02::1".parse().unwrap()));
    }

    #[test]
    fn the_overlays_own_ula_prefix_is_not_ipv6_connectivity() {
        // fd00::/8 is where the mesh's own /128s live. Counting those as
        // "this host has IPv6" would report every meshed host as v6-capable.
        assert!(!is_global_unicast_ipv6(
            "fd12:3456:789a::1".parse().unwrap()
        ));
        assert!(!is_global_unicast_ipv6("fc00::1".parse().unwrap()));
    }

    fn observed(server: &str, mapped: SocketAddr) -> ServerOutcome {
        ServerOutcome::Observed {
            server: server.to_owned(),
            mapped,
            rtt_ms: 12.5,
        }
    }

    #[test]
    fn a_failed_server_yields_no_mapping_and_no_rtt() {
        let outcome = ServerOutcome::Failed {
            server: "stun.example:3478".to_owned(),
            reason: "no answer".to_owned(),
        };
        assert!(outcome.mapped().is_none());
        assert!(outcome.rtt_ms().is_none());
    }

    #[test]
    fn consistency_is_unknown_rather_than_false_when_a_server_is_silent() {
        // The distinction the module doc rests on: a silent server must not be
        // recorded as a measured inconsistency.
        let seen = observed(
            "a",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 4242),
        );
        let silent = ServerOutcome::Failed {
            server: "b".to_owned(),
            reason: "no answer".to_owned(),
        };

        let consistency = |a: &ServerOutcome, b: &ServerOutcome| match (a.mapped(), b.mapped()) {
            (Some(x), Some(y)) => Some(x == y),
            _ => None,
        };

        assert_eq!(consistency(&seen, &silent), None);
        assert_eq!(consistency(&seen, &seen), Some(true));

        let elsewhere = observed(
            "b",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 5353),
        );
        assert_eq!(
            consistency(&seen, &elsewhere),
            Some(false),
            "same address, different port is still an inconsistent mapping"
        );
    }

    #[test]
    fn observation_serialises_under_the_plans_field_names() {
        let observation = NatObservation {
            observed_at: 1_775_000_000,
            country: Some("BR".to_owned()),
            asn: None,
            network_type: Some("wifi".to_owned()),
            rtt_ms: Some(12.5),
            ipv6_available: true,
            local_port: 51_820,
            mapped_ip_1: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            mapped_port_1: Some(4242),
            mapped_ip_2: None,
            mapped_port_2: None,
            mapping_consistent: None,
            servers: Vec::new(),
        };

        let json = serde_json::to_value(&observation).unwrap();
        assert_eq!(json["ipv6_disponivel"], true);
        assert_eq!(json["porta_local"], 51_820);
        assert!(
            json.get("direct_possible").is_none(),
            "the record must never carry a verdict field"
        );
        assert!(json["mapping_consistent"].is_null());
    }
}
