//! Shared vmrunner host-port range contracts.

use serde::{Deserialize, Serialize};

/// Inclusive host-port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPortRange {
    pub min: u16,
    pub max: u16,
}

impl HostPortRange {
    #[must_use]
    pub const fn new(min: u16, max: u16) -> Self {
        Self { min, max }
    }

    #[must_use]
    pub const fn contains(self, port: u16) -> bool {
        self.min <= port && port <= self.max
    }

    #[must_use]
    pub fn iter(self) -> std::ops::RangeInclusive<u16> {
        self.min..=self.max
    }
}

impl std::fmt::Display for HostPortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.min, self.max)
    }
}

/// Host ports allocated for public app forwarding on macOS VZ VMs.
pub const PUBLIC_APP_HOST_PORT_RANGE: HostPortRange = HostPortRange::new(
    core_rs::guest_net::HOST_APP_PORT_RANGE_START,
    core_rs::guest_net::HOST_APP_PORT_RANGE_END,
);

/// Host ports allocated for Linux Firecracker SSH forwarding.
pub const LINUX_SSH_HOST_PORT_RANGE: HostPortRange = HostPortRange::new(
    core_rs::guest_net::SSH_HOST_PORT_RANGE_START,
    core_rs::guest_net::SSH_HOST_PORT_RANGE_END,
);

/// Port forwarding rule shared by vmrunner network wire contracts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortForward {
    /// Host port (external).
    pub host_port: u16,

    /// VM port (internal). The current macOS wire shape uses `vm_port`.
    pub vm_port: u16,

    /// Protocol (TCP/UDP).
    #[serde(default)]
    pub protocol: PortProtocol,
}

impl PortForward {
    /// Create a new TCP port forward.
    #[must_use]
    pub const fn tcp(host_port: u16, vm_port: u16) -> Self {
        Self {
            host_port,
            vm_port,
            protocol: PortProtocol::TCP,
        }
    }

    /// Create a new UDP port forward.
    #[must_use]
    pub const fn udp(host_port: u16, vm_port: u16) -> Self {
        Self {
            host_port,
            vm_port,
            protocol: PortProtocol::UDP,
        }
    }
}

/// Port protocol for vmrunner port forwarding rules.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum PortProtocol {
    #[default]
    TCP,
    UDP,
}

impl PortProtocol {
    /// Convert to display string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TCP => "tcp",
            Self::UDP => "udp",
        }
    }

    /// Parse from string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::TCP),
            "udp" => Some(Self::UDP),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_app_range_preserves_current_values() {
        assert_eq!(PUBLIC_APP_HOST_PORT_RANGE.min, 18_790);
        assert_eq!(PUBLIC_APP_HOST_PORT_RANGE.max, 19_999);
        assert!(PUBLIC_APP_HOST_PORT_RANGE.contains(18_790));
        assert!(PUBLIC_APP_HOST_PORT_RANGE.contains(19_999));
        assert!(!PUBLIC_APP_HOST_PORT_RANGE.contains(18_789));
        assert!(!PUBLIC_APP_HOST_PORT_RANGE.contains(20_000));
        assert_eq!(PUBLIC_APP_HOST_PORT_RANGE.to_string(), "18790-19999");
    }

    #[test]
    fn linux_ssh_range_preserves_current_values() {
        assert_eq!(LINUX_SSH_HOST_PORT_RANGE.min, 22_000);
        assert_eq!(LINUX_SSH_HOST_PORT_RANGE.max, 23_999);
        assert!(LINUX_SSH_HOST_PORT_RANGE.contains(22_000));
        assert!(LINUX_SSH_HOST_PORT_RANGE.contains(23_999));
        assert!(!LINUX_SSH_HOST_PORT_RANGE.contains(21_999));
        assert!(!LINUX_SSH_HOST_PORT_RANGE.contains(24_000));
        assert_eq!(LINUX_SSH_HOST_PORT_RANGE.to_string(), "22000-23999");
    }

    #[test]
    fn port_forward_serializes_current_macos_wire_shape() {
        let forward = PortForward::tcp(19_001, 80);

        assert_eq!(
            serde_json::to_value(forward).unwrap(),
            serde_json::json!({
                "host_port": 19001,
                "vm_port": 80,
                "protocol": "TCP"
            })
        );
    }

    #[test]
    fn port_forward_deserializes_current_macos_wire_shape() {
        let forward: PortForward = serde_json::from_value(serde_json::json!({
            "host_port": 19001,
            "vm_port": 80,
            "protocol": "UDP"
        }))
        .unwrap();

        assert_eq!(forward.host_port, 19_001);
        assert_eq!(forward.vm_port, 80);
        assert_eq!(forward.protocol, PortProtocol::UDP);
    }

    #[test]
    fn port_forward_deserializes_default_protocol_as_tcp() {
        let forward: PortForward = serde_json::from_value(serde_json::json!({
            "host_port": 19001,
            "vm_port": 80
        }))
        .unwrap();

        assert_eq!(forward.protocol, PortProtocol::TCP);
    }

    #[test]
    fn port_protocol_parse_preserves_current_inputs() {
        assert_eq!(PortProtocol::parse("tcp"), Some(PortProtocol::TCP));
        assert_eq!(PortProtocol::parse("TCP"), Some(PortProtocol::TCP));
        assert_eq!(PortProtocol::parse("udp"), Some(PortProtocol::UDP));
        assert_eq!(PortProtocol::parse("sctp"), None);
        assert_eq!(PortProtocol::TCP.as_str(), "tcp");
        assert_eq!(PortProtocol::UDP.as_str(), "udp");
    }
}
