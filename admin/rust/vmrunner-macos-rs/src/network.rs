//! Network configuration for macOS VZ VMs.
//!
//! Provides NAT networking setup and port forwarding for `VZVirtualMachine`.

use serde::{Deserialize, Serialize};

/// Network configuration for a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// NAT network subnet (e.g., "192.168.0.0/24")
    pub subnet: String,

    /// Port forwarding rules
    #[serde(default)]
    pub port_forwards: Vec<PortForward>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            subnet: "192.168.0.0/24".to_string(),
            port_forwards: Vec::new(),
        }
    }
}

/// Port forwarding rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortForward {
    /// Host port (external)
    pub host_port: u16,

    /// VM port (internal)
    pub vm_port: u16,

    /// Protocol (TCP/UDP)
    #[serde(default)]
    pub protocol: PortProtocol,
}

impl PortForward {
    /// Create a new TCP port forward.
    #[must_use]
    pub fn tcp(host_port: u16, vm_port: u16) -> Self {
        Self {
            host_port,
            vm_port,
            protocol: PortProtocol::TCP,
        }
    }

    /// Create a new UDP port forward.
    #[must_use]
    pub fn udp(host_port: u16, vm_port: u16) -> Self {
        Self {
            host_port,
            vm_port,
            protocol: PortProtocol::UDP,
        }
    }

    /// Validate the port forward rule.
    ///
    /// # Errors
    ///
    /// Returns an error if ports are invalid or duplicate.
    pub fn validate(&self, existing: &[PortForward]) -> Result<(), crate::VZError> {
        // Check valid port ranges
        if self.host_port == 0 {
            return Err(crate::VZError::InvalidConfig(
                "Host port cannot be 0".into(),
            ));
        }
        if self.vm_port == 0 {
            return Err(crate::VZError::InvalidConfig("VM port cannot be 0".into()));
        }

        // Check for duplicates
        for existing_rule in existing {
            if existing_rule.host_port == self.host_port {
                return Err(crate::VZError::PortInUse(self.host_port));
            }
        }

        Ok(())
    }
}

/// Port protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum PortProtocol {
    #[default]
    TCP,
    UDP,
}

impl PortProtocol {
    /// Convert to display string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TCP => "tcp",
            Self::UDP => "udp",
        }
    }

    /// Parse from string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Self::TCP),
            "udp" => Some(Self::UDP),
            _ => None,
        }
    }
}

/// Validate port is in the dynamic range (18790-19999).
///
/// # Errors
///
/// Returns an error if the port is outside the allowed range.
pub fn validate_port_range(port: u16) -> Result<(), crate::VZError> {
    const MIN_PORT: u16 = 18790;
    const MAX_PORT: u16 = 19999;

    if (MIN_PORT..=MAX_PORT).contains(&port) {
        Ok(())
    } else {
        Err(crate::VZError::InvalidConfig(format!(
            "Port {port} out of range (must be {MIN_PORT}-{MAX_PORT})"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();
        assert_eq!(config.subnet, "192.168.0.0/24");
        assert!(config.port_forwards.is_empty());
    }

    #[test]
    fn test_port_forward_tcp() {
        let pf = PortForward::tcp(19001, 80);
        assert_eq!(pf.host_port, 19001);
        assert_eq!(pf.vm_port, 80);
        assert_eq!(pf.protocol, PortProtocol::TCP);
    }

    #[test]
    fn test_port_forward_udp() {
        let pf = PortForward::udp(19001, 53);
        assert_eq!(pf.protocol, PortProtocol::UDP);
    }

    #[test]
    fn test_port_forward_validate_duplicate() {
        let existing = vec![PortForward::tcp(19001, 80)];
        let new_rule = PortForward::tcp(19001, 8080);

        let result = new_rule.validate(&existing);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Port 19001 already in use");
    }

    #[test]
    fn test_port_forward_validate_zero() {
        let rule = PortForward::tcp(0, 80);
        let result = rule.validate(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_port_range() {
        assert!(validate_port_range(18790).is_ok());
        assert!(validate_port_range(19000).is_ok());
        assert!(validate_port_range(19999).is_ok());

        assert!(validate_port_range(18789).is_err());
        assert!(validate_port_range(20000).is_err());
        assert!(validate_port_range(80).is_err());
    }

    #[test]
    fn test_port_protocol_from_str() {
        assert_eq!(PortProtocol::parse("tcp"), Some(PortProtocol::TCP));
        assert_eq!(PortProtocol::parse("TCP"), Some(PortProtocol::TCP));
        assert_eq!(PortProtocol::parse("udp"), Some(PortProtocol::UDP));
        assert_eq!(PortProtocol::parse("sctp"), None);
    }
}
