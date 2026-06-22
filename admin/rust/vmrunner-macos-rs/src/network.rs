//! Network configuration for macOS VZ VMs.
//!
//! Provides NAT networking setup and port forwarding for `VZVirtualMachine`.

use serde::{Deserialize, Serialize};
pub use vmrunner_common_rs::PortProtocol;
use vmrunner_common_rs::{PUBLIC_APP_HOST_PORT_RANGE, PortForward as CommonPortForward};

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
#[serde(transparent)]
pub struct PortForward(CommonPortForward);

impl std::ops::Deref for PortForward {
    type Target = CommonPortForward;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PortForward {
    /// Create a new TCP port forward.
    #[must_use]
    pub fn tcp(host_port: u16, vm_port: u16) -> Self {
        Self(CommonPortForward::tcp(host_port, vm_port))
    }

    /// Create a new UDP port forward.
    #[must_use]
    pub fn udp(host_port: u16, vm_port: u16) -> Self {
        Self(CommonPortForward::udp(host_port, vm_port))
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

/// Validate port is in the configured dynamic host app range.
///
/// # Errors
///
/// Returns an error if the port is outside the allowed range.
pub fn validate_port_range(port: u16) -> Result<(), crate::VZError> {
    if PUBLIC_APP_HOST_PORT_RANGE.contains(port) {
        Ok(())
    } else {
        Err(crate::VZError::InvalidConfig(format!(
            "Port {port} out of range (must be {PUBLIC_APP_HOST_PORT_RANGE})"
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
        assert!(validate_port_range(core_rs::guest_net::HOST_APP_PORT_RANGE_START).is_ok());
        assert!(validate_port_range(19000).is_ok());
        assert!(validate_port_range(core_rs::guest_net::HOST_APP_PORT_RANGE_END).is_ok());

        assert!(validate_port_range(core_rs::guest_net::HOST_APP_PORT_RANGE_START - 1).is_err());
        assert!(validate_port_range(core_rs::guest_net::HOST_APP_PORT_RANGE_END + 1).is_err());
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
