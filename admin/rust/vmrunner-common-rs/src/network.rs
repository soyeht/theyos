//! Shared vmrunner host-port range contracts.

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
}
