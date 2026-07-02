//! Pure address and host-route plans for the future per-Claw VPN agent.
//!
//! This module does not execute `ip`, `ifconfig`, `route`, or any other system
//! command. It only builds deterministic argv plans that a later runtime slice
//! can execute after it has an authorized session and a live TUN/utun device.

use std::fmt;
use std::net::Ipv4Addr;

use household_rs::claw_vpn::ClawVpnSessionAddrs;

const MAX_INTERFACE_NAME_BYTES: usize = 15;
const IPV4_HOST_PREFIX_LEN: &str = "32";
const MACOS_HOST_NETMASK: &str = "255.255.255.255";

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClawVpnInterfaceName {
    value: String,
}

impl fmt::Debug for ClawVpnInterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClawVpnInterfaceName")
            .field(&"<redacted>")
            .finish()
    }
}

impl ClawVpnInterfaceName {
    pub fn new(value: impl Into<String>) -> Result<Self, ClawVpnInterfaceNameError> {
        let value = value.into();
        validate_interface_name(&value)?;
        Ok(Self { value })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnInterfaceNameError {
    Empty,
    TooLong { max_bytes: usize },
    InvalidCharacter { index: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnInterfaceRoutePlatform {
    Linux,
    Macos,
}

/// Local endpoint role for an interface route plan.
///
/// A future runtime must derive this from its fixed-side agent core/config, not
/// from remote input or from a per-packet parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnInterfaceRouteSide {
    Device,
    Claw,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ClawVpnInterfaceRouteCommand {
    tool: ClawVpnInterfaceRouteTool,
    args: Vec<String>,
}

impl fmt::Debug for ClawVpnInterfaceRouteCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnInterfaceRouteCommand")
            .field("tool", &self.tool)
            .field("args", &"<redacted>")
            .finish()
    }
}

impl ClawVpnInterfaceRouteCommand {
    fn new(tool: ClawVpnInterfaceRouteTool, args: Vec<String>) -> Self {
        Self { tool, args }
    }

    #[must_use]
    pub fn tool(&self) -> ClawVpnInterfaceRouteTool {
        self.tool
    }

    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnInterfaceRouteTool {
    LinuxIp,
    MacosIfconfig,
    MacosRoute,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ClawVpnInterfaceRoutePlan {
    platform: ClawVpnInterfaceRoutePlatform,
    interface_name: ClawVpnInterfaceName,
    local_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
    setup_commands: Vec<ClawVpnInterfaceRouteCommand>,
    cleanup_commands: Vec<ClawVpnInterfaceRouteCommand>,
}

impl fmt::Debug for ClawVpnInterfaceRoutePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnInterfaceRoutePlan")
            .field("platform", &self.platform)
            .field("interface_name", &"<redacted>")
            .field("local_addr", &"<redacted>")
            .field("peer_addr", &"<redacted>")
            .field("setup_command_count", &self.setup_commands.len())
            .field("cleanup_command_count", &self.cleanup_commands.len())
            .finish()
    }
}

impl ClawVpnInterfaceRoutePlan {
    #[must_use]
    pub fn new(
        platform: ClawVpnInterfaceRoutePlatform,
        interface_name: ClawVpnInterfaceName,
        addrs: ClawVpnSessionAddrs,
        local_side: ClawVpnInterfaceRouteSide,
    ) -> Self {
        let (local_addr, peer_addr) = match local_side {
            ClawVpnInterfaceRouteSide::Device => (addrs.device(), addrs.claw()),
            ClawVpnInterfaceRouteSide::Claw => (addrs.claw(), addrs.device()),
        };
        let setup_commands =
            setup_commands(platform, interface_name.as_str(), local_addr, peer_addr);
        let cleanup_commands =
            cleanup_commands(platform, interface_name.as_str(), local_addr, peer_addr);
        Self {
            platform,
            interface_name,
            local_addr,
            peer_addr,
            setup_commands,
            cleanup_commands,
        }
    }

    #[must_use]
    pub fn platform(&self) -> ClawVpnInterfaceRoutePlatform {
        self.platform
    }

    #[must_use]
    pub fn interface_name(&self) -> &ClawVpnInterfaceName {
        &self.interface_name
    }

    #[must_use]
    pub fn local_addr(&self) -> Ipv4Addr {
        self.local_addr
    }

    #[must_use]
    pub fn peer_addr(&self) -> Ipv4Addr {
        self.peer_addr
    }

    #[must_use]
    pub fn setup_commands(&self) -> &[ClawVpnInterfaceRouteCommand] {
        &self.setup_commands
    }

    #[must_use]
    pub fn cleanup_commands(&self) -> &[ClawVpnInterfaceRouteCommand] {
        &self.cleanup_commands
    }
}

fn setup_commands(
    platform: ClawVpnInterfaceRoutePlatform,
    interface_name: &str,
    local_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
) -> Vec<ClawVpnInterfaceRouteCommand> {
    match platform {
        ClawVpnInterfaceRoutePlatform::Linux => {
            linux_setup_commands(interface_name, local_addr, peer_addr)
        }
        ClawVpnInterfaceRoutePlatform::Macos => {
            macos_setup_commands(interface_name, local_addr, peer_addr)
        }
    }
}

fn cleanup_commands(
    platform: ClawVpnInterfaceRoutePlatform,
    interface_name: &str,
    local_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
) -> Vec<ClawVpnInterfaceRouteCommand> {
    match platform {
        ClawVpnInterfaceRoutePlatform::Linux => {
            linux_cleanup_commands(interface_name, local_addr, peer_addr)
        }
        ClawVpnInterfaceRoutePlatform::Macos => macos_cleanup_commands(interface_name, peer_addr),
    }
}

fn linux_setup_commands(
    interface_name: &str,
    local_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
) -> Vec<ClawVpnInterfaceRouteCommand> {
    let local_host = format!("{local_addr}/{IPV4_HOST_PREFIX_LEN}");
    let peer_host = format!("{peer_addr}/{IPV4_HOST_PREFIX_LEN}");
    vec![
        ClawVpnInterfaceRouteCommand::new(
            ClawVpnInterfaceRouteTool::LinuxIp,
            vec![
                "addr".into(),
                "add".into(),
                local_host,
                "peer".into(),
                peer_addr.to_string(),
                "dev".into(),
                interface_name.into(),
            ],
        ),
        ClawVpnInterfaceRouteCommand::new(
            ClawVpnInterfaceRouteTool::LinuxIp,
            vec![
                "link".into(),
                "set".into(),
                "dev".into(),
                interface_name.into(),
                "up".into(),
            ],
        ),
        ClawVpnInterfaceRouteCommand::new(
            ClawVpnInterfaceRouteTool::LinuxIp,
            vec![
                "route".into(),
                "replace".into(),
                peer_host,
                "dev".into(),
                interface_name.into(),
                "src".into(),
                local_addr.to_string(),
            ],
        ),
    ]
}

fn linux_cleanup_commands(
    interface_name: &str,
    local_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
) -> Vec<ClawVpnInterfaceRouteCommand> {
    let local_host = format!("{local_addr}/{IPV4_HOST_PREFIX_LEN}");
    let peer_host = format!("{peer_addr}/{IPV4_HOST_PREFIX_LEN}");
    vec![
        ClawVpnInterfaceRouteCommand::new(
            ClawVpnInterfaceRouteTool::LinuxIp,
            vec![
                "route".into(),
                "del".into(),
                peer_host,
                "dev".into(),
                interface_name.into(),
            ],
        ),
        ClawVpnInterfaceRouteCommand::new(
            ClawVpnInterfaceRouteTool::LinuxIp,
            vec![
                "addr".into(),
                "del".into(),
                local_host,
                "peer".into(),
                peer_addr.to_string(),
                "dev".into(),
                interface_name.into(),
            ],
        ),
        ClawVpnInterfaceRouteCommand::new(
            ClawVpnInterfaceRouteTool::LinuxIp,
            vec![
                "link".into(),
                "set".into(),
                "dev".into(),
                interface_name.into(),
                "down".into(),
            ],
        ),
    ]
}

fn macos_setup_commands(
    interface_name: &str,
    local_addr: Ipv4Addr,
    peer_addr: Ipv4Addr,
) -> Vec<ClawVpnInterfaceRouteCommand> {
    vec![
        ClawVpnInterfaceRouteCommand::new(
            ClawVpnInterfaceRouteTool::MacosIfconfig,
            vec![
                interface_name.into(),
                "inet".into(),
                local_addr.to_string(),
                peer_addr.to_string(),
                "netmask".into(),
                MACOS_HOST_NETMASK.into(),
                "up".into(),
            ],
        ),
        ClawVpnInterfaceRouteCommand::new(
            ClawVpnInterfaceRouteTool::MacosRoute,
            vec![
                "-n".into(),
                "add".into(),
                "-host".into(),
                peer_addr.to_string(),
                "-interface".into(),
                interface_name.into(),
            ],
        ),
    ]
}

fn macos_cleanup_commands(
    interface_name: &str,
    peer_addr: Ipv4Addr,
) -> Vec<ClawVpnInterfaceRouteCommand> {
    vec![
        ClawVpnInterfaceRouteCommand::new(
            ClawVpnInterfaceRouteTool::MacosRoute,
            vec![
                "-n".into(),
                "delete".into(),
                "-host".into(),
                peer_addr.to_string(),
                "-interface".into(),
                interface_name.into(),
            ],
        ),
        ClawVpnInterfaceRouteCommand::new(
            ClawVpnInterfaceRouteTool::MacosIfconfig,
            vec![interface_name.into(), "down".into()],
        ),
    ]
}

fn validate_interface_name(value: &str) -> Result<(), ClawVpnInterfaceNameError> {
    if value.is_empty() {
        return Err(ClawVpnInterfaceNameError::Empty);
    }
    if value.len() > MAX_INTERFACE_NAME_BYTES {
        return Err(ClawVpnInterfaceNameError::TooLong {
            max_bytes: MAX_INTERFACE_NAME_BYTES,
        });
    }
    if matches!(value, "." | "..") {
        return Err(ClawVpnInterfaceNameError::InvalidCharacter { index: 0 });
    }
    if value.as_bytes().first() == Some(&b'-') {
        return Err(ClawVpnInterfaceNameError::InvalidCharacter { index: 0 });
    }
    for (index, byte) in value.bytes().enumerate() {
        let allowed = byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-');
        if !allowed {
            return Err(ClawVpnInterfaceNameError::InvalidCharacter { index });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_addrs() -> ClawVpnSessionAddrs {
        ClawVpnSessionAddrs::try_new(
            "198.51.100.10".parse().unwrap(),
            "198.51.100.11".parse().unwrap(),
        )
        .unwrap()
    }

    fn args(command: &ClawVpnInterfaceRouteCommand) -> Vec<&str> {
        command.args().iter().map(String::as_str).collect()
    }

    fn assert_no_default_or_lan_route(plan: &ClawVpnInterfaceRoutePlan) {
        for command in plan.setup_commands().iter().chain(plan.cleanup_commands()) {
            for arg in command.args() {
                assert_ne!(arg, "default");
                assert_ne!(arg, "0.0.0.0/0");
                assert_ne!(arg, "0/0");
                if let Some((_, prefix_len)) = arg.rsplit_once('/') {
                    assert_eq!(prefix_len, "32", "must plan only host routes: {arg}");
                }
            }
        }
    }

    #[test]
    fn linux_plan_assigns_point_to_point_address_and_single_peer_route() {
        let plan = ClawVpnInterfaceRoutePlan::new(
            ClawVpnInterfaceRoutePlatform::Linux,
            ClawVpnInterfaceName::new("clawvpn0").unwrap(),
            session_addrs(),
            ClawVpnInterfaceRouteSide::Device,
        );

        assert_eq!(plan.platform(), ClawVpnInterfaceRoutePlatform::Linux);
        assert_eq!(plan.interface_name().as_str(), "clawvpn0");
        assert_eq!(plan.local_addr(), Ipv4Addr::new(198, 51, 100, 10));
        assert_eq!(plan.peer_addr(), Ipv4Addr::new(198, 51, 100, 11));

        let setup = plan.setup_commands();
        assert_eq!(setup.len(), 3);
        assert_eq!(setup[0].tool(), ClawVpnInterfaceRouteTool::LinuxIp);
        assert_eq!(
            args(&setup[0]),
            vec![
                "addr",
                "add",
                "198.51.100.10/32",
                "peer",
                "198.51.100.11",
                "dev",
                "clawvpn0"
            ]
        );
        assert_eq!(
            args(&setup[1]),
            vec!["link", "set", "dev", "clawvpn0", "up"]
        );
        assert_eq!(setup[1].tool(), ClawVpnInterfaceRouteTool::LinuxIp);
        assert_eq!(
            args(&setup[2]),
            vec![
                "route",
                "replace",
                "198.51.100.11/32",
                "dev",
                "clawvpn0",
                "src",
                "198.51.100.10"
            ]
        );
        assert_eq!(setup[2].tool(), ClawVpnInterfaceRouteTool::LinuxIp);

        let cleanup = plan.cleanup_commands();
        assert_eq!(cleanup.len(), 3);
        assert_eq!(cleanup[0].tool(), ClawVpnInterfaceRouteTool::LinuxIp);
        assert_eq!(
            args(&cleanup[0]),
            vec!["route", "del", "198.51.100.11/32", "dev", "clawvpn0"]
        );
        assert_eq!(
            args(&cleanup[1]),
            vec![
                "addr",
                "del",
                "198.51.100.10/32",
                "peer",
                "198.51.100.11",
                "dev",
                "clawvpn0"
            ]
        );
        assert_eq!(cleanup[1].tool(), ClawVpnInterfaceRouteTool::LinuxIp);
        assert_eq!(
            args(&cleanup[2]),
            vec!["link", "set", "dev", "clawvpn0", "down"]
        );
        assert_eq!(cleanup[2].tool(), ClawVpnInterfaceRouteTool::LinuxIp);
        assert_no_default_or_lan_route(&plan);
    }

    #[test]
    fn macos_plan_assigns_point_to_point_address_and_single_peer_route() {
        let plan = ClawVpnInterfaceRoutePlan::new(
            ClawVpnInterfaceRoutePlatform::Macos,
            ClawVpnInterfaceName::new("utun7").unwrap(),
            session_addrs(),
            ClawVpnInterfaceRouteSide::Claw,
        );

        assert_eq!(plan.platform(), ClawVpnInterfaceRoutePlatform::Macos);
        assert_eq!(plan.interface_name().as_str(), "utun7");
        assert_eq!(plan.local_addr(), Ipv4Addr::new(198, 51, 100, 11));
        assert_eq!(plan.peer_addr(), Ipv4Addr::new(198, 51, 100, 10));

        let setup = plan.setup_commands();
        assert_eq!(setup.len(), 2);
        assert_eq!(setup[0].tool(), ClawVpnInterfaceRouteTool::MacosIfconfig);
        assert_eq!(
            args(&setup[0]),
            vec![
                "utun7",
                "inet",
                "198.51.100.11",
                "198.51.100.10",
                "netmask",
                "255.255.255.255",
                "up"
            ]
        );
        assert_eq!(setup[1].tool(), ClawVpnInterfaceRouteTool::MacosRoute);
        assert_eq!(
            args(&setup[1]),
            vec!["-n", "add", "-host", "198.51.100.10", "-interface", "utun7"]
        );

        let cleanup = plan.cleanup_commands();
        assert_eq!(cleanup.len(), 2);
        assert_eq!(cleanup[0].tool(), ClawVpnInterfaceRouteTool::MacosRoute);
        assert_eq!(
            args(&cleanup[0]),
            vec![
                "-n",
                "delete",
                "-host",
                "198.51.100.10",
                "-interface",
                "utun7"
            ]
        );
        assert_eq!(cleanup[1].tool(), ClawVpnInterfaceRouteTool::MacosIfconfig);
        assert_eq!(args(&cleanup[1]), vec!["utun7", "down"]);
        assert_no_default_or_lan_route(&plan);
    }

    #[test]
    fn interface_name_validation_is_conservative() {
        assert_eq!(
            ClawVpnInterfaceName::new("").unwrap_err(),
            ClawVpnInterfaceNameError::Empty
        );
        assert_eq!(
            ClawVpnInterfaceName::new("abcdefghijklmnop").unwrap_err(),
            ClawVpnInterfaceNameError::TooLong { max_bytes: 15 }
        );
        assert_eq!(
            ClawVpnInterfaceName::new(".").unwrap_err(),
            ClawVpnInterfaceNameError::InvalidCharacter { index: 0 }
        );
        assert_eq!(
            ClawVpnInterfaceName::new("..").unwrap_err(),
            ClawVpnInterfaceNameError::InvalidCharacter { index: 0 }
        );
        assert_eq!(
            ClawVpnInterfaceName::new("-clawvpn0").unwrap_err(),
            ClawVpnInterfaceNameError::InvalidCharacter { index: 0 }
        );
        assert_eq!(
            ClawVpnInterfaceName::new("--clawvpn0").unwrap_err(),
            ClawVpnInterfaceNameError::InvalidCharacter { index: 0 }
        );
        assert_eq!(
            ClawVpnInterfaceName::new("claw vpn").unwrap_err(),
            ClawVpnInterfaceNameError::InvalidCharacter { index: 4 }
        );
        assert_eq!(
            ClawVpnInterfaceName::new("claw-vpn.1").unwrap().as_str(),
            "claw-vpn.1"
        );
    }

    #[test]
    fn debug_output_redacts_interface_names_addresses_and_command_args() {
        let plan = ClawVpnInterfaceRoutePlan::new(
            ClawVpnInterfaceRoutePlatform::Linux,
            ClawVpnInterfaceName::new("clawvpn0").unwrap(),
            session_addrs(),
            ClawVpnInterfaceRouteSide::Device,
        );
        let debug = format!("{plan:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("clawvpn0"));
        assert!(!debug.contains("198.51.100.10"));
        assert!(!debug.contains("198.51.100.11"));

        let command_debug = format!("{:?}", &plan.setup_commands()[0]);
        assert!(command_debug.contains("tool"));
        assert!(command_debug.contains("<redacted>"));
        assert!(!command_debug.contains("clawvpn0"));
        assert!(!command_debug.contains("198.51.100.10"));
        assert!(!command_debug.contains("198.51.100.11"));

        let name_debug = format!("{:?}", plan.interface_name());
        assert!(name_debug.contains("<redacted>"));
        assert!(!name_debug.contains("clawvpn0"));
    }
}
