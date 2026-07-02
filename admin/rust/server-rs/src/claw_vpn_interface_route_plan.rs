//! Address and host-route plans for the future per-Claw VPN agent.
//!
//! This module builds deterministic argv plans and contains the narrow command
//! executor for those plans. Nothing in the product runtime calls the executor
//! yet; a later runtime slice must supply an authorized session, a live TUN/utun
//! device, and owner-reviewed absolute tool paths before using it.

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use household_rs::claw_vpn::ClawVpnSessionAddrs;

const MAX_INTERFACE_NAME_BYTES: usize = 15;
const IPV4_HOST_PREFIX_LEN: &str = "32";
const MACOS_HOST_NETMASK: &str = "255.255.255.255";
#[cfg(target_os = "linux")]
const HOST_ROUTE_PLATFORM: Option<ClawVpnInterfaceRoutePlatform> =
    Some(ClawVpnInterfaceRoutePlatform::Linux);
#[cfg(target_os = "macos")]
const HOST_ROUTE_PLATFORM: Option<ClawVpnInterfaceRoutePlatform> =
    Some(ClawVpnInterfaceRoutePlatform::Macos);
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const HOST_ROUTE_PLATFORM: Option<ClawVpnInterfaceRoutePlatform> = None;

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

/// Tool executable path selected by an owner-reviewed launcher/config layer.
///
/// The route planner intentionally carries a typed tool enum, not an executable
/// string. The executor maps that enum to absolute paths supplied by its caller;
/// future product wiring must source those paths from reviewed platform config,
/// not from the route plan or remote input.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ClawVpnInterfaceRouteToolPath {
    value: PathBuf,
}

impl fmt::Debug for ClawVpnInterfaceRouteToolPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ClawVpnInterfaceRouteToolPath")
            .field(&"<redacted>")
            .finish()
    }
}

impl ClawVpnInterfaceRouteToolPath {
    pub fn new(value: impl Into<PathBuf>) -> Result<Self, ClawVpnInterfaceRouteToolPathError> {
        let value = value.into();
        if value.as_os_str().is_empty() {
            return Err(ClawVpnInterfaceRouteToolPathError::Empty);
        }
        if !value.is_absolute() {
            return Err(ClawVpnInterfaceRouteToolPathError::NotAbsolute);
        }
        let mut has_program_component = false;
        for component in value.components() {
            match component {
                Component::Normal(_) => {
                    has_program_component = true;
                }
                Component::RootDir | Component::Prefix(_) => {}
                Component::CurDir | Component::ParentDir => {
                    return Err(ClawVpnInterfaceRouteToolPathError::UnsafeComponent);
                }
            }
        }
        if !has_program_component {
            return Err(ClawVpnInterfaceRouteToolPathError::UnsafeComponent);
        }
        Ok(Self { value })
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnInterfaceRouteToolPathError {
    Empty,
    NotAbsolute,
    UnsafeComponent,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ClawVpnInterfaceRouteToolPaths {
    linux_ip: ClawVpnInterfaceRouteToolPath,
    macos_ifconfig: ClawVpnInterfaceRouteToolPath,
    macos_route: ClawVpnInterfaceRouteToolPath,
}

impl fmt::Debug for ClawVpnInterfaceRouteToolPaths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnInterfaceRouteToolPaths")
            .field("linux_ip", &"<redacted>")
            .field("macos_ifconfig", &"<redacted>")
            .field("macos_route", &"<redacted>")
            .finish()
    }
}

impl ClawVpnInterfaceRouteToolPaths {
    pub fn try_new(
        linux_ip: impl Into<PathBuf>,
        macos_ifconfig: impl Into<PathBuf>,
        macos_route: impl Into<PathBuf>,
    ) -> Result<Self, ClawVpnInterfaceRouteToolPathError> {
        Ok(Self {
            linux_ip: ClawVpnInterfaceRouteToolPath::new(linux_ip)?,
            macos_ifconfig: ClawVpnInterfaceRouteToolPath::new(macos_ifconfig)?,
            macos_route: ClawVpnInterfaceRouteToolPath::new(macos_route)?,
        })
    }

    #[must_use]
    pub fn path_for(&self, tool: ClawVpnInterfaceRouteTool) -> &Path {
        match tool {
            ClawVpnInterfaceRouteTool::LinuxIp => self.linux_ip.as_path(),
            ClawVpnInterfaceRouteTool::MacosIfconfig => self.macos_ifconfig.as_path(),
            ClawVpnInterfaceRouteTool::MacosRoute => self.macos_route.as_path(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ClawVpnInterfaceRouteExecutor {
    tool_paths: ClawVpnInterfaceRouteToolPaths,
    platform: Option<ClawVpnInterfaceRoutePlatform>,
}

impl fmt::Debug for ClawVpnInterfaceRouteExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnInterfaceRouteExecutor")
            .field("tool_paths", &"<redacted>")
            .field("platform", &self.platform)
            .finish()
    }
}

impl ClawVpnInterfaceRouteExecutor {
    #[must_use]
    pub fn new(tool_paths: ClawVpnInterfaceRouteToolPaths) -> Self {
        Self {
            tool_paths,
            platform: HOST_ROUTE_PLATFORM,
        }
    }

    #[cfg(test)]
    fn new_for_platform(
        tool_paths: ClawVpnInterfaceRouteToolPaths,
        platform: ClawVpnInterfaceRoutePlatform,
    ) -> Self {
        Self {
            tool_paths,
            platform: Some(platform),
        }
    }

    pub fn apply(
        &self,
        plan: &ClawVpnInterfaceRoutePlan,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
        let mut runner = SystemInterfaceRouteCommandRunner;
        self.apply_with_runner(plan, &mut runner)
    }

    pub fn cleanup(
        &self,
        plan: &ClawVpnInterfaceRoutePlan,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
        let mut runner = SystemInterfaceRouteCommandRunner;
        self.cleanup_with_runner(plan, &mut runner)
    }

    fn apply_with_runner(
        &self,
        plan: &ClawVpnInterfaceRoutePlan,
        runner: &mut impl ClawVpnInterfaceRouteCommandRunner,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
        self.ensure_platform(plan)?;
        if let Err(setup_error) = self.run_commands(
            ClawVpnInterfaceRouteExecutionPhase::Setup,
            plan.setup_commands(),
            runner,
        ) {
            let cleanup_error = self
                .run_commands(
                    ClawVpnInterfaceRouteExecutionPhase::Cleanup,
                    plan.cleanup_commands(),
                    runner,
                )
                .err()
                .map(Box::new);
            return Err(ClawVpnInterfaceRouteExecutionError::SetupFailed {
                setup_error: Box::new(setup_error),
                cleanup_error,
            });
        }
        Ok(())
    }

    fn cleanup_with_runner(
        &self,
        plan: &ClawVpnInterfaceRoutePlan,
        runner: &mut impl ClawVpnInterfaceRouteCommandRunner,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
        self.ensure_platform(plan)?;
        self.run_commands(
            ClawVpnInterfaceRouteExecutionPhase::Cleanup,
            plan.cleanup_commands(),
            runner,
        )
    }

    fn run_commands(
        &self,
        phase: ClawVpnInterfaceRouteExecutionPhase,
        commands: &[ClawVpnInterfaceRouteCommand],
        runner: &mut impl ClawVpnInterfaceRouteCommandRunner,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
        let mut first_cleanup_error = None;
        for (command_index, command) in commands.iter().enumerate() {
            let result = self.run_command(phase, command_index, command, runner);
            match (phase, result) {
                (_, Ok(())) => {}
                (ClawVpnInterfaceRouteExecutionPhase::Setup, Err(error)) => return Err(error),
                (ClawVpnInterfaceRouteExecutionPhase::Cleanup, Err(error)) => {
                    first_cleanup_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = first_cleanup_error {
            return Err(error);
        }
        Ok(())
    }

    fn run_command(
        &self,
        phase: ClawVpnInterfaceRouteExecutionPhase,
        command_index: usize,
        command: &ClawVpnInterfaceRouteCommand,
        runner: &mut impl ClawVpnInterfaceRouteCommandRunner,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
        let tool = command.tool();
        let exit = runner
            .run(tool, self.tool_paths.path_for(tool), command.args())
            .map_err(|source| ClawVpnInterfaceRouteExecutionError::CommandSpawn {
                phase,
                command_index,
                tool,
                source,
            })?;
        if !exit.success {
            return Err(ClawVpnInterfaceRouteExecutionError::CommandFailed {
                phase,
                command_index,
                tool,
                status_code: exit.status_code,
            });
        }
        Ok(())
    }

    fn ensure_platform(
        &self,
        plan: &ClawVpnInterfaceRoutePlan,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
        if self.platform == Some(plan.platform()) {
            return Ok(());
        }
        Err(ClawVpnInterfaceRouteExecutionError::PlatformMismatch {
            executor_platform: self.platform,
            plan_platform: plan.platform(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnInterfaceRouteExecutionPhase {
    Setup,
    Cleanup,
}

#[derive(Debug)]
pub enum ClawVpnInterfaceRouteExecutionError {
    PlatformMismatch {
        executor_platform: Option<ClawVpnInterfaceRoutePlatform>,
        plan_platform: ClawVpnInterfaceRoutePlatform,
    },
    CommandSpawn {
        phase: ClawVpnInterfaceRouteExecutionPhase,
        command_index: usize,
        tool: ClawVpnInterfaceRouteTool,
        source: io::Error,
    },
    CommandFailed {
        phase: ClawVpnInterfaceRouteExecutionPhase,
        command_index: usize,
        tool: ClawVpnInterfaceRouteTool,
        status_code: Option<i32>,
    },
    SetupFailed {
        setup_error: Box<ClawVpnInterfaceRouteExecutionError>,
        cleanup_error: Option<Box<ClawVpnInterfaceRouteExecutionError>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClawVpnInterfaceRouteCommandExit {
    success: bool,
    status_code: Option<i32>,
}

impl From<ExitStatus> for ClawVpnInterfaceRouteCommandExit {
    fn from(status: ExitStatus) -> Self {
        Self {
            success: status.success(),
            status_code: status.code(),
        }
    }
}

trait ClawVpnInterfaceRouteCommandRunner {
    fn run(
        &mut self,
        tool: ClawVpnInterfaceRouteTool,
        program: &Path,
        args: &[String],
    ) -> Result<ClawVpnInterfaceRouteCommandExit, io::Error>;
}

struct SystemInterfaceRouteCommandRunner;

impl ClawVpnInterfaceRouteCommandRunner for SystemInterfaceRouteCommandRunner {
    fn run(
        &mut self,
        _tool: ClawVpnInterfaceRouteTool,
        program: &Path,
        args: &[String],
    ) -> Result<ClawVpnInterfaceRouteCommandExit, io::Error> {
        Command::new(program)
            .env_clear()
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(Into::into)
    }
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

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedRouteCommand {
        tool: ClawVpnInterfaceRouteTool,
        program: String,
        args: Vec<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeRouteCommandOutcome {
        Success,
        ExitFailure(Option<i32>),
        SpawnFailure,
    }

    #[derive(Debug, Default)]
    struct RecordingRouteCommandRunner {
        outcomes: Vec<FakeRouteCommandOutcome>,
        calls: Vec<RecordedRouteCommand>,
    }

    impl RecordingRouteCommandRunner {
        fn with_outcomes(outcomes: Vec<FakeRouteCommandOutcome>) -> Self {
            Self {
                outcomes,
                calls: Vec::new(),
            }
        }
    }

    impl ClawVpnInterfaceRouteCommandRunner for RecordingRouteCommandRunner {
        fn run(
            &mut self,
            tool: ClawVpnInterfaceRouteTool,
            program: &Path,
            args: &[String],
        ) -> Result<ClawVpnInterfaceRouteCommandExit, io::Error> {
            let outcome = self
                .outcomes
                .get(self.calls.len())
                .copied()
                .unwrap_or(FakeRouteCommandOutcome::Success);
            self.calls.push(RecordedRouteCommand {
                tool,
                program: program.display().to_string(),
                args: args.to_vec(),
            });
            match outcome {
                FakeRouteCommandOutcome::Success => Ok(ClawVpnInterfaceRouteCommandExit {
                    success: true,
                    status_code: Some(0),
                }),
                FakeRouteCommandOutcome::ExitFailure(status_code) => {
                    Ok(ClawVpnInterfaceRouteCommandExit {
                        success: false,
                        status_code,
                    })
                }
                FakeRouteCommandOutcome::SpawnFailure => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "fake spawn failure",
                )),
            }
        }
    }

    fn session_addrs() -> ClawVpnSessionAddrs {
        ClawVpnSessionAddrs::try_new(
            "198.51.100.10".parse().unwrap(),
            "198.51.100.11".parse().unwrap(),
        )
        .unwrap()
    }

    fn tool_paths() -> ClawVpnInterfaceRouteToolPaths {
        ClawVpnInterfaceRouteToolPaths::try_new(
            "/run/current-system/sw/bin/ip",
            "/sbin/ifconfig",
            "/sbin/route",
        )
        .unwrap()
    }

    fn executor() -> ClawVpnInterfaceRouteExecutor {
        ClawVpnInterfaceRouteExecutor::new_for_platform(
            tool_paths(),
            ClawVpnInterfaceRoutePlatform::Linux,
        )
    }

    fn linux_plan() -> ClawVpnInterfaceRoutePlan {
        ClawVpnInterfaceRoutePlan::new(
            ClawVpnInterfaceRoutePlatform::Linux,
            ClawVpnInterfaceName::new("clawvpn0").unwrap(),
            session_addrs(),
            ClawVpnInterfaceRouteSide::Device,
        )
    }

    fn macos_plan() -> ClawVpnInterfaceRoutePlan {
        ClawVpnInterfaceRoutePlan::new(
            ClawVpnInterfaceRoutePlatform::Macos,
            ClawVpnInterfaceName::new("utun7").unwrap(),
            session_addrs(),
            ClawVpnInterfaceRouteSide::Claw,
        )
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
    fn tool_paths_require_absolute_paths_and_debug_redacts() {
        assert_eq!(
            ClawVpnInterfaceRouteToolPath::new("").unwrap_err(),
            ClawVpnInterfaceRouteToolPathError::Empty
        );
        assert_eq!(
            ClawVpnInterfaceRouteToolPath::new("ip").unwrap_err(),
            ClawVpnInterfaceRouteToolPathError::NotAbsolute
        );
        assert_eq!(
            ClawVpnInterfaceRouteToolPath::new("/").unwrap_err(),
            ClawVpnInterfaceRouteToolPathError::UnsafeComponent
        );
        assert_eq!(
            ClawVpnInterfaceRouteToolPath::new("/run/current-system/../bin/ip").unwrap_err(),
            ClawVpnInterfaceRouteToolPathError::UnsafeComponent
        );

        let paths = tool_paths();
        assert_eq!(
            paths.path_for(ClawVpnInterfaceRouteTool::LinuxIp),
            Path::new("/run/current-system/sw/bin/ip")
        );
        assert_eq!(
            paths.path_for(ClawVpnInterfaceRouteTool::MacosIfconfig),
            Path::new("/sbin/ifconfig")
        );
        assert_eq!(
            paths.path_for(ClawVpnInterfaceRouteTool::MacosRoute),
            Path::new("/sbin/route")
        );

        let debug = format!("{paths:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("/run/current-system/sw/bin/ip"));
        assert!(!debug.contains("/sbin/ifconfig"));
        assert!(!debug.contains("/sbin/route"));

        let executor_debug = format!("{:?}", executor());
        assert!(executor_debug.contains("<redacted>"));
        assert!(!executor_debug.contains("/run/current-system/sw/bin/ip"));
        assert!(!executor_debug.contains("/sbin/ifconfig"));
        assert!(!executor_debug.contains("/sbin/route"));
    }

    #[test]
    fn linux_plan_assigns_point_to_point_address_and_single_peer_route() {
        let plan = linux_plan();

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
    fn executor_applies_setup_and_cleanup_in_planned_order() {
        let plan = linux_plan();
        let executor = executor();
        let mut runner = RecordingRouteCommandRunner::default();

        executor.apply_with_runner(&plan, &mut runner).unwrap();
        executor.cleanup_with_runner(&plan, &mut runner).unwrap();

        assert_eq!(runner.calls.len(), 6);
        for call in &runner.calls {
            assert_eq!(call.tool, ClawVpnInterfaceRouteTool::LinuxIp);
            assert_eq!(call.program, "/run/current-system/sw/bin/ip");
        }
        assert_eq!(
            runner.calls[0].args,
            plan.setup_commands()[0].args().to_vec()
        );
        assert_eq!(
            runner.calls[1].args,
            plan.setup_commands()[1].args().to_vec()
        );
        assert_eq!(
            runner.calls[2].args,
            plan.setup_commands()[2].args().to_vec()
        );
        assert_eq!(
            runner.calls[3].args,
            plan.cleanup_commands()[0].args().to_vec()
        );
        assert_eq!(
            runner.calls[4].args,
            plan.cleanup_commands()[1].args().to_vec()
        );
        assert_eq!(
            runner.calls[5].args,
            plan.cleanup_commands()[2].args().to_vec()
        );
    }

    #[test]
    fn executor_applies_macos_setup_and_cleanup_in_planned_order() {
        let plan = macos_plan();
        let executor = ClawVpnInterfaceRouteExecutor::new_for_platform(
            tool_paths(),
            ClawVpnInterfaceRoutePlatform::Macos,
        );
        let mut runner = RecordingRouteCommandRunner::default();

        executor.apply_with_runner(&plan, &mut runner).unwrap();
        executor.cleanup_with_runner(&plan, &mut runner).unwrap();

        assert_eq!(runner.calls.len(), 4);
        assert_eq!(
            runner.calls[0].tool,
            ClawVpnInterfaceRouteTool::MacosIfconfig
        );
        assert_eq!(runner.calls[0].program, "/sbin/ifconfig");
        assert_eq!(
            runner.calls[0].args,
            plan.setup_commands()[0].args().to_vec()
        );
        assert_eq!(runner.calls[1].tool, ClawVpnInterfaceRouteTool::MacosRoute);
        assert_eq!(runner.calls[1].program, "/sbin/route");
        assert_eq!(
            runner.calls[1].args,
            plan.setup_commands()[1].args().to_vec()
        );
        assert_eq!(runner.calls[2].tool, ClawVpnInterfaceRouteTool::MacosRoute);
        assert_eq!(runner.calls[2].program, "/sbin/route");
        assert_eq!(
            runner.calls[2].args,
            plan.cleanup_commands()[0].args().to_vec()
        );
        assert_eq!(
            runner.calls[3].tool,
            ClawVpnInterfaceRouteTool::MacosIfconfig
        );
        assert_eq!(runner.calls[3].program, "/sbin/ifconfig");
        assert_eq!(
            runner.calls[3].args,
            plan.cleanup_commands()[1].args().to_vec()
        );
    }

    #[test]
    fn executor_rejects_platform_mismatch_before_running_commands() {
        let plan = linux_plan();
        let executor = ClawVpnInterfaceRouteExecutor::new_for_platform(
            tool_paths(),
            ClawVpnInterfaceRoutePlatform::Macos,
        );
        let mut runner = RecordingRouteCommandRunner::default();

        let apply_error = executor.apply_with_runner(&plan, &mut runner).unwrap_err();
        assert_eq!(runner.calls.len(), 0);
        match apply_error {
            ClawVpnInterfaceRouteExecutionError::PlatformMismatch {
                executor_platform: Some(ClawVpnInterfaceRoutePlatform::Macos),
                plan_platform: ClawVpnInterfaceRoutePlatform::Linux,
            } => {}
            other => panic!("unexpected apply error: {other:?}"),
        }

        let cleanup_error = executor
            .cleanup_with_runner(&plan, &mut runner)
            .unwrap_err();
        assert_eq!(runner.calls.len(), 0);
        match cleanup_error {
            ClawVpnInterfaceRouteExecutionError::PlatformMismatch {
                executor_platform: Some(ClawVpnInterfaceRoutePlatform::Macos),
                plan_platform: ClawVpnInterfaceRoutePlatform::Linux,
            } => {}
            other => panic!("unexpected cleanup error: {other:?}"),
        }
    }

    #[test]
    fn executor_reports_setup_spawn_failure_and_attempts_cleanup() {
        let plan = linux_plan();
        let executor = executor();
        let mut runner =
            RecordingRouteCommandRunner::with_outcomes(vec![FakeRouteCommandOutcome::SpawnFailure]);

        let error = executor.apply_with_runner(&plan, &mut runner).unwrap_err();
        let error_debug = format!("{error:?}");
        assert!(!error_debug.contains("clawvpn0"));
        assert!(!error_debug.contains("198.51.100.10"));
        assert!(!error_debug.contains("198.51.100.11"));
        assert!(!error_debug.contains("/run/current-system/sw/bin/ip"));
        assert!(!error_debug.contains("/sbin/ifconfig"));
        assert!(!error_debug.contains("/sbin/route"));

        match error {
            ClawVpnInterfaceRouteExecutionError::SetupFailed {
                setup_error,
                cleanup_error: None,
            } => match *setup_error {
                ClawVpnInterfaceRouteExecutionError::CommandSpawn {
                    phase: ClawVpnInterfaceRouteExecutionPhase::Setup,
                    command_index: 0,
                    tool: ClawVpnInterfaceRouteTool::LinuxIp,
                    ..
                } => {}
                other => panic!("unexpected setup error: {other:?}"),
            },
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(runner.calls.len(), 4);
        assert_eq!(
            runner.calls[0].args,
            plan.setup_commands()[0].args().to_vec()
        );
        assert_eq!(
            runner.calls[1].args,
            plan.cleanup_commands()[0].args().to_vec()
        );
        assert_eq!(
            runner.calls[2].args,
            plan.cleanup_commands()[1].args().to_vec()
        );
        assert_eq!(
            runner.calls[3].args,
            plan.cleanup_commands()[2].args().to_vec()
        );
        assert!(
            !runner
                .calls
                .iter()
                .any(|call| call.args == plan.setup_commands()[1].args().to_vec())
        );
    }

    #[test]
    fn executor_runs_cleanup_after_setup_failure_without_continuing_setup() {
        let plan = linux_plan();
        let executor = executor();
        let mut runner = RecordingRouteCommandRunner::with_outcomes(vec![
            FakeRouteCommandOutcome::Success,
            FakeRouteCommandOutcome::ExitFailure(Some(2)),
        ]);

        let error = executor.apply_with_runner(&plan, &mut runner).unwrap_err();
        let error_debug = format!("{error:?}");
        assert!(!error_debug.contains("clawvpn0"));
        assert!(!error_debug.contains("198.51.100.10"));
        assert!(!error_debug.contains("198.51.100.11"));
        assert!(!error_debug.contains("/run/current-system/sw/bin/ip"));
        assert!(!error_debug.contains("/sbin/ifconfig"));
        assert!(!error_debug.contains("/sbin/route"));

        match error {
            ClawVpnInterfaceRouteExecutionError::SetupFailed {
                setup_error,
                cleanup_error: None,
            } => match *setup_error {
                ClawVpnInterfaceRouteExecutionError::CommandFailed {
                    phase: ClawVpnInterfaceRouteExecutionPhase::Setup,
                    command_index: 1,
                    tool: ClawVpnInterfaceRouteTool::LinuxIp,
                    status_code: Some(2),
                } => {}
                other => panic!("unexpected setup error: {other:?}"),
            },
            other => panic!("unexpected error: {other:?}"),
        }

        assert_eq!(runner.calls.len(), 5);
        assert_eq!(
            runner.calls[0].args,
            plan.setup_commands()[0].args().to_vec()
        );
        assert_eq!(
            runner.calls[1].args,
            plan.setup_commands()[1].args().to_vec()
        );
        assert_eq!(
            runner.calls[2].args,
            plan.cleanup_commands()[0].args().to_vec()
        );
        assert_eq!(
            runner.calls[3].args,
            plan.cleanup_commands()[1].args().to_vec()
        );
        assert_eq!(
            runner.calls[4].args,
            plan.cleanup_commands()[2].args().to_vec()
        );
        assert!(
            !runner
                .calls
                .iter()
                .any(|call| call.args == plan.setup_commands()[2].args().to_vec())
        );
    }

    #[test]
    fn cleanup_continues_after_cleanup_command_failure() {
        let plan = linux_plan();
        let executor = executor();
        let mut runner = RecordingRouteCommandRunner::with_outcomes(vec![
            FakeRouteCommandOutcome::SpawnFailure,
            FakeRouteCommandOutcome::Success,
            FakeRouteCommandOutcome::ExitFailure(Some(3)),
        ]);

        let error = executor
            .cleanup_with_runner(&plan, &mut runner)
            .unwrap_err();

        match error {
            ClawVpnInterfaceRouteExecutionError::CommandSpawn {
                phase: ClawVpnInterfaceRouteExecutionPhase::Cleanup,
                command_index: 0,
                tool: ClawVpnInterfaceRouteTool::LinuxIp,
                ..
            } => {}
            other => panic!("unexpected cleanup error: {other:?}"),
        }
        assert_eq!(runner.calls.len(), 3);
        assert_eq!(
            runner.calls[0].args,
            plan.cleanup_commands()[0].args().to_vec()
        );
        assert_eq!(
            runner.calls[1].args,
            plan.cleanup_commands()[1].args().to_vec()
        );
        assert_eq!(
            runner.calls[2].args,
            plan.cleanup_commands()[2].args().to_vec()
        );
    }

    #[test]
    fn setup_failure_reports_cleanup_failure_after_attempting_cleanup() {
        let plan = linux_plan();
        let executor = executor();
        let mut runner = RecordingRouteCommandRunner::with_outcomes(vec![
            FakeRouteCommandOutcome::Success,
            FakeRouteCommandOutcome::ExitFailure(Some(2)),
            FakeRouteCommandOutcome::SpawnFailure,
            FakeRouteCommandOutcome::Success,
            FakeRouteCommandOutcome::Success,
        ]);

        let error = executor.apply_with_runner(&plan, &mut runner).unwrap_err();
        let error_debug = format!("{error:?}");
        assert!(!error_debug.contains("clawvpn0"));
        assert!(!error_debug.contains("198.51.100.10"));
        assert!(!error_debug.contains("198.51.100.11"));
        assert!(!error_debug.contains("/run/current-system/sw/bin/ip"));
        assert!(!error_debug.contains("/sbin/ifconfig"));
        assert!(!error_debug.contains("/sbin/route"));

        match error {
            ClawVpnInterfaceRouteExecutionError::SetupFailed {
                setup_error,
                cleanup_error: Some(cleanup_error),
            } => {
                match *setup_error {
                    ClawVpnInterfaceRouteExecutionError::CommandFailed {
                        phase: ClawVpnInterfaceRouteExecutionPhase::Setup,
                        command_index: 1,
                        tool: ClawVpnInterfaceRouteTool::LinuxIp,
                        status_code: Some(2),
                    } => {}
                    other => panic!("unexpected setup error: {other:?}"),
                }
                match *cleanup_error {
                    ClawVpnInterfaceRouteExecutionError::CommandSpawn {
                        phase: ClawVpnInterfaceRouteExecutionPhase::Cleanup,
                        command_index: 0,
                        tool: ClawVpnInterfaceRouteTool::LinuxIp,
                        ..
                    } => {}
                    other => panic!("unexpected cleanup error: {other:?}"),
                }
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(runner.calls.len(), 5);
        assert_eq!(
            runner.calls[0].args,
            plan.setup_commands()[0].args().to_vec()
        );
        assert_eq!(
            runner.calls[1].args,
            plan.setup_commands()[1].args().to_vec()
        );
        assert_eq!(
            runner.calls[2].args,
            plan.cleanup_commands()[0].args().to_vec()
        );
        assert_eq!(
            runner.calls[3].args,
            plan.cleanup_commands()[1].args().to_vec()
        );
        assert_eq!(
            runner.calls[4].args,
            plan.cleanup_commands()[2].args().to_vec()
        );
    }

    #[test]
    fn macos_plan_assigns_point_to_point_address_and_single_peer_route() {
        let plan = macos_plan();

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

        let mut runner =
            RecordingRouteCommandRunner::with_outcomes(vec![FakeRouteCommandOutcome::SpawnFailure]);
        let error = executor()
            .apply_with_runner(&plan, &mut runner)
            .unwrap_err();
        let error_debug = format!("{error:?}");
        assert!(!error_debug.contains("clawvpn0"));
        assert!(!error_debug.contains("198.51.100.10"));
        assert!(!error_debug.contains("198.51.100.11"));
        assert!(!error_debug.contains("/run/current-system/sw/bin/ip"));
        assert!(!error_debug.contains("/sbin/ifconfig"));
        assert!(!error_debug.contains("/sbin/route"));
    }
}
