//! Unwired lifecycle coordinator for the Product A per-Claw VPN proof.
//!
//! This module deliberately does not open TUN/utun interfaces, dial relay
//! sockets, spawn tasks, read product flags, or choose route tool paths. It
//! only sequences a caller-supplied route controller with the already reviewed
//! bounded packet-pump loop over abstract interface/relay traits.

use std::fmt;

use crate::claw_vpn_interface_route_plan::{
    ClawVpnInterfaceRouteExecutionError, ClawVpnInterfaceRouteExecutor, ClawVpnInterfaceRoutePlan,
};
use crate::claw_vpn_packet_pump::{
    ClawVpnPacketInterface, ClawVpnPacketPump, ClawVpnPacketPumpLoopDriver,
    ClawVpnPacketPumpLoopReport, ClawVpnPacketPumpLoopStopReason, ClawVpnPacketRelay,
};
use crate::claw_vpn_pollable_pump::{
    ClawVpnPollablePacketInterface, ClawVpnPollablePacketRelay, ClawVpnPollablePump,
    ClawVpnPollablePumpBudget, ClawVpnPollablePumpReport, ClawVpnPollablePumpStopReason,
};

pub const CLAW_VPN_RUNTIME_MAX_PACKET_PUMP_STEPS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClawVpnRuntimeStepBudgetError {
    Zero,
    TooLarge { max_steps: usize },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnRuntimeStepBudget {
    max_steps: usize,
}

impl fmt::Debug for ClawVpnRuntimeStepBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnRuntimeStepBudget")
            .field("max_steps", &self.max_steps)
            .finish()
    }
}

impl ClawVpnRuntimeStepBudget {
    pub fn new(max_steps: usize) -> Result<Self, ClawVpnRuntimeStepBudgetError> {
        if max_steps == 0 {
            return Err(ClawVpnRuntimeStepBudgetError::Zero);
        }
        if max_steps > CLAW_VPN_RUNTIME_MAX_PACKET_PUMP_STEPS {
            return Err(ClawVpnRuntimeStepBudgetError::TooLarge {
                max_steps: CLAW_VPN_RUNTIME_MAX_PACKET_PUMP_STEPS,
            });
        }
        Ok(Self { max_steps })
    }

    #[must_use]
    pub fn max_steps(self) -> usize {
        self.max_steps
    }
}

pub trait ClawVpnRuntimeRouteController {
    fn apply_routes(
        &mut self,
        plan: &ClawVpnInterfaceRoutePlan,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError>;

    fn cleanup_routes(
        &mut self,
        plan: &ClawVpnInterfaceRoutePlan,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError>;
}

impl ClawVpnRuntimeRouteController for ClawVpnInterfaceRouteExecutor {
    fn apply_routes(
        &mut self,
        plan: &ClawVpnInterfaceRoutePlan,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
        ClawVpnInterfaceRouteExecutor::apply(self, plan)
    }

    fn cleanup_routes(
        &mut self,
        plan: &ClawVpnInterfaceRoutePlan,
    ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
        ClawVpnInterfaceRouteExecutor::cleanup(self, plan)
    }
}

pub struct ClawVpnRuntimeReport {
    pump_report: ClawVpnPacketPumpLoopReport,
}

impl fmt::Debug for ClawVpnRuntimeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnRuntimeReport")
            .field("pump_report", &self.pump_report)
            .finish()
    }
}

impl ClawVpnRuntimeReport {
    #[must_use]
    pub fn pump_report(&self) -> &ClawVpnPacketPumpLoopReport {
        &self.pump_report
    }
}

pub enum ClawVpnRuntimeError {
    RouteSetup {
        source: ClawVpnInterfaceRouteExecutionError,
    },
    PacketPump {
        pump_report: ClawVpnPacketPumpLoopReport,
    },
    RouteCleanup {
        pump_report: ClawVpnPacketPumpLoopReport,
        source: ClawVpnInterfaceRouteExecutionError,
    },
}

impl fmt::Debug for ClawVpnRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RouteSetup { .. } => f
                .debug_struct("ClawVpnRuntimeError::RouteSetup")
                .field("source", &"<redacted>")
                .finish(),
            Self::PacketPump { pump_report } => f
                .debug_struct("ClawVpnRuntimeError::PacketPump")
                .field("pump_report", pump_report)
                .finish(),
            Self::RouteCleanup { pump_report, .. } => f
                .debug_struct("ClawVpnRuntimeError::RouteCleanup")
                .field("pump_report", pump_report)
                .field("source", &"<redacted>")
                .finish(),
        }
    }
}

pub struct ClawVpnRuntime {
    route_plan: ClawVpnInterfaceRoutePlan,
    packet_pump: ClawVpnPacketPump,
    step_budget: ClawVpnRuntimeStepBudget,
}

impl fmt::Debug for ClawVpnRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnRuntime")
            .field("route_plan", &"<redacted>")
            .field("packet_pump", &"<redacted>")
            .field("step_budget", &self.step_budget)
            .finish()
    }
}

impl ClawVpnRuntime {
    #[must_use]
    pub fn new(
        route_plan: ClawVpnInterfaceRoutePlan,
        packet_pump: ClawVpnPacketPump,
        step_budget: ClawVpnRuntimeStepBudget,
    ) -> Self {
        Self {
            route_plan,
            packet_pump,
            step_budget,
        }
    }

    pub fn run_until_stopped(
        &mut self,
        route_controller: &mut impl ClawVpnRuntimeRouteController,
        interface: &mut impl ClawVpnPacketInterface,
        relay: &mut impl ClawVpnPacketRelay,
        driver: &mut impl ClawVpnPacketPumpLoopDriver,
    ) -> Result<ClawVpnRuntimeReport, ClawVpnRuntimeError> {
        route_controller
            .apply_routes(&self.route_plan)
            .map_err(|source| ClawVpnRuntimeError::RouteSetup { source })?;

        let pump_report = self.packet_pump.pump_with_driver_until_stopped(
            interface,
            relay,
            driver,
            self.step_budget.max_steps(),
        );

        let pump_stopped_on_io_error = matches!(
            pump_report.stop_reason(),
            ClawVpnPacketPumpLoopStopReason::IoError { .. }
        );

        match route_controller.cleanup_routes(&self.route_plan) {
            Ok(()) if pump_stopped_on_io_error => {
                Err(ClawVpnRuntimeError::PacketPump { pump_report })
            }
            Ok(()) => Ok(ClawVpnRuntimeReport { pump_report }),
            Err(source) => Err(ClawVpnRuntimeError::RouteCleanup {
                pump_report,
                source,
            }),
        }
    }
}

/// End-of-run report for the non-blocking pollable datapath.
pub struct ClawVpnPollableRuntimeReport {
    pump_report: ClawVpnPollablePumpReport,
}

impl fmt::Debug for ClawVpnPollableRuntimeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPollableRuntimeReport")
            .field("pump_report", &self.pump_report)
            .finish()
    }
}

impl ClawVpnPollableRuntimeReport {
    #[must_use]
    pub fn pump_report(&self) -> &ClawVpnPollablePumpReport {
        &self.pump_report
    }
}

pub enum ClawVpnPollableRuntimeError {
    RouteSetup {
        source: ClawVpnInterfaceRouteExecutionError,
    },
    PacketPump {
        pump_report: ClawVpnPollablePumpReport,
    },
    RouteCleanup {
        pump_report: ClawVpnPollablePumpReport,
        source: ClawVpnInterfaceRouteExecutionError,
    },
}

impl fmt::Debug for ClawVpnPollableRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RouteSetup { .. } => f
                .debug_struct("ClawVpnPollableRuntimeError::RouteSetup")
                .field("source", &"<redacted>")
                .finish(),
            Self::PacketPump { pump_report } => f
                .debug_struct("ClawVpnPollableRuntimeError::PacketPump")
                .field("pump_report", pump_report)
                .finish(),
            Self::RouteCleanup { pump_report, .. } => f
                .debug_struct("ClawVpnPollableRuntimeError::RouteCleanup")
                .field("pump_report", pump_report)
                .field("source", &"<redacted>")
                .finish(),
        }
    }
}

/// Lifecycle coordinator for the non-blocking pollable datapath: applies routes,
/// runs the readiness-driven pump, and always cleans up routes. Mirrors
/// [`ClawVpnRuntime`] but drives [`ClawVpnPollablePump`]. A clean stop
/// (idle/step budget) yields a report; a fatal stop (partial-frame/IoError)
/// yields an error — cleanup runs on every path.
pub struct ClawVpnPollableRuntime {
    route_plan: ClawVpnInterfaceRoutePlan,
    pollable_pump: ClawVpnPollablePump,
    budget: ClawVpnPollablePumpBudget,
}

impl fmt::Debug for ClawVpnPollableRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPollableRuntime")
            .field("route_plan", &"<redacted>")
            .field("pollable_pump", &"<redacted>")
            .field("budget", &self.budget)
            .finish()
    }
}

impl ClawVpnPollableRuntime {
    #[must_use]
    pub fn new(
        route_plan: ClawVpnInterfaceRoutePlan,
        pollable_pump: ClawVpnPollablePump,
        budget: ClawVpnPollablePumpBudget,
    ) -> Self {
        Self {
            route_plan,
            pollable_pump,
            budget,
        }
    }

    pub fn run_until_stopped(
        &mut self,
        route_controller: &mut impl ClawVpnRuntimeRouteController,
        interface: &mut impl ClawVpnPollablePacketInterface,
        relay: &mut impl ClawVpnPollablePacketRelay,
    ) -> Result<ClawVpnPollableRuntimeReport, ClawVpnPollableRuntimeError> {
        route_controller
            .apply_routes(&self.route_plan)
            .map_err(|source| ClawVpnPollableRuntimeError::RouteSetup { source })?;

        let pump_report = self
            .pollable_pump
            .run_until_stopped(interface, relay, &self.budget);

        let pump_stopped_fatal = matches!(
            pump_report.stop_reason,
            ClawVpnPollablePumpStopReason::PartialFrameStalled
                | ClawVpnPollablePumpStopReason::IoError { .. }
        );

        match route_controller.cleanup_routes(&self.route_plan) {
            Ok(()) if pump_stopped_fatal => {
                Err(ClawVpnPollableRuntimeError::PacketPump { pump_report })
            }
            Ok(()) => Ok(ClawVpnPollableRuntimeReport { pump_report }),
            Err(source) => Err(ClawVpnPollableRuntimeError::RouteCleanup {
                pump_report,
                source,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claw_vpn_interface_route_plan::{
        ClawVpnInterfaceName, ClawVpnInterfaceRouteExecutionPhase, ClawVpnInterfaceRoutePlatform,
        ClawVpnInterfaceRouteSide, ClawVpnInterfaceRouteTool,
    };
    use crate::claw_vpn_packet_pump::{
        ClawVpnPacketPumpDirection, ClawVpnPacketPumpLoopControl, ClawVpnPacketPumpLoopStopReason,
    };
    use household_rs::claw_share_data_tunnel::TunnelFrame;
    use household_rs::claw_vpn::{
        ClawVpnAcl, ClawVpnAclKey, ClawVpnAgentCore, ClawVpnAuditReason, ClawVpnDatapathSide,
        ClawVpnIpv4Pool, ClawVpnSessionAddrs, ClawVpnSessionRegistry,
    };
    use household_rs::keys::{IdentityKey, P256Keypair};
    use std::collections::VecDeque;
    use std::io;
    use std::net::Ipv4Addr;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RouteCall {
        Apply,
        Cleanup,
    }

    #[derive(Debug, Default)]
    struct FakeRouteController {
        calls: Vec<RouteCall>,
        fail_apply: bool,
        fail_cleanup: bool,
    }

    impl ClawVpnRuntimeRouteController for FakeRouteController {
        fn apply_routes(
            &mut self,
            _plan: &ClawVpnInterfaceRoutePlan,
        ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
            self.calls.push(RouteCall::Apply);
            if self.fail_apply {
                return Err(route_error(ClawVpnInterfaceRouteExecutionPhase::Setup));
            }
            Ok(())
        }

        fn cleanup_routes(
            &mut self,
            _plan: &ClawVpnInterfaceRoutePlan,
        ) -> Result<(), ClawVpnInterfaceRouteExecutionError> {
            self.calls.push(RouteCall::Cleanup);
            if self.fail_cleanup {
                return Err(route_error(ClawVpnInterfaceRouteExecutionPhase::Cleanup));
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeInterface {
        reads: VecDeque<Vec<u8>>,
        writes: Vec<Vec<u8>>,
        read_count: usize,
    }

    impl FakeInterface {
        fn with_read(packet: Vec<u8>) -> Self {
            let mut reads = VecDeque::new();
            reads.push_back(packet);
            Self {
                reads,
                writes: Vec::new(),
                read_count: 0,
            }
        }
    }

    impl ClawVpnPacketInterface for FakeInterface {
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_count += 1;
            let packet = self.reads.pop_front().unwrap_or_default();
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        }

        fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            self.writes.push(packet.to_vec());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeRelay {
        recv_frames: VecDeque<TunnelFrame>,
        sent_frames: Vec<TunnelFrame>,
        recv_error: Option<io::Error>,
        send_error: Option<io::Error>,
    }

    impl ClawVpnPacketRelay for FakeRelay {
        fn recv_frame(&mut self) -> io::Result<TunnelFrame> {
            if let Some(error) = self.recv_error.take() {
                return Err(error);
            }
            self.recv_frames
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "fake relay eof"))
        }

        fn send_frame(&mut self, frame: TunnelFrame) -> io::Result<()> {
            if let Some(error) = self.send_error.take() {
                return Err(error);
            }
            self.sent_frames.push(frame);
            Ok(())
        }
    }

    struct ScriptedLoopDriver {
        controls: VecDeque<ClawVpnPacketPumpLoopControl>,
    }

    impl ScriptedLoopDriver {
        fn new(controls: Vec<ClawVpnPacketPumpLoopControl>) -> Self {
            Self {
                controls: VecDeque::from(controls),
            }
        }
    }

    impl ClawVpnPacketPumpLoopDriver for ScriptedLoopDriver {
        fn next_step(
            &mut self,
            _stats: crate::claw_vpn_packet_pump::ClawVpnPacketPumpLoopStats,
        ) -> ClawVpnPacketPumpLoopControl {
            self.controls
                .pop_front()
                .unwrap_or(ClawVpnPacketPumpLoopControl::Stop)
        }
    }

    fn route_error(
        phase: ClawVpnInterfaceRouteExecutionPhase,
    ) -> ClawVpnInterfaceRouteExecutionError {
        ClawVpnInterfaceRouteExecutionError::CommandFailed {
            phase,
            command_index: 0,
            tool: ClawVpnInterfaceRouteTool::LinuxIp,
            status_code: Some(2),
        }
    }

    fn runtime_with_addrs() -> (ClawVpnRuntime, ClawVpnSessionAddrs) {
        let key = acl_key();
        let mut acl = ClawVpnAcl::new();
        assert!(acl.grant(key.clone()));
        let pool = ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 24).unwrap();
        let registry = ClawVpnSessionRegistry::new(acl, pool);
        let mut core = ClawVpnAgentCore::new(ClawVpnDatapathSide::Device, registry);
        let (session, open_event) = core.open_with_audit(&key);
        let session = session.unwrap();
        assert_eq!(open_event.reason(), ClawVpnAuditReason::SessionOpened);
        let addrs = session.addrs();
        let route_plan = ClawVpnInterfaceRoutePlan::new(
            ClawVpnInterfaceRoutePlatform::Linux,
            ClawVpnInterfaceName::new("clawvpn0").unwrap(),
            addrs,
            ClawVpnInterfaceRouteSide::Device,
        );
        let session_core = core.into_session_core(session.id()).unwrap();
        let runtime = ClawVpnRuntime::new(
            route_plan,
            ClawVpnPacketPump::new(session_core),
            ClawVpnRuntimeStepBudget::new(8).unwrap(),
        );
        (runtime, addrs)
    }

    fn acl_key() -> ClawVpnAclKey {
        ClawVpnAclKey::try_new("member-m1", P256Keypair::generate().public(), "claw-a").unwrap()
    }

    fn packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet
    }

    #[test]
    fn runtime_applies_routes_pumps_and_cleans_up_in_order() {
        let (mut runtime, addrs) = runtime_with_addrs();
        let local_packet = packet(addrs.device(), addrs.claw());
        let mut route_controller = FakeRouteController::default();
        let mut interface = FakeInterface::with_read(local_packet.clone());
        let mut relay = FakeRelay::default();
        let mut driver = ScriptedLoopDriver::new(vec![
            ClawVpnPacketPumpLoopControl::Pump(ClawVpnPacketPumpDirection::InterfaceToRelay),
            ClawVpnPacketPumpLoopControl::Stop,
        ]);

        let report = runtime
            .run_until_stopped(
                &mut route_controller,
                &mut interface,
                &mut relay,
                &mut driver,
            )
            .unwrap();

        assert_eq!(
            route_controller.calls,
            vec![RouteCall::Apply, RouteCall::Cleanup]
        );
        assert_eq!(relay.sent_frames, vec![TunnelFrame::Data(local_packet)]);
        assert_eq!(
            report.pump_report().stats().interface_to_relay_forwarded(),
            1
        );
        assert_eq!(report.pump_report().stats().total_steps(), 1);
        assert!(matches!(
            report.pump_report().stop_reason(),
            ClawVpnPacketPumpLoopStopReason::DriverStopped
        ));
    }

    #[test]
    fn runtime_setup_failure_stops_before_pump_or_cleanup() {
        let (mut runtime, addrs) = runtime_with_addrs();
        let mut route_controller = FakeRouteController {
            fail_apply: true,
            ..FakeRouteController::default()
        };
        let mut interface = FakeInterface::with_read(packet(addrs.device(), addrs.claw()));
        let mut relay = FakeRelay::default();
        let mut driver = ScriptedLoopDriver::new(vec![ClawVpnPacketPumpLoopControl::Pump(
            ClawVpnPacketPumpDirection::InterfaceToRelay,
        )]);

        let error = runtime
            .run_until_stopped(
                &mut route_controller,
                &mut interface,
                &mut relay,
                &mut driver,
            )
            .unwrap_err();
        let debug = format!("{error:?}");

        assert!(matches!(error, ClawVpnRuntimeError::RouteSetup { .. }));
        assert_eq!(route_controller.calls, vec![RouteCall::Apply]);
        assert_eq!(interface.read_count, 0);
        assert!(relay.sent_frames.is_empty());
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("clawvpn0"));
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
        assert!(!debug.contains(&addrs.device().to_string()));
        assert!(!debug.contains(&addrs.claw().to_string()));
    }

    #[test]
    fn runtime_cleans_up_and_reports_packet_pump_io_error() {
        let (mut runtime, addrs) = runtime_with_addrs();
        let local_packet = packet(addrs.device(), addrs.claw());
        let mut route_controller = FakeRouteController::default();
        let mut interface = FakeInterface::with_read(local_packet);
        let mut relay = FakeRelay {
            recv_frames: VecDeque::new(),
            sent_frames: Vec::new(),
            recv_error: None,
            send_error: Some(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "/tmp/private-relay",
            )),
        };
        let mut driver = ScriptedLoopDriver::new(vec![
            ClawVpnPacketPumpLoopControl::Pump(ClawVpnPacketPumpDirection::InterfaceToRelay),
            ClawVpnPacketPumpLoopControl::Pump(ClawVpnPacketPumpDirection::RelayToInterface),
        ]);

        let error = runtime
            .run_until_stopped(
                &mut route_controller,
                &mut interface,
                &mut relay,
                &mut driver,
            )
            .unwrap_err();
        let debug = format!("{error:?}");

        assert_eq!(
            route_controller.calls,
            vec![RouteCall::Apply, RouteCall::Cleanup]
        );
        let ClawVpnRuntimeError::PacketPump { pump_report } = error else {
            panic!("packet pump error expected");
        };
        assert!(matches!(
            pump_report.stop_reason(),
            ClawVpnPacketPumpLoopStopReason::IoError {
                direction: ClawVpnPacketPumpDirection::InterfaceToRelay,
                ..
            }
        ));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("/tmp/private-relay"));
        assert!(!debug.contains("clawvpn0"));
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
        assert!(!debug.contains(&addrs.device().to_string()));
        assert!(!debug.contains(&addrs.claw().to_string()));
    }

    #[test]
    fn runtime_reports_cleanup_failure_with_pump_report() {
        let (mut runtime, addrs) = runtime_with_addrs();
        let local_packet = packet(addrs.device(), addrs.claw());
        let mut route_controller = FakeRouteController {
            fail_cleanup: true,
            ..FakeRouteController::default()
        };
        let mut interface = FakeInterface::with_read(local_packet.clone());
        let mut relay = FakeRelay::default();
        let mut driver = ScriptedLoopDriver::new(vec![
            ClawVpnPacketPumpLoopControl::Pump(ClawVpnPacketPumpDirection::InterfaceToRelay),
            ClawVpnPacketPumpLoopControl::Stop,
        ]);

        let error = runtime
            .run_until_stopped(
                &mut route_controller,
                &mut interface,
                &mut relay,
                &mut driver,
            )
            .unwrap_err();
        let debug = format!("{error:?}");

        assert_eq!(
            route_controller.calls,
            vec![RouteCall::Apply, RouteCall::Cleanup]
        );
        assert_eq!(relay.sent_frames, vec![TunnelFrame::Data(local_packet)]);
        let ClawVpnRuntimeError::RouteCleanup { pump_report, .. } = error else {
            panic!("cleanup error expected");
        };
        assert_eq!(pump_report.stats().interface_to_relay_forwarded(), 1);
        assert_eq!(pump_report.stats().total_steps(), 1);
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("clawvpn0"));
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
        assert!(!debug.contains(&addrs.device().to_string()));
        assert!(!debug.contains(&addrs.claw().to_string()));
    }

    #[test]
    fn runtime_step_budget_rejects_zero_and_unbounded_values() {
        assert_eq!(
            ClawVpnRuntimeStepBudget::new(0),
            Err(ClawVpnRuntimeStepBudgetError::Zero)
        );
        assert_eq!(
            ClawVpnRuntimeStepBudget::new(CLAW_VPN_RUNTIME_MAX_PACKET_PUMP_STEPS + 1),
            Err(ClawVpnRuntimeStepBudgetError::TooLarge {
                max_steps: CLAW_VPN_RUNTIME_MAX_PACKET_PUMP_STEPS
            })
        );
        assert_eq!(
            ClawVpnRuntimeStepBudget::new(usize::MAX),
            Err(ClawVpnRuntimeStepBudgetError::TooLarge {
                max_steps: CLAW_VPN_RUNTIME_MAX_PACKET_PUMP_STEPS
            })
        );
        assert_eq!(
            ClawVpnRuntimeStepBudget::new(CLAW_VPN_RUNTIME_MAX_PACKET_PUMP_STEPS)
                .unwrap()
                .max_steps(),
            CLAW_VPN_RUNTIME_MAX_PACKET_PUMP_STEPS
        );
    }

    #[test]
    fn runtime_debug_does_not_print_route_or_packet_material() {
        let (runtime, addrs) = runtime_with_addrs();
        let debug = format!("{runtime:?}");

        assert!(debug.contains("ClawVpnRuntime"));
        assert!(debug.contains("step_budget"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("clawvpn0"));
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
        assert!(!debug.contains(&addrs.device().to_string()));
        assert!(!debug.contains(&addrs.claw().to_string()));
    }
}
