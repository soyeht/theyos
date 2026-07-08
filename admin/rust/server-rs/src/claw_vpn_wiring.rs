//! Default-off wiring assembly for the Product A per-Claw VPN proof.
//!
//! This module intentionally does not read product flags, open TUN/utun
//! interfaces, dial relays, install routes during assembly, spawn tasks, or wire
//! bootstrap. It is the reviewed composition point for caller-supplied handles:
//! the disabled path returns before constructing any handle, and the enabled
//! path binds one active session to the route plan, packet pump, bounded
//! production driver, and runtime coordinator.

use std::fmt;

use household_rs::claw_vpn::{
    ClawVpnAgentSessionCore, ClawVpnDatapathSide, ClawVpnSessionAddrs, ClawVpnSessionFrameError,
};

use crate::claw_vpn_interface_route_plan::{
    ClawVpnInterfaceName, ClawVpnInterfaceRouteExecutor, ClawVpnInterfaceRoutePlatform,
    ClawVpnInterfaceRouteSide, ClawVpnInterfaceRouteToolPaths,
};
use crate::claw_vpn_packet_pump::{
    ClawVpnPacketInterface, ClawVpnPacketPump, ClawVpnPacketPumpProductionDriver,
    ClawVpnPacketPumpProductionDriverBudget, ClawVpnPacketPumpSystemClock, ClawVpnPacketRelay,
};
use crate::claw_vpn_pollable_pump::{
    ClawVpnPollablePacketInterface, ClawVpnPollablePacketRelay, ClawVpnPollablePump,
    ClawVpnPollablePumpBudget,
};
use crate::claw_vpn_runtime::{
    ClawVpnPollableRuntime, ClawVpnPollableRuntimeError, ClawVpnPollableRuntimeReport,
    ClawVpnRuntime, ClawVpnRuntimeError, ClawVpnRuntimeReport, ClawVpnRuntimeStepBudget,
};

/// Poll timeout (ms) for the pollable datapath — how long each readiness poll
/// waits before counting as an idle cycle. Active forwarding returns early.
const CLAW_VPN_POLLABLE_POLL_TIMEOUT_MS: i32 = 250;
/// Consecutive idle polls before the pollable datapath tears down cleanly
/// (≈ timeout × this ≈ 10s of no traffic in either direction).
const CLAW_VPN_POLLABLE_MAX_IDLE_POLLS: usize = 40;
/// Consecutive polls a single frame may stay partially transferred before the
/// pollable datapath treats it as a stalled peer (fatal).
const CLAW_VPN_POLLABLE_MAX_PARTIAL_FRAME_POLLS: usize = 40;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnRuntimeWiringConfig {
    enabled: bool,
    runtime_step_budget: ClawVpnRuntimeStepBudget,
    driver_budget: ClawVpnPacketPumpProductionDriverBudget,
}

impl fmt::Debug for ClawVpnRuntimeWiringConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnRuntimeWiringConfig")
            .field("enabled", &self.enabled)
            .field("runtime_step_budget", &self.runtime_step_budget)
            .field("driver_budget", &self.driver_budget)
            .finish()
    }
}

impl Default for ClawVpnRuntimeWiringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            runtime_step_budget: ClawVpnRuntimeStepBudget::new(
                crate::claw_vpn_runtime::CLAW_VPN_RUNTIME_MAX_PACKET_PUMP_STEPS,
            )
            .expect("default runtime step budget is valid"),
            driver_budget: ClawVpnPacketPumpProductionDriverBudget::default(),
        }
    }
}

impl ClawVpnRuntimeWiringConfig {
    #[must_use]
    pub fn new(
        enabled: bool,
        runtime_step_budget: ClawVpnRuntimeStepBudget,
        driver_budget: ClawVpnPacketPumpProductionDriverBudget,
    ) -> Self {
        Self {
            enabled,
            runtime_step_budget,
            driver_budget,
        }
    }

    #[must_use]
    pub fn enabled(self) -> bool {
        self.enabled
    }

    #[must_use]
    pub fn runtime_step_budget(self) -> ClawVpnRuntimeStepBudget {
        self.runtime_step_budget
    }

    #[must_use]
    pub fn driver_budget(self) -> ClawVpnPacketPumpProductionDriverBudget {
        self.driver_budget
    }

    /// Budget for the non-blocking pollable datapath. Reuses the configured
    /// step cap; the poll timeout and idle/partial-frame bounds are the
    /// pollable-specific defaults (idle teardown ≈ timeout × idle-polls).
    ///
    /// # Panics
    /// Never in practice: the timeout/idle/partial-frame constants and the
    /// already-validated step budget are all in range for
    /// [`ClawVpnPollablePumpBudget::new`].
    #[must_use]
    pub fn pollable_pump_budget(self) -> ClawVpnPollablePumpBudget {
        ClawVpnPollablePumpBudget::new(
            CLAW_VPN_POLLABLE_POLL_TIMEOUT_MS,
            CLAW_VPN_POLLABLE_MAX_IDLE_POLLS,
            CLAW_VPN_POLLABLE_MAX_PARTIAL_FRAME_POLLS,
            self.runtime_step_budget.max_steps(),
        )
        .expect("default pollable pump budget is valid")
    }
}

pub struct ClawVpnRuntimeWiringInputs<I, R> {
    pub route_platform: ClawVpnInterfaceRoutePlatform,
    pub interface_name: ClawVpnInterfaceName,
    pub route_tool_paths: ClawVpnInterfaceRouteToolPaths,
    pub interface: I,
    pub relay: R,
}

impl<I, R> fmt::Debug for ClawVpnRuntimeWiringInputs<I, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnRuntimeWiringInputs")
            .field("route_platform", &self.route_platform)
            .field("interface_name", &"<redacted>")
            .field("route_tool_paths", &"<redacted>")
            .field("interface", &"<redacted>")
            .field("relay", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClawVpnRuntimeWiringContext {
    route_side: ClawVpnInterfaceRouteSide,
    addrs: ClawVpnSessionAddrs,
}

impl fmt::Debug for ClawVpnRuntimeWiringContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnRuntimeWiringContext")
            .field("route_side", &self.route_side)
            .field("addrs", &"<redacted>")
            .finish()
    }
}

impl ClawVpnRuntimeWiringContext {
    #[must_use]
    pub fn route_side(self) -> ClawVpnInterfaceRouteSide {
        self.route_side
    }

    #[must_use]
    pub fn addrs(self) -> ClawVpnSessionAddrs {
        self.addrs
    }
}

pub struct ClawVpnRuntimeWiring<I, R> {
    runtime: ClawVpnRuntime,
    route_executor: ClawVpnInterfaceRouteExecutor,
    interface: I,
    relay: R,
    driver: ClawVpnPacketPumpProductionDriver<ClawVpnPacketPumpSystemClock>,
}

impl<I, R> fmt::Debug for ClawVpnRuntimeWiring<I, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnRuntimeWiring")
            .field("runtime", &"<redacted>")
            .field("route_executor", &"<redacted>")
            .field("interface", &"<redacted>")
            .field("relay", &"<redacted>")
            .field("driver", &self.driver)
            .finish()
    }
}

impl<I, R> ClawVpnRuntimeWiring<I, R>
where
    I: ClawVpnPacketInterface,
    R: ClawVpnPacketRelay,
{
    pub fn run_until_stopped(&mut self) -> Result<ClawVpnRuntimeReport, ClawVpnRuntimeError> {
        self.runtime.run_until_stopped(
            &mut self.route_executor,
            &mut self.interface,
            &mut self.relay,
            &mut self.driver,
        )
    }
}

/// Non-blocking pollable datapath assembly: the readiness-driven pump variant of
/// [`ClawVpnRuntimeWiring`]. Holds no production driver — the pollable pump owns
/// its own budget through [`ClawVpnPollableRuntime`].
pub struct ClawVpnPollableRuntimeWiring<I, R> {
    runtime: ClawVpnPollableRuntime,
    route_executor: ClawVpnInterfaceRouteExecutor,
    interface: I,
    relay: R,
}

impl<I, R> fmt::Debug for ClawVpnPollableRuntimeWiring<I, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPollableRuntimeWiring")
            .field("runtime", &"<redacted>")
            .field("route_executor", &"<redacted>")
            .field("interface", &"<redacted>")
            .field("relay", &"<redacted>")
            .finish()
    }
}

impl<I, R> ClawVpnPollableRuntimeWiring<I, R>
where
    I: ClawVpnPollablePacketInterface,
    R: ClawVpnPollablePacketRelay,
{
    pub fn run_until_stopped(
        &mut self,
    ) -> Result<ClawVpnPollableRuntimeReport, ClawVpnPollableRuntimeError> {
        self.runtime.run_until_stopped(
            &mut self.route_executor,
            &mut self.interface,
            &mut self.relay,
        )
    }
}

#[derive(thiserror::Error)]
pub enum ClawVpnRuntimeWiringError {
    #[error("claw vpn runtime wiring session is not active")]
    Session(#[from] ClawVpnSessionFrameError),
}

impl fmt::Debug for ClawVpnRuntimeWiringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(_) => f
                .debug_struct("ClawVpnRuntimeWiringError::Session")
                .field("source", &"<redacted>")
                .finish(),
        }
    }
}

pub enum ClawVpnRuntimeWiringBuildError<E> {
    Session(ClawVpnSessionFrameError),
    Inputs(E),
}

impl<E> fmt::Debug for ClawVpnRuntimeWiringBuildError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(_) => f
                .debug_struct("ClawVpnRuntimeWiringBuildError::Session")
                .field("source", &"<redacted>")
                .finish(),
            Self::Inputs(_) => f
                .debug_struct("ClawVpnRuntimeWiringBuildError::Inputs")
                .field("source", &"<redacted>")
                .finish(),
        }
    }
}

pub fn assemble_claw_vpn_runtime_wiring<I, R>(
    config: ClawVpnRuntimeWiringConfig,
    session_core: ClawVpnAgentSessionCore,
    build_inputs: impl FnOnce(ClawVpnRuntimeWiringContext) -> ClawVpnRuntimeWiringInputs<I, R>,
) -> Result<Option<ClawVpnRuntimeWiring<I, R>>, ClawVpnRuntimeWiringError>
where
    I: ClawVpnPacketInterface,
    R: ClawVpnPacketRelay,
{
    if !config.enabled() {
        return Ok(None);
    }

    let route_side = route_side_for_datapath(session_core.local_side());
    let addrs = session_core.addrs()?;
    let inputs = build_inputs(ClawVpnRuntimeWiringContext { route_side, addrs });
    let route_plan = crate::claw_vpn_interface_route_plan::ClawVpnInterfaceRoutePlan::new(
        inputs.route_platform,
        inputs.interface_name,
        addrs,
        route_side,
    );
    let packet_pump = ClawVpnPacketPump::new(session_core);
    let runtime = ClawVpnRuntime::new(route_plan, packet_pump, config.runtime_step_budget());
    let route_executor = ClawVpnInterfaceRouteExecutor::new(inputs.route_tool_paths);
    let driver = ClawVpnPacketPumpProductionDriver::new(config.driver_budget());

    Ok(Some(ClawVpnRuntimeWiring {
        runtime,
        route_executor,
        interface: inputs.interface,
        relay: inputs.relay,
        driver,
    }))
}

/// Assemble the non-blocking pollable datapath. Mirrors
/// [`assemble_claw_vpn_runtime_wiring`] but builds a [`ClawVpnPollablePump`] +
/// [`ClawVpnPollableRuntime`]; the interface/relay must implement the pollable
/// (`O_NONBLOCK`) traits. Returns `None` when the datapath is disabled.
pub fn assemble_claw_vpn_pollable_runtime_wiring<I, R>(
    config: ClawVpnRuntimeWiringConfig,
    session_core: ClawVpnAgentSessionCore,
    build_inputs: impl FnOnce(ClawVpnRuntimeWiringContext) -> ClawVpnRuntimeWiringInputs<I, R>,
) -> Result<Option<ClawVpnPollableRuntimeWiring<I, R>>, ClawVpnRuntimeWiringError>
where
    I: ClawVpnPollablePacketInterface,
    R: ClawVpnPollablePacketRelay,
{
    if !config.enabled() {
        return Ok(None);
    }

    let route_side = route_side_for_datapath(session_core.local_side());
    let addrs = session_core.addrs()?;
    let inputs = build_inputs(ClawVpnRuntimeWiringContext { route_side, addrs });
    let route_plan = crate::claw_vpn_interface_route_plan::ClawVpnInterfaceRoutePlan::new(
        inputs.route_platform,
        inputs.interface_name,
        addrs,
        route_side,
    );
    let pollable_pump = ClawVpnPollablePump::new(session_core);
    let runtime =
        ClawVpnPollableRuntime::new(route_plan, pollable_pump, config.pollable_pump_budget());
    let route_executor = ClawVpnInterfaceRouteExecutor::new(inputs.route_tool_paths);

    Ok(Some(ClawVpnPollableRuntimeWiring {
        runtime,
        route_executor,
        interface: inputs.interface,
        relay: inputs.relay,
    }))
}

pub fn try_assemble_claw_vpn_runtime_wiring_deferred<I, R, E>(
    config: ClawVpnRuntimeWiringConfig,
    build_session_core: impl FnOnce() -> ClawVpnAgentSessionCore,
    build_inputs: impl FnOnce(
        ClawVpnRuntimeWiringContext,
    ) -> Result<ClawVpnRuntimeWiringInputs<I, R>, E>,
) -> Result<Option<ClawVpnRuntimeWiring<I, R>>, ClawVpnRuntimeWiringBuildError<E>>
where
    I: ClawVpnPacketInterface,
    R: ClawVpnPacketRelay,
{
    if !config.enabled() {
        return Ok(None);
    }

    let session_core = build_session_core();
    let route_side = route_side_for_datapath(session_core.local_side());
    let addrs = session_core
        .addrs()
        .map_err(ClawVpnRuntimeWiringBuildError::Session)?;
    let inputs = build_inputs(ClawVpnRuntimeWiringContext { route_side, addrs })
        .map_err(ClawVpnRuntimeWiringBuildError::Inputs)?;
    let route_plan = crate::claw_vpn_interface_route_plan::ClawVpnInterfaceRoutePlan::new(
        inputs.route_platform,
        inputs.interface_name,
        addrs,
        route_side,
    );
    let packet_pump = ClawVpnPacketPump::new(session_core);
    let runtime = ClawVpnRuntime::new(route_plan, packet_pump, config.runtime_step_budget());
    let route_executor = ClawVpnInterfaceRouteExecutor::new(inputs.route_tool_paths);
    let driver = ClawVpnPacketPumpProductionDriver::new(config.driver_budget());

    Ok(Some(ClawVpnRuntimeWiring {
        runtime,
        route_executor,
        interface: inputs.interface,
        relay: inputs.relay,
        driver,
    }))
}

/// Deferred (lazy session-core) assembly of the non-blocking pollable datapath —
/// the pollable-pump variant of [`try_assemble_claw_vpn_runtime_wiring_deferred`].
pub fn try_assemble_claw_vpn_pollable_runtime_wiring_deferred<I, R, E>(
    config: ClawVpnRuntimeWiringConfig,
    build_session_core: impl FnOnce() -> ClawVpnAgentSessionCore,
    build_inputs: impl FnOnce(
        ClawVpnRuntimeWiringContext,
    ) -> Result<ClawVpnRuntimeWiringInputs<I, R>, E>,
) -> Result<Option<ClawVpnPollableRuntimeWiring<I, R>>, ClawVpnRuntimeWiringBuildError<E>>
where
    I: ClawVpnPollablePacketInterface,
    R: ClawVpnPollablePacketRelay,
{
    if !config.enabled() {
        return Ok(None);
    }

    let session_core = build_session_core();
    let route_side = route_side_for_datapath(session_core.local_side());
    let addrs = session_core
        .addrs()
        .map_err(ClawVpnRuntimeWiringBuildError::Session)?;
    let inputs = build_inputs(ClawVpnRuntimeWiringContext { route_side, addrs })
        .map_err(ClawVpnRuntimeWiringBuildError::Inputs)?;
    let route_plan = crate::claw_vpn_interface_route_plan::ClawVpnInterfaceRoutePlan::new(
        inputs.route_platform,
        inputs.interface_name,
        addrs,
        route_side,
    );
    let pollable_pump = ClawVpnPollablePump::new(session_core);
    let runtime =
        ClawVpnPollableRuntime::new(route_plan, pollable_pump, config.pollable_pump_budget());
    let route_executor = ClawVpnInterfaceRouteExecutor::new(inputs.route_tool_paths);

    Ok(Some(ClawVpnPollableRuntimeWiring {
        runtime,
        route_executor,
        interface: inputs.interface,
        relay: inputs.relay,
    }))
}

pub fn assemble_claw_vpn_runtime_wiring_deferred<I, R>(
    config: ClawVpnRuntimeWiringConfig,
    build_session_core: impl FnOnce() -> ClawVpnAgentSessionCore,
    build_inputs: impl FnOnce(ClawVpnRuntimeWiringContext) -> ClawVpnRuntimeWiringInputs<I, R>,
) -> Result<Option<ClawVpnRuntimeWiring<I, R>>, ClawVpnRuntimeWiringError>
where
    I: ClawVpnPacketInterface,
    R: ClawVpnPacketRelay,
{
    if !config.enabled() {
        return Ok(None);
    }

    assemble_claw_vpn_runtime_wiring(config, build_session_core(), build_inputs)
}

fn route_side_for_datapath(side: ClawVpnDatapathSide) -> ClawVpnInterfaceRouteSide {
    match side {
        ClawVpnDatapathSide::Device => ClawVpnInterfaceRouteSide::Device,
        ClawVpnDatapathSide::Claw => ClawVpnInterfaceRouteSide::Claw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::rc::Rc;

    use household_rs::claw_share_data_tunnel::TunnelFrame;
    use household_rs::claw_vpn::{
        ClawVpnAcl, ClawVpnAclKey, ClawVpnAgentCore, ClawVpnAuditReason, ClawVpnIpv4Pool,
        ClawVpnSession, ClawVpnSessionRegistry,
    };
    use household_rs::keys::{IdentityKey, P256Keypair};

    use crate::claw_vpn_packet_pump::ClawVpnPacketPumpLoopStopReason;

    #[derive(Default)]
    struct FakeInterface {
        reads: VecDeque<Vec<u8>>,
        writes: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl FakeInterface {
        fn with_read_and_writes(packet: Vec<u8>, writes: Rc<RefCell<Vec<Vec<u8>>>>) -> Self {
            let mut reads = VecDeque::new();
            reads.push_back(packet);
            Self { reads, writes }
        }
    }

    impl ClawVpnPacketInterface for FakeInterface {
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let packet = self.reads.pop_front().unwrap_or_default();
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        }

        fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            self.writes.borrow_mut().push(packet.to_vec());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeRelay {
        recv_frames: VecDeque<TunnelFrame>,
        sent_frames: Rc<RefCell<Vec<TunnelFrame>>>,
    }

    impl FakeRelay {
        fn with_sent_frames(sent_frames: Rc<RefCell<Vec<TunnelFrame>>>) -> Self {
            Self {
                recv_frames: VecDeque::new(),
                sent_frames,
            }
        }
    }

    impl ClawVpnPacketRelay for FakeRelay {
        fn recv_frame(&mut self) -> io::Result<TunnelFrame> {
            self.recv_frames
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "fake relay eof"))
        }

        fn send_frame(&mut self, frame: TunnelFrame) -> io::Result<()> {
            self.sent_frames.borrow_mut().push(frame);
            Ok(())
        }
    }

    #[test]
    fn runtime_wiring_default_off_does_not_build_inputs() {
        let called = Rc::new(Cell::new(false));
        let called_by_factory = Rc::clone(&called);
        let (session, core) = session_and_core(ClawVpnDatapathSide::Device);
        let session_core = core.into_session_core(session.id()).unwrap();

        let wiring = assemble_claw_vpn_runtime_wiring::<FakeInterface, FakeRelay>(
            ClawVpnRuntimeWiringConfig::default(),
            session_core,
            |_| {
                called_by_factory.set(true);
                panic!("disabled wiring must not build live handles");
            },
        )
        .unwrap();

        assert!(wiring.is_none());
        assert!(!called.get());
    }

    #[test]
    fn runtime_wiring_deferred_default_off_does_not_build_session_or_inputs() {
        let session_called = Rc::new(Cell::new(false));
        let session_called_by_factory = Rc::clone(&session_called);
        let inputs_called = Rc::new(Cell::new(false));
        let inputs_called_by_factory = Rc::clone(&inputs_called);

        let wiring = assemble_claw_vpn_runtime_wiring_deferred::<FakeInterface, FakeRelay>(
            ClawVpnRuntimeWiringConfig::default(),
            || {
                session_called_by_factory.set(true);
                panic!("disabled deferred wiring must not build a session core");
            },
            |_| {
                inputs_called_by_factory.set(true);
                panic!("disabled deferred wiring must not build live handles");
            },
        )
        .unwrap();

        assert!(wiring.is_none());
        assert!(!session_called.get());
        assert!(!inputs_called.get());
    }

    #[test]
    fn runtime_wiring_deferred_enabled_builds_session_then_inputs() {
        let (session, core) = session_and_core(ClawVpnDatapathSide::Device);
        let addrs = session.addrs();
        let config = enabled_config(1);
        let session_built = Rc::new(Cell::new(false));
        let session_built_by_factory = Rc::clone(&session_built);
        let inputs_built = Rc::new(Cell::new(false));
        let inputs_built_by_factory = Rc::clone(&inputs_built);

        let wiring = assemble_claw_vpn_runtime_wiring_deferred(
            config,
            || {
                session_built_by_factory.set(true);
                core.into_session_core(session.id()).unwrap()
            },
            |context| {
                assert!(session_built.get());
                inputs_built_by_factory.set(true);
                assert_eq!(context.addrs(), addrs);
                inputs(FakeInterface::default(), FakeRelay::default())
            },
        )
        .unwrap();

        assert!(wiring.is_some());
        assert!(session_built.get());
        assert!(inputs_built.get());
    }

    #[test]
    fn runtime_wiring_rejects_session_not_active_in_core() {
        let (session, mut core) = session_and_core(ClawVpnDatapathSide::Device);
        assert!(core.close_with_audit(session.id()).0.is_some());
        let closed_session_core = core.into_session_core(session.id()).err();
        assert!(matches!(
            closed_session_core,
            Some(ClawVpnSessionFrameError::UnknownSession)
        ));
        let (session, core) = session_and_core(ClawVpnDatapathSide::Device);
        let mut session_core = core.into_session_core(session.id()).unwrap();
        assert!(session_core.close_with_audit().0.is_some());
        let config = enabled_config(1);
        let called = Rc::new(Cell::new(false));
        let called_by_factory = Rc::clone(&called);

        let error = assemble_claw_vpn_runtime_wiring(config, session_core, |_| {
            called_by_factory.set(true);
            inputs(FakeInterface::default(), FakeRelay::default())
        })
        .unwrap_err();

        assert!(!called.get());
        assert!(matches!(error, ClawVpnRuntimeWiringError::Session(_)));
        let debug = format!("{error:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
    }

    #[test]
    fn runtime_wiring_runs_bounded_pump_and_cleans_up_routes() {
        let (session, core) = session_and_core(ClawVpnDatapathSide::Device);
        let addrs = session.addrs();
        let packet = packet(addrs.device(), addrs.claw());
        let config = enabled_config(1);
        let interface_writes = Rc::new(RefCell::new(Vec::new()));
        let relay_sent_frames = Rc::new(RefCell::new(Vec::new()));

        let mut wiring = assemble_claw_vpn_runtime_wiring(
            config,
            core.into_session_core(session.id()).unwrap(),
            |context| {
                assert_eq!(context.addrs(), addrs);
                assert_eq!(context.route_side(), ClawVpnInterfaceRouteSide::Device);
                inputs(
                    FakeInterface::with_read_and_writes(
                        packet.clone(),
                        Rc::clone(&interface_writes),
                    ),
                    FakeRelay::with_sent_frames(Rc::clone(&relay_sent_frames)),
                )
            },
        )
        .unwrap()
        .unwrap();

        let report = wiring.run_until_stopped().unwrap();

        assert!(matches!(
            report.pump_report().stop_reason(),
            ClawVpnPacketPumpLoopStopReason::StepBudgetExhausted
        ));
        assert_eq!(
            report.pump_report().stats().interface_to_relay_forwarded(),
            1
        );
        let relay_sent_frames = relay_sent_frames.borrow();
        assert_eq!(relay_sent_frames.len(), 1);
        assert!(matches!(
            &relay_sent_frames[0],
            TunnelFrame::Data(payload) if payload == &packet
        ));
        assert!(interface_writes.borrow().is_empty());
    }

    #[test]
    fn runtime_wiring_claw_side_context_uses_claw_route_side() {
        let (session, core) = session_and_core(ClawVpnDatapathSide::Claw);
        let addrs = session.addrs();
        let config = enabled_config(1);

        let wiring = assemble_claw_vpn_runtime_wiring(
            config,
            core.into_session_core(session.id()).unwrap(),
            |context| {
                assert_eq!(context.addrs(), addrs);
                assert_eq!(context.route_side(), ClawVpnInterfaceRouteSide::Claw);
                inputs(FakeInterface::default(), FakeRelay::default())
            },
        )
        .unwrap();

        assert!(wiring.is_some());
    }

    #[test]
    fn runtime_wiring_debug_redacts_live_material() {
        let (session, core) = session_and_core(ClawVpnDatapathSide::Device);
        let config = enabled_config(1);

        let wiring = assemble_claw_vpn_runtime_wiring(
            config,
            core.into_session_core(session.id()).unwrap(),
            |_| inputs(FakeInterface::default(), FakeRelay::default()),
        )
        .unwrap()
        .unwrap();

        let debug = format!("{wiring:?}");
        assert!(debug.contains("ClawVpnRuntimeWiring"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("clawvpn0"));
        assert!(!debug.contains("/usr/bin/true"));
        assert!(!debug.contains("198.18.0."));
        assert!(!debug.contains("member-m1"));
        assert!(!debug.contains("claw-a"));
    }

    fn enabled_config(max_steps: usize) -> ClawVpnRuntimeWiringConfig {
        ClawVpnRuntimeWiringConfig::new(
            true,
            ClawVpnRuntimeStepBudget::new(max_steps).unwrap(),
            ClawVpnPacketPumpProductionDriverBudget::new(
                max_steps,
                std::time::Duration::from_secs(60),
                max_steps,
                std::time::Duration::from_secs(1),
            )
            .unwrap(),
        )
    }

    fn inputs(
        interface: FakeInterface,
        relay: FakeRelay,
    ) -> ClawVpnRuntimeWiringInputs<FakeInterface, FakeRelay> {
        ClawVpnRuntimeWiringInputs {
            route_platform: host_platform(),
            interface_name: ClawVpnInterfaceName::new("clawvpn0").unwrap(),
            route_tool_paths: true_tool_paths(),
            interface,
            relay,
        }
    }

    fn host_platform() -> ClawVpnInterfaceRoutePlatform {
        #[cfg(target_os = "linux")]
        {
            ClawVpnInterfaceRoutePlatform::Linux
        }
        #[cfg(target_os = "macos")]
        {
            ClawVpnInterfaceRoutePlatform::Macos
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            panic!("test only supports Linux/macOS route platforms")
        }
    }

    fn true_tool_paths() -> ClawVpnInterfaceRouteToolPaths {
        let path = PathBuf::from("/usr/bin/true");
        ClawVpnInterfaceRouteToolPaths::try_new(&path, &path, &path).unwrap()
    }

    fn session_and_core(side: ClawVpnDatapathSide) -> (ClawVpnSession, ClawVpnAgentCore) {
        let key = acl_key();
        let mut acl = ClawVpnAcl::new();
        assert!(acl.grant(key.clone()));
        let pool = ClawVpnIpv4Pool::try_new(Ipv4Addr::new(198, 18, 0, 0), 24).unwrap();
        let registry = ClawVpnSessionRegistry::new(acl, pool);
        let mut core = ClawVpnAgentCore::new(side, registry);
        let (session, open_event) = core.open_with_audit(&key);
        assert_eq!(open_event.reason(), ClawVpnAuditReason::SessionOpened);
        (session.unwrap(), core)
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
}
