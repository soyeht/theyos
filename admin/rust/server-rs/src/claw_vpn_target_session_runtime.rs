//! Inert assembly bridge from a relay-stream `TargetSession` to VPN runtime wiring.
//!
//! This module does not mount `IpTunnel`, open TUN/utun devices, install routes,
//! spawn work, or choose a runtime execution context. It only builds the local
//! target-session socketpair after the fixed VPN session is active, then returns
//! both halves so a future owner-reviewed caller can decide where to run the
//! synchronous packet-pump runtime.

use std::fmt;
use std::io;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::time::Duration;

use household_rs::claw_share_data_tunnel::TargetSession;
use household_rs::claw_vpn::{ClawVpnAgentSessionCore, ClawVpnSessionFrameError};

use crate::claw_vpn_packet_pump::ClawVpnPacketInterface;
use crate::claw_vpn_pollable_pump::ClawVpnPollablePacketInterface;
use crate::claw_vpn_relay_stream::ClawVpnRelayStream;
use crate::claw_vpn_target_session_relay::{
    ClawVpnPollableTargetSessionRelay, ClawVpnTargetSessionRelayPair,
};
use crate::claw_vpn_wiring::{
    ClawVpnPollableRuntimeWiring, ClawVpnRuntimeWiring, ClawVpnRuntimeWiringBuildError,
    ClawVpnRuntimeWiringConfig, ClawVpnRuntimeWiringContext, ClawVpnRuntimeWiringInputs,
    try_assemble_claw_vpn_pollable_runtime_wiring_deferred,
    try_assemble_claw_vpn_runtime_wiring_deferred,
};

pub struct ClawVpnTargetSessionRuntime<I> {
    target_session: TargetSession,
    wiring: ClawVpnRuntimeWiring<I, ClawVpnRelayStream<StdUnixStream>>,
}

impl<I> fmt::Debug for ClawVpnTargetSessionRuntime<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnTargetSessionRuntime")
            .field("target_session", &"<redacted>")
            .field("wiring", &self.wiring)
            .finish()
    }
}

impl<I> ClawVpnTargetSessionRuntime<I> {
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        TargetSession,
        ClawVpnRuntimeWiring<I, ClawVpnRelayStream<StdUnixStream>>,
    ) {
        (self.target_session, self.wiring)
    }
}

pub enum ClawVpnTargetSessionRuntimeError<E> {
    Session(ClawVpnSessionFrameError),
    TargetSessionRelay(io::Error),
    Inputs(E),
}

impl<E> fmt::Debug for ClawVpnTargetSessionRuntimeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(_) => f
                .debug_struct("ClawVpnTargetSessionRuntimeError::Session")
                .field("source", &"<redacted>")
                .finish(),
            Self::TargetSessionRelay(_) => f
                .debug_struct("ClawVpnTargetSessionRuntimeError::TargetSessionRelay")
                .field("source", &"<redacted>")
                .finish(),
            Self::Inputs(_) => f
                .debug_struct("ClawVpnTargetSessionRuntimeError::Inputs")
                .field("source", &"<redacted>")
                .finish(),
        }
    }
}

enum TargetSessionRuntimeInputError<E> {
    TargetSessionRelay(io::Error),
    Inputs(E),
}

pub fn assemble_claw_vpn_target_session_runtime<I, E>(
    config: ClawVpnRuntimeWiringConfig,
    io_timeout: Duration,
    build_session_core: impl FnOnce() -> ClawVpnAgentSessionCore,
    build_inputs: impl FnOnce(
        ClawVpnRuntimeWiringContext,
        ClawVpnRelayStream<StdUnixStream>,
    ) -> Result<
        ClawVpnRuntimeWiringInputs<I, ClawVpnRelayStream<StdUnixStream>>,
        E,
    >,
) -> Result<Option<ClawVpnTargetSessionRuntime<I>>, ClawVpnTargetSessionRuntimeError<E>>
where
    I: ClawVpnPacketInterface,
{
    if !config.enabled() {
        return Ok(None);
    }

    let mut target_session = None;
    let wiring =
        match try_assemble_claw_vpn_runtime_wiring_deferred(config, build_session_core, |context| {
            let pair = ClawVpnTargetSessionRelayPair::new(io_timeout)
                .map_err(TargetSessionRuntimeInputError::TargetSessionRelay)?;
            let (session, relay) = pair.into_parts();
            target_session = Some(session);
            build_inputs(context, relay).map_err(TargetSessionRuntimeInputError::Inputs)
        }) {
            Ok(None) => return Ok(None),
            Ok(Some(wiring)) => wiring,
            Err(ClawVpnRuntimeWiringBuildError::Session(error)) => {
                return Err(ClawVpnTargetSessionRuntimeError::Session(error));
            }
            Err(ClawVpnRuntimeWiringBuildError::Inputs(
                TargetSessionRuntimeInputError::TargetSessionRelay(error),
            )) => return Err(ClawVpnTargetSessionRuntimeError::TargetSessionRelay(error)),
            Err(ClawVpnRuntimeWiringBuildError::Inputs(
                TargetSessionRuntimeInputError::Inputs(error),
            )) => return Err(ClawVpnTargetSessionRuntimeError::Inputs(error)),
        };

    let Some(target_session) = target_session else {
        return Err(ClawVpnTargetSessionRuntimeError::TargetSessionRelay(
            io::Error::other("target session relay was not built"),
        ));
    };
    Ok(Some(ClawVpnTargetSessionRuntime {
        target_session,
        wiring,
    }))
}

/// Non-blocking pollable variant of [`ClawVpnTargetSessionRuntime`]. Holds the
/// pollable wiring over an `O_NONBLOCK` relay side; the interface is expected to
/// have been set non-blocking by its builder.
pub struct ClawVpnPollableTargetSessionRuntime<I> {
    target_session: TargetSession,
    wiring: ClawVpnPollableRuntimeWiring<I, ClawVpnPollableTargetSessionRelay>,
}

impl<I> fmt::Debug for ClawVpnPollableTargetSessionRuntime<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPollableTargetSessionRuntime")
            .field("target_session", &"<redacted>")
            .field("wiring", &self.wiring)
            .finish()
    }
}

impl<I> ClawVpnPollableTargetSessionRuntime<I> {
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        TargetSession,
        ClawVpnPollableRuntimeWiring<I, ClawVpnPollableTargetSessionRelay>,
    ) {
        (self.target_session, self.wiring)
    }
}

/// Assemble the non-blocking pollable datapath bridge: creates the `O_NONBLOCK`
/// target-session socketpair via [`ClawVpnTargetSessionRelayPair::new_pollable`]
/// and hands the relay side to `build_inputs`. Mirrors
/// [`assemble_claw_vpn_target_session_runtime`] for the pollable pump.
pub fn assemble_claw_vpn_pollable_target_session_runtime<I, E>(
    config: ClawVpnRuntimeWiringConfig,
    build_session_core: impl FnOnce() -> ClawVpnAgentSessionCore,
    build_inputs: impl FnOnce(
        ClawVpnRuntimeWiringContext,
        ClawVpnPollableTargetSessionRelay,
    ) -> Result<
        ClawVpnRuntimeWiringInputs<I, ClawVpnPollableTargetSessionRelay>,
        E,
    >,
) -> Result<Option<ClawVpnPollableTargetSessionRuntime<I>>, ClawVpnTargetSessionRuntimeError<E>>
where
    I: ClawVpnPollablePacketInterface,
{
    if !config.enabled() {
        return Ok(None);
    }

    let mut target_session = None;
    let wiring = match try_assemble_claw_vpn_pollable_runtime_wiring_deferred(
        config,
        build_session_core,
        |context| {
            let (session, relay) = ClawVpnTargetSessionRelayPair::new_pollable()
                .map_err(TargetSessionRuntimeInputError::TargetSessionRelay)?;
            target_session = Some(session);
            build_inputs(context, relay).map_err(TargetSessionRuntimeInputError::Inputs)
        },
    ) {
        Ok(None) => return Ok(None),
        Ok(Some(wiring)) => wiring,
        Err(ClawVpnRuntimeWiringBuildError::Session(error)) => {
            return Err(ClawVpnTargetSessionRuntimeError::Session(error));
        }
        Err(ClawVpnRuntimeWiringBuildError::Inputs(
            TargetSessionRuntimeInputError::TargetSessionRelay(error),
        )) => return Err(ClawVpnTargetSessionRuntimeError::TargetSessionRelay(error)),
        Err(ClawVpnRuntimeWiringBuildError::Inputs(TargetSessionRuntimeInputError::Inputs(
            error,
        ))) => return Err(ClawVpnTargetSessionRuntimeError::Inputs(error)),
    };

    let Some(target_session) = target_session else {
        return Err(ClawVpnTargetSessionRuntimeError::TargetSessionRelay(
            io::Error::other("target session relay was not built"),
        ));
    };
    Ok(Some(ClawVpnPollableTargetSessionRuntime {
        target_session,
        wiring,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use household_rs::claw_share_data_tunnel::TunnelFrame;
    use household_rs::claw_vpn::{
        ClawVpnAcl, ClawVpnAclKey, ClawVpnAgentCore, ClawVpnAuditReason, ClawVpnDatapathSide,
        ClawVpnIpv4Pool, ClawVpnSession, ClawVpnSessionRegistry,
    };
    use household_rs::keys::{IdentityKey, P256Keypair};
    use tokio::io::AsyncReadExt;

    use crate::claw_vpn_interface_route_plan::{
        ClawVpnInterfaceName, ClawVpnInterfaceRoutePlatform, ClawVpnInterfaceRouteToolPaths,
    };
    use crate::claw_vpn_packet_pump::{
        ClawVpnPacketPumpLoopStopReason, ClawVpnPacketPumpProductionDriverBudget,
    };
    use crate::claw_vpn_runtime::ClawVpnRuntimeStepBudget;

    #[derive(Default)]
    struct FakeInterface {
        reads: VecDeque<Vec<u8>>,
    }

    impl FakeInterface {
        fn with_read(packet: Vec<u8>) -> Self {
            let mut reads = VecDeque::new();
            reads.push_back(packet);
            Self { reads }
        }
    }

    impl ClawVpnPacketInterface for FakeInterface {
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let packet = self.reads.pop_front().unwrap_or_default();
            let len = packet.len().min(buf.len());
            buf[..len].copy_from_slice(&packet[..len]);
            Ok(len)
        }

        fn write_packet(&mut self, _packet: &[u8]) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn target_session_runtime_default_off_builds_nothing() {
        let session_called = Cell::new(false);
        let inputs_called = Cell::new(false);

        let runtime = assemble_claw_vpn_target_session_runtime::<FakeInterface, io::Error>(
            ClawVpnRuntimeWiringConfig::default(),
            Duration::from_secs(1),
            || {
                session_called.set(true);
                panic!("disabled target-session runtime must not build session core");
            },
            |_, _| {
                inputs_called.set(true);
                panic!("disabled target-session runtime must not build inputs");
            },
        )
        .unwrap();

        assert!(runtime.is_none());
        assert!(!session_called.get());
        assert!(!inputs_called.get());
    }

    #[tokio::test]
    async fn target_session_runtime_threads_pump_output_to_target_session() {
        let (session, core) = session_and_core(ClawVpnDatapathSide::Device);
        let addrs = session.addrs();
        let packet = packet(addrs.device(), addrs.claw());
        let runtime = assemble_claw_vpn_target_session_runtime(
            enabled_config(1),
            Duration::from_secs(1),
            || core.into_session_core(session.id()).unwrap(),
            |context, relay| {
                assert_eq!(context.addrs(), addrs);
                Ok::<_, io::Error>(inputs(FakeInterface::with_read(packet.clone()), relay))
            },
        )
        .unwrap()
        .unwrap();
        let (mut target_session, mut wiring) = runtime.into_parts();

        let report = wiring.run_until_stopped().unwrap();

        assert!(matches!(
            report.pump_report().stop_reason(),
            ClawVpnPacketPumpLoopStopReason::StepBudgetExhausted
        ));
        assert_eq!(
            report.pump_report().stats().interface_to_relay_forwarded(),
            1
        );
        let mut len_buf = [0u8; 4];
        target_session
            .reader
            .read_exact(&mut len_buf)
            .await
            .expect("read relay frame length");
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0; len];
        target_session
            .reader
            .read_exact(&mut payload)
            .await
            .expect("read relay frame payload");
        assert_eq!(
            TunnelFrame::decode(&payload).expect("decode relay payload"),
            TunnelFrame::Data(packet)
        );
    }

    #[test]
    fn target_session_runtime_rejects_zero_timeout_before_inputs() {
        let (session, core) = session_and_core(ClawVpnDatapathSide::Device);
        let inputs_called = Cell::new(false);

        let error = assemble_claw_vpn_target_session_runtime::<FakeInterface, &'static str>(
            enabled_config(1),
            Duration::ZERO,
            || core.into_session_core(session.id()).unwrap(),
            |_, _| {
                inputs_called.set(true);
                Err("inputs should not run")
            },
        )
        .unwrap_err();

        assert!(!inputs_called.get());
        assert!(matches!(
            error,
            ClawVpnTargetSessionRuntimeError::TargetSessionRelay(_)
        ));
        let debug = format!("{error:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("UnixStream"));
    }

    #[tokio::test]
    async fn target_session_runtime_input_error_debug_is_redacted() {
        let (session, core) = session_and_core(ClawVpnDatapathSide::Device);

        let error = assemble_claw_vpn_target_session_runtime::<FakeInterface, &'static str>(
            enabled_config(1),
            Duration::from_secs(1),
            || core.into_session_core(session.id()).unwrap(),
            |_, _| Err("SECRET-INPUT-MATERIAL"),
        )
        .unwrap_err();

        let debug = format!("{error:?}");
        assert!(debug.contains("ClawVpnTargetSessionRuntimeError::Inputs"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("SECRET-INPUT-MATERIAL"));
    }

    fn enabled_config(max_steps: usize) -> ClawVpnRuntimeWiringConfig {
        ClawVpnRuntimeWiringConfig::new(
            true,
            ClawVpnRuntimeStepBudget::new(max_steps).unwrap(),
            ClawVpnPacketPumpProductionDriverBudget::new(
                max_steps,
                Duration::from_secs(60),
                max_steps,
                Duration::from_secs(1),
            )
            .unwrap(),
        )
    }

    fn inputs(
        interface: FakeInterface,
        relay: ClawVpnRelayStream<StdUnixStream>,
    ) -> ClawVpnRuntimeWiringInputs<FakeInterface, ClawVpnRelayStream<StdUnixStream>> {
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
