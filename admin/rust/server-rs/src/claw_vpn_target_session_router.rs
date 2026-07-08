//! Unwired `IpTunnel` target backend for the per-Claw VPN target-session runtime.
//!
//! This adapter is deliberately not mounted by startup or the relay-stream
//! runtime. It only converts a caller-supplied target-session runtime builder
//! plus a caller-supplied synchronous-runtime launcher into a `ClawTargetRouter`
//! implementation. The future live caller still owns concrete device selection,
//! route-tool paths, execution context, and the reviewed mount swap.

use std::fmt;
use std::marker::PhantomData;
use std::os::unix::net::UnixStream as StdUnixStream;

use household_rs::claw_share_data_tunnel::{ClawTargetRouter, DataTunnelError, TargetSession};

use crate::claw_vpn_packet_pump::ClawVpnPacketInterface;
use crate::claw_vpn_pollable_pump::ClawVpnPollablePacketInterface;
use crate::claw_vpn_relay_stream::ClawVpnRelayStream;
use crate::claw_vpn_target_session_relay::ClawVpnPollableTargetSessionRelay;
use crate::claw_vpn_target_session_runtime::{
    ClawVpnPollableTargetSessionRuntime, ClawVpnTargetSessionRuntime,
};
use crate::claw_vpn_wiring::{ClawVpnPollableRuntimeWiring, ClawVpnRuntimeWiring};

pub type ClawVpnTargetSessionRouterBuildResult<I> =
    Result<Option<ClawVpnTargetSessionRuntime<I>>, ClawVpnTargetSessionRouterBuildError>;

pub type ClawVpnTargetSessionRouterLaunchResult = Result<(), ClawVpnTargetSessionRouterLaunchError>;

pub type ClawVpnTargetSessionRouterWiring<I> =
    ClawVpnRuntimeWiring<I, ClawVpnRelayStream<StdUnixStream>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnTargetSessionRouterBuildError {
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClawVpnTargetSessionRouterLaunchError {
    Failed,
}

pub struct ClawVpnTargetSessionRouter<I, BuildRuntime, LaunchRuntime> {
    build_runtime: BuildRuntime,
    launch_runtime: LaunchRuntime,
    _interface: PhantomData<fn() -> I>,
}

impl<I, BuildRuntime, LaunchRuntime> ClawVpnTargetSessionRouter<I, BuildRuntime, LaunchRuntime> {
    #[must_use]
    pub fn new(build_runtime: BuildRuntime, launch_runtime: LaunchRuntime) -> Self {
        Self {
            build_runtime,
            launch_runtime,
            _interface: PhantomData,
        }
    }
}

impl<I, BuildRuntime, LaunchRuntime> fmt::Debug
    for ClawVpnTargetSessionRouter<I, BuildRuntime, LaunchRuntime>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnTargetSessionRouter")
            .field("build_runtime", &"<redacted>")
            .field("launch_runtime", &"<redacted>")
            .finish()
    }
}

impl<I, BuildRuntime, LaunchRuntime> ClawTargetRouter
    for ClawVpnTargetSessionRouter<I, BuildRuntime, LaunchRuntime>
where
    I: ClawVpnPacketInterface + Send + 'static,
    BuildRuntime: Fn(&str) -> ClawVpnTargetSessionRouterBuildResult<I> + Send + Sync,
    LaunchRuntime: Fn(ClawVpnTargetSessionRouterWiring<I>) -> ClawVpnTargetSessionRouterLaunchResult
        + Send
        + Sync,
{
    async fn open(&self, target_id: &str) -> Result<TargetSession, DataTunnelError> {
        let Some(runtime) = (self.build_runtime)(target_id)
            .map_err(|_| target_unavailable("claw-vpn-target-session-runtime-unavailable"))?
        else {
            return Err(target_unavailable(
                "claw-vpn-target-session-runtime-disabled",
            ));
        };
        let (target_session, wiring) = runtime.into_parts();
        (self.launch_runtime)(wiring)
            .map_err(|_| target_unavailable("claw-vpn-target-session-runtime-launch-failed"))?;
        Ok(target_session)
    }
}

pub type ClawVpnPollableTargetSessionRouterBuildResult<I> =
    Result<Option<ClawVpnPollableTargetSessionRuntime<I>>, ClawVpnTargetSessionRouterBuildError>;

pub type ClawVpnPollableTargetSessionRouterWiring<I> =
    ClawVpnPollableRuntimeWiring<I, ClawVpnPollableTargetSessionRelay>;

/// Pollable (non-blocking) variant of [`ClawVpnTargetSessionRouter`]: builds a
/// [`ClawVpnPollableTargetSessionRuntime`] and launches the pollable wiring so
/// the Claw responder runs the readiness-driven pump instead of the blocking
/// strict-alternating one.
pub struct ClawVpnPollableTargetSessionRouter<I, BuildRuntime, LaunchRuntime> {
    build_runtime: BuildRuntime,
    launch_runtime: LaunchRuntime,
    _interface: PhantomData<fn() -> I>,
}

impl<I, BuildRuntime, LaunchRuntime>
    ClawVpnPollableTargetSessionRouter<I, BuildRuntime, LaunchRuntime>
{
    #[must_use]
    pub fn new(build_runtime: BuildRuntime, launch_runtime: LaunchRuntime) -> Self {
        Self {
            build_runtime,
            launch_runtime,
            _interface: PhantomData,
        }
    }
}

impl<I, BuildRuntime, LaunchRuntime> fmt::Debug
    for ClawVpnPollableTargetSessionRouter<I, BuildRuntime, LaunchRuntime>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnPollableTargetSessionRouter")
            .field("build_runtime", &"<redacted>")
            .field("launch_runtime", &"<redacted>")
            .finish()
    }
}

impl<I, BuildRuntime, LaunchRuntime> ClawTargetRouter
    for ClawVpnPollableTargetSessionRouter<I, BuildRuntime, LaunchRuntime>
where
    I: ClawVpnPollablePacketInterface + Send + 'static,
    BuildRuntime: Fn(&str) -> ClawVpnPollableTargetSessionRouterBuildResult<I> + Send + Sync,
    LaunchRuntime: Fn(ClawVpnPollableTargetSessionRouterWiring<I>) -> ClawVpnTargetSessionRouterLaunchResult
        + Send
        + Sync,
{
    async fn open(&self, target_id: &str) -> Result<TargetSession, DataTunnelError> {
        let Some(runtime) = (self.build_runtime)(target_id).map_err(|_| {
            target_unavailable("claw-vpn-pollable-target-session-runtime-unavailable")
        })?
        else {
            return Err(target_unavailable(
                "claw-vpn-pollable-target-session-runtime-disabled",
            ));
        };
        let (target_session, wiring) = runtime.into_parts();
        (self.launch_runtime)(wiring).map_err(|_| {
            target_unavailable("claw-vpn-pollable-target-session-runtime-launch-failed")
        })?;
        Ok(target_session)
    }
}

fn target_unavailable(reason: &'static str) -> DataTunnelError {
    DataTunnelError::TargetUnavailable(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::io;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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
    use crate::claw_vpn_target_session_runtime::assemble_claw_vpn_target_session_runtime;
    use crate::claw_vpn_wiring::{ClawVpnRuntimeWiringConfig, ClawVpnRuntimeWiringInputs};

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

    #[tokio::test]
    async fn target_session_router_fails_closed_when_runtime_is_disabled() {
        let launch_count = Arc::new(AtomicUsize::new(0));
        let launch_count_for_router = Arc::clone(&launch_count);
        let router = ClawVpnTargetSessionRouter::<FakeInterface, _, _>::new(
            |_target_id: &str| -> ClawVpnTargetSessionRouterBuildResult<FakeInterface> { Ok(None) },
            move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                launch_count_for_router.fetch_add(1, Ordering::SeqCst);
                Ok::<(), ClawVpnTargetSessionRouterLaunchError>(())
            },
        );

        let error = open_error(&router, "claw-a").await;

        assert!(matches!(
            error,
            DataTunnelError::TargetUnavailable(reason)
                if reason == "claw-vpn-target-session-runtime-disabled"
        ));
        assert_eq!(launch_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn target_session_router_launches_wiring_and_returns_target_session() {
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
        let runtime_slot = Arc::new(Mutex::new(Some(runtime)));
        let runtime_slot_for_router = Arc::clone(&runtime_slot);
        let launch_count = Arc::new(AtomicUsize::new(0));
        let launch_count_for_router = Arc::clone(&launch_count);
        let router = ClawVpnTargetSessionRouter::<FakeInterface, _, _>::new(
            move |target_id: &str| -> ClawVpnTargetSessionRouterBuildResult<FakeInterface> {
                assert_eq!(target_id, "claw-a");
                Ok(runtime_slot_for_router.lock().unwrap().take())
            },
            move |mut wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                let report = wiring.run_until_stopped().unwrap();
                assert!(matches!(
                    report.pump_report().stop_reason(),
                    ClawVpnPacketPumpLoopStopReason::StepBudgetExhausted
                ));
                assert_eq!(
                    report.pump_report().stats().interface_to_relay_forwarded(),
                    1
                );
                launch_count_for_router.fetch_add(1, Ordering::SeqCst);
                Ok::<(), ClawVpnTargetSessionRouterLaunchError>(())
            },
        );

        let mut target_session = router.open("claw-a").await.unwrap();

        assert_eq!(launch_count.load(Ordering::SeqCst), 1);
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

    #[tokio::test]
    async fn target_session_router_sanitizes_build_and_launch_failures() {
        let build_error_router = ClawVpnTargetSessionRouter::<FakeInterface, _, _>::new(
            |_target_id: &str| -> ClawVpnTargetSessionRouterBuildResult<FakeInterface> {
                Err(ClawVpnTargetSessionRouterBuildError::Unavailable)
            },
            |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                Ok::<(), ClawVpnTargetSessionRouterLaunchError>(())
            },
        );

        let build_error = open_error(&build_error_router, "SECRET-TARGET").await;
        assert!(matches!(
            build_error,
            DataTunnelError::TargetUnavailable(ref reason)
                if reason == "claw-vpn-target-session-runtime-unavailable"
        ));
        assert!(!build_error.to_string().contains("SECRET-TARGET"));

        let (session, core) = session_and_core(ClawVpnDatapathSide::Device);
        let runtime = assemble_claw_vpn_target_session_runtime(
            enabled_config(1),
            Duration::from_secs(1),
            || core.into_session_core(session.id()).unwrap(),
            |_, relay| Ok::<_, io::Error>(inputs(FakeInterface::default(), relay)),
        )
        .unwrap()
        .unwrap();
        let runtime_slot = Arc::new(Mutex::new(Some(runtime)));
        let runtime_slot_for_router = Arc::clone(&runtime_slot);
        let launch_error_router = ClawVpnTargetSessionRouter::<FakeInterface, _, _>::new(
            move |_target_id: &str| -> ClawVpnTargetSessionRouterBuildResult<FakeInterface> {
                Ok(runtime_slot_for_router.lock().unwrap().take())
            },
            |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                Err(ClawVpnTargetSessionRouterLaunchError::Failed)
            },
        );

        let launch_error = open_error(&launch_error_router, "SECRET-TARGET").await;
        assert!(matches!(
            launch_error,
            DataTunnelError::TargetUnavailable(ref reason)
                if reason == "claw-vpn-target-session-runtime-launch-failed"
        ));
        assert!(!launch_error.to_string().contains("SECRET-TARGET"));
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

    async fn open_error(router: &impl ClawTargetRouter, target_id: &str) -> DataTunnelError {
        match router.open(target_id).await {
            Ok(_) => panic!("target open should fail"),
            Err(error) => error,
        }
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
