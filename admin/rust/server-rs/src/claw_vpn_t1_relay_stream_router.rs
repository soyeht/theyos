//! Member-scoped T1 `IpTunnel` backend for the per-Claw VPN live caller.
//!
//! This is the first relay-stream shaped caller that consumes the authenticated
//! Group audience context from the `IpTunnel` offer gate. It still does not
//! mount itself into bootstrap. Construction is intended to stay behind the T1
//! caller gate; `open_ip_tunnel` derives the VPN ACL key from the authenticated
//! `(member, device, claw)` tuple, builds the target-session runtime with
//! caller-supplied lazy inputs, and hands the resulting wiring to a
//! caller-supplied launcher.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use household_rs::claw_share_data_tunnel::{DataTunnelError, TargetSession};
use household_rs::claw_vpn::{
    ClawVpnAcl, ClawVpnAclKey, ClawVpnAgentCore, ClawVpnAuditEvent, ClawVpnDatapathSide,
    ClawVpnSessionRegistry,
};

use crate::claw_share_relay_stream_target_router::{
    RelayStreamIpTunnelRouter, RelayStreamIpTunnelTarget,
};
use crate::claw_vpn_dev_config::{ClawVpnDevConfig, ClawVpnDevConfigError};
use crate::claw_vpn_packet_pump::ClawVpnPacketInterface;
use crate::claw_vpn_relay_stream::ClawVpnRelayStream;
use crate::claw_vpn_t1_caller::{ClawVpnT1CallerStatus, assemble_claw_vpn_t1_caller};
use crate::claw_vpn_target_session_router::{
    ClawVpnTargetSessionRouterLaunchResult, ClawVpnTargetSessionRouterWiring,
};
use crate::claw_vpn_target_session_runtime::{
    ClawVpnTargetSessionRuntimeError, assemble_claw_vpn_target_session_runtime,
};
use crate::claw_vpn_wiring::{
    ClawVpnRuntimeWiringConfig, ClawVpnRuntimeWiringContext, ClawVpnRuntimeWiringInputs,
};
use crate::startup_wiring::PerClawVpnT1PreflightEvidence;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub type ClawVpnT1RelayStreamWiringInputs<I> =
    ClawVpnRuntimeWiringInputs<I, ClawVpnRelayStream<StdUnixStream>>;
pub type ClawVpnT1RelayStreamBuildInputs<I> = Box<
    dyn Fn(
            &ClawVpnDevConfig,
            &RelayStreamIpTunnelTarget,
            ClawVpnRuntimeWiringContext,
            ClawVpnRelayStream<StdUnixStream>,
        ) -> io::Result<ClawVpnT1RelayStreamWiringInputs<I>>
        + Send
        + Sync,
>;
pub type ClawVpnT1RelayStreamLaunchRuntime<I> = Box<
    dyn Fn(ClawVpnTargetSessionRouterWiring<I>) -> ClawVpnTargetSessionRouterLaunchResult
        + Send
        + Sync,
>;
pub type ClawVpnT1RelayStreamAuditSink =
    Box<dyn Fn(ClawVpnAuditEvent) -> Result<(), &'static str> + Send + Sync>;
pub type ClawVpnT1RelayStreamBoxedRouter<I> = ClawVpnT1RelayStreamIpTunnelRouter<
    I,
    ClawVpnT1RelayStreamBuildInputs<I>,
    ClawVpnT1RelayStreamLaunchRuntime<I>,
>;

pub struct ClawVpnT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime> {
    runtime_config: ClawVpnRuntimeWiringConfig,
    io_timeout: Duration,
    build_inputs: BuildInputs,
    launch_runtime: LaunchRuntime,
    audit_sink: ClawVpnT1RelayStreamAuditSink,
    _interface: PhantomData<fn() -> I>,
}

impl<I, BuildInputs, LaunchRuntime> fmt::Debug
    for ClawVpnT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnT1RelayStreamRouterParts")
            .field("runtime_config", &self.runtime_config)
            .field("io_timeout", &self.io_timeout)
            .field("build_inputs", &"<redacted>")
            .field("launch_runtime", &"<redacted>")
            .field("audit_sink", &"<redacted>")
            .finish()
    }
}

impl<I, BuildInputs, LaunchRuntime> ClawVpnT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime> {
    #[must_use]
    pub fn new(
        runtime_config: ClawVpnRuntimeWiringConfig,
        io_timeout: Duration,
        build_inputs: BuildInputs,
        launch_runtime: LaunchRuntime,
        audit_sink: ClawVpnT1RelayStreamAuditSink,
    ) -> Self {
        Self {
            runtime_config,
            io_timeout,
            build_inputs,
            launch_runtime,
            audit_sink,
            _interface: PhantomData,
        }
    }
}

pub struct ClawVpnT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime> {
    config: ClawVpnDevConfig,
    runtime_config: ClawVpnRuntimeWiringConfig,
    io_timeout: Duration,
    build_inputs: BuildInputs,
    launch_runtime: LaunchRuntime,
    audit_sink: ClawVpnT1RelayStreamAuditSink,
    admission: Arc<Mutex<ClawVpnT1RelayStreamAdmission>>,
    _interface: PhantomData<fn() -> I>,
}

impl<I, BuildInputs, LaunchRuntime> fmt::Debug
    for ClawVpnT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClawVpnT1RelayStreamIpTunnelRouter")
            .field("config", &self.config)
            .field("runtime_config", &self.runtime_config)
            .field("io_timeout", &self.io_timeout)
            .field("build_inputs", &"<redacted>")
            .field("launch_runtime", &"<redacted>")
            .field("audit_sink", &"<redacted>")
            .field("admission", &"<redacted>")
            .finish()
    }
}

impl<I, BuildInputs, LaunchRuntime>
    ClawVpnT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>
{
    #[must_use]
    fn new(
        config: ClawVpnDevConfig,
        runtime_config: ClawVpnRuntimeWiringConfig,
        io_timeout: Duration,
        build_inputs: BuildInputs,
        launch_runtime: LaunchRuntime,
        audit_sink: ClawVpnT1RelayStreamAuditSink,
    ) -> Self {
        Self::with_admission(
            config,
            runtime_config,
            io_timeout,
            build_inputs,
            launch_runtime,
            audit_sink,
            Arc::new(Mutex::new(ClawVpnT1RelayStreamAdmission::default())),
        )
    }

    #[must_use]
    fn with_admission(
        config: ClawVpnDevConfig,
        runtime_config: ClawVpnRuntimeWiringConfig,
        io_timeout: Duration,
        build_inputs: BuildInputs,
        launch_runtime: LaunchRuntime,
        audit_sink: ClawVpnT1RelayStreamAuditSink,
        admission: Arc<Mutex<ClawVpnT1RelayStreamAdmission>>,
    ) -> Self {
        Self {
            config,
            runtime_config,
            io_timeout,
            build_inputs,
            launch_runtime,
            audit_sink,
            admission,
            _interface: PhantomData,
        }
    }
}

#[derive(Default)]
struct ClawVpnT1RelayStreamAdmission {
    active_by_key: HashMap<ClawVpnAclKey, usize>,
    active_by_claw: HashMap<String, usize>,
}

impl ClawVpnT1RelayStreamAdmission {
    fn reserve(
        &mut self,
        key: &ClawVpnAclKey,
        max_sessions_per_member_claw: usize,
        max_sessions_per_claw: usize,
    ) -> Result<(), &'static str> {
        if self.active_by_key.get(key).copied().unwrap_or(0) >= max_sessions_per_member_claw {
            return Err("claw-vpn-t1-session-member-claw-limit-reached");
        }
        if self.active_by_claw.get(key.claw_id()).copied().unwrap_or(0) >= max_sessions_per_claw {
            return Err("claw-vpn-t1-session-claw-limit-reached");
        }

        *self.active_by_key.entry(key.clone()).or_insert(0) += 1;
        *self
            .active_by_claw
            .entry(key.claw_id().to_string())
            .or_insert(0) += 1;
        Ok(())
    }

    fn release(&mut self, key: &ClawVpnAclKey) {
        decrement_count(&mut self.active_by_key, key);
        decrement_count(&mut self.active_by_claw, &key.claw_id().to_string());
    }
}

fn decrement_count<K>(counts: &mut HashMap<K, usize>, key: &K)
where
    K: Eq + std::hash::Hash,
{
    if let Some(count) = counts.get_mut(key) {
        if *count <= 1 {
            counts.remove(key);
        } else {
            *count -= 1;
        }
    }
}

struct ClawVpnT1RelayStreamAdmissionPermit {
    admission: Arc<Mutex<ClawVpnT1RelayStreamAdmission>>,
    key: ClawVpnAclKey,
}

impl Drop for ClawVpnT1RelayStreamAdmissionPermit {
    fn drop(&mut self) {
        if let Ok(mut admission) = self.admission.lock() {
            admission.release(&self.key);
        }
    }
}

struct ClawVpnT1RelayStreamPermitReader<R> {
    inner: R,
    _permit: Arc<ClawVpnT1RelayStreamAdmissionPermit>,
}

impl<R> AsyncRead for ClawVpnT1RelayStreamPermitReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

struct ClawVpnT1RelayStreamPermitWriter<W> {
    inner: W,
    _permit: Arc<ClawVpnT1RelayStreamAdmissionPermit>,
}

impl<W> AsyncWrite for ClawVpnT1RelayStreamPermitWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn attach_admission_permit(
    session: TargetSession,
    permit: ClawVpnT1RelayStreamAdmissionPermit,
) -> TargetSession {
    let TargetSession {
        reader,
        writer,
        resize,
        exit,
    } = session;
    let permit = Arc::new(permit);
    let resize_permit = Arc::clone(&permit);
    let exit_permit = Arc::clone(&permit);
    TargetSession {
        reader: Box::new(ClawVpnT1RelayStreamPermitReader {
            inner: reader,
            _permit: Arc::clone(&permit),
        }),
        writer: Box::new(ClawVpnT1RelayStreamPermitWriter {
            inner: writer,
            _permit: Arc::clone(&permit),
        }),
        resize: Box::new(move |cols, rows| {
            let _permit = Arc::clone(&resize_permit);
            resize(cols, rows)
        }),
        exit: Box::pin(async move {
            let result = exit.await;
            drop(exit_permit);
            result
        }),
    }
}

impl<I, BuildInputs, LaunchRuntime> RelayStreamIpTunnelRouter
    for ClawVpnT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>
where
    I: ClawVpnPacketInterface + Send + 'static,
    BuildInputs: Fn(
            &ClawVpnDevConfig,
            &RelayStreamIpTunnelTarget,
            ClawVpnRuntimeWiringContext,
            ClawVpnRelayStream<StdUnixStream>,
        ) -> io::Result<ClawVpnT1RelayStreamWiringInputs<I>>
        + Send
        + Sync,
    LaunchRuntime: Fn(ClawVpnTargetSessionRouterWiring<I>) -> ClawVpnTargetSessionRouterLaunchResult
        + Send
        + Sync,
{
    async fn open_ip_tunnel(
        &self,
        target: RelayStreamIpTunnelTarget,
    ) -> Result<TargetSession, DataTunnelError> {
        let key = ClawVpnAclKey::try_new(
            target.member_id().to_string(),
            target.member_device_pub().clone(),
            target.claw_id().to_string(),
        )
        .map_err(|_| target_unavailable("claw-vpn-t1-acl-key-invalid"))?;
        let permit = {
            let mut admission = self
                .admission
                .lock()
                .map_err(|_| target_unavailable("claw-vpn-t1-admission-lock-poisoned"))?;
            admission
                .reserve(
                    &key,
                    self.config.max_sessions_per_member_claw(),
                    self.config.max_sessions_per_claw(),
                )
                .map_err(target_unavailable)?;
            ClawVpnT1RelayStreamAdmissionPermit {
                admission: Arc::clone(&self.admission),
                key: key.clone(),
            }
        };

        let mut acl = ClawVpnAcl::new();
        acl.grant(key.clone());
        let registry = ClawVpnSessionRegistry::with_limits(
            acl,
            self.config.ipv4_pool(),
            self.config.max_sessions_per_member_claw(),
            self.config.max_sessions_per_claw(),
        )
        .map_err(|_| target_unavailable("claw-vpn-t1-session-registry-invalid"))?;
        let mut core = ClawVpnAgentCore::new(ClawVpnDatapathSide::Claw, registry);
        let (session, open_event) = core.open_with_audit(&key);
        let session = session.map_err(|_| target_unavailable("claw-vpn-t1-session-open-failed"))?;
        let session_id = session.id();
        if let Err(reason) = (self.audit_sink)(open_event) {
            let (_closed, close_event) = core.close_with_audit(session_id);
            let _ = (self.audit_sink)(close_event);
            return Err(target_unavailable(reason));
        }
        let session_core = core
            .into_session_core(session_id)
            .map_err(|_| target_unavailable("claw-vpn-t1-session-core-missing"))?;
        let config = &self.config;
        let build_inputs = &self.build_inputs;
        let runtime = assemble_claw_vpn_target_session_runtime(
            self.runtime_config,
            self.io_timeout,
            move || session_core,
            |context, relay| build_inputs(config, &target, context, relay),
        )
        .map_err(|error| map_runtime_error(&error))?;
        let Some(runtime) = runtime else {
            return Err(target_unavailable("claw-vpn-t1-runtime-disabled"));
        };
        let (target_session, wiring) = runtime.into_parts();
        (self.launch_runtime)(wiring)
            .map_err(|_| target_unavailable("claw-vpn-t1-runtime-launch-failed"))?;
        Ok(attach_admission_permit(target_session, permit))
    }
}

#[must_use = "inspect the T1 relay-stream router gate status before mounting IpTunnel"]
pub fn assemble_claw_vpn_t1_relay_stream_router<
    I,
    LoadConfig,
    LoadPreflight,
    BuildRouterParts,
    BuildInputs,
    LaunchRuntime,
>(
    load_config: LoadConfig,
    load_preflight: LoadPreflight,
    build_router_parts: BuildRouterParts,
) -> ClawVpnT1CallerStatus<ClawVpnT1RelayStreamIpTunnelRouter<I, BuildInputs, LaunchRuntime>>
where
    LoadConfig: FnOnce() -> Result<Option<ClawVpnDevConfig>, ClawVpnDevConfigError>,
    LoadPreflight: FnOnce() -> PerClawVpnT1PreflightEvidence,
    BuildRouterParts:
        FnOnce(&ClawVpnDevConfig) -> ClawVpnT1RelayStreamRouterParts<I, BuildInputs, LaunchRuntime>,
    BuildInputs: Send + Sync,
    LaunchRuntime: Send + Sync,
{
    assemble_claw_vpn_t1_caller(load_config, load_preflight, move |config| {
        let parts = build_router_parts(config);
        ClawVpnT1RelayStreamIpTunnelRouter::new(
            config.clone(),
            parts.runtime_config,
            parts.io_timeout,
            parts.build_inputs,
            parts.launch_runtime,
            parts.audit_sink,
        )
    })
}

fn map_runtime_error(error: &ClawVpnTargetSessionRuntimeError<io::Error>) -> DataTunnelError {
    match error {
        ClawVpnTargetSessionRuntimeError::Session(_) => {
            target_unavailable("claw-vpn-t1-session-core-failed")
        }
        ClawVpnTargetSessionRuntimeError::TargetSessionRelay(_) => {
            target_unavailable("claw-vpn-t1-target-session-relay-failed")
        }
        ClawVpnTargetSessionRuntimeError::Inputs(_) => {
            target_unavailable("claw-vpn-t1-runtime-inputs-failed")
        }
    }
}

fn target_unavailable(reason: &'static str) -> DataTunnelError {
    DataTunnelError::TargetUnavailable(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::claw_vpn_interface_route_plan::{
        ClawVpnInterfaceName, ClawVpnInterfaceRoutePlatform, ClawVpnInterfaceRouteToolPaths,
    };

    use household_rs::claw_vpn::{ClawVpnAuditAction, ClawVpnAuditReason, ClawVpnAuditSubject};
    use household_rs::keys::{IdentityKey, P256Keypair};

    struct FakeInterface {
        reads: VecDeque<Vec<u8>>,
    }

    impl FakeInterface {
        fn empty() -> Self {
            Self {
                reads: VecDeque::new(),
            }
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

    fn live_config() -> ClawVpnDevConfig {
        config_with_session_limits("1", "1")
    }

    fn config_with_session_limits(
        max_sessions_per_member_claw: &str,
        max_sessions_per_claw: &str,
    ) -> ClawVpnDevConfig {
        ClawVpnDevConfig::from_values(
            Some("1"),
            None,
            Some("relay-stream://127.0.0.1:49152"),
            Some("198.18.0.0/24"),
            Some(max_sessions_per_member_claw),
            Some(max_sessions_per_claw),
        )
        .unwrap()
        .unwrap()
    }

    fn enabled_runtime_config() -> ClawVpnRuntimeWiringConfig {
        let defaults = ClawVpnRuntimeWiringConfig::default();
        ClawVpnRuntimeWiringConfig::new(
            true,
            defaults.runtime_step_budget(),
            defaults.driver_budget(),
        )
    }

    fn target_with_device(
        member_id: &str,
        member_device_pub: household_rs::keys::P256PublicKey,
        claw_id: &str,
    ) -> RelayStreamIpTunnelTarget {
        RelayStreamIpTunnelTarget::new_for_test(
            "group-alpha",
            member_id,
            member_device_pub,
            claw_id,
        )
    }

    fn target(member_id: &str, claw_id: &str) -> RelayStreamIpTunnelTarget {
        target_with_device(member_id, P256Keypair::generate().public(), claw_id)
    }

    fn inputs(
        interface: FakeInterface,
        relay: ClawVpnRelayStream<StdUnixStream>,
    ) -> ClawVpnT1RelayStreamWiringInputs<FakeInterface> {
        ClawVpnRuntimeWiringInputs {
            route_platform: ClawVpnInterfaceRoutePlatform::Linux,
            interface_name: ClawVpnInterfaceName::new("t1test0").unwrap(),
            route_tool_paths: ClawVpnInterfaceRouteToolPaths::try_new(
                "/sbin/ip",
                "/sbin/ifconfig",
                "/sbin/route",
            )
            .unwrap(),
            interface,
            relay,
        }
    }

    fn noop_audit_sink() -> ClawVpnT1RelayStreamAuditSink {
        Box::new(|_event| Ok(()))
    }

    fn recording_audit_sink(
        events: Arc<Mutex<Vec<ClawVpnAuditEvent>>>,
    ) -> ClawVpnT1RelayStreamAuditSink {
        Box::new(move |event| {
            events.lock().unwrap().push(event);
            Ok(())
        })
    }

    #[tokio::test]
    async fn t1_relay_stream_router_builds_wiring_from_group_target_context() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let seen_target = Arc::new(Mutex::new(None));
        let audit_events = Arc::new(Mutex::new(Vec::new()));
        let member_device_pub = P256Keypair::generate().public();
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            live_config(),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                let seen_target = Arc::clone(&seen_target);
                move |
                    _config: &ClawVpnDevConfig,
                    target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    *seen_target.lock().unwrap() = Some((
                        target.group_id().to_string(),
                        target.member_id().to_string(),
                        target.member_device_pub().clone(),
                        target.claw_id().to_string(),
                    ));
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            recording_audit_sink(Arc::clone(&audit_events)),
        );

        let _session = router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub.clone(),
                "claw-alpha",
            ))
            .await
            .unwrap();

        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            seen_target.lock().unwrap().as_ref(),
            Some(&(
                "group-alpha".to_string(),
                "member-alpha".to_string(),
                member_device_pub.clone(),
                "claw-alpha".to_string()
            ))
        );
        let audit_events = audit_events.lock().unwrap();
        assert_eq!(audit_events.len(), 1);
        let audit_event = &audit_events[0];
        assert_eq!(audit_event.action(), ClawVpnAuditAction::SessionOpen);
        assert_eq!(audit_event.reason(), ClawVpnAuditReason::SessionOpened);
        assert_eq!(
            audit_event.subject(),
            Some(ClawVpnAuditSubject::from_acl_key(
                &ClawVpnAclKey::try_new(
                    "member-alpha".to_string(),
                    member_device_pub.clone(),
                    "claw-alpha".to_string()
                )
                .unwrap()
            ))
        );
        assert!(audit_event.session_id().is_some());
    }

    #[tokio::test]
    async fn t1_relay_stream_router_enforces_member_claw_limit_until_session_drops() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            config_with_session_limits("1", "2"),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                move |
                    _config: &ClawVpnDevConfig,
                    _target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            noop_audit_sink(),
        );
        let member_device_pub = P256Keypair::generate().public();

        let first_session = router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub.clone(),
                "claw-alpha",
            ))
            .await
            .unwrap();
        let error = match router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub.clone(),
                "claw-alpha",
            ))
            .await
        {
            Ok(_) => panic!("second session for the same member/claw must be limited"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-session-member-claw-limit-reached")
        );
        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);

        drop(first_session);
        let _second_session = router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub,
                "claw-alpha",
            ))
            .await
            .unwrap();
        assert_eq!(build_count.load(Ordering::SeqCst), 2);
        assert_eq!(launch_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn t1_relay_stream_router_enforces_claw_limit_across_members() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            config_with_session_limits("2", "1"),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                move |
                    _config: &ClawVpnDevConfig,
                    _target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            noop_audit_sink(),
        );

        let _first_session = router
            .open_ip_tunnel(target("member-alpha", "claw-alpha"))
            .await
            .unwrap();
        let error = match router
            .open_ip_tunnel(target("member-beta", "claw-alpha"))
            .await
        {
            Ok(_) => panic!("second session for the same claw must be limited"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-session-claw-limit-reached")
        );
        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn t1_relay_stream_router_shared_admission_crosses_router_instances() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let admission = Arc::new(Mutex::new(ClawVpnT1RelayStreamAdmission::default()));
        let router = |admission| {
            ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::with_admission(
                config_with_session_limits("1", "2"),
                enabled_runtime_config(),
                Duration::from_secs(1),
                {
                    let build_count = Arc::clone(&build_count);
                    move |
                        _config: &ClawVpnDevConfig,
                        _target: &RelayStreamIpTunnelTarget,
                        _context: ClawVpnRuntimeWiringContext,
                        relay: ClawVpnRelayStream<StdUnixStream>,
                    | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                        build_count.fetch_add(1, Ordering::SeqCst);
                        Ok(inputs(FakeInterface::empty(), relay))
                    }
                },
                {
                    let launch_count = Arc::clone(&launch_count);
                    move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                        launch_count.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
                noop_audit_sink(),
                admission,
            )
        };
        let first_router = router(Arc::clone(&admission));
        let second_router = router(admission);
        let member_device_pub = P256Keypair::generate().public();

        let first_session = first_router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub.clone(),
                "claw-alpha",
            ))
            .await
            .unwrap();
        let error = match second_router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub.clone(),
                "claw-alpha",
            ))
            .await
        {
            Ok(_) => panic!("shared admission must cross router instances"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-session-member-claw-limit-reached")
        );
        assert_eq!(build_count.load(Ordering::SeqCst), 1);
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);

        drop(first_session);
        let _second_session = second_router
            .open_ip_tunnel(target_with_device(
                "member-alpha",
                member_device_pub,
                "claw-alpha",
            ))
            .await
            .unwrap();
        assert_eq!(build_count.load(Ordering::SeqCst), 2);
        assert_eq!(launch_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn t1_relay_stream_router_rejects_invalid_acl_context_before_inputs() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            live_config(),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                move |
                    _config: &ClawVpnDevConfig,
                    _target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            noop_audit_sink(),
        );

        let error = match router
            .open_ip_tunnel(target(" member-alpha", "claw-alpha"))
            .await
        {
            Ok(_) => panic!("invalid ACL context must fail before returning a target session"),
            Err(error) => error,
        };

        assert!(
            matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-acl-key-invalid")
        );
        assert_eq!(build_count.load(Ordering::SeqCst), 0);
        assert_eq!(launch_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn t1_relay_stream_router_rejects_audit_failure_before_inputs() {
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let audit_count = Arc::new(AtomicUsize::new(0));
        let member_device_pub = P256Keypair::generate().public();
        let router = ClawVpnT1RelayStreamIpTunnelRouter::<FakeInterface, _, _>::new(
            live_config(),
            enabled_runtime_config(),
            Duration::from_secs(1),
            {
                let build_count = Arc::clone(&build_count);
                move |
                    _config: &ClawVpnDevConfig,
                    _target: &RelayStreamIpTunnelTarget,
                    _context: ClawVpnRuntimeWiringContext,
                    relay: ClawVpnRelayStream<StdUnixStream>,
                | -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                    build_count.fetch_add(1, Ordering::SeqCst);
                    Ok(inputs(FakeInterface::empty(), relay))
                }
            },
            {
                let launch_count = Arc::clone(&launch_count);
                move |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                    launch_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            {
                let audit_count = Arc::clone(&audit_count);
                Box::new(move |event: ClawVpnAuditEvent| {
                    let index = audit_count.fetch_add(1, Ordering::SeqCst);
                    match index % 2 {
                        0 => {
                            assert_eq!(event.action(), ClawVpnAuditAction::SessionOpen);
                            assert_eq!(event.reason(), ClawVpnAuditReason::SessionOpened);
                            Err("claw-vpn-t1-audit-open-failed")
                        }
                        1 => {
                            assert_eq!(event.action(), ClawVpnAuditAction::SessionClose);
                            assert_eq!(event.reason(), ClawVpnAuditReason::SessionClosed);
                            Ok(())
                        }
                        _ => unreachable!(),
                    }
                })
            },
        );

        for _ in 0..2 {
            let error = match router
                .open_ip_tunnel(target_with_device(
                    "member-alpha",
                    member_device_pub.clone(),
                    "claw-alpha",
                ))
                .await
            {
                Ok(_) => panic!("audit sink failure must fail before returning a target session"),
                Err(error) => error,
            };

            assert!(
                matches!(error, DataTunnelError::TargetUnavailable(reason) if reason == "claw-vpn-t1-audit-open-failed")
            );
        }

        assert_eq!(audit_count.load(Ordering::SeqCst), 4);
        assert_eq!(build_count.load(Ordering::SeqCst), 0);
        assert_eq!(launch_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn t1_relay_stream_router_gate_returns_before_building_router_when_preflight_missing() {
        let parts_built = Arc::new(AtomicUsize::new(0));
        let status = assemble_claw_vpn_t1_relay_stream_router::<FakeInterface, _, _, _, _, _>(
            || Ok(Some(live_config())),
            PerClawVpnT1PreflightEvidence::missing,
            {
                let parts_built = Arc::clone(&parts_built);
                move |_config| {
                    parts_built.fetch_add(1, Ordering::SeqCst);
                    ClawVpnT1RelayStreamRouterParts::new(
                        enabled_runtime_config(),
                        Duration::from_secs(1),
                        |_config: &ClawVpnDevConfig,
                         _target: &RelayStreamIpTunnelTarget,
                         _context: ClawVpnRuntimeWiringContext,
                         relay: ClawVpnRelayStream<StdUnixStream>|
                         -> io::Result<ClawVpnT1RelayStreamWiringInputs<FakeInterface>> {
                            Ok(inputs(FakeInterface::empty(), relay))
                        },
                        |_wiring: ClawVpnTargetSessionRouterWiring<FakeInterface>| {
                            Ok::<(), crate::claw_vpn_target_session_router::ClawVpnTargetSessionRouterLaunchError>(
                                (),
                            )
                        },
                        noop_audit_sink(),
                    )
                }
            },
        );

        assert!(matches!(
            status,
            ClawVpnT1CallerStatus::OwnerAuthorizationRequired { .. }
        ));
        assert_eq!(parts_built.load(Ordering::SeqCst), 0);
    }
}
