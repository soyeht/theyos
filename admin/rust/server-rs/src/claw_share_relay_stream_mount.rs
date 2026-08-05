//! Bootstrap mount for the Product A `relay_stream` live wiring (default-off).
//!
//! C6.2. This is the thin glue that lets `assemble_relay_stream_live` (C6) run
//! inside the engine: it is called from household bootstrap right after the live
//! `claw_share` mesh log and slot store are created, and passes those SAME live
//! `Arc`s in, so the `relay_stream` pool shares one slot store with the
//! data-tunnel revoke-poll (the M2b invariant) and one mesh log with the rest of
//! the engine.
//!
//! Default-OFF is the #1 property: gated by the `THEYOS_RELAY_STREAM_LIVE` env
//! var, OFF (unset/false) returns before reading the household, creating a
//! keystore, building inputs, or spawning anything. ON, it builds a real PTY
//! target factory, an offer-aware `ClawSite` factory, and a dedicated Noise
//! keystore, then assembles and keeps the handles alive in a process-lifetime
//! `OnceLock`.
//!
//! `ClawSite` routing is chosen per offer from its SIGNED audience, never from
//! the shape of `claw_id`. A Device offer resolves the D6 share and dials the
//! resolved port on loopback; Group/Public stay in the legacy namespace, whose
//! only backend is DEV-gated and therefore absent from a product build, so that
//! arm fails closed there.
//!
//! It announces nothing public: no advertise, no inbound listener bind, no
//! claim-ack, no guest/iOS. With an empty offer store, ON is a serving no-op.
//!
//! Phase 0 production builds compile out the `IpTunnel` backend and reject that
//! resource at provisioning. The real TUN/utun path exists only for unit tests
//! or the explicit `dev_t1_datapath` targets; the PTY factory is untouched by
//! the `ClawSite` work above, and `IpTunnel` is untouched entirely.
//!
//! Carries (out of scope here): the `relay_stream` mount uses its OWN
//! `ReplayGuard` (unify with the direct data-tunnel listener pre-live); the
//! Noise key uses a `FileKeystore` (live keychain hardening later); handles live
//! in a `OnceLock` rather than a graceful `AppState` holder.

#[cfg(any(test, feature = "dev_t1_datapath"))]
use std::cell::RefCell;
#[cfg(any(test, feature = "dev_t1_datapath"))]
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
#[cfg(any(test, feature = "dev_t1_datapath"))]
use std::rc::Rc;
use std::sync::{Arc, OnceLock};
#[cfg(any(test, feature = "dev_t1_datapath"))]
use std::time::Duration;

use household_rs::claw_share::{ClawShareSlotStore, GuestCredential};
use household_rs::claw_share_data_tunnel::{
    ClawTargetRouter, DataTunnelError, ReplayGuard, TargetSession, TcpStreamRouter,
};
use household_rs::household_mesh_log::MeshLogStore;
use household_rs::keys::{IdentityKey, P256PublicKey};
use keystore_rs::FileKeystore;
use tokio::sync::Notify;

use crate::claw_share_app_descriptor::{DeviceShareAppId, ShareResolution};
use crate::claw_share_pty_target::{PtyPolicy, PtyTargetRouter};
use crate::claw_share_relay_stream_contract::{
    RelayStreamAudience, RelayStreamClawStaticPublicKey, RelayStreamOfferContract,
    RelayStreamResource, ShareableAppPresentation,
};
use crate::claw_share_relay_stream_issuer_trust::{
    RelayStreamIssuerTrust, RelayStreamTrustContext,
};
use crate::claw_share_relay_stream_noise_keystore::{
    DEFAULT_RELAY_STREAM_NOISE_KEY_ID, RelayStreamNoiseKeyStore,
};
use crate::claw_share_relay_stream_offer_store::{
    RelayStreamOfferStore, RelayStreamOfferStoreError,
};
use crate::claw_share_relay_stream_provision::{
    RelayStreamProvisionError, provision_relay_stream_group_offer, provision_relay_stream_offer,
    provision_relay_stream_public_offer,
};
#[cfg(not(any(test, feature = "dev_t1_datapath")))]
use crate::claw_share_relay_stream_runtime::assemble_relay_stream_live;
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::claw_share_relay_stream_runtime::assemble_relay_stream_live_with_ip_tunnel_router;
use crate::claw_share_relay_stream_runtime::{
    RelayStreamLiveConfig, RelayStreamLiveError, RelayStreamLiveHandles, RelayStreamLiveInputs,
};
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::claw_share_relay_stream_target_router::{
    RelayStreamIpTunnelRouter, RelayStreamIpTunnelTarget, RelayStreamIpTunnelUnavailableRouter,
};
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::claw_vpn_dev_config::{ClawVpnDevConfig, ClawVpnDevConfigError};
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::claw_vpn_interface_route_plan::{
    ClawVpnInterfaceName, ClawVpnInterfaceRoutePlatform, ClawVpnInterfaceRouteToolPaths,
};
#[cfg(all(any(test, feature = "dev_t1_datapath"), target_os = "linux"))]
use crate::claw_vpn_linux_tun::{
    ClawVpnLinuxTunConfig, ClawVpnLinuxTunDevice, ClawVpnLinuxTunName,
};
#[cfg(all(any(test, feature = "dev_t1_datapath"), target_os = "macos"))]
use crate::claw_vpn_macos_utun::ClawVpnMacosUtunDevice;
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::claw_vpn_packet_pump::ClawVpnPacketInterface;
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::claw_vpn_t1_caller::ClawVpnT1CallerStatus;
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::claw_vpn_t1_relay_stream_router::{
    ClawVpnT1AuditSinkError, ClawVpnT1RelayStreamAuditSink, ClawVpnT1RelayStreamBoxedRouter,
    ClawVpnT1RelayStreamBuildInputs, ClawVpnT1RelayStreamLaunchRuntime,
    ClawVpnT1RelayStreamRouterParts, assemble_claw_vpn_t1_relay_stream_router,
    claw_vpn_t1_canonical_audit_log_path, claw_vpn_t1_spooled_jsonl_audit_sink,
};
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::claw_vpn_target_session_router::{
    ClawVpnTargetSessionRouterLaunchError, ClawVpnTargetSessionRouterWiring,
};
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::claw_vpn_wiring::{ClawVpnRuntimeWiringConfig, ClawVpnRuntimeWiringInputs};
use crate::household_state::HouseholdState;
#[cfg(any(test, feature = "dev_t1_datapath"))]
use crate::startup_wiring::{
    PerClawVpnT1PreflightEvidence, PerClawVpnT1PreflightEvidenceBundle,
    load_per_claw_vpn_t1_preflight_evidence_record_for_current_build,
};
use crate::state::SharedState;

/// Env var that opts the `relay_stream` live path IN. Absent or non-truthy = OFF.
const RELAY_STREAM_LIVE_ENV: &str = "THEYOS_RELAY_STREAM_LIVE";

/// Stable keystore service + subdir for the `relay_stream` Noise static key. This
/// is a SEPARATE X25519 key, not the household machine signing key.
const RELAY_STREAM_KEYSTORE_SERVICE: &str = "com.soyeht.theyos.relay-stream";
const RELAY_STREAM_KEYSTORE_SUBDIR: &str = "relay_stream_keystore";

/// Env var for the relay endpoint shared by the offer's `relay_endpoint` and the
/// pool's reverse-connect dial address, so the two never diverge. Default is the
/// loopback responder bind.
const RELAY_STREAM_RELAY_ENDPOINT_ENV: &str = "THEYOS_RELAY_STREAM_RELAY_ENDPOINT";
const DEFAULT_RELAY_STREAM_RELAY_ENDPOINT: &str = "127.0.0.1:49152";
const RELAY_STREAM_DEV_ALLOW_PUBLIC_RELAY_DIAL_ENV: &str =
    "THEYOS_RELAY_STREAM_DEV_ALLOW_PUBLIC_RELAY_DIAL";

/// DEV/test-only backend for the LEGACY Group/Public `ClawSite` namespace, e.g.
/// `127.0.0.1:8080`.
///
/// It replaces a former global backend var that applied to every `ClawSite`
/// dial. The D6 Device path has no operator-configured backend at all — it dials
/// the port the share resolution returns — so a product build cannot point
/// `ClawSite` anywhere, by construction rather than by policy. Unset here (and
/// always, in a product build) means the legacy namespace fails closed.
/// Gated on the feature ALONE, never `any(test, feature)`: a default `cargo
/// test` build must compile the same snapshot-free arm production does, or the
/// product's fail-closed behavior becomes unprovable by the suite.
#[cfg(feature = "dev_claw_share_mint")]
const DEV_RELAY_STREAM_CLAWSITE_BACKEND_ENV: &str = "THEYOS_DEV_RELAY_STREAM_CLAWSITE_BACKEND";

/// DEV/test-only env var selecting the resource a legacy (snapshot-free) offer
/// is minted for: `pty` (default), `clawsite`, or `ip_tunnel`.
///
/// Deliberately absent from product builds. It replaces a former GLOBAL
/// resource env var that was read on EVERY provision path, which meant an unset
/// variable silently minted `Pty` — and `Pty` is forbidden for Group/Public
/// audiences, so every shared-audience offer failed. The old name is gone from
/// the tree entirely, literal included, so nobody rediscovers the button by
/// grep; the name now says DEV so the product path cannot be steered by an
/// operator's environment.
#[cfg(any(test, feature = "dev_claw_share_mint"))]
const DEV_RELAY_STREAM_RESOURCE_ENV: &str = "THEYOS_DEV_RELAY_STREAM_RESOURCE";

#[cfg(any(test, feature = "dev_t1_datapath"))]
const CLAW_VPN_T1_TARGET_SESSION_IO_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(test, feature = "dev_t1_datapath"))]
const CLAW_VPN_T1_PREFLIGHT_EVIDENCE_RECORD_ENV: &str =
    "THEYOS_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_RECORD";
#[cfg(all(any(test, feature = "dev_t1_datapath"), target_os = "linux"))]
const CLAW_VPN_T1_LINUX_TUN_NAME: &str = "clawvpn0";
#[cfg(any(test, feature = "dev_t1_datapath"))]
const CLAW_VPN_LINUX_IP_TOOL_PATH: &str = "/sbin/ip";
#[cfg(any(test, feature = "dev_t1_datapath"))]
const CLAW_VPN_MACOS_IFCONFIG_TOOL_PATH: &str = "/sbin/ifconfig";
#[cfg(any(test, feature = "dev_t1_datapath"))]
const CLAW_VPN_MACOS_ROUTE_TOOL_PATH: &str = "/sbin/route";

/// The single source for the relay address (`host:port`). The provisioned offer
/// stores it as `relay-stream://<addr>`; the pool dials it as a `SocketAddr`.
/// Both read this, so the offer endpoint and the pool dial target cannot drift.
pub(crate) fn relay_stream_relay_endpoint() -> String {
    std::env::var(RELAY_STREAM_RELAY_ENDPOINT_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map_or_else(
            || DEFAULT_RELAY_STREAM_RELAY_ENDPOINT.to_string(),
            |value| value.trim().to_string(),
        )
}

/// Resolve the operator-configured relay endpoint once, before assembling the
/// reverse-connect pool. Offers keep the hostname verbatim while the owner
/// dials the resolved address. This is required for IPv6-only/NAT64 guests:
/// advertising an IPv4 literal prevents DNS64 synthesis, whereas a hostname
/// remains reachable without changing the blind relay or its Noise boundary.
///
/// Resolution is fail-closed. The previous `parse::<SocketAddr>()` path
/// silently left the pool on its loopback default when a hostname was
/// configured, while offers advertised that hostname; that split-brain could
/// never pair.
async fn resolve_relay_stream_relay_addr(
    endpoint: &str,
) -> Result<SocketAddr, RelayStreamMountError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(RelayStreamMountError::RelayEndpoint(
            "relay endpoint is empty".to_string(),
        ));
    }
    let mut resolved = tokio::net::lookup_host(endpoint).await.map_err(|error| {
        RelayStreamMountError::RelayEndpoint(format!(
            "failed to resolve relay endpoint {endpoint:?}: {error}"
        ))
    })?;
    resolved.next().ok_or_else(|| {
        RelayStreamMountError::RelayEndpoint(format!(
            "relay endpoint {endpoint:?} resolved to no addresses"
        ))
    })
}

/// Process-lifetime holder so the spawned driver/pool are not Drop-aborted right
/// after the mount returns. A graceful `AppState` holder is a future carry.
static LIVE_HANDLES: OnceLock<RelayStreamLiveHandles> = OnceLock::new();

/// Process-lifetime `IpTunnel` backend for the mounted relay-stream runtime.
///
/// The runtime calls its router factory per binding/worker. Caching the mounted
/// router here keeps T1 admission state shared across those factory calls.
#[cfg(any(test, feature = "dev_t1_datapath"))]
static MOUNTED_IP_TUNNEL_ROUTER: OnceLock<Arc<RelayStreamMountedIpTunnelRouter>> = OnceLock::new();

/// `ClawSite` target router.
///
/// Resolve a D6 share app to its readiness + dial port.
///
/// A closure rather than a concrete store handle so the router stays testable
/// without a database: production closes over `SharedState`, tests inject a
/// canned answer. It is SYNCHRONOUS because the store is — callers wrap it in
/// `spawn_blocking` rather than blocking the reactor.
pub type ShareAppResolver = Arc<
    dyn for<'a> Fn(DeviceShareAppId, &'a str) -> Result<ShareResolution, store_rs::StoreError>
        + Send
        + Sync,
>;

/// D6 Device path: resolve the app named by the offer's `claw_id`, then dial the
/// port that resolution returned. There is no second query and no configured
/// backend — the port comes from `ShareReadyApp` and nowhere else.
pub struct DeviceShareClawSiteRouter {
    resolve: ShareAppResolver,
    household_id: String,
}

/// Pre-D6 Group/Public namespace: one operator-configured backend, now DEV-only.
/// A product build has no way to set it, so this fails closed there.
pub struct LegacyClawSiteRouter {
    backend_addr: Option<String>,
}

/// Which `ClawSite` implementation an offer gets. Chosen from the SIGNED audience
/// at bind time, never from the shape of `claw_id` — a Group offer whose
/// `claw_id` happens to look like `app_…` is still Group.
///
/// Construction is inert on every arm: no store access, no connect, no
/// resolution. All of that happens in `open`, behind the authorization gate.
pub enum RelayStreamClawSiteRouter {
    DeviceShare(DeviceShareClawSiteRouter),
    Legacy(LegacyClawSiteRouter),
    /// A Device offer on an instance with no resolver (no `SharedState`).
    /// Cannot resolve, so it fails closed — deliberately indistinguishable from
    /// an app that never existed.
    Unresolvable,
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
enum RelayStreamMountedIpTunnelRouter {
    Unavailable(RelayStreamIpTunnelUnavailableRouter),
    #[cfg(target_os = "linux")]
    T1Linux(Box<ClawVpnT1RelayStreamBoxedRouter<ClawVpnLinuxTunDevice>>),
    #[cfg(target_os = "macos")]
    T1Macos(Box<ClawVpnT1RelayStreamBoxedRouter<ClawVpnMacosUtunDevice>>),
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
impl RelayStreamIpTunnelRouter for RelayStreamMountedIpTunnelRouter {
    async fn open_ip_tunnel(
        &self,
        target: RelayStreamIpTunnelTarget,
    ) -> Result<TargetSession, DataTunnelError> {
        match self {
            Self::Unavailable(router) => router.open_ip_tunnel(target).await,
            #[cfg(target_os = "linux")]
            Self::T1Linux(router) => router.open_ip_tunnel(target).await,
            #[cfg(target_os = "macos")]
            Self::T1Macos(router) => router.open_ip_tunnel(target).await,
        }
    }
}

/// The app resolved to a live identity in a recoverable runtime state — the
/// guest may retry.
const SHARE_APP_UNAVAILABLE: &str = "relay-stream-share-app-unavailable";
/// Detail-free bucket. Unknown, retired, foreign, deleted, malformed, and every
/// resolver fault collapse here on purpose: distinguishing them would turn this
/// reason into an existence oracle for app ids.
const SHARE_APP_GONE: &str = "relay-stream-share-app-no-longer-available";

impl LegacyClawSiteRouter {
    /// DEV only. A product build cannot configure a backend at all, so the
    /// legacy namespace fails closed there. No fallback to the removed global.
    #[cfg(feature = "dev_claw_share_mint")]
    #[must_use]
    pub fn from_dev_env() -> Self {
        Self {
            backend_addr: std::env::var(DEV_RELAY_STREAM_CLAWSITE_BACKEND_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        }
    }

    /// Product-shaped arm, and the one a DEFAULT `cargo test` compiles: there is
    /// no env to read, so the legacy namespace is unconfigurable and fails
    /// closed. Forwarding tests construct the struct directly instead.
    #[cfg(not(feature = "dev_claw_share_mint"))]
    #[must_use]
    pub fn from_dev_env() -> Self {
        Self { backend_addr: None }
    }
}

impl DeviceShareClawSiteRouter {
    async fn open_resolved(&self, target_id: &str) -> Result<TargetSession, DataTunnelError> {
        // The offer's own claw_id is the app id. A shape that is not a D6 id
        // cannot name a share, and says nothing further.
        let Ok(app_id) = DeviceShareAppId::try_from(target_id) else {
            return Err(target_unavailable_owned(SHARE_APP_GONE));
        };
        let resolve = Arc::clone(&self.resolve);
        let household_id = self.household_id.clone();
        // The store is synchronous; keep it off the reactor. A panic inside the
        // resolver surfaces as a JoinError and is treated like any other fault.
        let resolved = tokio::task::spawn_blocking(move || resolve(app_id, &household_id)).await;

        let ready = match resolved {
            Ok(Ok(ShareResolution::Ready(ready))) => ready,
            Ok(Ok(ShareResolution::Unavailable(_))) => {
                return Err(target_unavailable_owned(SHARE_APP_UNAVAILABLE));
            }
            // Terminal, store fault, and resolver panic are ONE outcome on the
            // wire. Splitting them would let a dialer probe which app ids exist.
            Ok(Ok(ShareResolution::Terminal) | Err(_)) | Err(_) => {
                return Err(target_unavailable_owned(SHARE_APP_GONE));
            }
        };

        // The only port, straight off the resolution — no second query, and
        // loopback only: a share backend is always local to this engine.
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), ready.backend_port);
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|_| target_unavailable_owned(SHARE_APP_UNAVAILABLE))?;
        Ok(TargetSession::from_stream(stream))
    }
}

impl ClawTargetRouter for RelayStreamClawSiteRouter {
    async fn open(&self, target_id: &str) -> Result<TargetSession, DataTunnelError> {
        match self {
            Self::DeviceShare(router) => router.open_resolved(target_id).await,
            Self::Legacy(LegacyClawSiteRouter {
                backend_addr: Some(addr),
            }) => TcpStreamRouter::new(addr.clone()).open(target_id).await,
            Self::Legacy(LegacyClawSiteRouter { backend_addr: None }) => Err(
                DataTunnelError::TargetUnavailable("relay-stream-clawsite-not-configured".into()),
            ),
            Self::Unresolvable => Err(target_unavailable_owned(SHARE_APP_GONE)),
        }
    }
}

fn target_unavailable_owned(reason: &'static str) -> DataTunnelError {
    DataTunnelError::TargetUnavailable(reason.to_string())
}

/// Pick the `ClawSite` implementation for one offer, from its SIGNED audience.
///
/// Inert by construction: it clones handles and returns. Nothing here reads the
/// store, resolves an app, or opens a socket — `validate_target_for_resource`
/// downstream remains the only authorization gate, and it runs before `open`.
fn clawsite_router_for_offer(
    offer: &RelayStreamOfferContract,
    resolver: Option<&ShareAppResolver>,
    household_id: &str,
) -> RelayStreamClawSiteRouter {
    match offer.payload.audience() {
        // D6. Note this branches on the audience, NOT on whether `claw_id`
        // parses as an app id — see the Group/Public arm.
        RelayStreamAudience::Device => match resolver {
            Some(resolve) => RelayStreamClawSiteRouter::DeviceShare(DeviceShareClawSiteRouter {
                resolve: Arc::clone(resolve),
                household_id: household_id.to_string(),
            }),
            None => RelayStreamClawSiteRouter::Unresolvable,
        },
        // Legacy namespace this cycle, even when `claw_id` carries an `app_…`
        // shape: a signed Group/Public offer never addresses a D6 share.
        RelayStreamAudience::Group { .. } | RelayStreamAudience::Public => {
            RelayStreamClawSiteRouter::Legacy(LegacyClawSiteRouter::from_dev_env())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayStreamResourceEnvError {
    #[error("invalid THEYOS_DEV_RELAY_STREAM_RESOURCE value")]
    Invalid,
}

/// Resource a provisioned offer is minted for. Missing value defaults to `Pty`;
/// recognized values select the matching signed resource. `ip_tunnel` is
/// rejected by the Phase 0 production build even when explicitly requested.
/// Unknown values fail closed so a typo never mints a broader capability.
fn parse_resource_for_policy(
    value: Option<&str>,
    ip_tunnel_compiled: bool,
) -> Result<RelayStreamResource, RelayStreamResourceEnvError> {
    match value.map(str::trim) {
        None | Some("" | "pty" | "Pty" | "PTY") => Ok(RelayStreamResource::Pty),
        Some("clawsite" | "ClawSite" | "CLAWSITE") => Ok(RelayStreamResource::ClawSite),
        Some("ip_tunnel" | "iptunnel" | "IpTunnel" | "IPTUNNEL") => {
            if ip_tunnel_compiled {
                Ok(RelayStreamResource::IpTunnel)
            } else {
                Err(RelayStreamResourceEnvError::Invalid)
            }
        }
        Some(_) => Err(RelayStreamResourceEnvError::Invalid),
    }
}

fn parse_resource(value: Option<&str>) -> Result<RelayStreamResource, RelayStreamResourceEnvError> {
    parse_resource_for_policy(
        value,
        crate::claw_share_relay_stream_offer_store::IP_TUNNEL_RESOURCE_COMPILED,
    )
}

/// Executable artifact probe used by the Phase 0 attestation command.
#[must_use]
pub(crate) fn phase0_ip_tunnel_env_accepts_resource() -> bool {
    parse_resource(Some("IpTunnel")).is_ok()
}

/// DEV/test only. The product build has no env-steered resource at all: the
/// Device path derives it from the durable snapshot, and Group/Public pin
/// `ClawSite` explicitly.
#[cfg(any(test, feature = "dev_claw_share_mint"))]
fn dev_relay_stream_resource_from_env() -> Result<RelayStreamResource, RelayStreamResourceEnvError>
{
    parse_resource(std::env::var(DEV_RELAY_STREAM_RESOURCE_ENV).ok().as_deref())
}

/// Decide the resource and the snapshot a Device claim mints with.
///
/// PURE — no env, no cfg, no globals — so both outcomes are executable from the
/// test suite by injection. `dev_fallback` is the ONLY way a snapshot-free claim
/// can succeed, and the call site supplies it exclusively under
/// `feature = "dev_claw_share_mint"`. Note the gate is the feature ALONE, not
/// `any(test, feature)`: making `cfg(test)` supply a fallback would compile the
/// legacy branch into every test build and leave the product's fail-closed
/// behavior permanently unprovable by the suite.
///
/// A present snapshot decides everything on its own: it means Device+ClawSite,
/// so `dev_fallback` is not even consulted and no environment can steer it.
fn select_resource_and_snapshot(
    snapshot: Option<ShareableAppPresentation>,
    dev_fallback: Option<RelayStreamResource>,
) -> Result<(RelayStreamResource, Option<ShareableAppPresentation>), RelayStreamClaimProvisionError>
{
    match snapshot {
        Some(presentation) => Ok((RelayStreamResource::ClawSite, Some(presentation))),
        // Absent slot and snapshot-free slot are deliberately the same case:
        // neither is a Device+ClawSite share.
        None => match dev_fallback {
            Some(resource) => Ok((resource, None)),
            None => Err(RelayStreamClaimProvisionError::MissingAppPresentation),
        },
    }
}

/// Resolve a Device claim's resource + snapshot, reading the DEV env var ONLY
/// when there is no snapshot.
///
/// The laziness is load-bearing, not a micro-optimisation. Evaluating
/// `dev_relay_stream_resource_from_env()?` eagerly would propagate a malformed
/// env value out of a claim that HAS a snapshot — so a broken environment could
/// still break the product path this checkpoint exists to make env-independent.
/// Testing the pure selector cannot catch that, because by then the env has
/// already been read; the property only exists here, so it is tested here.
fn resolve_claim_resource(
    snapshot: Option<ShareableAppPresentation>,
) -> Result<(RelayStreamResource, Option<ShareableAppPresentation>), RelayStreamClaimProvisionError>
{
    #[cfg(feature = "dev_claw_share_mint")]
    let dev_fallback = snapshot
        .is_none()
        .then(dev_relay_stream_resource_from_env)
        .transpose()?;
    // Feature-gated ALONE, not `any(test, feature)`: a default `cargo test`
    // build gets `None` here and therefore executes the real product
    // fail-closed path.
    #[cfg(not(feature = "dev_claw_share_mint"))]
    let dev_fallback = None;
    select_resource_and_snapshot(snapshot, dev_fallback)
}

fn parse_enabled(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true" | "TRUE"))
}

fn relay_stream_live_enabled_from_env() -> bool {
    parse_enabled(std::env::var(RELAY_STREAM_LIVE_ENV).ok().as_deref())
}

/// Bootstrap entry: mount the `relay_stream` live path if enabled by env.
///
/// Default-OFF: when the env flag is absent/false this returns immediately,
/// before any household read, keystore creation, input build, or task spawn.
/// Idempotent: a second call after a successful mount is a no-op (never spawns a
/// second set of components). Failures are surfaced to the caller, which should
/// log and continue — a `relay_stream` mount failure must not break bootstrap.
pub async fn mount_relay_stream_live_if_enabled(
    state_dir: PathBuf,
    household: HouseholdState,
    mesh_log: Arc<MeshLogStore>,
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
    shared_state: Option<SharedState>,
) -> Result<(), RelayStreamMountError> {
    if !relay_stream_live_enabled_from_env() {
        return Ok(());
    }
    if LIVE_HANDLES.get().is_some() {
        tracing::warn!(stage = "claw_share.relay_stream.mount.already_mounted");
        return Ok(());
    }

    let mut config = RelayStreamLiveConfig {
        enabled: true,
        ..RelayStreamLiveConfig::default()
    };
    // Single-source the relay address so the pool dials the endpoint the
    // provisioned offers advertise. Hostnames are intentional: guests on an
    // IPv6-only network need DNS64 instead of an IPv4 literal. Invalid or
    // unresolvable configuration fails closed rather than silently dialing the
    // loopback default while advertising a different endpoint.
    let advertised_relay_endpoint = relay_stream_relay_endpoint();
    config.reverse_connect.relay_addr =
        resolve_relay_stream_relay_addr(&advertised_relay_endpoint).await?;
    if parse_enabled(
        std::env::var(RELAY_STREAM_DEV_ALLOW_PUBLIC_RELAY_DIAL_ENV)
            .ok()
            .as_deref(),
    ) {
        tracing::warn!(
            stage = "claw_share.relay_stream.mount.public_relay_dial_enabled",
            relay_addr = %config.reverse_connect.relay_addr,
            advertised_relay_endpoint = %advertised_relay_endpoint,
            "THEYOS_RELAY_STREAM_DEV_ALLOW_PUBLIC_RELAY_DIAL=1 — allowing relay_stream reverse-connect to a non-loopback relay endpoint for a dev smoke"
        );
        config.reverse_connect.allow_non_loopback_relay_addr = true;
    }
    match mount_relay_stream_live(
        state_dir,
        household,
        mesh_log,
        slots,
        replay,
        config,
        shared_state,
    )
    .await?
    {
        Some(handles) => {
            tracing::info!(
                stage = "claw_share.relay_stream.mount.enabled",
                offer_count = handles.offer_count(),
                pool_tasks = handles.pool_task_count(),
            );
            if LIVE_HANDLES.set(handles).is_err() {
                tracing::warn!(stage = "claw_share.relay_stream.mount.race_already_set");
            }
        }
        None => {
            tracing::warn!(stage = "claw_share.relay_stream.mount.assemble_returned_none");
        }
    }
    Ok(())
}

/// Build the live inputs from the injected handles and assemble.
///
/// Separated from the env/`OnceLock` wrapper so it is deterministically testable
/// without process-global state. With `config.enabled == false` it returns
/// `Ok(None)` BEFORE creating the keystore directory or reading the household,
/// preserving the default-off zero-side-effect property.
async fn mount_relay_stream_live(
    state_dir: PathBuf,
    household: HouseholdState,
    mesh_log: Arc<MeshLogStore>,
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
    config: RelayStreamLiveConfig,
    shared_state: Option<SharedState>,
) -> Result<Option<RelayStreamLiveHandles>, RelayStreamMountError> {
    let now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync> = Arc::new(|| {
        crate::claw_share_session_clock::wall_now_secs("claw_share.relay_stream.mount")
    });
    mount_relay_stream_live_with_clock(
        state_dir,
        household,
        mesh_log,
        slots,
        replay,
        config,
        now_unix,
        shared_state,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn mount_relay_stream_live_with_clock(
    state_dir: PathBuf,
    household: HouseholdState,
    mesh_log: Arc<MeshLogStore>,
    slots: Arc<ClawShareSlotStore>,
    replay: Arc<ReplayGuard>,
    config: RelayStreamLiveConfig,
    now_unix: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
    shared_state: Option<SharedState>,
) -> Result<Option<RelayStreamLiveHandles>, RelayStreamMountError> {
    if !config.enabled {
        return Ok(None);
    }

    let Some(identity) = household.current().await else {
        tracing::warn!(stage = "claw_share.relay_stream.mount.no_identity");
        return Ok(None);
    };
    let household_id = identity.record.hh_id.clone();

    // The D6 resolver seam. Built once here, from the SAME worker-derived
    // household id above and the daemon's single `Arc<AppState>` — no second
    // identity and no second database handle. Absent `SharedState` (install /
    // bootstrap paths) leaves it `None`, and the Device arm then fails closed.
    let share_app_resolver: Option<ShareAppResolver> = shared_state.map(|state| {
        Arc::new(
            move |app_id: DeviceShareAppId,
                  hh_id: &str|
                  -> Result<ShareResolution, store_rs::StoreError> {
                crate::claw_share_app_descriptor::resolve_device_share_app(
                    &state.instance_db,
                    &app_id,
                    hh_id,
                )
            },
        ) as ShareAppResolver
    });
    let factory_household_id = household_id.to_string();
    let clawsite_router_factory: Arc<
        dyn Fn(&RelayStreamOfferContract) -> RelayStreamClawSiteRouter + Send + Sync,
    > = Arc::new(move |offer: &RelayStreamOfferContract| {
        clawsite_router_for_offer(offer, share_app_resolver.as_ref(), &factory_household_id)
    });

    let keystore_dir = state_dir
        .join("claw_share")
        .join(RELAY_STREAM_KEYSTORE_SUBDIR);
    let keystore = FileKeystore::new(&keystore_dir, RELAY_STREAM_KEYSTORE_SERVICE);

    // Temporal AUTHORITY seam: `None` means the wall clock is unusable (before
    // the epoch, exactly at it, or below the sanity floor) and every consumer
    // must fail closed. Never a sentinel — `unwrap_or(0)` here used to make
    // `not_after <= now` always false, i.e. nothing ever expired. Deliberately
    // NOT `time_util::unix_now_secs_checked`, which still returns `Some(0)` at
    // the epoch despite its name.
    let inputs = RelayStreamLiveInputs {
        state_dir,
        household,
        mesh_log,
        keystore_backend: &keystore,
        household_id,
        slots,
        replay,
        pty_router_factory: Arc::new(|| PtyTargetRouter::new(PtyPolicy::from_env())),
        clawsite_router_factory,
        refresh_trigger: Arc::new(Notify::new()),
        now_unix,
    };

    #[cfg(any(test, feature = "dev_t1_datapath"))]
    {
        return Ok(assemble_relay_stream_live_with_ip_tunnel_router(
            inputs,
            config,
            Arc::new(mounted_ip_tunnel_router_from_t1_gate),
        )
        .await?);
    }
    #[cfg(not(any(test, feature = "dev_t1_datapath")))]
    {
        Ok(assemble_relay_stream_live(inputs, config).await?)
    }
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
fn mounted_ip_tunnel_router_from_t1_gate() -> Arc<RelayStreamMountedIpTunnelRouter> {
    Arc::clone(
        MOUNTED_IP_TUNNEL_ROUTER
            .get_or_init(|| Arc::new(build_mounted_ip_tunnel_router_from_t1_gate())),
    )
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
fn build_mounted_ip_tunnel_router_from_t1_gate() -> RelayStreamMountedIpTunnelRouter {
    #[cfg(target_os = "linux")]
    {
        let status = assemble_linux_t1_ip_tunnel_router();
        if status.is_ready() {
            if let Some((_mode, router)) = status.into_ready() {
                return RelayStreamMountedIpTunnelRouter::T1Linux(Box::new(router));
            }
        } else {
            tracing::warn!(
                stage = "claw_share.relay_stream.mount.claw_vpn_t1_not_ready",
                status = ?status,
                "per-Claw VPN T1 IpTunnel backend remains unavailable"
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        let status = assemble_macos_t1_ip_tunnel_router();
        if status.is_ready() {
            if let Some((_mode, router)) = status.into_ready() {
                return RelayStreamMountedIpTunnelRouter::T1Macos(Box::new(router));
            }
        } else {
            tracing::warn!(
                stage = "claw_share.relay_stream.mount.claw_vpn_t1_not_ready",
                status = ?status,
                "per-Claw VPN T1 IpTunnel backend remains unavailable"
            );
        }
    }
    RelayStreamMountedIpTunnelRouter::Unavailable(RelayStreamIpTunnelUnavailableRouter)
}

#[cfg(all(any(test, feature = "dev_t1_datapath"), target_os = "linux"))]
fn assemble_linux_t1_ip_tunnel_router()
-> ClawVpnT1CallerStatus<ClawVpnT1RelayStreamBoxedRouter<ClawVpnLinuxTunDevice>> {
    assemble_t1_ip_tunnel_router(
        ClawVpnDevConfig::from_env,
        t1_preflight_evidence_bundle_from_env,
        linux_t1_build_inputs(),
        t1_runtime_launcher(),
    )
}

#[cfg(all(any(test, feature = "dev_t1_datapath"), target_os = "macos"))]
fn assemble_macos_t1_ip_tunnel_router()
-> ClawVpnT1CallerStatus<ClawVpnT1RelayStreamBoxedRouter<ClawVpnMacosUtunDevice>> {
    assemble_t1_ip_tunnel_router(
        ClawVpnDevConfig::from_env,
        t1_preflight_evidence_bundle_from_env,
        macos_t1_build_inputs(),
        t1_runtime_launcher(),
    )
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
fn assemble_t1_ip_tunnel_router<I, LoadConfig, LoadEvidence>(
    load_config: LoadConfig,
    load_evidence_bundle: LoadEvidence,
    build_inputs: ClawVpnT1RelayStreamBuildInputs<I>,
    launch_runtime: ClawVpnT1RelayStreamLaunchRuntime<I>,
) -> ClawVpnT1CallerStatus<ClawVpnT1RelayStreamBoxedRouter<I>>
where
    LoadConfig: FnOnce() -> Result<Option<ClawVpnDevConfig>, ClawVpnDevConfigError>,
    LoadEvidence: FnOnce() -> Option<PerClawVpnT1PreflightEvidenceBundle>,
{
    let evidence_bundle = Rc::new(RefCell::new(None));
    let preflight_bundle = Rc::clone(&evidence_bundle);
    let sink_bundle = Rc::clone(&evidence_bundle);
    assemble_claw_vpn_t1_relay_stream_router(
        load_config,
        move || {
            let bundle = load_evidence_bundle();
            let preflight = t1_preflight_evidence_or_missing(bundle.as_ref());
            *preflight_bundle.borrow_mut() = bundle;
            preflight
        },
        move |_config| {
            let bundle = sink_bundle.borrow();
            ClawVpnT1RelayStreamRouterParts::new(
                enabled_claw_vpn_t1_wiring_config(),
                CLAW_VPN_T1_TARGET_SESSION_IO_TIMEOUT,
                build_inputs,
                launch_runtime,
                t1_open_audit_sink_from_preflight(bundle.as_ref()),
            )
        },
    )
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
#[derive(Debug, thiserror::Error)]
enum ClawVpnT1MountedAuditSinkError {
    #[error("claw vpn t1 audit path unavailable")]
    Path(#[source] io::Error),

    #[error("claw vpn t1 audit sink unavailable")]
    Sink(#[source] ClawVpnT1AuditSinkError),
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
fn t1_preflight_evidence_bundle_from_env() -> Option<PerClawVpnT1PreflightEvidenceBundle> {
    let record_path = std::env::var_os(CLAW_VPN_T1_PREFLIGHT_EVIDENCE_RECORD_ENV)?;
    match load_per_claw_vpn_t1_preflight_evidence_record_for_current_build(record_path) {
        Ok(bundle) => Some(bundle),
        Err(error) => {
            tracing::warn!(
                stage = "claw_share.relay_stream.mount.claw_vpn_t1_preflight_evidence_unavailable",
                error = %error,
                "per-Claw VPN T1 evidence record did not validate for this build"
            );
            None
        }
    }
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
fn t1_preflight_evidence_or_missing(
    bundle: Option<&PerClawVpnT1PreflightEvidenceBundle>,
) -> PerClawVpnT1PreflightEvidence {
    bundle.map_or_else(PerClawVpnT1PreflightEvidence::missing, |bundle| {
        bundle.evidence()
    })
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
fn t1_open_audit_sink_from_preflight(
    bundle: Option<&PerClawVpnT1PreflightEvidenceBundle>,
) -> ClawVpnT1RelayStreamAuditSink {
    let Some(bundle) = bundle else {
        tracing::warn!(
            stage = "claw_share.relay_stream.mount.claw_vpn_t1_audit_sink_unavailable",
            "per-Claw VPN T1 evidence record is missing; audit sink remains unavailable"
        );
        return Box::new(|_event| Err("claw-vpn-t1-audit-sink-unavailable"));
    };
    match t1_spooled_audit_sink_from_root(bundle.audit_root()) {
        Ok(sink) => sink,
        Err(error) => {
            tracing::warn!(
                stage = "claw_share.relay_stream.mount.claw_vpn_t1_audit_sink_unavailable",
                error = %error,
                "per-Claw VPN T1 audit sink remains unavailable"
            );
            Box::new(|_event| Err("claw-vpn-t1-audit-sink-unavailable"))
        }
    }
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
fn t1_spooled_audit_sink_from_root(
    root: impl AsRef<Path>,
) -> Result<ClawVpnT1RelayStreamAuditSink, ClawVpnT1MountedAuditSinkError> {
    let audit_path =
        claw_vpn_t1_canonical_audit_log_path(root).map_err(ClawVpnT1MountedAuditSinkError::Path)?;
    claw_vpn_t1_spooled_jsonl_audit_sink(&audit_path).map_err(ClawVpnT1MountedAuditSinkError::Sink)
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
fn enabled_claw_vpn_t1_wiring_config() -> ClawVpnRuntimeWiringConfig {
    let defaults = ClawVpnRuntimeWiringConfig::default();
    ClawVpnRuntimeWiringConfig::new(
        true,
        defaults.runtime_step_budget(),
        defaults.driver_budget(),
    )
}

#[cfg(all(any(test, feature = "dev_t1_datapath"), target_os = "linux"))]
fn linux_t1_build_inputs() -> ClawVpnT1RelayStreamBuildInputs<ClawVpnLinuxTunDevice> {
    Box::new(|_config, _target, _context, relay| {
        let tun_name = ClawVpnLinuxTunName::new(CLAW_VPN_T1_LINUX_TUN_NAME)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let device = ClawVpnLinuxTunDevice::open(&ClawVpnLinuxTunConfig::new(tun_name))?;
        let interface_name = ClawVpnInterfaceName::new(device.name().as_str())
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        Ok(ClawVpnRuntimeWiringInputs {
            route_platform: ClawVpnInterfaceRoutePlatform::Linux,
            interface_name,
            route_tool_paths: claw_vpn_route_tool_paths()?,
            interface: device,
            relay,
        })
    })
}

#[cfg(all(any(test, feature = "dev_t1_datapath"), target_os = "macos"))]
fn macos_t1_build_inputs() -> ClawVpnT1RelayStreamBuildInputs<ClawVpnMacosUtunDevice> {
    Box::new(|_config, _target, _context, relay| {
        let device = ClawVpnMacosUtunDevice::open()?;
        let interface_name = ClawVpnInterfaceName::new(device.name().as_str())
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        Ok(ClawVpnRuntimeWiringInputs {
            route_platform: ClawVpnInterfaceRoutePlatform::Macos,
            interface_name,
            route_tool_paths: claw_vpn_route_tool_paths()?,
            interface: device,
            relay,
        })
    })
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
fn claw_vpn_route_tool_paths() -> io::Result<ClawVpnInterfaceRouteToolPaths> {
    ClawVpnInterfaceRouteToolPaths::try_new(
        CLAW_VPN_LINUX_IP_TOOL_PATH,
        CLAW_VPN_MACOS_IFCONFIG_TOOL_PATH,
        CLAW_VPN_MACOS_ROUTE_TOOL_PATH,
    )
    .map_err(|error| io::Error::other(format!("{error:?}")))
}

#[cfg(any(test, feature = "dev_t1_datapath"))]
fn t1_runtime_launcher<I>() -> ClawVpnT1RelayStreamLaunchRuntime<I>
where
    I: ClawVpnPacketInterface + Send + 'static,
{
    Box::new(|mut wiring: ClawVpnTargetSessionRouterWiring<I>| {
        tokio::task::spawn_blocking(move || {
            if let Err(error) = wiring.run_until_stopped() {
                tracing::warn!(
                    stage = "claw_share.relay_stream.mount.claw_vpn_t1_runtime_stopped",
                    error = ?error,
                    "per-Claw VPN T1 runtime stopped with an error"
                );
            }
        });
        Ok::<(), ClawVpnTargetSessionRouterLaunchError>(())
    })
}

/// Best-effort: when the live path is enabled, mint + store a `relay_stream` offer
/// for a just-consumed claim, so the pool can serve it after a restart/
/// re-assemble. Called from BOTH claim paths AFTER the `SlotConsumed` log is
/// durable, BEFORE the ack. A failure here NEVER affects the claim - it is logged
/// and swallowed.
///
/// Default-OFF via the same `THEYOS_RELAY_STREAM_LIVE` flag as the mount: OFF
/// returns before any household read / keystore / store access.
///
/// NOTE: the pool's resync driver re-reads the store on a 30s tick, slower than
/// the dialer's connect timeout, so the success arm below pulses an immediate
/// resync through the mounted live handles (when present) to serve the fresh
/// offer without waiting for the tick.
pub(crate) async fn try_provision_relay_stream_offer_for_claim(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    owner_key: &dyn IdentityKey,
    credential: &GuestCredential,
    now: u64,
) -> Option<RelayStreamOfferContract> {
    if !relay_stream_live_enabled_from_env() {
        return None;
    }
    match provision_relay_stream_offer_for_claim(
        state_dir, household, mesh_log, owner_key, credential, now,
    )
    .await
    {
        Ok(offer) => {
            if let Some(handles) = LIVE_HANDLES.get() {
                handles.trigger_resync();
            }
            Some(offer)
        }
        Err(error) => {
            tracing::warn!(
                stage = "claw_share.relay_stream.claim_provision_failed",
                error = %error,
                "relay_stream claim provisioning failed; claim unaffected",
            );
            None
        }
    }
}

/// Gated wrapper around [`provision_group_offer_for_claw`] for the Path-A Group
/// claim handler. Returns `None` when `THEYOS_RELAY_STREAM_LIVE` is unset
/// (default-off, same gate as [`try_provision_relay_stream_offer_for_claim`]) or
/// on provision failure, so the caller can fail closed without emitting an ack.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_provision_group_offer_for_claim(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    owner_key: &dyn IdentityKey,
    group_id: String,
    member_id: String,
    member_device_pub: P256PublicKey,
    claw_id: String,
    not_after: u64,
    now: u64,
) -> Option<RelayStreamOfferContract> {
    if !relay_stream_live_enabled_from_env() {
        return None;
    }
    match provision_group_offer_for_claw(
        state_dir,
        household,
        mesh_log,
        owner_key,
        group_id,
        member_id,
        member_device_pub,
        claw_id,
        not_after,
        now,
    )
    .await
    {
        Ok(offer) => Some(offer),
        Err(error) => {
            tracing::warn!(
                stage = "claw_share.relay_stream.group_provision_failed",
                error = %error,
                "relay_stream group offer provisioning failed; no ack emitted",
            );
            None
        }
    }
}

/// Shared loading for live-engine `relay_stream` offer provisioning: the live
/// trust seam (household record/cert + mesh-log projection), the responder's own
/// claw static Noise key, the relay endpoint, and the on-disk offer store. Used
/// by the claim (Device), group, and public provisioning paths so they all mint
/// against the SAME keystore key, endpoint, and store.
///
/// It selects NO resource — that decision belongs to each caller. It is also
/// NOT side-effect free: `get_or_create` writes a Noise key and the store load
/// touches the offer-store path, which is why callers that can reject a request
/// cheaply must do so BEFORE calling this.
async fn relay_stream_provision_context(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    now: u64,
) -> Result<
    (
        RelayStreamIssuerTrust,
        RelayStreamClawStaticPublicKey,
        String,
        RelayStreamOfferStore,
    ),
    RelayStreamClaimProvisionError,
> {
    let Some(identity) = household.current().await else {
        return Err(RelayStreamClaimProvisionError::NoIdentity);
    };
    let record = identity.record.clone();
    let cert = identity.cert.clone();
    let projection = mesh_log.project();
    let trust = RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
        record: record.clone(),
        cert: cert.clone(),
        projection: projection.clone(),
    });

    // Same keystore/service/key_id the responder mount uses, so the offer's
    // claw_static_pub is the key the responder will actually present.
    let keystore_dir = state_dir
        .join("claw_share")
        .join(RELAY_STREAM_KEYSTORE_SUBDIR);
    let keystore = FileKeystore::new(&keystore_dir, RELAY_STREAM_KEYSTORE_SERVICE);
    let keypair = RelayStreamNoiseKeyStore::new(&keystore)
        .get_or_create(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
        .map_err(|error| RelayStreamClaimProvisionError::Keystore(error.to_string()))?;
    let claw_static_pub = keypair.public_key().clone();

    let relay_endpoint = format!("relay-stream://{}", relay_stream_relay_endpoint());
    let store = RelayStreamOfferStore::load(state_dir, &trust, now)?;
    Ok((trust, claw_static_pub, relay_endpoint, store))
}

async fn provision_relay_stream_offer_for_claim(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    owner_key: &dyn IdentityKey,
    credential: &GuestCredential,
    now: u64,
) -> Result<RelayStreamOfferContract, RelayStreamClaimProvisionError> {
    // Decided FIRST, before any I/O. The mesh-log projection is the ONE source
    // for the snapshot: the slot is keyed by the credential's own `slot_id`, so
    // there is no string to parse and no namespace to infer. A slot that is
    // absent reads the same as a slot with no snapshot — both mean "no
    // Device+ClawSite share here".
    //
    // Ordering is load-bearing: `relay_stream_provision_context` writes a Noise
    // key and touches the offer store, so resolving this afterwards would let a
    // claim we are about to reject leave state behind on disk.
    let snapshot = mesh_log
        .project()
        .slots
        .get(&credential.slot_id)
        .and_then(|slot| slot.app_presentation.clone());
    let (resource, app_presentation) = resolve_claim_resource(snapshot)?;

    let (trust, claw_static_pub, relay_endpoint, mut store) =
        relay_stream_provision_context(state_dir, household, mesh_log, now).await?;
    let offer = provision_relay_stream_offer(
        &mut store,
        credential,
        resource,
        claw_static_pub,
        relay_endpoint,
        credential.expires_at,
        owner_key,
        &trust,
        now,
        app_presentation,
    )?;
    Ok(offer)
}

/// Fase E2.5: mint + store a GROUP `relay_stream` offer for one member device in
/// the live engine. Loads the same trust/keystore/store/endpoint as the claim
/// path. Authorized at DIAL time by live group membership; this only delivers it
/// to the store so the reverse-connect pool serves it. The TRIGGER (who calls
/// this — a member-request or dev-mint endpoint) and the secure delivery of the
/// returned offer to the dialer are the remaining E2.5 wiring.
#[allow(clippy::too_many_arguments)]
pub async fn provision_group_offer_for_claw(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    owner_key: &dyn IdentityKey,
    group_id: String,
    member_id: String,
    member_device_pub: P256PublicKey,
    claw_id: String,
    not_after: u64,
    now: u64,
) -> Result<RelayStreamOfferContract, RelayStreamClaimProvisionError> {
    let (trust, claw_static_pub, relay_endpoint, mut store) =
        relay_stream_provision_context(state_dir, household, mesh_log, now).await?;
    let offer = provision_relay_stream_group_offer(
        &mut store,
        group_id,
        member_id,
        member_device_pub,
        claw_id,
        // Pinned, never env-derived: `Pty` is forbidden for shared audiences by
        // contract policy, so an unset env used to make EVERY Group offer fail.
        // Group/Public stay in the legacy claw namespace and carry no snapshot.
        RelayStreamResource::ClawSite,
        claw_static_pub,
        relay_endpoint,
        not_after,
        owner_key,
        &trust,
        now,
    )?;
    Ok(offer)
}

/// Fase E3: mint + store a PUBLIC `relay_stream` offer for one dialer device in the
/// live engine. Authorized at DIAL time by the live published flag.
#[allow(clippy::too_many_arguments)]
pub async fn provision_public_offer_for_claw(
    state_dir: &Path,
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    owner_key: &dyn IdentityKey,
    dialer_device_pub: P256PublicKey,
    claw_id: String,
    not_after: u64,
    now: u64,
) -> Result<RelayStreamOfferContract, RelayStreamClaimProvisionError> {
    let (trust, claw_static_pub, relay_endpoint, mut store) =
        relay_stream_provision_context(state_dir, household, mesh_log, now).await?;
    let offer = provision_relay_stream_public_offer(
        &mut store,
        dialer_device_pub,
        claw_id,
        // Same pin as the Group path, same reason.
        RelayStreamResource::ClawSite,
        claw_static_pub,
        relay_endpoint,
        not_after,
        owner_key,
        &trust,
        now,
    )?;
    Ok(offer)
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamClaimProvisionError {
    #[error("no loaded household identity")]
    NoIdentity,

    #[error("relay stream noise keystore error: {0}")]
    Keystore(String),

    #[error("relay stream offer store error: {0}")]
    Store(#[from] RelayStreamOfferStoreError),

    #[error("relay stream provision error: {0}")]
    Provision(#[from] RelayStreamProvisionError),

    #[error("relay stream resource env error: {0}")]
    Resource(#[from] RelayStreamResourceEnvError),

    /// Product fail-closed: a Device claim whose slot carries no durable
    /// presentation snapshot (or whose slot is absent from the projection) has
    /// no Device+ClawSite share to serve. Only reachable in a build where the
    /// legacy/dev fallback is compiled out.
    #[error("device claim has no durable app presentation snapshot")]
    MissingAppPresentation,
}

#[derive(Debug, thiserror::Error)]
pub enum RelayStreamMountError {
    #[error("relay stream live assembly failed: {0}")]
    Assemble(#[from] RelayStreamLiveError),

    #[error("relay stream endpoint resolution failed: {0}")]
    RelayEndpoint(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relay_endpoint_resolution_accepts_literals_and_hostnames() {
        assert_eq!(
            resolve_relay_stream_relay_addr("127.0.0.1:49152")
                .await
                .unwrap(),
            "127.0.0.1:49152".parse::<SocketAddr>().unwrap()
        );

        let hostname = resolve_relay_stream_relay_addr("localhost:49152")
            .await
            .unwrap();
        assert!(hostname.ip().is_loopback());
        assert_eq!(hostname.port(), 49152);
    }

    #[tokio::test]
    async fn relay_endpoint_resolution_fails_closed() {
        assert!(matches!(
            resolve_relay_stream_relay_addr("   ").await,
            Err(RelayStreamMountError::RelayEndpoint(_))
        ));
        assert!(matches!(
            resolve_relay_stream_relay_addr("not a valid endpoint").await,
            Err(RelayStreamMountError::RelayEndpoint(_))
        ));
    }

    #[test]
    fn phase0_policy_rejects_ip_tunnel_before_mount_or_router_selection() {
        assert_eq!(
            parse_resource_for_policy(Some("IpTunnel"), false),
            Err(RelayStreamResourceEnvError::Invalid)
        );
        assert_eq!(
            parse_resource_for_policy(Some("pty"), false),
            Ok(RelayStreamResource::Pty)
        );
        assert_eq!(
            parse_resource_for_policy(Some("clawsite"), false),
            Ok(RelayStreamResource::ClawSite)
        );
    }

    use std::cell::Cell;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::claw_share_relay_stream_offer_store::relay_stream_offer_store_path;
    use crate::claw_share_relay_stream_test_support::{
        attacker_signer, guest_pub, now_unix, owner_signer, relay_stream_household_state,
        relay_stream_issuer_trust,
    };
    use crate::claw_vpn_dev_config::{
        CLAW_VPN_DIAL_ENV, CLAW_VPN_IPV4_POOL_ENV, CLAW_VPN_LIVE_ENV,
        CLAW_VPN_MAX_SESSIONS_PER_CLAW_ENV, CLAW_VPN_MAX_SESSIONS_PER_MEMBER_CLAW_ENV,
        CLAW_VPN_RELAY_ENDPOINT_ENV,
    };
    use crate::claw_vpn_t1_relay_stream_router::{
        CLAW_VPN_T1_AUDIT_LOG_DIRECTORY_NAME, CLAW_VPN_T1_AUDIT_LOG_FILE_NAME,
    };
    use crate::startup_wiring::{
        PER_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_SCHEMA, theyos_server_build_git_sha,
    };

    static CLAW_VPN_T1_TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TestEnvRestore {
        key: &'static str,
        previous: Option<OsString>,
    }

    #[allow(unsafe_code)]
    impl Drop for TestEnvRestore {
        fn drop(&mut self) {
            // SAFETY: tests that mutate these env vars hold
            // CLAW_VPN_T1_TEST_ENV_LOCK until this guard restores them.
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[allow(unsafe_code)]
    fn set_t1_test_env(key: &'static str, value: Option<&str>) -> TestEnvRestore {
        let previous = std::env::var_os(key);
        // SAFETY: callers hold CLAW_VPN_T1_TEST_ENV_LOCK while mutating these
        // process env vars.
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        TestEnvRestore { key, previous }
    }

    fn share_app_id() -> String {
        format!("app_{:032x}", 0x5eed_u128)
    }

    fn share_app_presentation() -> ShareableAppPresentation {
        ShareableAppPresentation::try_new(share_app_id(), "Study", "Caio").unwrap()
    }

    /// A credential for a Device+ClawSite share: its `claw_id` IS the app id, so
    /// the signed offer satisfies the presentation fence
    /// (`presentation.app_id == claw_id`) honestly rather than by relaxing it.
    fn share_app_credential() -> GuestCredential {
        let owner = owner_signer();
        let issued_at = now_unix().saturating_sub(60);
        GuestCredential::sign(
            household_rs::ids::derive_household_id(&owner.public()),
            household_rs::person_cert::derive_person_id(&owner.public()),
            owner.public(),
            share_app_id(),
            crate::claw_share_relay_stream_test_support::guest_signer().public(),
            crate::claw_share_relay_stream_test_support::DATA_TUNNEL_SLOT,
            issued_at,
            issued_at + 86_400,
            &owner,
        )
        .unwrap()
    }

    /// Seed the DURABLE source the claim path reads: a real owner-signed
    /// `ClawShareSlotMinted` for the slot this credential names. Passing
    /// `None` seeds a slot that exists but carries no snapshot.
    fn seed_minted_slot(
        mesh_log: &MeshLogStore,
        credential: &GuestCredential,
        presentation: Option<ShareableAppPresentation>,
    ) {
        let owner = owner_signer();
        let entry = household_rs::household_mesh_log::build_slot_mint_event_with_presentation(
            credential.slot_id.clone(),
            credential.claw_id.clone(),
            credential.expires_at,
            now_unix(),
            owner.public(),
            &owner,
            presentation,
        )
        .unwrap();
        mesh_log.append(entry).unwrap();
    }

    #[test]
    fn snapshot_selects_clawsite_and_ignores_any_dev_fallback() {
        let presentation = share_app_presentation();
        // Hostile fallback: even asked for Pty, a slot WITH a snapshot must
        // mint ClawSite. This is the "env cannot steer the Some path" property,
        // proven without touching process state at all.
        for fallback in [
            None,
            Some(RelayStreamResource::Pty),
            Some(RelayStreamResource::ClawSite),
        ] {
            let (resource, snapshot) =
                select_resource_and_snapshot(Some(presentation.clone()), fallback).unwrap();
            assert_eq!(resource, RelayStreamResource::ClawSite);
            assert_eq!(snapshot.as_ref(), Some(&presentation));
        }
    }

    #[test]
    fn no_snapshot_without_dev_fallback_fails_closed() {
        // The product build's behavior, executable here because the call site
        // gates `dev_fallback` on the feature alone.
        assert!(matches!(
            select_resource_and_snapshot(None, None),
            Err(RelayStreamClaimProvisionError::MissingAppPresentation)
        ));
    }

    #[test]
    fn no_snapshot_with_dev_fallback_is_the_legacy_path() {
        // The dev/test fixture: legacy claims still mint, carrying no snapshot.
        let (resource, snapshot) =
            select_resource_and_snapshot(None, Some(RelayStreamResource::Pty)).unwrap();
        assert_eq!(resource, RelayStreamResource::Pty);
        assert!(snapshot.is_none());
    }

    #[test]
    fn dev_env_helper_parses_the_dev_var() {
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let _env = set_t1_test_env(DEV_RELAY_STREAM_RESOURCE_ENV, Some("clawsite"));
        assert_eq!(
            dev_relay_stream_resource_from_env(),
            Ok(RelayStreamResource::ClawSite)
        );
    }

    /// Default (product-shaped) build: no fallback is compiled in, so a claim
    /// without a snapshot fails closed at the real call site, not just in the
    /// pure selector.
    #[cfg(not(feature = "dev_claw_share_mint"))]
    #[test]
    fn product_call_site_fails_closed_without_a_snapshot() {
        assert!(matches!(
            resolve_claim_resource(None),
            Err(RelayStreamClaimProvisionError::MissingAppPresentation)
        ));
        let presentation = share_app_presentation();
        let (resource, snapshot) = resolve_claim_resource(Some(presentation.clone())).unwrap();
        assert_eq!(resource, RelayStreamResource::ClawSite);
        assert_eq!(snapshot.as_ref(), Some(&presentation));
    }

    /// Feature build: the env is read ONLY when there is no snapshot.
    /// Run with `--features dev_claw_share_mint`.
    #[cfg(feature = "dev_claw_share_mint")]
    #[test]
    fn dev_env_is_read_lazily_and_cannot_break_a_snapshot_claim() {
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let _env = set_t1_test_env(DEV_RELAY_STREAM_RESOURCE_ENV, Some("garbage"));

        // Non-vacuity first: with NO snapshot the garbage IS read and rejected,
        // proving this test can actually see the env at this call site.
        assert!(matches!(
            resolve_claim_resource(None),
            Err(RelayStreamClaimProvisionError::Resource(
                RelayStreamResourceEnvError::Invalid
            ))
        ));

        // The property: the same garbage env must not touch a claim that has a
        // snapshot. Eagerly evaluating the env would fail this.
        let presentation = share_app_presentation();
        let (resource, snapshot) = resolve_claim_resource(Some(presentation.clone()))
            .expect("a snapshot claim must not consult the dev env");
        assert_eq!(resource, RelayStreamResource::ClawSite);
        assert_eq!(snapshot.as_ref(), Some(&presentation));
    }

    #[test]
    fn env_flag_parses_only_explicit_truthy_values() {
        assert!(parse_enabled(Some("1")));
        assert!(parse_enabled(Some("true")));
        assert!(parse_enabled(Some("TRUE")));
        assert!(!parse_enabled(Some("0")));
        assert!(!parse_enabled(Some("false")));
        assert!(!parse_enabled(Some("yes")));
        assert!(!parse_enabled(Some("")));
        assert!(!parse_enabled(None));
    }

    #[tokio::test]
    async fn clawsite_router_unconfigured_fails_closed() {
        let router = RelayStreamClawSiteRouter::Legacy(LegacyClawSiteRouter { backend_addr: None });
        // `TargetSession` is not `Debug`, so match instead of `unwrap_err`.
        let error = match router.open("claw_alpha").await {
            Ok(_) => panic!("unconfigured clawsite router must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            DataTunnelError::TargetUnavailable(reason)
                if reason == "relay-stream-clawsite-not-configured"
        ));
    }

    #[tokio::test]
    async fn clawsite_router_configured_forwards_to_backend() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // A backend that echoes a prefix proves the router splices bytes both ways.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let mut response = b"SITE:".to_vec();
                response.extend_from_slice(&buf[..n]);
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            }
        });

        let router = RelayStreamClawSiteRouter::Legacy(LegacyClawSiteRouter {
            backend_addr: Some(addr),
        });
        let mut session = router.open("claw_alpha").await.unwrap();
        session.writer.write_all(b"ping").await.unwrap();
        session.writer.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let n = session.reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"SITE:ping");
    }

    // ── 4B-2-3: offer-aware ClawSite routing ────────────────────────────────

    fn share_app_id_for_router() -> String {
        format!("app_{:032x}", 0x5eed_u128)
    }

    /// Build a signed offer with a chosen audience and `claw_id`. The factory
    /// never verifies — that is `validate_target_for_resource`'s job downstream
    /// — so this only needs to be well-formed.
    fn offer_with(
        audience: Option<RelayStreamAudience>,
        claw_id: &str,
    ) -> RelayStreamOfferContract {
        use crate::claw_share_relay_stream_contract::{
            RelayStreamExpectedPath, RelayStreamOfferPayload,
        };
        use crate::claw_share_rendezvous_stream_relay::RendezvousToken;

        let payload = RelayStreamOfferPayload::new(
            RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
            claw_id.to_string(),
            crate::claw_share_relay_stream_test_support::DATA_TUNNEL_SLOT,
            guest_pub(),
            RelayStreamResource::ClawSite,
            RelayStreamExpectedPath::RelayStream,
            "relay-stream://127.0.0.1:49152".to_string(),
            RelayStreamClawStaticPublicKey::try_new([0x33; 32]).unwrap(),
            now_unix() + 60,
        );
        let payload = match audience {
            Some(audience) => payload.with_authz(audience),
            None => payload,
        };
        RelayStreamOfferContract::sign(payload, &owner_signer()).unwrap()
    }

    /// What the router actually handed the resolver, so a test can prove the
    /// identity was not swapped on the way in.
    type ResolverCalls = Arc<std::sync::Mutex<Vec<(String, String)>>>;

    /// A resolver that records every `(app_id, household_id)` it was called with
    /// and returns a fixed answer.
    fn counting_resolver(
        answer: Arc<dyn Fn() -> Result<ShareResolution, store_rs::StoreError> + Send + Sync>,
        seen: ResolverCalls,
    ) -> ShareAppResolver {
        Arc::new(move |app_id, hh_id| {
            seen.lock()
                .expect("resolver call log")
                .push((app_id.as_str().to_string(), hh_id.to_string()));
            answer()
        })
    }

    fn call_count(seen: &ResolverCalls) -> usize {
        seen.lock().expect("resolver call log").len()
    }

    fn expect_fail_closed(result: Result<TargetSession, DataTunnelError>, expected_code: &str) {
        let error = match result {
            Ok(_) => panic!("must fail closed, got a session"),
            Err(error) => error,
        };
        let DataTunnelError::TargetUnavailable(code) = &error else {
            panic!("expected TargetUnavailable, got {error:?}");
        };
        assert_eq!(code, expected_code, "internal reason code must be exact");
        // Pins the `DataTunnelError` Display exactly — that string is what the
        // existing `serve_data_tunnel_core` call site passes to
        // `TunnelFrame::Error`. This test does NOT run the shared core, so it
        // proves the rendering, not the frame round-trip. Whole-string, never
        // `contains`, so a widened reason cannot slip through.
        assert_eq!(
            error
                .to_string()
                .strip_prefix("target service unavailable: "),
            Some(expected_code),
            "rendered reason must be the prefix plus exactly this code"
        );
    }

    #[test]
    fn clawsite_factory_routes_by_signed_audience_never_by_claw_id_shape() {
        let app_shaped = share_app_id_for_router();
        let calls: ResolverCalls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let resolver = counting_resolver(
            Arc::new(|| Ok(ShareResolution::Terminal)),
            Arc::clone(&calls),
        );

        // Device + resolver ⇒ the D6 path.
        assert!(matches!(
            clawsite_router_for_offer(&offer_with(None, &app_shaped), Some(&resolver), "hh_alpha"),
            RelayStreamClawSiteRouter::DeviceShare(_)
        ));

        // ADVERSARIAL: the SAME app-shaped claw_id under a shared audience must
        // still be legacy. Routing reads the signed audience, never the shape.
        for audience in [
            RelayStreamAudience::Group {
                group_id: "g".to_string(),
                member_id: "m".to_string(),
            },
            RelayStreamAudience::Public,
        ] {
            assert!(
                matches!(
                    clawsite_router_for_offer(
                        &offer_with(Some(audience.clone()), &app_shaped),
                        Some(&resolver),
                        "hh_alpha"
                    ),
                    RelayStreamClawSiteRouter::Legacy(_)
                ),
                "{audience:?} with an app-shaped claw_id must stay legacy"
            );
        }

        // Device WITHOUT a resolver fails closed rather than falling back.
        assert!(matches!(
            clawsite_router_for_offer(&offer_with(None, &app_shaped), None, "hh_alpha"),
            RelayStreamClawSiteRouter::Unresolvable
        ));

        // Product-shaped build (the default `cargo test` compiles the same arm
        // production does): the legacy namespace has no configurable backend at
        // all, so Group/Public come out unconfigured and fail closed on dial.
        #[cfg(not(feature = "dev_claw_share_mint"))]
        {
            let legacy = clawsite_router_for_offer(
                &offer_with(Some(RelayStreamAudience::Public), &app_shaped),
                Some(&resolver),
                "hh_alpha",
            );
            assert!(matches!(
                legacy,
                RelayStreamClawSiteRouter::Legacy(LegacyClawSiteRouter { backend_addr: None })
            ));
        }

        assert_eq!(
            call_count(&calls),
            0,
            "construction must not resolve: no store access before authorization"
        );
    }

    #[tokio::test]
    async fn device_share_router_dials_the_exact_resolved_port_once() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let mut response = b"APP:".to_vec();
                response.extend_from_slice(&buf[..n]);
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            }
        });

        let app_id = share_app_id_for_router();
        let descriptor = crate::claw_share_app_descriptor::ShareableAppDescriptor {
            app_id: DeviceShareAppId::try_from(app_id.as_str()).unwrap(),
            claw_id: DeviceShareAppId::try_from(app_id.as_str()).unwrap(),
            display_name: "Study".to_string(),
            resource: crate::claw_share_app_descriptor::ShareAppResource::ClawSite,
            readiness: crate::claw_share_app_descriptor::ShareReadiness::Running,
        };
        let ready = crate::claw_share_app_descriptor::ShareReadyApp {
            descriptor,
            backend_port: port,
        };
        let calls: ResolverCalls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let resolver = counting_resolver(
            Arc::new(move || Ok(ShareResolution::Ready(ready.clone()))),
            Arc::clone(&calls),
        );
        let router = RelayStreamClawSiteRouter::DeviceShare(DeviceShareClawSiteRouter {
            resolve: resolver,
            household_id: "hh_alpha".to_string(),
        });

        let mut session = router.open(&app_id).await.unwrap();
        session.writer.write_all(b"ping").await.unwrap();
        session.writer.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let n = session.reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"APP:ping");

        // Exactly one resolution, with exactly the identity that came in: the
        // target's own app_id and the router's household. Without this a
        // mutation that swapped either argument before the call would pass.
        let seen = calls.lock().expect("resolver call log").clone();
        assert_eq!(
            seen,
            vec![(app_id.clone(), "hh_alpha".to_string())],
            "the port must come from ONE resolution of the exact (app_id, household_id)"
        );
    }

    #[tokio::test]
    async fn device_share_router_reasons_are_exact_and_faults_fail_closed() {
        let app_id = share_app_id_for_router();
        let calls: ResolverCalls = Arc::new(std::sync::Mutex::new(Vec::new()));

        let descriptor = crate::claw_share_app_descriptor::ShareableAppDescriptor {
            app_id: DeviceShareAppId::try_from(app_id.as_str()).unwrap(),
            claw_id: DeviceShareAppId::try_from(app_id.as_str()).unwrap(),
            display_name: "Study".to_string(),
            resource: crate::claw_share_app_descriptor::ShareAppResource::ClawSite,
            readiness: crate::claw_share_app_descriptor::ShareReadiness::Unavailable,
        };
        let unavailable = descriptor.clone();
        let router = RelayStreamClawSiteRouter::DeviceShare(DeviceShareClawSiteRouter {
            resolve: counting_resolver(
                Arc::new(move || Ok(ShareResolution::Unavailable(unavailable.clone()))),
                Arc::clone(&calls),
            ),
            household_id: "hh_alpha".to_string(),
        });
        expect_fail_closed(router.open(&app_id).await, SHARE_APP_UNAVAILABLE);

        // Terminal, a store fault, and a resolver PANIC are one wire outcome:
        // splitting them would turn the reason into an app-id existence oracle.
        let terminal = RelayStreamClawSiteRouter::DeviceShare(DeviceShareClawSiteRouter {
            resolve: counting_resolver(
                Arc::new(|| Ok(ShareResolution::Terminal)),
                Arc::clone(&calls),
            ),
            household_id: "hh_alpha".to_string(),
        });
        expect_fail_closed(terminal.open(&app_id).await, SHARE_APP_GONE);

        let store_fault = RelayStreamClawSiteRouter::DeviceShare(DeviceShareClawSiteRouter {
            resolve: counting_resolver(
                Arc::new(|| Err(store_rs::StoreError::Internal("boom".to_string()))),
                Arc::clone(&calls),
            ),
            household_id: "hh_alpha".to_string(),
        });
        expect_fail_closed(store_fault.open(&app_id).await, SHARE_APP_GONE);

        let panicking = RelayStreamClawSiteRouter::DeviceShare(DeviceShareClawSiteRouter {
            resolve: Arc::new(|_app, _hh| panic!("resolver exploded")),
            household_id: "hh_alpha".to_string(),
        });
        expect_fail_closed(panicking.open(&app_id).await, SHARE_APP_GONE);

        // A target that is not a D6 id never reaches the resolver at all.
        let before = call_count(&calls);
        let malformed = RelayStreamClawSiteRouter::DeviceShare(DeviceShareClawSiteRouter {
            resolve: counting_resolver(
                Arc::new(|| Ok(ShareResolution::Terminal)),
                Arc::clone(&calls),
            ),
            household_id: "hh_alpha".to_string(),
        });
        expect_fail_closed(malformed.open("claw_alpha").await, SHARE_APP_GONE);
        assert_eq!(
            call_count(&calls),
            before,
            "a malformed target must not reach the store"
        );
    }

    #[tokio::test]
    async fn unresolvable_device_offer_is_indistinguishable_from_a_dead_app() {
        expect_fail_closed(
            RelayStreamClawSiteRouter::Unresolvable
                .open(&share_app_id_for_router())
                .await,
            SHARE_APP_GONE,
        );
    }

    #[test]
    fn resource_env_parses_clawsite_else_pty() {
        assert_eq!(
            parse_resource(Some("clawsite")),
            Ok(RelayStreamResource::ClawSite)
        );
        assert_eq!(
            parse_resource(Some(" ClawSite ")),
            Ok(RelayStreamResource::ClawSite)
        );
        assert_eq!(
            parse_resource(Some("CLAWSITE")),
            Ok(RelayStreamResource::ClawSite)
        );
        assert_eq!(
            parse_resource(Some("ip_tunnel")),
            Ok(RelayStreamResource::IpTunnel)
        );
        assert_eq!(
            parse_resource(Some("IpTunnel")),
            Ok(RelayStreamResource::IpTunnel)
        );
        assert_eq!(parse_resource(Some("pty")), Ok(RelayStreamResource::Pty));
        assert_eq!(parse_resource(None), Ok(RelayStreamResource::Pty));
        assert_eq!(
            parse_resource(Some("garbage")),
            Err(RelayStreamResourceEnvError::Invalid)
        );
    }

    fn t1_preflight_evidence_json(artifact_sha: &str, audit_root: &Path) -> String {
        serde_json::json!({
            "schema": PER_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_SCHEMA,
            "artifact_sha": artifact_sha,
            "scope": "dev-host T1-T4 only",
            "production_activation": false,
            "owner_authorization": true,
            "owner_authorization_ref": "owner-authorization-alpha",
            "rollback": true,
            "rollback_ref": "rollback-artifact-alpha",
            "hardware_t1_t4": true,
            "hardware_evidence_ref": "evidence-pack-t1-t4-alpha",
            "audit_root": audit_root.to_str().unwrap(),
        })
        .to_string()
    }

    fn write_t1_preflight_evidence_record(
        dir: &Path,
        artifact_sha: &str,
        audit_root: &Path,
    ) -> PathBuf {
        let record_path = dir.join("t1-preflight-evidence.json");
        std::fs::write(
            &record_path,
            t1_preflight_evidence_json(artifact_sha, audit_root),
        )
        .unwrap();
        record_path
    }

    fn write_t1_preflight_evidence_record_body(dir: &Path, name: &str, body: String) -> PathBuf {
        let record_path = dir.join(name);
        std::fs::write(&record_path, body).unwrap();
        record_path
    }

    fn set_mounted_t1_live_test_env(record_path: Option<&str>) -> Vec<TestEnvRestore> {
        vec![
            set_t1_test_env(CLAW_VPN_T1_PREFLIGHT_EVIDENCE_RECORD_ENV, record_path),
            set_t1_test_env(CLAW_VPN_LIVE_ENV, Some("1")),
            set_t1_test_env(CLAW_VPN_DIAL_ENV, None),
            set_t1_test_env(
                CLAW_VPN_RELAY_ENDPOINT_ENV,
                Some("relay-stream://127.0.0.1:49152"),
            ),
            set_t1_test_env(CLAW_VPN_IPV4_POOL_ENV, Some("198.18.0.0/24")),
            set_t1_test_env(CLAW_VPN_MAX_SESSIONS_PER_MEMBER_CLAW_ENV, None),
            set_t1_test_env(CLAW_VPN_MAX_SESSIONS_PER_CLAW_ENV, None),
        ]
    }

    struct TestPacketInterface;

    impl ClawVpnPacketInterface for TestPacketInterface {
        fn read_packet(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            panic!("test packet interface must not read packets");
        }

        fn write_packet(&mut self, _packet: &[u8]) -> io::Result<()> {
            panic!("test packet interface must not write packets");
        }
    }

    fn counting_t1_build_inputs(
        build_count: Arc<AtomicUsize>,
    ) -> ClawVpnT1RelayStreamBuildInputs<TestPacketInterface> {
        Box::new(move |_config, _target, _context, _relay| {
            build_count.fetch_add(1, Ordering::SeqCst);
            panic!("test T1 build inputs must not be called")
        })
    }

    fn counting_t1_runtime_launcher(
        launch_count: Arc<AtomicUsize>,
    ) -> ClawVpnT1RelayStreamLaunchRuntime<TestPacketInterface> {
        Box::new(move |_wiring| {
            launch_count.fetch_add(1, Ordering::SeqCst);
            panic!("test T1 runtime launcher must not be called")
        })
    }

    fn t1_target_for_mount_test() -> RelayStreamIpTunnelTarget {
        RelayStreamIpTunnelTarget::new_for_test(
            "group-alpha",
            "member-alpha",
            guest_pub(),
            "claw-alpha",
        )
    }

    #[test]
    fn t1_mount_missing_evidence_keeps_preflight_missing() {
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let _record = set_t1_test_env(CLAW_VPN_T1_PREFLIGHT_EVIDENCE_RECORD_ENV, None);
        let evidence = t1_preflight_evidence_or_missing(None);

        assert!(!evidence.has_owner_authorization());
        assert!(!evidence.has_rollback());
        assert!(!evidence.has_hardware_t1_t4());
    }

    #[test]
    fn t1_mount_does_not_load_evidence_when_config_disabled_or_invalid() {
        let disabled_loads = Rc::new(Cell::new(0));
        let disabled_build_count = Arc::new(AtomicUsize::new(0));
        let disabled_launch_count = Arc::new(AtomicUsize::new(0));
        let disabled_loads_for_closure = Rc::clone(&disabled_loads);
        let disabled = assemble_t1_ip_tunnel_router(
            || Ok(None),
            move || {
                disabled_loads_for_closure.set(disabled_loads_for_closure.get() + 1);
                None
            },
            counting_t1_build_inputs(Arc::clone(&disabled_build_count)),
            counting_t1_runtime_launcher(Arc::clone(&disabled_launch_count)),
        );
        assert!(matches!(disabled, ClawVpnT1CallerStatus::Disabled));
        assert_eq!(disabled_loads.get(), 0);
        assert_eq!(disabled_build_count.load(Ordering::SeqCst), 0);
        assert_eq!(disabled_launch_count.load(Ordering::SeqCst), 0);

        let invalid_loads = Rc::new(Cell::new(0));
        let invalid_build_count = Arc::new(AtomicUsize::new(0));
        let invalid_launch_count = Arc::new(AtomicUsize::new(0));
        let invalid_loads_for_closure = Rc::clone(&invalid_loads);
        let invalid = assemble_t1_ip_tunnel_router(
            || ClawVpnDevConfig::from_values(Some("1"), Some("1"), None, None, None, None),
            move || {
                invalid_loads_for_closure.set(invalid_loads_for_closure.get() + 1);
                None
            },
            counting_t1_build_inputs(Arc::clone(&invalid_build_count)),
            counting_t1_runtime_launcher(Arc::clone(&invalid_launch_count)),
        );
        assert!(matches!(invalid, ClawVpnT1CallerStatus::InvalidConfig));
        assert_eq!(invalid_loads.get(), 0);
        assert_eq!(invalid_build_count.load(Ordering::SeqCst), 0);
        assert_eq!(invalid_launch_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn t1_mount_audit_sink_uses_canonical_root_and_spooled_log() {
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("audit-root");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

        let _sink = t1_spooled_audit_sink_from_root(&root).unwrap();

        let audit_path = root
            .join(CLAW_VPN_T1_AUDIT_LOG_DIRECTORY_NAME)
            .join(CLAW_VPN_T1_AUDIT_LOG_FILE_NAME);
        assert_eq!(
            std::fs::metadata(audit_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn mounted_t1_iptunnel_router_missing_preflight_does_not_create_audit_log() {
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("audit-root");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _record = set_t1_test_env(CLAW_VPN_T1_PREFLIGHT_EVIDENCE_RECORD_ENV, None);
        let _live = set_t1_test_env(CLAW_VPN_LIVE_ENV, Some("1"));
        let _dial = set_t1_test_env(CLAW_VPN_DIAL_ENV, None);
        let _endpoint = set_t1_test_env(
            CLAW_VPN_RELAY_ENDPOINT_ENV,
            Some("relay-stream://127.0.0.1:49152"),
        );
        let _pool = set_t1_test_env(CLAW_VPN_IPV4_POOL_ENV, Some("198.18.0.0/24"));
        let _per_member = set_t1_test_env(CLAW_VPN_MAX_SESSIONS_PER_MEMBER_CLAW_ENV, None);
        let _per_claw = set_t1_test_env(CLAW_VPN_MAX_SESSIONS_PER_CLAW_ENV, None);

        let router = build_mounted_ip_tunnel_router_from_t1_gate();

        assert!(matches!(
            router,
            RelayStreamMountedIpTunnelRouter::Unavailable(_)
        ));
        let audit_path = root
            .join(CLAW_VPN_T1_AUDIT_LOG_DIRECTORY_NAME)
            .join(CLAW_VPN_T1_AUDIT_LOG_FILE_NAME);
        assert!(!audit_path.exists());
    }

    #[test]
    fn mounted_t1_iptunnel_router_rejects_missing_stale_and_incomplete_evidence_records() {
        let Some(artifact_sha) = theyos_server_build_git_sha() else {
            return;
        };
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let stale_sha = if artifact_sha == "0000000000000000000000000000000000000000" {
            "1111111111111111111111111111111111111111"
        } else {
            "0000000000000000000000000000000000000000"
        };

        fn assert_unavailable_for_record(name: &str, record_path: &Path) {
            let _env = set_mounted_t1_live_test_env(record_path.to_str());
            let router = build_mounted_ip_tunnel_router_from_t1_gate();
            assert!(
                matches!(router, RelayStreamMountedIpTunnelRouter::Unavailable(_)),
                "{name} evidence must keep mounted T1 unavailable"
            );
        }

        let missing_dir = tempfile::tempdir().unwrap();
        assert_unavailable_for_record(
            "missing",
            &missing_dir
                .path()
                .join("missing-t1-preflight-evidence.json"),
        );

        let stale_dir = tempfile::tempdir().unwrap();
        let stale_root = std::fs::canonicalize(stale_dir.path())
            .unwrap()
            .join("audit-root");
        std::fs::create_dir(&stale_root).unwrap();
        std::fs::set_permissions(&stale_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let stale_path =
            write_t1_preflight_evidence_record(stale_dir.path(), stale_sha, &stale_root);
        assert_unavailable_for_record("stale", &stale_path);

        let incomplete_dir = tempfile::tempdir().unwrap();
        let incomplete_root = std::fs::canonicalize(incomplete_dir.path())
            .unwrap()
            .join("audit-root");
        std::fs::create_dir(&incomplete_root).unwrap();
        std::fs::set_permissions(&incomplete_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let incomplete_body = serde_json::json!({
            "schema": PER_CLAW_VPN_T1_PREFLIGHT_EVIDENCE_SCHEMA,
            "artifact_sha": artifact_sha,
            "scope": "dev-host T1-T4 only",
            "production_activation": false,
            "owner_authorization": true,
            "owner_authorization_ref": "owner-authorization-alpha",
            "rollback": false,
            "rollback_ref": "",
            "hardware_t1_t4": true,
            "hardware_evidence_ref": "evidence-pack-t1-t4-alpha",
            "audit_root": incomplete_root.to_str().unwrap(),
        })
        .to_string();
        let incomplete_path = write_t1_preflight_evidence_record_body(
            incomplete_dir.path(),
            "incomplete-t1-preflight-evidence.json",
            incomplete_body,
        );
        assert_unavailable_for_record("incomplete", &incomplete_path);
    }

    #[test]
    fn mounted_t1_iptunnel_router_uses_sha_bound_evidence_audit_root() {
        let Some(artifact_sha) = theyos_server_build_git_sha() else {
            return;
        };
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("audit-root");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let record_path = write_t1_preflight_evidence_record(dir.path(), artifact_sha, &root);

        let _env = set_mounted_t1_live_test_env(Some(record_path.to_str().unwrap()));

        let router = build_mounted_ip_tunnel_router_from_t1_gate();

        #[cfg(target_os = "linux")]
        assert!(matches!(
            router,
            RelayStreamMountedIpTunnelRouter::T1Linux(_)
        ));
        #[cfg(target_os = "macos")]
        assert!(matches!(
            router,
            RelayStreamMountedIpTunnelRouter::T1Macos(_)
        ));
        let audit_path = root
            .join(CLAW_VPN_T1_AUDIT_LOG_DIRECTORY_NAME)
            .join(CLAW_VPN_T1_AUDIT_LOG_FILE_NAME);
        assert_eq!(
            std::fs::metadata(audit_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn mounted_t1_iptunnel_router_rejects_invalid_audit_root_before_build_or_launch() {
        let Some(artifact_sha) = theyos_server_build_git_sha() else {
            return;
        };
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("audit-root");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let record_path = write_t1_preflight_evidence_record(dir.path(), artifact_sha, &root);
        let _env = set_mounted_t1_live_test_env(Some(record_path.to_str().unwrap()));
        let build_count = Arc::new(AtomicUsize::new(0));
        let launch_count = Arc::new(AtomicUsize::new(0));
        let status = assemble_t1_ip_tunnel_router(
            ClawVpnDevConfig::from_env,
            t1_preflight_evidence_bundle_from_env,
            counting_t1_build_inputs(Arc::clone(&build_count)),
            counting_t1_runtime_launcher(Arc::clone(&launch_count)),
        );
        let Some((_mode, router)) = status.into_ready() else {
            panic!(
                "valid preflight evidence with invalid audit root must still assemble the gated router"
            );
        };

        let error = match router.open_ip_tunnel(t1_target_for_mount_test()).await {
            Ok(_) => panic!("invalid audit root must fail closed before opening T1"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            DataTunnelError::TargetUnavailable(reason)
                if reason == "claw-vpn-t1-audit-sink-unavailable"
        ));
        assert_eq!(build_count.load(Ordering::SeqCst), 0);
        assert_eq!(launch_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mounted_t1_iptunnel_router_remains_unavailable_without_preflight_evidence() {
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let _env = set_mounted_t1_live_test_env(None);

        let router = build_mounted_ip_tunnel_router_from_t1_gate();

        assert!(matches!(
            router,
            RelayStreamMountedIpTunnelRouter::Unavailable(_)
        ));
    }

    #[test]
    fn mounted_t1_iptunnel_router_factory_reuses_process_router() {
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let _env = set_mounted_t1_live_test_env(None);

        let first = mounted_ip_tunnel_router_from_t1_gate();
        let second = mounted_ip_tunnel_router_from_t1_gate();

        assert!(Arc::ptr_eq(&first, &second));
        assert!(matches!(
            first.as_ref(),
            RelayStreamMountedIpTunnelRouter::Unavailable(_)
        ));
    }

    #[tokio::test]
    async fn mount_disabled_config_is_noop_and_touches_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let config = RelayStreamLiveConfig::default(); // enabled == false

        let result = mount_relay_stream_live(
            dir.path().to_path_buf(),
            relay_stream_household_state(),
            Arc::new(MeshLogStore::new()),
            Arc::new(ClawShareSlotStore::new()),
            Arc::new(ReplayGuard::new()),
            config,
            None,
        )
        .await
        .unwrap();

        assert!(result.is_none());
        // Disabled path must not create the keystore subdir or the offer store.
        assert!(
            !dir.path()
                .join("claw_share")
                .join(RELAY_STREAM_KEYSTORE_SUBDIR)
                .exists()
        );
        assert!(!relay_stream_offer_store_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn mount_unusable_clock_fails_before_keystore_or_live_tasks() {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap();
        drop(listener);
        let mut config = RelayStreamLiveConfig {
            enabled: true,
            ..RelayStreamLiveConfig::default()
        };
        config.reverse_connect.relay_addr = relay_addr;

        let error = mount_relay_stream_live_with_clock(
            dir.path().to_path_buf(),
            relay_stream_household_state(),
            Arc::new(MeshLogStore::new()),
            Arc::new(ClawShareSlotStore::new()),
            Arc::new(ReplayGuard::new()),
            config,
            Arc::new(|| None),
            None,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            RelayStreamMountError::Assemble(RelayStreamLiveError::ClockUnusable)
        ));
        assert!(!relay_stream_offer_store_path(dir.path()).exists());
        assert!(
            !dir.path()
                .join("claw_share")
                .join(RELAY_STREAM_KEYSTORE_SUBDIR)
                .exists()
        );
    }

    #[tokio::test]
    async fn mount_enabled_empty_store_returns_live_handles() {
        let dir = tempfile::tempdir().unwrap();
        // Bind+drop a loopback port so the pool's dial target is closed; with an
        // empty store there are zero offers/workers anyway, so nothing dials.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap();
        drop(listener);

        let mut config = RelayStreamLiveConfig {
            enabled: true,
            ..RelayStreamLiveConfig::default()
        };
        config.reverse_connect.relay_addr = relay_addr;

        let handles = mount_relay_stream_live(
            dir.path().to_path_buf(),
            relay_stream_household_state(),
            Arc::new(MeshLogStore::new()),
            Arc::new(ClawShareSlotStore::new()),
            Arc::new(ReplayGuard::new()),
            config,
            None,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(handles.offer_count(), 0);
        assert_eq!(handles.pool_task_count(), 0);
        handles.trust_runtime().ensure_healthy(now_unix()).unwrap();
        handles.shutdown();
    }

    #[tokio::test]
    async fn claim_provision_stores_offer_with_responder_static_key() {
        let dir = tempfile::tempdir().unwrap();
        let household = relay_stream_household_state();
        let mesh_log = MeshLogStore::new();
        let credential = share_app_credential();
        let presentation = share_app_presentation();
        let now = now_unix();
        // The durable source, written the real way: an owner-signed
        // ClawShareSlotMinted carrying the snapshot for THIS credential's slot.
        seed_minted_slot(&mesh_log, &credential, Some(presentation.clone()));

        let returned = provision_relay_stream_offer_for_claim(
            dir.path(),
            &household,
            &mesh_log,
            &owner_signer(),
            &credential,
            now,
        )
        .await
        .unwrap();

        // The offer is durable and active for the pool to pick up. `list_active`
        // re-verifies on read, so reaching this line already means the signed
        // presentation fence (Device + ClawSite + app_id == claw_id) passed.
        let trust = relay_stream_issuer_trust();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust, now).unwrap();
        let active = store.list_active(&trust, now).unwrap();
        assert_eq!(active.len(), 1);
        let offer = &active[0];
        // Derived from the snapshot, never from an env var.
        assert_eq!(offer.payload.resource, RelayStreamResource::ClawSite);
        assert_eq!(offer.payload.app_presentation.as_ref(), Some(&presentation));
        assert_eq!(offer.payload.claw_id, share_app_id());
        assert_eq!(
            offer.payload.relay_endpoint,
            format!("relay-stream://{}", relay_stream_relay_endpoint())
        );

        // claw_static_pub is the key the responder mount's keystore would present.
        let keystore = FileKeystore::new(
            dir.path()
                .join("claw_share")
                .join(RELAY_STREAM_KEYSTORE_SUBDIR),
            RELAY_STREAM_KEYSTORE_SERVICE,
        );
        let expected = RelayStreamNoiseKeyStore::new(&keystore)
            .get_or_create(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
            .unwrap();
        assert_eq!(offer.payload.claw_static_pub, *expected.public_key());

        // The returned offer is the EXACT one persisted (same mint, no re-mint):
        // the relay path delivers THIS offer in the ack.
        assert_eq!(&returned, offer);
        // It serializes to opaque canonical CBOR that decodes back intact - the
        // bytes the relay path puts in ClawShareAck.relay_stream_offer.
        let bytes = household_rs::cbor::to_canonical_vec(&returned).unwrap();
        let decoded: RelayStreamOfferContract =
            household_rs::cbor::from_canonical_slice(&bytes).unwrap();
        assert_eq!(decoded, returned);
    }

    #[tokio::test]
    async fn provision_group_and_public_offers_store_with_audience() {
        use crate::claw_share_relay_stream_contract::RelayStreamAudience;

        // No env guard needed any more: Group/Public pin ClawSite in the
        // provisioner. This test used to set the former global resource env var
        // to `clawsite` to work around the Pty default, which hid the defect
        // that made the two handler-level tests 500 — the workaround is gone so
        // a regression here fails instead of being papered over.
        let dir = tempfile::tempdir().unwrap();
        let household = relay_stream_household_state();
        let mesh_log = MeshLogStore::new();
        let now = now_unix();
        let member_dev = household_rs::keys::P256Keypair::generate().public();
        let dialer_dev = household_rs::keys::P256Keypair::generate().public();

        let group_offer = provision_group_offer_for_claw(
            dir.path(),
            &household,
            &mesh_log,
            &owner_signer(),
            "g".to_string(),
            "g_a".to_string(),
            member_dev,
            "claw_alpha".to_string(),
            now + 600,
            now,
        )
        .await
        .unwrap();
        assert_eq!(
            group_offer.payload.audience(),
            RelayStreamAudience::Group {
                group_id: "g".to_string(),
                member_id: "g_a".to_string(),
            }
        );

        let public_offer = provision_public_offer_for_claw(
            dir.path(),
            &household,
            &mesh_log,
            &owner_signer(),
            dialer_dev,
            "claw_pub".to_string(),
            now + 600,
            now,
        )
        .await
        .unwrap();
        assert_eq!(public_offer.payload.audience(), RelayStreamAudience::Public);

        // The two properties the shared-audience paths must hold, asserted on
        // BOTH offers. Audience + store length alone would not catch a resource
        // change that the mint still accepts, nor a snapshot leaking into the
        // legacy namespace.
        for (label, offer) in [("group", &group_offer), ("public", &public_offer)] {
            assert_eq!(
                offer.payload.resource,
                RelayStreamResource::ClawSite,
                "{label} offer must pin ClawSite, never an env-derived resource"
            );
            assert!(
                offer.payload.app_presentation.is_none(),
                "{label} offer must stay in the legacy namespace with no snapshot"
            );
        }

        // Both durable + active for the reverse-connect pool (no slot collision).
        let trust = relay_stream_issuer_trust();
        let mut store = RelayStreamOfferStore::load(dir.path(), &trust, now).unwrap();
        assert_eq!(store.list_active(&trust, now).unwrap().len(), 2);
    }

    /// Feature-build counterpart to the two fail-closed tests: with the dev
    /// fallback compiled in, a snapshot-free slot is the LEGACY path and must
    /// still mint — carrying the fallback resource and no snapshot. Run with
    /// `--features dev_claw_share_mint`.
    #[cfg(feature = "dev_claw_share_mint")]
    // The env guard is deliberately held across the await: the var is
    // process-wide, so releasing it before the claim would let a parallel test
    // change it mid-provision — the race this lock exists to prevent.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn dev_build_mints_legacy_when_the_slot_has_no_snapshot() {
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let _env = set_t1_test_env(DEV_RELAY_STREAM_RESOURCE_ENV, Some("pty"));
        let dir = tempfile::tempdir().unwrap();
        let household = relay_stream_household_state();
        let mesh_log = MeshLogStore::new();
        let credential = share_app_credential();
        let now = now_unix();
        seed_minted_slot(&mesh_log, &credential, None);

        let offer = provision_relay_stream_offer_for_claim(
            dir.path(),
            &household,
            &mesh_log,
            &owner_signer(),
            &credential,
            now,
        )
        .await
        .expect("the dev fallback must keep the legacy path minting");

        assert_eq!(offer.payload.resource, RelayStreamResource::Pty);
        assert!(offer.payload.app_presentation.is_none());
    }

    #[tokio::test]
    async fn claim_provision_errors_gracefully_on_owner_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let household = relay_stream_household_state();
        let mesh_log = MeshLogStore::new();
        let credential = share_app_credential();
        let now = now_unix();
        // A VALID snapshot is seeded first, on purpose: without it this claim
        // would stop at the new MissingAppPresentation gate and the test would
        // silently stop exercising the owner check it exists for.
        seed_minted_slot(&mesh_log, &credential, Some(share_app_presentation()));

        // attacker_signer() is not the credential's owner key: the mint rejects,
        // an error is returned (not a panic), and nothing is persisted - the
        // outer best-effort wrapper would log and let the claim proceed.
        let result = provision_relay_stream_offer_for_claim(
            dir.path(),
            &household,
            &mesh_log,
            &attacker_signer(),
            &credential,
            now,
        )
        .await;

        assert!(matches!(
            result,
            Err(RelayStreamClaimProvisionError::Provision(_))
        ));
        let trust = relay_stream_issuer_trust();
        let store = RelayStreamOfferStore::load(dir.path(), &trust, now).unwrap();
        assert!(store.is_empty());
    }

    /// Assert the rejected claim left NOTHING on disk. Deliberately does not go
    /// through `RelayStreamOfferStore::load`, which constructs a store and can
    /// itself create the parent directory — that would mask the very side
    /// effect being tested. These are raw path existence checks.
    ///
    /// Gated with its callers: both are `cfg(not(feature =
    /// "dev_claw_share_mint"))`, because only a product-shaped build rejects a
    /// snapshot-free claim. Without this gate the feature build compiles a
    /// function nobody calls and warns.
    #[cfg(not(feature = "dev_claw_share_mint"))]
    fn assert_no_provision_side_effects(state_dir: &Path) {
        let keystore_dir = state_dir
            .join("claw_share")
            .join(RELAY_STREAM_KEYSTORE_SUBDIR);
        assert!(
            !keystore_dir.exists(),
            "a rejected claim must not create the responder keystore at {}",
            keystore_dir.display()
        );
        let offer_store = crate::claw_share_relay_stream_offer_store::relay_stream_offer_store_path(
            state_dir,
        );
        assert!(
            !offer_store.exists(),
            "a rejected claim must not create the offer store at {}",
            offer_store.display()
        );
    }

    /// Product-build property: with the dev fallback compiled in, this claim
    /// legitimately mints legacy instead, so asserting fail-closed here would
    /// make the feature suite contradict itself. See the feature counterpart
    /// `dev_build_mints_legacy_when_the_slot_has_no_snapshot`.
    #[cfg(not(feature = "dev_claw_share_mint"))]
    #[tokio::test]
    async fn claim_provision_fails_closed_when_the_slot_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let household = relay_stream_household_state();
        // Empty projection: the credential names a slot the log never saw.
        let mesh_log = MeshLogStore::new();
        let credential = share_app_credential();
        let now = now_unix();

        let result = provision_relay_stream_offer_for_claim(
            dir.path(),
            &household,
            &mesh_log,
            &owner_signer(),
            &credential,
            now,
        )
        .await;

        assert!(matches!(
            result,
            Err(RelayStreamClaimProvisionError::MissingAppPresentation)
        ));
        // Physical absence, not "loaded an empty store": the reject must
        // happen before any keystore/offer-store I/O at all.
        assert_no_provision_side_effects(dir.path());
    }

    /// Product-build property; see the note on the sibling absent-slot test.
    #[cfg(not(feature = "dev_claw_share_mint"))]
    #[tokio::test]
    async fn claim_provision_fails_closed_when_the_slot_carries_no_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let household = relay_stream_household_state();
        let mesh_log = MeshLogStore::new();
        let credential = share_app_credential();
        let now = now_unix();
        // The slot EXISTS and is owner-signed — it just predates the snapshot.
        // Indistinguishable from absent at this gate, and deliberately so.
        seed_minted_slot(&mesh_log, &credential, None);

        let result = provision_relay_stream_offer_for_claim(
            dir.path(),
            &household,
            &mesh_log,
            &owner_signer(),
            &credential,
            now,
        )
        .await;

        assert!(matches!(
            result,
            Err(RelayStreamClaimProvisionError::MissingAppPresentation)
        ));
        // Physical absence, not "loaded an empty store": the reject must
        // happen before any keystore/offer-store I/O at all.
        assert_no_provision_side_effects(dir.path());
    }

    #[tokio::test]
    async fn claim_provision_pulses_immediate_pool_resync() {
        let _lock = CLAW_VPN_T1_TEST_ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // A closed relay endpoint: workers cannot dial, but resync registers
        // offers in the worker registry before any dial attempt.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap();
        drop(listener);

        let household = relay_stream_household_state();
        let mesh_log = Arc::new(MeshLogStore::new());
        let mut config = RelayStreamLiveConfig {
            enabled: true,
            ..RelayStreamLiveConfig::default()
        };
        config.reverse_connect.relay_addr = relay_addr;
        let handles = mount_relay_stream_live(
            dir.path().to_path_buf(),
            household.clone(),
            Arc::clone(&mesh_log),
            Arc::new(ClawShareSlotStore::new()),
            Arc::new(ReplayGuard::new()),
            config,
            None,
        )
        .await
        .unwrap()
        .unwrap();
        if LIVE_HANDLES.set(handles).is_err() {
            panic!("LIVE_HANDLES must be unset before this test runs");
        }
        let handles = LIVE_HANDLES.get().unwrap();
        assert_eq!(handles.offer_count(), 0);

        // The claim path is snapshot-driven now, so this needs a real durable
        // slot too — resync must be exercised by a claim that actually mints.
        let credential = share_app_credential();
        seed_minted_slot(&mesh_log, &credential, Some(share_app_presentation()));

        // Env window kept minimal: the wrapper's gate is the only reader.
        let _offer = {
            let _live_env = set_t1_test_env(RELAY_STREAM_LIVE_ENV, Some("1"));
            try_provision_relay_stream_offer_for_claim(
                dir.path(),
                &household,
                &mesh_log,
                &owner_signer(),
                &credential,
                now_unix(),
            )
            .await
            .expect("claim provisioning must succeed")
        };

        // The resync tick is 30s, so only the provision-time pulse can surface
        // the offer inside this window. Removing the trigger_resync call from
        // the provision success arm turns this test RED.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if handles.offer_count() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("claim provision must pulse an immediate pool resync");

        handles.shutdown();
    }

    #[test]
    fn shared_replay_guard_rejects_cross_path_nonce() {
        // The engine threads ONE Arc<ReplayGuard> into both the direct
        // data-tunnel listener and the relay_stream mount. A single-use auth
        // nonce burned on one path must then be rejected on the other.
        let guard = Arc::new(ReplayGuard::new());
        let nonce = b"shared-replay-nonce";
        let now = 1_800_000_000u64;
        let expires_at = now + 60;

        // Path A burns the nonce.
        guard.check_and_record(nonce, expires_at, now).unwrap();
        // Path B (same shared guard) sees the replay.
        let error = guard.check_and_record(nonce, expires_at, now).unwrap_err();
        assert!(matches!(
            error,
            DataTunnelError::TokenRejected(reason) if reason == "token-replayed"
        ));
    }
}
