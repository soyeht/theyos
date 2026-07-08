//! Dev-only standalone Claw responder for T1 `IpTunnel` Phase 0.
//!
//! This binary is intentionally absent from default/product builds
//! (`required-features = ["dev_t1_datapath"]`). It is a two-ended dev-host
//! harness for generating real hardware observations before the #281 activation
//! record exists. It is not mounted by the engine and does not change the
//! production `relay_stream` mount, which remains `PerClawVpnT1PreflightEvidence::missing`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use household_rs::LoadedIdentity;
use household_rs::cbor;
use household_rs::claw_share::{ClawShareSlotStore, SLOT_ID_LEN, SlotId};
use household_rs::claw_share_data_tunnel::ReplayGuard;
use household_rs::claw_share_relay_stream_contract::{
    RelayStreamClawStaticPublicKey, RelayStreamOfferContract, RelayStreamResource,
    mint_relay_stream_group_offer,
};
use household_rs::household_mesh_log::{
    MeshLogStore, MeshMembership, ProjectedGroup, ProjectedMemberDevice, ProjectedState,
    build_claw_site_published_event,
};
use household_rs::household_record::HouseholdRecord;
use household_rs::ids::{derive_household_id, derive_machine_id};
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
use household_rs::machine_cert::{MachineCert, Platform, SignOptions};

use server_rs::claw_share_relay_stream_admission::RelayStreamAdmission;
use server_rs::claw_share_relay_stream_contract::RelayStreamExpectedPath;
use server_rs::claw_share_relay_stream_issuer_trust::{
    RelayStreamIssuerTrust, RelayStreamTrustContext,
};
use server_rs::claw_share_relay_stream_noise::generate_relay_stream_noise_static_keypair;
use server_rs::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
use server_rs::claw_share_relay_stream_responder_reverse_connect::{
    RelayStreamResponderReverseConnectConfig, serve_relay_stream_responder_reverse_connect_binding,
};
use server_rs::claw_share_relay_stream_reverse_connect_binding::bind_relay_stream_reverse_connect_with_ip_tunnel_router;
use server_rs::claw_share_relay_stream_target_router::RelayStreamIpTunnelUnavailableRouter;
use server_rs::claw_share_relay_stream_trust_context_health::{
    RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
};
use server_rs::claw_share_rendezvous_stream_relay::RendezvousToken;
use server_rs::claw_vpn_dev_config::ClawVpnDevConfig;
use server_rs::claw_vpn_interface_route_plan::{
    ClawVpnInterfaceName, ClawVpnInterfaceRoutePlatform, ClawVpnInterfaceRouteToolPaths,
};
#[cfg(target_os = "linux")]
use server_rs::claw_vpn_linux_tun::{
    ClawVpnLinuxTunConfig, ClawVpnLinuxTunDevice, ClawVpnLinuxTunName,
};
#[cfg(target_os = "macos")]
use server_rs::claw_vpn_macos_utun::ClawVpnMacosUtunDevice;
use server_rs::claw_vpn_pollable_pump::ClawVpnPollablePacketInterface;
use server_rs::claw_vpn_t1_relay_stream_router::{
    ClawVpnPollableT1RelayStreamBoxedRouter, ClawVpnPollableT1RelayStreamBuildInputs,
    ClawVpnPollableT1RelayStreamLaunchRuntime, ClawVpnPollableT1RelayStreamRouterParts,
    ClawVpnT1RelayStreamAuditSink, assemble_claw_vpn_pollable_t1_relay_stream_router,
};
use server_rs::claw_vpn_target_session_router::{
    ClawVpnPollableTargetSessionRouterWiring, ClawVpnTargetSessionRouterLaunchError,
};
use server_rs::claw_vpn_wiring::{ClawVpnRuntimeWiringConfig, ClawVpnRuntimeWiringInputs};
use server_rs::household_state::HouseholdState;
use server_rs::startup_wiring::PerClawVpnT1PreflightEvidence;

const DEV_HOST_ACK: &str = "dev-host T1-T4 only; no production activation";
const DEV_PUBLIC_RELAY_ACK: &str = "dev-host public relay dial allowed; no production activation";
const DEV_DATAPATH_ENV: &str = "THEYOS_T1_DEV_DATAPATH";
const DEV_SOFTWARE_KEYS_ENV: &str = "THEYOS_FORCE_SOFTWARE_KEYS";
const RELAY_ENDPOINT_ENV: &str = "RELAY_ENDPOINT";
const CLAW_ID_ENV: &str = "CLAW_ID";
const GUEST_DEVICE_PUB_ENV: &str = "GUEST_DEVICE_PUB";
const OFFER_OUT_ENV: &str = "OFFER_OUT";
const OFFER_TTL_SECS_ENV: &str = "OFFER_TTL_SECS";

const DEV_GROUP_ID: &str = "group-alpha";
const DEV_GROUP_NAME: &str = "Group Alpha";
const DEV_MEMBER_ID: &str = "member-alpha";
const DEV_MEMBER_NPUB: &str = "member-alpha";
const DEV_IPV4_POOL: &str = "198.18.0.0/24";
const DEV_MAX_SESSIONS: &str = "1";
const DEFAULT_RELAY_ENDPOINT: &str = "127.0.0.1:49152";
const DEFAULT_OFFER_OUT: &str = "t1-iptunnel-offer.cbor";
const DEFAULT_OFFER_TTL_SECS: u64 = 600;
const LINUX_IP_TOOL_PATH: &str = "/sbin/ip";
#[cfg(target_os = "linux")]
const LINUX_TUN_NAME: &str = "clawvpn-dev0";
const MACOS_IFCONFIG_TOOL_PATH: &str = "/sbin/ifconfig";
const MACOS_ROUTE_TOOL_PATH: &str = "/sbin/route";

const DEV_OWNER_SCALAR: [u8; 32] = [0x11; 32];
const DEV_HOUSEHOLD_ROOT_SCALAR: [u8; 32] = [0xAA; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
struct Args {
    dev_host_ack: String,
    allow_public_relay_ack: Option<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn parse_args() -> Args {
    parse_args_from(std::env::args().skip(1)).unwrap_or_else(|message| fatal(message))
}

fn parse_args_from<I, S>(args: I) -> Result<Args, &'static str>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut dev_host_ack = None;
    let mut allow_public_relay_ack = None;
    let mut iter = args.into_iter().map(Into::into);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--dev-host-ack" => {
                dev_host_ack = Some(iter.next().ok_or("missing dev-host ack argument")?);
            }
            "--allow-public-relay-ack" => {
                allow_public_relay_ack =
                    Some(iter.next().ok_or("missing public relay ack argument")?);
            }
            "--help" | "-h" => {
                return Err(
                    "usage: t1_iptunnel_claw_dev --dev-host-ack <ack> [--allow-public-relay-ack <ack>]",
                );
            }
            _ => return Err("unknown argument"),
        }
    }
    Ok(Args {
        dev_host_ack: dev_host_ack.ok_or("missing dev-host ack argument")?,
        allow_public_relay_ack,
    })
}

fn validate_dev_host_ack(value: &str) -> Result<(), &'static str> {
    if value == DEV_HOST_ACK {
        Ok(())
    } else {
        Err("dev-host ack invalid")
    }
}

fn require_env_enabled(name: &'static str) -> Result<(), &'static str> {
    match std::env::var(name) {
        Ok(value) if value.trim() == "1" => Ok(()),
        _ => Err(name),
    }
}

fn validate_relay_endpoint_or_ack(
    relay_addr: SocketAddr,
    allow_public_relay_ack: Option<&str>,
) -> Result<bool, &'static str> {
    if relay_addr.ip().is_loopback() {
        return Ok(false);
    }
    if matches!(allow_public_relay_ack, Some(value) if value == DEV_PUBLIC_RELAY_ACK) {
        return Ok(true);
    }
    Err("non-loopback relay requires explicit dev public relay acknowledgement")
}

fn validate_runtime_gates(args: &Args, relay_addr: SocketAddr) -> Result<bool, &'static str> {
    validate_dev_host_ack(&args.dev_host_ack)?;
    require_env_enabled(DEV_DATAPATH_ENV)?;
    require_env_enabled(DEV_SOFTWARE_KEYS_ENV)?;
    validate_relay_endpoint_or_ack(relay_addr, args.allow_public_relay_ack.as_deref())
}

fn env_optional_trimmed(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_required_trimmed(key: &'static str) -> String {
    env_optional_trimmed(key).unwrap_or_else(|| {
        fatal(match key {
            CLAW_ID_ENV => "claw id missing",
            GUEST_DEVICE_PUB_ENV => "guest device public key missing",
            _ => "required environment value missing",
        })
    })
}

fn parse_relay_addr(value: &str) -> SocketAddr {
    value
        .parse()
        .unwrap_or_else(|_| fatal("relay endpoint must be an IP:port"))
}

fn relay_endpoint_uri(relay_addr: SocketAddr) -> String {
    match relay_addr.ip() {
        IpAddr::V4(ip) => format!("relay-stream://{ip}:{}", relay_addr.port()),
        IpAddr::V6(ip) => format!("relay-stream://[{ip}]:{}", relay_addr.port()),
    }
}

fn decode_guest_device_pub(hex_str: &str) -> P256PublicKey {
    let bytes = hex::decode(hex_str).unwrap_or_else(|_| fatal("guest device public key invalid"));
    P256PublicKey::from_bytes(&bytes).unwrap_or_else(|_| fatal("guest device public key invalid"))
}

fn dev_owner_signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&DEV_OWNER_SCALAR).expect("dev owner scalar is valid")
}

fn dev_household_root() -> P256Keypair {
    P256Keypair::from_secret_scalar(&DEV_HOUSEHOLD_ROOT_SCALAR).expect("dev root scalar is valid")
}

fn dev_machine_cert(owner_pub: &P256PublicKey) -> MachineCert {
    let root = dev_household_root();
    MachineCert::sign(
        &root,
        owner_pub,
        &SignOptions {
            hh_id: derive_household_id(&root.public()),
            hostname: "claw-dev-mac-alpha".to_string(),
            platform: Platform::Macos,
            joined_at: 0,
        },
    )
    .expect("sign dev machine cert")
}

fn dev_household_record(owner_pub: &P256PublicKey) -> HouseholdRecord {
    let root = dev_household_root();
    HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&root.public()),
        hh_pub: root.public(),
        name: "claw-dev".to_string(),
        created_at: 0,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![derive_machine_id(owner_pub)],
        is_follower: false,
    }
}

fn dev_household_state(owner_pub: &P256PublicKey) -> HouseholdState {
    HouseholdState::loaded(Arc::new(LoadedIdentity {
        record: dev_household_record(owner_pub),
        cert: dev_machine_cert(owner_pub),
        hh_priv: None,
        m_priv: Box::new(dev_owner_signer()),
        backing: "software",
    }))
}

fn dev_published_mesh_log(claw_id: &str, owner: &P256Keypair, now: u64) -> MeshLogStore {
    let mesh_log = MeshLogStore::new();
    let entry = build_claw_site_published_event(claw_id.to_string(), now, owner.public(), owner)
        .expect("build ClawSitePublished");
    mesh_log.append(entry).expect("append ClawSitePublished");
    mesh_log
}

async fn dev_admission(
    household: &HouseholdState,
    mesh_log: &MeshLogStore,
    now: u64,
) -> RelayStreamAdmission {
    let policy = RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(3_600), 3)
        .expect("refresh policy is valid");
    let runtime = RelayStreamTrustContextRuntime::load(household, mesh_log, now, policy)
        .await
        .expect("load trust runtime");
    RelayStreamAdmission::new(Arc::new(runtime))
}

fn dev_group_projection(
    claw_id: &str,
    member_device_pub: &P256PublicKey,
    published_projection: &ProjectedState,
) -> ProjectedState {
    let mut projection = published_projection.clone();
    projection.groups.insert(
        DEV_GROUP_ID.to_string(),
        ProjectedGroup {
            group_id: DEV_GROUP_ID.to_string(),
            name: DEV_GROUP_NAME.to_string(),
            members: BTreeMap::from([(DEV_MEMBER_ID.to_string(), MeshMembership::Active)]),
            member_labels: BTreeMap::new(),
            granted_claws: BTreeMap::from([(claw_id.to_string(), MeshMembership::Active)]),
            revision: 1,
        },
    );
    projection.member_devices.insert(
        DEV_MEMBER_ID.to_string(),
        BTreeMap::from([(
            member_device_pub.as_bytes().to_vec(),
            ProjectedMemberDevice {
                participant_npub: DEV_MEMBER_NPUB.to_string(),
                status: MeshMembership::Active,
            },
        )]),
    );
    projection
}

fn dev_trust(
    record: HouseholdRecord,
    cert: MachineCert,
    projection: ProjectedState,
) -> RelayStreamIssuerTrust {
    RelayStreamIssuerTrust::new(move || RelayStreamTrustContext {
        record: record.clone(),
        cert: cert.clone(),
        projection: projection.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn dev_group_offer(
    claw_id: &str,
    guest_device_pub: P256PublicKey,
    claw_static_pub: RelayStreamClawStaticPublicKey,
    relay_endpoint: String,
    not_after: u64,
    now: u64,
    owner: &P256Keypair,
) -> RelayStreamOfferContract {
    mint_relay_stream_group_offer(
        RendezvousToken::try_new(vec![0x42; 16]).expect("rendezvous token"),
        SlotId([0x99; SLOT_ID_LEN]),
        DEV_GROUP_ID.to_string(),
        DEV_MEMBER_ID.to_string(),
        guest_device_pub,
        claw_id.to_string(),
        RelayStreamResource::IpTunnel,
        relay_endpoint,
        claw_static_pub,
        not_after,
        now,
        owner,
    )
    .expect("mint group ip tunnel offer")
}

fn dev_claw_vpn_config(
    relay_endpoint: &str,
) -> Result<Option<ClawVpnDevConfig>, server_rs::claw_vpn_dev_config::ClawVpnDevConfigError> {
    ClawVpnDevConfig::from_values(
        Some("1"),
        None,
        Some(relay_endpoint),
        Some(DEV_IPV4_POOL),
        Some(DEV_MAX_SESSIONS),
        Some(DEV_MAX_SESSIONS),
    )
}

fn enabled_t1_wiring_config() -> ClawVpnRuntimeWiringConfig {
    let defaults = ClawVpnRuntimeWiringConfig::default();
    ClawVpnRuntimeWiringConfig::new(
        true,
        defaults.runtime_step_budget(),
        defaults.driver_budget(),
    )
}

fn route_tool_paths() -> std::io::Result<ClawVpnInterfaceRouteToolPaths> {
    ClawVpnInterfaceRouteToolPaths::try_new(
        LINUX_IP_TOOL_PATH,
        MACOS_IFCONFIG_TOOL_PATH,
        MACOS_ROUTE_TOOL_PATH,
    )
    .map_err(|error| std::io::Error::other(format!("{error:?}")))
}

#[cfg(target_os = "linux")]
fn t1_build_inputs() -> ClawVpnPollableT1RelayStreamBuildInputs<ClawVpnLinuxTunDevice> {
    Box::new(|_config, _target, _context, relay| {
        let tun_name = ClawVpnLinuxTunName::new(LINUX_TUN_NAME)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let device = ClawVpnLinuxTunDevice::open(&ClawVpnLinuxTunConfig::new(tun_name))?;
        device.set_nonblocking()?;
        let interface_name = ClawVpnInterfaceName::new(device.name().as_str())
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        Ok(ClawVpnRuntimeWiringInputs {
            route_platform: ClawVpnInterfaceRoutePlatform::Linux,
            interface_name,
            route_tool_paths: route_tool_paths()?,
            interface: device,
            relay,
        })
    })
}

#[cfg(target_os = "macos")]
fn t1_build_inputs() -> ClawVpnPollableT1RelayStreamBuildInputs<ClawVpnMacosUtunDevice> {
    Box::new(|_config, _target, _context, relay| {
        let device = ClawVpnMacosUtunDevice::open()?;
        device.set_nonblocking()?;
        let interface_name = ClawVpnInterfaceName::new(device.name().as_str())
            .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
        Ok(ClawVpnRuntimeWiringInputs {
            route_platform: ClawVpnInterfaceRoutePlatform::Macos,
            interface_name,
            route_tool_paths: route_tool_paths()?,
            interface: device,
            relay,
        })
    })
}

fn t1_runtime_launcher<I>() -> ClawVpnPollableT1RelayStreamLaunchRuntime<I>
where
    I: ClawVpnPollablePacketInterface + Send + 'static,
{
    Box::new(|mut wiring: ClawVpnPollableTargetSessionRouterWiring<I>| {
        tokio::task::spawn_blocking(move || {
            if wiring.run_until_stopped().is_err() {
                eprintln!("t1 claw dev: datapath runtime stopped");
            }
        });
        Ok::<(), ClawVpnTargetSessionRouterLaunchError>(())
    })
}

fn no_op_audit_sink() -> ClawVpnT1RelayStreamAuditSink {
    Box::new(|_event| Ok(()))
}

#[cfg(target_os = "linux")]
type DevPacketInterface = ClawVpnLinuxTunDevice;
#[cfg(target_os = "macos")]
type DevPacketInterface = ClawVpnMacosUtunDevice;

fn dev_t1_router(
    relay_endpoint: &str,
) -> ClawVpnPollableT1RelayStreamBoxedRouter<DevPacketInterface> {
    let endpoint = relay_endpoint.to_string();
    let status = assemble_claw_vpn_pollable_t1_relay_stream_router(
        move || dev_claw_vpn_config(&endpoint),
        || PerClawVpnT1PreflightEvidence::new(true, true, true),
        |_config| {
            ClawVpnPollableT1RelayStreamRouterParts::new(
                enabled_t1_wiring_config(),
                t1_build_inputs(),
                t1_runtime_launcher(),
                no_op_audit_sink(),
            )
        },
    );
    match status.into_ready() {
        Some((_mode, router)) => router,
        None => fatal("dev T1 router unavailable"),
    }
}

fn fatal(message: &str) -> ! {
    eprintln!("t1 claw dev: {message}");
    std::process::exit(2)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = parse_args();
    let relay_addr = parse_relay_addr(
        &env_optional_trimmed(RELAY_ENDPOINT_ENV).unwrap_or_else(|| DEFAULT_RELAY_ENDPOINT.into()),
    );
    let allow_non_loopback =
        validate_runtime_gates(&args, relay_addr).unwrap_or_else(|message| fatal(message));

    let claw_id = env_required_trimmed(CLAW_ID_ENV);
    let guest_device_pub = decode_guest_device_pub(&env_required_trimmed(GUEST_DEVICE_PUB_ENV));
    let offer_out =
        env_optional_trimmed(OFFER_OUT_ENV).unwrap_or_else(|| DEFAULT_OFFER_OUT.to_string());
    let ttl_secs = env_optional_trimmed(OFFER_TTL_SECS_ENV)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_OFFER_TTL_SECS);

    let now = now_unix();
    let owner = dev_owner_signer();
    let owner_pub = owner.public();
    let household = dev_household_state(&owner_pub);
    let mesh_log = dev_published_mesh_log(&claw_id, &owner, now);
    let admission = dev_admission(&household, &mesh_log, now).await;
    let published_projection = mesh_log.project();
    let projection = dev_group_projection(&claw_id, &guest_device_pub, &published_projection);
    let record = dev_household_record(&owner_pub);
    let cert = dev_machine_cert(&owner_pub);
    let trust = dev_trust(record, cert, projection);

    let noise_keypair = generate_relay_stream_noise_static_keypair().expect("noise keypair");
    let claw_static_pub = noise_keypair.public_key().clone();
    let relay_endpoint = relay_endpoint_uri(relay_addr);
    let offer = dev_group_offer(
        &claw_id,
        guest_device_pub,
        claw_static_pub,
        relay_endpoint.clone(),
        now.saturating_add(ttl_secs),
        now,
        &owner,
    );
    if offer.payload.resource != RelayStreamResource::IpTunnel
        || offer.payload.expected_path != RelayStreamExpectedPath::RelayStream
    {
        fatal("dev offer target invalid");
    }

    let offer_bytes = cbor::to_canonical_vec(&offer).expect("encode offer");
    std::fs::write(&offer_out, &offer_bytes)?;

    let params = RelayStreamResponderParams {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 49_152)),
        auth_deadline: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(300),
        admission,
        noise_keypair,
    };
    let router = dev_t1_router(&relay_endpoint);
    let binding = bind_relay_stream_reverse_connect_with_ip_tunnel_router(
        Arc::new(offer),
        trust,
        derive_household_id(&dev_household_root().public()),
        Arc::new(ClawShareSlotStore::new()),
        Arc::new(ReplayGuard::new()),
        RelayStreamIpTunnelUnavailableRouter,
        RelayStreamIpTunnelUnavailableRouter,
        router,
        now_unix,
    );
    let config = RelayStreamResponderReverseConnectConfig {
        relay_addr,
        connect_timeout: Duration::from_secs(10),
        hello_timeout: Duration::from_secs(10),
        allow_non_loopback_relay_addr: allow_non_loopback,
    };

    println!("runner_claw_dev_offer_written=true");
    println!("runner_claw_dev_offer_bytes={}", offer_bytes.len());
    println!("runner_tun_opened=false");
    println!("runner_route_installed=false");
    println!("runner_packet_pump_started=false");

    loop {
        match serve_relay_stream_responder_reverse_connect_binding(
            config,
            &binding,
            &params,
            now_unix(),
        )
        .await
        {
            Ok(()) => eprintln!("t1 claw dev: reverse-connect session completed"),
            Err(_) => eprintln!("t1 claw dev: reverse-connect attempt ended"),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_gates_are_default_off_without_value_echo() {
        let args = Args {
            dev_host_ack: DEV_HOST_ACK.to_string(),
            allow_public_relay_ack: None,
        };
        let relay = "127.0.0.1:49152".parse().unwrap();
        let error = validate_runtime_gates(&args, relay).unwrap_err();
        assert_eq!(error, DEV_DATAPATH_ENV);

        let args = Args {
            dev_host_ack: "not-approved".to_string(),
            allow_public_relay_ack: None,
        };
        let error = validate_runtime_gates(&args, relay).unwrap_err();
        assert_eq!(error, "dev-host ack invalid");
        assert!(!error.contains("not-approved"));
    }

    #[test]
    fn non_loopback_relay_requires_second_ack_without_endpoint_echo() {
        let relay = "198.18.0.10:49152".parse().unwrap();
        let error = validate_relay_endpoint_or_ack(relay, None).unwrap_err();
        assert_eq!(
            error,
            "non-loopback relay requires explicit dev public relay acknowledgement"
        );
        assert!(!error.contains("198.18.0.10"));
        assert!(validate_relay_endpoint_or_ack(relay, Some(DEV_PUBLIC_RELAY_ACK)).unwrap());
    }

    #[test]
    fn args_require_explicit_dev_ack() {
        let parsed = parse_args_from([
            "--dev-host-ack",
            DEV_HOST_ACK,
            "--allow-public-relay-ack",
            DEV_PUBLIC_RELAY_ACK,
        ])
        .unwrap();
        assert_eq!(parsed.dev_host_ack, DEV_HOST_ACK);
        assert_eq!(
            parsed.allow_public_relay_ack.as_deref(),
            Some(DEV_PUBLIC_RELAY_ACK)
        );
        assert!(parse_args_from(std::iter::empty::<&str>()).is_err());
    }
}
