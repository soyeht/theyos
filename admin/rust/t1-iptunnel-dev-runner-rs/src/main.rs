//! Dev-only Product A T1 `IpTunnel` runner boundary.
//!
//! This binary is a dev-host tool only. The `validate-offer` command remains
//! offline. The `open-session` command can explicitly authenticate and open an
//! `IpTunnel` data-tunnel session, but this runner still does not implement a
//! local tunnel interface, route install, packet pump, or production-app
//! control path. A target open against an activated dev host remains a gated
//! T1-T4 validation step, not a production activation path.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use household_rs::claw_share_data_tunnel::{
    HEALTH_PROBE, SessionAuthToken, TunnelAck, client_authenticate, client_health,
    client_open_stream,
};
use household_rs::claw_share_relay_stream_contract::{
    RelayStreamAudience, RelayStreamExpectedPath, RelayStreamOfferContract, RelayStreamResource,
};
use household_rs::claw_share_relay_stream_endpoint::parse_relay_endpoint;
use household_rs::claw_share_relay_stream_noise::{
    RelayStreamNoiseAsyncStream, RelayStreamNoiseFramed,
};
use household_rs::claw_share_rendezvous_hello::{RendezvousHello, RendezvousRole};
#[cfg(feature = "dev_t1_datapath")]
use household_rs::claw_vpn::ClawVpnIpv4Pool;
use household_rs::claw_vpn::ClawVpnSessionAddrs;
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
use rand::RngCore;
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

const DEV_HOST_ACK: &str = "dev-host T1-T4 only; no production activation";
#[cfg(feature = "dev_t1_datapath")]
const DEV_DATAPATH_ENV: &str = "THEYOS_T1_DEV_DATAPATH";
#[cfg(feature = "dev_t1_datapath")]
const DEV_SOFTWARE_KEYS_ENV: &str = "THEYOS_FORCE_SOFTWARE_KEYS";
#[cfg(feature = "dev_t1_datapath")]
const DEV_PUBLIC_RELAY_ACK: &str = "dev-host public relay dial allowed; no production activation";
const DEV_RUNNER_SESSION_CONFIG_SCHEMA: &str = "t1-dev-runner-device-session-v1";
const DEV_RUNNER_SESSION_CONFIG_SCOPE: &str = "dev-host T1-T4 only";
const DEV_RUNNER_CLAW_ROUTE_PREFIX_LEN: u8 = 32;

#[derive(Parser, Debug)]
#[command(
    name = "t1-iptunnel-dev-runner",
    version,
    about = "Dev-only T1 IpTunnel runner preparation tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Validate a pre-minted `IpTunnel` offer without connecting or opening a device.
    ValidateOffer {
        /// Canonical CBOR `RelayStreamOfferContract` file.
        #[arg(long)]
        offer_file: PathBuf,
    },
    /// Validate reviewed Device-side session config shape without opening datapath.
    ///
    /// This command only validates a private config file for a future dev-host
    /// run. It does not open a local interface, install routes, run a packet
    /// pump, connect to a relay, or touch production apps.
    ValidateSessionConfig {
        /// Private JSON Device-side session config file. Paths and values are
        /// never printed.
        #[arg(long)]
        config_file: PathBuf,
    },
    /// Explicitly authenticate and open a dev-host `IpTunnel` session.
    ///
    /// This runner does not implement a local tunnel interface, install local
    /// routes, run a packet pump, or touch production apps. It only proves the
    /// relay/data-tunnel session-open step for a reviewed dev-host flow.
    OpenSession {
        /// Canonical CBOR `RelayStreamOfferContract` file.
        #[arg(long)]
        offer_file: PathBuf,
        /// File containing the 64-hex dev device secret scalar. The value is
        /// never printed.
        #[arg(long)]
        device_secret_file: PathBuf,
        /// Exact acknowledgement required before any network dial.
        #[arg(long)]
        dev_host_ack: String,
    },
    /// Generate a dev-host Device keypair for a T1 run.
    ///
    /// Writes the private 64-hex P-256 secret scalar to `--secret-out` (mode
    /// `0600`, refused if the path exists) and prints the matching 66-hex SEC1
    /// `guest-device-pub`. The secret scalar is NEVER printed. The printed
    /// public key is the value to pass to the serving claw's
    /// `--guest-device-pub`; the runner re-checks that it corresponds to this
    /// secret at session open. This opens no interface, dials no relay, and does
    /// not touch production apps.
    GenDeviceKeypair {
        /// Output path for the private 64-hex device secret scalar. Refused if
        /// the file already exists; the value is never printed.
        #[arg(long)]
        secret_out: PathBuf,
    },
    /// Owner-present dev-only run path for Device-side T1 datapath validation.
    ///
    /// This command is compiled only with `--features dev_t1_datapath`. It is
    /// still default-off at runtime and requires explicit dev env gates before
    /// any interface is opened.
    #[cfg(feature = "dev_t1_datapath")]
    RunDeviceDatapath {
        /// Canonical CBOR `RelayStreamOfferContract` file.
        #[arg(long)]
        offer_file: PathBuf,
        /// File containing the 64-hex dev device secret scalar. The value is
        /// never printed.
        #[arg(long)]
        device_secret_file: PathBuf,
        /// Private JSON Device-side session config file. Paths and values are
        /// never printed.
        #[arg(long)]
        config_file: PathBuf,
        /// Exact acknowledgement required before any datapath action.
        #[arg(long)]
        dev_host_ack: String,
        /// Second acknowledgement required only when the offer relay endpoint is
        /// non-loopback.
        #[arg(long)]
        allow_public_relay_ack: Option<String>,
    },
    /// Generate a reviewed dev-host Device-side session config file.
    ///
    /// This command is compiled only with `--features dev_t1_datapath`. It emits
    /// a `t1-dev-runner-device-session-v1` config by reusing the real per-Claw
    /// VPN IPv4 allocator to derive the address pair, so an operator does not
    /// hand-author it. It does not open a local tunnel interface, install local
    /// routes, run a packet pump, connect to a relay, or touch production apps.
    /// The derived IPv4 values are never printed.
    #[cfg(feature = "dev_t1_datapath")]
    GenDeviceConfig {
        /// Host platform the emitted config targets.
        #[arg(long, value_enum)]
        platform: GenDeviceConfigPlatformArg,
        /// Doc-safe IPv4 pool network in CIDR form. Defaults to the RFC2544
        /// benchmarking doc range; RFC1918/CGNAT/reserved pools are refused.
        #[arg(long, default_value = "198.18.0.0/24")]
        pool_network: String,
        /// Session index used to derive the point-to-point address pair.
        #[arg(long, default_value_t = 0)]
        session_index: u32,
        /// Inner MTU written to the config (1280..=9000).
        #[arg(long, default_value_t = 1400)]
        mtu: u16,
        /// Output path for the generated private config file.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedIpTunnelOffer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevRunnerSessionConfigPlatform {
    Linux,
    Macos,
}

/// CLI value for the `gen-device-config --platform` argument.
#[cfg(feature = "dev_t1_datapath")]
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum GenDeviceConfigPlatformArg {
    #[value(name = "linux")]
    Linux,
    #[value(name = "macos")]
    Macos,
}

#[cfg(feature = "dev_t1_datapath")]
impl From<GenDeviceConfigPlatformArg> for DevRunnerSessionConfigPlatform {
    fn from(value: GenDeviceConfigPlatformArg) -> Self {
        match value {
            GenDeviceConfigPlatformArg::Linux => Self::Linux,
            GenDeviceConfigPlatformArg::Macos => Self::Macos,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ValidatedDevRunnerSessionConfig {
    platform: DevRunnerSessionConfigPlatform,
    addrs: ClawVpnSessionAddrs,
    claw_route_prefix_len: u8,
    mtu: u16,
}

impl fmt::Debug for ValidatedDevRunnerSessionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedDevRunnerSessionConfig")
            .field("platform", &self.platform)
            .field("device_ipv4", &"<redacted>")
            .field("claw_ipv4", &"<redacted>")
            .field("claw_route_prefix_len", &self.claw_route_prefix_len)
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl ValidatedDevRunnerSessionConfig {
    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn claw_route_prefix_len(&self) -> u8 {
        self.claw_route_prefix_len
    }

    fn device_ipv4_present(&self) -> bool {
        !self.addrs.device().is_unspecified()
    }

    fn claw_ipv4_present(&self) -> bool {
        !self.addrs.claw().is_unspecified()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct DevRunnerSessionAck {
    mesh_ipv6: Ipv6Addr,
    mtu: u16,
    session_id: String,
}

impl fmt::Debug for DevRunnerSessionAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DevRunnerSessionAck")
            .field("mesh_ipv6", &"<redacted>")
            .field("mtu", &self.mtu)
            .field("session_id", &"<redacted>")
            .field("session_id_present", &self.session_id_present())
            .finish()
    }
}

impl DevRunnerSessionAck {
    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn mesh_ipv6_present(&self) -> bool {
        !self.mesh_ipv6.is_unspecified()
    }

    fn session_id_present(&self) -> bool {
        !self.session_id.is_empty()
    }
}

fn validate_iptunnel_offer_file(path: &PathBuf) -> Result<ValidatedIpTunnelOffer> {
    let bytes = std::fs::read(path).context("read IpTunnel offer file")?;
    validate_iptunnel_offer_bytes(&bytes)
}

fn read_iptunnel_offer_file(path: &PathBuf) -> Result<RelayStreamOfferContract> {
    let bytes = std::fs::read(path).context("read IpTunnel offer file")?;
    let offer = RelayStreamOfferContract::from_canonical_bytes(&bytes)
        .context("decode relay_stream offer")?;
    validate_iptunnel_offer(&offer)?;
    Ok(offer)
}

fn validate_iptunnel_offer_bytes(bytes: &[u8]) -> Result<ValidatedIpTunnelOffer> {
    let offer = RelayStreamOfferContract::from_canonical_bytes(bytes)
        .context("decode relay_stream offer")?;
    validate_iptunnel_offer(&offer)
}

fn validate_iptunnel_offer(offer: &RelayStreamOfferContract) -> Result<ValidatedIpTunnelOffer> {
    if offer.payload.resource != RelayStreamResource::IpTunnel {
        bail!("relay_stream offer resource is not IpTunnel");
    }
    if offer.payload.expected_path != RelayStreamExpectedPath::RelayStream {
        bail!("IpTunnel offer expected_path is not RelayStream");
    }

    let RelayStreamAudience::Group {
        group_id,
        member_id,
    } = offer.payload.audience()
    else {
        bail!("IpTunnel offer must be member-scoped group audience");
    };
    if group_id.trim().is_empty() {
        bail!("IpTunnel offer group id is empty");
    }
    if member_id.trim().is_empty() {
        bail!("IpTunnel offer member id is empty");
    }
    if offer.payload.claw_id.trim().is_empty() {
        bail!("IpTunnel offer claw id is empty");
    }

    parse_relay_endpoint(&offer.payload.relay_endpoint).context("validate relay endpoint shape")?;

    Ok(ValidatedIpTunnelOffer)
}

fn validate_session_config_file(path: &PathBuf) -> Result<ValidatedDevRunnerSessionConfig> {
    let bytes = std::fs::read(path).context("read dev session config file")?;
    validate_session_config_bytes(&bytes)
}

fn validate_session_config_bytes(bytes: &[u8]) -> Result<ValidatedDevRunnerSessionConfig> {
    let value: Value = serde_json::from_slice(bytes).context("decode dev session config json")?;
    let Some(object) = value.as_object() else {
        bail!("dev session config must be a JSON object");
    };

    let schema = required_string(object, "schema")?;
    if schema != DEV_RUNNER_SESSION_CONFIG_SCHEMA {
        bail!("dev session config schema invalid");
    }
    let scope = required_string(object, "scope")?;
    if scope != DEV_RUNNER_SESSION_CONFIG_SCOPE {
        bail!("dev session config scope invalid");
    }
    if required_bool(object, "production_activation")? {
        bail!("dev session config production_activation must be false");
    }

    let platform = match required_string(object, "platform")? {
        "linux" => DevRunnerSessionConfigPlatform::Linux,
        "macos" => DevRunnerSessionConfigPlatform::Macos,
        _ => bail!("dev session config platform invalid"),
    };
    if required_string(object, "local_side")? != "device" {
        bail!("dev session config local_side must be device");
    }

    let claw_route_prefix_len = required_u8(object, "claw_route_prefix_len")?;
    if claw_route_prefix_len != DEV_RUNNER_CLAW_ROUTE_PREFIX_LEN {
        bail!("dev session config claw_route_prefix_len must be 32");
    }
    let mtu = required_u16(object, "mtu")?;
    if !(1280..=9000).contains(&mtu) {
        bail!("dev session config mtu invalid");
    }

    let device_ipv4 = parse_config_ipv4(required_string(object, "device_ipv4")?, "device_ipv4")?;
    let claw_ipv4 = parse_config_ipv4(required_string(object, "claw_ipv4")?, "claw_ipv4")?;
    let addrs = ClawVpnSessionAddrs::try_new(device_ipv4, claw_ipv4)
        .context("dev session config IPv4 pair invalid")?;

    Ok(ValidatedDevRunnerSessionConfig {
        platform,
        addrs,
        claw_route_prefix_len,
        mtu,
    })
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    let Some(value) = object.get(field).and_then(Value::as_str) else {
        bail!("dev session config {field} must be a non-empty string");
    };
    if value.trim().is_empty() || value.trim() != value {
        bail!("dev session config {field} must be a non-empty string");
    }
    Ok(value)
}

fn required_bool(object: &Map<String, Value>, field: &str) -> Result<bool> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("dev session config {field} must be a boolean"))
}

fn required_u16(object: &Map<String, Value>, field: &str) -> Result<u16> {
    let value = object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("dev session config {field} must be an integer"))?;
    u16::try_from(value).map_err(|_| anyhow!("dev session config {field} must be an integer"))
}

fn required_u8(object: &Map<String, Value>, field: &str) -> Result<u8> {
    let value = object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("dev session config {field} must be an integer"))?;
    u8::try_from(value).map_err(|_| anyhow!("dev session config {field} must be an integer"))
}

fn parse_config_ipv4(value: &str, field: &str) -> Result<Ipv4Addr> {
    value
        .parse::<Ipv4Addr>()
        .map_err(|_| anyhow!("dev session config {field} must be a valid IPv4 address"))
}

fn validate_dev_host_ack(value: &str) -> Result<()> {
    if value == DEV_HOST_ACK {
        return Ok(());
    }
    bail!("dev-host acknowledgement is required");
}

fn validate_session_ack(ack: TunnelAck) -> Result<DevRunnerSessionAck> {
    let (mesh_ipv6, mtu, session_id) = match ack {
        TunnelAck::Ok {
            mesh_ipv6,
            mtu,
            session_id,
        } => (mesh_ipv6, mtu, session_id),
        TunnelAck::Rejected { reason } => bail!("IpTunnel session auth rejected: {reason}"),
    };

    if session_id.trim().is_empty()
        || session_id.trim() != session_id
        || !session_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        bail!("IpTunnel session ack session id invalid");
    }

    let mesh_ipv6 = mesh_ipv6
        .parse::<Ipv6Addr>()
        .context("IpTunnel session ack mesh address invalid")?;
    if mesh_ipv6.is_unspecified() || mesh_ipv6.is_multicast() {
        bail!("IpTunnel session ack mesh address invalid");
    }

    if !(1280..=9000).contains(&mtu) {
        bail!("IpTunnel session ack mtu invalid");
    }

    Ok(DevRunnerSessionAck {
        mesh_ipv6,
        mtu,
        session_id,
    })
}

fn device_secret_from_hex(hex: &str) -> Result<P256Keypair> {
    let hex = hex.trim();
    if hex.len() != 64 || !hex.is_ascii() {
        bail!("device secret must be 64 hex chars");
    }
    let mut scalar = [0u8; 32];
    for (index, byte) in scalar.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .context("device secret is not valid hex")?;
    }
    P256Keypair::from_secret_scalar(&scalar).context("derive dev device key")
}

fn read_device_secret_file(path: &PathBuf) -> Result<P256Keypair> {
    let value = std::fs::read_to_string(path).context("read dev device secret file")?;
    device_secret_from_hex(&value)
}

/// The public result of `gen-device-keypair`. Deliberately carries only PUBLIC
/// material: the secret scalar is written to disk and never returned or logged.
struct GeneratedDeviceKeypair {
    guest_device_pub_hex: String,
}

/// Lowercase-hex encode (paired with the runner's hand-rolled hex decode).
fn encode_lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decode an even-length ASCII hex string (no `0x` prefix) into bytes.
fn decode_lower_hex(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 || !hex.is_ascii() {
        bail!("value is not even-length ascii hex");
    }
    (0..hex.len() / 2)
        .map(|index| {
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).context("value is not valid hex")
        })
        .collect()
}

/// Write a private secret file with `0600` permissions, refusing to overwrite an
/// existing path. The content is secret and is never logged; the path is not
/// echoed on error.
fn write_private_secret_file(path: &Path, secret_hex: &str) -> Result<()> {
    use std::fs::Permissions;
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("device secret file already exists; refusing to overwrite");
        }
        Err(error) => return Err(error).context("create device secret file"),
    };
    // Force exactly 0600 regardless of the caller's umask (the create mode above
    // is umask-filtered; fchmod is not), so the reported mode is literal and the
    // run can always read the secret back. create_new still guarantees no-clobber.
    file.set_permissions(Permissions::from_mode(0o600))
        .context("set device secret file permissions")?;
    file.write_all(secret_hex.as_bytes())
        .context("write device secret file")?;
    file.write_all(b"\n").context("write device secret file")?;
    file.flush().context("flush device secret file")?;
    Ok(())
}

/// Generate a fresh software P-256 device keypair, write its 64-hex secret scalar
/// to `secret_out` (mode `0600`, refused if the path exists), and return the
/// matching 66-hex SEC1 `guest-device-pub`.
///
/// Fail-closed BEFORE writing: the secret is round-tripped through the runner's
/// own [`device_secret_from_hex`] reader and must re-derive the emitted public
/// key, and the emitted public key must pass the same
/// [`P256PublicKey::from_bytes`] SEC1 check the serving claw applies. On any
/// mismatch nothing is written.
fn generate_device_keypair_to_file(secret_out: &Path) -> Result<GeneratedDeviceKeypair> {
    let keypair = P256Keypair::generate();
    let secret_scalar = keypair
        .as_software_secret()
        .ok_or_else(|| anyhow!("generated device keypair is not software-backed"))?;
    let secret_hex = encode_lower_hex(secret_scalar);
    let public_key = keypair.public();
    let guest_device_pub_hex = encode_lower_hex(public_key.as_bytes());

    // Fail closed before writing anything: the secret must re-derive its own
    // public key through the exact reader the runner uses at session open, and
    // the emitted public key must satisfy the serving claw's SEC1 decoder.
    let rederived =
        device_secret_from_hex(&secret_hex).context("generated device secret failed to derive")?;
    if rederived.public() != public_key {
        bail!("generated device secret does not derive its own public key");
    }
    let decoded_pub =
        decode_lower_hex(&guest_device_pub_hex).context("emitted guest-device-pub is not hex")?;
    P256PublicKey::from_bytes(&decoded_pub)
        .map_err(|_| anyhow!("emitted guest-device-pub failed SEC1 validation"))?;

    write_private_secret_file(secret_out, &secret_hex)?;

    Ok(GeneratedDeviceKeypair {
        guest_device_pub_hex,
    })
}

fn validate_open_session_inputs(
    offer: &RelayStreamOfferContract,
    device_key: &P256Keypair,
) -> Result<()> {
    validate_iptunnel_offer(offer)?;
    if offer.payload.guest_device_pub != device_key.public() {
        bail!("device secret does not match the IpTunnel offer");
    }
    Ok(())
}

fn current_unix() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

fn build_iptunnel_session_auth(
    offer: &RelayStreamOfferContract,
    device_key: &P256Keypair,
    now_unix: u64,
    nonce: Vec<u8>,
) -> Result<(Vec<u8>, SessionAuthToken)> {
    let offer_cbor = offer
        .payload
        .to_canonical_bytes()
        .context("encode IpTunnel offer payload")?;
    let token = SessionAuthToken::sign(
        format!("t1-iptunnel-dev-runner-{}-{now_unix}", std::process::id()),
        &offer_cbor,
        offer.payload.relay_endpoint.clone(),
        offer.payload.claw_id.clone(),
        nonce,
        now_unix + 60,
        device_key as &dyn IdentityKey,
    )
    .context("mint IpTunnel session auth token")?;
    Ok((offer_cbor, token))
}

async fn authenticate_open_iptunnel_session<T>(
    stream: &mut T,
    offer: &RelayStreamOfferContract,
    device_key: &P256Keypair,
    now_unix: u64,
) -> Result<DevRunnerSessionAck>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut nonce = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let (offer_cbor, token) = build_iptunnel_session_auth(offer, device_key, now_unix, nonce)?;

    let session_ack = validate_session_ack(
        client_authenticate(stream, &offer_cbor, token)
            .await
            .context("IpTunnel session authenticate")?,
    )?;

    let echo = client_health(stream, HEALTH_PROBE)
        .await
        .context("IpTunnel session health probe")?;
    if echo != HEALTH_PROBE {
        bail!("IpTunnel session health echo mismatch");
    }

    client_open_stream(stream)
        .await
        .context("IpTunnel session open")?;
    Ok(session_ack)
}

type OpenedIpTunnelStream = RelayStreamNoiseAsyncStream<tokio::net::TcpStream>;

async fn connect_open_iptunnel_session(
    offer: &RelayStreamOfferContract,
    device_key: &P256Keypair,
    now_unix: u64,
) -> Result<(DevRunnerSessionAck, OpenedIpTunnelStream)> {
    validate_open_session_inputs(offer, device_key)?;
    let (host, port) = parse_relay_endpoint(&offer.payload.relay_endpoint)
        .context("validate relay endpoint shape")?;

    let mut stream = match tokio::time::timeout(
        std::time::Duration::from_secs(4),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(error).context("connect to relay_stream relay"),
        Err(_) => bail!("connect to relay_stream relay timed out"),
    };

    let hello = RendezvousHello::new(
        RendezvousRole::Guest,
        offer.payload.rendezvous_token.clone(),
    );
    stream
        .write_all(&hello.encode())
        .await
        .context("send rendezvous hello")?;
    stream.flush().await.context("flush rendezvous hello")?;

    let framed = RelayStreamNoiseFramed::initiator_handshake(
        stream,
        offer,
        &offer.signer_pub,
        &device_key.public(),
        now_unix,
    )
    .await
    .context("relay_stream Noise handshake")?;
    let mut stream = framed.into_async_stream();
    let session_ack =
        authenticate_open_iptunnel_session(&mut stream, offer, device_key, now_unix).await?;
    Ok((session_ack, stream))
}

async fn open_iptunnel_session(
    offer: &RelayStreamOfferContract,
    device_key: &P256Keypair,
    now_unix: u64,
) -> Result<DevRunnerSessionAck> {
    let (session_ack, _stream) = connect_open_iptunnel_session(offer, device_key, now_unix).await?;
    Ok(session_ack)
}

#[cfg(feature = "dev_t1_datapath")]
fn dev_runner_platform_str(platform: DevRunnerSessionConfigPlatform) -> &'static str {
    match platform {
        DevRunnerSessionConfigPlatform::Linux => "linux",
        DevRunnerSessionConfigPlatform::Macos => "macos",
    }
}

/// Parse a `host/prefix` IPv4 CIDR without echoing its value on error.
#[cfg(feature = "dev_t1_datapath")]
fn parse_pool_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let (network, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("pool network must be an IPv4 host/prefix CIDR"))?;
    let network = network
        .parse::<Ipv4Addr>()
        .map_err(|_| anyhow!("pool network must be a valid IPv4 address"))?;
    let prefix_len = prefix
        .parse::<u8>()
        .map_err(|_| anyhow!("pool network prefix must be an integer"))?;
    Ok((network, prefix_len))
}

/// Emit a `t1-dev-runner-device-session-v1` config as pretty JSON bytes.
///
/// The device/claw address pair is derived only by reusing the real
/// `ClawVpnIpv4Pool` allocator; this never hand-computes addresses. The pool is
/// admitted through `ClawVpnIpv4Pool::try_new`, so RFC1918/CGNAT/reserved pools
/// fail closed here with a static error before any config is produced.
#[cfg(feature = "dev_t1_datapath")]
fn generate_device_session_config_bytes(
    platform: DevRunnerSessionConfigPlatform,
    pool_network: Ipv4Addr,
    pool_prefix_len: u8,
    session_index: u32,
    mtu: u16,
) -> Result<Vec<u8>> {
    if !(1280..=9000).contains(&mtu) {
        bail!("dev session config mtu invalid");
    }
    let pool = ClawVpnIpv4Pool::try_new(pool_network, pool_prefix_len)
        .map_err(|_| anyhow!("dev session config pool rejected"))?;
    let addrs = pool
        .allocate_pair(session_index)
        .map_err(|_| anyhow!("dev session config pool allocation failed"))?;

    let config = serde_json::json!({
        "schema": DEV_RUNNER_SESSION_CONFIG_SCHEMA,
        "scope": DEV_RUNNER_SESSION_CONFIG_SCOPE,
        "production_activation": false,
        "platform": dev_runner_platform_str(platform),
        "local_side": "device",
        "device_ipv4": addrs.device().to_string(),
        "claw_ipv4": addrs.claw().to_string(),
        "claw_route_prefix_len": DEV_RUNNER_CLAW_ROUTE_PREFIX_LEN,
        "mtu": mtu,
    });
    let mut bytes = serde_json::to_vec_pretty(&config).context("encode dev session config json")?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(feature = "dev_t1_datapath")]
mod dev_datapath {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr};

    use anyhow::{Result, anyhow, bail};
    use household_rs::claw_share_data_tunnel::{
        TargetSession, TunnelFrame, recv_frame, send_frame,
    };
    use household_rs::claw_share_relay_stream_contract::RelayStreamAudience;
    use household_rs::claw_vpn::{
        ClawVpnAcl, ClawVpnAclKey, ClawVpnAgentCore, ClawVpnAgentSessionCore, ClawVpnDatapathSide,
        ClawVpnIpv4Pool, ClawVpnSessionRegistry,
    };
    use server_rs::claw_vpn_interface_route_plan::{
        ClawVpnInterfaceName, ClawVpnInterfaceRoutePlatform, ClawVpnInterfaceRouteToolPaths,
    };
    #[cfg(target_os = "linux")]
    use server_rs::claw_vpn_linux_tun::{
        ClawVpnLinuxTunConfig, ClawVpnLinuxTunDevice, ClawVpnLinuxTunName,
    };
    #[cfg(target_os = "macos")]
    use server_rs::claw_vpn_macos_utun::ClawVpnMacosUtunDevice;
    use server_rs::claw_vpn_pollable_pump::{
        ClawVpnPollablePacketInterface, ClawVpnPollablePumpStopReason,
    };
    use server_rs::claw_vpn_runtime::ClawVpnPollableRuntimeReport;
    use server_rs::claw_vpn_target_session_relay::ClawVpnPollableTargetSessionRelay;
    use server_rs::claw_vpn_target_session_runtime::{
        ClawVpnTargetSessionRuntimeError, assemble_claw_vpn_pollable_target_session_runtime,
    };
    use server_rs::claw_vpn_wiring::{
        ClawVpnRuntimeWiringConfig, ClawVpnRuntimeWiringContext, ClawVpnRuntimeWiringInputs,
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use super::{
        DEV_DATAPATH_ENV, DEV_PUBLIC_RELAY_ACK, DEV_SOFTWARE_KEYS_ENV, OpenedIpTunnelStream,
        RelayStreamOfferContract, ValidatedDevRunnerSessionConfig, connect_open_iptunnel_session,
        parse_relay_endpoint, validate_dev_host_ack,
    };
    use household_rs::keys::{IdentityKey, P256Keypair};

    const DEV_DEVICE_POOL_NETWORK: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);
    const DEV_DEVICE_POOL_PREFIX_LEN: u8 = 24;
    #[cfg(target_os = "linux")]
    const DEV_LINUX_TUN_NAME: &str = "clawvpn0";
    const LINUX_IP_TOOL_PATH: &str = "/sbin/ip";
    const MACOS_IFCONFIG_TOOL_PATH: &str = "/sbin/ifconfig";
    const MACOS_ROUTE_TOOL_PATH: &str = "/sbin/route";
    const PIPE_CHUNK: usize = 16 * 1024;

    #[cfg(target_os = "linux")]
    type DevPacketInterface = ClawVpnLinuxTunDevice;
    #[cfg(target_os = "macos")]
    type DevPacketInterface = ClawVpnMacosUtunDevice;

    pub(super) fn validate_dev_datapath_runtime_gates(
        offer: &RelayStreamOfferContract,
        dev_host_ack: &str,
        allow_public_relay_ack: Option<&str>,
    ) -> Result<()> {
        validate_dev_datapath_runtime_gates_with_env(
            offer,
            dev_host_ack,
            allow_public_relay_ack,
            |name| std::env::var(name).ok(),
        )
    }

    pub(super) fn validate_dev_datapath_runtime_gates_with_env(
        offer: &RelayStreamOfferContract,
        dev_host_ack: &str,
        allow_public_relay_ack: Option<&str>,
        get_env: impl Fn(&str) -> Option<String>,
    ) -> Result<()> {
        validate_dev_host_ack(dev_host_ack)?;
        require_env_enabled(DEV_DATAPATH_ENV, &get_env)?;
        require_env_enabled(DEV_SOFTWARE_KEYS_ENV, &get_env)?;
        validate_loopback_relay_endpoint_or_ack(offer, allow_public_relay_ack)?;
        Ok(())
    }

    fn require_env_enabled(name: &str, get_env: &impl Fn(&str) -> Option<String>) -> Result<()> {
        match get_env(name) {
            Some(value) if value.trim() == "1" => Ok(()),
            _ => bail!("{name} must be set to 1 for dev-host T1 datapath"),
        }
    }

    fn validate_loopback_relay_endpoint_or_ack(
        offer: &RelayStreamOfferContract,
        allow_public_relay_ack: Option<&str>,
    ) -> Result<()> {
        let (host, _port) = parse_relay_endpoint(&offer.payload.relay_endpoint)
            .map_err(|_| anyhow!("dev relay endpoint invalid"))?;
        let ip = host
            .parse::<IpAddr>()
            .map_err(|_| anyhow!("dev relay endpoint must use an IP host"))?;
        if ip.is_loopback() {
            return Ok(());
        }
        if matches!(allow_public_relay_ack, Some(value) if value == DEV_PUBLIC_RELAY_ACK) {
            return Ok(());
        }
        bail!("non-loopback relay requires explicit dev public relay acknowledgement");
    }

    fn validate_host_platform(config: &ValidatedDevRunnerSessionConfig) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if !matches!(
                config.platform,
                super::DevRunnerSessionConfigPlatform::Linux
            ) {
                bail!("dev session config platform does not match this host");
            }
        }
        #[cfg(target_os = "macos")]
        {
            if !matches!(
                config.platform,
                super::DevRunnerSessionConfigPlatform::Macos
            ) {
                bail!("dev session config platform does not match this host");
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = config;
            bail!("dev-host T1 datapath supports only linux and macos hosts");
        }
        Ok(())
    }

    fn device_session_core(
        offer: &RelayStreamOfferContract,
        device_key: &P256Keypair,
        config: &ValidatedDevRunnerSessionConfig,
    ) -> Result<ClawVpnAgentSessionCore> {
        let RelayStreamAudience::Group { member_id, .. } = offer.payload.audience() else {
            bail!("IpTunnel offer must be member-scoped group audience");
        };
        let key = ClawVpnAclKey::try_new(
            member_id,
            device_key.public(),
            offer.payload.claw_id.clone(),
        )
        .map_err(|_| anyhow!("dev datapath acl key invalid"))?;
        let mut acl = ClawVpnAcl::new();
        acl.grant(key.clone());
        let pool = ClawVpnIpv4Pool::try_new(DEV_DEVICE_POOL_NETWORK, DEV_DEVICE_POOL_PREFIX_LEN)
            .map_err(|_| anyhow!("dev datapath IPv4 pool invalid"))?;
        let mut core = ClawVpnAgentCore::new(
            ClawVpnDatapathSide::Device,
            ClawVpnSessionRegistry::new(acl, pool),
        );
        let (session, _open_event) = core.open_with_audit(&key);
        let session = session.map_err(|_| anyhow!("dev datapath session open failed"))?;
        if session.addrs() != config.addrs {
            bail!("dev session config IPv4 pair does not match dev datapath pool");
        }
        core.into_session_core(session.id())
            .map_err(|_| anyhow!("dev datapath session core missing"))
    }

    fn enabled_runtime_config() -> ClawVpnRuntimeWiringConfig {
        let defaults = ClawVpnRuntimeWiringConfig::default();
        ClawVpnRuntimeWiringConfig::new(
            true,
            defaults.runtime_step_budget(),
            defaults.driver_budget(),
        )
    }

    fn route_tool_paths() -> io::Result<ClawVpnInterfaceRouteToolPaths> {
        ClawVpnInterfaceRouteToolPaths::try_new(
            LINUX_IP_TOOL_PATH,
            MACOS_IFCONFIG_TOOL_PATH,
            MACOS_ROUTE_TOOL_PATH,
        )
        .map_err(|error| io::Error::other(format!("{error:?}")))
    }

    #[cfg(target_os = "linux")]
    fn build_inputs(
        _config: &ValidatedDevRunnerSessionConfig,
        _context: ClawVpnRuntimeWiringContext,
        relay: ClawVpnPollableTargetSessionRelay,
    ) -> io::Result<ClawVpnRuntimeWiringInputs<DevPacketInterface, ClawVpnPollableTargetSessionRelay>>
    {
        let tun_name = ClawVpnLinuxTunName::new(DEV_LINUX_TUN_NAME)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let device = ClawVpnLinuxTunDevice::open(&ClawVpnLinuxTunConfig::new(tun_name))?;
        device.set_nonblocking()?;
        let interface_name = ClawVpnInterfaceName::new(device.name().as_str())
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        Ok(ClawVpnRuntimeWiringInputs {
            route_platform: ClawVpnInterfaceRoutePlatform::Linux,
            interface_name,
            route_tool_paths: route_tool_paths()?,
            interface: device,
            relay,
        })
    }

    #[cfg(target_os = "macos")]
    fn build_inputs(
        _config: &ValidatedDevRunnerSessionConfig,
        _context: ClawVpnRuntimeWiringContext,
        relay: ClawVpnPollableTargetSessionRelay,
    ) -> io::Result<ClawVpnRuntimeWiringInputs<DevPacketInterface, ClawVpnPollableTargetSessionRelay>>
    {
        let device = ClawVpnMacosUtunDevice::open()?;
        device.set_nonblocking()?;
        let interface_name = ClawVpnInterfaceName::new(device.name().as_str())
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        Ok(ClawVpnRuntimeWiringInputs {
            route_platform: ClawVpnInterfaceRoutePlatform::Macos,
            interface_name,
            route_tool_paths: route_tool_paths()?,
            interface: device,
            relay,
        })
    }

    fn map_runtime_error(error: &ClawVpnTargetSessionRuntimeError<io::Error>) -> anyhow::Error {
        match error {
            ClawVpnTargetSessionRuntimeError::Session(_) => {
                anyhow!("dev datapath session core failed")
            }
            ClawVpnTargetSessionRuntimeError::TargetSessionRelay(_) => {
                anyhow!("dev datapath target-session relay failed")
            }
            ClawVpnTargetSessionRuntimeError::Inputs(_) => {
                anyhow!("dev datapath runtime inputs failed")
            }
        }
    }

    /// Redacted, static label for a pump stop reason. The `IoError` arm ignores
    /// the embedded error so an io error can never leak an address, endpoint, or
    /// path into the datapath's stopped-summary evidence line.
    pub(super) fn stop_reason_label(reason: &ClawVpnPollablePumpStopReason) -> &'static str {
        match reason {
            ClawVpnPollablePumpStopReason::IdleBudgetExhausted => "idle_budget_exhausted",
            ClawVpnPollablePumpStopReason::StepBudgetExhausted => "step_budget_exhausted",
            ClawVpnPollablePumpStopReason::PartialFrameStalled => "partial_frame_stalled",
            ClawVpnPollablePumpStopReason::IoError { .. } => "io_error",
        }
    }

    async fn pipe_target_session_to_tunnel<S>(
        stream: S,
        mut target_session: TargetSession,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut tunnel_r, mut tunnel_w) = tokio::io::split(stream);
        let mut buf = vec![0u8; PIPE_CHUNK];
        loop {
            tokio::select! {
                read = target_session.reader.read(&mut buf) => {
                    match read {
                        Ok(0) | Err(_) => {
                            let _ = send_frame(&mut tunnel_w, &TunnelFrame::Close).await;
                            return Ok(());
                        }
                        Ok(n) => send_frame(&mut tunnel_w, &TunnelFrame::Data(buf[..n].to_vec())).await
                            .map_err(|error| anyhow!("dev datapath tunnel write failed: {error}"))?,
                    }
                }
                frame = recv_frame(&mut tunnel_r) => {
                    match frame.map_err(|error| anyhow!("dev datapath tunnel read failed: {error}"))? {
                        TunnelFrame::Data(packet) => {
                            target_session.writer.write_all(&packet).await
                                .map_err(|_| anyhow!("dev datapath target write failed"))?;
                            target_session.writer.flush().await
                                .map_err(|_| anyhow!("dev datapath target flush failed"))?;
                        }
                        TunnelFrame::Window(_) | TunnelFrame::Resize { .. } => {}
                        TunnelFrame::Close => {
                            let _ = target_session.writer.shutdown().await;
                            return Ok(());
                        }
                        TunnelFrame::Error(_) => bail!("dev datapath peer returned target error"),
                        TunnelFrame::Exit(_) => return Ok(()),
                        TunnelFrame::Health(_) | TunnelFrame::Open => {
                            bail!("dev datapath peer sent unexpected control frame");
                        }
                        TunnelFrame::NetworkSettings(sealed) => {
                            // IpTunnel path: the server delivers the guest's VPN
                            // interface here (once, right after the Open-ack). This
                            // dev runner installs no real interface, but it MUST
                            // consume the frame (never a silent noop) and enforce the
                            // client-side route-scope invariant, mirroring the iOS
                            // client: a default route (prefix 0) is rejected fail-closed.
                            //
                            // S0: the body is sealed, so it is read through the one
                            // strict door. Route scope is now checked with the neutral
                            // rule that travels with the type rather than by an
                            // open-coded `prefix_len == 0`, so this consumer also
                            // rejects a peer outside the prefix and a peer equal to
                            // addr — strictly more than it caught before.
                            let settings =
                                household_rs::claw_share_data_tunnel::decode_network_settings_body(
                                    &sealed,
                                )
                                .map_err(|_| anyhow!("dev datapath received a malformed NetworkSettings body"))?;
                            if let Some(violation) = settings.mesh_ipv4.route_scope_violation() {
                                bail!(
                                    "dev datapath received NetworkSettings violating route scope: {violation}"
                                );
                            }
                            // Follow the module's address-redaction discipline: log
                            // only the non-sensitive prefix length.
                            eprintln!(
                                "dev datapath: VPN NetworkSettings received (prefix_len={})",
                                settings.mesh_ipv4.prefix_len
                            );
                        }
                    }
                }
            }
        }
    }

    async fn run_device_datapath_with_inputs<I>(
        offer: &RelayStreamOfferContract,
        device_key: &P256Keypair,
        config: &ValidatedDevRunnerSessionConfig,
        now_unix: u64,
        runtime_config: ClawVpnRuntimeWiringConfig,
        build_runtime_inputs: impl FnOnce(
            &ValidatedDevRunnerSessionConfig,
            ClawVpnRuntimeWiringContext,
            ClawVpnPollableTargetSessionRelay,
        ) -> io::Result<
            ClawVpnRuntimeWiringInputs<I, ClawVpnPollableTargetSessionRelay>,
        >,
    ) -> Result<()>
    where
        I: ClawVpnPollablePacketInterface + Send + 'static,
    {
        validate_host_platform(config)?;
        let session_core = device_session_core(offer, device_key, config)?;
        let (session_ack, stream): (super::DevRunnerSessionAck, OpenedIpTunnelStream) =
            connect_open_iptunnel_session(offer, device_key, now_unix).await?;

        let runtime = assemble_claw_vpn_pollable_target_session_runtime(
            runtime_config,
            move || session_core,
            |context, relay| build_runtime_inputs(config, context, relay),
        )
        .map_err(|error| map_runtime_error(&error))?;
        let Some(runtime) = runtime else {
            bail!("dev datapath runtime disabled");
        };
        let (target_session, mut wiring) = runtime.into_parts();
        let runtime_handle =
            tokio::task::spawn_blocking(move || -> Result<ClawVpnPollableRuntimeReport> {
                wiring
                    .run_until_stopped()
                    .map_err(|error| anyhow!("dev datapath runtime stopped: {error:?}"))
            });

        println!(
            "OK: dev IpTunnel datapath started \
             (runner_session_ack_ok=true, runner_ack_mtu={}, \
             runner_session_id_present={}, runner_mesh_ipv6_present={}, \
             runner_tun_opened=true, runner_route_installed=true, \
             runner_packet_pump_started=true)",
            session_ack.mtu(),
            session_ack.session_id_present(),
            session_ack.mesh_ipv6_present()
        );
        let pipe_result = pipe_target_session_to_tunnel(stream, target_session).await;
        let runtime_report = runtime_handle
            .await
            .map_err(|_| anyhow!("dev datapath runtime join failed"))??;
        pipe_result?;

        // Authoritative pump/teardown evidence (redacted): plain integer counters
        // plus a STATIC stop-reason label. No session id / mesh / endpoint is
        // printed, and the stop reason is reduced to a &'static str so an embedded
        // io error can never leak an address, endpoint, or path into this line.
        let pump_report = runtime_report.pump_report();
        println!(
            "OK: dev IpTunnel datapath stopped \
             (runner_interface_to_relay_forwarded={}, \
             runner_interface_to_relay_dropped={}, \
             runner_relay_to_interface_forwarded={}, \
             runner_relay_to_interface_dropped={}, \
             runner_stop_reason={})",
            pump_report.stats.interface_to_relay_forwarded(),
            pump_report.stats.interface_to_relay_dropped(),
            pump_report.stats.relay_to_interface_forwarded(),
            pump_report.stats.relay_to_interface_dropped(),
            stop_reason_label(&pump_report.stop_reason),
        );
        Ok(())
    }

    pub(super) async fn run_device_datapath(
        offer: &RelayStreamOfferContract,
        device_key: &P256Keypair,
        config: &ValidatedDevRunnerSessionConfig,
        now_unix: u64,
    ) -> Result<()> {
        run_device_datapath_with_inputs(
            offer,
            device_key,
            config,
            now_unix,
            enabled_runtime_config(),
            build_inputs,
        )
        .await
    }

    #[cfg(test)]
    pub(super) async fn run_device_datapath_with_test_inputs<I>(
        offer: &RelayStreamOfferContract,
        device_key: &P256Keypair,
        config: &ValidatedDevRunnerSessionConfig,
        now_unix: u64,
        runtime_config: ClawVpnRuntimeWiringConfig,
        build_runtime_inputs: impl FnOnce(
            &ValidatedDevRunnerSessionConfig,
            ClawVpnRuntimeWiringContext,
            ClawVpnPollableTargetSessionRelay,
        ) -> io::Result<
            ClawVpnRuntimeWiringInputs<I, ClawVpnPollableTargetSessionRelay>,
        >,
    ) -> Result<()>
    where
        I: ClawVpnPollablePacketInterface + Send + 'static,
    {
        run_device_datapath_with_inputs(
            offer,
            device_key,
            config,
            now_unix,
            runtime_config,
            build_runtime_inputs,
        )
        .await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ValidateOffer { offer_file } => {
            validate_iptunnel_offer_file(&offer_file)?;
            println!(
                "OK: dev IpTunnel offer shape validated \
                 (group_present=true, member_present=true, claw_present=true, \
                 endpoint_shape_valid=true)"
            );
        }
        Command::ValidateSessionConfig { config_file } => {
            let config = validate_session_config_file(&config_file)?;
            println!(
                "OK: dev IpTunnel session config shape validated \
                 (device_ipv4_present={}, claw_ipv4_present={}, \
                 claw_route_prefix_len={}, runner_config_mtu={}, \
                 runner_tun_opened=false, runner_route_installed=false, \
                 runner_packet_pump_started=false)",
                config.device_ipv4_present(),
                config.claw_ipv4_present(),
                config.claw_route_prefix_len(),
                config.mtu()
            );
        }
        Command::GenDeviceKeypair { secret_out } => {
            let generated = generate_device_keypair_to_file(&secret_out)?;
            // The secret scalar is never printed — only written to secret_out at
            // mode 0600. The public key is public material, safe to print, and is
            // the value the operator passes to the serving claw's
            // --guest-device-pub.
            println!(
                "OK: dev device keypair generated \
                 (secret_written=true, secret_file_mode=0600, secret_printed=false, \
                 guest_device_pub_len={}, secret_roundtrip_ok=true, pub_sec1_ok=true)",
                generated.guest_device_pub_hex.len()
            );
            println!("guest-device-pub: {}", generated.guest_device_pub_hex);
        }
        Command::OpenSession {
            offer_file,
            device_secret_file,
            dev_host_ack,
        } => {
            validate_dev_host_ack(&dev_host_ack)?;
            let offer = read_iptunnel_offer_file(&offer_file)?;
            let device_key = read_device_secret_file(&device_secret_file)?;
            let session_ack = open_iptunnel_session(&offer, &device_key, current_unix()?).await?;
            println!(
                "OK: dev IpTunnel session opened \
                 (auth_ok=true, health_ok=true, stream_open=true, \
                 runner_session_ack_ok=true, runner_ack_mtu={}, \
                 runner_session_id_present={}, runner_mesh_ipv6_present={}, \
                 runner_tun_opened=false, runner_route_installed=false, \
                 runner_packet_pump_started=false)",
                session_ack.mtu(),
                session_ack.session_id_present(),
                session_ack.mesh_ipv6_present()
            );
        }
        #[cfg(feature = "dev_t1_datapath")]
        Command::RunDeviceDatapath {
            offer_file,
            device_secret_file,
            config_file,
            dev_host_ack,
            allow_public_relay_ack,
        } => {
            let offer = read_iptunnel_offer_file(&offer_file)?;
            dev_datapath::validate_dev_datapath_runtime_gates(
                &offer,
                &dev_host_ack,
                allow_public_relay_ack.as_deref(),
            )?;
            let config = validate_session_config_file(&config_file)?;
            let device_key = read_device_secret_file(&device_secret_file)?;
            dev_datapath::run_device_datapath(&offer, &device_key, &config, current_unix()?)
                .await?;
        }
        #[cfg(feature = "dev_t1_datapath")]
        Command::GenDeviceConfig {
            platform,
            pool_network,
            session_index,
            mtu,
            out,
        } => {
            let (network, prefix_len) = parse_pool_cidr(&pool_network)?;
            let bytes = generate_device_session_config_bytes(
                platform.into(),
                network,
                prefix_len,
                session_index,
                mtu,
            )?;
            // Fail closed: re-run the runner's own validator on the emitted bytes
            // so a generated file always round-trips before it is written.
            validate_session_config_bytes(&bytes)?;
            std::fs::write(&out, &bytes).context("write dev session config file")?;
            println!(
                "OK: dev IpTunnel session config generated \
                 (schema_valid=true, scope_valid=true, production_activation=false, \
                 local_side_device=true, claw_route_prefix_len=32, \
                 runner_config_written=true)"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use household_rs::claw_share::{GuestCredential, SlotId};
    use household_rs::claw_share_data_tunnel::{
        ClawTargetRouter, DataTunnelError, DataTunnelSession, TargetSession, credential_hash,
        serve_connection_io_with_auth_deadline,
    };
    use household_rs::claw_share_relay_stream_contract::{
        RelayStreamClawStaticPublicKey, RelayStreamOfferMintInput, mint_relay_stream_group_offer,
        mint_relay_stream_offer, mint_relay_stream_public_offer,
    };
    use household_rs::claw_share_rendezvous_token::RendezvousToken;
    use household_rs::ids::derive_household_id;
    use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
    use household_rs::person_cert::derive_person_id;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::AsyncWriteExt;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    /// A unique temp path that is removed on drop — avoids a `tempfile` dev-dep.
    struct TempSecretPath(std::path::PathBuf);

    impl TempSecretPath {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::AtomicU64;
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1-gen-device-keypair-{}-{unique}-{tag}.hex",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempSecretPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn hex_roundtrips() {
        let bytes = [0x00u8, 0x02, 0xab, 0xff, 0x10];
        assert_eq!(encode_lower_hex(&bytes), "0002abff10");
        assert_eq!(
            decode_lower_hex("0002abff10").expect("valid"),
            bytes.to_vec()
        );
    }

    #[test]
    fn decode_lower_hex_rejects_malformed() {
        assert!(decode_lower_hex("abc").is_err(), "odd length rejected");
        assert!(decode_lower_hex("zz").is_err(), "non-hex rejected");
        assert_eq!(decode_lower_hex("02af").expect("valid"), vec![0x02, 0xaf]);
    }

    #[test]
    fn gen_device_keypair_writes_0600_secret_and_matching_66hex_pub() {
        use std::os::unix::fs::PermissionsExt as _;

        let secret_path = TempSecretPath::new("match");
        let generated =
            generate_device_keypair_to_file(secret_path.path()).expect("keypair generation");

        // Emitted guest-device-pub is a 66-hex SEC1-compressed key (02/03 tag).
        assert_eq!(generated.guest_device_pub_hex.len(), 66);
        assert!(
            generated.guest_device_pub_hex.starts_with("02")
                || generated.guest_device_pub_hex.starts_with("03"),
            "pub must carry a SEC1 compressed tag"
        );

        // Secret file is owner-only 0600 and holds a 64-hex scalar.
        let mode = std::fs::metadata(secret_path.path())
            .expect("secret file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "secret file must be mode 0600");
        let secret_contents = std::fs::read_to_string(secret_path.path()).expect("read secret");
        assert_eq!(secret_contents.trim().len(), 64, "secret is 64-hex");

        // The written secret re-derives EXACTLY the emitted public key, through
        // the same reader + SEC1 decoder the run path uses.
        let rederived = device_secret_from_hex(secret_contents.trim())
            .expect("secret re-reads via the runner's own reader");
        let decoded_pub = decode_lower_hex(&generated.guest_device_pub_hex).expect("pub decodes");
        let claw_pub = P256PublicKey::from_bytes(&decoded_pub)
            .expect("pub passes the serving claw's SEC1 decoder");
        assert_eq!(
            rederived.public(),
            claw_pub,
            "device secret and guest-device-pub must be a matched keypair"
        );
    }

    #[test]
    fn gen_device_keypair_refuses_to_overwrite_existing_secret() {
        let secret_path = TempSecretPath::new("nooverwrite");
        std::fs::write(secret_path.path(), "preexisting-do-not-clobber")
            .expect("seed a pre-existing file");

        let Err(error) = generate_device_keypair_to_file(secret_path.path()) else {
            panic!("must refuse to overwrite an existing secret file");
        };
        assert!(
            format!("{error:?}").contains("refusing to overwrite"),
            "error must name the no-clobber refusal, got: {error:?}"
        );
        // The pre-existing content is untouched (fail closed, no partial write).
        assert_eq!(
            std::fs::read_to_string(secret_path.path()).expect("read secret"),
            "preexisting-do-not-clobber"
        );
    }

    #[test]
    fn gen_device_keypair_produces_fresh_distinct_keys() {
        let first_path = TempSecretPath::new("distinct-a");
        let second_path = TempSecretPath::new("distinct-b");
        let first = generate_device_keypair_to_file(first_path.path()).expect("first keypair");
        let second = generate_device_keypair_to_file(second_path.path()).expect("second keypair");
        // Distinct PUBLIC keys prove fresh randomness without ever reading the
        // secret files back: a distinct-secret assertion would print the real
        // secrets to the test log on failure, which a secret helper must never do.
        assert_ne!(
            first.guest_device_pub_hex, second.guest_device_pub_hex,
            "each generation must draw fresh randomness"
        );
    }

    fn key(seed: u8) -> P256Keypair {
        P256Keypair::from_secret_scalar(&[seed; 32]).expect("p256 keypair")
    }

    fn claw_static_pub() -> RelayStreamClawStaticPublicKey {
        RelayStreamClawStaticPublicKey::try_new([0x33; 32]).expect("claw static key")
    }

    fn valid_session_config_json() -> String {
        format!(
            r#"{{
                "schema": "{DEV_RUNNER_SESSION_CONFIG_SCHEMA}",
                "scope": "{DEV_RUNNER_SESSION_CONFIG_SCOPE}",
                "production_activation": false,
                "platform": "macos",
                "local_side": "device",
                "device_ipv4": "198.18.0.1",
                "claw_ipv4": "198.18.0.2",
                "claw_route_prefix_len": 32,
                "mtu": 1280
            }}"#
        )
    }

    fn rendezvous_token() -> RendezvousToken {
        RendezvousToken::try_new(vec![0x42; 16]).expect("rendezvous token")
    }

    fn credential(owner: &P256Keypair, guest_pub: &P256PublicKey) -> GuestCredential {
        GuestCredential::sign(
            derive_household_id(&owner.public()),
            derive_person_id(&owner.public()),
            owner.public(),
            "claw-alpha".to_string(),
            guest_pub.clone(),
            SlotId([0x22; 16]),
            NOW - 60,
            NOW + 600,
            owner as &dyn IdentityKey,
        )
        .expect("guest credential")
    }

    fn member_iptunnel_offer() -> (RelayStreamOfferContract, P256Keypair) {
        let owner = key(0x11);
        let device = key(0x33);
        let offer = mint_relay_stream_group_offer(
            rendezvous_token(),
            SlotId([0x99; 16]),
            "group-alpha".to_string(),
            "member-alpha".to_string(),
            device.public(),
            "claw-alpha".to_string(),
            RelayStreamResource::IpTunnel,
            "relay-stream://127.0.0.1:49152".to_string(),
            claw_static_pub(),
            NOW + 60,
            NOW,
            &owner as &dyn IdentityKey,
        )
        .expect("member IpTunnel offer");
        (offer, device)
    }

    #[derive(Clone)]
    struct TestSession {
        session_id: &'static str,
        mesh_ipv6: &'static str,
    }

    impl TestSession {
        fn valid() -> Self {
            Self {
                session_id: "session-alpha",
                mesh_ipv6: "fd00::1",
            }
        }

        fn invalid_mesh() -> Self {
            Self {
                session_id: "session-alpha",
                mesh_ipv6: "SECRET-MESH",
            }
        }
    }

    impl DataTunnelSession for TestSession {
        fn session_id(&self) -> String {
            self.session_id.to_string()
        }

        fn mesh_ipv6(&self) -> String {
            self.mesh_ipv6.to_string()
        }
    }

    struct CountingRouter {
        opens: Arc<AtomicUsize>,
    }

    impl ClawTargetRouter for CountingRouter {
        async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let (client, mut target) = tokio::io::duplex(64);
            tokio::spawn(async move {
                let _ = target.shutdown().await;
            });
            Ok(TargetSession::from_stream(client))
        }
    }

    async fn run_scripted_data_tunnel_server(
        server: tokio::io::DuplexStream,
        offer: RelayStreamOfferContract,
        expect_auth_success: bool,
        session: TestSession,
        opens: Arc<AtomicUsize>,
    ) -> Result<(), DataTunnelError> {
        let expected_cbor = offer.payload.to_canonical_bytes().expect("offer cbor");
        let verify_called = Arc::new(AtomicBool::new(false));
        let verify_called_for_closure = Arc::clone(&verify_called);
        let verify_session = session.clone();
        let verify = move |envelope: &household_rs::claw_share_data_tunnel::AuthEnvelope,
                           now_unix: u64| {
            verify_called_for_closure.store(true, Ordering::SeqCst);
            if !expect_auth_success {
                return Err(DataTunnelError::TokenRejected(
                    "synthetic-reject".to_string(),
                ));
            }
            if envelope.credential_cbor != expected_cbor {
                return Err(DataTunnelError::Rejected(
                    "unexpected-offer-payload".to_string(),
                ));
            }
            let expected_hash = credential_hash(&envelope.credential_cbor);
            envelope
                .token
                .verify(&offer.payload.guest_device_pub, &expected_hash, now_unix)?;
            if envelope.token.endpoint != offer.payload.relay_endpoint {
                return Err(DataTunnelError::TokenRejected(
                    "endpoint-mismatch".to_string(),
                ));
            }
            if envelope.token.target_id != offer.payload.claw_id {
                return Err(DataTunnelError::TokenRejected(
                    "target-mismatch".to_string(),
                ));
            }
            Ok(verify_session.clone())
        };
        let router = CountingRouter { opens };
        let result = serve_connection_io_with_auth_deadline(
            server,
            NOW,
            verify,
            &router,
            |_session: &TestSession| false,
            std::time::Duration::from_secs(1),
        )
        .await;
        assert!(verify_called.load(Ordering::SeqCst));
        result
    }

    #[test]
    fn accepts_member_scoped_iptunnel_offer_shape() {
        let (offer, _device) = member_iptunnel_offer();
        let validated = validate_iptunnel_offer_bytes(&offer.to_canonical_bytes().unwrap())
            .expect("member-scoped IpTunnel offer accepted");

        assert_eq!(validated, ValidatedIpTunnelOffer);
    }

    #[test]
    fn rejects_non_iptunnel_offer() {
        let owner = key(0x11);
        let guest = key(0x33);
        let credential = credential(&owner, &guest.public());
        let offer = mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                rendezvous_token: rendezvous_token(),
                credential: &credential,
                resource: RelayStreamResource::Pty,
                expected_path: RelayStreamExpectedPath::RelayStream,
                relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
                claw_static_pub: claw_static_pub(),
                not_after: NOW + 60,
                now_unix: NOW,
            },
            &owner as &dyn IdentityKey,
        )
        .expect("PTY offer");

        let error = validate_iptunnel_offer(&offer).expect_err("PTY is not IpTunnel");
        assert!(error.to_string().contains("resource is not IpTunnel"));
    }

    #[test]
    fn rejects_device_scoped_iptunnel_offer() {
        let owner = key(0x11);
        let guest = key(0x33);
        let credential = credential(&owner, &guest.public());
        let offer = mint_relay_stream_offer(
            RelayStreamOfferMintInput {
                rendezvous_token: rendezvous_token(),
                credential: &credential,
                resource: RelayStreamResource::IpTunnel,
                expected_path: RelayStreamExpectedPath::RelayStream,
                relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
                claw_static_pub: claw_static_pub(),
                not_after: NOW + 60,
                now_unix: NOW,
            },
            &owner as &dyn IdentityKey,
        )
        .expect("Device IpTunnel offer");

        let error = validate_iptunnel_offer(&offer).expect_err("Device offer must not validate");
        assert!(error.to_string().contains("member-scoped group audience"));
    }

    #[test]
    fn rejects_public_iptunnel_offer() {
        let owner = key(0x11);
        let device = key(0x33);
        let offer = mint_relay_stream_public_offer(
            rendezvous_token(),
            SlotId([0x98; 16]),
            device.public(),
            "claw-alpha".to_string(),
            RelayStreamResource::IpTunnel,
            "relay-stream://127.0.0.1:49152".to_string(),
            claw_static_pub(),
            NOW + 60,
            NOW,
            &owner as &dyn IdentityKey,
        )
        .expect("Public IpTunnel offer");

        let error = validate_iptunnel_offer(&offer).expect_err("Public offer must not validate");
        assert!(error.to_string().contains("member-scoped group audience"));
    }

    #[test]
    fn rejects_invalid_relay_endpoint_shape() {
        let (mut offer, _device) = member_iptunnel_offer();
        offer.payload.relay_endpoint = "https://127.0.0.1:49152".to_string();

        let error = validate_iptunnel_offer(&offer).expect_err("endpoint scheme rejected");
        assert!(error.to_string().contains("validate relay endpoint shape"));
    }

    #[test]
    fn open_session_requires_exact_dev_host_ack() {
        assert!(validate_dev_host_ack(DEV_HOST_ACK).is_ok());
        let error = validate_dev_host_ack("dev-host T1-T4 only").expect_err("partial ack rejected");
        assert!(error.to_string().contains("acknowledgement"));
    }

    #[test]
    fn validates_reviewed_session_config_shape_without_echoing_addresses() {
        let config = validate_session_config_bytes(valid_session_config_json().as_bytes())
            .expect("valid config");

        assert!(config.device_ipv4_present());
        assert!(config.claw_ipv4_present());
        assert_eq!(config.claw_route_prefix_len(), 32);
        assert_eq!(config.mtu(), 1280);

        let debug = format!("{config:?}");
        assert!(debug.contains("claw_route_prefix_len"));
        assert!(debug.contains("mtu"));
        assert!(!debug.contains("198.18.0.1"));
        assert!(!debug.contains("198.18.0.2"));
    }

    #[test]
    fn session_config_rejects_invalid_values_without_echoing_them() {
        let bad_address = valid_session_config_json().replace("198.18.0.1", "SECRET-DEVICE-IP");
        let error = validate_session_config_bytes(bad_address.as_bytes())
            .expect_err("bad address rejected");
        let message = format!("{error:#}");
        assert!(message.contains("device_ipv4 must be a valid IPv4 address"));
        assert!(!message.contains("SECRET-DEVICE-IP"));

        let broad_route = valid_session_config_json().replace(
            r#""claw_route_prefix_len": 32"#,
            r#""claw_route_prefix_len": 24"#,
        );
        let error = validate_session_config_bytes(broad_route.as_bytes())
            .expect_err("broad route rejected");
        assert!(
            error
                .to_string()
                .contains("claw_route_prefix_len must be 32")
        );
    }

    #[test]
    fn session_config_stays_non_production_device_side_only() {
        let prod_config = valid_session_config_json().replace(
            r#""production_activation": false"#,
            r#""production_activation": true"#,
        );
        let error = validate_session_config_bytes(prod_config.as_bytes())
            .expect_err("production activation rejected");
        assert!(
            error
                .to_string()
                .contains("production_activation must be false")
        );

        let claw_side = valid_session_config_json()
            .replace(r#""local_side": "device""#, r#""local_side": "claw""#);
        let error = validate_session_config_bytes(claw_side.as_bytes())
            .expect_err("non-device local side rejected");
        assert!(error.to_string().contains("local_side must be device"));
    }

    #[test]
    fn session_config_rejects_invalid_schema_scope_platform_and_mtu() {
        let bad_schema = valid_session_config_json().replace(
            DEV_RUNNER_SESSION_CONFIG_SCHEMA,
            "t1-dev-runner-device-session-v0",
        );
        let error =
            validate_session_config_bytes(bad_schema.as_bytes()).expect_err("schema rejected");
        assert!(error.to_string().contains("schema invalid"));

        let bad_scope =
            valid_session_config_json().replace(DEV_RUNNER_SESSION_CONFIG_SCOPE, "dev-host");
        let error =
            validate_session_config_bytes(bad_scope.as_bytes()).expect_err("scope rejected");
        assert!(error.to_string().contains("scope invalid"));

        let bad_platform =
            valid_session_config_json().replace(r#""platform": "macos""#, r#""platform": "ios""#);
        let error =
            validate_session_config_bytes(bad_platform.as_bytes()).expect_err("platform rejected");
        assert!(error.to_string().contains("platform invalid"));

        for invalid_mtu in [1279, 9001] {
            let bad_mtu = valid_session_config_json()
                .replace(r#""mtu": 1280"#, &format!(r#""mtu": {invalid_mtu}"#));
            let error =
                validate_session_config_bytes(bad_mtu.as_bytes()).expect_err("mtu rejected");
            assert!(error.to_string().contains("mtu invalid"));
        }
    }

    #[test]
    fn device_secret_rejects_non_ascii_without_echoing_secret() {
        let mut secret = "11".repeat(31);
        secret.push('\u{00e9}');
        assert_eq!(secret.len(), 64);

        let Err(error) = device_secret_from_hex(&secret) else {
            panic!("non-ascii secret accepted");
        };
        let message = format!("{error:#}");

        assert!(message.contains("device secret must be 64 hex chars"));
        assert!(!message.contains(&secret));
        assert!(!message.contains('\u{00e9}'));
    }

    #[test]
    fn open_session_rejects_device_key_mismatch_before_dial() {
        let (offer, _device) = member_iptunnel_offer();
        let wrong_device = key(0x44);

        let error = validate_open_session_inputs(&offer, &wrong_device)
            .expect_err("wrong device key must be rejected");

        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn open_session_token_binds_offer_hash_endpoint_and_claw() {
        let (offer, device) = member_iptunnel_offer();
        let nonce = vec![0x55; 16];

        let (offer_cbor, token) = build_iptunnel_session_auth(&offer, &device, NOW, nonce.clone())
            .expect("session token");

        assert_eq!(
            token.credential_hash,
            household_rs::claw_share_data_tunnel::credential_hash(&offer_cbor)
        );
        assert_eq!(token.endpoint, offer.payload.relay_endpoint);
        assert_eq!(token.target_id, offer.payload.claw_id);
        assert_eq!(token.nonce, nonce);
        assert_eq!(token.expires_at, NOW + 60);
        token
            .verify(&device.public(), &token.credential_hash, NOW)
            .expect("token verifies with offer device");
    }

    #[test]
    fn session_ack_debug_redacts_mesh_and_session_id() {
        let ack = validate_session_ack(TunnelAck::Ok {
            mesh_ipv6: "fd00::1".to_string(),
            mtu: 1280,
            session_id: "secret-session".to_string(),
        })
        .expect("ack validates");

        let debug = format!("{ack:?}");
        assert!(debug.contains("session_id_present"));
        assert!(debug.contains("mtu"));
        assert!(!debug.contains("fd00::1"));
        assert!(!debug.contains("secret-session"));
    }

    #[test]
    fn session_ack_rejects_invalid_values_without_echoing_them() {
        let error = validate_session_ack(TunnelAck::Ok {
            mesh_ipv6: "SECRET-MESH".to_string(),
            mtu: 1280,
            session_id: "session-alpha".to_string(),
        })
        .expect_err("bad mesh address rejected");
        let message = format!("{error:#}");

        assert!(message.contains("IpTunnel session ack mesh address invalid"));
        assert!(!message.contains("SECRET-MESH"));

        let error = validate_session_ack(TunnelAck::Ok {
            mesh_ipv6: "fd00::1".to_string(),
            mtu: 0,
            session_id: "session-alpha".to_string(),
        })
        .expect_err("bad mtu rejected");
        assert!(error.to_string().contains("session ack mtu invalid"));
    }

    #[tokio::test]
    async fn open_session_sequence_authenticates_health_checks_and_opens_stream() {
        let (offer, device) = member_iptunnel_offer();
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let opens = Arc::new(AtomicUsize::new(0));
        let server_opens = Arc::clone(&opens);
        let server_offer = offer.clone();
        let server_task = tokio::spawn(async move {
            run_scripted_data_tunnel_server(
                server,
                server_offer,
                true,
                TestSession::valid(),
                server_opens,
            )
            .await
        });

        let session_ack = authenticate_open_iptunnel_session(&mut client, &offer, &device, NOW)
            .await
            .expect("auth + health + open succeed");
        assert_eq!(session_ack.mtu(), 1280);
        assert!(session_ack.session_id_present());
        assert!(session_ack.mesh_ipv6_present());
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        server_task.abort();
        assert!(server_task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn open_session_rejects_invalid_session_ack_before_opening_stream() {
        let (offer, device) = member_iptunnel_offer();
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let opens = Arc::new(AtomicUsize::new(0));
        let server_opens = Arc::clone(&opens);
        let server_offer = offer.clone();
        let server_task = tokio::spawn(async move {
            run_scripted_data_tunnel_server(
                server,
                server_offer,
                true,
                TestSession::invalid_mesh(),
                server_opens,
            )
            .await
        });

        let error = authenticate_open_iptunnel_session(&mut client, &offer, &device, NOW)
            .await
            .expect_err("invalid ack fails closed");
        let message = format!("{error:#}");
        assert!(message.contains("IpTunnel session ack mesh address invalid"));
        assert!(!message.contains("SECRET-MESH"));
        drop(client);

        let server_result = tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
            .await
            .expect("server exits")
            .expect("server task joins");
        assert!(server_result.is_ok());
        assert_eq!(opens.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn open_session_rejects_tunnel_ack_rejected_before_opening_stream() {
        let (offer, device) = member_iptunnel_offer();
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let opens = Arc::new(AtomicUsize::new(0));
        let server_opens = Arc::clone(&opens);
        let server_offer = offer.clone();
        let server_task = tokio::spawn(async move {
            run_scripted_data_tunnel_server(
                server,
                server_offer,
                false,
                TestSession::valid(),
                server_opens,
            )
            .await
        });

        let error = authenticate_open_iptunnel_session(&mut client, &offer, &device, NOW)
            .await
            .expect_err("rejected ack fails closed");
        assert!(error.to_string().contains("synthetic-reject"));
        drop(client);

        let server_result = tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
            .await
            .expect("server exits")
            .expect("server task joins");
        assert!(matches!(
            server_result,
            Err(DataTunnelError::TokenRejected(reason)) if reason == "synthetic-reject"
        ));
        assert_eq!(opens.load(Ordering::SeqCst), 0);
    }

    fn source_without_dev_datapath_module(source: &str) -> String {
        let Some(start) = source.find("#[cfg(feature = \"dev_t1_datapath\")]\nmod dev_datapath")
        else {
            return source.to_string();
        };
        let Some(end) = source[start..].find("#[tokio::main]") else {
            return source.to_string();
        };
        let end = start + end;
        let mut bounded = String::new();
        bounded.push_str(&source[..start]);
        bounded.push_str(&source[end..]);
        bounded
    }

    #[test]
    fn source_keeps_session_open_boundary_bounded() {
        let source = source_without_dev_datapath_module(include_str!("main.rs"));
        assert!(source.contains("OpenSession"));
        assert!(source.contains(DEV_HOST_ACK));
        for forbidden in [
            concat!("std::process::", "Command"),
            concat!("/dev/", "tun"),
            concat!("u", "tun"),
            concat!("route", " add"),
            concat!("ip ", "route"),
            concat!("if", "config"),
            concat!("Soyeht", ".app"),
            concat!("Soyeht", " Dev.app"),
        ] {
            assert!(
                !source.contains(forbidden),
                "dev session opener must not cross into TUN/route/app control: {forbidden}"
            );
        }
    }

    #[cfg(feature = "dev_t1_datapath")]
    #[test]
    fn dev_datapath_runtime_gates_are_default_off_and_no_value_echo() {
        let (offer, _device) = member_iptunnel_offer();

        let error = dev_datapath::validate_dev_datapath_runtime_gates_with_env(
            &offer,
            DEV_HOST_ACK,
            None,
            |_| None,
        )
        .expect_err("datapath env gate is required");
        assert!(error.to_string().contains(DEV_DATAPATH_ENV));

        let error = dev_datapath::validate_dev_datapath_runtime_gates_with_env(
            &offer,
            DEV_HOST_ACK,
            None,
            |name| (name == DEV_DATAPATH_ENV).then(|| "1".to_string()),
        )
        .expect_err("software key env gate is required");
        assert!(error.to_string().contains(DEV_SOFTWARE_KEYS_ENV));

        let error = dev_datapath::validate_dev_datapath_runtime_gates_with_env(
            &offer,
            "partial acknowledgement",
            None,
            |name| {
                matches!(name, DEV_DATAPATH_ENV | DEV_SOFTWARE_KEYS_ENV).then(|| "1".to_string())
            },
        )
        .expect_err("exact dev host ack is required");
        assert!(error.to_string().contains("acknowledgement"));
    }

    #[cfg(feature = "dev_t1_datapath")]
    #[test]
    fn dev_datapath_non_loopback_requires_second_ack_without_endpoint_echo() {
        let (mut offer, _device) = member_iptunnel_offer();
        offer.payload.relay_endpoint = "relay-stream://203.0.113.10:49152".to_string();
        let env = |name: &str| {
            matches!(name, DEV_DATAPATH_ENV | DEV_SOFTWARE_KEYS_ENV).then(|| "1".to_string())
        };

        let error = dev_datapath::validate_dev_datapath_runtime_gates_with_env(
            &offer,
            DEV_HOST_ACK,
            None,
            env,
        )
        .expect_err("non-loopback relay needs second ack");
        let message = error.to_string();
        assert!(message.contains("non-loopback relay"));
        assert!(!message.contains("203.0.113.10"));
        assert!(
            dev_datapath::validate_dev_datapath_runtime_gates_with_env(
                &offer,
                DEV_HOST_ACK,
                Some(DEV_PUBLIC_RELAY_ACK),
                env,
            )
            .is_ok()
        );
    }

    #[cfg(feature = "dev_t1_datapath")]
    #[test]
    fn datapath_stop_reason_label_is_static_and_never_echoes_error_detail() {
        use server_rs::claw_vpn_pollable_pump::{
            ClawVpnPollablePumpDirection, ClawVpnPollablePumpStopReason,
        };

        assert_eq!(
            dev_datapath::stop_reason_label(&ClawVpnPollablePumpStopReason::IdleBudgetExhausted),
            "idle_budget_exhausted"
        );
        assert_eq!(
            dev_datapath::stop_reason_label(&ClawVpnPollablePumpStopReason::StepBudgetExhausted),
            "step_budget_exhausted"
        );
        assert_eq!(
            dev_datapath::stop_reason_label(&ClawVpnPollablePumpStopReason::PartialFrameStalled),
            "partial_frame_stalled"
        );
        // The IoError variant must reduce to a static label. The pollable stop
        // reason carries only an `io::ErrorKind` (no source string), so nothing
        // an endpoint/path could ride on can reach this evidence line.
        let io_reason = ClawVpnPollablePumpStopReason::IoError {
            direction: ClawVpnPollablePumpDirection::InterfaceToRelay,
            kind: std::io::ErrorKind::ConnectionReset,
        };
        let label = dev_datapath::stop_reason_label(&io_reason);
        assert_eq!(label, "io_error");
    }

    #[cfg(feature = "dev_t1_datapath")]
    mod dev_datapath_two_end_integration {
        use super::*;

        use std::collections::BTreeMap;
        use std::net::{Ipv4Addr, SocketAddr};
        use std::path::PathBuf;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use household_rs::LoadedIdentity;
        use household_rs::claw_share::{ClawShareSlotStore, SLOT_ID_LEN};
        use household_rs::claw_share_data_tunnel::ReplayGuard;
        use household_rs::household_mesh_log::{
            MeshLogStore, MeshMembership, ProjectedGroup, ProjectedMemberDevice, ProjectedState,
        };
        use household_rs::household_record::HouseholdRecord;
        use household_rs::ids::{derive_household_id, derive_machine_id};
        use household_rs::machine_cert::{MachineCert, Platform, SignOptions};
        use server_rs::claw_share_relay_stream_abuse::RelayAbuseConfig;
        use server_rs::claw_share_relay_stream_admission::RelayStreamAdmission;
        use server_rs::claw_share_relay_stream_issuer_trust::{
            RelayStreamIssuerTrust, RelayStreamTrustContext,
        };
        use server_rs::claw_share_relay_stream_noise::generate_relay_stream_noise_static_keypair;
        use server_rs::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
        use server_rs::claw_share_relay_stream_responder_reverse_connect::{
            RelayStreamResponderReverseConnectConfig,
            serve_relay_stream_responder_reverse_connect_binding,
        };
        use server_rs::claw_share_relay_stream_reverse_connect_binding::bind_relay_stream_reverse_connect_with_ip_tunnel_router;
        use server_rs::claw_share_relay_stream_target_router::RelayStreamIpTunnelUnavailableRouter;
        use server_rs::claw_share_relay_stream_trust_context_health::{
            RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
        };
        use server_rs::claw_share_rendezvous_stream_relay_listener::{
            RendezvousStreamRelayListenerConfig, serve_rendezvous_stream_relay,
        };
        use server_rs::claw_share_session_clock::AdmissionInstant;
        use server_rs::claw_vpn_dev_config::ClawVpnDevConfig;
        use server_rs::claw_vpn_interface_route_plan::{
            ClawVpnInterfaceName, ClawVpnInterfaceRoutePlatform, ClawVpnInterfaceRouteToolPaths,
        };
        use server_rs::claw_vpn_packet_pump::ClawVpnPacketPumpProductionDriverBudget;
        use server_rs::claw_vpn_pollable_pump::ClawVpnPollablePacketInterface;
        use server_rs::claw_vpn_runtime::ClawVpnRuntimeStepBudget;
        use server_rs::claw_vpn_t1_relay_stream_router::{
            ClawVpnPollableT1RelayStreamBuildInputs, ClawVpnPollableT1RelayStreamLaunchRuntime,
            ClawVpnPollableT1RelayStreamRouterParts, ClawVpnT1RelayStreamAuditSink,
            assemble_claw_vpn_pollable_t1_relay_stream_router,
        };
        use server_rs::claw_vpn_target_session_relay::ClawVpnPollableTargetSessionRelay;
        use server_rs::claw_vpn_target_session_router::{
            ClawVpnPollableTargetSessionRouterWiring, ClawVpnTargetSessionRouterLaunchError,
        };
        use server_rs::claw_vpn_wiring::{ClawVpnRuntimeWiringConfig, ClawVpnRuntimeWiringInputs};
        use server_rs::household_state::HouseholdState;
        use server_rs::startup_wiring::PerClawVpnT1PreflightEvidence;
        use std::os::fd::{AsRawFd, RawFd};
        use std::os::unix::net::UnixDatagram;
        use tokio::net::TcpListener;
        use tokio::task::JoinHandle;

        const GROUP_ID: &str = "group-alpha";
        const GROUP_NAME: &str = "Group Alpha";
        const MEMBER_ID: &str = "member-alpha";
        const MEMBER_NPUB: &str = "member-alpha";
        const CLAW_ID: &str = "claw-alpha";
        const IPV4_POOL: &str = "198.18.0.0/24";

        // Factored out to satisfy clippy::type_complexity — the runtime handle
        // list is threaded through several two-ended-test helpers.
        type ClawRuntimeHandles = Arc<Mutex<Vec<JoinHandle<Result<(), String>>>>>;

        /// Real-fd device interface mock for the pollable datapath: the pump
        /// `poll()`s a `UnixDatagram` end. The paired peer injects inbound
        /// packets (`send`) and drains what the pump wrote (`recv`) — no fd-less
        /// pre-load, so the pump's own forwarding is what moves each packet.
        struct PollableMockInterface {
            stream: UnixDatagram,
        }

        impl PollableMockInterface {
            fn paired() -> std::io::Result<(Self, UnixDatagram)> {
                let (pump_side, peer) = UnixDatagram::pair()?;
                pump_side.set_nonblocking(true)?;
                peer.set_nonblocking(true)?;
                Ok((Self { stream: pump_side }, peer))
            }
        }

        impl ClawVpnPollablePacketInterface for PollableMockInterface {
            fn interface_fd(&self) -> RawFd {
                self.stream.as_raw_fd()
            }

            fn read_packet_nonblocking(
                &mut self,
                buf: &mut [u8],
            ) -> std::io::Result<Option<usize>> {
                match self.stream.recv(buf) {
                    Ok(n) => Ok(Some(n)),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                    Err(error) => Err(error),
                }
            }

            fn write_packet_nonblocking(&mut self, packet: &[u8]) -> std::io::Result<bool> {
                match self.stream.send(packet) {
                    Ok(n) if n == packet.len() => Ok(true),
                    Ok(_) => Ok(false),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
                    Err(error) => Err(error),
                }
            }
        }

        #[tokio::test]
        async fn dev_datapath_two_ends_forward_packets_over_loopback_relay_without_tun() {
            tokio::time::timeout(Duration::from_secs(10), async {
                let (relay_addr, relay_handle) = spawn_test_relay().await;
                let relay_endpoint = relay_endpoint_uri(relay_addr);
                let owner = key(0x11);
                let device = key(0x33);
                let root = key(0xAA);
                let noise_keypair = generate_relay_stream_noise_static_keypair()
                    .expect("generate responder noise keypair");
                let offer = mint_relay_stream_group_offer(
                    rendezvous_token(),
                    SlotId([0x99; SLOT_ID_LEN]),
                    GROUP_ID.to_string(),
                    MEMBER_ID.to_string(),
                    device.public(),
                    CLAW_ID.to_string(),
                    RelayStreamResource::IpTunnel,
                    relay_endpoint.clone(),
                    noise_keypair.public_key().clone(),
                    NOW + 600,
                    NOW,
                    &owner as &dyn IdentityKey,
                )
                .expect("mint group IpTunnel offer");
                let config =
                    validate_session_config_bytes(device_config_json().as_bytes()).expect("config");
                let addrs = config.addrs;
                // Two DISTINCT device packets (distinct IPv4 identification field,
                // still valid IPv4 that passes the session policy) so the claw-edge
                // assertion below cannot be false-greened by an accidental frame
                // duplication (@alaine).
                let mut device_packet_1 = ipv4_packet(addrs.device(), addrs.claw());
                device_packet_1[4..6].copy_from_slice(&0xA1u16.to_be_bytes());
                let mut device_packet_2 = ipv4_packet(addrs.device(), addrs.claw());
                device_packet_2[4..6].copy_from_slice(&0xA2u16.to_be_bytes());
                let claw_packet = ipv4_packet(addrs.claw(), addrs.device());
                let claw_runtime_handles: ClawRuntimeHandles = Arc::new(Mutex::new(Vec::new()));

                dev_datapath::validate_dev_datapath_runtime_gates_with_env(
                    &offer,
                    DEV_HOST_ACK,
                    None,
                    |name| {
                        matches!(name, DEV_DATAPATH_ENV | DEV_SOFTWARE_KEYS_ENV)
                            .then(|| "1".to_string())
                    },
                )
                .expect("runtime gates pass with explicit test env");

                let record = household_record(&root, &owner.public());
                let cert = machine_cert(&root, &owner.public());
                let projection = group_projection(&offer.payload.guest_device_pub);
                let trust = RelayStreamIssuerTrust::new({
                    let record = record.clone();
                    let cert = cert.clone();
                    let projection = projection.clone();
                    move || RelayStreamTrustContext {
                        record: record.clone(),
                        cert: cert.clone(),
                        projection: projection.clone(),
                    }
                });
                let params = RelayStreamResponderParams {
                    bind_addr: relay_addr,
                    auth_deadline: Duration::from_secs(2),
                    idle_timeout: Duration::from_secs(30),
                    admission: admission(&root, &owner, &record, &cert).await,
                    noise_keypair,
                };
                let (claw_iface, claw_peer) =
                    PollableMockInterface::paired().expect("claw interface pair");
                claw_peer
                    .send(&claw_packet)
                    .expect("inject the claw packet into the claw interface");
                let claw_router = claw_router(&relay_endpoint, claw_iface, &claw_runtime_handles);
                let binding = bind_relay_stream_reverse_connect_with_ip_tunnel_router(
                    Arc::new(offer.clone()),
                    trust,
                    record.hh_id.clone(),
                    Arc::new(ClawShareSlotStore::new()),
                    Arc::new(ReplayGuard::new()),
                    RelayStreamIpTunnelUnavailableRouter,
                    RelayStreamIpTunnelUnavailableRouter,
                    claw_router,
                    || Some(NOW),
                );
                // The fixed synthetic clock is usable by construction, so the seam
                // returns `Some`. Pairing goes through the public production-ordered
                // `capture_with`, which anchors BEFORE reading the wall; the
                // late-anchor `from_seam_wall` seam is `cfg(test)` inside server-rs
                // and is deliberately not reachable from this crate.
                let admission =
                    AdmissionInstant::capture_with(|| Some(NOW)).expect("plausible test clock");
                let claw_task = tokio::spawn(async move {
                    serve_relay_stream_responder_reverse_connect_binding(
                        reverse_config(relay_addr),
                        &binding,
                        &params,
                        admission,
                    )
                    .await
                });

                let (device_iface, device_peer) =
                    PollableMockInterface::paired().expect("device interface pair");
                // Asymmetric, off the old symmetric 1-each preload: the device side
                // bursts TWO distinct packets while the claw side sends ONE, so both
                // pollable pumps must forward uneven traffic without stalling.
                device_peer
                    .send(&device_packet_1)
                    .expect("inject the first device packet");
                device_peer
                    .send(&device_packet_2)
                    .expect("inject the second device packet");
                let device_datapath_outcome = dev_datapath::run_device_datapath_with_test_inputs(
                    &offer,
                    &device,
                    &config,
                    NOW,
                    bounded_runtime_config(16),
                    move |_config, context, relay| {
                        assert_eq!(context.addrs(), addrs);
                        Ok(pollable_runtime_inputs(device_iface, relay))
                    },
                )
                .await;
                // The pollable device pump forwards BOTH directions, then the claw
                // responder closes the tunnel at end-of-exchange — which the device
                // pump correctly surfaces as a fatal relay EOF (the same relay-EOF
                // semantics #300 proves). A clean stop or that end-of-exchange EOF is
                // acceptable; the authoritative proof is packet delivery, below. Any
                // OTHER failure is a real regression.
                if let Err(error) = &device_datapath_outcome {
                    let detail = format!("{error:?}");
                    // Accept ONLY the end-of-exchange relay EOF — not a route-cleanup
                    // failure that happens to stringify an EOF pump report (@brianna).
                    assert!(
                        detail.contains("UnexpectedEof") && !detail.contains("RouteCleanup"),
                        "device datapath must stop cleanly or on the end-of-exchange relay EOF \
                         (never a route-cleanup failure), got: {detail}"
                    );
                }

                claw_task
                    .await
                    .expect("claw task joins")
                    .expect("claw responder exits cleanly");
                for handle in drain_runtime_handles(&claw_runtime_handles) {
                    // Like the device side: the claw pollable pump forwards, then
                    // sees the device close the tunnel at end-of-exchange as a fatal
                    // relay EOF. A clean stop or that end-of-exchange EOF is fine;
                    // the delivery assertions below are the authoritative proof.
                    if let Err(detail) = handle.await.expect("claw runtime task joins") {
                        // Accept ONLY the end-of-exchange relay EOF — not a route-cleanup
                        // failure that stringifies an EOF pump report (@brianna).
                        assert!(
                            detail.contains("UnexpectedEof") && !detail.contains("RouteCleanup"),
                            "claw runtime must stop cleanly or on the end-of-exchange relay EOF \
                             (never a route-cleanup failure), got: {detail}"
                        );
                    }
                }
                relay_handle.abort();

                let mut device_received = Vec::new();
                let mut device_buf = vec![0u8; 2048];
                while let Ok(n) = device_peer.recv(&mut device_buf) {
                    device_received.push(device_buf[..n].to_vec());
                }
                let mut claw_received = Vec::new();
                let mut claw_buf = vec![0u8; 2048];
                while let Ok(n) = claw_peer.recv(&mut claw_buf) {
                    claw_received.push(claw_buf[..n].to_vec());
                }
                // Both pollable pumps forwarded uneven traffic without stalling. The
                // claw interface got EXACTLY the two DISTINCT device packets (not a
                // duplicated single frame — the false-green a symmetric 1-each preload
                // would have masked), and the device interface got exactly the one
                // claw packet. Exact counts + distinct identity, no extra.
                assert_eq!(
                    device_received,
                    vec![claw_packet.clone()],
                    "device interface must receive exactly the one claw packet, got {} packet(s)",
                    device_received.len()
                );
                assert!(
                    claw_received.contains(&device_packet_1)
                        && claw_received.contains(&device_packet_2),
                    "claw interface must receive BOTH distinct device packets"
                );
                assert_eq!(
                    claw_received.len(),
                    2,
                    "claw interface must receive exactly the two device packets (no dup/extra), \
                     got {}",
                    claw_received.len()
                );
            })
            .await
            .expect("two-ended no-net datapath test is bounded");
        }

        async fn spawn_test_relay() -> (SocketAddr, JoinHandle<()>) {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind loopback relay");
            let addr = listener.local_addr().expect("relay addr");
            let config = RendezvousStreamRelayListenerConfig {
                hello_timeout: Duration::from_secs(1),
                token_ttl: Duration::from_secs(30),
                max_pending: 8,
                max_active_connections: 8,
                reaper_interval: Duration::from_millis(50),
                splice_idle_timeout: Duration::from_secs(3),
                splice_max_lifetime: Duration::from_secs(10),
                abuse: RelayAbuseConfig::default(),
            };
            (addr, serve_rendezvous_stream_relay(listener, config))
        }

        fn relay_endpoint_uri(addr: SocketAddr) -> String {
            format!("relay-stream://{}:{}", addr.ip(), addr.port())
        }

        fn reverse_config(relay_addr: SocketAddr) -> RelayStreamResponderReverseConnectConfig {
            RelayStreamResponderReverseConnectConfig {
                relay_addr,
                connect_timeout: Duration::from_secs(2),
                hello_timeout: Duration::from_secs(2),
                allow_non_loopback_relay_addr: false,
            }
        }

        fn device_config_json() -> String {
            format!(
                r#"{{
                    "schema": "{DEV_RUNNER_SESSION_CONFIG_SCHEMA}",
                    "scope": "{DEV_RUNNER_SESSION_CONFIG_SCOPE}",
                    "production_activation": false,
                    "platform": "{}",
                    "local_side": "device",
                    "device_ipv4": "198.18.0.1",
                    "claw_ipv4": "198.18.0.2",
                    "claw_route_prefix_len": 32,
                    "mtu": 1280
                }}"#,
                host_platform_name()
            )
        }

        fn host_platform_name() -> &'static str {
            #[cfg(target_os = "linux")]
            {
                "linux"
            }
            #[cfg(target_os = "macos")]
            {
                "macos"
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                "unsupported"
            }
        }

        fn household_record(root: &P256Keypair, owner_pub: &P256PublicKey) -> HouseholdRecord {
            HouseholdRecord {
                version: HouseholdRecord::SCHEMA_VERSION,
                hh_id: derive_household_id(&root.public()),
                hh_pub: root.public(),
                name: "claw-dev".to_string(),
                created_at: NOW,
                shamir_k: 1,
                shamir_n: 1,
                members: vec![derive_machine_id(owner_pub)],
                is_follower: false,
            }
        }

        fn machine_cert(root: &P256Keypair, owner_pub: &P256PublicKey) -> MachineCert {
            MachineCert::sign(
                root,
                owner_pub,
                &SignOptions {
                    hh_id: derive_household_id(&root.public()),
                    hostname: "claw-dev-mac-alpha".to_string(),
                    platform: Platform::Macos,
                    joined_at: NOW,
                },
            )
            .expect("sign machine cert")
        }

        fn group_projection(member_device_pub: &P256PublicKey) -> ProjectedState {
            let mut projection = ProjectedState::default();
            projection.groups.insert(
                GROUP_ID.to_string(),
                ProjectedGroup {
                    group_id: GROUP_ID.to_string(),
                    name: GROUP_NAME.to_string(),
                    members: BTreeMap::from([(MEMBER_ID.to_string(), MeshMembership::Active)]),
                    member_labels: BTreeMap::new(),
                    granted_claws: BTreeMap::from([(CLAW_ID.to_string(), MeshMembership::Active)]),
                    revision: 1,
                },
            );
            projection.member_devices.insert(
                MEMBER_ID.to_string(),
                BTreeMap::from([(
                    member_device_pub.as_bytes().to_vec(),
                    ProjectedMemberDevice {
                        participant_npub: MEMBER_NPUB.to_string(),
                        status: MeshMembership::Active,
                    },
                )]),
            );
            projection
        }

        async fn admission(
            root: &P256Keypair,
            owner: &P256Keypair,
            record: &HouseholdRecord,
            cert: &MachineCert,
        ) -> RelayStreamAdmission {
            let household = HouseholdState::loaded(Arc::new(LoadedIdentity {
                record: record.clone(),
                cert: cert.clone(),
                hh_priv: None,
                m_priv: Box::new(key_from_public_seed(owner)),
                backing: "software",
            }));
            let _ = root;
            let policy = RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(3_600), 3)
                .expect("trust refresh policy");
            let runtime =
                RelayStreamTrustContextRuntime::load(&household, &MeshLogStore::new(), NOW, policy)
                    .await
                    .expect("load trust runtime");
            RelayStreamAdmission::new(Arc::new(runtime))
        }

        fn key_from_public_seed(owner: &P256Keypair) -> P256Keypair {
            if owner.public() == key(0x11).public() {
                key(0x11)
            } else {
                key(0x12)
            }
        }

        fn claw_router(
            relay_endpoint: &str,
            interface: PollableMockInterface,
            runtime_handles: &ClawRuntimeHandles,
        ) -> server_rs::claw_vpn_t1_relay_stream_router::ClawVpnPollableT1RelayStreamBoxedRouter<
            PollableMockInterface,
        >{
            let endpoint = relay_endpoint.to_string();
            let runtime_handles = Arc::clone(runtime_handles);
            let status = assemble_claw_vpn_pollable_t1_relay_stream_router(
                move || {
                    ClawVpnDevConfig::from_values(
                        Some("1"),
                        None,
                        Some(endpoint.as_str()),
                        Some(IPV4_POOL),
                        Some("1"),
                        Some("1"),
                    )
                },
                || PerClawVpnT1PreflightEvidence::new(true, true, true),
                move |_config| {
                    ClawVpnPollableT1RelayStreamRouterParts::new(
                        bounded_runtime_config(16),
                        claw_build_inputs(interface),
                        claw_runtime_launcher(runtime_handles),
                        noop_audit_sink(),
                    )
                },
            );
            status
                .into_ready()
                .map(|(_mode, router)| router)
                .expect("dev T1 pollable router ready")
        }

        fn claw_build_inputs(
            interface: PollableMockInterface,
        ) -> ClawVpnPollableT1RelayStreamBuildInputs<PollableMockInterface> {
            // The pollable interface holds a non-Clone UnixDatagram, and the
            // build closure is `Fn`; move it in behind a take-once cell (one
            // session per test open).
            let interface = Mutex::new(Some(interface));
            Box::new(move |_config, _target, _context, relay| {
                let interface = interface
                    .lock()
                    .expect("claw interface lock")
                    .take()
                    .ok_or_else(|| std::io::Error::other("claw interface already consumed"))?;
                Ok(pollable_runtime_inputs(interface, relay))
            })
        }

        fn claw_runtime_launcher(
            runtime_handles: ClawRuntimeHandles,
        ) -> ClawVpnPollableT1RelayStreamLaunchRuntime<PollableMockInterface> {
            Box::new(
                move |mut wiring: ClawVpnPollableTargetSessionRouterWiring<
                    PollableMockInterface,
                >| {
                    let handle = tokio::task::spawn_blocking(move || {
                        wiring
                            .run_until_stopped()
                            .map(|_report| ())
                            .map_err(|error| format!("{error:?}"))
                    });
                    runtime_handles
                        .lock()
                        .expect("runtime handles lock")
                        .push(handle);
                    Ok::<(), ClawVpnTargetSessionRouterLaunchError>(())
                },
            )
        }

        fn noop_audit_sink() -> ClawVpnT1RelayStreamAuditSink {
            Box::new(|_event| Ok(()))
        }

        fn bounded_runtime_config(max_steps: usize) -> ClawVpnRuntimeWiringConfig {
            ClawVpnRuntimeWiringConfig::new(
                true,
                ClawVpnRuntimeStepBudget::new(max_steps).expect("runtime step budget"),
                ClawVpnPacketPumpProductionDriverBudget::new(
                    max_steps,
                    Duration::from_secs(5),
                    max_steps,
                    Duration::from_secs(1),
                )
                .expect("driver budget"),
            )
        }

        fn pollable_runtime_inputs(
            interface: PollableMockInterface,
            relay: ClawVpnPollableTargetSessionRelay,
        ) -> ClawVpnRuntimeWiringInputs<PollableMockInterface, ClawVpnPollableTargetSessionRelay>
        {
            ClawVpnRuntimeWiringInputs {
                route_platform: host_route_platform(),
                interface_name: ClawVpnInterfaceName::new("t1mock0").expect("interface name"),
                route_tool_paths: true_tool_paths(),
                interface,
                relay,
            }
        }

        fn host_route_platform() -> ClawVpnInterfaceRoutePlatform {
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
                panic!("T1 dev datapath test supports only linux/macos")
            }
        }

        fn true_tool_paths() -> ClawVpnInterfaceRouteToolPaths {
            let path = PathBuf::from("/usr/bin/true");
            ClawVpnInterfaceRouteToolPaths::try_new(&path, &path, &path).expect("true tool paths")
        }

        fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
            let mut packet = vec![0u8; 20];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&20u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = 6;
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            packet
        }

        fn drain_runtime_handles(
            handles: &ClawRuntimeHandles,
        ) -> Vec<JoinHandle<Result<(), String>>> {
            std::mem::take(&mut *handles.lock().expect("runtime handles lock"))
        }
    }

    #[cfg(feature = "dev_t1_datapath")]
    #[test]
    fn generated_device_config_round_trips_through_runner_validator() {
        let bytes = generate_device_session_config_bytes(
            DevRunnerSessionConfigPlatform::Linux,
            Ipv4Addr::new(198, 18, 0, 0),
            24,
            0,
            1400,
        )
        .expect("doc-range pool generates a config");

        let config = validate_session_config_bytes(&bytes).expect("generated config validates");
        assert!(config.device_ipv4_present());
        assert!(config.claw_ipv4_present());
        assert_eq!(config.claw_route_prefix_len(), 32);
        assert_eq!(config.mtu(), 1400);

        // Addresses come straight from ClawVpnIpv4Pool::allocate_pair
        // (device = network + 1, claw = device + 1) for session index 0.
        let text = String::from_utf8(bytes).expect("config is utf8");
        assert!(text.contains("\"device_ipv4\": \"198.18.0.1\""));
        assert!(text.contains("\"claw_ipv4\": \"198.18.0.2\""));
        assert!(text.contains("\"platform\": \"linux\""));
        assert!(text.contains("\"local_side\": \"device\""));
        assert!(text.contains("\"production_activation\": false"));
    }

    #[cfg(feature = "dev_t1_datapath")]
    #[test]
    fn generated_device_config_derives_distinct_pair_per_session_index() {
        let bytes = generate_device_session_config_bytes(
            DevRunnerSessionConfigPlatform::Macos,
            Ipv4Addr::new(198, 18, 0, 0),
            24,
            1,
            1400,
        )
        .expect("session index 1 generates a config");
        validate_session_config_bytes(&bytes).expect("generated config validates");

        // Session index 1 -> device = network + 1 + 2*1, claw = device + 1.
        let text = String::from_utf8(bytes).expect("config is utf8");
        assert!(text.contains("\"device_ipv4\": \"198.18.0.3\""));
        assert!(text.contains("\"claw_ipv4\": \"198.18.0.4\""));
        assert!(text.contains("\"platform\": \"macos\""));
    }

    #[cfg(feature = "dev_t1_datapath")]
    #[test]
    fn generated_device_config_rejects_rfc1918_pool_without_echoing_it() {
        let error = generate_device_session_config_bytes(
            DevRunnerSessionConfigPlatform::Linux,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            0,
            1400,
        )
        .expect_err("rfc1918 pool must be rejected");
        let message = format!("{error:#}");
        assert!(message.contains("pool rejected"));
        assert!(!message.contains("10.0.0.0"));
    }

    #[cfg(feature = "dev_t1_datapath")]
    #[test]
    fn generated_device_config_rejects_cgnat_pool() {
        let error = generate_device_session_config_bytes(
            DevRunnerSessionConfigPlatform::Linux,
            Ipv4Addr::new(100, 64, 0, 0),
            24,
            0,
            1400,
        )
        .expect_err("cgnat pool must be rejected");
        assert!(error.to_string().contains("pool rejected"));
    }

    #[cfg(feature = "dev_t1_datapath")]
    #[test]
    fn generated_device_config_rejects_out_of_range_mtu() {
        for bad_mtu in [1279u16, 9001u16] {
            let error = generate_device_session_config_bytes(
                DevRunnerSessionConfigPlatform::Linux,
                Ipv4Addr::new(198, 18, 0, 0),
                24,
                0,
                bad_mtu,
            )
            .expect_err("out-of-range mtu must be rejected");
            assert!(error.to_string().contains("mtu invalid"));
        }
    }

    #[cfg(feature = "dev_t1_datapath")]
    #[test]
    fn pool_cidr_parses_network_and_prefix() {
        let (network, prefix_len) = parse_pool_cidr("198.18.0.0/24").expect("valid cidr parses");
        assert_eq!(network, Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(prefix_len, 24);
        assert!(parse_pool_cidr("198.18.0.0").is_err());
        assert!(parse_pool_cidr("not-an-ip/24").is_err());
    }
}
