//! Dev-only Product A T1 `IpTunnel` runner boundary.
//!
//! This binary is a dev-host tool only. The `validate-offer` command remains
//! offline. The `open-session` command can explicitly authenticate and open an
//! `IpTunnel` data-tunnel session, but this runner still does not implement a
//! local tunnel interface, route install, packet pump, or production-app
//! control path. A target open against an activated dev host remains a gated
//! T1-T4 validation step, not a production activation path.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use household_rs::claw_share_data_tunnel::{
    HEALTH_PROBE, SessionAuthToken, TunnelAck, client_authenticate, client_health,
    client_open_stream,
};
use household_rs::claw_share_relay_stream_contract::{
    RelayStreamAudience, RelayStreamExpectedPath, RelayStreamOfferContract, RelayStreamResource,
};
use household_rs::claw_share_relay_stream_endpoint::parse_relay_endpoint;
use household_rs::claw_share_relay_stream_noise::RelayStreamNoiseFramed;
use household_rs::claw_share_rendezvous_hello::{RendezvousHello, RendezvousRole};
use household_rs::keys::{IdentityKey, P256Keypair};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

const DEV_HOST_ACK: &str = "dev-host T1-T4 only; no production activation";

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedIpTunnelOffer;

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

fn validate_dev_host_ack(value: &str) -> Result<()> {
    if value == DEV_HOST_ACK {
        return Ok(());
    }
    bail!("dev-host acknowledgement is required");
}

fn device_secret_from_hex(hex: &str) -> Result<P256Keypair> {
    let hex = hex.trim();
    if hex.len() != 64 {
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
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut nonce = vec![0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let (offer_cbor, token) = build_iptunnel_session_auth(offer, device_key, now_unix, nonce)?;

    match client_authenticate(stream, &offer_cbor, token)
        .await
        .context("IpTunnel session authenticate")?
    {
        TunnelAck::Ok { .. } => {}
        TunnelAck::Rejected { reason } => bail!("IpTunnel session auth rejected: {reason}"),
    }

    let echo = client_health(stream, HEALTH_PROBE)
        .await
        .context("IpTunnel session health probe")?;
    if echo != HEALTH_PROBE {
        bail!("IpTunnel session health echo mismatch");
    }

    client_open_stream(stream)
        .await
        .context("IpTunnel session open")?;
    Ok(())
}

async fn open_iptunnel_session(
    offer: &RelayStreamOfferContract,
    device_key: &P256Keypair,
    now_unix: u64,
) -> Result<()> {
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
    authenticate_open_iptunnel_session(&mut stream, offer, device_key, now_unix).await
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
        Command::OpenSession {
            offer_file,
            device_secret_file,
            dev_host_ack,
        } => {
            validate_dev_host_ack(&dev_host_ack)?;
            let offer = read_iptunnel_offer_file(&offer_file)?;
            let device_key = read_device_secret_file(&device_secret_file)?;
            open_iptunnel_session(&offer, &device_key, current_unix()?).await?;
            println!(
                "OK: dev IpTunnel session opened \
                 (auth_ok=true, health_ok=true, stream_open=true, \
                 runner_tun_opened=false, runner_route_installed=false, \
                 runner_packet_pump_started=false)"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
    use tokio::io::AsyncWriteExt;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn key(seed: u8) -> P256Keypair {
        P256Keypair::from_secret_scalar(&[seed; 32]).expect("p256 keypair")
    }

    fn claw_static_pub() -> RelayStreamClawStaticPublicKey {
        RelayStreamClawStaticPublicKey::try_new([0x33; 32]).expect("claw static key")
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

    struct TestSession;

    impl DataTunnelSession for TestSession {
        fn session_id(&self) -> String {
            "session-alpha".to_string()
        }

        fn mesh_ipv6(&self) -> String {
            "fd00::1".to_string()
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
        opens: Arc<AtomicUsize>,
    ) -> Result<(), DataTunnelError> {
        let expected_cbor = offer.payload.to_canonical_bytes().expect("offer cbor");
        let verify_called = Arc::new(AtomicBool::new(false));
        let verify_called_for_closure = Arc::clone(&verify_called);
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
            Ok(TestSession)
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

    #[tokio::test]
    async fn open_session_sequence_authenticates_health_checks_and_opens_stream() {
        let (offer, device) = member_iptunnel_offer();
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let opens = Arc::new(AtomicUsize::new(0));
        let server_opens = Arc::clone(&opens);
        let server_offer = offer.clone();
        let server_task = tokio::spawn(async move {
            run_scripted_data_tunnel_server(server, server_offer, true, server_opens).await
        });

        authenticate_open_iptunnel_session(&mut client, &offer, &device, NOW)
            .await
            .expect("auth + health + open succeed");
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        server_task.abort();
        assert!(server_task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn open_session_rejects_tunnel_ack_rejected_before_opening_stream() {
        let (offer, device) = member_iptunnel_offer();
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let opens = Arc::new(AtomicUsize::new(0));
        let server_opens = Arc::clone(&opens);
        let server_offer = offer.clone();
        let server_task = tokio::spawn(async move {
            run_scripted_data_tunnel_server(server, server_offer, false, server_opens).await
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

    #[test]
    fn source_keeps_session_open_boundary_bounded() {
        let source = include_str!("main.rs");
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
}
