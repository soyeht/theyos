#![cfg(test)]

use std::sync::Arc;

use household_rs::claw_share::data_tunnel::{
    ClawTargetRouter, DataTunnelError, DataTunnelSession, TargetSession, credential_hash,
    serve_connection_io_with_auth_deadline,
};
use household_rs::claw_share::relay_stream_contract::{
    RelayStreamClawStaticPublicKey, RelayStreamOfferMintInput, mint_relay_stream_group_offer,
    mint_relay_stream_offer, mint_relay_stream_public_offer,
};
use household_rs::claw_share::rendezvous_token::RendezvousToken;
use household_rs::claw_share::{GuestCredential, SlotId};
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
    let verify = move |envelope: &household_rs::claw_share::data_tunnel::AuthEnvelope,
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
            app_presentation: None,
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
            app_presentation: None,
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
    let error =
        validate_session_config_bytes(bad_address.as_bytes()).expect_err("bad address rejected");
    let message = format!("{error:#}");
    assert!(message.contains("device_ipv4 must be a valid IPv4 address"));
    assert!(!message.contains("SECRET-DEVICE-IP"));

    let broad_route = valid_session_config_json().replace(
        r#""claw_route_prefix_len": 32"#,
        r#""claw_route_prefix_len": 24"#,
    );
    let error =
        validate_session_config_bytes(broad_route.as_bytes()).expect_err("broad route rejected");
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

    let claw_side =
        valid_session_config_json().replace(r#""local_side": "device""#, r#""local_side": "claw""#);
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
    let error = validate_session_config_bytes(bad_schema.as_bytes()).expect_err("schema rejected");
    assert!(error.to_string().contains("schema invalid"));

    let bad_scope =
        valid_session_config_json().replace(DEV_RUNNER_SESSION_CONFIG_SCOPE, "dev-host");
    let error = validate_session_config_bytes(bad_scope.as_bytes()).expect_err("scope rejected");
    assert!(error.to_string().contains("scope invalid"));

    let bad_platform =
        valid_session_config_json().replace(r#""platform": "macos""#, r#""platform": "ios""#);
    let error =
        validate_session_config_bytes(bad_platform.as_bytes()).expect_err("platform rejected");
    assert!(error.to_string().contains("platform invalid"));

    for invalid_mtu in [1279, 9001] {
        let bad_mtu = valid_session_config_json()
            .replace(r#""mtu": 1280"#, &format!(r#""mtu": {invalid_mtu}"#));
        let error = validate_session_config_bytes(bad_mtu.as_bytes()).expect_err("mtu rejected");
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

    let (offer_cbor, token) =
        build_iptunnel_session_auth(&offer, &device, NOW, nonce.clone()).expect("session token");

    assert_eq!(
        token.credential_hash,
        household_rs::claw_share::data_tunnel::credential_hash(&offer_cbor)
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
    let Some(start) = source.find("#[cfg(feature = \"dev_t1_datapath\")]\nmod dev_datapath") else {
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
    // Production plus this extracted test module, as when the tests were inline.
    let source = source_without_dev_datapath_module(concat!(
        include_str!("main.rs"),
        include_str!("tests.rs")
    ));
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
        |name| matches!(name, DEV_DATAPATH_ENV | DEV_SOFTWARE_KEYS_ENV).then(|| "1".to_string()),
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

    let error =
        dev_datapath::validate_dev_datapath_runtime_gates_with_env(&offer, DEV_HOST_ACK, None, env)
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
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    use household_rs::LoadedIdentity;
    use household_rs::claw_share::data_tunnel::ReplayGuard;
    use household_rs::claw_share::{ClawShareSlotStore, SLOT_ID_LEN};
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
    use server_rs::claw_share_relay_stream_reopen_limiter::{
        ReopenLimiterConfig, ReopenStreamLimiter,
    };
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
    use server_rs::claw_share_session_clock::{AdmissionInstant, wall_now_secs};
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

    /// The single wall reading this two-ended test builds its whole session on.
    ///
    /// Every other test in this file is pure: it feeds `NOW` in and asserts on
    /// what comes out, and never reaches a clock that reads the host. This one
    /// drives the REAL responder, and `SessionClock::live_now` deliberately
    /// re-reads the host wall clock instead of deriving it from the admission
    /// anchor — that direct re-read is how it catches suspend and forward jumps
    /// (theyos#336). A fixed constant therefore cannot satisfy it from both
    /// sides at once:
    ///
    /// - a value in the past trips `wall >= not_after`  -> `SignedExpiryPassed`
    /// - a value in the future trips `wall < accepted_at` -> `WallRegressed`
    ///
    /// The outer `NOW` (`1_800_000_000`, 2027-01-15) is the second case: it is
    /// dated ahead of any host that runs this today, so `live_now` read a wall
    /// BELOW `accepted_at`, called it a regression and failed the responder
    /// closed with `ClockUnusable` before it ever served. The device end then
    /// saw only the EOF that left behind, which is why the failure surfaced as
    /// a Noise handshake error at the far end from its cause.
    /// `MEASURED 2026-08-06 origin/main@74f5c0e7`
    ///
    /// Note the shape of the trap: that constant would satisfy BOTH bounds
    /// during the 600 seconds after it, so this test is not permanently red —
    /// it would pass for one ten-minute window in 2027 and fail on either
    /// side. Deriving the reading instead of dating it removes the window
    /// entirely rather than moving it.
    ///
    /// Read ONCE per process: `created_at`, `joined_at`, the offer's signed
    /// bound and the admission anchor must share a single instant, or two
    /// reads straddling a second boundary make `not_after` disagree with the
    /// admission it is checked against.
    fn session_now() -> u64 {
        static SESSION_NOW: OnceLock<u64> = OnceLock::new();
        *SESSION_NOW.get_or_init(|| {
            wall_now_secs("t1_runner.two_ended_datapath_test").expect(
                "host wall clock must be plausible to drive the real responder; \
                     a clock below MIN_PLAUSIBLE_UNIX_SECS fails this test closed \
                     rather than silently admitting an unusable session",
            )
        })
    }

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

        fn read_packet_nonblocking(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
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
                session_now() + 600,
                session_now(),
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
                // Default limiter, matching the one other test-side caller of
                // THIS function (reverse_connect_binding.rs:402). The
                // production caller (claw_share_relay_stream_runtime.rs:441)
                // passes one built from `config.reopen_limiter`, so this is
                // deliberately the test pattern and not the general one.
                // This site opens a single stream, so the reopen budget is
                // never the thing under test.
                Arc::new(ReopenStreamLimiter::new(ReopenLimiterConfig::default())),
                || Some(session_now()),
            );
            // The fixed synthetic clock is usable by construction, so the seam
            // returns `Some`. Pairing goes through the public production-ordered
            // `capture_with`, which anchors BEFORE reading the wall; the
            // late-anchor `from_seam_wall` seam is `cfg(test)` inside server-rs
            // and is deliberately not reachable from this crate.
            let admission = AdmissionInstant::capture_with(|| Some(session_now()))
                .expect("plausible test clock");
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
                session_now(),
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
            // `None` = no per-direction byte cap, matching the other test-side
            // listener config (`claw_share_relay_stream_reverse_connect_pool.rs`).
            // Production parses a real cap from env; this loopback relay exists
            // to carry a handful of frames, and a cap here would test the cap
            // rather than the datapath.
            splice_max_bytes_per_direction: None,
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
            created_at: session_now(),
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
                joined_at: session_now(),
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
        let runtime = RelayStreamTrustContextRuntime::load(
            &household,
            &MeshLogStore::new(),
            session_now(),
            policy,
        )
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
    > {
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
            move |mut wiring: ClawVpnPollableTargetSessionRouterWiring<PollableMockInterface>| {
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
    ) -> ClawVpnRuntimeWiringInputs<PollableMockInterface, ClawVpnPollableTargetSessionRelay> {
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

    /// A no-op binary standing in for the platform's interface and routing
    /// tools, resolved on the host rather than hardcoded.
    ///
    /// Do not name those tools literally here. `source_keeps_session_open_
    /// boundary_bounded` scans this file for them to prove the dev session
    /// opener never crosses into TUN/route/app control, and it splits its own
    /// needles with `concat!` so it cannot match itself. An earlier draft of
    /// this very comment spelled one out and turned that guard red — the
    /// guard was right, the comment was careless.
    ///
    /// This used to be `/usr/bin/true` outright. `try_new` validates only
    /// the SHAPE of a path, never its existence, so a host without that file
    /// builds a perfectly valid `ClawVpnInterfaceRouteToolPaths` and then
    /// fails at exec time as `ClawVpnPollableRuntimeError::RouteSetup` — an
    /// error that reads like the route layer is broken when the truth is
    /// that the test's own stand-in is missing. Measured on NixOS, where
    /// `/usr/bin` contains exactly one entry (`env`): the whole two-ended
    /// datapath test failed there for that reason alone, on a tree whose
    /// route handling was fine.
    ///
    /// So resolve it, and **panic with the list of places tried** if nothing
    /// is found. A test that cannot build its own stand-in must say so in
    /// those words; silently substituting something else would turn a
    /// missing fixture into a green run.
    const NOOP_CANDIDATES: &[&str] = &["/usr/bin/true", "/bin/true", "/usr/local/bin/true"];

    /// The resolution itself, with both inputs injected.
    ///
    /// Split out from `true_tool_paths` so BOTH outcomes are provable without
    /// touching the host: the found case, and the not-found case that must
    /// stay `None` so the caller can panic. Testing this through the
    /// environment instead would mean emptying `PATH`, which takes the shell's
    /// own tools with it — the first attempt at that lost `grep`.
    fn resolve_noop_binary(
        candidates: &[&str],
        path_var: Option<&std::ffi::OsStr>,
        exists: &dyn Fn(&Path) -> bool,
    ) -> Option<PathBuf> {
        candidates
            .iter()
            .map(PathBuf::from)
            .find(|p| exists(p))
            .or_else(|| {
                // NixOS and friends put coreutils only on PATH.
                path_var.and_then(|paths| {
                    std::env::split_paths(paths)
                        .map(|dir| dir.join("true"))
                        .find(|p| exists(p))
                })
            })
    }

    fn true_tool_paths() -> ClawVpnInterfaceRouteToolPaths {
        let path = resolve_noop_binary(
            NOOP_CANDIDATES,
            std::env::var_os("PATH").as_deref(),
            &|p: &Path| p.is_file(),
        )
        .unwrap_or_else(|| {
            panic!(
                "no no-op binary found for the route-tool stand-in; tried \
                     {NOOP_CANDIDATES:?} and every PATH entry. This is the TEST's fixture, \
                     not the route layer: without it the run fails as RouteSetup and points \
                     at the wrong code."
            )
        });

        ClawVpnInterfaceRouteToolPaths::try_new(&path, &path, &path)
            .expect("no-op tool paths are absolute and well-formed")
    }

    #[cfg(feature = "dev_t1_datapath")]
    #[test]
    fn noop_binary_resolution_finds_a_candidate_and_refuses_to_invent_one() {
        use std::ffi::OsString;

        // Found via the fixed candidate list.
        let only_bin_true = |p: &Path| p == Path::new("/bin/true");
        assert_eq!(
            Some(PathBuf::from("/bin/true")),
            resolve_noop_binary(NOOP_CANDIDATES, None, &only_bin_true),
        );

        // Found via PATH when no candidate exists -- the NixOS case.
        let only_on_path = |p: &Path| p == Path::new("/nix/store/xyz/bin/true");
        assert_eq!(
            Some(PathBuf::from("/nix/store/xyz/bin/true")),
            resolve_noop_binary(
                NOOP_CANDIDATES,
                Some(&OsString::from("/nowhere:/nix/store/xyz/bin")),
                &only_on_path,
            ),
        );

        // Nothing anywhere -> None, so the caller panics with its own message.
        // Without this arm the panic branch is unreachable in any test and the
        // fixture could go missing while the suite still reported green.
        assert_eq!(
            None,
            resolve_noop_binary(
                NOOP_CANDIDATES,
                Some(&OsString::from("/nowhere:/also-nowhere")),
                &|_: &Path| false,
            ),
        );
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

    fn drain_runtime_handles(handles: &ClawRuntimeHandles) -> Vec<JoinHandle<Result<(), String>>> {
        std::mem::take(&mut *handles.lock().expect("runtime handles lock"))
    }
}

/// D3, the load-bearing half: a server allocation that disagrees with the
/// configured session must FAIL, not be accepted or silently corrected.
///
/// The defect this pins is subtle because the runner already had an equality
/// check — `session.addrs() != config.addrs` — comparing its own fresh
/// registry against its own config file. Two LOCAL values, computed from the
/// same pool and the same session index, so it could not fail. A green
/// T1/T2 therefore attested only that two independently configured
/// allocators agreed, never that the client would honour a different answer
/// from the server.
///
/// The three mismatch cases are separate because they fail for different
/// reasons: the server can move the device address, the claw address, or
/// both. A check that only compared one of them would pass two of these.
#[cfg(feature = "dev_t1_datapath")]
#[test]
fn served_allocation_that_disagrees_with_the_configured_session_fails_closed() {
    use dev_datapath::served_allocation_matches_configured;
    use household_rs::claw_share::data_tunnel::MeshIpv4;

    let configured =
        ClawVpnSessionAddrs::try_new(Ipv4Addr::new(198, 18, 0, 2), Ipv4Addr::new(198, 18, 0, 3))
            .expect("configured pair");

    let mesh = |addr: &str, peer: &str| MeshIpv4 {
        addr: addr.into(),
        prefix_len: 30,
        peer: peer.into(),
    };

    // Positive control FIRST: without it, every assertion below could pass
    // because the function rejects everything.
    served_allocation_matches_configured(&mesh("198.18.0.2", "198.18.0.3"), configured)
        .expect("the server's own allocation must be accepted");

    for (case, served) in [
        // The realistic one: a prior session on the serving claw shifted the
        // server's index, so both addresses moved together.
        ("both moved", mesh("198.18.0.6", "198.18.0.7")),
        // Only the device moved.
        ("device moved", mesh("198.18.0.6", "198.18.0.3")),
        // Only the claw moved.
        ("claw moved", mesh("198.18.0.2", "198.18.0.7")),
    ] {
        let err = served_allocation_matches_configured(&served, configured)
            .expect_err(case)
            .to_string();
        assert!(
            err.contains("does not match the configured session"),
            "{case}: wrong refusal: {err}"
        );
        // Redaction: the refusal names which side disagreed, never a value.
        assert!(
            !err.contains("198.18."),
            "{case}: refusal echoed an address: {err}"
        );
    }
}

/// An address the frame carries but cannot be parsed is a refusal, not a
/// panic. The live path bails on `route_scope_violation` first, so this arm
/// is unreachable there today — it exists so narrowing that guard later
/// cannot turn a malformed frame into a crash.
#[cfg(feature = "dev_t1_datapath")]
#[test]
fn served_allocation_with_unparseable_addresses_is_refused() {
    use dev_datapath::served_allocation_matches_configured;
    use household_rs::claw_share::data_tunnel::MeshIpv4;

    let configured =
        ClawVpnSessionAddrs::try_new(Ipv4Addr::new(198, 18, 0, 2), Ipv4Addr::new(198, 18, 0, 3))
            .expect("configured pair");
    let err = served_allocation_matches_configured(
        &MeshIpv4 {
            addr: "not-an-address".into(),
            prefix_len: 30,
            peer: "198.18.0.3".into(),
        },
        configured,
    )
    .expect_err("unparseable addr must be refused")
    .to_string();
    assert!(err.contains("unparseable addresses"), "{err}");
    assert!(
        !err.contains("not-an-address"),
        "refusal echoed the value: {err}"
    );
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
