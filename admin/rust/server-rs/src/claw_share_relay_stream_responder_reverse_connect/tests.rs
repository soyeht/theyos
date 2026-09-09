#![cfg(test)]

use super::*;

use household_rs::cbor;
use household_rs::claw_share::data_tunnel::{
    HEALTH_PROBE, SessionAuthToken, TunnelAck, TunnelFrame, client_authenticate, client_health,
    client_open_stream, recv_frame, send_frame,
};
use household_rs::keys::IdentityKey;
use tokio::io::{AsyncWriteExt, duplex};
use tokio::net::TcpListener;

use crate::claw_share_relay_stream_noise::{
    RelayStreamNoiseFramed, generate_relay_stream_noise_static_keypair,
};
use crate::claw_share_relay_stream_test_support::{
    attacker_signer, data_tunnel_credential, data_tunnel_deps_arc,
    data_tunnel_token as support_data_tunnel_token, guest_pub, owner_pub, relay_stream_offer,
    relay_stream_offer_signed_by, relay_stream_responder_params as params, rendezvous_token,
    spawn_ack_target,
};
use crate::claw_share_rendezvous_stream_relay::{RendezvousRole, RendezvousToken};
use crate::claw_share_rendezvous_stream_relay_listener::{
    RendezvousStreamRelayListenerConfig, serve_rendezvous_stream_relay,
};

const TOKEN_AUDIENCE: &str = "relay-stream-reverse-connect-test";

fn data_tunnel_token(credential_cbor: &[u8], nonce: &[u8]) -> SessionAuthToken {
    support_data_tunnel_token(TOKEN_AUDIENCE, credential_cbor, nonce)
}

fn test_relay_config() -> RendezvousStreamRelayListenerConfig {
    RendezvousStreamRelayListenerConfig {
        hello_timeout: Duration::from_secs(1),
        token_ttl: Duration::from_secs(2),
        max_pending: 16,
        max_active_connections: 16,
        reaper_interval: Duration::from_millis(50),
        splice_idle_timeout: Duration::from_secs(5),
        splice_max_lifetime: Duration::from_secs(60),
        splice_max_bytes_per_direction: None,
        abuse: crate::claw_share_relay_stream_abuse::RelayAbuseConfig::default(),
    }
}

fn reverse_config(relay_addr: SocketAddr) -> RelayStreamResponderReverseConnectConfig {
    RelayStreamResponderReverseConnectConfig {
        relay_addr,
        connect_timeout: Duration::from_secs(1),
        hello_timeout: Duration::from_secs(1),
        allow_non_loopback_relay_addr: false,
    }
}

async fn spawn_test_relay() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = serve_rendezvous_stream_relay(listener, test_relay_config());
    (addr, handle)
}

async fn connect_guest_with_hello(relay_addr: SocketAddr, token: RendezvousToken) -> TcpStream {
    let mut stream = TcpStream::connect(relay_addr).await.unwrap();
    stream
        .write_all(&RendezvousHello::new(RendezvousRole::Guest, token).encode())
        .await
        .unwrap();
    stream.flush().await.unwrap();
    stream
}

#[tokio::test]
async fn relay_stream_reverse_connect_dials_rendezvous_and_pipes_data_to_target() {
    timeout(Duration::from_secs(5), async {
        let (relay_addr, relay_handle) = spawn_test_relay().await;
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = Arc::new(relay_stream_offer(rendezvous_token(0x91), &keypair));
        let params = Arc::new(params(keypair, Duration::from_secs(2)).await);
        let deps = data_tunnel_deps_arc(spawn_ack_target().await);
        let claw = tokio::spawn(serve_relay_stream_responder_reverse_connect(
            reverse_config(relay_addr),
            Arc::clone(&offer),
            Arc::clone(&params),
            Arc::clone(&deps),
        ));

        let guest =
            connect_guest_with_hello(relay_addr, offer.payload.rendezvous_token.clone()).await;
        let guest_key = guest_pub();
        let mut stream = RelayStreamNoiseFramed::initiator_handshake(
            guest,
            &offer,
            &owner_pub(),
            &guest_key,
            crate::claw_share_session_clock::wall_now_secs("test").expect("plausible clock"),
        )
        .await
        .unwrap()
        .into_async_stream();
        let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
        assert!(matches!(
            client_authenticate(&mut stream, &cbor, data_tunnel_token(&cbor, b"reverse-ok"))
                .await
                .unwrap(),
            TunnelAck::Ok { .. }
        ));
        assert_eq!(
            client_health(&mut stream, HEALTH_PROBE).await.unwrap(),
            HEALTH_PROBE
        );
        client_open_stream(&mut stream).await.unwrap();
        send_frame(&mut stream, &TunnelFrame::Data(b"reverse-data".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            recv_frame(&mut stream).await.unwrap(),
            TunnelFrame::Data(b"ACK:reverse-data".to_vec())
        );
        send_frame(&mut stream, &TunnelFrame::Close).await.unwrap();

        claw.await.unwrap().unwrap();
        relay_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_stream_reverse_connect_different_token_does_not_open_data_tunnel() {
    timeout(Duration::from_secs(3), async {
        let (relay_addr, relay_handle) = spawn_test_relay().await;
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = Arc::new(relay_stream_offer(rendezvous_token(0x92), &keypair));
        let params = Arc::new(params(keypair, Duration::from_millis(100)).await);
        let deps = data_tunnel_deps_arc("127.0.0.1:1".to_string());
        let claw = tokio::spawn(serve_relay_stream_responder_reverse_connect(
            reverse_config(relay_addr),
            Arc::clone(&offer),
            Arc::clone(&params),
            Arc::clone(&deps),
        ));

        let guest = connect_guest_with_hello(relay_addr, rendezvous_token(0x93)).await;
        let guest_key = guest_pub();
        let guest_result = timeout(
            Duration::from_millis(300),
            RelayStreamNoiseFramed::initiator_handshake(
                guest,
                &offer,
                &owner_pub(),
                &guest_key,
                crate::claw_share_session_clock::wall_now_secs("test").expect("plausible clock"),
            ),
        )
        .await;
        assert!(guest_result.is_err() || guest_result.unwrap().is_err());

        let claw_error = claw.await.unwrap().unwrap_err();
        assert!(matches!(
            claw_error,
            RelayStreamResponderReverseConnectError::Responder(
                RelayStreamResponderError::HandshakeTimeout
            )
        ));
        relay_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_stream_reverse_connect_attacker_offer_fails_before_auth() {
    timeout(Duration::from_secs(3), async {
        let (relay_addr, relay_handle) = spawn_test_relay().await;
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = Arc::new(relay_stream_offer_signed_by(
            rendezvous_token(0x94),
            &keypair,
            &attacker_signer(),
        ));
        let params = Arc::new(params(keypair, Duration::from_secs(1)).await);
        let deps = data_tunnel_deps_arc("127.0.0.1:1".to_string());
        let claw = tokio::spawn(serve_relay_stream_responder_reverse_connect(
            reverse_config(relay_addr),
            Arc::clone(&offer),
            Arc::clone(&params),
            Arc::clone(&deps),
        ));

        let guest =
            connect_guest_with_hello(relay_addr, offer.payload.rendezvous_token.clone()).await;
        let guest_key = guest_pub();
        let result = RelayStreamNoiseFramed::initiator_handshake(
            guest,
            &offer,
            &attacker_signer().public(),
            &guest_key,
            crate::claw_share_session_clock::wall_now_secs("test").expect("plausible clock"),
        )
        .await;
        assert!(result.is_err());
        assert!(claw.await.unwrap().is_err());
        relay_handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_stream_reverse_connect_rejects_non_loopback_relay_addr() {
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = Arc::new(relay_stream_offer(rendezvous_token(0x95), &keypair));
    let params = Arc::new(params(keypair, Duration::from_secs(1)).await);
    let error = serve_relay_stream_responder_reverse_connect(
        reverse_config("0.0.0.0:49152".parse().unwrap()),
        offer,
        params,
        data_tunnel_deps_arc("127.0.0.1:1".to_string()),
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        RelayStreamResponderReverseConnectError::NonLoopbackRelayAddr
    ));
}

#[test]
fn relay_stream_reverse_connect_accepts_non_loopback_with_explicit_opt_in() {
    let config = RelayStreamResponderReverseConnectConfig {
        relay_addr: "0.0.0.0:49152".parse().unwrap(),
        connect_timeout: Duration::from_secs(1),
        hello_timeout: Duration::from_secs(1),
        allow_non_loopback_relay_addr: true,
    };

    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn relay_stream_reverse_connected_hello_write_is_bounded() {
    timeout(Duration::from_secs(2), async {
        let keypair = generate_relay_stream_noise_static_keypair().unwrap();
        let offer = relay_stream_offer(rendezvous_token(0x96), &keypair);
        let params = params(keypair, Duration::from_secs(1)).await;
        let deps = data_tunnel_deps_arc("127.0.0.1:1".to_string());
        let (stream, _peer) = duplex(1);
        let error = serve_relay_stream_responder_reverse_connected(
            stream,
            &offer,
            &params,
            capture_admission().expect("test host clock must be plausible"),
            &deps,
            RelayStreamResponderReverseConnectConfig {
                relay_addr: "127.0.0.1:49152".parse().unwrap(),
                connect_timeout: Duration::from_secs(1),
                hello_timeout: Duration::from_millis(25),
                allow_non_loopback_relay_addr: false,
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            RelayStreamResponderReverseConnectError::HelloTimeout
        ));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_stream_reverse_connect_unhealthy_admission_does_not_dial() {
    use crate::claw_share_relay_stream_admission::RelayStreamAdmission;
    use crate::claw_share_relay_stream_responder_params::RelayStreamResponderParams;
    use crate::claw_share_relay_stream_test_support::relay_stream_household_state;
    use crate::claw_share_relay_stream_trust_context_health::{
        RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
    };
    use household_rs::household_mesh_log::MeshLogStore;

    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = Arc::new(relay_stream_offer(rendezvous_token(0x97), &keypair));

    // Runtime whose last success is far in the past versus a 1s staleness
    // bound: admission fails closed.
    let policy = RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(1), 1).unwrap();
    let runtime = RelayStreamTrustContextRuntime::load(
        &relay_stream_household_state(),
        &MeshLogStore::new(),
        crate::claw_share_session_clock::wall_now_secs("test")
            .expect("plausible clock")
            .saturating_sub(10_000),
        policy,
    )
    .await
    .unwrap();
    let params = Arc::new(RelayStreamResponderParams {
        bind_addr: "127.0.0.1:49152".parse().unwrap(),
        auth_deadline: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(60),
        admission: RelayStreamAdmission::new(Arc::new(runtime)),
        noise_keypair: keypair,
    });
    // Loopback port with no listener: had we reached the dial, the error would
    // be a connect failure. An Admission error proves admit ran first.
    let error = serve_relay_stream_responder_reverse_connect(
        reverse_config("127.0.0.1:1".parse().unwrap()),
        offer,
        params,
        data_tunnel_deps_arc("127.0.0.1:1".to_string()),
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        RelayStreamResponderReverseConnectError::Admission(_)
    ));
}
