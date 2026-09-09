#![cfg(test)]

fn now_unix() -> u64 {
    crate::claw_share_session_clock::wall_now_secs("test")
        .expect("test host clock must be plausible")
}

use super::*;
use std::time::Duration;

use household_rs::cbor;
use household_rs::claw_share::data_tunnel::{
    HEALTH_PROBE, ReplayGuard, SessionAuthToken, TcpStreamRouter, TunnelAck, TunnelFrame,
    client_authenticate, client_health, client_open_stream, recv_frame, send_frame,
};
use household_rs::claw_share::{ClawShareSlotStore, GuestCredential};
use household_rs::household_mesh_log::MeshLogStore;
use household_rs::ids::derive_household_id;
use household_rs::keys::{IdentityKey, P256PublicKey};
use household_rs::{BootstrapOpts, KeyBackingPolicy, LoadedIdentity};
use keystore_rs::FileKeystore;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::claw_share_relay_stream_contract::{
    RelayStreamClawStaticPublicKey, RelayStreamOfferContract,
};
use crate::claw_share_relay_stream_noise::{
    RelayStreamNoiseFramed, generate_relay_stream_noise_static_keypair,
};
use crate::claw_share_relay_stream_noise_keystore::{
    DEFAULT_RELAY_STREAM_NOISE_KEY_ID, RelayStreamNoiseKeyStore,
};
use crate::claw_share_relay_stream_reopen_limiter::{ReopenLimiterConfig, ReopenStreamLimiter};
use crate::claw_share_relay_stream_test_support::{
    attacker_signer, data_tunnel_credential_with_owner, data_tunnel_store,
    data_tunnel_token as support_data_tunnel_token, guest_pub, relay_stream_offer_for_static_pub,
    rendezvous_token, spawn_ack_target,
};
use crate::claw_share_relay_stream_trust_context_health::{
    RelayStreamTrustContextRefreshPolicy, RelayStreamTrustContextRuntime,
};
use crate::household_state::HouseholdState;

const TOKEN_AUDIENCE: &str = "relay-stream-responder-server-test";

struct RuntimeFixture {
    _household_dir: tempfile::TempDir,
    _key_dir: tempfile::TempDir,
    identity: Arc<LoadedIdentity>,
    backend: FileKeystore,
}

impl RuntimeFixture {
    fn new() -> Self {
        let household_dir = tempfile::tempdir().unwrap();
        let identity = household_rs::bootstrap_or_load(
            household_dir.path(),
            BootstrapOpts {
                household_name: "Relay Stream Server Test".to_string(),
                hostname_label: Some("relay-stream-server-test".to_string()),
            },
            KeyBackingPolicy::ForceSoftware,
        )
        .unwrap();
        let identity = Arc::new(identity);
        let key_dir = tempfile::tempdir().unwrap();
        let backend = FileKeystore::new(key_dir.path(), "com.soyeht.theyos.test");
        Self {
            _household_dir: household_dir,
            _key_dir: key_dir,
            identity,
            backend,
        }
    }

    fn owner_pub(&self) -> P256PublicKey {
        self.identity.record.hh_pub.clone()
    }

    fn owner_key(&self) -> &dyn IdentityKey {
        self.identity
            .hh_priv
            .as_ref()
            .expect("test household has local HH private key")
            .as_ref()
    }

    async fn admission_loaded_at(
        &self,
        last_success_unix: u64,
        policy: RelayStreamTrustContextRefreshPolicy,
    ) -> RelayStreamAdmission {
        let runtime = RelayStreamTrustContextRuntime::load(
            &HouseholdState::loaded(Arc::clone(&self.identity)),
            &MeshLogStore::new(),
            last_success_unix,
            policy,
        )
        .await
        .unwrap();
        RelayStreamAdmission::new(Arc::new(runtime))
    }

    // Admission factory over the fixture's real household identity. Offers
    // here are signed by the household root key (`owner_key()` == hh_priv),
    // so the resolver's root fallback (`signer_pub == record.hh_pub`) accepts
    // them. A generous policy keeps the runtime healthy across the test.
    async fn admission(&self) -> RelayStreamAdmission {
        self.admission_loaded_at(
            now_unix(),
            RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(3_600), 3).unwrap(),
        )
        .await
    }

    fn key_account(&self) -> String {
        RelayStreamNoiseKeyStore::account_for_key_id(DEFAULT_RELAY_STREAM_NOISE_KEY_ID).unwrap()
    }

    fn key_path_exists(&self) -> bool {
        self.backend.path_for(&self.key_account()).exists()
    }

    fn preprovision_noise_public(&self) -> RelayStreamClawStaticPublicKey {
        RelayStreamNoiseKeyStore::new(&self.backend)
            .get_or_create(DEFAULT_RELAY_STREAM_NOISE_KEY_ID)
            .unwrap()
            .public_key()
            .clone()
    }
}

fn server_config(max_active_connections: usize) -> RelayStreamResponderServerConfig {
    RelayStreamResponderServerConfig {
        max_active_connections,
    }
}

fn responder_config(bind_addr: &str) -> RelayStreamResponderConfig {
    RelayStreamResponderConfig::new(
        bind_addr,
        Some(DEFAULT_RELAY_STREAM_NOISE_KEY_ID),
        Duration::from_millis(250),
        Duration::from_secs(60),
    )
    .unwrap()
}

fn relay_stream_offer_signed_by(
    claw_static_pub: RelayStreamClawStaticPublicKey,
    signer: &dyn IdentityKey,
) -> RelayStreamOfferContract {
    relay_stream_offer_for_static_pub(rendezvous_token(0x81), claw_static_pub, signer)
}

fn relay_stream_offer(
    fixture: &RuntimeFixture,
    claw_static_pub: RelayStreamClawStaticPublicKey,
) -> RelayStreamOfferContract {
    relay_stream_offer_signed_by(claw_static_pub, fixture.owner_key())
}

fn data_tunnel_credential(fixture: &RuntimeFixture) -> GuestCredential {
    data_tunnel_credential_with_owner(fixture.owner_pub(), fixture.owner_key())
}

fn data_tunnel_token(credential_cbor: &[u8], nonce: &[u8]) -> SessionAuthToken {
    support_data_tunnel_token(TOKEN_AUDIENCE, credential_cbor, nonce)
}

fn deps(
    fixture: &RuntimeFixture,
    slots: Arc<ClawShareSlotStore>,
    target_addr: String,
) -> Arc<ResponderDataTunnelDeps<TcpStreamRouter>> {
    Arc::new(ResponderDataTunnelDeps::new(
        derive_household_id(&fixture.owner_pub()),
        slots,
        Arc::new(ReplayGuard::new()),
        TcpStreamRouter::new(target_addr),
        Arc::new(ReopenStreamLimiter::new(ReopenLimiterConfig::default())),
    ))
}

async fn assembled_params(
    fixture: &RuntimeFixture,
    bind_addr: &str,
) -> Arc<RelayStreamResponderParams> {
    assembled_params_with_admission(fixture, bind_addr, fixture.admission().await).await
}

async fn assembled_params_with_admission(
    fixture: &RuntimeFixture,
    bind_addr: &str,
    admission: RelayStreamAdmission,
) -> Arc<RelayStreamResponderParams> {
    Arc::new(
        assemble_relay_stream_responder_params(
            &responder_config(bind_addr),
            &fixture.backend,
            admission,
        )
        .await
        .unwrap(),
    )
}

async fn spawn_test_server(
    fixture: &RuntimeFixture,
    offer: Arc<RelayStreamOfferContract>,
    deps: Arc<ResponderDataTunnelDeps<TcpStreamRouter>>,
    max_active_connections: usize,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let params = assembled_params(fixture, "127.0.0.1:49152").await;
    let handle = spawn_relay_stream_responder_on_listener(
        listener,
        server_config(max_active_connections),
        params,
        offer,
        deps,
    )
    .unwrap();
    (addr, handle)
}

async fn client_noise_stream(
    addr: SocketAddr,
    offer: &RelayStreamOfferContract,
    expected_owner_pub: &P256PublicKey,
) -> crate::claw_share_relay_stream_noise::RelayStreamNoiseAsyncStream<TcpStream> {
    let stream = TcpStream::connect(addr).await.unwrap();
    let guest = guest_pub();
    RelayStreamNoiseFramed::initiator_handshake(
        stream,
        offer,
        expected_owner_pub,
        &guest,
        now_unix(),
    )
    .await
    .unwrap()
    .into_async_stream()
}

#[tokio::test]
async fn relay_stream_responder_server_default_off_does_not_create_key() {
    let fixture = RuntimeFixture::new();
    let dummy_keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = Arc::new(relay_stream_offer(
        &fixture,
        dummy_keypair.public_key().clone(),
    ));
    let deps = deps(&fixture, data_tunnel_store(), "127.0.0.1:1".to_string());

    let handle = spawn_relay_stream_responder_if_enabled(
        None,
        RelayStreamResponderServerConfig::default(),
        &fixture.backend,
        fixture.admission().await,
        offer,
        deps,
    )
    .await
    .unwrap();

    assert!(handle.is_none());
    assert!(!fixture.key_path_exists());
}

#[tokio::test]
async fn relay_stream_responder_server_rejects_public_bind_addr_before_key_creation() {
    let fixture = RuntimeFixture::new();
    let dummy_keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = Arc::new(relay_stream_offer(
        &fixture,
        dummy_keypair.public_key().clone(),
    ));
    let deps = deps(&fixture, data_tunnel_store(), "127.0.0.1:1".to_string());
    let mut config = responder_config("127.0.0.1:49152");
    config.bind_addr = "0.0.0.0:49152".parse().unwrap();

    let error = spawn_relay_stream_responder_if_enabled(
        Some(config),
        RelayStreamResponderServerConfig::default(),
        &fixture.backend,
        fixture.admission().await,
        offer,
        deps,
    )
    .await
    .unwrap_err();

    assert!(matches!(
        error,
        RelayStreamResponderServerError::NonLoopbackBindAddr
    ));
    assert!(!fixture.key_path_exists());
}

#[tokio::test]
async fn relay_stream_responder_server_on_listener_auth_ok_pipes_data_to_target() {
    timeout(Duration::from_secs(5), async {
        let fixture = RuntimeFixture::new();
        let public = fixture.preprovision_noise_public();
        let offer = Arc::new(relay_stream_offer(&fixture, public));
        let slots = data_tunnel_store();
        let deps = deps(&fixture, slots, spawn_ack_target().await);
        let (addr, handle) = spawn_test_server(&fixture, Arc::clone(&offer), deps, 8).await;
        assert!(addr.ip().is_loopback());

        let mut stream = client_noise_stream(addr, &offer, &fixture.owner_pub()).await;
        let cbor = cbor::to_canonical_vec(&data_tunnel_credential(&fixture)).unwrap();
        assert!(matches!(
            client_authenticate(&mut stream, &cbor, data_tunnel_token(&cbor, b"server-ok"))
                .await
                .unwrap(),
            TunnelAck::Ok { .. }
        ));
        assert_eq!(
            client_health(&mut stream, HEALTH_PROBE).await.unwrap(),
            HEALTH_PROBE
        );
        client_open_stream(&mut stream).await.unwrap();
        send_frame(&mut stream, &TunnelFrame::Data(b"over-server".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            recv_frame(&mut stream).await.unwrap(),
            TunnelFrame::Data(b"ACK:over-server".to_vec())
        );
        send_frame(&mut stream, &TunnelFrame::Close).await.unwrap();
        handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_stream_responder_server_active_cap_drops_second_connection() {
    timeout(Duration::from_secs(3), async {
        let fixture = RuntimeFixture::new();
        let public = fixture.preprovision_noise_public();
        let offer = Arc::new(relay_stream_offer(&fixture, public));
        let deps = deps(&fixture, data_tunnel_store(), "127.0.0.1:1".to_string());
        let (addr, handle) = spawn_test_server(&fixture, offer, deps, 1).await;

        let first = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut second = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        match timeout(Duration::from_secs(2), second.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("cap-dropped connection read {n} byte(s)"),
            Err(_) => panic!("cap-dropped connection did not close"),
        }

        drop(first);
        handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_stream_responder_server_stale_admission_rejects_before_handshake() {
    timeout(Duration::from_secs(3), async {
        let fixture = RuntimeFixture::new();
        let public = fixture.preprovision_noise_public();
        let offer = Arc::new(relay_stream_offer(&fixture, public));
        let deps = deps(&fixture, data_tunnel_store(), "127.0.0.1:1".to_string());
        let stale_admission = fixture
            .admission_loaded_at(
                now_unix().saturating_sub(120),
                RelayStreamTrustContextRefreshPolicy::new(Duration::from_secs(1), 2).unwrap(),
            )
            .await;
        let params =
            assembled_params_with_admission(&fixture, "127.0.0.1:49152", stale_admission).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = spawn_relay_stream_responder_on_listener(
            listener,
            server_config(8),
            params,
            Arc::clone(&offer),
            deps,
        )
        .unwrap();

        let stream = TcpStream::connect(addr).await.unwrap();
        let guest = guest_pub();
        let result = timeout(
            Duration::from_millis(500),
            RelayStreamNoiseFramed::initiator_handshake(
                stream,
                &offer,
                &fixture.owner_pub(),
                &guest,
                now_unix(),
            ),
        )
        .await;

        assert!(result.is_err() || result.unwrap().is_err());
        handle.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_stream_responder_server_attacker_offer_fails_before_auth() {
    timeout(Duration::from_secs(3), async {
        let fixture = RuntimeFixture::new();
        let public = fixture.preprovision_noise_public();
        let attacker = attacker_signer();
        let offer = Arc::new(relay_stream_offer_signed_by(public, &attacker));
        let deps = deps(&fixture, data_tunnel_store(), "127.0.0.1:1".to_string());
        let (addr, handle) = spawn_test_server(&fixture, Arc::clone(&offer), deps, 8).await;

        let stream = TcpStream::connect(addr).await.unwrap();
        let guest = guest_pub();
        let result = RelayStreamNoiseFramed::initiator_handshake(
            stream,
            &offer,
            &attacker.public(),
            &guest,
            now_unix(),
        )
        .await;

        assert!(result.is_err());
        handle.abort();
    })
    .await
    .unwrap();
}
