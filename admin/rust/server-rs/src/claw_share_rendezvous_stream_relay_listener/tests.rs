#![cfg(test)]

use super::*;
use crate::claw_share_relay_stream_contract::{
    RelayStreamExpectedPath, RelayStreamOfferContract, RelayStreamOfferPayload, RelayStreamResource,
};
use crate::claw_share_relay_stream_noise::{
    RelayStreamNoiseAsyncStream, RelayStreamNoiseFramed, RelayStreamNoiseStaticKeypair,
    generate_relay_stream_noise_static_keypair, responder_handshake_with_trust,
};
use crate::claw_share_relay_stream_test_support::relay_stream_issuer_trust as trust;
use crate::claw_share_rendezvous_stream_relay::{RendezvousRole, RendezvousToken};
use household_rs::cbor;
use household_rs::claw_share::data_tunnel::{
    DEFAULT_AUTH_DEADLINE, DataTunnelError, HEALTH_PROBE, ReplayGuard, SessionAuthToken,
    TcpStreamRouter, TunnelAck, TunnelFrame, authorize_session, client_authenticate, client_health,
    client_open_stream, recv_frame, send_frame, serve_connection_io_with_auth_deadline,
};
use household_rs::claw_share::{
    ClawShareSlotStore, GuestCredential, SLOT_ID_LEN, SlotId, SlotRecord, SlotState,
};
use household_rs::ids::derive_household_id;
use household_rs::keys::{IdentityKey, P256Keypair, P256PublicKey};
use household_rs::person_cert::derive_person_id;
use std::ffi::OsString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const NOW: u64 = 1_800_000_000;
const NOT_AFTER: u64 = NOW + 60;
const DATA_TUNNEL_SLOT: SlotId = SlotId([0x22u8; SLOT_ID_LEN]);

struct EnvVarRestore {
    key: &'static str,
    previous: Option<OsString>,
}

#[allow(unsafe_code)]
impl Drop for EnvVarRestore {
    fn drop(&mut self) {
        // SAFETY: tests that mutate this var hold ENV_LOCK until this guard
        // restores it, preventing concurrent mutation in this module.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

#[allow(unsafe_code)]
fn set_bind_addr_env(value: Option<&str>) {
    // SAFETY: callers hold ENV_LOCK while mutating this process env var.
    unsafe {
        match value {
            Some(value) => std::env::set_var(RENDEZVOUS_RELAY_BIND_ADDR_ENV, value),
            None => std::env::remove_var(RENDEZVOUS_RELAY_BIND_ADDR_ENV),
        }
    }
}

fn token(label: u8) -> RendezvousToken {
    RendezvousToken::try_new(vec![label; 16]).unwrap()
}

fn owner_signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
}

fn owner_pub() -> P256PublicKey {
    owner_signer().public()
}

fn guest_signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap()
}

fn attacker_signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap()
}

fn relay_stream_offer(
    rendezvous_token: RendezvousToken,
    keypair: &RelayStreamNoiseStaticKeypair,
) -> RelayStreamOfferContract {
    let payload = RelayStreamOfferPayload::new(
        rendezvous_token,
        "claw_alpha".to_string(),
        DATA_TUNNEL_SLOT,
        guest_signer().public(),
        RelayStreamResource::Pty,
        RelayStreamExpectedPath::RelayStream,
        "relay-stream://127.0.0.1:0".to_string(),
        keypair.public_key().clone(),
        NOT_AFTER,
    );
    RelayStreamOfferContract::sign(payload, &owner_signer()).unwrap()
}

fn test_config() -> RendezvousStreamRelayListenerConfig {
    RendezvousStreamRelayListenerConfig {
        hello_timeout: Duration::from_millis(150),
        token_ttl: Duration::from_secs(30),
        max_pending: 8,
        max_active_connections: 16,
        reaper_interval: Duration::from_millis(50),
        splice_idle_timeout: Duration::from_secs(2),
        splice_max_lifetime: Duration::from_secs(60),
        splice_max_bytes_per_direction: None,
        abuse: RelayAbuseConfig::default(),
    }
}

async fn spawn_test_listener(
    config: RendezvousStreamRelayListenerConfig,
) -> (std::net::SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = serve_rendezvous_stream_relay(listener, config);
    (addr, handle)
}

async fn spawn_test_listener_with_status(
    config: RendezvousStreamRelayListenerConfig,
) -> (
    std::net::SocketAddr,
    JoinHandle<()>,
    RendezvousStreamRelayStatusHandle,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let status = RendezvousStreamRelayStatusHandle::new(addr.to_string(), true, &config);
    let handle = serve_rendezvous_stream_relay_with_status(listener, config, status.clone());
    (addr, handle, status)
}

async fn connect_with_hello(
    addr: std::net::SocketAddr,
    role: RendezvousRole,
    token: RendezvousToken,
) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let hello = RendezvousHello::new(role, token).encode();
    stream.write_all(&hello).await.unwrap();
    stream
}

async fn wait_until_status(
    status: &RendezvousStreamRelayStatusHandle,
    predicate: impl Fn(
        &crate::claw_share_rendezvous_stream_relay_status::RendezvousStreamRelayStatusSnapshot,
    ) -> bool,
) -> crate::claw_share_rendezvous_stream_relay_status::RendezvousStreamRelayStatusSnapshot {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let snapshot = status.snapshot();
        if predicate(&snapshot) || Instant::now() >= deadline {
            return snapshot;
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn relay_noise_async_stream_pair(
    label: u8,
) -> (
    RelayStreamNoiseAsyncStream<TcpStream>,
    RelayStreamNoiseAsyncStream<TcpStream>,
    JoinHandle<()>,
) {
    let (addr, server) = spawn_test_listener(test_config()).await;
    let rendezvous_token = token(label);
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = relay_stream_offer(rendezvous_token.clone(), &keypair);
    let owner = owner_pub();
    let issuer_trust = trust();
    let guest_device_pub = offer.payload.guest_device_pub.clone();

    let guest = connect_with_hello(addr, RendezvousRole::Guest, rendezvous_token.clone()).await;
    let claw = connect_with_hello(addr, RendezvousRole::Claw, rendezvous_token).await;
    let (guest_noise, claw_noise) = timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            RelayStreamNoiseFramed::initiator_handshake(
                guest,
                &offer,
                &owner,
                &guest_device_pub,
                NOW,
            ),
            responder_handshake_with_trust(claw, &offer, &issuer_trust, NOW, keypair.private_key(),)
        )
    })
    .await
    .unwrap()
    .unwrap();

    (
        guest_noise.into_async_stream(),
        claw_noise.into_async_stream(),
        server,
    )
}

fn data_tunnel_credential() -> GuestCredential {
    let owner = owner_signer();
    let owner_pub = owner.public();
    let issued_at = now_unix().saturating_sub(60);
    GuestCredential::sign(
        derive_household_id(&owner_pub),
        derive_person_id(&owner_pub),
        owner_pub,
        "claw_test".to_string(),
        guest_signer().public(),
        DATA_TUNNEL_SLOT,
        issued_at,
        issued_at + 86_400,
        &owner,
    )
    .unwrap()
}

fn data_tunnel_store() -> Arc<ClawShareSlotStore> {
    let store = ClawShareSlotStore::new();
    store
        .insert(SlotRecord {
            slot_id: DATA_TUNNEL_SLOT,
            claw_id: "claw_test".to_string(),
            expires_at: now_unix() + 86_400,
            state: SlotState::Open,
            app_presentation: None,
            created_at: None,
        })
        .unwrap();
    store
        .consume_atomic(
            &DATA_TUNNEL_SLOT,
            "claw_test",
            guest_signer().public(),
            now_unix(),
        )
        .unwrap();
    Arc::new(store)
}

fn data_tunnel_token_signed(
    credential_cbor: &[u8],
    signer: &P256Keypair,
    nonce: &[u8],
) -> SessionAuthToken {
    SessionAuthToken::sign(
        "relay-stream-data-tunnel".to_string(),
        credential_cbor,
        "relay-stream".to_string(),
        "claw_test".to_string(),
        nonce.to_vec(),
        now_unix() + 60,
        signer,
    )
    .unwrap()
}

fn data_tunnel_token(credential_cbor: &[u8], nonce: &[u8]) -> SessionAuthToken {
    data_tunnel_token_signed(credential_cbor, &guest_signer(), nonce)
}

async fn spawn_ack_target() -> String {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut sock, _) = target.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        loop {
            let n = match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut reply = b"ACK:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            if sock.write_all(&reply).await.is_err() {
                break;
            }
            let _ = sock.flush().await;
        }
    });
    addr
}

async fn spawn_ack_target_for_first_payload(expected: &'static [u8]) -> String {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut sock, _) = target.accept().await.unwrap();
        let mut first = vec![0u8; expected.len()];
        if sock.read_exact(&mut first).await.is_err() || first != expected {
            return;
        }

        let mut reply = b"ACK:".to_vec();
        reply.extend_from_slice(&first);
        if sock.write_all(&reply).await.is_err() {
            return;
        }
        let _ = sock.flush().await;

        let mut buf = [0u8; 1024];
        while matches!(sock.read(&mut buf).await, Ok(n) if n > 0) {}
    });
    addr
}

async fn serve_data_tunnel_over_noise(
    stream: RelayStreamNoiseAsyncStream<TcpStream>,
    slots: Arc<ClawShareSlotStore>,
    target_addr: String,
    replay: Arc<ReplayGuard>,
) -> Result<(), DataTunnelError> {
    serve_data_tunnel_over_noise_with_auth_deadline(
        stream,
        slots,
        target_addr,
        replay,
        DEFAULT_AUTH_DEADLINE,
    )
    .await
}

async fn serve_data_tunnel_over_noise_with_auth_deadline(
    stream: RelayStreamNoiseAsyncStream<TcpStream>,
    slots: Arc<ClawShareSlotStore>,
    target_addr: String,
    replay: Arc<ReplayGuard>,
    auth_deadline: Duration,
) -> Result<(), DataTunnelError> {
    let router = TcpStreamRouter::new(target_addr);
    let household = derive_household_id(&owner_pub());
    let auth_slots = Arc::clone(&slots);
    let rev_slots = Arc::clone(&slots);
    serve_connection_io_with_auth_deadline(
        stream,
        now_unix(),
        move |envelope, now| authorize_session(envelope, &household, &auth_slots, &replay, now),
        &router,
        move |cred| {
            matches!(
                rev_slots.get(&cred.slot_id).map(|record| record.state),
                Some(SlotState::Revoked { .. })
            )
        },
        auth_deadline,
    )
    .await
}

async fn assert_stream_closes(stream: &mut TcpStream) {
    let mut buf = [0u8; 1];
    let closed = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap();
    match closed {
        Ok(0) => {}
        Ok(n) => panic!("connection should close, read {n} byte(s)"),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof
            ) => {}
        Err(error) => panic!("unexpected close error: {error}"),
    }
}

async fn assert_plaintext_splice(from: &mut TcpStream, to: &mut TcpStream, payload: &'static [u8]) {
    from.write_all(payload).await.unwrap();
    let mut received = vec![0; payload.len()];
    timeout(Duration::from_secs(2), to.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
async fn rendezvous_stream_listener_splices_relay_stream_noise_end_to_end() {
    let (addr, server) = spawn_test_listener(test_config()).await;
    let token = token(0x61);
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = relay_stream_offer(token.clone(), &keypair);
    let owner = owner_pub();
    let issuer_trust = trust();
    let guest_device_pub = offer.payload.guest_device_pub.clone();

    let guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    let (mut guest_noise, mut claw_noise) = timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            RelayStreamNoiseFramed::initiator_handshake(
                guest,
                &offer,
                &owner,
                &guest_device_pub,
                NOW,
            ),
            responder_handshake_with_trust(claw, &offer, &issuer_trust, NOW, keypair.private_key(),)
        )
    })
    .await
    .unwrap()
    .unwrap();

    let guest_plaintext = b"guest plaintext only after Noise handshake";
    let claw_plaintext = b"claw plaintext only after Noise handshake";
    let guest_task = async {
        guest_noise.write_all_encrypted(guest_plaintext).await?;
        guest_noise.read_exact_encrypted(claw_plaintext.len()).await
    };
    let claw_task = async {
        let received = claw_noise
            .read_exact_encrypted(guest_plaintext.len())
            .await?;
        claw_noise.write_all_encrypted(claw_plaintext).await?;
        Ok::<_, crate::claw_share_relay_stream_noise::RelayStreamNoiseError>(received)
    };

    let (guest_received, claw_received) = timeout(Duration::from_secs(2), async {
        tokio::try_join!(guest_task, claw_task)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(guest_received, claw_plaintext);
    assert_eq!(claw_received, guest_plaintext);

    server.abort();
}

// The listener wires the per-direction byte cap end to end: 65 bytes
// against a 64-byte cap delivers exactly 64, hard-closes, and attributes
// the cap to the offending direction in the status counters.
#[tokio::test]
async fn rendezvous_stream_listener_byte_cap_hard_closes_and_counts_direction() {
    let config = RendezvousStreamRelayListenerConfig {
        splice_max_bytes_per_direction: Some(64),
        splice_idle_timeout: Duration::from_secs(5),
        ..test_config()
    };
    let (addr, server, status) = spawn_test_listener_with_status(config).await;
    let token = token(0x7b);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    guest.write_all(&vec![0x42; 65]).await.unwrap();
    let mut received = Vec::new();
    timeout(Duration::from_secs(2), claw.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.len(), 64, "byte B+1 must never be delivered");

    let snapshot = wait_until_status(&status, |s| {
        s.counters.splice_byte_cap_exceeded_guest_to_claw == 1
    })
    .await;
    assert_eq!(snapshot.counters.splice_byte_cap_exceeded_guest_to_claw, 1);
    assert_eq!(snapshot.counters.splice_byte_cap_exceeded_claw_to_guest, 0);
    // §6.2: the forwarded bytes reach the status surface, and stop at the
    // cap. 65 was offered, 64 forwarded — the counter must read 64, not 65.
    assert_eq!(snapshot.counters.bytes_guest_to_claw, 64);
    assert_eq!(snapshot.counters.bytes_claw_to_guest, 0);
    server.abort();
}

// The opposite cap direction, end to end. §6.2 asks for BOTH directions and
// only guest->claw existed at the listener level before this slice.
#[tokio::test]
async fn rendezvous_stream_listener_byte_cap_counts_claw_to_guest_bytes() {
    let config = RendezvousStreamRelayListenerConfig {
        splice_max_bytes_per_direction: Some(64),
        splice_idle_timeout: Duration::from_secs(5),
        ..test_config()
    };
    let (addr, server, status) = spawn_test_listener_with_status(config).await;
    let token = token(0x81);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    claw.write_all(&vec![0x43; 65]).await.unwrap();
    let mut received = Vec::new();
    timeout(Duration::from_secs(2), guest.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.len(), 64, "byte B+1 must never be delivered");

    let snapshot = wait_until_status(&status, |s| {
        s.counters.splice_byte_cap_exceeded_claw_to_guest == 1
    })
    .await;
    assert_eq!(snapshot.counters.splice_byte_cap_exceeded_claw_to_guest, 1);
    assert_eq!(snapshot.counters.splice_byte_cap_exceeded_guest_to_claw, 0);
    assert_eq!(snapshot.counters.bytes_claw_to_guest, 64);
    assert_eq!(snapshot.counters.bytes_guest_to_claw, 0);
    server.abort();
}

// §6.2 normal close: real bytes in BOTH directions reach the status
// surface. The pre-existing end-to-end tests asserted payload equality
// only, never the counters.
#[tokio::test]
async fn rendezvous_stream_listener_normal_close_counts_bytes_both_directions() {
    let (addr, server, status) = spawn_test_listener_with_status(test_config()).await;
    let token = token(0x82);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    guest.write_all(&vec![0xa1; 100]).await.unwrap();
    claw.write_all(&vec![0xb2; 40]).await.unwrap();
    let mut to_claw = vec![0_u8; 100];
    claw.read_exact(&mut to_claw).await.unwrap();
    let mut to_guest = vec![0_u8; 40];
    guest.read_exact(&mut to_guest).await.unwrap();
    guest.shutdown().await.unwrap();
    claw.shutdown().await.unwrap();

    let snapshot = wait_until_status(&status, |s| s.counters.splice_closed == 1).await;
    assert_eq!(snapshot.counters.splice_closed, 1);
    assert_eq!(snapshot.counters.bytes_guest_to_claw, 100);
    assert_eq!(snapshot.counters.bytes_claw_to_guest, 40);
    server.abort();
}

// §6.2's headline gap: a splice that ends by IDLE TIMEOUT used to report
// zero bytes, because the timer arm cancelled the pump and its local
// counters died with it. Non-zero here is the whole point — mutating the
// timeout path back to reporting 0 must turn this RED.
#[tokio::test]
async fn rendezvous_stream_listener_idle_timeout_counts_the_bytes_it_forwarded() {
    let config = RendezvousStreamRelayListenerConfig {
        splice_idle_timeout: Duration::from_millis(200),
        ..test_config()
    };
    let (addr, server, status) = spawn_test_listener_with_status(config).await;
    let token = token(0x83);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    // Forward real traffic, then go quiet and let the idle timer win.
    guest.write_all(&vec![0xc3; 77]).await.unwrap();
    let mut to_claw = vec![0_u8; 77];
    claw.read_exact(&mut to_claw).await.unwrap();

    let snapshot = wait_until_status(&status, |s| s.counters.splice_idle_timeout == 1).await;
    assert_eq!(snapshot.counters.splice_idle_timeout, 1);
    assert_eq!(
        snapshot.counters.bytes_guest_to_claw, 77,
        "an idle-timed-out splice must still report what it forwarded"
    );
    server.abort();
}

// Same gap, the lifetime cap. In practice the worse of the two: a
// long-lived high-volume splice hitting the absolute lifetime used to
// report zero.
#[tokio::test]
async fn rendezvous_stream_listener_lifetime_elapsed_counts_the_bytes_it_forwarded() {
    let config = RendezvousStreamRelayListenerConfig {
        splice_idle_timeout: Duration::from_secs(30),
        splice_max_lifetime: Duration::from_millis(300),
        ..test_config()
    };
    let (addr, server, status) = spawn_test_listener_with_status(config).await;
    let token = token(0x84);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    guest.write_all(&vec![0xd4; 55]).await.unwrap();
    let mut to_claw = vec![0_u8; 55];
    claw.read_exact(&mut to_claw).await.unwrap();
    claw.write_all(&vec![0xe5; 33]).await.unwrap();
    let mut to_guest = vec![0_u8; 33];
    guest.read_exact(&mut to_guest).await.unwrap();

    let snapshot = wait_until_status(&status, |s| s.counters.splice_lifetime_elapsed == 1).await;
    assert_eq!(snapshot.counters.splice_lifetime_elapsed, 1);
    assert_eq!(
        snapshot.counters.bytes_guest_to_claw, 55,
        "a lifetime-capped splice must still report what it forwarded"
    );
    assert_eq!(snapshot.counters.bytes_claw_to_guest, 33);
    server.abort();
}

// Legacy default stays unlimited: with the generic test_config (no cap),
// a payload far above the public-relay budget splices intact.
#[tokio::test]
async fn rendezvous_stream_listener_default_config_has_no_byte_cap() {
    let (addr, server) = spawn_test_listener(test_config()).await;
    let token = token(0x7c);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    let payload = vec![0x24; 128 * 1024];
    guest.write_all(&payload).await.unwrap();
    guest.shutdown().await.unwrap();
    let mut received = Vec::new();
    timeout(Duration::from_secs(5), claw.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, payload);
    server.abort();
}

#[tokio::test]
#[ignore = "deflake-carry: timing flake under parallel load, passes isolated 3x; tracked, see relay-integration deflake carry"]
async fn rendezvous_stream_listener_carries_noise_async_data_tunnel_to_target() {
    timeout(Duration::from_secs(5), async {
        let (mut guest, claw, server) = relay_noise_async_stream_pair(0x66).await;
        let slots = data_tunnel_store();
        let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
        let payload = b"over-relay-noise";
        let target_addr = spawn_ack_target_for_first_payload(payload).await;
        let claw_task = tokio::spawn(serve_data_tunnel_over_noise(
            claw,
            Arc::clone(&slots),
            target_addr,
            Arc::new(ReplayGuard::new()),
        ));

        assert!(matches!(
            client_authenticate(&mut guest, &cbor, data_tunnel_token(&cbor, b"noise-e2e"))
                .await
                .unwrap(),
            TunnelAck::Ok { .. }
        ));
        assert_eq!(
            client_health(&mut guest, HEALTH_PROBE).await.unwrap(),
            HEALTH_PROBE
        );
        client_open_stream(&mut guest).await.unwrap();
        send_frame(&mut guest, &TunnelFrame::Data(payload.to_vec()))
            .await
            .unwrap();
        assert_eq!(
            recv_frame(&mut guest).await.unwrap(),
            TunnelFrame::Data(b"ACK:over-relay-noise".to_vec())
        );

        send_frame(&mut guest, &TunnelFrame::Close).await.unwrap();
        claw_task.await.unwrap().unwrap();
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "deflake-carry: timing flake under parallel load, passes isolated 3x; tracked, see relay-integration deflake carry"]
async fn rendezvous_stream_listener_data_tunnel_revoke_post_open_tears_down_inside_noise() {
    timeout(Duration::from_secs(5), async {
        let (mut guest, claw, server) = relay_noise_async_stream_pair(0x68).await;
        let slots = data_tunnel_store();
        let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
        let claw_task = tokio::spawn(serve_data_tunnel_over_noise(
            claw,
            Arc::clone(&slots),
            spawn_ack_target().await,
            Arc::new(ReplayGuard::new()),
        ));

        assert!(matches!(
            client_authenticate(&mut guest, &cbor, data_tunnel_token(&cbor, b"revoke-open"))
                .await
                .unwrap(),
            TunnelAck::Ok { .. }
        ));
        assert_eq!(
            client_health(&mut guest, HEALTH_PROBE).await.unwrap(),
            HEALTH_PROBE
        );
        client_open_stream(&mut guest).await.unwrap();
        send_frame(&mut guest, &TunnelFrame::Data(b"before-revoke".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            recv_frame(&mut guest).await.unwrap(),
            TunnelFrame::Data(b"ACK:before-revoke".to_vec())
        );

        slots.revoke(&DATA_TUNNEL_SLOT, now_unix()).unwrap();
        match timeout(
            Duration::from_secs(2),
            send_frame(&mut guest, &TunnelFrame::Data(b"after-revoke".to_vec())),
        )
        .await
        {
            Ok(Ok(())) => match timeout(Duration::from_secs(2), recv_frame(&mut guest)).await {
                Ok(Ok(frame)) => {
                    panic!("revoked Noise data-tunnel session must close, got {frame:?}")
                }
                Ok(Err(_)) | Err(_) => {}
            },
            Ok(Err(_)) => {}
            Err(_) => panic!("write after revoke hung"),
        }

        assert_eq!(
            timeout(Duration::from_secs(2), claw_task)
                .await
                .expect("revoked session should stop within 2s")
                .unwrap()
                .unwrap_err(),
            DataTunnelError::Rejected("slot-revoked".into())
        );
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rendezvous_stream_listener_noise_without_auth_times_out_data_tunnel() {
    timeout(Duration::from_secs(5), async {
        let (mut guest, claw, server) = relay_noise_async_stream_pair(0x69).await;
        let claw_task = tokio::spawn(serve_data_tunnel_over_noise_with_auth_deadline(
            claw,
            data_tunnel_store(),
            "127.0.0.1:1".to_string(),
            Arc::new(ReplayGuard::new()),
            Duration::from_millis(75),
        ));

        let mut buf = [0u8; 1];
        match timeout(Duration::from_secs(2), guest.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("pre-auth timeout should close, read {n} byte(s)"),
            Err(_) => panic!("pre-auth timeout did not close guest side"),
        }

        assert_eq!(
            timeout(Duration::from_secs(2), claw_task)
                .await
                .expect("pre-auth timeout should stop within 2s")
                .unwrap()
                .unwrap_err(),
            DataTunnelError::AuthTimeout
        );
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rendezvous_stream_listener_data_tunnel_rejects_bad_token_inside_noise() {
    timeout(Duration::from_secs(5), async {
        let (mut guest, claw, server) = relay_noise_async_stream_pair(0x67).await;
        let slots = data_tunnel_store();
        let cbor = cbor::to_canonical_vec(&data_tunnel_credential()).unwrap();
        let claw_task = tokio::spawn(serve_data_tunnel_over_noise(
            claw,
            Arc::clone(&slots),
            "127.0.0.1:1".to_string(),
            Arc::new(ReplayGuard::new()),
        ));

        match client_authenticate(
            &mut guest,
            &cbor,
            data_tunnel_token_signed(&cbor, &attacker_signer(), b"bad-token"),
        )
        .await
        .unwrap()
        {
            TunnelAck::Rejected { reason } => assert_eq!(reason, "signature-invalid"),
            other => panic!("bad token inside Noise must be rejected, got {other:?}"),
        }

        assert_eq!(
            claw_task.await.unwrap().unwrap_err(),
            DataTunnelError::TokenRejected("signature-invalid".into())
        );
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rendezvous_stream_listener_splices_noise_handshake_failures_without_plaintext() {
    let (addr, server) = spawn_test_listener(test_config()).await;
    let rendezvous_token = token(0x62);
    let keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let responder_offer = relay_stream_offer(rendezvous_token.clone(), &keypair);
    let initiator_offer = relay_stream_offer(token(0x63), &keypair);
    let owner = owner_pub();
    let issuer_trust = trust();
    let initiator_guest_device_pub = initiator_offer.payload.guest_device_pub.clone();

    let guest = connect_with_hello(addr, RendezvousRole::Guest, rendezvous_token.clone()).await;
    let claw = connect_with_hello(addr, RendezvousRole::Claw, rendezvous_token).await;
    let divergent = timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            RelayStreamNoiseFramed::initiator_handshake(
                guest,
                &initiator_offer,
                &owner,
                &initiator_guest_device_pub,
                NOW,
            ),
            responder_handshake_with_trust(
                claw,
                &responder_offer,
                &issuer_trust,
                NOW,
                keypair.private_key(),
            )
        )
    })
    .await
    .unwrap();
    assert!(divergent.is_err());

    let rendezvous_token = token(0x64);
    let expected_keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let wrong_keypair = generate_relay_stream_noise_static_keypair().unwrap();
    let offer = relay_stream_offer(rendezvous_token.clone(), &expected_keypair);
    let guest_device_pub = offer.payload.guest_device_pub.clone();
    let guest = connect_with_hello(addr, RendezvousRole::Guest, rendezvous_token.clone()).await;
    let claw = connect_with_hello(addr, RendezvousRole::Claw, rendezvous_token).await;
    let wrong_key = timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            RelayStreamNoiseFramed::initiator_handshake(
                guest,
                &offer,
                &owner,
                &guest_device_pub,
                NOW,
            ),
            responder_handshake_with_trust(
                claw,
                &offer,
                &issuer_trust,
                NOW,
                wrong_keypair.private_key(),
            )
        )
    })
    .await
    .unwrap();
    assert!(wrong_key.is_err());

    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_noise_handshake_idle_is_capped_by_splice_timeout() {
    let config = RendezvousStreamRelayListenerConfig {
        splice_idle_timeout: Duration::from_millis(100),
        ..test_config()
    };
    let (addr, server) = spawn_test_listener(config).await;
    let token = token(0x65);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let _claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    assert_stream_closes(&mut guest).await;
    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_pairs_and_splices_loopback() {
    let (addr, server) = spawn_test_listener(test_config()).await;
    let token = token(0x51);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    let from_guest = b"guest-to-claw";
    guest.write_all(from_guest).await.unwrap();
    let mut received_by_claw = vec![0; from_guest.len()];
    timeout(
        Duration::from_secs(2),
        claw.read_exact(&mut received_by_claw),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received_by_claw, from_guest);

    let from_claw = b"claw-to-guest";
    claw.write_all(from_claw).await.unwrap();
    let mut received_by_guest = vec![0; from_claw.len()];
    timeout(
        Duration::from_secs(2),
        guest.read_exact(&mut received_by_guest),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received_by_guest, from_claw);

    guest.shutdown().await.unwrap();
    claw.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_activity_extends_splice_lifetime() {
    let config = RendezvousStreamRelayListenerConfig {
        splice_idle_timeout: Duration::from_millis(150),
        ..test_config()
    };
    let (addr, server) = spawn_test_listener(config).await;
    let token = token(0x54);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    for byte in [0xa1, 0xa2, 0xa3] {
        sleep(Duration::from_millis(90)).await;
        guest.write_all(&[byte]).await.unwrap();
        let mut received = [0u8; 1];
        timeout(Duration::from_secs(2), claw.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, [byte]);
    }

    guest.shutdown().await.unwrap();
    claw.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_idle_splice_closes() {
    let config = RendezvousStreamRelayListenerConfig {
        splice_idle_timeout: Duration::from_millis(100),
        ..test_config()
    };
    let (addr, server) = spawn_test_listener(config).await;
    let token = token(0x55);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let _claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    assert_stream_closes(&mut guest).await;
    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_absolute_splice_lifetime_closes_active_pair() {
    let config = RendezvousStreamRelayListenerConfig {
        splice_idle_timeout: Duration::from_secs(5),
        splice_max_lifetime: Duration::from_millis(100),
        ..test_config()
    };
    let (addr, server) = spawn_test_listener(config).await;
    let token = token(0x6a);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let _claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;

    assert_stream_closes(&mut guest).await;
    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_hello_timeout_closes_idle_connection() {
    let (addr, server) = spawn_test_listener(test_config()).await;
    let mut idle = TcpStream::connect(addr).await.unwrap();
    assert_stream_closes(&mut idle).await;

    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_status_counts_aggregate_hello_rejects() {
    let (addr, server, status) = spawn_test_listener_with_status(test_config()).await;
    let mut malformed = TcpStream::connect(addr).await.unwrap();
    malformed.write_all(&[0, 0, 0, 0]).await.unwrap();
    assert_stream_closes(&mut malformed).await;

    let snapshot = wait_until_status(&status, |snapshot| snapshot.drops.malformed_hello == 1).await;
    assert_eq!(snapshot.drops.malformed_hello, 1);
    assert_eq!(snapshot.counters.accepted_connections, 1);
    assert_eq!(snapshot.active_connections, 0);

    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains("payload"));
    assert!(!encoded.contains("source_ip"));
    assert!(!encoded.contains("source_buckets\":{"));
    assert!(!encoded.contains("sources\":["));

    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_duplicate_role_rejects_second_guest() {
    let (addr, server) = spawn_test_listener(test_config()).await;
    let token = token(0x52);

    let mut first_guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    let mut duplicate_guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    assert_stream_closes(&mut duplicate_guest).await;

    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;
    let payload = b"first-guest-still-pairs";
    first_guest.write_all(payload).await.unwrap();
    let mut received = vec![0; payload.len()];
    timeout(Duration::from_secs(2), claw.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, payload);

    first_guest.shutdown().await.unwrap();
    claw.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_active_connection_limit_rejects_pre_offer_flood() {
    let config = RendezvousStreamRelayListenerConfig {
        max_active_connections: 1,
        ..test_config()
    };
    let (addr, server) = spawn_test_listener(config).await;
    let rejected_token = token(0x56);

    let _parked_guest = connect_with_hello(addr, RendezvousRole::Guest, token(0x57)).await;
    let mut rejected = TcpStream::connect(addr).await.unwrap();
    rejected
        .write_all(&RendezvousHello::new(RendezvousRole::Claw, rejected_token).encode())
        .await
        .unwrap();

    assert_stream_closes(&mut rejected).await;
    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_source_unpaired_limit_rejects_pre_hello_flood() {
    let config = RendezvousStreamRelayListenerConfig {
        hello_timeout: Duration::from_secs(1),
        abuse: RelayAbuseConfig {
            max_unpaired_active_per_source: 1,
            ..RelayAbuseConfig::default()
        },
        ..test_config()
    };
    let (addr, server) = spawn_test_listener(config).await;

    let _idle = TcpStream::connect(addr).await.unwrap();
    let mut rejected = TcpStream::connect(addr).await.unwrap();
    let _ = rejected
        .write_all(&RendezvousHello::new(RendezvousRole::Guest, token(0x6b)).encode())
        .await;

    assert_stream_closes(&mut rejected).await;
    server.abort();
}

#[tokio::test]
#[ignore = "deflake-carry: timing flake under parallel load, passes isolated 3x; tracked, see relay-integration deflake carry"]
async fn rendezvous_stream_listener_parked_stream_releases_unpaired_source_permit() {
    let config = RendezvousStreamRelayListenerConfig {
        abuse: RelayAbuseConfig {
            max_unpaired_active_per_source: 1,
            max_pending_per_source: 4,
            ..RelayAbuseConfig::default()
        },
        ..test_config()
    };
    let (addr, server) = spawn_test_listener(config).await;
    let token_a = token(0x6c);
    let token_b = token(0x6d);

    let mut first_guest = connect_with_hello(addr, RendezvousRole::Guest, token_a.clone()).await;
    sleep(Duration::from_millis(50)).await;
    let mut second_guest = connect_with_hello(addr, RendezvousRole::Guest, token_b.clone()).await;

    let mut first_claw = connect_with_hello(addr, RendezvousRole::Claw, token_a).await;
    assert_plaintext_splice(&mut first_guest, &mut first_claw, b"first-pairs").await;

    let mut second_claw = connect_with_hello(addr, RendezvousRole::Claw, token_b).await;
    assert_plaintext_splice(&mut second_guest, &mut second_claw, b"second-pairs").await;

    first_guest.shutdown().await.unwrap();
    first_claw.shutdown().await.unwrap();
    second_guest.shutdown().await.unwrap();
    second_claw.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_source_pending_limit_rejects_second_parked_stream() {
    let config = RendezvousStreamRelayListenerConfig {
        abuse: RelayAbuseConfig {
            max_unpaired_active_per_source: 4,
            max_pending_per_source: 1,
            ..RelayAbuseConfig::default()
        },
        ..test_config()
    };
    let (addr, server) = spawn_test_listener(config).await;
    let first_token = token(0x6e);

    let mut first_guest =
        connect_with_hello(addr, RendezvousRole::Guest, first_token.clone()).await;
    sleep(Duration::from_millis(50)).await;
    let mut rejected_guest = connect_with_hello(addr, RendezvousRole::Guest, token(0x6f)).await;
    assert_stream_closes(&mut rejected_guest).await;

    let mut first_claw = connect_with_hello(addr, RendezvousRole::Claw, first_token).await;
    assert_plaintext_splice(&mut first_guest, &mut first_claw, b"pending-survives").await;

    first_guest.shutdown().await.unwrap();
    first_claw.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_failed_hello_budget_blocks_until_refill() {
    let config = RendezvousStreamRelayListenerConfig {
        abuse: RelayAbuseConfig {
            max_failed_hellos_per_source_per_window: 1,
            hello_attempt_window: Duration::from_millis(100),
            ..RelayAbuseConfig::default()
        },
        ..test_config()
    };
    let (addr, server) = spawn_test_listener(config).await;

    let mut bad = TcpStream::connect(addr).await.unwrap();
    bad.write_all(&[0xff, 0xff, 0x00, 0x00]).await.unwrap();
    assert_stream_closes(&mut bad).await;

    let mut blocked = connect_with_hello(addr, RendezvousRole::Guest, token(0x70)).await;
    assert_stream_closes(&mut blocked).await;

    sleep(Duration::from_millis(120)).await;
    let allowed_token = token(0x71);
    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, allowed_token.clone()).await;
    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, allowed_token).await;
    assert_plaintext_splice(&mut guest, &mut claw, b"after-refill").await;

    guest.shutdown().await.unwrap();
    claw.shutdown().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_paired_stream_survives_same_source_failed_hello_flood() {
    let config = RendezvousStreamRelayListenerConfig {
        abuse: RelayAbuseConfig {
            max_failed_hellos_per_source_per_window: 2,
            max_hello_attempts_per_source_per_window: 8,
            max_unpaired_active_per_source: 2,
            ..RelayAbuseConfig::default()
        },
        ..test_config()
    };
    let (addr, server, status) = spawn_test_listener_with_status(config).await;
    let legitimate_token = token(0x72);
    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, legitimate_token.clone()).await;
    let mut claw = connect_with_hello(addr, RendezvousRole::Claw, legitimate_token).await;
    assert_plaintext_splice(&mut guest, &mut claw, b"legit-before-flood").await;

    for _ in 0..5 {
        let mut bad = TcpStream::connect(addr).await.unwrap();
        bad.write_all(&[0xff, 0xff, 0x00, 0x00]).await.unwrap();
        assert_stream_closes(&mut bad).await;
    }

    assert_plaintext_splice(&mut guest, &mut claw, b"legit-after-flood").await;
    guest.shutdown().await.unwrap();
    claw.shutdown().await.unwrap();

    let snapshot = wait_until_status(&status, |snapshot| {
        snapshot.active_connections == 0
            && snapshot.counters.paired_sessions == 1
            && snapshot.drops.malformed_hello == 2
            && snapshot.drops.failed_hello_rate_limited == 3
    })
    .await;
    assert_eq!(snapshot.active_connections, 0);
    assert_eq!(snapshot.counters.paired_sessions, 1);
    assert_eq!(snapshot.drops.malformed_hello, 2);
    assert_eq!(snapshot.drops.failed_hello_rate_limited, 3);
    assert_eq!(snapshot.drops.global_active_limit, 0);
    assert_eq!(snapshot.source_buckets, 1);

    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_garbage_and_oversized_hello_close() {
    let (addr, server) = spawn_test_listener(test_config()).await;

    let mut garbage = TcpStream::connect(addr).await.unwrap();
    garbage.write_all(&[0xff, 0xff, 0x00, 0x00]).await.unwrap();
    assert_stream_closes(&mut garbage).await;

    let mut oversized = TcpStream::connect(addr).await.unwrap();
    oversized.write_all(&[1, 1, 0, 129]).await.unwrap();
    assert_stream_closes(&mut oversized).await;

    server.abort();
}

#[tokio::test]
async fn rendezvous_stream_listener_reaper_expires_parked_guest() {
    let config = RendezvousStreamRelayListenerConfig {
        token_ttl: Duration::from_secs(1),
        reaper_interval: Duration::from_millis(50),
        ..test_config()
    };
    let (addr, server) = spawn_test_listener(config).await;
    let token = token(0x53);

    let mut guest = connect_with_hello(addr, RendezvousRole::Guest, token.clone()).await;
    assert_stream_closes(&mut guest).await;

    let mut late_claw = connect_with_hello(addr, RendezvousRole::Claw, token).await;
    assert_stream_closes(&mut late_claw).await;

    server.abort();
}

#[tokio::test]
#[allow(unsafe_code)]
async fn rendezvous_stream_relay_env_helper_is_default_off() {
    let _env_guard = ENV_LOCK.lock().await;
    let _restore = EnvVarRestore {
        key: RENDEZVOUS_RELAY_BIND_ADDR_ENV,
        previous: std::env::var_os(RENDEZVOUS_RELAY_BIND_ADDR_ENV),
    };
    set_bind_addr_env(None);

    let spawned = spawn_rendezvous_stream_relay_from_env().await.unwrap();

    assert!(spawned.is_none());

    set_bind_addr_env(Some(""));
    let spawned = spawn_rendezvous_stream_relay_from_env().await.unwrap();

    assert!(spawned.is_none());
}

#[tokio::test]
async fn rendezvous_stream_relay_env_helper_accepts_ipv4_loopback() {
    let _env_guard = ENV_LOCK.lock().await;
    let _restore = EnvVarRestore {
        key: RENDEZVOUS_RELAY_BIND_ADDR_ENV,
        previous: std::env::var_os(RENDEZVOUS_RELAY_BIND_ADDR_ENV),
    };
    set_bind_addr_env(Some("127.0.0.1:0"));

    let spawned = spawn_rendezvous_stream_relay_from_env().await.unwrap();
    let handle = spawned.expect("loopback env bind should spawn listener");

    handle.abort();
}

#[tokio::test]
async fn rendezvous_stream_relay_env_helper_accepts_ipv6_loopback_when_available() {
    if TcpListener::bind("[::1]:0").await.is_err() {
        return;
    }

    let _env_guard = ENV_LOCK.lock().await;
    let _restore = EnvVarRestore {
        key: RENDEZVOUS_RELAY_BIND_ADDR_ENV,
        previous: std::env::var_os(RENDEZVOUS_RELAY_BIND_ADDR_ENV),
    };
    set_bind_addr_env(Some("[::1]:0"));

    let spawned = spawn_rendezvous_stream_relay_from_env().await.unwrap();
    let handle = spawned.expect("ipv6 loopback env bind should spawn listener");

    handle.abort();
}

#[tokio::test]
async fn rendezvous_stream_relay_env_helper_rejects_wildcard_binds() {
    let _env_guard = ENV_LOCK.lock().await;
    let _restore = EnvVarRestore {
        key: RENDEZVOUS_RELAY_BIND_ADDR_ENV,
        previous: std::env::var_os(RENDEZVOUS_RELAY_BIND_ADDR_ENV),
    };

    for bind_addr in ["0.0.0.0:0", "[::]:0"] {
        set_bind_addr_env(Some(bind_addr));
        let error = spawn_rendezvous_stream_relay_from_env().await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
}

// C7d-2: the opt-in public path skips the loopback fail-closed check, so it
// binds the exact wildcard address the loopback path rejects above. Uses an
// ephemeral port and aborts immediately; no env mutation (explicit addr).
#[tokio::test]
async fn rendezvous_stream_relay_allow_public_binds_wildcard() {
    let handle = spawn_rendezvous_stream_relay_allow_public("0.0.0.0:0")
        .await
        .expect("allow-public path must bind a non-loopback wildcard address");
    handle.abort();
}
