#![cfg(test)]

use super::*;
use crate::claw_share::{SLOT_ID_LEN, SlotId, SlotRecord};
use crate::ids::derive_household_id;
use crate::keys::{IdentityKey, P256Keypair};
use crate::person_cert::derive_person_id;
use tokio::net::{TcpListener, TcpStream};

const ISSUED: u64 = 1_800_000_000;
const EXPIRES: u64 = 1_800_086_400; // 24h
const NOW: u64 = 1_800_000_002;
const SLOT: SlotId = SlotId([0x22u8; SLOT_ID_LEN]);

fn owner() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
}
fn guest() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap()
}

/// Owner-signed credential for `(claw_id, guest_device_pub)`.
fn credential(claw_id: &str, guest_pub: crate::keys::P256PublicKey) -> GuestCredential {
    let owner_key = owner();
    let owner_pub = owner_key.public();
    let hh_id = derive_household_id(&owner_pub);
    let owner_p_id = derive_person_id(&owner_pub);
    GuestCredential::sign(
        hh_id,
        owner_p_id,
        owner_pub,
        claw_id.to_string(),
        guest_pub,
        SLOT,
        ISSUED,
        EXPIRES,
        &owner_key,
    )
    .expect("sign credential")
}

fn engine_hh() -> HouseholdId {
    derive_household_id(&owner().public())
}

// ── S0 oracle: frozen claw wire vectors ────────────────────────────────
//
// These assert the wire bytes of every `TunnelFrame` variant against a
// fixture that lives in `tests/data/`, NOT in this file. That separation is
// the point: S0 will move this codec into a neutral module, and an oracle
// living in the file under test would move with it and could be regenerated
// by the very commit it is supposed to judge. The fixture lands in an
// EARLIER commit, so its blob belongs to a prior generation and
// `git diff --name-only <vectors-commit> <extraction-commit> -- <fixture>`
// being empty is a fact about history rather than a promise.
//
// The vectors were emitted from the live encoder, not hand-written.

fn s0_wire_vectors() -> Vec<(String, Vec<u8>)> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/s0_claw_wire_vectors_v1.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("S0 wire-vector fixture unreadable at {path:?}: {e}"));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("fixture is JSON");
    let cases = doc["vectors"].as_array().expect("vectors array");
    assert!(!cases.is_empty(), "the fixture must not be empty");
    cases
        .iter()
        .map(|c| {
            let name = c["name"].as_str().expect("name").to_string();
            let bytes = hex_decode(c["hex"].as_str().expect("hex"));
            (name, bytes)
        })
        .collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex must be even-length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Every frozen vector must still decode, and re-encode to the SAME bytes.
///
/// This is the byte-equality oracle S0 is measured against. It runs
/// identically before and after the neutral extraction; if the move changes
/// a single wire byte of claw behaviour, this fails.
#[test]
fn s0_claw_wire_vectors_round_trip_byte_identical() {
    let vectors = s0_wire_vectors();
    assert_eq!(
        vectors.len(),
        11,
        "the frozen set covers every TunnelFrame variant; losing one \
             silently narrows the oracle"
    );
    for (name, bytes) in vectors {
        let frame = TunnelFrame::decode(&bytes)
            .unwrap_or_else(|e| panic!("{name}: frozen vector no longer decodes: {e:?}"));
        let re = frame.encode();
        assert_eq!(
            re, bytes,
            "{name}: re-encoding the frozen vector produced different wire bytes"
        );
    }
}

/// Non-vacuity control for the oracle above.
///
/// A round-trip test passes trivially if the fixture is empty, if the
/// decoder accepts anything, or if `encode` and `decode` are inverses of
/// each other while both drifting together. This pins the opcode byte of
/// each vector against the `FRAME_*` constants independently of the codec,
/// and proves the decoder rejects a corrupted vector.
#[test]
fn s0_wire_vector_oracle_can_actually_fail() {
    let vectors = s0_wire_vectors();
    let expected_opcode: std::collections::BTreeMap<&str, u8> = [
        ("health", FRAME_HEALTH),
        ("open", FRAME_OPEN),
        ("data", FRAME_DATA),
        ("close", FRAME_CLOSE),
        ("error", FRAME_ERROR),
        ("window", FRAME_WINDOW),
        ("resize", FRAME_RESIZE),
        ("exit_code", FRAME_EXIT),
        ("exit_signal", FRAME_EXIT),
        ("exit_lost", FRAME_EXIT),
        ("network_settings", FRAME_NETWORK_SETTINGS),
    ]
    .into_iter()
    .collect();

    for (name, bytes) in &vectors {
        let want = expected_opcode
            .get(name.as_str())
            .unwrap_or_else(|| panic!("{name}: vector not covered by the opcode control"));
        assert_eq!(
            bytes[0], *want,
            "{name}: frozen vector's opcode byte drifted from the FRAME_* constant"
        );
    }

    // The needle: a corrupted opcode must be rejected, so "it decoded" is
    // information and not a foregone conclusion.
    let mut corrupt = vectors[0].1.clone();
    corrupt[0] = 0xEE;
    assert!(
        TunnelFrame::decode(&corrupt).is_err(),
        "the decoder accepts an unknown opcode; the round-trip oracle would \
             then pass for the wrong reason"
    );
}

#[test]
fn guest_credential_data_tunnel_session_delegates_byte_identical() {
    // Device byte-identity guard (Fase E2.5 serve-core generalization): the
    // DataTunnelSession impl for GuestCredential MUST delegate VERBATIM to the
    // existing slot-derived helpers, so a Device TunnelAck's session_id +
    // mesh_ipv6 are byte-identical before/after generalizing the serve core
    // over the trait. The trait method == the free function, and the exact
    // bytes for SLOT = [0x22;16] are pinned so any drift on either path fails.
    let cred = credential("claw_test", guest().public());
    assert_eq!(cred.session_id(), derive_session_id(&cred));
    assert_eq!(cred.mesh_ipv6(), derive_mesh_ipv6(&cred));
    assert_eq!(cred.session_id(), "22222222222222222222222222222222");
    assert_eq!(cred.mesh_ipv6(), "fd00:c1aw::2222:2222");
    assert!(
        !cred.allows_persistent_targets(),
        "Device credentials must retain the legacy single-target protocol"
    );
}

/// Slot store with `SLOT` open then consumed by `guest`, for `claw_test`.
fn consumed_store(claw_id: &str) -> ClawShareSlotStore {
    let store = ClawShareSlotStore::new();
    store
        .insert(SlotRecord {
            slot_id: SLOT,
            claw_id: claw_id.to_string(),
            expires_at: EXPIRES,
            state: SlotState::Open,
            app_presentation: None,
            created_at: None,
        })
        .unwrap();
    store
        .consume_atomic(&SLOT, claw_id, guest().public(), ISSUED + 1)
        .unwrap();
    store
}

#[test]
fn accepts_valid_credential() {
    let store = consumed_store("claw_test");
    assert!(
        authorize_credential(
            &credential("claw_test", guest().public()),
            &engine_hh(),
            &store,
            NOW
        )
        .is_ok()
    );
}

#[test]
fn rejects_expired_credential() {
    let store = consumed_store("claw_test");
    let err = authorize_credential(
        &credential("claw_test", guest().public()),
        &engine_hh(),
        &store,
        EXPIRES + 1,
    )
    .unwrap_err();
    assert!(
        matches!(err, DataTunnelError::Rejected(_)),
        "expired must be rejected: {err:?}"
    );
}

#[test]
fn rejects_revoked_slot() {
    let store = consumed_store("claw_test");
    store.revoke(&SLOT, NOW).unwrap();
    let err = authorize_credential(
        &credential("claw_test", guest().public()),
        &engine_hh(),
        &store,
        NOW,
    )
    .unwrap_err();
    assert_eq!(err, DataTunnelError::Rejected("slot-revoked".into()));
}

#[test]
fn rejects_wrong_claw() {
    // Slot is for `claw_test`; the credential names a different claw.
    let store = consumed_store("claw_test");
    let err = authorize_credential(
        &credential("claw_evil", guest().public()),
        &engine_hh(),
        &store,
        NOW,
    )
    .unwrap_err();
    assert_eq!(
        err,
        DataTunnelError::Rejected("claw-binding-mismatch".into())
    );
}

#[test]
fn rejects_wrong_household() {
    let store = consumed_store("claw_test");
    let other_hh = derive_household_id(
        &P256Keypair::from_secret_scalar(&[0x77; 32])
            .unwrap()
            .public(),
    );
    let err = authorize_credential(
        &credential("claw_test", guest().public()),
        &other_hh,
        &store,
        NOW,
    )
    .unwrap_err();
    assert_eq!(err, DataTunnelError::Rejected("household-mismatch".into()));
}

#[test]
fn rejects_other_device_credential_for_consumed_slot() {
    // Slot consumed by `guest`; a credential for a DIFFERENT device key.
    let store = consumed_store("claw_test");
    let other_device = P256Keypair::from_secret_scalar(&[0x44; 32])
        .unwrap()
        .public();
    let err = authorize_credential(
        &credential("claw_test", other_device),
        &engine_hh(),
        &store,
        NOW,
    )
    .unwrap_err();
    assert_eq!(
        err,
        DataTunnelError::Rejected("guest-device-mismatch".into())
    );
}

// ─── Proof-of-possession (unit) ──────────────────────────────────────

use std::sync::Arc;

fn token_full(
    cred_cbor: &[u8],
    signer: &P256Keypair,
    target_id: &str,
    nonce: &[u8],
) -> SessionAuthToken {
    SessionAuthToken::sign(
        "sess-test".into(),
        cred_cbor,
        "127.0.0.1:7423".into(),
        target_id.into(),
        nonce.to_vec(),
        NOW + 60,
        signer,
    )
    .expect("sign token")
}

fn cred_cbor() -> Vec<u8> {
    cbor::to_canonical_vec(&credential("claw_test", guest().public())).unwrap()
}

fn valid_token(nonce: &[u8]) -> SessionAuthToken {
    token_full(&cred_cbor(), &guest(), "claw_test", nonce)
}

fn envelope_with(token: SessionAuthToken) -> AuthEnvelope {
    AuthEnvelope {
        credential_cbor: cred_cbor(),
        token,
    }
}

#[test]
fn session_accepts_valid_credential_and_token() {
    let store = consumed_store("claw_test");
    let env = envelope_with(valid_token(b"n1"));
    assert!(authorize_session(&env, &engine_hh(), &store, &ReplayGuard::new(), NOW).is_ok());
}

#[test]
fn stolen_credential_with_token_from_other_device_is_rejected() {
    let store = consumed_store("claw_test");
    let attacker = P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap();
    let env = envelope_with(token_full(&cred_cbor(), &attacker, "claw_test", b"n1"));
    let err = authorize_session(&env, &engine_hh(), &store, &ReplayGuard::new(), NOW).unwrap_err();
    assert_eq!(
        err,
        DataTunnelError::TokenRejected("signature-invalid".into())
    );
}

#[test]
fn expired_token_is_rejected() {
    let store = consumed_store("claw_test");
    let token = SessionAuthToken::sign(
        "s".into(),
        &cred_cbor(),
        "e".into(),
        "claw_test".into(),
        b"n1".to_vec(),
        NOW - 1,
        &guest(),
    )
    .unwrap();
    let err = authorize_session(
        &envelope_with(token),
        &engine_hh(),
        &store,
        &ReplayGuard::new(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err, DataTunnelError::TokenRejected("token-expired".into()));
}

#[test]
fn token_for_other_target_is_rejected() {
    // Token minted for a different claw — must not open this one.
    let store = consumed_store("claw_test");
    let token = token_full(&cred_cbor(), &guest(), "claw_other", b"n1");
    let err = authorize_session(
        &envelope_with(token),
        &engine_hh(),
        &store,
        &ReplayGuard::new(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(
        err,
        DataTunnelError::TokenRejected("target-mismatch".into())
    );
}

#[test]
fn replayed_token_is_rejected() {
    let store = consumed_store("claw_test");
    let guard = ReplayGuard::new();
    let env = envelope_with(valid_token(b"once"));
    assert!(authorize_session(&env, &engine_hh(), &store, &guard, NOW).is_ok());
    // Same nonce again → replay.
    let err = authorize_session(&env, &engine_hh(), &store, &guard, NOW).unwrap_err();
    assert_eq!(err, DataTunnelError::TokenRejected("token-replayed".into()));
}

#[test]
fn session_rejects_revoked_even_with_valid_token() {
    let store = consumed_store("claw_test");
    store.revoke(&SLOT, NOW).unwrap();
    let env = envelope_with(valid_token(b"n1"));
    let err = authorize_session(&env, &engine_hh(), &store, &ReplayGuard::new(), NOW).unwrap_err();
    assert_eq!(err, DataTunnelError::Rejected("slot-revoked".into()));
}

// ─── Persistent stream (wire) ────────────────────────────────────────

/// A fake interactive target: on connect it sends a banner, then for
/// every line it receives it replies `ACK:<line>`. Proves a PERSISTENT
/// bidirectional stream (unsolicited banner + multiple request/replies
/// on the same connection).
async fn spawn_banner_target() -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut sock, _) = target.accept().await.unwrap();
        sock.write_all(b"FAKE-SSH-BANNER").await.unwrap();
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
        }
    });
    addr
}

/// A request/response target that closes each accepted TCP connection.
/// Two accepts prove that the data-tunnel can reopen a fresh ClawSite
/// backend without repeating rendezvous, Noise, or auth.
async fn spawn_two_request_target() -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        for index in 1..=2 {
            let (mut sock, _) = target.accept().await.unwrap();
            let mut request = vec![0_u8; 1024];
            let n = sock.read(&mut request).await.unwrap();
            assert!(n > 0, "request {index} must reach the target");
            sock.write_all(format!("response-{index}").as_bytes())
                .await
                .unwrap();
            sock.shutdown().await.unwrap();
        }
    });
    addr
}

/// Two keep-alive-style request targets. Each accepted target stays open
/// after its response until the data-tunnel explicitly closes it. This
/// pins the opposite lifecycle ordering from `spawn_two_request_target`:
/// client-close first rather than target-EOF first.
async fn spawn_two_keepalive_targets() -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        for index in 1..=2 {
            let (mut sock, _) = target.accept().await.unwrap();
            let mut request = vec![0_u8; 1024];
            let n = sock.read(&mut request).await.unwrap();
            assert!(n > 0, "request {index} must reach the target");
            sock.write_all(format!("response-{index}").as_bytes())
                .await
                .unwrap();
            let mut drain = [0_u8; 1];
            assert_eq!(
                sock.read(&mut drain).await.unwrap(),
                0,
                "target {index} must remain open until the client closes it"
            );
        }
    });
    addr
}

fn spawn_engine(
    store: Arc<ClawShareSlotStore>,
    target_addr: String,
    guard: Arc<ReplayGuard>,
) -> std::net::SocketAddr {
    let hh = engine_hh();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let router = TcpStreamRouter::new(target_addr);
        let rev_store = store.clone();
        let _ = serve_connection(
            sock,
            NOW,
            move |e, n| authorize_session(e, &hh, &store, &guard, n),
            &router,
            move |cred| {
                matches!(
                    rev_store.get(&cred.slot_id).map(|r| r.state),
                    Some(SlotState::Revoked { .. })
                )
            },
        )
        .await;
    });
    addr
}

struct PersistentTestSession(GuestCredential);

impl DataTunnelSession for PersistentTestSession {
    fn session_id(&self) -> String {
        self.0.session_id()
    }

    fn mesh_ipv6(&self) -> String {
        self.0.mesh_ipv6()
    }

    fn allows_persistent_targets(&self) -> bool {
        true
    }
}

fn spawn_persistent_engine_with_router<R>(
    store: Arc<ClawShareSlotStore>,
    guard: Arc<ReplayGuard>,
    router: R,
) -> std::net::SocketAddr
where
    R: ClawTargetRouter + Send + Sync + 'static,
{
    let hh = engine_hh();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let rev_store = Arc::clone(&store);
        let _ = serve_connection_io_with_auth_deadline(
            sock,
            NOW,
            move |e, n| authorize_session(e, &hh, &store, &guard, n).map(PersistentTestSession),
            &router,
            move |session: &PersistentTestSession| {
                matches!(
                    rev_store.get(&session.0.slot_id).map(|r| r.state),
                    Some(SlotState::Revoked { .. })
                )
            },
            DEFAULT_AUTH_DEADLINE,
        )
        .await;
    });
    addr
}

fn spawn_persistent_engine(
    store: Arc<ClawShareSlotStore>,
    target_addr: String,
    guard: Arc<ReplayGuard>,
) -> std::net::SocketAddr {
    spawn_persistent_engine_with_router(store, guard, TcpStreamRouter::new(target_addr))
}

struct ImmediateCloseRouter {
    opens: Arc<std::sync::atomic::AtomicU32>,
}

impl ClawTargetRouter for ImmediateCloseRouter {
    async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
        self.opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (stream, peer) = tokio::io::duplex(1);
        drop(peer);
        let (reader, writer) = tokio::io::split(stream);
        Ok(TargetSession {
            reader: Box::new(reader),
            writer: Box::new(writer),
            resize: Box::new(|_, _| Ok(())),
            exit: Box::pin(std::future::ready(TargetExit::Code(0))),
            vpn_mesh_ipv4: None,
        })
    }
}

struct DrainRouter;

impl ClawTargetRouter for DrainRouter {
    async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
        use tokio::io::AsyncReadExt as _;
        let (stream, mut peer) = tokio::io::duplex(MAX_FRAME_LEN * 2);
        tokio::spawn(async move {
            let mut buf = vec![0_u8; MAX_FRAME_LEN];
            while peer.read(&mut buf).await.is_ok_and(|n| n > 0) {}
        });
        Ok(TargetSession::from_stream(stream))
    }
}

struct FloodRouter;

impl ClawTargetRouter for FloodRouter {
    async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
        use tokio::io::AsyncWriteExt as _;
        let (stream, mut peer) = tokio::io::duplex(STREAM_READ_CHUNK * 2);
        tokio::spawn(async move {
            let chunk = vec![0xa5; STREAM_READ_CHUNK];
            let full_chunks = PERSISTENT_MAX_BYTES_PER_DIRECTION / STREAM_READ_CHUNK as u64;
            for _ in 0..full_chunks {
                peer.write_all(&chunk).await.unwrap();
            }
            let remainder = PERSISTENT_MAX_BYTES_PER_DIRECTION % STREAM_READ_CHUNK as u64;
            if remainder > 0 {
                peer.write_all(&chunk[..remainder as usize]).await.unwrap();
            }
            peer.write_all(&[0xa5]).await.unwrap();
        });
        Ok(TargetSession::from_stream(stream))
    }
}

async fn serve_with_short_auth_deadline<S>(
    stream: S,
    deadline: Duration,
) -> Result<(), DataTunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let store = Arc::new(consumed_store("claw_test"));
    let hh = engine_hh();
    let guard = Arc::new(ReplayGuard::new());
    let router = TcpStreamRouter::new("127.0.0.1:1");
    let rev_store = Arc::clone(&store);
    serve_connection_io_with_auth_deadline(
        stream,
        NOW,
        move |e, n| authorize_session(e, &hh, &store, &guard, n),
        &router,
        move |cred| {
            matches!(
                rev_store.get(&cred.slot_id).map(|r| r.state),
                Some(SlotState::Revoked { .. })
            )
        },
        deadline,
    )
    .await
}

#[tokio::test]
async fn auth_deadline_times_out_when_peer_sends_no_auth() {
    let (server, _client) = tokio::io::duplex(64);

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        serve_with_short_auth_deadline(server, std::time::Duration::from_millis(50)),
    )
    .await
    .unwrap();

    assert_eq!(result.unwrap_err(), DataTunnelError::AuthTimeout);
}

#[tokio::test]
async fn auth_deadline_does_not_reset_for_partial_auth_frame() {
    let (server, mut client) = tokio::io::duplex(64);
    let server_task = tokio::spawn(serve_with_short_auth_deadline(
        server,
        std::time::Duration::from_millis(50),
    ));

    client.write_all(&[0x00, 0x00]).await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.unwrap_err(), DataTunnelError::AuthTimeout);
}

#[tokio::test]
async fn persistent_stream_carries_multiple_frames_both_ways() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_engine(
        store,
        spawn_banner_target().await,
        Arc::new(ReplayGuard::new()),
    );

    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert!(matches!(
        client_authenticate(&mut client, &cbor, valid_token(b"n1"))
            .await
            .unwrap(),
        TunnelAck::Ok { .. }
    ));
    assert_eq!(
        client_health(&mut client, HEALTH_PROBE).await.unwrap(),
        HEALTH_PROBE
    );

    // Open the persistent stream; the target's banner arrives first.
    client_open_stream(&mut client).await.unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"FAKE-SSH-BANNER".to_vec())
    );

    // Multiple request/replies on the SAME session — persistent.
    for line in [
        b"ls\n".as_slice(),
        b"pwd\n".as_slice(),
        b"whoami\n".as_slice(),
    ] {
        send_frame(&mut client, &TunnelFrame::Data(line.to_vec()))
            .await
            .unwrap();
        let mut expected = b"ACK:".to_vec();
        expected.extend_from_slice(line);
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(expected)
        );
    }

    send_frame(&mut client, &TunnelFrame::Close).await.unwrap();
}

#[tokio::test]
async fn persistent_connection_reopens_two_sequential_target_streams() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_persistent_engine(
        store,
        spawn_two_request_target().await,
        Arc::new(ReplayGuard::new()),
    );

    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(&mut client, &cbor, valid_token(b"persistent-reopen"))
        .await
        .unwrap();

    for index in 1..=2 {
        client_open_persistent_stream(&mut client).await.unwrap();
        send_frame(
            &mut client,
            &TunnelFrame::Data(format!("request-{index}").into_bytes()),
        )
        .await
        .unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Data(format!("response-{index}").into_bytes())
        );
        assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);
    }
}

#[tokio::test]
async fn persistent_close_retry_after_target_race_is_idempotent_and_does_not_poison_next_open() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_persistent_engine(
        store,
        spawn_two_keepalive_targets().await,
        Arc::new(ReplayGuard::new()),
    );

    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(
        &mut client,
        &cbor,
        valid_token(b"persistent-idempotent-close"),
    )
    .await
    .unwrap();

    client_open_persistent_stream(&mut client).await.unwrap();
    send_frame(&mut client, &TunnelFrame::Data(b"request-1".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"response-1".to_vec())
    );

    // The first Close ends target 1 and produces exactly one Close ack.
    // The second models the legitimate race where the target had already
    // reached EOF and the client independently closes the same target.
    // It must be ignored in pre-stream state and must not produce a second
    // ack that could poison target 2.
    send_frame(&mut client, &TunnelFrame::Close).await.unwrap();
    send_frame(&mut client, &TunnelFrame::Close).await.unwrap();
    assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);

    client_open_persistent_stream(&mut client).await.unwrap();
    send_frame(&mut client, &TunnelFrame::Data(b"request-2".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"response-2".to_vec()),
        "a duplicate Close must not leave a stale ack ahead of target 2"
    );
    send_frame(&mut client, &TunnelFrame::Close).await.unwrap();
    assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);
}

#[tokio::test]
async fn device_session_rejects_persistent_target_before_backend_open() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_engine(
        store,
        "127.0.0.1:1".to_string(),
        Arc::new(ReplayGuard::new()),
    );

    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(
        &mut client,
        &cred_cbor(),
        valid_token(b"device-persistent-denied"),
    )
    .await
    .unwrap();
    let denied = client_open_persistent_stream(&mut client)
        .await
        .unwrap_err();
    assert_eq!(
        denied,
        DataTunnelError::TargetUnavailable("persistent-target-not-authorized".into())
    );
}

#[tokio::test]
async fn persistent_mode_rejects_legacy_open_downgrade() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_persistent_engine(
        store,
        spawn_two_request_target().await,
        Arc::new(ReplayGuard::new()),
    );

    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(
        &mut client,
        &cred_cbor(),
        valid_token(b"persistent-no-downgrade"),
    )
    .await
    .unwrap();
    client_open_persistent_stream(&mut client).await.unwrap();
    send_frame(&mut client, &TunnelFrame::Data(b"request-1".to_vec()))
        .await
        .unwrap();
    assert!(matches!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(_)
    ));
    assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);

    send_frame(&mut client, &TunnelFrame::Open).await.unwrap();
    assert!(
        recv_frame(&mut client).await.is_err(),
        "persistent mode must not silently downgrade to legacy Open"
    );
}

#[tokio::test]
async fn persistent_open_budget_rejects_129th_before_target_allocation() {
    let store = Arc::new(consumed_store("claw_test"));
    let opens = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let addr = spawn_persistent_engine_with_router(
        store,
        Arc::new(ReplayGuard::new()),
        ImmediateCloseRouter {
            opens: Arc::clone(&opens),
        },
    );

    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(
        &mut client,
        &cred_cbor(),
        valid_token(b"persistent-open-budget"),
    )
    .await
    .unwrap();

    for index in 1..=PERSISTENT_MAX_TARGET_OPENS {
        client_open_persistent_stream(&mut client).await.unwrap();
        assert_eq!(
            recv_frame(&mut client).await.unwrap(),
            TunnelFrame::Exit(TargetExit::Code(0)),
            "target {index} must close normally"
        );
        assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);
    }

    let exhausted = client_open_persistent_stream(&mut client)
        .await
        .unwrap_err();
    assert_eq!(
        exhausted,
        DataTunnelError::TargetUnavailable("session-open-budget-exhausted".into())
    );
    assert_eq!(
        opens.load(std::sync::atomic::Ordering::SeqCst),
        PERSISTENT_MAX_TARGET_OPENS,
        "the rejected 129th open must allocate no target"
    );
}

#[tokio::test]
async fn persistent_revocation_blocks_second_open_before_target_allocation() {
    // §3 baseline item 4 / §7.1: "before every new persistent target
    // open" must be a PINNED ordering property, not an accident of the
    // 500 ms revoke-poll interval. A test that only observes the client
    // eventually seeing an error cannot tell "the fence ran before
    // `router.open`" (correct) apart from "the fence ran after
    // `router.open`, but something else — the poll, or the next Data
    // check — tore the session down anyway" (a real regression that
    // would still look green). `ImmediateCloseRouter`'s open counter
    // makes the two distinguishable: if the fence ever moves after
    // `router.open`, this test goes red because `opens` reaches 2, even
    // though the client-observed outcome (rejection) looks unchanged.
    let store = Arc::new(consumed_store("claw_test"));
    let opens = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let addr = spawn_persistent_engine_with_router(
        Arc::clone(&store),
        Arc::new(ReplayGuard::new()),
        ImmediateCloseRouter {
            opens: Arc::clone(&opens),
        },
    );

    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(
        &mut client,
        &cred_cbor(),
        valid_token(b"persistent-revocation-ordering"),
    )
    .await
    .unwrap();

    // Target #1: opens and closes normally, exactly once.
    client_open_persistent_stream(&mut client).await.unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Exit(TargetExit::Code(0))
    );
    assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Revoke between the two opens, then ask for target #2. The fence
    // returns before sending any frame (unlike a `router.open` failure,
    // which does send `TunnelFrame::Error` first) — the connection is
    // simply dropped, so the client observes EOF here, matching the
    // `is_err()`-only assertion already used by the sibling tests
    // (`revoking_during_health_wait_blocks_open_before_the_target_is_opened`
    // and the responder-level
    // `relay_stream_responder_device_clawsite_revocation_blocks_next_persistent_open`).
    store.revoke(&SLOT, NOW).unwrap();
    assert!(
        client_open_persistent_stream(&mut client).await.is_err(),
        "revocation between persistent targets must reject the second open"
    );

    // The pin: `router.open` must never have run a second time. A
    // count of 2 here means the fence ran too late — the target was
    // already allocated before the rejection reached the client.
    assert_eq!(
        opens.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "revocation must block the second open before target allocation, not just \
             eventually close the connection"
    );
}

#[tokio::test]
async fn persistent_upload_budget_accepts_exact_boundary_and_rejects_one_more_byte() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr =
        spawn_persistent_engine_with_router(store, Arc::new(ReplayGuard::new()), DrainRouter);

    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(
        &mut client,
        &cred_cbor(),
        valid_token(b"persistent-byte-budget"),
    )
    .await
    .unwrap();
    client_open_persistent_stream(&mut client).await.unwrap();

    let chunk_len = MAX_FRAME_LEN - 1;
    let full_chunks = PERSISTENT_MAX_BYTES_PER_DIRECTION / chunk_len as u64;
    let remainder = PERSISTENT_MAX_BYTES_PER_DIRECTION % chunk_len as u64;
    let chunk = vec![0x5a; chunk_len];
    for _ in 0..full_chunks {
        send_frame(&mut client, &TunnelFrame::Data(chunk.clone()))
            .await
            .unwrap();
    }
    if remainder > 0 {
        send_frame(
            &mut client,
            &TunnelFrame::Data(vec![0x5a; remainder as usize]),
        )
        .await
        .unwrap();
    }

    send_frame(&mut client, &TunnelFrame::Data(vec![0x5a]))
        .await
        .unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Error("session-byte-budget-exhausted".into())
    );
}

#[tokio::test]
async fn persistent_download_budget_accepts_exact_boundary_and_rejects_one_more_byte() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr =
        spawn_persistent_engine_with_router(store, Arc::new(ReplayGuard::new()), FloodRouter);

    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(
        &mut client,
        &cred_cbor(),
        valid_token(b"persistent-download-budget"),
    )
    .await
    .unwrap();
    client_open_persistent_stream(&mut client).await.unwrap();

    let mut received = 0_u64;
    loop {
        match recv_frame(&mut client).await.unwrap() {
            TunnelFrame::Data(bytes) => {
                received = received.saturating_add(bytes.len() as u64);
            }
            TunnelFrame::Error(reason) => {
                assert_eq!(reason, "session-byte-budget-exhausted");
                break;
            }
            frame => panic!("unexpected frame at download boundary: {frame:?}"),
        }
    }
    assert_eq!(received, PERSISTENT_MAX_BYTES_PER_DIRECTION);
}

#[tokio::test]
async fn revocation_between_persistent_targets_blocks_the_next_open() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_persistent_engine(
        Arc::clone(&store),
        spawn_two_request_target().await,
        Arc::new(ReplayGuard::new()),
    );

    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(
        &mut client,
        &cbor,
        valid_token(b"persistent-revoke-between"),
    )
    .await
    .unwrap();
    client_open_persistent_stream(&mut client).await.unwrap();
    send_frame(&mut client, &TunnelFrame::Data(b"request-1".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"response-1".to_vec())
    );
    assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);

    store.revoke(&SLOT, NOW).unwrap();
    send_frame(&mut client, &TunnelFrame::OpenPersistent)
        .await
        .unwrap();
    let after = recv_frame(&mut client).await;
    assert!(
        after.is_err(),
        "revocation between targets must close before a second backend opens: {after:?}"
    );
}

#[tokio::test]
async fn target_close_propagates_to_client() {
    use tokio::io::AsyncWriteExt;
    // Target sends a banner then closes immediately.
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut sock, _) = target.accept().await.unwrap();
        sock.write_all(b"BYE").await.unwrap();
        drop(sock); // close
    });

    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_engine(store, target_addr, Arc::new(ReplayGuard::new()));
    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(&mut client, &cbor, valid_token(b"n1"))
        .await
        .unwrap();
    client_open_stream(&mut client).await.unwrap();

    // Banner, then Close.
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"BYE".to_vec())
    );
    assert_eq!(recv_frame(&mut client).await.unwrap(), TunnelFrame::Close);
}

#[tokio::test]
async fn revoking_slot_mid_session_blocks_next_frame() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_engine(
        store.clone(),
        spawn_banner_target().await,
        Arc::new(ReplayGuard::new()),
    );

    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(&mut client, &cbor, valid_token(b"n1"))
        .await
        .unwrap();
    client_open_stream(&mut client).await.unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"FAKE-SSH-BANNER".to_vec())
    );

    // Revoke mid-session; the next data frame must be blocked + the
    // session torn down (client sees EOF/close).
    store.revoke(&SLOT, NOW).unwrap();
    send_frame(&mut client, &TunnelFrame::Data(b"ls\n".to_vec()))
        .await
        .unwrap();
    // The engine stops forwarding and drops the session → the client's
    // next read sees the closed tunnel.
    let after = recv_frame(&mut client).await;
    assert!(
        after.is_err(),
        "session must be torn down after revocation, got {after:?}"
    );
}

#[tokio::test]
async fn revoking_during_health_wait_blocks_open_before_the_target_is_opened() {
    // The Health→Open window: a client may sit in the Health loop for as
    // long as it likes, so authorization can lapse in between. Before the
    // pre-`router.open` fence, the first `is_revoked` call happened only on
    // the per-`Data` path — i.e. AFTER the target had been opened and the
    // Open-ack (and, on the IpTunnel path, `NetworkSettings` carrying a real
    // pool-allocated address) had already been sent.
    //
    // Here the slot is revoked while the client is still in Health. The
    // engine must refuse at Open and never reach the target, so the client
    // sees the tunnel close INSTEAD of an Open-ack.
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_engine(
        store.clone(),
        spawn_banner_target().await,
        Arc::new(ReplayGuard::new()),
    );

    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(&mut client, &cbor, valid_token(b"n-health-revoke"))
        .await
        .unwrap();

    // Still pre-Open: exercise the Health loop, proving the session is live
    // and simply waiting.
    client_health(&mut client, HEALTH_PROBE).await.unwrap();

    // Authorization lapses in the window.
    store.revoke(&SLOT, NOW).unwrap();

    // Now ask to Open. The fence must reject before `router.open`.
    send_frame(&mut client, &TunnelFrame::Open).await.unwrap();

    let after = recv_frame(&mut client).await;
    assert!(
        after.is_err(),
        "Open after revocation must be refused before the target is opened, got {after:?}"
    );
}

#[tokio::test]
async fn revoking_idle_session_tears_down_without_client_traffic() {
    // The cold-5G idle revocation gate: an interactive session that is
    // simply QUIET (no inbound Data frames — the iPhone bridge only emits a
    // no-op Window keepalive) must STILL be cut promptly when the slot is
    // revoked. Before the revoke-poll branch, is_revoked was only consulted
    // on inbound Data, so an idle session lingered until the next keystroke.
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_engine(
        store.clone(),
        spawn_banner_target().await,
        Arc::new(ReplayGuard::new()),
    );

    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(&mut client, &cbor, valid_token(b"n1"))
        .await
        .unwrap();
    client_open_stream(&mut client).await.unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"FAKE-SSH-BANNER".to_vec())
    );

    // Revoke, then send NOTHING. The idle revocation poll must tear the
    // session down on its own — and within the <2s SLA — not wait for a
    // client frame. The client's next read must see the closed tunnel.
    store.revoke(&SLOT, NOW).unwrap();
    match tokio::time::timeout(std::time::Duration::from_secs(2), recv_frame(&mut client)).await {
        Ok(res) => assert!(
            res.is_err(),
            "idle session must be torn down after revoke, got {res:?}"
        ),
        Err(_) => {
            panic!("idle session NOT torn down within 2s of revoke (idle-revoke <2s gate)")
        }
    }
}

#[tokio::test]
async fn replayed_token_rejected_over_the_wire() {
    let guard = Arc::new(ReplayGuard::new());
    let store = Arc::new(consumed_store("claw_test"));
    let cbor = cred_cbor();

    // First connection with nonce "once" succeeds.
    let addr1 = spawn_engine(store.clone(), spawn_banner_target().await, guard.clone());
    let mut c1 = TcpStream::connect(addr1).await.unwrap();
    assert!(matches!(
        client_authenticate(&mut c1, &cbor, valid_token(b"once"))
            .await
            .unwrap(),
        TunnelAck::Ok { .. }
    ));

    // Second connection reusing the SAME token nonce → rejected.
    let addr2 = spawn_engine(store, spawn_banner_target().await, guard);
    let mut c2 = TcpStream::connect(addr2).await.unwrap();
    match client_authenticate(&mut c2, &cbor, valid_token(b"once"))
        .await
        .unwrap()
    {
        TunnelAck::Rejected { reason } => assert_eq!(reason, "token-replayed"),
        other => panic!("replayed token must be rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn invalid_frame_before_open_tears_down_session() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_engine(
        store,
        spawn_banner_target().await,
        Arc::new(ReplayGuard::new()),
    );
    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert!(matches!(
        client_authenticate(&mut client, &cbor, valid_token(b"n1"))
            .await
            .unwrap(),
        TunnelAck::Ok { .. }
    ));
    // Unknown frame kind before opening the stream.
    write_frame(&mut client, &[0xFF, 0x01]).await.unwrap();
    let after = recv_frame(&mut client).await;
    assert!(after.is_err(), "unknown frame must tear down the session");
}

#[tokio::test]
async fn revoked_at_auth_is_rejected_over_the_wire() {
    let store = Arc::new(consumed_store("claw_test"));
    store.revoke(&SLOT, NOW).unwrap();
    let addr = spawn_engine(
        store,
        spawn_banner_target().await,
        Arc::new(ReplayGuard::new()),
    );
    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    match client_authenticate(&mut client, &cbor, valid_token(b"n1"))
        .await
        .unwrap()
    {
        TunnelAck::Rejected { reason } => assert_eq!(reason, "slot-revoked"),
        other => panic!("revoked slot must be rejected at auth, got {other:?}"),
    }
}

// ─── Interactive frames (resize / exit) ──────────────────────────────

#[test]
fn tunnel_frame_debug_redacts_payloads() {
    let data_debug = format!("{:?}", TunnelFrame::Data(b"SECRET-PACKET-DATA!!".to_vec()));
    assert!(data_debug.contains("Data"));
    assert!(data_debug.contains("<redacted>"));
    assert!(data_debug.contains("len: 20"));
    assert!(!data_debug.contains("SECRET-PACKET-DATA"));
    assert!(!data_debug.contains("83, 69, 67, 82, 69, 84"));

    let health_debug = format!("{:?}", TunnelFrame::Health(b"SECRET-HEALTH".to_vec()));
    assert!(health_debug.contains("Health"));
    assert!(health_debug.contains("<redacted>"));
    assert!(health_debug.contains("len: 13"));
    assert!(!health_debug.contains("SECRET-HEALTH"));
    assert!(!health_debug.contains("83, 69, 67, 82, 69, 84"));

    let error_debug = format!(
        "{:?}",
        TunnelFrame::Error("SECRET-TARGET-ERROR".to_string())
    );
    assert!(error_debug.contains("Error"));
    assert!(error_debug.contains("<redacted>"));
    assert!(error_debug.contains("len: 19"));
    assert!(!error_debug.contains("SECRET-TARGET-ERROR"));

    let resize_debug = format!(
        "{:?}",
        TunnelFrame::Resize {
            cols: 120,
            rows: 40
        }
    );
    assert!(resize_debug.contains("cols"));
    assert!(resize_debug.contains("rows"));
}

#[test]
fn resize_frame_round_trips() {
    let f = TunnelFrame::Resize {
        cols: 120,
        rows: 40,
    };
    assert_eq!(TunnelFrame::decode(&f.encode()).unwrap(), f);
    // Boundary values.
    let f0 = TunnelFrame::Resize { cols: 0, rows: 0 };
    assert_eq!(TunnelFrame::decode(&f0.encode()).unwrap(), f0);
    let fmax = TunnelFrame::Resize {
        cols: u16::MAX,
        rows: u16::MAX,
    };
    assert_eq!(TunnelFrame::decode(&fmax.encode()).unwrap(), fmax);
}

#[test]
fn open_persistent_frame_round_trips() {
    let frame = TunnelFrame::OpenPersistent;
    assert_eq!(frame.encode(), vec![FRAME_OPEN_PERSISTENT]);
    assert_eq!(TunnelFrame::decode(&frame.encode()).unwrap(), frame);
}

#[test]
fn exit_frame_round_trips_all_variants() {
    for status in [
        TargetExit::Code(0),
        TargetExit::Code(127),
        TargetExit::Code(-1),
        TargetExit::Signal(9),
        TargetExit::Lost,
    ] {
        let f = TunnelFrame::Exit(status);
        assert_eq!(
            TunnelFrame::decode(&f.encode()).unwrap(),
            f,
            "exit {status:?}"
        );
    }
}

#[test]
fn malformed_resize_and_exit_frames_are_rejected() {
    // Resize needs exactly 4 payload bytes; Exit needs exactly 5.
    assert!(TunnelFrame::decode(&[FRAME_RESIZE, 0x01]).is_err());
    assert!(TunnelFrame::decode(&[FRAME_EXIT, 0x01, 0x00]).is_err());
    // Unknown exit tag.
    assert!(TunnelFrame::decode(&[FRAME_EXIT, 0x09, 0, 0, 0, 0]).is_err());
}

/// A mid-stream `Resize` is applied (no-op for a raw TCP target) and must
/// NOT disturb the stream: data still round-trips on the same session.
#[tokio::test]
async fn resize_mid_stream_keeps_session_alive() {
    let store = Arc::new(consumed_store("claw_test"));
    let addr = spawn_engine(
        store,
        spawn_banner_target().await,
        Arc::new(ReplayGuard::new()),
    );

    let cbor = cred_cbor();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(&mut client, &cbor, valid_token(b"n1"))
        .await
        .unwrap();
    client_open_stream(&mut client).await.unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"FAKE-SSH-BANNER".to_vec())
    );

    // Resize before and after data — neither breaks the pipe.
    client_resize(&mut client, 100, 30).await.unwrap();
    send_frame(&mut client, &TunnelFrame::Data(b"ls\n".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"ACK:ls\n".to_vec())
    );
    client_resize(&mut client, 80, 24).await.unwrap();
    send_frame(&mut client, &TunnelFrame::Data(b"pwd\n".to_vec()))
        .await
        .unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"ACK:pwd\n".to_vec())
    );
}

// ─── Cancel-safety of the inbound frame reader ──────────────────────────
//
// `read_frame` is two sequential `read_exact` awaits: the 4-byte length
// prefix, then the body. If the future holding it is DROPPED between them,
// the prefix bytes are gone from the socket and the next read interprets
// body bytes as a length — the stream desynchronises. The serve loop's
// `select!` has two sibling arms (`revoke_poll.tick`, `reader.read`) that
// can win at exactly that moment.
//
// Making that deterministic needs an answer to "has the server consumed the
// prefix YET?", which the wire cannot give: a half-read frame produces no
// output to synchronise against. `PrefixProbe` creates that observation
// point inside the test by intercepting `poll_read` on the SERVER endpoint
// and signalling once exactly the prefix has been delivered. No clock, no
// sleep, no production API, no new dependency.

/// Test-only tunnel wrapper that reports when the inbound length prefix has
/// been consumed. Counting is armed by the test so the auth/health/open
/// frames, which also flow through here, are not mistaken for the frame
/// under test.
struct PrefixProbe<S> {
    inner: S,
    armed: Arc<std::sync::atomic::AtomicBool>,
    seen: Arc<std::sync::atomic::AtomicUsize>,
    prefix_consumed: Arc<tokio::sync::Notify>,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixProbe<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::sync::atomic::Ordering;
        let me = self.get_mut();
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut me.inner).poll_read(cx, buf);
        if matches!(polled, std::task::Poll::Ready(Ok(()))) {
            let n = buf.filled().len() - before;
            if n > 0 && me.armed.load(Ordering::SeqCst) {
                let total = me.seen.fetch_add(n, Ordering::SeqCst) + n;
                if total >= 4 {
                    // `notify_one` stores a permit, so the signal is not
                    // lost if the test has not reached its await yet.
                    me.prefix_consumed.notify_one();
                }
            }
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixProbe<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A target that sends a banner on connect, then a second chunk only when
/// the test releases it, then echoes `ACK:<bytes>`. The gated second chunk
/// is what makes the competing `reader.read` arm fire at a moment the test
/// chooses.
async fn spawn_gated_target(release: tokio::sync::oneshot::Receiver<()>) -> String {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = target.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut sock, _) = target.accept().await.unwrap();
        sock.write_all(b"BANNER").await.unwrap();
        if release.await.is_err() {
            return;
        }
        sock.write_all(b"SECOND").await.unwrap();
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
        }
    });
    addr
}

/// `read_frame` must report an orderly close and a frame cut in half as
/// DIFFERENT errors. They used to be one variant, so a reader could not tell
/// the end of an exchange from a stream that lost bytes: `read_exact`
/// reports a shortfall without saying how much it consumed, and both arrived
/// as `Closed("frame")` with identical text.
///
/// All three outcomes are pinned in one test on purpose. Asserting only the
/// boundary case would not show the split has teeth — a change that returned
/// `ClosedAtFrameBoundary` for every shortfall would satisfy that half while
/// making truncation silently acceptable at every caller that treats the
/// softer variant as a clean end.
#[tokio::test]
async fn a_close_between_frames_is_reported_apart_from_a_frame_cut_in_half() {
    // A `Data` frame, not the 1-byte-body `Close`: case 3 has to cut a body
    // in half, which needs a body with a half.
    let mut whole = Vec::new();
    send_frame(&mut whole, &TunnelFrame::Data(b"payload".to_vec()))
        .await
        .unwrap();
    assert!(
        whole.len() > 5,
        "the fixture needs a body of at least 2 bytes for case 3 to cut one, got {} byte(s)",
        whole.len(),
    );

    // 1. EOF with nothing of the next frame consumed — a frame boundary.
    let mut at_boundary = whole.as_slice();
    recv_frame(&mut at_boundary)
        .await
        .expect("the whole frame reads back");
    assert_eq!(
        recv_frame(&mut at_boundary).await.unwrap_err(),
        DataTunnelError::ClosedAtFrameBoundary("frame"),
        "a peer that stops between frames ended the exchange; it did not cut it",
    );

    // 2. EOF inside the 4-byte length prefix — NOT a boundary.
    let mut partial_prefix = &whole[..2];
    assert_eq!(
        recv_frame(&mut partial_prefix).await.unwrap_err(),
        DataTunnelError::Closed("frame"),
        "a length prefix that arrived in pieces is a cut stream, not an orderly close",
    );

    // 3. EOF inside the body, prefix complete — NOT a boundary.
    let mut partial_body = &whole[..whole.len() - 1];
    assert_eq!(
        recv_frame(&mut partial_body).await.unwrap_err(),
        DataTunnelError::Closed("frame"),
        "a body cut short is a cut stream, not an orderly close",
    );
}

/// A sibling `select!` arm winning while the inbound reader sits BETWEEN the
/// length prefix and the body must not cost the connection its framing.
///
/// Causality is enforced, not assumed: the test only fires the competing arm
/// after `PrefixProbe` has reported that exactly the prefix was consumed, so
/// the interleaving under test is the one that actually occurs. Every wait
/// is bounded and a lapsed bound fails the test as INCONCLUSIVE rather than
/// passing — a timeout is not evidence of either behaviour.
#[tokio::test]
async fn sibling_select_arm_cannot_desync_a_partially_read_frame() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    const BOUND: Duration = Duration::from_secs(10);

    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let target_addr = spawn_gated_target(release_rx).await;

    let armed = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicUsize::new(0));
    let prefix_consumed = Arc::new(tokio::sync::Notify::new());

    let (server_raw, mut client) = tokio::io::duplex(64 * 1024);
    let server = PrefixProbe {
        inner: server_raw,
        armed: Arc::clone(&armed),
        seen: Arc::clone(&seen),
        prefix_consumed: Arc::clone(&prefix_consumed),
    };

    let store = Arc::new(consumed_store("claw_test"));
    let hh = engine_hh();
    let guard = Arc::new(ReplayGuard::new());
    let rev_store = Arc::clone(&store);
    tokio::spawn(async move {
        let router = TcpStreamRouter::new(target_addr);
        serve_connection_io(
            server,
            NOW,
            move |e, n| authorize_session(e, &hh, &store, &guard, n),
            &router,
            move |cred| {
                matches!(
                    rev_store.get(&cred.slot_id).map(|r| r.state),
                    Some(SlotState::Revoked { .. })
                )
            },
        )
        .await
    });

    let cbor = cred_cbor();
    client_authenticate(&mut client, &cbor, valid_token(b"n1"))
        .await
        .unwrap();
    client_open_stream(&mut client).await.unwrap();
    assert_eq!(
        recv_frame(&mut client).await.unwrap(),
        TunnelFrame::Data(b"BANNER".to_vec())
    );

    // Arm only now: the frames above already went through the probe.
    armed.store(true, Ordering::SeqCst);

    // A `Data("PING")` frame, split. `encode()` is [kind][body] = 5 bytes,
    // so the prefix is 5 — the body is withheld, which is what parks the
    // reader between its two `read_exact` calls.
    let body = TunnelFrame::Data(b"PING".to_vec()).encode();
    assert_eq!(
        body.len(),
        5,
        "frame layout changed; the split is no longer mid-frame"
    );
    client
        .write_all(&(u32::try_from(body.len()).unwrap()).to_be_bytes())
        .await
        .unwrap();
    client.flush().await.unwrap();

    // NON-VACUITY: the interleaving only exists if the prefix really landed.
    tokio::time::timeout(BOUND, prefix_consumed.notified())
        .await
        .expect("probe never saw the prefix consumed — the test proves nothing");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        4,
        "probe must have seen exactly the 4 prefix bytes"
    );

    // Now let the competing `reader.read` arm win, with the reader parked
    // mid-frame, and confirm it actually ran by observing its output.
    release_tx.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(BOUND, recv_frame(&mut client))
            .await
            .expect("target chunk never arrived — competing arm did not run")
            .unwrap(),
        TunnelFrame::Data(b"SECOND".to_vec())
    );

    // Deliver the withheld body. Before the fix the prefix is gone, so this
    // is read as a length (0x11504_94E, past MAX_FRAME_LEN) and the
    // connection dies; after it, the frame completes and reaches the target.
    client.write_all(&body).await.unwrap();
    client.flush().await.unwrap();

    let echoed = tokio::time::timeout(BOUND, recv_frame(&mut client))
        .await
        .expect("no verdict within bound — inconclusive, not a pass");
    assert_eq!(
        echoed.unwrap(),
        TunnelFrame::Data(b"ACK:PING".to_vec()),
        "the partially-read frame must survive a sibling arm winning"
    );
}

// ─── 0x17 canonical-form admission ──────────────────────────────────────
//
// The `NetworkSettings` body configures a VPN interface and is consumed
// before any packet pump, so the bytes that reach the typed value must be
// exactly the ones the encoder would have produced. Three malformed shapes
// decode cleanly today: a map whose keys are not in RFC 8949 canonical
// order, a map carrying a key the struct does not model, and a well-formed
// item followed by trailing bytes inside the same length-delimited frame.
//
// Every case asserts BOTH halves. The control — that the LENIENT helper
// still accepts the mutant — is not decoration: without it a passing
// rejection proves nothing, because an unreachable, mistyped or otherwise
// broken fixture also "rejects". The control pins that the bytes really do
// reach a decoder that currently tolerates them, so the rejection is the
// new rule firing and not the fixture failing.
//
// Bodies are built with the crate's own encoders, never from a
// hand-derived hex constant: a hand-written vector would pin my arithmetic
// rather than the encoder's behaviour.

fn network_settings_fixture() -> NetworkSettings {
    // TEST-NET-1 (RFC 5737) documentation addresses only.
    NetworkSettings {
        mesh_ipv4: MeshIpv4 {
            addr: "192.0.2.2".into(),
            prefix_len: 24,
            peer: "192.0.2.3".into(),
        },
        mtu: 1280,
        session_id: "session-alpha_1".into(),
    }
}

fn network_settings_frame(body: &[u8]) -> Vec<u8> {
    let mut framed = vec![FRAME_NETWORK_SETTINGS];
    framed.extend_from_slice(body);
    framed
}

/// The same three fields emitted in DECLARATION order through raw
/// `ciborium`, bypassing the canonicalizing encoder. Declaration order is
/// `mesh_ipv4, mtu, session_id`; canonical order is `mtu, mesh_ipv4,
/// session_id`. The nested `MeshIpv4` is likewise emitted `addr,
/// prefix_len, peer` against a canonical `addr, peer, prefix_len`, so both
/// map levels are non-canonical.
#[derive(Serialize)]
struct NetworkSettingsDeclarationOrder {
    mesh_ipv4: MeshIpv4,
    mtu: u16,
    session_id: String,
}

/// Every modelled field PLUS one the struct does not declare, encoded
/// through the canonicalizing encoder. `unknown_extra` sorts last, so the
/// first three entries keep their canonical order and no trailing bytes
/// exist: the ONLY defect is the extra key.
#[derive(Serialize)]
struct NetworkSettingsUnknownKey {
    mesh_ipv4: MeshIpv4,
    mtu: u16,
    session_id: String,
    unknown_extra: bool,
}

#[test]
// ── S0 relocation notice, for the four 0x17 strictness tests ────────────
//
// These four are X2's, and they are CHANGED by S0 — declared, not hidden.
// They used to assert rejection at `TunnelFrame::decode`, because the strict
// mirrors lived beside the codec and the strictness "could not escape" it.
// S0 had to move the settings struct product-side: it carries a `session_id`
// stamped by the serve loop, and a neutral type may not hold a field whose
// only legitimate producer is an authority.
//
// So the assertion point moves to `decode_network_settings_body`, which is
// now the only public way to interpret a sealed `NetworkSettingsBody`. Every
// mutant and every positive control is preserved byte for byte; only the
// call path changed. The claim "the existing claw tests pass unmodified" is
// therefore NOT made for these four — the frozen wire vectors under
// `tests/data/`, untouched since an earlier commit, carry the byte-identity
// proof instead.
fn network_settings_canonical_body_is_accepted() {
    let settings = network_settings_fixture();
    let body = cbor::to_canonical_vec(&settings).expect("canonical encode");

    // The frame still decodes, and the sealed body still yields the settings
    // through the strict door.
    let frame = TunnelFrame::decode(&network_settings_frame(&body)).expect("frame decodes");
    let TunnelFrame::NetworkSettings(sealed) = frame else {
        panic!("expected a NetworkSettings frame");
    };
    assert_eq!(
        decode_network_settings_body(&sealed).expect("canonical body decodes"),
        settings,
    );
}

/// Helper for the three mutant tests: run a body through the frame and then
/// the strict door, which is where rejection now lives.
fn strict_decode_via_frame(body: &[u8]) -> Result<NetworkSettings, DataTunnelError> {
    let frame = TunnelFrame::decode(&network_settings_frame(body))?;
    let TunnelFrame::NetworkSettings(sealed) = frame else {
        panic!("expected a NetworkSettings frame");
    };
    decode_network_settings_body(&sealed)
}

#[test]
fn network_settings_non_canonical_key_order_is_rejected() {
    let settings = network_settings_fixture();
    let canonical = cbor::to_canonical_vec(&settings).expect("canonical encode");

    let mut body = Vec::new();
    ciborium::ser::into_writer(
        &NetworkSettingsDeclarationOrder {
            mesh_ipv4: settings.mesh_ipv4.clone(),
            mtu: settings.mtu,
            session_id: settings.session_id.clone(),
        },
        &mut body,
    )
    .expect("declaration-order encode");
    assert_ne!(
        body, canonical,
        "fixture is not actually non-canonical — the mutation did nothing"
    );

    // CONTROL: the lenient helper accepts these bytes today.
    assert!(
        cbor::from_canonical_slice::<NetworkSettings>(&body).is_ok(),
        "control failed: lenient decode must still accept the mutant"
    );

    assert!(
        strict_decode_via_frame(&body).is_err(),
        "non-canonical key order must be rejected"
    );
}

#[test]
fn network_settings_unknown_key_is_rejected() {
    let settings = network_settings_fixture();
    let body = cbor::to_canonical_vec(&NetworkSettingsUnknownKey {
        mesh_ipv4: settings.mesh_ipv4.clone(),
        mtu: settings.mtu,
        session_id: settings.session_id.clone(),
        unknown_extra: true,
    })
    .expect("unknown-key encode");

    // CONTROL: the PUBLIC type still ignores the unmodelled key, because
    // the strictness lives on the private wire mirror and not on
    // `NetworkSettings`. This is the load-bearing scope assertion: it
    // fails the moment `deny_unknown_fields` migrates onto the public
    // type and starts binding the dev runner, the bridge and the FFI.
    assert!(
        cbor::from_canonical_slice::<NetworkSettings>(&body).is_ok(),
        "control failed: the public type must NOT carry the 0x17 policy"
    );

    // The strict helper catches an unmodelled key ON ITS OWN, with no
    // `deny_unknown_fields` in play: the key does not survive into the
    // typed value, so the canonical re-encode comes out shorter. The
    // mirror's attribute and the helper genuinely overlap here rather
    // than one silently carrying the other.
    assert!(
        cbor::from_canonical_slice_strict::<NetworkSettings>(&body).is_err(),
        "the strict helper must reject an unmodelled key unaided"
    );

    assert!(
        strict_decode_via_frame(&body).is_err(),
        "an unmodelled key must be rejected"
    );
}

#[test]
fn network_settings_trailing_byte_is_rejected() {
    let settings = network_settings_fixture();
    let mut body = cbor::to_canonical_vec(&settings).expect("canonical encode");
    body.push(0x00);

    // CONTROL: the decoder stops at the end of the item and ignores the
    // rest of the frame today.
    assert!(
        cbor::from_canonical_slice::<NetworkSettings>(&body).is_ok(),
        "control failed: lenient decode must still accept the mutant"
    );

    assert!(
        strict_decode_via_frame(&body).is_err(),
        "trailing bytes inside the frame must be rejected"
    );
}
