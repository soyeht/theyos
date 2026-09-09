#![cfg(test)]

use super::*;
use household_rs::cbor;
use household_rs::claw_share::data_tunnel::{
    HEALTH_PROBE, ReplayGuard, SessionAuthToken, TargetExit, TunnelAck, TunnelFrame,
    client_authenticate, client_health, client_open_stream, client_resize, recv_frame, send_frame,
};
use household_rs::claw_share::{GuestCredential, SLOT_ID_LEN, SlotId, SlotRecord, SlotState};
use household_rs::ids::derive_household_id;
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::person_cert::derive_person_id;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SLOT: SlotId = SlotId([0x22u8; SLOT_ID_LEN]);

fn owner() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
}
fn guest() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap()
}

fn credential() -> GuestCredential {
    let ok = owner();
    let owner_pub = ok.public();
    GuestCredential::sign(
        derive_household_id(&owner_pub),
        derive_person_id(&owner_pub),
        owner_pub,
        "claw_test".to_string(),
        guest().public(),
        SLOT,
        1_800_000_000,
        1_800_086_400,
        &ok,
    )
    .unwrap()
}

fn store() -> Arc<ClawShareSlotStore> {
    let s = ClawShareSlotStore::new();
    s.insert(SlotRecord {
        slot_id: SLOT,
        claw_id: "claw_test".to_string(),
        expires_at: 1_800_086_400,
        state: SlotState::Open,
        app_presentation: None,
        created_at: None,
    })
    .unwrap();
    s.consume_atomic(&SLOT, "claw_test", guest().public(), 1_800_000_001)
        .unwrap();
    Arc::new(s)
}

fn token_signed(cred_cbor: &[u8], signer: &P256Keypair, nonce: &[u8]) -> SessionAuthToken {
    // `serve_conn` verifies against the REAL wall clock (300s max TTL),
    // so the token must expire shortly after *now*.
    SessionAuthToken::sign(
        "s".into(),
        cred_cbor,
        "e".into(),
        "claw_test".into(),
        nonce.to_vec(),
        now_unix() + 60,
        signer,
    )
    .unwrap()
}
fn token(cred_cbor: &[u8]) -> SessionAuthToken {
    token_signed(cred_cbor, &guest(), b"nonce-1")
}

/// A loopback HTTP responder standing in for the claw's ClawSite (which
/// serves the identical static marker page on loopback). Replies the marker
/// HTML to the first request, then closes — exactly what the authed proxy
/// pipes back to the friend's WebView.
async fn spawn_clawsite_target(claw_id: &str) -> String {
    let marker = format!("Soyeht claw {claw_id} — mesh OK");
    let body = format!("<!doctype html><html><body><p>{marker}</p></body></html>");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await; // drain the request line/headers
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        }
    });
    addr
}

/// A credential bound to an ARBITRARY claw_id (same slot), to prove a
/// credential for one claw cannot open another claw's ClawSite/PTY.
fn credential_for(claw_id: &str) -> GuestCredential {
    let ok = owner();
    let owner_pub = ok.public();
    GuestCredential::sign(
        derive_household_id(&owner_pub),
        derive_person_id(&owner_pub),
        owner_pub,
        claw_id.to_string(),
        guest().public(),
        SLOT,
        1_800_000_000,
        1_800_086_400,
        &ok,
    )
    .unwrap()
}

/// R76-4 SECURITY: ClawSite served behind the authed data-tunnel gate is
/// DEFAULT-DENY per claw. (a) a valid GuestCredential for the claw fetches
/// the marker page; (b) no/invalid credential is rejected; (c) a credential
/// for a DIFFERENT claw is rejected. Mesh-membership alone grants nothing —
/// the same gate as the PTY (`authorize_session`) governs the site.
#[tokio::test]
#[ignore = "deflake-carry: timing flake under parallel load, passes isolated 3x; tracked, see relay-integration deflake carry"]
async fn clawsite_behind_authed_gate_is_default_deny_per_claw() {
    // (a) valid cred for claw_test → marker page flows back.
    let addr = spawn_one(
        store(),
        TargetSpec::Tcp(spawn_clawsite_target("claw_test").await),
    )
    .await;
    let cbor = cbor::to_canonical_vec(&credential()).unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert!(matches!(
        client_authenticate(&mut client, &cbor, token(&cbor))
            .await
            .unwrap(),
        TunnelAck::Ok { .. }
    ));
    client_health(&mut client, HEALTH_PROBE).await.unwrap();
    client_open_stream(&mut client).await.unwrap();
    send_frame(
        &mut client,
        &TunnelFrame::Data(b"GET / HTTP/1.1\r\nHost: claw\r\n\r\n".to_vec()),
    )
    .await
    .unwrap();
    let mut seen = Vec::new();
    for _ in 0..10 {
        match tokio::time::timeout(std::time::Duration::from_secs(5), recv_frame(&mut client)).await
        {
            Ok(Ok(TunnelFrame::Data(d))) => {
                seen.extend_from_slice(&d);
                if String::from_utf8_lossy(&seen).contains("mesh OK") {
                    break;
                }
            }
            Ok(Ok(_)) => {}
            _ => break,
        }
    }
    assert!(
        String::from_utf8_lossy(&seen).contains("Soyeht claw claw_test — mesh OK"),
        "valid per-claw credential must fetch the ClawSite marker, got: {:?}",
        String::from_utf8_lossy(&seen)
    );

    // (b) no/invalid credential (token signed by an attacker) → rejected.
    let addr_b = spawn_one(store(), TargetSpec::Tcp("127.0.0.1:1".into())).await;
    let attacker = P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap();
    let mut c_b = TcpStream::connect(addr_b).await.unwrap();
    match client_authenticate(&mut c_b, &cbor, token_signed(&cbor, &attacker, b"nb"))
        .await
        .unwrap()
    {
        TunnelAck::Rejected { reason } => assert_eq!(reason, "signature-invalid"),
        other => panic!("ClawSite must reject an invalid credential, got {other:?}"),
    }

    // (c) a credential for a DIFFERENT claw → rejected (claw-binding-mismatch).
    let addr_c = spawn_one(store(), TargetSpec::Tcp("127.0.0.1:1".into())).await;
    let other_cbor = cbor::to_canonical_vec(&credential_for("claw_OTHER")).unwrap();
    let mut c_c = TcpStream::connect(addr_c).await.unwrap();
    match client_authenticate(&mut c_c, &other_cbor, token(&other_cbor))
        .await
        .unwrap()
    {
        TunnelAck::Rejected { reason } => assert_eq!(reason, "claw-binding-mismatch"),
        other => panic!("ClawSite must reject another claw's credential, got {other:?}"),
    }
}

/// A persistent stream target: replies `ACK:<bytes>` to each read.
async fn spawn_stream_target() -> String {
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
        }
    });
    addr
}

async fn spawn_one(slots: Arc<ClawShareSlotStore>, target: TargetSpec) -> std::net::SocketAddr {
    spawn_one_with_replay(slots, target, Arc::new(ReplayGuard::new())).await
}

async fn spawn_one_with_replay(
    slots: Arc<ClawShareSlotStore>,
    target: TargetSpec,
    replay: Arc<ReplayGuard>,
) -> std::net::SocketAddr {
    let hh_id = derive_household_id(&owner().public());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, peer) = listener.accept().await.unwrap();
        let local = sock.local_addr().ok();
        serve_conn(sock, peer, local, hh_id, slots, target, replay).await;
    });
    addr
}

#[tokio::test]
async fn engine_listener_opens_persistent_stream_to_target() {
    let addr = spawn_one(store(), TargetSpec::Tcp(spawn_stream_target().await)).await;
    let cbor = cbor::to_canonical_vec(&credential()).unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert!(matches!(
        client_authenticate(&mut client, &cbor, token(&cbor))
            .await
            .unwrap(),
        TunnelAck::Ok { .. }
    ));
    assert_eq!(
        client_health(&mut client, HEALTH_PROBE).await.unwrap(),
        HEALTH_PROBE
    );

    // Open the persistent stream; multiple frames flow on the same conn.
    client_open_stream(&mut client).await.unwrap();
    for line in [b"ls\n".as_slice(), b"pwd\n".as_slice()] {
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
}

#[tokio::test]
async fn data_tunnel_shared_replay_guard_rejects_replay_across_listener_entries() {
    let slots = store();
    let replay = Arc::new(ReplayGuard::new());
    let addr_a = spawn_one_with_replay(
        Arc::clone(&slots),
        TargetSpec::Tcp("127.0.0.1:1".into()),
        Arc::clone(&replay),
    )
    .await;
    let addr_b = spawn_one_with_replay(slots, TargetSpec::Tcp("127.0.0.1:1".into()), replay).await;
    let cbor = cbor::to_canonical_vec(&credential()).unwrap();
    let reused_token = token_signed(&cbor, &guest(), b"shared-listener-nonce");

    let mut first = TcpStream::connect(addr_a).await.unwrap();
    assert!(matches!(
        client_authenticate(&mut first, &cbor, reused_token.clone())
            .await
            .unwrap(),
        TunnelAck::Ok { .. }
    ));

    let mut second = TcpStream::connect(addr_b).await.unwrap();
    match client_authenticate(&mut second, &cbor, reused_token)
        .await
        .unwrap()
    {
        TunnelAck::Rejected { reason } => assert_eq!(reason, "token-replayed"),
        other => panic!("shared replay guard must reject cross-listener replay, got {other:?}"),
    }
}

#[tokio::test]
async fn engine_listener_rejects_revoked() {
    let slots = store();
    slots.revoke(&SLOT, 1_800_000_002).unwrap();
    let addr = spawn_one(slots, TargetSpec::Tcp("127.0.0.1:1".into())).await;
    let cbor = cbor::to_canonical_vec(&credential()).unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    match client_authenticate(&mut client, &cbor, token(&cbor))
        .await
        .unwrap()
    {
        TunnelAck::Rejected { reason } => assert_eq!(reason, "slot-revoked"),
        other => panic!("revoked must be rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn engine_listener_rejects_stolen_credential_without_valid_token() {
    let addr = spawn_one(store(), TargetSpec::Tcp("127.0.0.1:1".into())).await;
    let cbor = cbor::to_canonical_vec(&credential()).unwrap();
    let attacker = P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    match client_authenticate(&mut client, &cbor, token_signed(&cbor, &attacker, b"n1"))
        .await
        .unwrap()
    {
        TunnelAck::Rejected { reason } => assert_eq!(reason, "signature-invalid"),
        other => panic!("stolen credential w/o valid token must be rejected, got {other:?}"),
    }
}

// ─── Real interactive PTY (end-to-end through the engine listener) ────

use crate::claw_share_pty_target::PtyPolicy;

/// Drive the WHOLE real path: authenticate → health → open → a real
/// `/bin/sh` runs a command on a real PTY → its output streams back →
/// its typed exit status propagates. No fixture, no echo — a real shell.
#[tokio::test]
async fn engine_opens_real_pty_shell_runs_command_and_propagates_exit() {
    let policy = PtyPolicy {
        shell: "/bin/sh".into(),
        args: vec!["-c".into(), "echo R18-E2E-$((6*7)); exit 0".into()],
        ..Default::default()
    };
    let addr = spawn_one(store(), TargetSpec::Pty(policy)).await;
    let cbor = cbor::to_canonical_vec(&credential()).unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    assert!(matches!(
        client_authenticate(&mut client, &cbor, token(&cbor))
            .await
            .unwrap(),
        TunnelAck::Ok { .. }
    ));
    assert_eq!(
        client_health(&mut client, HEALTH_PROBE).await.unwrap(),
        HEALTH_PROBE
    );
    client_open_stream(&mut client).await.unwrap();

    let mut out = Vec::new();
    let mut exit = None;
    loop {
        match recv_frame(&mut client).await {
            Ok(TunnelFrame::Data(d)) => out.extend_from_slice(&d),
            Ok(TunnelFrame::Exit(status)) => exit = Some(status),
            Ok(TunnelFrame::Close) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("R18-E2E-42"),
        "real shell command output missing, got: {text:?}"
    );
    assert_eq!(
        exit,
        Some(TargetExit::Code(0)),
        "real shell exit status must propagate"
    );
}

/// Interactive PTY: keyboard input is echoed by the terminal, and a
/// resize is delivered to a live shell without disturbing the stream.
#[tokio::test]
#[ignore = "deflake-carry: timing flake under parallel load, passes isolated 3x; tracked, see relay-integration deflake carry"]
async fn engine_pty_interactive_input_and_resize() {
    let policy = PtyPolicy {
        shell: "/bin/cat".into(),
        ..Default::default()
    };
    let addr = spawn_one(store(), TargetSpec::Pty(policy)).await;
    let cbor = cbor::to_canonical_vec(&credential()).unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(&mut client, &cbor, token(&cbor))
        .await
        .unwrap();
    client_health(&mut client, HEALTH_PROBE).await.unwrap();
    client_open_stream(&mut client).await.unwrap();

    // Resize the live terminal, then type — the echo must come back.
    client_resize(&mut client, 132, 43).await.unwrap();
    send_frame(&mut client, &TunnelFrame::Data(b"hello-pty\n".to_vec()))
        .await
        .unwrap();

    // Collect until the echoed line shows up (terminal echo of stdin).
    let mut seen = Vec::new();
    for _ in 0..10 {
        match tokio::time::timeout(std::time::Duration::from_secs(5), recv_frame(&mut client)).await
        {
            Ok(Ok(TunnelFrame::Data(d))) => {
                seen.extend_from_slice(&d);
                if String::from_utf8_lossy(&seen).contains("hello-pty") {
                    break;
                }
            }
            Ok(Ok(_)) => {}
            _ => break,
        }
    }
    assert!(
        String::from_utf8_lossy(&seen).contains("hello-pty"),
        "interactive input must echo back through the real PTY, got: {:?}",
        String::from_utf8_lossy(&seen)
    );
}

/// Revoking the slot mid-session tears down a live PTY session: the next
/// data frame is blocked and the client sees the session close.
#[tokio::test]
async fn engine_pty_revocation_mid_session_tears_down() {
    let slots = store();
    let policy = PtyPolicy {
        shell: "/bin/cat".into(),
        ..Default::default()
    };
    let addr = spawn_one(slots.clone(), TargetSpec::Pty(policy)).await;
    let cbor = cbor::to_canonical_vec(&credential()).unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    client_authenticate(&mut client, &cbor, token(&cbor))
        .await
        .unwrap();
    client_open_stream(&mut client).await.unwrap();

    // Revoke, then send input — the engine must stop forwarding and drop
    // the session.
    slots.revoke(&SLOT, now_unix()).unwrap();
    send_frame(
        &mut client,
        &TunnelFrame::Data(b"should-not-run\n".to_vec()),
    )
    .await
    .unwrap();

    // The session is torn down: reads eventually error or close.
    let mut closed = false;
    for _ in 0..10 {
        match tokio::time::timeout(std::time::Duration::from_secs(3), recv_frame(&mut client)).await
        {
            Ok(Ok(TunnelFrame::Data(_))) => {} // drain any echo already in flight
            Ok(Ok(TunnelFrame::Close)) | Ok(Err(_)) | Err(_) => {
                closed = true;
                break;
            }
            Ok(Ok(_)) => {}
        }
    }
    assert!(closed, "revoked session must be torn down");
}
