#![cfg(test)]

use super::*;
use household_rs::claw_share::{SLOT_ID_LEN, SlotId};

fn fake_credential() -> GuestCredential {
    use household_rs::keys::{IdentityKey, P256Keypair};
    let owner_key = P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap();
    let guest_key = P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap();
    let owner_pub = owner_key.public();
    let hh_id = household_rs::ids::derive_household_id(&owner_pub);
    let owner_p_id = household_rs::person_cert::derive_person_id(&owner_pub);
    GuestCredential::sign(
        hh_id,
        owner_p_id,
        owner_pub,
        "claw_test".to_string(),
        guest_key.public(),
        SlotId([0x22; SLOT_ID_LEN]),
        1_800_000_000,
        1_800_086_400,
        &owner_key,
    )
    .expect("sign credential")
}

fn fake_token(cred_cbor: &[u8]) -> Vec<u8> {
    use household_rs::keys::P256Keypair;
    let guest = P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap();
    let token = dt::SessionAuthToken::sign(
        "sess".into(),
        cred_cbor,
        "127.0.0.1:0".into(),
        "claw_test".into(),
        b"nonce-1".to_vec(),
        1_800_000_060,
        &guest,
    )
    .unwrap();
    cbor::to_canonical_vec(&token).unwrap()
}

async fn connected_session(port: u16) -> Arc<ClawSession> {
    let session = ClawSession::new();
    let cbor = cbor::to_canonical_vec(&fake_credential()).unwrap();
    session
        .clone()
        .load_credential(cbor.clone(), 1_800_000_001)
        .await
        .unwrap();
    session
        .clone()
        .start_session(
            DataPlaneConfig {
                host: "127.0.0.1".into(),
                port,
            },
            fake_token(&cbor),
        )
        .await
        .expect("start");
    session
}

/// Router that delegates to the base `TcpStreamRouter` and attaches a
/// pool-allocated VPN address, so `serve_connection` takes the `IpTunnel`
/// branch and emits a REAL `NetworkSettings` frame after the Open-ack.
/// Without this the loopback fixture only ever exercises the PTY path,
/// where no such frame exists and the assertions below would be vacuous.
struct VpnRouter {
    inner: dt::TcpStreamRouter,
    mesh_ipv4: dt::MeshIpv4,
}

impl dt::ClawTargetRouter for VpnRouter {
    async fn open(&self, target_id: &str) -> Result<dt::TargetSession, dt::DataTunnelError> {
        Ok(self
            .inner
            .open(target_id)
            .await?
            .with_vpn_mesh_ipv4(self.mesh_ipv4.clone()))
    }
}

/// Same shape as `start_loopback_echo_server`, but on the `IpTunnel` path.
/// Kept test-local so the exported FFI surface stays unchanged.
async fn start_loopback_vpn_server(mesh_ipv4: dt::MeshIpv4) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = target.accept().await {
            tokio::spawn(async move {
                let _ = sock.write_all(b"FAKE-SSH-BANNER").await;
                let mut buf = vec![0u8; 2048];
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
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let router = VpnRouter {
                inner: dt::TcpStreamRouter::new(target_addr.clone()),
                mesh_ipv4: mesh_ipv4.clone(),
            };
            tokio::spawn(async move {
                let verify = |env: &dt::AuthEnvelope, _now: u64| {
                    cbor::from_canonical_slice::<GuestCredential>(&env.credential_cbor)
                        .map_err(|e| dt::DataTunnelError::Cbor(e.to_string()))
                };
                let _ = dt::serve_connection(sock, 0, verify, &router, |_cred| false).await;
            });
        }
    });
    port
}

fn pool_allocation() -> dt::MeshIpv4 {
    dt::MeshIpv4 {
        addr: "10.42.0.2".into(),
        prefix_len: 30,
        peer: "10.42.0.3".into(),
    }
}

/// The real wire path: the engine's post-Open `NetworkSettings` frame is
/// parsed, validated, and surfaced — and does NOT break the interactive
/// open, which previously rejected any unrecognised frame before first
/// output.
#[tokio::test]
async fn network_settings_frame_is_accepted_and_exposed() {
    let port = start_loopback_vpn_server(pool_allocation()).await;
    let session = connected_session(port).await;
    session.clone().health_ping().await.expect("health");

    // Pre-condition: nothing before the frame arrives. If this were already
    // `Some`, the assertion below would prove nothing.
    assert!(session.clone().network_settings().await.is_none());

    session.clone().open_stream().await.expect("open");
    assert_eq!(
        session.clone().receive_data().await.expect("banner"),
        b"FAKE-SSH-BANNER"
    );

    let ns = session
        .clone()
        .network_settings()
        .await
        .expect("settings delivered on the IpTunnel path");
    assert_eq!(ns.addr, "10.42.0.2");
    assert_eq!(ns.prefix_len, 30);
    assert_eq!(ns.peer, "10.42.0.3");
    assert_eq!(ns.mtu, 1280);
    // Cross-phase binding: the engine stamps the auth ack's session id.
    assert!(!ns.session_id.is_empty());

    // The stream still works after the extra frame.
    session
        .clone()
        .send_data(b"echo\n".to_vec())
        .await
        .expect("send");
    assert_eq!(
        session.clone().receive_data().await.expect("recv"),
        b"ACK:echo\n"
    );
}

/// Non-`IpTunnel` paths send no frame, so the accessor stays `None` — the
/// negative control for the test above.
#[tokio::test]
async fn non_ip_tunnel_path_exposes_no_network_settings() {
    let port = start_loopback_echo_server().await.unwrap();
    let session = connected_session(port).await;
    session.clone().health_ping().await.expect("health");
    session.clone().open_stream().await.expect("open");
    assert!(session.clone().network_settings().await.is_none());
}

/// Settings AND the session id are dropped with the session, so nothing
/// after a stop can validate against the dead session and a reconnect
/// cannot inherit an id it never negotiated.
#[tokio::test]
async fn stop_session_clears_network_settings() {
    let port = start_loopback_vpn_server(pool_allocation()).await;
    let session = connected_session(port).await;
    session.clone().health_ping().await.expect("health");
    session.clone().open_stream().await.expect("open");
    assert!(session.clone().network_settings().await.is_some());

    // Capture the live id so the post-stop assertion below is a real
    // replay of a once-valid value, not an arbitrary string.
    let live_id = session.inner.lock().await.session_id.clone().unwrap();
    assert!(!live_id.is_empty());

    session.clone().stop_session("test".into()).await;
    assert!(session.clone().network_settings().await.is_none());
    assert!(session.inner.lock().await.session_id.is_none());

    // A settings frame carrying the PREVIOUS session's id, arriving before
    // any new handshake, must be refused rather than re-accepted.
    let err = session
        .accept_network_settings(dt::NetworkSettings {
            mesh_ipv4: pool_allocation(),
            mtu: 1280,
            session_id: live_id,
        })
        .await
        .expect_err("settings after stop must be refused");
    assert!(matches!(err, BridgeError::NetworkSettingsInvalid(_)));
    assert!(session.clone().network_settings().await.is_none());
}

/// Fail-closed: a frame whose session id is not the one the auth ack
/// carried is rejected and nothing is stored.
#[tokio::test]
async fn network_settings_with_wrong_session_id_fails_closed() {
    let port = start_loopback_vpn_server(pool_allocation()).await;
    let session = connected_session(port).await;

    let err = session
        .accept_network_settings(dt::NetworkSettings {
            mesh_ipv4: pool_allocation(),
            mtu: 1280,
            session_id: "not-the-acked-session".into(),
        })
        .await
        .expect_err("mismatched session id must be refused");
    assert!(matches!(err, BridgeError::NetworkSettingsInvalid(_)));
    assert!(session.clone().network_settings().await.is_none());
    // The rejection must not echo the offending id.
    assert!(!err.to_string().contains("not-the-acked-session"));
}

/// Fail-closed: route scope is enforced HERE, on a frame whose provenance is
/// otherwise perfect.
///
/// The frames below carry the live session id, arrive after a real
/// handshake, and are the first of their kind — so every check that existed
/// before this one passes them. The defect they pin was exactly that: a
/// frame could be impeccably provenanced and still describe a default route,
/// and `prefix_len` was copied into `VpnNetworkSettings` verbatim. The
/// consumer that installs a route from it is a NetworkExtension in another
/// repository, so this is the last place the answer can be no.
///
/// Each case is a DIFFERENT violation, not the same one five times: a
/// consumer that only rejected `prefix_len == 0` would pass four of them.
#[tokio::test]
async fn network_settings_violating_route_scope_fail_closed() {
    for (case, mesh) in [
        // The whole point: a default route captures every destination.
        (
            "default route",
            dt::MeshIpv4 {
                addr: "10.42.0.2".into(),
                prefix_len: 0,
                peer: "10.42.0.3".into(),
            },
        ),
        (
            "prefix longer than an IPv4 address",
            dt::MeshIpv4 {
                addr: "10.42.0.2".into(),
                prefix_len: 33,
                peer: "10.42.0.3".into(),
            },
        ),
        (
            "addr is not IPv4",
            dt::MeshIpv4 {
                addr: "not-an-address".into(),
                prefix_len: 30,
                peer: "10.42.0.3".into(),
            },
        ),
        (
            "peer equals addr",
            dt::MeshIpv4 {
                addr: "10.42.0.2".into(),
                prefix_len: 30,
                peer: "10.42.0.2".into(),
            },
        ),
        // Subtlest of the five, and the reason for reusing the neutral rule
        // rather than open-coding a prefix check: the prefix is sane and
        // both addresses parse, but they are not on the same link.
        (
            "peer outside the prefix",
            dt::MeshIpv4 {
                addr: "10.42.0.2".into(),
                prefix_len: 30,
                peer: "10.42.7.9".into(),
            },
        ),
    ] {
        let port = start_loopback_vpn_server(pool_allocation()).await;
        let session = connected_session(port).await;
        let acked = session.inner.lock().await.session_id.clone().unwrap();

        let Err(err) = session
            .accept_network_settings(dt::NetworkSettings {
                mesh_ipv4: mesh,
                mtu: 1280,
                session_id: acked,
            })
            .await
        else {
            panic!("{case}: must be refused");
        };
        assert!(
            matches!(err, BridgeError::NetworkSettingsInvalid(_)),
            "{case}: wrong error variant, so a caller matching on \
                 NetworkSettingsInvalid would not see this as a settings refusal"
        );
        // Nothing stored: a rejected frame must leave no allocation behind,
        // or a later reader sees settings that were never accepted.
        assert!(
            session.clone().network_settings().await.is_none(),
            "{case}: refused frame still stored an allocation"
        );
        // Addresses are redacted in Debug for a reason; a rejection message
        // must not reintroduce them.
        let msg = err.to_string();
        assert!(
            !msg.contains("10.42.") && !msg.contains("not-an-address"),
            "{case}: rejection echoed an address: {msg}"
        );
    }
}

/// Fail-closed: a second frame cannot overwrite an accepted allocation.
#[tokio::test]
async fn duplicate_network_settings_is_refused() {
    let port = start_loopback_vpn_server(pool_allocation()).await;
    let session = connected_session(port).await;
    session.clone().health_ping().await.expect("health");
    session.clone().open_stream().await.expect("open");
    assert!(session.clone().network_settings().await.is_some());

    let acked = session.inner.lock().await.session_id.clone().unwrap();
    let err = session
        .accept_network_settings(dt::NetworkSettings {
            mesh_ipv4: dt::MeshIpv4 {
                addr: "10.42.9.9".into(),
                prefix_len: 30,
                peer: "10.42.9.8".into(),
            },
            mtu: 1280,
            session_id: acked,
        })
        .await
        .expect_err("a duplicate frame must be refused");
    assert!(matches!(err, BridgeError::NetworkSettingsInvalid(_)));
    // The original allocation is intact — not re-pointed.
    assert_eq!(
        session.clone().network_settings().await.unwrap().addr,
        "10.42.0.2"
    );
}

/// Settings arriving before a handshake has established a session id are
/// refused rather than stored against an unknown session.
#[tokio::test]
async fn network_settings_before_handshake_fails_closed() {
    let session = ClawSession::new();
    let err = session
        .accept_network_settings(dt::NetworkSettings {
            mesh_ipv4: pool_allocation(),
            mtu: 1280,
            session_id: "anything".into(),
        })
        .await
        .expect_err("settings before handshake must be refused");
    assert!(matches!(err, BridgeError::NetworkSettingsInvalid(_)));
    assert!(session.clone().network_settings().await.is_none());
}

/// The diag channel is drained by the app and can reach a log, so it must
/// never hold an endpoint or a session identifier.
///
/// Asserts on two axes so neither alone can carry the test: the literal
/// values (loopback address, session id) must be absent, AND the field KEYS
/// that used to carry them must be gone structurally. The key check is what
/// makes this robust — a numeric port can coincide with an `elapsed_ms` or
/// `bytes` value, so a value-only assertion would be both flaky and weaker
/// than it looks.
#[tokio::test]
async fn diag_events_never_carry_endpoints_or_session_id() {
    let port = start_loopback_echo_server().await.unwrap();
    let session = connected_session(port).await;
    session.clone().health_ping().await.expect("health");

    let session_id = session.inner.lock().await.session_id.clone().unwrap();
    // Non-vacuity: an empty id would make the "absent" assertion trivial.
    assert!(!session_id.is_empty());

    let events = session.clone().drain_diag_events().await;
    assert!(!events.is_empty(), "diag must retain per-category utility");
    let joined = events.join("\n");

    // Values: the host, the resolved address, and both socket addresses are
    // all loopback in this fixture, so one literal covers every one of them.
    assert!(!joined.contains("127.0.0.1"), "diag leaked an endpoint");
    assert!(!joined.contains(&session_id), "diag leaked the session id");
    // A prefix is still a partial identifier.
    let prefix: String = session_id.chars().take(8).collect();
    assert!(!joined.contains(&prefix), "diag leaked a session id prefix");

    // Keys: the fields that used to carry those values are gone.
    for key in ["host=", "addrs=", "local=", "peer=", "session_id=", "err="] {
        assert!(!joined.contains(key), "diag still emits `{key}`");
    }

    // Utility by category is retained.
    for kept in [
        "start_session_enter",
        "resolve_ok",
        "connect_ok",
        "client_authenticate_ok",
        "ack_ok",
    ] {
        assert!(joined.contains(kept), "diag lost the `{kept}` category");
    }
    // And the surviving fields are non-identifying.
    assert!(joined.contains("addr_count="));
    assert!(joined.contains("session_id_present="));
    assert!(joined.contains("elapsed_ms="));
}

/// Transport errors reach the diag channel as closed-set discriminants, so
/// an `Io(String)` payload carrying an address can never be formatted in.
#[test]
fn dt_error_label_is_a_static_discriminant() {
    assert_eq!(
        dt_error_label(&dt::DataTunnelError::Io("connect to 10.0.0.7:443".into())),
        "io"
    );
    assert_eq!(
        dt_error_label(&dt::DataTunnelError::Rejected("secret-reason".into())),
        "rejected"
    );
    assert_eq!(
        dt_error_label(&dt::DataTunnelError::AuthTimeout),
        "auth_timeout"
    );
}

/// Engine auth traces are allowlisted, so an upstream event that started
/// carrying an identifier would degrade to a bare label instead of being
/// passed through.
#[test]
fn auth_trace_label_allowlists_and_drops_payloads() {
    assert_eq!(
        auth_trace_label("auth_frame_write_ok bytes=42"),
        "auth_frame_write_ok"
    );
    assert_eq!(auth_trace_label("ack_read_start"), "ack_read_start");
    assert_eq!(
        auth_trace_label("some_future_event host=engine.internal"),
        "auth_trace_other"
    );
}

/// The redacting `Debug` must survive refactors: addresses and the session
/// id reveal VPN topology and must never reach a log through a formatter.
#[test]
fn network_settings_debug_redacts_addresses_and_session_id() {
    let rendered = format!(
        "{:?}",
        VpnNetworkSettings {
            addr: "10.42.0.2".into(),
            prefix_len: 30,
            peer: "10.42.0.3".into(),
            mtu: 1280,
            session_id: "sess-secret".into(),
        }
    );
    assert!(!rendered.contains("10.42.0.2"));
    assert!(!rendered.contains("10.42.0.3"));
    assert!(!rendered.contains("sess-secret"));
    assert!(rendered.contains("<redacted>"));
    // Non-sensitive fields stay visible for diagnosis.
    assert!(rendered.contains("30"));
    assert!(rendered.contains("1280"));
}

#[tokio::test]
async fn credential_advances_to_ready() {
    let session = ClawSession::new();
    let cbor = cbor::to_canonical_vec(&fake_credential()).unwrap();
    let status = session
        .clone()
        .load_credential(cbor, 1_800_000_001)
        .await
        .unwrap();
    assert!(matches!(status, SessionStatus::CredentialReady));
}

#[tokio::test]
async fn expired_credential_is_refused() {
    let session = ClawSession::new();
    let cbor = cbor::to_canonical_vec(&fake_credential()).unwrap();
    let err = session
        .clone()
        .load_credential(cbor, 1_800_086_401)
        .await
        .expect_err("expired");
    assert!(matches!(err, BridgeError::CredentialInvalid));
}

#[tokio::test]
async fn start_without_credential_fails() {
    let session = ClawSession::new();
    let cbor = cbor::to_canonical_vec(&fake_credential()).unwrap();
    let err = session
        .clone()
        .start_session(
            DataPlaneConfig {
                host: "127.0.0.1".into(),
                port: 9,
            },
            fake_token(&cbor),
        )
        .await
        .expect_err("no credential");
    assert!(matches!(err, BridgeError::CredentialInvalid));
}

#[tokio::test]
async fn stream_methods_without_session_fail() {
    let session = ClawSession::new();
    assert!(matches!(
        session.clone().health_ping().await,
        Err(BridgeError::HealthRoundTripFailed)
    ));
    assert!(matches!(
        session.clone().send_data(vec![1]).await,
        Err(BridgeError::NoSession)
    ));
    assert!(matches!(
        session.clone().receive_data().await,
        Err(BridgeError::NoSession)
    ));
}

/// The Apple-grade gate end to end over the real loopback tunnel:
/// start → health (Connected, tunnel ready) → open_stream — which only
/// reaches `InteractiveReady` after the target's first output (the
/// banner). `StreamReady` is an internal checkpoint, never the end state
/// of `open_stream`.
#[tokio::test]
async fn interactive_ready_only_after_first_output() {
    let port = start_loopback_echo_server().await.unwrap();
    let session = connected_session(port).await;

    let health = session.clone().health_ping().await.expect("health");
    assert!(
        matches!(health, SessionStatus::Connected { .. }),
        "health → Connected, got {health:?}"
    );

    let ready = session.clone().open_stream().await.expect("open stream");
    assert!(
        matches!(ready, SessionStatus::InteractiveReady { .. }),
        "open → InteractiveReady (after first output), got {ready:?}"
    );
}

/// Persistent bidirectional stream: the target's banner (captured as the
/// first output during open) is returned first, then multiple data
/// frames round-trip on the SAME session.
#[tokio::test]
async fn persistent_stream_data_round_trips() {
    let port = start_loopback_echo_server().await.unwrap();
    let session = connected_session(port).await;
    session.clone().health_ping().await.expect("health");
    session.clone().open_stream().await.expect("open");

    // Banner first (the buffered first output that flipped InteractiveReady).
    assert_eq!(
        session.clone().receive_data().await.expect("banner"),
        b"FAKE-SSH-BANNER"
    );
    // Multiple data frames on the same session.
    for line in [b"ls\n".as_slice(), b"pwd\n".as_slice()] {
        session
            .clone()
            .send_data(line.to_vec())
            .await
            .expect("send");
        let mut expected = b"ACK:".to_vec();
        expected.extend_from_slice(line);
        assert_eq!(
            session.clone().receive_data().await.expect("recv"),
            expected
        );
    }
}

/// Idle survival: hold an open interactive session idle, then prove the
/// session is still live (data round-trips). The bridge intentionally does
/// not send an application-level keepalive after `InteractiveReady`; the
/// mesh underlay owns transport liveness, while the PTY stream only sends
/// explicit terminal frames.
#[tokio::test]
async fn idle_session_survives_without_app_keepalive_then_data_flows() {
    let port = start_loopback_echo_server().await.unwrap();
    let session = connected_session(port).await;
    session.clone().health_ping().await.expect("health");
    session.clone().open_stream().await.expect("open");
    assert_eq!(
        session.clone().receive_data().await.expect("banner"),
        b"FAKE-SSH-BANNER"
    );

    // Idle past the previous keepalive tick interval. No application-level
    // frame should be sent during this gap; the round-trip below proves the
    // stream remains usable without injecting control traffic.
    tokio::time::sleep(std::time::Duration::from_millis(3_500)).await;
    assert!(
        matches!(
            session.clone().status().await,
            SessionStatus::InteractiveReady { .. }
        ),
        "session must stay interactive across an idle keepalive gap"
    );

    session
        .clone()
        .send_data(b"whoami\n".to_vec())
        .await
        .expect("send after idle");
    assert_eq!(
        session
            .clone()
            .receive_data()
            .await
            .expect("recv after idle"),
        b"ACK:whoami\n",
        "data must still round-trip after the idle keepalive gap"
    );
}

/// Resize is a valid write on an open interactive session (the loopback
/// target ignores it; the engine-side PTY honours it — covered by
/// server-rs tests). It must not disturb subsequent data flow.
#[tokio::test]
async fn resize_then_data_still_flows() {
    let port = start_loopback_echo_server().await.unwrap();
    let session = connected_session(port).await;
    session.clone().health_ping().await.expect("health");
    session.clone().open_stream().await.expect("open");
    assert_eq!(
        session.clone().receive_data().await.expect("banner"),
        b"FAKE-SSH-BANNER"
    );

    session.clone().resize(120, 40).await.expect("resize");
    session
        .clone()
        .send_data(b"echo\n".to_vec())
        .await
        .expect("send");
    assert_eq!(
        session.clone().receive_data().await.expect("recv"),
        b"ACK:echo\n"
    );
    session.clone().resize(80, 24).await.expect("resize-2");
}

#[tokio::test]
async fn resize_without_session_fails() {
    let session = ClawSession::new();
    assert!(matches!(
        session.clone().resize(80, 24).await,
        Err(BridgeError::NoSession)
    ));
}

#[tokio::test]
async fn stop_session_is_idempotent_and_drops_transport() {
    let port = start_loopback_echo_server().await.unwrap();
    let session = connected_session(port).await;
    let s1 = session.clone().stop_session("test".to_string()).await;
    let s2 = session.clone().stop_session("test".to_string()).await;
    assert!(matches!(s1, SessionStatus::Stopped { .. }));
    assert!(matches!(s2, SessionStatus::Stopped { .. }));
    assert!(matches!(
        session.clone().send_data(vec![1]).await,
        Err(BridgeError::NoSession)
    ));
}
