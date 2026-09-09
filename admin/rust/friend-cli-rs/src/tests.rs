#![cfg(test)]

use super::*;

// ─── C7c-2b: relay_stream offer parse + audience verification ─────────────

use household_rs::claw_share::data_tunnel::{
    AuthEnvelope, ClawTargetRouter, DataTunnelError, DataTunnelSession, ReplayGuard, TargetSession,
    credential_hash, serve_connection_io, serve_connection_io_with_auth_deadline,
};
use household_rs::claw_share::relay_stream_contract::{
    RelayStreamAudience, RelayStreamClawStaticPublicKey, RelayStreamOfferMintInput,
    RelayStreamResource, mint_relay_stream_group_offer, mint_relay_stream_offer,
    mint_relay_stream_public_offer,
};
use household_rs::claw_share::rendezvous_token::RendezvousToken;
use household_rs::claw_share::{GuestCredential, SlotId};
use household_rs::ids::derive_household_id;
use household_rs::keys::P256PublicKey;
use household_rs::person_cert::derive_person_id;
use tokio::io::{AsyncReadExt, duplex};

const OFFER_NOW: u64 = 1_800_000_000;

fn offer_kp(seed: u8) -> P256Keypair {
    P256Keypair::from_secret_scalar(&[seed; 32]).expect("p256 keypair")
}

fn offer_credential(owner: &P256Keypair, guest_pub: &P256PublicKey) -> GuestCredential {
    GuestCredential::sign(
        derive_household_id(&owner.public()),
        derive_person_id(&owner.public()),
        owner.public(),
        "claw_alpha".to_string(),
        guest_pub.clone(),
        SlotId([0x22; 16]),
        OFFER_NOW - 60,
        OFFER_NOW + 600,
        owner as &dyn IdentityKey,
    )
    .expect("sign guest credential")
}

fn mint_offer(
    owner: &P256Keypair,
    credential: &GuestCredential,
    expected_path: RelayStreamExpectedPath,
    not_after: u64,
) -> RelayStreamOfferContract {
    mint_offer_with_resource(
        owner,
        credential,
        RelayStreamResource::Pty,
        expected_path,
        not_after,
    )
}

fn mint_offer_with_resource(
    owner: &P256Keypair,
    credential: &GuestCredential,
    resource: RelayStreamResource,
    expected_path: RelayStreamExpectedPath,
    not_after: u64,
) -> RelayStreamOfferContract {
    mint_relay_stream_offer(
        RelayStreamOfferMintInput {
            rendezvous_token: RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
            credential,
            resource,
            expected_path,
            relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
            claw_static_pub: RelayStreamClawStaticPublicKey::try_new([0x33; 32]).unwrap(),
            not_after,
            now_unix: OFFER_NOW,
            app_presentation: None,
        },
        owner as &dyn IdentityKey,
    )
    .expect("mint relay stream offer")
}

fn ack_with_offer(
    credential: GuestCredential,
    offer: Option<&RelayStreamOfferContract>,
) -> ClawShareAck {
    ClawShareAck {
        v: 1,
        credential,
        tunnel: TunnelHandle::Loopback {
            channel: "test".to_string(),
        },
        relay_stream_offer: offer
            .map(|o| serde_bytes::ByteBuf::from(o.to_canonical_bytes().unwrap())),
    }
}

#[test]
fn relay_stream_offer_absent_is_noop() {
    let owner = offer_kp(0x11);
    let guest = offer_kp(0x33);
    let ack = ack_with_offer(offer_credential(&owner, &guest.public()), None);

    assert!(verify_relay_stream_offer(&ack, &guest, OFFER_NOW).is_none());
}

#[test]
fn relay_stream_offer_valid_parses_and_verifies() {
    let owner = offer_kp(0x11);
    let guest = offer_kp(0x33);
    let credential = offer_credential(&owner, &guest.public());
    let offer = mint_offer(
        &owner,
        &credential,
        RelayStreamExpectedPath::RelayStream,
        OFFER_NOW + 60,
    );
    let ack = ack_with_offer(credential, Some(&offer));

    let verified =
        verify_relay_stream_offer(&ack, &guest, OFFER_NOW).expect("valid offer accepted");
    assert_eq!(
        verified.payload.expected_path,
        RelayStreamExpectedPath::RelayStream
    );
    assert_eq!(verified.payload.guest_device_pub, guest.public());
}

#[test]
fn relay_stream_offer_wrong_audience_is_rejected() {
    let owner = offer_kp(0x11);
    let guest = offer_kp(0x33);
    let other_guest = offer_kp(0x99);
    let credential = offer_credential(&owner, &guest.public());
    let offer = mint_offer(
        &owner,
        &credential,
        RelayStreamExpectedPath::RelayStream,
        OFFER_NOW + 60,
    );
    let ack = ack_with_offer(credential, Some(&offer));

    // Offer is addressed to `guest`; verifying as `other_guest` must drop it.
    assert!(verify_relay_stream_offer(&ack, &other_guest, OFFER_NOW).is_none());
}

#[test]
fn relay_stream_offer_signer_mismatch_is_rejected() {
    let owner = offer_kp(0x11);
    let attacker = offer_kp(0x55);
    let guest = offer_kp(0x33);
    // Offer minted + signed under the attacker's own credential...
    let attacker_credential = offer_credential(&attacker, &guest.public());
    let attacker_offer = mint_offer(
        &attacker,
        &attacker_credential,
        RelayStreamExpectedPath::RelayStream,
        OFFER_NOW + 60,
    );
    // ...but delivered in an ack whose credential pins the real owner.
    let ack = ack_with_offer(
        offer_credential(&owner, &guest.public()),
        Some(&attacker_offer),
    );

    assert!(verify_relay_stream_offer(&ack, &guest, OFFER_NOW).is_none());
}

#[test]
fn relay_stream_offer_wrong_expected_path_is_rejected() {
    let owner = offer_kp(0x11);
    let guest = offer_kp(0x33);
    let credential = offer_credential(&owner, &guest.public());
    let offer = mint_offer(
        &owner,
        &credential,
        RelayStreamExpectedPath::CommunityRelay,
        OFFER_NOW + 60,
    );
    let ack = ack_with_offer(credential, Some(&offer));

    assert!(verify_relay_stream_offer(&ack, &guest, OFFER_NOW).is_none());
}

#[test]
fn relay_stream_offer_expired_is_rejected() {
    let owner = offer_kp(0x11);
    let guest = offer_kp(0x33);
    let credential = offer_credential(&owner, &guest.public());
    // not_after is in the future at mint time, but we verify well past it.
    let offer = mint_offer(
        &owner,
        &credential,
        RelayStreamExpectedPath::RelayStream,
        OFFER_NOW + 60,
    );
    let ack = ack_with_offer(credential, Some(&offer));

    assert!(verify_relay_stream_offer(&ack, &guest, OFFER_NOW + 120).is_none());
}

#[test]
fn relay_stream_offer_malformed_bytes_is_rejected() {
    let owner = offer_kp(0x11);
    let guest = offer_kp(0x33);
    let mut ack = ack_with_offer(offer_credential(&owner, &guest.public()), None);
    ack.relay_stream_offer = Some(serde_bytes::ByteBuf::from(vec![0xff, 0x00, 0x13, 0x37]));

    assert!(verify_relay_stream_offer(&ack, &guest, OFFER_NOW).is_none());
}

#[test]
fn relay_stream_dial_flag_parses_only_truthy_values() {
    assert!(parse_dial_flag(Some("1")));
    assert!(parse_dial_flag(Some("true")));
    assert!(parse_dial_flag(Some("TRUE")));
    assert!(parse_dial_flag(Some(" 1 ")));
    assert!(!parse_dial_flag(Some("0")));
    assert!(!parse_dial_flag(Some("false")));
    assert!(!parse_dial_flag(Some("")));
    assert!(!parse_dial_flag(None));
}

#[test]
fn relay_stream_client_rejects_iptunnel_before_connecting() {
    assert!(ensure_relay_stream_client_resource_supported(RelayStreamResource::Pty).is_ok());
    assert!(ensure_relay_stream_client_resource_supported(RelayStreamResource::ClawSite).is_ok());

    let error = ensure_relay_stream_client_resource_supported(RelayStreamResource::IpTunnel)
        .expect_err("IpTunnel must stay unsupported until a reviewed dev runner exists");
    assert!(
        error
            .to_string()
            .contains("relay_stream IpTunnel payload is not implemented in this client"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn relay_stream_device_dial_rejects_iptunnel_before_connecting() {
    let owner = offer_kp(0x11);
    let guest = offer_kp(0x33);
    let credential = offer_credential(&owner, &guest.public());
    let offer = mint_offer_with_resource(
        &owner,
        &credential,
        RelayStreamResource::IpTunnel,
        RelayStreamExpectedPath::RelayStream,
        OFFER_NOW + 60,
    );

    let error = dial_relay_stream(&offer, &guest, &credential, OFFER_NOW)
        .await
        .expect_err("IpTunnel must fail before relay connection");
    assert!(
        error
            .to_string()
            .contains("relay_stream IpTunnel payload is not implemented in this client"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn relay_stream_group_dial_rejects_iptunnel_before_connecting() {
    let owner = offer_kp(0x11);
    let device = offer_kp(0x33);
    let offer = mint_relay_stream_group_offer(
        RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
        SlotId([0x99; 16]),
        "g".to_string(),
        "g_a".to_string(),
        device.public(),
        "claw_alpha".to_string(),
        RelayStreamResource::IpTunnel,
        "relay-stream://127.0.0.1:49152".to_string(),
        RelayStreamClawStaticPublicKey::try_new([0x33; 32]).unwrap(),
        OFFER_NOW + 60,
        OFFER_NOW,
        &owner as &dyn IdentityKey,
    )
    .expect("mint group IpTunnel offer");

    let error = dial_relay_stream_offer_session(&offer, &device, OFFER_NOW)
        .await
        .expect_err("IpTunnel must fail before relay connection");
    assert!(
        error
            .to_string()
            .contains("relay_stream IpTunnel payload is not implemented in this client"),
        "unexpected error: {error}"
    );
}

// Minimal data-tunnel target that just exists long enough for the client to
// open then drop; the dropped duplex peer gives the target a clean EOF.
struct NoopTargetRouter;

impl ClawTargetRouter for NoopTargetRouter {
    async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
        let (target, _peer) = duplex(64);
        Ok(TargetSession::from_stream(target))
    }
}

// No-net composition test for the friend-cli guest dial: the generic
// authenticate_open_relay_stream runs over a plain duplex straight into the
// real household `serve_connection_io` (Noise/transport is covered by 2c-2b /
// 2c-3a, so it is deliberately bypassed here). The light verify closure stands
// in for the engine's authorize_session minus its slot-store / replay /
// household checks, so a regression in what the guest mints — credential_cbor
// (hash), token signature vs guest_device_pub, TTL, target_id == claw_id — or
// in the auth → health → open order makes the server reject and the guest fail.
#[tokio::test]
async fn relay_stream_authenticate_open_round_trips_against_household_server() {
    let owner = offer_kp(0x11);
    let guest = offer_kp(0x33);
    let credential = offer_credential(&owner, &guest.public());
    let offer = mint_offer(
        &owner,
        &credential,
        RelayStreamExpectedPath::RelayStream,
        OFFER_NOW + 60,
    );

    let (guest_io, claw_io) = duplex(1 << 16);

    let verify = |envelope: &AuthEnvelope, now: u64| -> Result<GuestCredential, DataTunnelError> {
        let cred: GuestCredential = cbor::from_canonical_slice(&envelope.credential_cbor)
            .map_err(|error| DataTunnelError::Cbor(error.to_string()))?;
        let expected = credential_hash(&envelope.credential_cbor);
        envelope
            .token
            .verify(&cred.guest_device_pub, &expected, now)?;
        if envelope.token.target_id != cred.claw_id {
            return Err(DataTunnelError::TokenRejected("target-mismatch".into()));
        }
        Ok(cred)
    };

    let claw = serve_connection_io(
        claw_io,
        OFFER_NOW,
        verify,
        &NoopTargetRouter,
        |_: &GuestCredential| false,
    );
    let guest_side =
        authenticate_open_relay_stream(guest_io, &offer, &guest, &credential, OFFER_NOW);

    let (claw_res, guest_res) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(claw, guest_side)
    })
    .await
    .expect("relay_stream auth round-trip should not hang");

    // The guest succeeding proves the server accepted the minted token and ran
    // auth → health → open. After open the guest drops the stream; the server
    // then ends on the client EOF.
    guest_res.expect("guest auth + health + open against household server");
    let _ = claw_res;
}

// Echo target: replies with whatever the guest sends (its "echo
// relay-stream-ok" line), then closes so run_pty_command collects the marker
// and stops promptly.
struct PtyEchoTargetRouter;

impl ClawTargetRouter for PtyEchoTargetRouter {
    async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
        let (server_side, mut target_side) = duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            if let Ok(n) = target_side.read(&mut buf).await {
                if n > 0 {
                    let _ = target_side.write_all(&buf[..n]).await;
                    let _ = target_side.flush().await;
                }
            }
            // Drop target_side -> EOF -> the server closes the client stream.
        });
        Ok(TargetSession::from_stream(server_side))
    }
}

// HTTP target: reads the guest's request, replies with a canned HTTP/1.1
// response, then closes so run_http_request collects it and stops promptly.
struct ClawSiteHttpTargetRouter;

impl ClawTargetRouter for ClawSiteHttpTargetRouter {
    async fn open(&self, _target_id: &str) -> Result<TargetSession, DataTunnelError> {
        let (server_side, mut target_side) = duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            if let Ok(n) = target_side.read(&mut buf).await {
                if n > 0 {
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\
                                        Connection: close\r\n\r\nhello";
                    let _ = target_side.write_all(response.as_bytes()).await;
                    let _ = target_side.flush().await;
                }
            }
            // Drop target_side -> EOF -> the server closes the client stream.
        });
        Ok(TargetSession::from_stream(server_side))
    }
}

// No-net composition test for the PTY payload over the relay_stream transport:
// authenticate_open_relay_stream, then run_pty_command, over a plain duplex into
// the real household serve_connection_io with an echo target. Locks the
// friend-cli composition end to end (token mint + auth -> health -> open + the
// PTY frame loop) and that the marker round-trips. Noise/transport is covered
// by 2c-2b / 2c-3a, so it is bypassed here.
#[tokio::test]
async fn relay_stream_pty_payload_round_trips_against_household_server() {
    let owner = offer_kp(0x11);
    let guest = offer_kp(0x33);
    let credential = offer_credential(&owner, &guest.public());
    let offer = mint_offer(
        &owner,
        &credential,
        RelayStreamExpectedPath::RelayStream,
        OFFER_NOW + 60,
    );

    let (guest_io, claw_io) = duplex(1 << 16);

    let verify = |envelope: &AuthEnvelope, now: u64| -> Result<GuestCredential, DataTunnelError> {
        let cred: GuestCredential = cbor::from_canonical_slice(&envelope.credential_cbor)
            .map_err(|error| DataTunnelError::Cbor(error.to_string()))?;
        let expected = credential_hash(&envelope.credential_cbor);
        envelope
            .token
            .verify(&cred.guest_device_pub, &expected, now)?;
        if envelope.token.target_id != cred.claw_id {
            return Err(DataTunnelError::TokenRejected("target-mismatch".into()));
        }
        Ok(cred)
    };

    let claw = serve_connection_io(
        claw_io,
        OFFER_NOW,
        verify,
        &PtyEchoTargetRouter,
        |_: &GuestCredential| false,
    );
    let guest_side = async {
        let mut tunnel =
            authenticate_open_relay_stream(guest_io, &offer, &guest, &credential, OFFER_NOW)
                .await?;
        run_pty_command(&mut tunnel, "echo relay-stream-ok").await
    };

    let (claw_res, guest_res) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(claw, guest_side)
    })
    .await
    .expect("relay_stream PTY round-trip should not hang");

    let output = guest_res.expect("guest PTY payload over household server");
    assert!(
        output.contains("relay-stream-ok"),
        "expected marker in PTY output, got: {output:?}"
    );
    let _ = claw_res;
}

// No-net composition test for the ClawSite payload over the relay_stream
// transport: authenticate_open_relay_stream, then run_http_request, over a
// plain duplex into the real household serve_connection_io with an HTTP
// target. Proves the guest's HTTP request and the backend's response splice
// end to end over the open tunnel (the ClawSite analog of the PTY test).
#[tokio::test]
async fn relay_stream_clawsite_payload_round_trips_against_household_server() {
    let owner = offer_kp(0x11);
    let guest = offer_kp(0x33);
    let credential = offer_credential(&owner, &guest.public());
    let offer = mint_offer(
        &owner,
        &credential,
        RelayStreamExpectedPath::RelayStream,
        OFFER_NOW + 60,
    );

    let (guest_io, claw_io) = duplex(1 << 16);

    let verify = |envelope: &AuthEnvelope, now: u64| -> Result<GuestCredential, DataTunnelError> {
        let cred: GuestCredential = cbor::from_canonical_slice(&envelope.credential_cbor)
            .map_err(|error| DataTunnelError::Cbor(error.to_string()))?;
        let expected = credential_hash(&envelope.credential_cbor);
        envelope
            .token
            .verify(&cred.guest_device_pub, &expected, now)?;
        if envelope.token.target_id != cred.claw_id {
            return Err(DataTunnelError::TokenRejected("target-mismatch".into()));
        }
        Ok(cred)
    };

    let claw = serve_connection_io(
        claw_io,
        OFFER_NOW,
        verify,
        &ClawSiteHttpTargetRouter,
        |_: &GuestCredential| false,
    );
    let guest_side = async {
        let mut tunnel =
            authenticate_open_relay_stream(guest_io, &offer, &guest, &credential, OFFER_NOW)
                .await?;
        run_http_request(&mut tunnel).await
    };

    let (claw_res, guest_res) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(claw, guest_side)
    })
    .await
    .expect("relay_stream clawsite round-trip should not hang");

    let response = guest_res.expect("guest http request over household server");
    assert!(response.starts_with("HTTP/"), "got: {response:?}");
    assert!(response.contains("200 OK"), "got: {response:?}");
    assert!(response.contains("hello"), "got: {response:?}");
    let _ = claw_res;
}

// ── Fase E2.5/E3: relay-offer REQUEST client (no-net) ────────────────────

#[test]
fn relay_offer_group_request_is_accepted_by_server_checks() {
    // Build a Group request the way friend-cli does, then verify it the EXACT
    // way the engine's handle_relay_offer_group does: the member binding holds,
    // and the device PoP verifies under binding.device_pub over the canonical
    // RelayOfferGroupReqUnsigned view. Proves the client emits a request the
    // server accepts — without a live engine.
    let member = P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap();
    let device = P256Keypair::from_secret_scalar(&[0x22; 32]).unwrap();
    let challenge = vec![0x42u8; 32];
    let req = build_relay_offer_group_request(
        challenge,
        &member as &dyn IdentityKey,
        &device,
        "npub_member_device".to_string(),
        "g".to_string(),
        "claw_alpha".to_string(),
        Some(300),
        1_800_000_000,
    )
    .unwrap();

    // Server step 1: member binding self-signature + member_id derivation.
    req.binding.verify().expect("binding must verify");
    assert_eq!(req.binding.device_pub, device.public());

    // Server step 2: device PoP over the reconstructed unsigned view.
    let unsigned = RelayOfferGroupReqUnsigned {
        v: req.v,
        challenge: &req.challenge,
        group_id: &req.group_id,
        claw_id: &req.claw_id,
        ttl_secs: req.ttl_secs,
    };
    let pop_bytes = cbor::to_canonical_vec(&unsigned).unwrap();
    verify_signature(&req.binding.device_pub, &pop_bytes, &req.device_pop)
        .expect("device PoP must verify under the bound device key");

    // A PoP checked against any other key is rejected (wrong-device guard).
    let stranger = P256Keypair::from_secret_scalar(&[0x77; 32]).unwrap();
    assert!(verify_signature(&stranger.public(), &pop_bytes, &req.device_pop).is_err());

    // Changing the challenge-bound view breaks the PoP (anti-replay binding).
    let tampered = RelayOfferGroupReqUnsigned {
        v: req.v,
        challenge: &[0x00u8; 32],
        group_id: &req.group_id,
        claw_id: &req.claw_id,
        ttl_secs: req.ttl_secs,
    };
    let tampered_bytes = cbor::to_canonical_vec(&tampered).unwrap();
    assert!(verify_signature(&req.binding.device_pub, &tampered_bytes, &req.device_pop).is_err());
}

#[test]
fn relay_offer_group_request_none_ttl_pop_round_trips() {
    // ttl_secs = None must also produce a PoP the server verifies (it
    // reconstructs the unsigned view with req.ttl_secs = None).
    let member = P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap();
    let device = P256Keypair::from_secret_scalar(&[0x44; 32]).unwrap();
    let req = build_relay_offer_group_request(
        vec![0x09u8; 32],
        &member as &dyn IdentityKey,
        &device,
        "npub".to_string(),
        "fam".to_string(),
        "claw_beta".to_string(),
        None,
        1_800_000_100,
    )
    .unwrap();
    let unsigned = RelayOfferGroupReqUnsigned {
        v: req.v,
        challenge: &req.challenge,
        group_id: &req.group_id,
        claw_id: &req.claw_id,
        ttl_secs: req.ttl_secs,
    };
    let pop_bytes = cbor::to_canonical_vec(&unsigned).unwrap();
    verify_signature(&req.binding.device_pub, &pop_bytes, &req.device_pop).unwrap();
}

#[test]
fn relay_offer_public_request_carries_dialer_device_and_claw() {
    let device = P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap();
    let req = build_relay_offer_public_request(
        vec![0x42u8; 32],
        device.public(),
        "claw_pub".to_string(),
        Some(120),
    );
    assert_eq!(req.v, RELAY_OFFER_REQ_VERSION);
    assert_eq!(req.dialer_device_pub, device.public());
    assert_eq!(req.claw_id, "claw_pub");
    assert_eq!(req.ttl_secs, Some(120));
    // Serializes to canonical CBOR (what the client POSTs).
    let bytes = cbor::to_canonical_vec(&req).unwrap();
    assert!(!bytes.is_empty());
}

#[test]
fn member_key_from_hex_round_trips_and_rejects_bad_input() {
    let kp = P256Keypair::from_secret_scalar(&[0xAB; 32]).unwrap();
    let hex = "ab".repeat(32);
    let parsed = member_key_from_hex(&hex).unwrap();
    assert_eq!(parsed.public(), kp.public());
    assert!(member_key_from_hex("deadbeef").is_err()); // too short
    assert!(member_key_from_hex(&"zz".repeat(32)).is_err()); // not hex
}

// Group dial e2e (no-net): drive the credential-less auth + ClawSite payload over a
// duplex into the household data-tunnel serve loop, with a server verifier that
// faithfully mirrors the engine's verify_relay_stream_offer_session (PoP under
// offer.guest_device_pub, hash = blake3(THIS offer), target == claw, replay).
// Proves the friend-cli Group/Public dial produces a frame the claw accepts and
// completes an HTTP response. (The REAL verifier is tested in server-rs half B;
// the real responder over Noise is the gated hardware smoke.)
#[tokio::test]
async fn group_dial_authenticates_and_runs_clawsite_against_household_server() {
    // Server-side authorized session (credential-less; correlation only).
    struct TestSession;
    impl DataTunnelSession for TestSession {
        fn session_id(&self) -> String {
            "test-session".to_string()
        }
        fn mesh_ipv6(&self) -> String {
            "fd00:c1aw::1".to_string()
        }
    }

    let owner = offer_kp(0x11);
    let device = offer_kp(0x33);
    let offer = mint_relay_stream_group_offer(
        RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
        SlotId([0x99; 16]),
        "g".to_string(),
        "g_a".to_string(),
        device.public(),
        "claw_alpha".to_string(),
        RelayStreamResource::ClawSite,
        "relay-stream://127.0.0.1:49152".to_string(),
        RelayStreamClawStaticPublicKey::try_new([0x33; 32]).unwrap(),
        OFFER_NOW + 60,
        OFFER_NOW,
        &owner as &dyn IdentityKey,
    )
    .expect("mint group offer");

    let (guest_io, claw_io) = duplex(1 << 16);
    let replay = ReplayGuard::new();
    let offer_bytes = offer.payload.to_canonical_bytes().unwrap();
    let server_guest_pub = offer.payload.guest_device_pub.clone();
    let server_claw_id = offer.payload.claw_id.clone();
    // Faithful mirror of verify_relay_stream_offer_session (server-rs).
    let verify = move |envelope: &AuthEnvelope, now: u64| -> Result<TestSession, DataTunnelError> {
        let expected = credential_hash(&offer_bytes);
        envelope.token.verify(&server_guest_pub, &expected, now)?;
        if envelope.token.target_id != server_claw_id {
            return Err(DataTunnelError::TokenRejected("target-mismatch".into()));
        }
        replay.check_and_record(&envelope.token.nonce, envelope.token.expires_at, now)?;
        Ok(TestSession)
    };

    let claw = serve_connection_io_with_auth_deadline(
        claw_io,
        OFFER_NOW,
        verify,
        &ClawSiteHttpTargetRouter,
        |_: &TestSession| false,
        std::time::Duration::from_secs(5),
    );
    let guest_side = async {
        let mut tunnel =
            authenticate_open_relay_stream_session(guest_io, &offer, &device, OFFER_NOW).await?;
        run_http_request(&mut tunnel).await
    };

    let (claw_res, guest_res) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(claw, guest_side)
    })
    .await
    .expect("group dial round-trip should not hang");

    let output = guest_res.expect("guest ClawSite payload over household server");
    assert!(
        output.starts_with("HTTP/1.1 200 OK") && output.contains("hello"),
        "expected ClawSite HTTP response, got: {output:?}"
    );
    let _ = claw_res;
}

#[test]
fn relay_offer_dial_offer_file_validates_device_matches() {
    // run_relay_offer_dial decodes the offer from CBOR bytes (the --offer-file
    // contents) and requires the dialing device key to equal the offer's
    // guest_device_pub. A public offer minted for device A round-trips and matches
    // A, and is detectably wrong for B (the fail-fast guard before dialing).
    let owner = offer_kp(0x11);
    let device_a = offer_kp(0x33);
    let device_b = offer_kp(0x44);
    let offer = mint_relay_stream_public_offer(
        RendezvousToken::try_new(vec![0x42; 16]).unwrap(),
        SlotId([0x98; 16]),
        device_a.public(),
        "claw_alpha".to_string(),
        RelayStreamResource::ClawSite,
        "relay-stream://127.0.0.1:49152".to_string(),
        RelayStreamClawStaticPublicKey::try_new([0x33; 32]).unwrap(),
        OFFER_NOW + 60,
        OFFER_NOW,
        &owner as &dyn IdentityKey,
    )
    .expect("mint public offer");

    let bytes = offer.to_canonical_bytes().unwrap();
    let decoded = RelayStreamOfferContract::from_canonical_bytes(&bytes).expect("decode offer");
    assert_eq!(decoded.payload.audience(), RelayStreamAudience::Public);
    assert_eq!(decoded.payload.guest_device_pub, device_a.public()); // matches → dial
    assert_ne!(decoded.payload.guest_device_pub, device_b.public()); // mismatch → bail
}
