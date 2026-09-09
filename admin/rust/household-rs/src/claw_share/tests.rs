#![cfg(test)]

use super::*;
use crate::ids::derive_household_id;
use crate::keys::P256Keypair;
use crate::person_cert::derive_person_id;

fn fresh_owner() -> (P256Keypair, HouseholdId, PersonId) {
    let kp = P256Keypair::generate();
    let pub_bytes = kp.public();
    let hh_id = derive_household_id(&pub_bytes);
    let p_id = derive_person_id(&pub_bytes);
    (kp, hh_id, p_id)
}

/// Cross-language fixture: a deterministic invite encoded to
/// canonical CBOR. The hex literal below MUST be identical to the
/// vector the Swift `ClawShareCodecTests.swift` fixture asserts.
/// If you change the wire shape, regenerate both sides together.
///
/// Deterministic inputs:
/// - owner key: P-256 with secret scalar = [0x11; 32]
/// - slot_id:   [0x22; 16]
/// - expires_at: 1_800_000_000
/// - claw_id:    "claw_fixture_v1"
/// - transport:  Loopback { channel: "ch-fixture" }
/// - owner_engine_npub: "npub_engine_fixture"
/// - claim_relays:  ["wss://relay-a", "wss://relay-b"]
#[test]
fn cross_language_fixture_invite_hex() {
    let scalar = [0x11u8; 32];
    let owner_key = P256Keypair::from_secret_scalar(&scalar).expect("key");
    let pub_bytes = owner_key.public();
    let hh_id = derive_household_id(&pub_bytes);
    let owner_p_id = derive_person_id(&pub_bytes);
    let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
    let invite = ClawShareInvite::sign(
        hh_id,
        owner_p_id,
        owner_key.public(),
        "claw_fixture_v1".to_string(),
        slot_id,
        TunnelHandle::Loopback {
            channel: "ch-fixture".to_string(),
        },
        1_800_000_000,
        "npub_engine_fixture".to_string(),
        vec!["wss://relay-a".to_string(), "wss://relay-b".to_string()],
        &owner_key,
    )
    .expect("sign");
    let bytes = cbor::to_canonical_vec(&invite).expect("encode");
    let hex_actual = hex::encode(&bytes);
    // To regenerate after a wire-shape change:
    //   eprintln!("{hex_actual}");
    // The Swift counterpart pins this same hex via
    // `ClawShareCodecTests.cross_language_fixture_invite_hex`.
    let expected = ClawShareInvite::from_uri(&invite.to_uri().unwrap()).expect("decode self");
    assert_eq!(invite, expected, "self round-trip");
    // The hex is pinned by length: a wire-shape change visibly
    // mutates the byte length, and the matching Swift test will
    // also fail. We don't pin the full hex here because key
    // generation from a fixed scalar is the only non-portable
    // step — the signature varies if either side regenerates with
    // different `rfc6979` deps. The portable invariant is "Swift
    // can decode the Rust output AND the unsigned bytes match".
    let unsigned_bytes = cbor::to_canonical_vec(&ClawShareInviteUnsigned {
        v: invite.v,
        kind: &invite.kind,
        hh_id: &invite.hh_id,
        owner_p_id: &invite.owner_p_id,
        owner_p_pub: &invite.owner_p_pub,
        claw_id: &invite.claw_id,
        slot_id: &invite.slot_id,
        transport_hint: &invite.transport_hint,
        expires_at: invite.expires_at,
        owner_engine_npub: &invite.owner_engine_npub,
        claim_relays: &invite.claim_relays,
    })
    .expect("encode unsigned");
    let unsigned_hex = hex::encode(&unsigned_bytes);

    // Pinned cross-language fixture: the SAME hex literal lives
    // in `Packages/SoyehtCore/Tests/SoyehtCoreTests/
    // ClawShareCrossLanguageFixtureTests.swift`. If a wire-shape
    // change makes them diverge, both tests fail loudly. To
    // regenerate after an intentional wire-shape change, run this
    // test with `--nocapture` and copy the printed hex to both
    // files in lockstep.
    const EXPECTED_UNSIGNED_HEX: &str = "ab617601646b696e6471636c61772d73686172652f696e766974656568685f6964783768685f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e32783232337232716636616769727167636c61775f69646f636c61775f666978747572655f763167736c6f745f696450222222222222222222222222222222226a657870697265735f61741a6b49d2006a6f776e65725f705f69647836705f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e3278323233723271663661676972716b6f776e65725f705f7075625821020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed6c636c61696d5f72656c617973826d7773733a2f2f72656c61792d616d7773733a2f2f72656c61792d626e7472616e73706f72745f68696e74a2646b696e64686c6f6f706261636b676368616e6e656c6a63682d66697874757265716f776e65725f656e67696e655f6e707562736e7075625f656e67696e655f66697874757265";
    assert_eq!(
        unsigned_hex, EXPECTED_UNSIGNED_HEX,
        "wire shape drift — Swift fixture is now stale"
    );

    // Determinism check inside the same compilation: re-encoding
    // the decoded invite must produce identical bytes.
    let re = cbor::to_canonical_vec(&invite).expect("re-encode");
    assert_eq!(re, bytes, "canonical encoding is not deterministic");
    let _ = hex_actual;
}

// The two L3-overlay cross-language tunnel-handle fixtures are
// intentionally omitted from this relay/membership subset: that
// overlay transport variant is not part of this landing.

/// Cross-language fixture: deterministic `ClawShareClaim` unsigned
/// canonical CBOR. Same lockstep contract as the invite fixture —
/// the Swift counterpart in
/// `ClawShareCrossLanguageFixtureTests.testUnsignedClaimCBORMatchesRustFixture`
/// pins this same hex.
#[test]
fn cross_language_fixture_claim_hex() {
    let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
    let guest_scalar = [0x33u8; 32];
    let guest_key = P256Keypair::from_secret_scalar(&guest_scalar).expect("guest key");
    let guest_device_pub = guest_key.public();
    let nonce = ClaimNonce([0x44u8; NONCE_LEN]);
    let timestamp: u64 = 1_800_000_500;
    let unsigned = ClawShareClaimUnsigned {
        v: CLAW_SHARE_CLAIM_VERSION,
        kind: CLAIM_KIND,
        slot_id: &slot_id,
        guest_device_pub: &guest_device_pub,
        nonce: &nonce,
        timestamp,
        // None → skipped → byte-identical to a pre-mesh claim (a6 = 6-entry
        // map). This pins the backward-compat guarantee.
        participant_npub: None,
    };
    let bytes = cbor::to_canonical_vec(&unsigned).expect("encode");
    let unsigned_hex = hex::encode(&bytes);
    const EXPECTED_UNSIGNED_HEX: &str = "a6617601646b696e6470636c61772d73686172652f636c61696d656e6f6e63655820444444444444444444444444444444444444444444444444444444444444444467736c6f745f696450222222222222222222222222222222226974696d657374616d701a6b49d3f47067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d";
    assert_eq!(
        unsigned_hex, EXPECTED_UNSIGNED_HEX,
        "claim wire shape drift — Swift fixture is now stale"
    );
    let re = cbor::to_canonical_vec(&unsigned).expect("re-encode");
    assert_eq!(re, bytes);
}

#[test]
fn claim_participant_npub_is_signed_and_tamper_proof() {
    let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
    let guest_key = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("guest key");
    let guest_device_pub = guest_key.public();
    let nonce = ClaimNonce([0x44u8; NONCE_LEN]);
    let ts: u64 = 1_800_000_500;
    let npub = "82f283e20094eb4da5922cfba6c0284b790525f4d4ddb2d17fd98f1bd0956c02";

    let claim = ClawShareClaim::sign_with_participant(
        slot_id.clone(),
        guest_device_pub.clone(),
        nonce.clone(),
        ts,
        Some(npub.to_string()),
        &guest_key as &dyn IdentityKey,
    )
    .expect("sign");
    claim.verify(ts).expect("verify");
    assert_eq!(claim.participant_npub.as_deref(), Some(npub));

    // The npub is inside the signed payload: swapping it (a MITM trying to
    // gain mesh routing under their own npub) breaks verification.
    let mut tampered = claim.clone();
    tampered.participant_npub = Some("00".repeat(32));
    assert!(matches!(
        tampered.verify(ts),
        Err(ClawShareError::ClaimSignatureRejected)
    ));

    // Dropping it from a claim that signed WITH it also fails — bound, not
    // advisory.
    let mut dropped = claim.clone();
    dropped.participant_npub = None;
    assert!(matches!(
        dropped.verify(ts),
        Err(ClawShareError::ClaimSignatureRejected)
    ));

    // Cross-language fixture: Some-variant unsigned CBOR (a7 = 7-entry map;
    // participant_npub sorts last). Swift must pin the same hex.
    let unsigned = ClawShareClaimUnsigned {
        v: CLAW_SHARE_CLAIM_VERSION,
        kind: CLAIM_KIND,
        slot_id: &slot_id,
        guest_device_pub: &guest_device_pub,
        nonce: &nonce,
        timestamp: ts,
        participant_npub: Some(npub),
    };
    let hex = hex::encode(cbor::to_canonical_vec(&unsigned).expect("encode"));
    const EXPECTED_WITH_NPUB_HEX: &str = "a7617601646b696e6470636c61772d73686172652f636c61696d656e6f6e63655820444444444444444444444444444444444444444444444444444444444444444467736c6f745f696450222222222222222222222222222222226974696d657374616d701a6b49d3f47067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d707061727469636970616e745f6e707562784038326632383365323030393465623464613539323263666261366330323834623739303532356634643464646232643137666439386631626430393536633032";
    assert_eq!(hex, EXPECTED_WITH_NPUB_HEX, "Some-variant claim wire hex");
}

// ─── Group claim (Path-A) — wire shape + byte-stability ──────────────────

fn group_test_keys() -> (P256Keypair, P256Keypair) {
    let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).expect("member key");
    let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("device key");
    (member, device)
}

fn sample_group_request() -> GroupClaimRequest {
    let (member, device) = group_test_keys();
    let binding = MemberDeviceBinding::sign(
        &member as &dyn IdentityKey,
        device.public(),
        "npub_member_alpha".to_string(),
        1_800_000_000,
    )
    .expect("sign binding");
    GroupClaimRequest::sign(
        binding,
        "group_alpha".to_string(),
        "claw_alpha".to_string(),
        vec![0x66u8; 32],
        Some(600),
        &device as &dyn IdentityKey,
    )
    .expect("sign group request")
}

#[test]
fn group_request_round_trips_and_device_pop_verifies() {
    let req = sample_group_request();
    req.binding.verify().expect("binding verifies");
    req.verify_device_pop().expect("device pop verifies");

    let bytes = cbor::to_canonical_vec(&req).expect("encode");
    let decoded: GroupClaimRequest = cbor::from_canonical_slice(&bytes).expect("decode");
    assert_eq!(decoded, req);
    decoded.verify_device_pop().expect("decoded pop verifies");
}

#[test]
fn group_request_device_pop_is_bound_to_group_claw_and_challenge() {
    let base = sample_group_request();

    let mut wrong_group = base.clone();
    wrong_group.group_id = "group_beta".to_string();
    assert!(wrong_group.binding.verify().is_ok());
    assert!(matches!(
        wrong_group.verify_device_pop(),
        Err(ClawShareError::GroupDevicePopRejected)
    ));

    let mut wrong_claw = base.clone();
    wrong_claw.claw_id = "claw_beta".to_string();
    assert!(matches!(
        wrong_claw.verify_device_pop(),
        Err(ClawShareError::GroupDevicePopRejected)
    ));

    let mut wrong_challenge = base.clone();
    wrong_challenge.challenge = vec![0x77u8; 32];
    assert!(matches!(
        wrong_challenge.verify_device_pop(),
        Err(ClawShareError::GroupDevicePopRejected)
    ));

    let mut wrong_ttl = base;
    wrong_ttl.ttl_secs = Some(601);
    assert!(matches!(
        wrong_ttl.verify_device_pop(),
        Err(ClawShareError::GroupDevicePopRejected)
    ));
}

#[test]
fn group_request_sign_rejects_device_key_not_in_binding() {
    let (member, device) = group_test_keys();
    let binding = MemberDeviceBinding::sign(
        &member as &dyn IdentityKey,
        device.public(),
        "npub_member_alpha".to_string(),
        1_800_000_000,
    )
    .unwrap();
    let other = P256Keypair::from_secret_scalar(&[0x99u8; 32]).unwrap();
    assert!(matches!(
        GroupClaimRequest::sign(
            binding,
            "group_alpha".to_string(),
            "claw_alpha".to_string(),
            vec![0x66u8; 32],
            Some(600),
            &other as &dyn IdentityKey,
        ),
        Err(ClawShareError::GroupDeviceKeyMismatch)
    ));
}

#[test]
fn group_claim_round_trips_and_device_fields_verify() {
    let req = sample_group_request();
    let (_member, device) = group_test_keys();
    let nonce = ClaimNonce([0x44u8; NONCE_LEN]);
    let ts: u64 = 1_800_000_500;
    let claim =
        ClawShareClaim::sign_group(device.public(), nonce, ts, req, &device as &dyn IdentityKey)
            .expect("sign group claim");

    claim.verify(ts).expect("device-field signature verifies");
    assert_eq!(claim.slot_id, SlotId([0u8; SLOT_ID_LEN]));
    assert!(claim.participant_npub.is_none());

    let gr = claim.group_request.as_ref().expect("group request present");
    gr.binding.verify().expect("binding verifies");
    gr.verify_device_pop().expect("device pop verifies");

    let bytes = cbor::to_canonical_vec(&claim).expect("encode claim");
    let decoded: ClawShareClaim = cbor::from_canonical_slice(&bytes).expect("decode claim");
    assert_eq!(decoded, claim);
}

#[test]
fn sign_group_rejects_guest_device_pub_not_matching_binding() {
    let req = sample_group_request();
    let nonce = ClaimNonce([0x44u8; NONCE_LEN]);
    let ts: u64 = 1_800_000_500;
    let other = P256Keypair::from_secret_scalar(&[0x99u8; 32]).unwrap();
    assert!(matches!(
        ClawShareClaim::sign_group(other.public(), nonce, ts, req, &other as &dyn IdentityKey),
        Err(ClawShareError::GroupDeviceKeyMismatch)
    ));
}

#[test]
fn device_claim_signed_bytes_unchanged_by_group_request_field() {
    let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
    let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("device key");
    let guest_device_pub = device.public();
    let nonce = ClaimNonce([0x44u8; NONCE_LEN]);
    let timestamp: u64 = 1_800_000_500;
    let unsigned = ClawShareClaimUnsigned {
        v: CLAW_SHARE_CLAIM_VERSION,
        kind: CLAIM_KIND,
        slot_id: &slot_id,
        guest_device_pub: &guest_device_pub,
        nonce: &nonce,
        timestamp,
        participant_npub: None,
    };
    let hex = hex::encode(cbor::to_canonical_vec(&unsigned).expect("encode"));
    const EXPECTED_UNSIGNED_HEX: &str = "a6617601646b696e6470636c61772d73686172652f636c61696d656e6f6e63655820444444444444444444444444444444444444444444444444444444444444444467736c6f745f696450222222222222222222222222222222226974696d657374616d701a6b49d3f47067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d";
    assert_eq!(
        hex, EXPECTED_UNSIGNED_HEX,
        "Device claim signing bytes drifted"
    );

    let claim = ClawShareClaim::sign(
        slot_id,
        guest_device_pub,
        nonce,
        timestamp,
        &device as &dyn IdentityKey,
    )
    .expect("sign device claim");
    assert!(claim.group_request.is_none());
    let bytes = cbor::to_canonical_vec(&claim).expect("encode");
    let decoded: ClawShareClaim = cbor::from_canonical_slice(&bytes).expect("decode");
    assert_eq!(decoded, claim);
}

#[test]
fn cross_language_fixture_group_claim_hex() {
    let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("device key");
    let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).expect("member key");
    let member_pub = member.public();
    let device_pub = device.public();
    let member_id = crate::member_identity::derive_member_id(&member_pub);
    let binding = MemberDeviceBinding {
        v: 1,
        kind: "claw-share/member-device/v1".to_string(),
        member_id,
        member_pub,
        device_pub: device_pub.clone(),
        participant_npub: "82f283e20094eb4da5922cfba6c0284b790525f4d4ddb2d17fd98f1bd0956c02"
            .to_string(),
        issued_at: 1_800_000_000,
        member_signature: P256Signature([0xABu8; 64]),
    };
    let group_request = GroupClaimRequest {
        v: CLAW_SHARE_GROUP_REQUEST_VERSION,
        challenge: vec![0x66u8; 32],
        binding,
        group_id: "group_alpha".to_string(),
        claw_id: "claw_alpha".to_string(),
        device_pop: P256Signature([0xCDu8; 64]),
        ttl_secs: Some(600),
    };
    let claim = ClawShareClaim {
        v: CLAW_SHARE_CLAIM_VERSION,
        kind: CLAIM_KIND.to_string(),
        slot_id: SlotId([0u8; SLOT_ID_LEN]),
        guest_device_pub: device_pub,
        nonce: ClaimNonce([0x44u8; NONCE_LEN]),
        timestamp: 1_800_000_500,
        participant_npub: None,
        group_request: Some(group_request),
        guest_signature: P256Signature([0xEFu8; 64]),
    };
    let hex = hex::encode(cbor::to_canonical_vec(&claim).expect("encode"));
    const EXPECTED_GROUP_CLAIM_HEX: &str = "a8617601646b696e6470636c61772d73686172652f636c61696d656e6f6e63655820444444444444444444444444444444444444444444444444444444444444444467736c6f745f696450000000000000000000000000000000006974696d657374616d701a6b49d3f46d67726f75705f72657175657374a76176016762696e64696e67a8617601646b696e64781b636c61772d73686172652f6d656d6265722d6465766963652f7631696973737565645f61741a6b49d200696d656d6265725f69647836675f6c65717a6d6f6869357363377665746d3361616a64743274707061736767356f717576666a73366c78736670346c6a686a3670716a6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d6a6d656d6265725f70756258210257e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34706d656d6265725f7369676e61747572655840abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab707061727469636970616e745f6e70756278403832663238336532303039346562346461353932326366626136633032383462373930353235663464346464623264313766643938663162643039353663303267636c61775f69646a636c61775f616c7068616867726f75705f69646b67726f75705f616c7068616874746c5f73656373190258696368616c6c656e6765582066666666666666666666666666666666666666666666666666666666666666666a6465766963655f706f705840cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd6f67756573745f7369676e61747572655840efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef7067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d";
    assert_eq!(
        hex, EXPECTED_GROUP_CLAIM_HEX,
        "group claim wire shape drift — Swift fixture is now stale"
    );
}

#[test]
fn group_ack_round_trips_credential_less() {
    let ack = ClawShareGroupAck {
        v: CLAW_SHARE_GROUP_ACK_VERSION,
        relay_stream_offer: serde_bytes::ByteBuf::from(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };
    let bytes = cbor::to_canonical_vec(&ack).expect("encode");
    let decoded: ClawShareGroupAck = cbor::from_canonical_slice(&bytes).expect("decode");
    assert_eq!(decoded, ack);
    assert_eq!(decoded.v, CLAW_SHARE_GROUP_ACK_VERSION);
}

fn relay_offer_ack(offer: Option<serde_bytes::ByteBuf>) -> ClawShareAck {
    let owner_key = P256Keypair::from_secret_scalar(&[0x11u8; 32]).expect("key");
    let guest_key = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("guest key");
    let credential = GuestCredential::sign(
        derive_household_id(&owner_key.public()),
        derive_person_id(&owner_key.public()),
        owner_key.public(),
        "claw_relay_offer_fixture".to_string(),
        guest_key.public(),
        SlotId([0x22u8; SLOT_ID_LEN]),
        1_800_000_500,
        1_800_010_500,
        &owner_key,
    )
    .expect("sign credential");
    ClawShareAck {
        v: GUEST_CREDENTIAL_VERSION,
        credential,
        tunnel: TunnelHandle::Loopback {
            channel: "ch-relay-offer".to_string(),
        },
        relay_stream_offer: offer,
    }
}

#[test]
fn claw_share_ack_omits_relay_stream_offer_when_none() {
    // A `None` offer is omitted on the wire (skip_serializing_if), so the ack
    // is byte-identical to the pre-C7c shape and round-trips to `None`.
    let ack = relay_offer_ack(None);
    let bytes = cbor::to_canonical_vec(&ack).expect("encode");
    let decoded: ClawShareAck = cbor::from_canonical_slice(&bytes).expect("decode");
    assert_eq!(decoded, ack);
    assert!(decoded.relay_stream_offer.is_none());

    // A pre-C7c-shaped decoder (deny_unknown_fields, no offer field) must
    // also accept the bytes: proof the `None` ack carries no extra field.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct LegacyAck {
        v: u8,
        credential: GuestCredential,
        tunnel: TunnelHandle,
    }
    let _legacy: LegacyAck =
        cbor::from_canonical_slice(&bytes).expect("legacy decoder accepts a None ack");
}

#[test]
fn claw_share_ack_round_trips_relay_stream_offer_when_present() {
    // When present, the opaque bytes round-trip intact (the C7c-1 forward path).
    let offer = serde_bytes::ByteBuf::from(vec![0xAB, 0xCD, 0xEF, 0x01]);
    let ack = relay_offer_ack(Some(offer.clone()));
    let bytes = cbor::to_canonical_vec(&ack).expect("encode");
    let decoded: ClawShareAck = cbor::from_canonical_slice(&bytes).expect("decode");
    assert_eq!(decoded, ack);
    assert_eq!(decoded.relay_stream_offer, Some(offer));
}

/// Cross-language fixture: deterministic `ClawShareAck` canonical
/// CBOR. The Ack wraps a `GuestCredential` (already pinned) plus
/// the engine's `TunnelHandle`. The fixture encodes a fully-signed
/// credential — owner signature is computed deterministically from
/// the same secret scalar = [0x11; 32] — so the byte vector below
/// covers the full ack as it lands on the wire to the friend.
#[test]
fn cross_language_fixture_ack_hex() {
    let scalar = [0x11u8; 32];
    let owner_key = P256Keypair::from_secret_scalar(&scalar).expect("key");
    let pub_bytes = owner_key.public();
    let hh_id = derive_household_id(&pub_bytes);
    let owner_p_id = derive_person_id(&pub_bytes);
    let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
    let guest_scalar = [0x33u8; 32];
    let guest_key = P256Keypair::from_secret_scalar(&guest_scalar).expect("guest key");
    let guest_device_pub = guest_key.public();
    let credential = GuestCredential::sign(
        hh_id.clone(),
        owner_p_id.clone(),
        owner_key.public(),
        "claw_fixture_v1".to_string(),
        guest_device_pub.clone(),
        slot_id,
        1_800_000_500,
        1_800_010_500,
        &owner_key,
    )
    .expect("sign credential");
    let ack = ClawShareAck {
        v: GUEST_CREDENTIAL_VERSION,
        credential,
        tunnel: TunnelHandle::Loopback {
            channel: "ch-fixture-ack".to_string(),
        },
        relay_stream_offer: None,
    };
    // The credential's owner_signature varies by RNG-free
    // determinism of `rfc6979` between Rust and Swift, so we pin
    // only the wire SHAPE here via a roundtrip + the unsigned
    // sub-structure (credential body + tunnel). The full bytes
    // are determinism-checked end-to-end.
    let ack_bytes = cbor::to_canonical_vec(&ack).expect("encode ack");
    let re = cbor::to_canonical_vec(&ack).expect("re-encode");
    assert_eq!(ack_bytes, re, "canonical encoding non-deterministic");

    // The portable cross-language vector is the ack shape WITHOUT
    // the owner signature on the credential — that's the byte
    // sequence both Rust and Swift can reproduce from the same
    // deterministic inputs. We assemble the map by hand here so
    // we don't have to introduce a one-off serde struct.
    #[derive(Serialize)]
    #[serde(deny_unknown_fields)]
    struct AckUnsigned<'a> {
        v: u8,
        credential: GuestCredentialUnsigned<'a>,
        tunnel: &'a TunnelHandle,
    }
    let unsigned = AckUnsigned {
        v: ack.v,
        credential: GuestCredentialUnsigned {
            v: ack.credential.v,
            kind: &ack.credential.kind,
            hh_id: &ack.credential.hh_id,
            owner_p_id: &ack.credential.owner_p_id,
            owner_p_pub: &ack.credential.owner_p_pub,
            claw_id: &ack.credential.claw_id,
            guest_device_pub: &ack.credential.guest_device_pub,
            slot_id: &ack.credential.slot_id,
            issued_at: ack.credential.issued_at,
            expires_at: ack.credential.expires_at,
        },
        tunnel: &ack.tunnel,
    };
    let unsigned_bytes = cbor::to_canonical_vec(&unsigned).expect("encode unsigned");
    let unsigned_hex = hex::encode(&unsigned_bytes);
    const EXPECTED_UNSIGNED_HEX: &str = "a36176016674756e6e656ca2646b696e64686c6f6f706261636b676368616e6e656c6e63682d666978747572652d61636b6a63726564656e7469616caa617601646b696e64781b636c61772d73686172652f67756573742d63726564656e7469616c6568685f6964783768685f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e32783232337232716636616769727167636c61775f69646f636c61775f666978747572655f763167736c6f745f69645022222222222222222222222222222222696973737565645f61741a6b49d3f46a657870697265735f61741a6b49fb046a6f776e65725f705f69647836705f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e3278323233723271663661676972716b6f776e65725f705f7075625821020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed7067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d";
    assert_eq!(
        unsigned_hex, EXPECTED_UNSIGNED_HEX,
        "ack wire shape drift — Swift fixture is now stale"
    );
}

/// Cross-language fixture: deterministic `GuestCredential` unsigned
/// canonical CBOR.
#[test]
fn cross_language_fixture_guest_credential_hex() {
    let scalar = [0x11u8; 32];
    let owner_key = P256Keypair::from_secret_scalar(&scalar).expect("key");
    let pub_bytes = owner_key.public();
    let hh_id = derive_household_id(&pub_bytes);
    let owner_p_id = derive_person_id(&pub_bytes);
    let slot_id = SlotId([0x22u8; SLOT_ID_LEN]);
    let guest_scalar = [0x33u8; 32];
    let guest_key = P256Keypair::from_secret_scalar(&guest_scalar).expect("guest key");
    let guest_device_pub = guest_key.public();
    let unsigned = GuestCredentialUnsigned {
        v: GUEST_CREDENTIAL_VERSION,
        kind: CREDENTIAL_KIND,
        hh_id: &hh_id,
        owner_p_id: &owner_p_id,
        owner_p_pub: &pub_bytes,
        claw_id: "claw_fixture_v1",
        guest_device_pub: &guest_device_pub,
        slot_id: &slot_id,
        issued_at: 1_800_000_500,
        expires_at: 1_800_010_500,
    };
    let bytes = cbor::to_canonical_vec(&unsigned).expect("encode");
    let unsigned_hex = hex::encode(&bytes);
    const EXPECTED_UNSIGNED_HEX: &str = "aa617601646b696e64781b636c61772d73686172652f67756573742d63726564656e7469616c6568685f6964783768685f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e32783232337232716636616769727167636c61775f69646f636c61775f666978747572655f763167736c6f745f69645022222222222222222222222222222222696973737565645f61741a6b49d3f46a657870697265735f61741a6b49fb046a6f776e65725f705f69647836705f6a707173797570796f747268676175343579376e6575336c3370346c65723678687537646e3278323233723271663661676972716b6f776e65725f705f7075625821020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed7067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d";
    assert_eq!(
        unsigned_hex, EXPECTED_UNSIGNED_HEX,
        "credential wire shape drift — Swift fixture is now stale"
    );
    let re = cbor::to_canonical_vec(&unsigned).expect("re-encode");
    assert_eq!(re, bytes);
}

#[test]
fn invite_round_trip_and_verify() {
    let (owner_key, hh_id, owner_p_id) = fresh_owner();
    let slot_id = SlotId::random();
    let invite = ClawShareInvite::sign(
        hh_id.clone(),
        owner_p_id.clone(),
        owner_key.public(),
        "claw_test".to_string(),
        slot_id.clone(),
        TunnelHandle::Loopback {
            channel: "test-channel".to_string(),
        },
        2_000_000_000,
        String::new(),
        Vec::new(),
        &owner_key,
    )
    .expect("sign invite");

    let bytes = cbor::to_canonical_vec(&invite).expect("encode invite");
    let decoded: ClawShareInvite = cbor::from_canonical_slice(&bytes).expect("decode invite");
    assert_eq!(invite, decoded);

    decoded.verify(1_000_000_000).expect("invite verifies");
}

#[test]
fn invite_tamper_detection() {
    let (owner_key, hh_id, owner_p_id) = fresh_owner();
    let mut invite = ClawShareInvite::sign(
        hh_id,
        owner_p_id,
        owner_key.public(),
        "claw_a".to_string(),
        SlotId::random(),
        TunnelHandle::Loopback {
            channel: "c".to_string(),
        },
        2_000_000_000,
        String::new(),
        Vec::new(),
        &owner_key,
    )
    .expect("sign");
    // Flip the claw_id — signature now covers a different value.
    invite.claw_id = "claw_b".to_string();
    let err = invite
        .verify(1_000_000_000)
        .expect_err("tamper must reject");
    assert!(matches!(err, ClawShareError::InviteSignatureRejected));
}

#[test]
fn invite_expiry_rejected() {
    let (owner_key, hh_id, owner_p_id) = fresh_owner();
    let invite = ClawShareInvite::sign(
        hh_id,
        owner_p_id,
        owner_key.public(),
        "claw_a".to_string(),
        SlotId::random(),
        TunnelHandle::Loopback {
            channel: "c".to_string(),
        },
        1_000,
        String::new(),
        Vec::new(),
        &owner_key,
    )
    .expect("sign");
    let err = invite.verify(2_000).expect_err("expired must reject");
    assert!(matches!(err, ClawShareError::InviteExpired));
}

#[test]
fn claim_round_trip_and_verify() {
    let guest_key = P256Keypair::generate();
    let claim = ClawShareClaim::sign(
        SlotId::random(),
        guest_key.public(),
        ClaimNonce::random(),
        1_000_000_000,
        &guest_key,
    )
    .expect("sign claim");
    claim.verify(1_000_000_000).expect("claim verifies");
    claim.verify(1_000_000_059).expect("inside skew window");
    let err = claim
        .verify(1_000_000_061)
        .expect_err("outside skew rejected");
    assert!(matches!(err, ClawShareError::ClaimReplayWindow { .. }));
}

#[test]
fn claim_tamper_detection() {
    let guest_key = P256Keypair::generate();
    let other_guest = P256Keypair::generate();
    let mut claim = ClawShareClaim::sign(
        SlotId::random(),
        guest_key.public(),
        ClaimNonce::random(),
        1_000_000_000,
        &guest_key,
    )
    .expect("sign");
    // Substitute another guest's pubkey — verify must fail.
    claim.guest_device_pub = other_guest.public();
    let err = claim
        .verify(1_000_000_000)
        .expect_err("substituted pub must reject");
    assert!(matches!(err, ClawShareError::ClaimSignatureRejected));
}

#[test]
fn credential_round_trip_and_verify() {
    let (owner_key, hh_id, owner_p_id) = fresh_owner();
    let guest_key = P256Keypair::generate();
    let cred = GuestCredential::sign(
        hh_id,
        owner_p_id,
        owner_key.public(),
        "claw_a".to_string(),
        guest_key.public(),
        SlotId::random(),
        1_000_000_000,
        1_000_000_000 + 3600,
        &owner_key,
    )
    .expect("sign cred");
    cred.verify(1_000_001_000).expect("cred verifies");

    let bytes = cbor::to_canonical_vec(&cred).expect("encode cred");
    let decoded: GuestCredential = cbor::from_canonical_slice(&bytes).expect("decode cred");
    assert_eq!(cred, decoded);
}

#[test]
fn credential_lifetime_cap_enforced() {
    let (owner_key, hh_id, owner_p_id) = fresh_owner();
    let guest_key = P256Keypair::generate();
    let err = GuestCredential::sign(
        hh_id,
        owner_p_id,
        owner_key.public(),
        "claw_a".to_string(),
        guest_key.public(),
        SlotId::random(),
        1_000_000_000,
        1_000_000_000 + MAX_CREDENTIAL_TTL_SECS + 1,
        &owner_key,
    )
    .expect_err("over-cap lifetime must reject");
    assert!(matches!(
        err,
        ClawShareError::CredentialLifetimeExceedsCap { .. }
    ));
}

#[test]
fn slot_store_atomic_consume() {
    let (_, _, _) = fresh_owner();
    let guest_key = P256Keypair::generate();
    let other_guest = P256Keypair::generate();
    let store = ClawShareSlotStore::new();
    let slot_id = SlotId::random();
    store
        .insert(SlotRecord {
            slot_id: slot_id.clone(),
            claw_id: "claw_a".to_string(),
            expires_at: 2_000_000_000,
            state: SlotState::Open,
            app_presentation: None,
            created_at: None,
        })
        .expect("insert");

    // First consume wins.
    let consumed = store
        .consume_atomic(&slot_id, "claw_a", guest_key.public(), 1_000_000_000)
        .expect("first consume");
    assert!(matches!(consumed.state, SlotState::Consumed { .. }));

    // Second consume rejects.
    let err = store
        .consume_atomic(&slot_id, "claw_a", other_guest.public(), 1_000_000_001)
        .expect_err("second consume must reject");
    assert!(matches!(err, ClawShareError::SlotAlreadyConsumed));
}

#[test]
fn slot_store_rejects_claw_mismatch() {
    let guest_key = P256Keypair::generate();
    let store = ClawShareSlotStore::new();
    let slot_id = SlotId::random();
    store
        .insert(SlotRecord {
            slot_id: slot_id.clone(),
            claw_id: "claw_a".to_string(),
            expires_at: 2_000_000_000,
            state: SlotState::Open,
            app_presentation: None,
            created_at: None,
        })
        .expect("insert");

    let err = store
        .consume_atomic(&slot_id, "claw_b", guest_key.public(), 1_000_000_000)
        .expect_err("claw mismatch must reject");
    assert!(matches!(err, ClawShareError::SlotClawMismatch));
}

#[test]
fn owner_mint_invite_is_atomic() {
    let (owner_key, hh_id, owner_p_id) = fresh_owner();
    let store = ClawShareSlotStore::new();
    let invite = owner_mint_invite(
        &owner_key,
        &owner_p_id,
        &hh_id,
        "claw_atomic",
        TunnelHandle::Loopback {
            channel: "ch".to_string(),
        },
        300,
        1_000_000_000,
        String::new(),
        Vec::new(),
        &store,
    )
    .expect("mint");

    invite.verify(1_000_000_001).expect("invite verifies");
    let slot = store.get(&invite.slot_id).expect("slot present");
    assert_eq!(slot.claw_id, "claw_atomic");
    assert!(matches!(slot.state, SlotState::Open));
    assert_eq!(slot.expires_at, invite.expires_at);
    // Legacy wrapper leaves no presentation.
    assert!(slot.app_presentation.is_none());
}

#[test]
fn owner_mint_invite_with_presentation_persists_snapshot() {
    use crate::claw_share::relay_stream_contract::ShareableAppPresentation;

    let (owner_key, hh_id, owner_p_id) = fresh_owner();
    let store = ClawShareSlotStore::new();
    let app_id = "app_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let presentation = ShareableAppPresentation::try_new(app_id.clone(), "Study", "Caio").unwrap();

    let invite = owner_mint_invite_with_presentation(
        &owner_key,
        &owner_p_id,
        &hh_id,
        &app_id,
        TunnelHandle::Loopback {
            channel: "ch".to_string(),
        },
        300,
        1_000_000_000,
        String::new(),
        Vec::new(),
        &store,
        Some(presentation),
    )
    .expect("mint");

    let slot = store.get(&invite.slot_id).expect("slot present");
    let stored = slot
        .app_presentation
        .as_ref()
        .expect("presentation must be persisted in the SlotRecord");
    assert_eq!(stored.app_id, app_id);
    assert_eq!(stored.display_name, "Study");
    assert_eq!(stored.owner_display_name, "Caio");
}

#[test]
fn mint_caps_ttl_at_max() {
    let (owner_key, hh_id, owner_p_id) = fresh_owner();
    let store = ClawShareSlotStore::new();
    let invite = owner_mint_invite(
        &owner_key,
        &owner_p_id,
        &hh_id,
        "claw_cap",
        TunnelHandle::Loopback {
            channel: "c".to_string(),
        },
        MAX_INVITE_TTL_SECS * 10, // request way more than the cap
        1_000_000_000,
        String::new(),
        Vec::new(),
        &store,
    )
    .expect("mint");
    assert_eq!(invite.expires_at, 1_000_000_000 + MAX_INVITE_TTL_SECS);
}

#[test]
fn invite_uri_round_trip_preserves_signature() {
    let (owner_key, hh_id, owner_p_id) = fresh_owner();
    let store = ClawShareSlotStore::new();
    let invite = owner_mint_invite(
        &owner_key,
        &owner_p_id,
        &hh_id,
        "claw_uri",
        TunnelHandle::Direct {
            host: "192.0.2.10".to_string(),
            port: 7423,
        },
        300,
        1_000_000_000,
        "npub1engine".to_string(),
        vec!["wss://relay.theyos.net".to_string()],
        &store,
    )
    .expect("mint");

    let uri = invite.to_uri().expect("encode uri");
    assert!(uri.starts_with(CLAW_SHARE_URI_PREFIX));

    let decoded = ClawShareInvite::from_uri(&uri).expect("decode uri");
    assert_eq!(invite, decoded);
    decoded.verify(1_000_000_001).expect("decoded verifies");
}

#[test]
fn malformed_uri_rejected() {
    let err =
        ClawShareInvite::from_uri("https://example.com/foo").expect_err("wrong scheme must reject");
    assert!(matches!(err, ClawShareError::UriMalformed));

    let err = ClawShareInvite::from_uri("soyeht://claw-share/v1?e=not-base64!!")
        .expect_err("malformed base64 must reject");
    assert!(matches!(err, ClawShareError::UriMalformed));

    let err = ClawShareInvite::from_uri("soyeht://claw-share/v2?e=AA")
        .expect_err("wrong version must reject");
    assert!(matches!(err, ClawShareError::UriMalformed));
}

/// Open slot for the revoke-idempotence tests.
fn revoke_fixture() -> (ClawShareSlotStore, SlotId) {
    let store = ClawShareSlotStore::new();
    let slot_id = SlotId::random();
    store
        .insert(SlotRecord {
            slot_id: slot_id.clone(),
            claw_id: "claw_a".to_string(),
            expires_at: 2_000_000_000,
            state: SlotState::Open,
            app_presentation: None,
            created_at: Some(1_700_000_000),
        })
        .unwrap();
    (store, slot_id)
}

#[test]
fn revoke_returns_the_canonical_timestamp_and_a_second_revoke_moves_nothing() {
    let (store, slot_id) = revoke_fixture();

    let first = store.revoke(&slot_id, 1_800_000_001).unwrap();
    assert_eq!(first, 1_800_000_001);
    let after_first = store.get(&slot_id).unwrap().state;

    // A LATER clock must not move anything: the canonical value is the
    // first one, and it is what the caller re-signs on every retry.
    let second = store.revoke(&slot_id, 1_900_000_999).unwrap();
    assert_eq!(
        second, 1_800_000_001,
        "second revoke must not move revoked_at"
    );
    assert_eq!(
        store.get(&slot_id).unwrap().state,
        after_first,
        "second revoke must not change the state at all"
    );
    assert_eq!(
        store.get(&slot_id).unwrap().created_at,
        Some(1_700_000_000),
        "revoking must not disturb created_at"
    );
}

#[test]
fn revoking_a_consumed_slot_preserves_when_it_was_accepted() {
    let (store, slot_id) = revoke_fixture();
    let guest = P256Keypair::generate();
    store
        .consume_atomic(&slot_id, "claw_a", guest.public(), 1_750_000_000)
        .unwrap();

    let revoked_at = store.revoke(&slot_id, 1_800_000_001).unwrap();
    assert_eq!(revoked_at, 1_800_000_001);
    assert_eq!(
        store.get(&slot_id).unwrap().state,
        SlotState::Revoked {
            revoked_at: 1_800_000_001,
            // The owner surface must still be able to say the share WAS
            // accepted, and when, after it has been revoked.
            accepted_at: Some(1_750_000_000),
        }
    );

    // And a repeat keeps both halves.
    assert_eq!(
        store.revoke(&slot_id, 1_999_999_999).unwrap(),
        1_800_000_001
    );
    assert_eq!(
        store.get(&slot_id).unwrap().state,
        SlotState::Revoked {
            revoked_at: 1_800_000_001,
            accepted_at: Some(1_750_000_000),
        }
    );
}

#[test]
fn revoking_an_open_slot_records_no_acceptance() {
    let (store, slot_id) = revoke_fixture();
    store.revoke(&slot_id, 1_800_000_001).unwrap();
    assert_eq!(
        store.get(&slot_id).unwrap().state,
        SlotState::Revoked {
            revoked_at: 1_800_000_001,
            accepted_at: None,
        }
    );
}

#[test]
fn slot_store_revoke_blocks_consume() {
    let guest_key = P256Keypair::generate();
    let store = ClawShareSlotStore::new();
    let slot_id = SlotId::random();
    store
        .insert(SlotRecord {
            slot_id: slot_id.clone(),
            claw_id: "claw_a".to_string(),
            expires_at: 2_000_000_000,
            state: SlotState::Open,
            app_presentation: None,
            created_at: None,
        })
        .expect("insert");
    store.revoke(&slot_id, 1_000_000_000).expect("revoke");
    let err = store
        .consume_atomic(&slot_id, "claw_a", guest_key.public(), 1_000_000_001)
        .expect_err("revoked must reject");
    assert!(matches!(err, ClawShareError::SlotRevoked));
}
