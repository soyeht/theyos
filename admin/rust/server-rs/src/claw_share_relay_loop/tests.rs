#![cfg(test)]

use super::*;
use household_rs::claw_share::{CLAIM_TIMESTAMP_TOLERANCE_SECS, ClaimNonce, ClawShareError};
use household_rs::household_mesh_log::{
    MeshEvent, MeshMembership, ProjectedGroup, ProjectedMemberDevice, build_group_claw_grant_event,
    build_group_created_event, build_group_member_add_event, build_member_device_enroll_event,
};
use household_rs::ids::derive_household_id;
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::member_identity::{MemberDeviceBinding, derive_member_id};
use household_rs::person_cert::derive_person_id;

fn fake_consume_event() -> MeshEvent {
    MeshEvent::ClawShareSlotConsumed {
        slot_id: household_rs::claw_share::SlotId([0u8; 16]),
        guest_device_pub: household_rs::keys::P256Keypair::from_secret_scalar(&[0x33u8; 32])
            .unwrap()
            .public(),
        claw_id: "claw_test".to_string(),
        expires_at: 1_800_000_000,
        participant_npub: None,
    }
}

#[test]
fn parse_relay_list_handles_csv_and_whitespace() {
    assert_eq!(parse_relay_list(""), Vec::<String>::new());
    assert_eq!(
        parse_relay_list("wss://a, wss://b ,, wss://c"),
        vec!["wss://a", "wss://b", "wss://c"]
    );
    assert_eq!(parse_relay_list("wss://only"), vec!["wss://only"]);
}

#[test]
fn mesh_write_rejects_entry_from_unauthorized_signer() {
    let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
    let intruder = P256Keypair::from_secret_scalar(&[0xAAu8; 32]).unwrap();
    let entry = LogEntry::sign(
        1_800_000_000,
        intruder.public(),
        fake_consume_event(),
        &intruder,
    )
    .unwrap();
    // Entry signature is cryptographically valid — verify() passes.
    assert!(entry.verify().is_ok());
    // But the authority check rejects it because intruder is not
    // the household owner.
    assert!(
        check_mesh_write_authority(&owner.public(), &entry).is_err(),
        "intruder-signed entry must be rejected even with valid signature"
    );
}

#[test]
fn mesh_write_accepts_entry_from_household_owner() {
    let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
    let entry =
        LogEntry::sign(1_800_000_000, owner.public(), fake_consume_event(), &owner).unwrap();
    assert!(check_mesh_write_authority(&owner.public(), &entry).is_ok());
}

#[test]
fn claim_requires_owner_auth_group_false_device_true() {
    // Regression (live hardware smoke "owner auth not loaded"): a
    // credential-less GROUP claim is owner-independent and must NOT require
    // owner_auth — process_one routes it to handle_group_claim BEFORE the
    // guard. A Device credential claim DOES require it (to mint the
    // GuestCredential bound to the owner p_id). The bug was the group branch
    // sitting BELOW the unconditional owner_auth guard, which blocked group
    // members on a headless engine whose owner cert is not loaded.
    let device_key = P256Keypair::from_secret_scalar(&[0x33u8; 32]).unwrap();
    let member_key = P256Keypair::from_secret_scalar(&[0x55u8; 32]).unwrap();
    let now = 1_800_000_000u64;

    // Device claim → requires owner_auth (hits the guard).
    let device_claim = ClawShareClaim::sign(
        SlotId([7u8; 16]),
        device_key.public(),
        ClaimNonce::random(),
        now,
        &device_key as &dyn IdentityKey,
    )
    .unwrap();
    assert!(
        claim_requires_owner_auth(&device_claim),
        "device claim must require owner_auth",
    );

    // Group claim → owner-independent (routes above the guard).
    let nonce = ClaimNonce::random();
    let binding =
        MemberDeviceBinding::sign(&member_key, device_key.public(), "npub".into(), now).unwrap();
    let group_req = GroupClaimRequest::sign(
        binding,
        "g".into(),
        "claw_a".into(),
        nonce.0.to_vec(),
        Some(600),
        &device_key as &dyn IdentityKey,
    )
    .unwrap();
    let group_claim = ClawShareClaim::sign_group(
        device_key.public(),
        nonce,
        now,
        group_req,
        &device_key as &dyn IdentityKey,
    )
    .unwrap();
    assert!(
        !claim_requires_owner_auth(&group_claim),
        "group claim must NOT require owner_auth",
    );
}

#[test]
fn mesh_write_rejects_forged_group_claw_grant_from_non_owner() {
    // The replication CARRY (design risk #4) must close for the NEW Fase E
    // group/membership events, not only ClawShareSlotConsumed: a forged
    // GroupClawGranted from a valid-but-non-owner key has a cryptographically
    // valid signature yet must be rejected before the fold, because group
    // grants are owner-only. The gate is variant-agnostic (it checks
    // issuer_pub), so this locks the protection for the whole new event family.
    let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
    let intruder = P256Keypair::from_secret_scalar(&[0xAAu8; 32]).unwrap();

    let forged = LogEntry::sign(
        1_800_000_000,
        intruder.public(),
        MeshEvent::GroupClawGranted {
            group_id: "g".to_string(),
            claw_id: "claw_alpha".to_string(),
        },
        &intruder,
    )
    .unwrap();
    // The entry's own signature is self-consistent...
    assert!(forged.verify().is_ok());
    // ...but the household authority check rejects a non-owner issuer.
    assert!(
        check_mesh_write_authority(&owner.public(), &forged).is_err(),
        "a forged GroupClawGranted from a non-owner must be rejected at ingest"
    );

    // The same owner-signed group event IS authorized.
    let owner_signed = LogEntry::sign(
        1_800_000_000,
        owner.public(),
        MeshEvent::GroupClawGranted {
            group_id: "g".to_string(),
            claw_id: "claw_alpha".to_string(),
        },
        &owner,
    )
    .unwrap();
    assert!(check_mesh_write_authority(&owner.public(), &owner_signed).is_ok());
}

/// Multi-relay fanout: when a `LogEntry` is broadcast and one
/// relay is "dead" (its receiver is dropped), the surviving relay
/// still receives the entry. The dedupe contract at
/// `MeshLogStore::append` ensures duplicate deliveries from
/// healthy relays are silent no-ops, so "success if any relay
/// delivers" is the operative invariant.
#[tokio::test]
async fn gossip_fanout_survives_dead_relay() {
    let (tx, _placeholder) = broadcast::channel::<Vec<u8>>(8);
    let mut relay_alive = tx.subscribe();
    let relay_dead = tx.subscribe();
    drop(relay_dead); // simulate the dead-relay loop having exited

    let payload = b"entry-cbor-bytes".to_vec();
    // The publish "succeeds" (broadcast returns the count of
    // active receivers, which includes the alive one).
    let count = tx.send(payload.clone()).expect("broadcast");
    assert!(count >= 1, "at least one live receiver must remain");

    let got = relay_alive
        .recv()
        .await
        .expect("alive receiver got payload");
    assert_eq!(got, payload, "alive relay receives the same payload");
}

const GC_GROUP: &str = "group_alpha";
const GC_CLAW: &str = "claw_alpha";
const GC_NPUB: &str = "npub_test";

fn gc_keys() -> (P256Keypair, P256Keypair) {
    let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).unwrap();
    let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).unwrap();
    (member, device)
}

fn gc_claim(
    member: &P256Keypair,
    device: &P256Keypair,
    ts: u64,
) -> (ClawShareClaim, GroupClaimRequest) {
    let nonce = ClaimNonce([0x44u8; 32]);
    let binding = MemberDeviceBinding::sign(
        member as &dyn IdentityKey,
        device.public(),
        GC_NPUB.to_string(),
        1_800_000_000,
    )
    .unwrap();
    let group_req = GroupClaimRequest::sign(
        binding,
        GC_GROUP.to_string(),
        GC_CLAW.to_string(),
        nonce.0.to_vec(),
        Some(600),
        device as &dyn IdentityKey,
    )
    .unwrap();
    let claim = ClawShareClaim::sign_group(
        device.public(),
        nonce,
        ts,
        group_req.clone(),
        device as &dyn IdentityKey,
    )
    .unwrap();
    (claim, group_req)
}

fn gc_projection(member_id: &str, device: &P256Keypair) -> ProjectedState {
    let mut projection = ProjectedState::default();
    projection.groups.insert(
        GC_GROUP.to_string(),
        ProjectedGroup {
            group_id: GC_GROUP.to_string(),
            name: "Alpha".to_string(),
            members: [(member_id.to_string(), MeshMembership::Active)]
                .into_iter()
                .collect(),
            member_labels: Default::default(),
            granted_claws: [(GC_CLAW.to_string(), MeshMembership::Active)]
                .into_iter()
                .collect(),
            revision: 1,
        },
    );
    projection.member_devices.insert(
        member_id.to_string(),
        [(
            device.public().as_bytes()[..].to_vec(),
            ProjectedMemberDevice {
                participant_npub: GC_NPUB.to_string(),
                status: MeshMembership::Active,
            },
        )]
        .into_iter()
        .collect(),
    );
    projection
}

fn m2a_mesh_log(
    bindings: &[&MemberDeviceBinding],
    owner: &P256Keypair,
    timestamp: u64,
) -> MeshLogStore {
    let mesh_log = MeshLogStore::new();
    let owner_pub = owner.public();
    mesh_log
        .append(
            build_group_created_event(
                "m2a_group".to_string(),
                "M2-A shared claw control-plane".to_string(),
                timestamp,
                owner_pub.clone(),
                owner,
            )
            .expect("sign group creation"),
        )
        .expect("append group creation");
    mesh_log
        .append(
            build_group_claw_grant_event(
                "m2a_group".to_string(),
                "m2a_claw_a".to_string(),
                timestamp + 1,
                owner_pub.clone(),
                owner,
            )
            .expect("sign single claw grant"),
        )
        .expect("append single claw grant");

    for (index, binding) in bindings.iter().enumerate() {
        binding.verify().expect("valid member/device binding");
        let event_timestamp = timestamp + 2 + (index as u64 * 2);
        mesh_log
            .append(
                build_group_member_add_event(
                    "m2a_group".to_string(),
                    binding.member_id.clone(),
                    format!("M2-A member {index}"),
                    event_timestamp,
                    owner_pub.clone(),
                    owner,
                )
                .expect("sign member add"),
            )
            .expect("append member add");
        mesh_log
            .append(
                build_member_device_enroll_event(
                    binding.member_id.clone(),
                    binding.device_pub.clone(),
                    binding.participant_npub.clone(),
                    event_timestamp + 1,
                    owner_pub.clone(),
                    owner,
                )
                .expect("sign device enrollment"),
            )
            .expect("append device enrollment");
    }
    mesh_log
}

fn m2a_group_claim(
    binding: &MemberDeviceBinding,
    device: &P256Keypair,
    claw_id: &str,
    nonce_byte: u8,
    timestamp: u64,
) -> (ClawShareClaim, GroupClaimRequest) {
    let nonce = ClaimNonce([nonce_byte; 32]);
    let request = GroupClaimRequest::sign(
        binding.clone(),
        "m2a_group".to_string(),
        claw_id.to_string(),
        nonce.0.to_vec(),
        Some(600),
        device as &dyn IdentityKey,
    )
    .expect("matching bound device signs its production group-request PoP");
    let claim = ClawShareClaim::sign_group(
        device.public(),
        nonce,
        timestamp,
        request.clone(),
        device as &dyn IdentityKey,
    )
    .expect("matching bound device signs its production group claim");
    (claim, request)
}

#[test]
fn m2a_real_device_pops_bind_two_members_to_claw_a_only() {
    // M2-A is a control-plane proof: use the production group-claim
    // verifier through its membership gate, but do not select or mint any
    // relay resource or transport.
    let timestamp = 1_800_000_700;
    let member_one = P256Keypair::from_secret_scalar(&[0x21u8; 32]).unwrap();
    let device_one = P256Keypair::from_secret_scalar(&[0x31u8; 32]).unwrap();
    let member_two = P256Keypair::from_secret_scalar(&[0x41u8; 32]).unwrap();
    let device_two = P256Keypair::from_secret_scalar(&[0x51u8; 32]).unwrap();

    let binding_one = MemberDeviceBinding::sign(
        &member_one as &dyn IdentityKey,
        device_one.public(),
        "m2a_member_one_npub".to_string(),
        timestamp,
    )
    .expect("member one binding");
    let binding_two = MemberDeviceBinding::sign(
        &member_two as &dyn IdentityKey,
        device_two.public(),
        "m2a_member_two_npub".to_string(),
        timestamp,
    )
    .expect("member two binding");
    assert_ne!(binding_one.member_id, binding_two.member_id);
    assert_ne!(binding_one.device_pub, binding_two.device_pub);

    let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
    let mesh_log = m2a_mesh_log(&[&binding_one, &binding_two], &owner, timestamp);
    let projection = mesh_log.project();

    // Each independently signed production request/claim reaches the real
    // membership gate and returns the exact bound member, device, and A
    // claw. Separate nonce tables keep these successes independent.
    for (binding, device, nonce_byte) in [
        (&binding_one, &device_one, 0x61u8),
        (&binding_two, &device_two, 0x62u8),
    ] {
        let (claim, request) =
            m2a_group_claim(binding, device, "m2a_claw_a", nonce_byte, timestamp);
        let nonces = GroupClaimNonceTable::new();
        let verified = verify_group_claim(&claim, &request, &projection, &nonces, timestamp)
            .expect("matching member/device is authorized only for claw A");
        assert_eq!(verified.member_id, binding.member_id);
        assert_eq!(verified.device_pub, binding.device_pub);
        assert_eq!(verified.claw_id, "m2a_claw_a");
    }

    // A member binding cannot be paired with the other member's device to
    // make a production-verifiable PoP. Check both directions explicitly.
    for (binding, other_device) in [(&binding_one, &device_two), (&binding_two, &device_one)] {
        assert!(matches!(
            GroupClaimRequest::sign(
                binding.clone(),
                "m2a_group".to_string(),
                "m2a_claw_a".to_string(),
                vec![0x70u8; 32],
                Some(600),
                other_device as &dyn IdentityKey,
            ),
            Err(ClawShareError::GroupDeviceKeyMismatch)
        ));
    }

    // Fresh claims, requests, and nonce tables reach membership (rather
    // than failing as a replay) and reject both valid pairs for claw B.
    for (binding, device, nonce_byte) in [
        (&binding_one, &device_one, 0x71u8),
        (&binding_two, &device_two, 0x72u8),
    ] {
        let (claim, request) =
            m2a_group_claim(binding, device, "m2a_claw_b", nonce_byte, timestamp);
        let nonces = GroupClaimNonceTable::new();
        assert!(matches!(
            verify_group_claim(&claim, &request, &projection, &nonces, timestamp),
            Err(GroupClaimReject::NotAuthorized(
                "relay-stream-group-claw-not-granted"
            ))
        ));
    }
}

#[test]
fn group_claim_valid_verifies() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, group_req) = gc_claim(&member, &device, ts);
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    let verified = verify_group_claim(&claim, &group_req, &projection, &nonces, ts).expect("valid");
    assert_eq!(verified.group_id, GC_GROUP);
    assert_eq!(verified.member_id, member_id);
    assert_eq!(verified.device_pub, device.public());
    assert_eq!(verified.claw_id, GC_CLAW);
    assert_eq!(verified.ttl_secs, Some(600));
}

#[test]
fn group_claim_carries_zeroed_sentinel_slot() {
    let (member, device) = gc_keys();
    let (claim, _group_req) = gc_claim(&member, &device, 1_800_000_500);
    assert!(claim.group_request.is_some());
    assert_eq!(claim.slot_id, SlotId([0u8; SLOT_ID_LEN]));
    assert!(claim.participant_npub.is_none());
}

#[test]
fn group_claim_replay_same_nonce_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, group_req) = gc_claim(&member, &device, ts);
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    assert!(verify_group_claim(&claim, &group_req, &projection, &nonces, ts).is_ok());
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, ts + 5),
        Err(GroupClaimReject::NonceReplay)
    ));
}

#[test]
fn group_claim_window_boundary_replay_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, group_req) = gc_claim(&member, &device, ts);
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    let early = ts - CLAIM_TIMESTAMP_TOLERANCE_SECS;
    let late = ts + CLAIM_TIMESTAMP_TOLERANCE_SECS;
    assert!(verify_group_claim(&claim, &group_req, &projection, &nonces, early).is_ok());
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, late),
        Err(GroupClaimReject::NonceReplay)
    ));
}

#[test]
fn group_claim_forged_binding_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, mut group_req) = gc_claim(&member, &device, ts);
    group_req.binding.member_id = "g_forged".to_string();
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
        Err(GroupClaimReject::BindingInvalid)
    ));
}

#[test]
fn group_claim_bad_device_pop_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, mut group_req) = gc_claim(&member, &device, ts);
    group_req.device_pop = household_rs::keys::P256Signature([0u8; 64]);
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
        Err(GroupClaimReject::DevicePop)
    ));
}

#[test]
fn group_claim_challenge_not_nonce_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, group_req) = gc_claim(&member, &device, ts);
    let rebound = GroupClaimRequest::sign(
        group_req.binding.clone(),
        GC_GROUP.to_string(),
        GC_CLAW.to_string(),
        vec![0x99u8; 32],
        Some(600),
        &device as &dyn IdentityKey,
    )
    .unwrap();
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    assert!(matches!(
        verify_group_claim(&claim, &rebound, &projection, &nonces, ts),
        Err(GroupClaimReject::ChallengeNotNonce)
    ));
}

#[test]
fn group_claim_non_member_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, group_req) = gc_claim(&member, &device, ts);
    let projection = ProjectedState::default();
    let nonces = GroupClaimNonceTable::new();
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
        Err(GroupClaimReject::NotAuthorized(_))
    ));
}

#[test]
fn group_claim_device_not_enrolled_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, group_req) = gc_claim(&member, &device, ts);
    let member_id = derive_member_id(&member.public());
    let other_device = P256Keypair::from_secret_scalar(&[0x66u8; 32]).unwrap();
    let projection = gc_projection(&member_id, &other_device);
    let nonces = GroupClaimNonceTable::new();
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
        Err(GroupClaimReject::NotAuthorized(_))
    ));
}

#[test]
fn group_claim_stale_timestamp_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, group_req) = gc_claim(&member, &device, ts);
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    let stale = ts + CLAIM_TIMESTAMP_TOLERANCE_SECS + 10;
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, stale),
        Err(GroupClaimReject::ClaimInvalid)
    ));
}

#[test]
fn group_claim_wrong_request_version_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, mut group_req) = gc_claim(&member, &device, ts);
    group_req.v = 2;
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
        Err(GroupClaimReject::RequestVersion)
    ));
}

#[test]
fn group_claim_device_pub_mismatch_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, mut group_req) = gc_claim(&member, &device, ts);
    let other_device = P256Keypair::from_secret_scalar(&[0x66u8; 32]).unwrap();
    group_req.binding = MemberDeviceBinding::sign(
        &member as &dyn IdentityKey,
        other_device.public(),
        GC_NPUB.to_string(),
        1_800_000_000,
    )
    .unwrap();
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
        Err(GroupClaimReject::DeviceMismatch)
    ));
}

#[test]
fn group_claim_non_sentinel_slot_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (_discard, group_req) = gc_claim(&member, &device, ts);
    let mut claim = ClawShareClaim::sign(
        SlotId([0x01u8; SLOT_ID_LEN]),
        device.public(),
        ClaimNonce([0x44u8; 32]),
        ts,
        &device as &dyn IdentityKey,
    )
    .unwrap();
    claim.group_request = Some(group_req.clone());
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
        Err(GroupClaimReject::NonSentinelDeviceFields)
    ));
}

#[test]
fn group_claim_filled_participant_npub_rejected() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (_discard, group_req) = gc_claim(&member, &device, ts);
    let mut claim = ClawShareClaim::sign_with_participant(
        SlotId([0u8; SLOT_ID_LEN]),
        device.public(),
        ClaimNonce([0x44u8; 32]),
        ts,
        Some("npub_should_not_be_here".to_string()),
        &device as &dyn IdentityKey,
    )
    .unwrap();
    claim.group_request = Some(group_req.clone());
    let member_id = derive_member_id(&member.public());
    let projection = gc_projection(&member_id, &device);
    let nonces = GroupClaimNonceTable::new();
    assert!(matches!(
        verify_group_claim(&claim, &group_req, &projection, &nonces, ts),
        Err(GroupClaimReject::NonSentinelDeviceFields)
    ));
}

#[test]
fn engine_rejects_group_claim_in_device_flow() {
    let (member, device) = gc_keys();
    let ts = 1_800_000_500;
    let (claim, _group_req) = gc_claim(&member, &device, ts);
    let owner = P256Keypair::from_secret_scalar(&[0x11u8; 32]).unwrap();
    let hh_id = derive_household_id(&owner.public());
    let owner_p_id = derive_person_id(&owner.public());
    let slots = ClawShareSlotStore::new();
    let tunnel_factory = |_claw_id: &str| TunnelHandle::Loopback {
        channel: "test".to_string(),
    };
    let ctx = EngineContext {
        owner_key: &owner,
        owner_p_id: &owner_p_id,
        hh_id: &hh_id,
        slot_store: &slots,
        credential_ttl_secs: 60,
        tunnel_factory: &tunnel_factory,
    };
    let err = engine_handle_claim(&ctx, &claim, ts).expect_err("group is not device flow");
    assert!(matches!(err, ClawShareError::SlotNotFound));
}

#[test]
fn group_claim_route_precedes_device_path_source_guard() {
    let source = include_str!("../claw_share_relay_loop.rs");
    let group_branch = source
        .find("if let Some(group_req) = claim.group_request.clone()")
        .expect("group branch marker");
    let engine_call = source
        .find("engine_handle_claim(&ctx, &claim, now)")
        .expect("device engine call marker");
    let slot_event_after_branch = source[group_branch..]
        .find("MeshEvent::ClawShareSlotConsumed")
        .expect("slot consume event after group branch")
        + group_branch;
    assert!(
        group_branch < engine_call,
        "Group claims must route before engine_handle_claim"
    );
    assert!(
        group_branch < slot_event_after_branch,
        "Group claims must route before slot-consume event append"
    );
}
