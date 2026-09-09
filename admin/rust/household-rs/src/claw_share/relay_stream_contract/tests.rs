#![cfg(test)]

use super::*;
use crate::claw_share::SlotId;
use crate::ids::{derive_household_id, derive_machine_id};
use crate::keys::{IdentityKey, P256Keypair};
use crate::machine_cert::{Platform, SignOptions};
use crate::person_cert::derive_person_id;

const NOW: u64 = 1_800_000_000;
const NOT_AFTER: u64 = NOW + 60;

/// CBOR map header `ab` = map(11): exactly the 11 v2 fields, authz omitted
/// (a Some(authz) offer would be `ac`/map(12)). This IS the byte-identity
/// anchor — the Swift fixture must pin this same literal. Module-scoped so
/// the payload fixture and the mint-path test share ONE copy; two hand-kept
/// copies of the same hex would drift silently.
const EXPECTED_OFFER_V2_AUTHZ_NONE_HEX: &str = "ab617602646b696e64781d636c61772d73686172652f72656c61792d73747265616d2d6f6666657267636c61775f69646a636c61775f616c70686167736c6f745f69645022222222222222222222222222222222687265736f7572636563707479696e6f745f61667465721a6b49d23c6d65787065637465645f706174686c72656c61795f73747265616d6e72656c61795f656e64706f696e74781e72656c61792d73747265616d3a2f2f3132372e302e302e313a34393135326f636c61775f7374617469635f707562582033333333333333333333333333333333333333333333333333333333333333337067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d7072656e64657a766f75735f746f6b656e5042424242424242424242424242424242";

/// The wire key, as bytes, for the omitted-when-None assertion.
const SHARE_APP_PRESENTATION_KEY: &[u8] = b"app_presentation";

fn signer() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x11; 32]).unwrap()
}

// ── Fase E2: additive authz migration + Group audience ───────────────────

fn member_device() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x66; 32]).unwrap()
}

fn group_projection(
    member_active: bool,
    claw_granted: bool,
    device_active: bool,
    device: &P256PublicKey,
) -> crate::household_mesh_log::ProjectedState {
    use crate::household_mesh_log::{
        MeshMembership, ProjectedGroup, ProjectedMemberDevice, ProjectedState,
    };
    let status = |on: bool| {
        if on {
            MeshMembership::Active
        } else {
            MeshMembership::Removed
        }
    };
    let mut p = ProjectedState::default();
    p.groups.insert(
        "g".to_string(),
        ProjectedGroup {
            group_id: "g".to_string(),
            name: "G".to_string(),
            members: [("g_a".to_string(), status(member_active))]
                .into_iter()
                .collect(),
            member_labels: Default::default(),
            granted_claws: [("claw_alpha".to_string(), status(claw_granted))]
                .into_iter()
                .collect(),
            revision: 1,
        },
    );
    p.member_devices.insert(
        "g_a".to_string(),
        [(
            device.as_bytes()[..].to_vec(),
            ProjectedMemberDevice {
                participant_npub: "npub".to_string(),
                status: status(device_active),
            },
        )]
        .into_iter()
        .collect(),
    );
    p
}

#[test]
fn authz_none_is_omitted_so_v2_canonical_bytes_are_unchanged() {
    let payload = payload();
    assert!(payload.authz.is_none());
    assert_eq!(payload.audience(), RelayStreamAudience::Device);
    let bytes = payload.to_canonical_bytes().unwrap();
    // The `authz` map key must NOT appear on the wire when None — this is the
    // byte-identity-to-v2 invariant that keeps old signatures/fixtures valid.
    assert!(
        !bytes.windows(5).any(|w| w == b"authz"),
        "authz key must be omitted when None"
    );
    // And the v2 offer still signs + verifies unchanged.
    let offer = RelayStreamOfferContract::sign(payload, &signer()).unwrap();
    offer.verify_owner_signature(&owner_pub(), NOW).unwrap();
}

#[test]
fn group_offer_carries_authz_round_trips_and_verifies_signer() {
    let offer = mint_relay_stream_group_offer(
        token(0x42),
        SlotId([0x99; 16]),
        "g".to_string(),
        "g_a".to_string(),
        member_device().public(),
        "claw_alpha".to_string(),
        RelayStreamResource::ClawSite,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
        NOW,
        &signer(),
    )
    .unwrap();

    assert_eq!(
        offer.payload.audience(),
        RelayStreamAudience::Group {
            group_id: "g".to_string(),
            member_id: "g_a".to_string(),
        }
    );
    // authz is in the signed bytes (so it cannot be downgraded silently).
    let bytes = offer.payload.to_canonical_bytes().unwrap();
    assert!(bytes.windows(5).any(|w| w == b"authz"));
    offer.verify_owner_signature(&owner_pub(), NOW).unwrap();
    let encoded = offer.to_canonical_bytes().unwrap();
    let decoded = RelayStreamOfferContract::from_canonical_bytes(&encoded).unwrap();
    assert_eq!(decoded, offer);
}

#[test]
fn group_membership_authorizes_only_active_member_active_grant_active_device() {
    let dev = member_device().public();
    // Happy path.
    check_relay_stream_group_membership(
        &group_projection(true, true, true, &dev),
        "g",
        "g_a",
        "claw_alpha",
        &dev,
    )
    .unwrap();
    // Each missing condition fails closed.
    for (proj, why) in [
        (group_projection(false, true, true, &dev), "member inactive"),
        (
            group_projection(true, false, true, &dev),
            "claw not granted",
        ),
        (group_projection(true, true, false, &dev), "device retired"),
    ] {
        assert!(
            check_relay_stream_group_membership(&proj, "g", "g_a", "claw_alpha", &dev).is_err(),
            "{why} must fail closed"
        );
    }
    // Unknown group / wrong claw / wrong device all fail.
    let ok = group_projection(true, true, true, &dev);
    assert!(check_relay_stream_group_membership(&ok, "other", "g_a", "claw_alpha", &dev).is_err());
    assert!(check_relay_stream_group_membership(&ok, "g", "g_a", "other_claw", &dev).is_err());
    let stranger = P256Keypair::from_secret_scalar(&[0x77; 32])
        .unwrap()
        .public();
    assert!(check_relay_stream_group_membership(&ok, "g", "g_a", "claw_alpha", &stranger).is_err());
}

#[test]
fn public_offer_carries_authz_and_check_requires_published_claw() {
    use crate::household_mesh_log::{MeshMembership, ProjectedState};

    let offer = mint_relay_stream_public_offer(
        token(0x42),
        SlotId([0x98; 16]),
        guest_pub(),
        "claw_alpha".to_string(),
        RelayStreamResource::ClawSite,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
        NOW,
        &signer(),
    )
    .unwrap();
    assert_eq!(offer.payload.audience(), RelayStreamAudience::Public);
    offer.verify_owner_signature(&owner_pub(), NOW).unwrap();

    let mut published = ProjectedState::default();
    published
        .published_claws
        .insert("claw_alpha".to_string(), MeshMembership::Active);
    check_relay_stream_public(&published, "claw_alpha").unwrap();

    // Unpublished / unknown claw fails closed.
    assert!(check_relay_stream_public(&ProjectedState::default(), "claw_alpha").is_err());
    let mut unpub = ProjectedState::default();
    unpub
        .published_claws
        .insert("claw_alpha".to_string(), MeshMembership::Removed);
    assert!(check_relay_stream_public(&unpub, "claw_alpha").is_err());
}

#[test]
fn pty_is_refused_for_group_and_public_audiences() {
    // Device is the deliberately retained 1:1, owner-approved PTY path.
    let credential = credential();
    mint_relay_stream_offer(mint_input_for(&credential), &signer())
        .expect("Device audience must retain PTY access");

    let group = mint_relay_stream_group_offer(
        token(0x42),
        SlotId([0x99; 16]),
        "g".to_string(),
        "g_a".to_string(),
        member_device().public(),
        "claw_alpha".to_string(),
        RelayStreamResource::Pty,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
        NOW,
        &signer(),
    );
    assert!(matches!(
        group,
        Err(RelayStreamContractError::PtyForbiddenForSharedAudience)
    ));

    let public = mint_relay_stream_public_offer(
        token(0x42),
        SlotId([0x98; 16]),
        guest_pub(),
        "claw_alpha".to_string(),
        RelayStreamResource::Pty,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
        NOW,
        &signer(),
    );
    assert!(matches!(
        public,
        Err(RelayStreamContractError::PtyForbiddenForSharedAudience)
    ));
}

fn attacker() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x55; 32]).unwrap()
}

fn owner_pub() -> P256PublicKey {
    signer().public()
}

fn guest() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x33; 32]).unwrap()
}

fn guest_pub() -> P256PublicKey {
    guest().public()
}

fn other_guest_pub() -> P256PublicKey {
    P256Keypair::from_secret_scalar(&[0x44; 32])
        .unwrap()
        .public()
}

fn token(label: u8) -> RendezvousToken {
    RendezvousToken::try_new(vec![label; 16]).unwrap()
}

fn static_pub(label: u8) -> RelayStreamClawStaticPublicKey {
    RelayStreamClawStaticPublicKey::try_new([label; 32]).unwrap()
}

fn payload() -> RelayStreamOfferPayload {
    RelayStreamOfferPayload::new(
        token(0x42),
        "claw_alpha".to_string(),
        SlotId([0x22; 16]),
        guest_pub(),
        RelayStreamResource::Pty,
        RelayStreamExpectedPath::RelayStream,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
    )
}

fn credential() -> GuestCredential {
    GuestCredential::sign(
        derive_household_id(&owner_pub()),
        derive_person_id(&owner_pub()),
        owner_pub(),
        "claw_alpha".to_string(),
        guest_pub(),
        SlotId([0x22; 16]),
        NOW - 60,
        NOW + 600,
        &signer(),
    )
    .unwrap()
}

fn trust_machine() -> P256Keypair {
    P256Keypair::from_secret_scalar(&[0x12; 32]).unwrap()
}

fn trust_record(root: &P256Keypair, machine: &P256Keypair) -> HouseholdRecord {
    HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&root.public()),
        hh_pub: root.public(),
        name: "home".to_string(),
        created_at: 0,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![derive_machine_id(&machine.public())],
        is_follower: false,
    }
}

fn trust_cert(root: &P256Keypair, machine: &P256Keypair) -> MachineCert {
    MachineCert::sign(
        root,
        &machine.public(),
        &SignOptions {
            hh_id: derive_household_id(&root.public()),
            hostname: "machine-alpha".to_string(),
            platform: Platform::Macos,
            joined_at: NOW - 60,
        },
    )
    .unwrap()
}

fn root_trust_inputs() -> (
    HouseholdRecord,
    MachineCert,
    crate::household_mesh_log::ProjectedState,
) {
    let root = signer();
    let machine = trust_machine();
    (
        trust_record(&root, &machine),
        trust_cert(&root, &machine),
        crate::household_mesh_log::ProjectedState::default(),
    )
}

fn credential_for_guest(guest_pub: P256PublicKey) -> GuestCredential {
    GuestCredential::sign(
        derive_household_id(&owner_pub()),
        derive_person_id(&owner_pub()),
        owner_pub(),
        "claw_alpha".to_string(),
        guest_pub,
        SlotId([0x22; 16]),
        NOW - 60,
        NOW + 600,
        &signer(),
    )
    .unwrap()
}

fn mint_input_for(credential: &GuestCredential) -> RelayStreamOfferMintInput<'_> {
    RelayStreamOfferMintInput {
        rendezvous_token: token(0x42),
        credential,
        resource: RelayStreamResource::Pty,
        expected_path: RelayStreamExpectedPath::RelayStream,
        relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
        claw_static_pub: static_pub(0x33),
        not_after: NOT_AFTER,
        now_unix: NOW,
        app_presentation: None,
    }
}

fn minted_offer() -> RelayStreamOfferContract {
    let credential = credential();
    mint_relay_stream_offer(mint_input_for(&credential), &signer()).unwrap()
}

fn signed_offer() -> RelayStreamOfferContract {
    RelayStreamOfferContract::sign(payload(), &signer()).unwrap()
}

#[test]
fn verify_with_trust_allows_root_signed_device_offer() {
    let (record, cert, projection) = root_trust_inputs();
    let offer = signed_offer();

    assert_eq!(offer.payload.audience(), RelayStreamAudience::Device);
    offer
        .verify_with_trust(&record, &cert, &projection, NOW)
        .unwrap();
}

#[test]
fn verify_with_trust_rejects_root_signed_group_offer() {
    let (record, cert, projection) = root_trust_inputs();
    let offer = mint_relay_stream_group_offer(
        token(0x42),
        SlotId([0x99; 16]),
        "g".to_string(),
        "g_a".to_string(),
        member_device().public(),
        "claw_alpha".to_string(),
        RelayStreamResource::ClawSite,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
        NOW,
        &signer(),
    )
    .unwrap();

    let err = offer
        .verify_with_trust(&record, &cert, &projection, NOW)
        .unwrap_err();
    assert!(matches!(
        err,
        RelayStreamContractError::IssuerUnauthorized(MachineIssuerError::SignerMismatch)
    ));
}

#[test]
fn verify_with_trust_rejects_root_signed_public_offer() {
    let (record, cert, projection) = root_trust_inputs();
    let offer = mint_relay_stream_public_offer(
        token(0x42),
        SlotId([0x98; 16]),
        guest_pub(),
        "claw_alpha".to_string(),
        RelayStreamResource::ClawSite,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
        NOW,
        &signer(),
    )
    .unwrap();

    let err = offer
        .verify_with_trust(&record, &cert, &projection, NOW)
        .unwrap_err();
    assert!(matches!(
        err,
        RelayStreamContractError::IssuerUnauthorized(MachineIssuerError::SignerMismatch)
    ));
}

fn signed_offer_with(edit: impl FnOnce(&mut RelayStreamOfferPayload)) -> RelayStreamOfferContract {
    let mut payload = payload();
    edit(&mut payload);
    RelayStreamOfferContract::sign(payload, &signer()).unwrap()
}

fn noise_prologue_for(offer: &RelayStreamOfferContract) -> RelayStreamNoisePrologue {
    offer.to_noise_prologue(&owner_pub(), NOW).unwrap()
}

#[test]
fn rendezvous_stream_relay_contract_mints_offer_from_guest_credential() {
    let credential = credential();

    let offer = mint_relay_stream_offer(mint_input_for(&credential), &signer()).unwrap();

    assert_eq!(offer.payload.guest_device_pub, credential.guest_device_pub);
    assert_eq!(offer.payload.slot_id, credential.slot_id);
    assert_eq!(offer.payload.claw_id, credential.claw_id);
    assert_eq!(offer.payload.not_after, NOT_AFTER);
    offer.verify_owner_signature(&owner_pub(), NOW).unwrap();
    offer
        .verify_for_audience(&owner_pub(), &credential.guest_device_pub, NOW)
        .unwrap();
    assert!(
        !offer
            .to_noise_prologue_for_audience(&owner_pub(), &credential.guest_device_pub, NOW)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn rendezvous_stream_relay_contract_minted_offer_rejects_wrong_guest_audience() {
    let offer = minted_offer();

    assert!(matches!(
        offer.verify_for_audience(&owner_pub(), &other_guest_pub(), NOW),
        Err(RelayStreamContractError::AudienceMismatch)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_mint_rejects_not_after_beyond_credential_expiry() {
    let credential = credential();
    let mut input = mint_input_for(&credential);
    input.not_after = credential.expires_at + 1;

    assert!(matches!(
        mint_relay_stream_offer(input, &signer()),
        Err(RelayStreamContractError::MintNotAfterExceedsCredentialExpiry)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_mint_rejects_not_after_not_in_future() {
    let credential = credential();
    let mut input = mint_input_for(&credential);
    input.not_after = NOW;

    assert!(matches!(
        mint_relay_stream_offer(input, &signer()),
        Err(RelayStreamContractError::Expired)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_mint_rejects_wrong_owner_signer() {
    let credential = credential();

    assert!(matches!(
        mint_relay_stream_offer(mint_input_for(&credential), &attacker()),
        Err(RelayStreamContractError::MintOwnerMismatch)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_mint_uses_credential_guest_by_construction() {
    let credential = credential_for_guest(other_guest_pub());

    let offer = mint_relay_stream_offer(mint_input_for(&credential), &signer()).unwrap();

    assert_eq!(offer.payload.guest_device_pub, other_guest_pub());
    assert!(
        offer
            .verify_for_audience(&owner_pub(), &other_guest_pub(), NOW)
            .is_ok()
    );
    assert!(matches!(
        offer.verify_for_audience(&owner_pub(), &guest_pub(), NOW),
        Err(RelayStreamContractError::AudienceMismatch)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_mint_debug_and_errors_do_not_leak_token_or_secret() {
    let credential = credential();
    let input = RelayStreamOfferMintInput {
        rendezvous_token: RendezvousToken::try_new(b"0123456789abcdef").unwrap(),
        credential: &credential,
        resource: RelayStreamResource::Pty,
        expected_path: RelayStreamExpectedPath::RelayStream,
        relay_endpoint: "relay-stream://127.0.0.1:49152".to_string(),
        claw_static_pub: static_pub(0x33),
        not_after: NOT_AFTER,
        now_unix: NOW,
        app_presentation: None,
    };
    let debug = format!("{input:?}");

    assert!(!debug.contains("0123456789abcdef"));
    assert!(!debug.contains("30313233343536373839616263646566"));
    assert!(debug.contains("redacted"));

    let err = mint_relay_stream_offer(input, &attacker()).unwrap_err();
    let error_text = format!("{err:?}");
    assert!(!error_text.contains("0123456789abcdef"));
    assert!(!error_text.contains("30313233343536373839616263646566"));
}

#[test]
fn rendezvous_stream_relay_contract_roundtrip_and_canonical_bytes_are_deterministic() {
    let offer = signed_offer();

    offer.verify_owner_signature(&owner_pub(), NOW).unwrap();
    offer
        .verify_for_audience(&owner_pub(), &guest_pub(), NOW)
        .unwrap();
    let payload_a = offer.payload.to_canonical_bytes().unwrap();
    let payload_b = offer.payload.to_canonical_bytes().unwrap();
    assert_eq!(payload_a, payload_b);

    let encoded = offer.to_canonical_bytes().unwrap();
    let decoded = RelayStreamOfferContract::from_canonical_bytes(&encoded).unwrap();
    assert_eq!(decoded, offer);
    assert_eq!(decoded.to_canonical_bytes().unwrap(), encoded);
}

#[test]
fn rendezvous_stream_relay_contract_token_change_fails_binding() {
    let mut offer = signed_offer();
    offer.payload.rendezvous_token = token(0x99);

    assert!(matches!(
        offer.verify(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_audience_change_fails_binding() {
    let mut offer = signed_offer();
    offer.payload.guest_device_pub = other_guest_pub();

    assert!(matches!(
        offer.verify_owner_signature(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_claw_id_change_fails_binding() {
    let mut offer = signed_offer();
    offer.payload.claw_id = "claw_beta".to_string();

    assert!(matches!(
        offer.verify(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_slot_and_static_key_changes_fail_binding() {
    let mut slot_changed = signed_offer();
    slot_changed.payload.slot_id = SlotId([0x23; 16]);
    assert!(matches!(
        slot_changed.verify(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));

    let mut static_key_changed = signed_offer();
    static_key_changed.payload.claw_static_pub = static_pub(0x44);
    assert!(matches!(
        static_key_changed.verify(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_resource_change_fails_binding() {
    let mut offer = signed_offer();
    offer.payload.resource = RelayStreamResource::ClawSite;

    assert!(matches!(
        offer.verify(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_ip_tunnel_is_distinct_signed_resource() {
    let offer = signed_offer_with(|payload| payload.resource = RelayStreamResource::IpTunnel);

    offer.verify(&owner_pub(), NOW).unwrap();
    assert_eq!(offer.payload.resource, RelayStreamResource::IpTunnel);

    let encoded = offer.to_canonical_bytes().unwrap();
    let decoded = RelayStreamOfferContract::from_canonical_bytes(&encoded).unwrap();
    assert_eq!(decoded.payload.resource, RelayStreamResource::IpTunnel);
    assert_eq!(decoded, offer);

    let mut downgraded = offer;
    downgraded.payload.resource = RelayStreamResource::Pty;
    assert!(matches!(
        downgraded.verify(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_relay_endpoint_and_path_change_fail_binding() {
    let mut endpoint_changed = signed_offer();
    endpoint_changed.payload.relay_endpoint = "relay-stream://127.0.0.1:49153".to_string();
    assert!(matches!(
        endpoint_changed.verify(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));

    let mut path_changed = signed_offer();
    path_changed.payload.expected_path = RelayStreamExpectedPath::CommunityRelay;
    assert!(matches!(
        path_changed.verify(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_expired_offer_fails_validation() {
    let mut offer = signed_offer();
    offer.payload.not_after = NOW;

    assert!(matches!(
        offer.verify(&owner_pub(), NOW),
        Err(RelayStreamContractError::Expired)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_attacker_signed_offer_fails_owner_anchor() {
    let offer = RelayStreamOfferContract::sign(payload(), &attacker()).unwrap();

    assert!(matches!(
        offer.verify(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignerMismatch)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_wrong_audience_fails_guest_verification() {
    let offer = signed_offer();

    assert!(matches!(
        offer.verify_for_audience(&owner_pub(), &other_guest_pub(), NOW),
        Err(RelayStreamContractError::AudienceMismatch)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_audience_changes_canonical_payload() {
    let base = payload().to_canonical_bytes().unwrap();
    let changed = signed_offer_with(|payload| payload.guest_device_pub = other_guest_pub())
        .payload
        .to_canonical_bytes()
        .unwrap();

    assert_ne!(changed, base);
}

#[test]
fn rendezvous_stream_relay_contract_debug_does_not_leak_token_or_secret() {
    let secret_text = b"0123456789abcdef";
    let payload = RelayStreamOfferPayload::new(
        RendezvousToken::try_new(secret_text).unwrap(),
        "claw_alpha".to_string(),
        SlotId([0x22; 16]),
        guest_pub(),
        RelayStreamResource::Pty,
        RelayStreamExpectedPath::RelayStream,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
    );
    let offer = RelayStreamOfferContract::sign(payload, &signer()).unwrap();
    let debug = format!("{offer:?}");

    assert!(!debug.contains("0123456789abcdef"));
    assert!(!debug.contains("30313233343536373839616263646566"));
    assert!(debug.contains("redacted"));
}

#[test]
fn rendezvous_stream_relay_contract_noise_prologue_roundtrip_and_bytes_are_deterministic() {
    let offer = signed_offer();

    let prologue_a = noise_prologue_for(&offer);
    let prologue_b = noise_prologue_for(&offer);
    assert_eq!(prologue_a, prologue_b);
    assert!(!prologue_a.is_empty());

    let decoded = RelayStreamNoisePrologue::from_canonical_bytes(prologue_a.as_bytes()).unwrap();
    assert_eq!(decoded, prologue_a);
}

#[test]
fn rendezvous_stream_relay_contract_noise_prologue_changes_when_bound_fields_change() {
    let base = noise_prologue_for(&signed_offer());

    let variants = [
        signed_offer_with(|payload| payload.rendezvous_token = token(0x99)),
        signed_offer_with(|payload| payload.guest_device_pub = other_guest_pub()),
        signed_offer_with(|payload| payload.claw_static_pub = static_pub(0x44)),
        signed_offer_with(|payload| payload.slot_id = SlotId([0x23; 16])),
        signed_offer_with(|payload| payload.claw_id = "claw_beta".to_string()),
        signed_offer_with(|payload| payload.resource = RelayStreamResource::ClawSite),
        signed_offer_with(|payload| {
            payload.expected_path = RelayStreamExpectedPath::CommunityRelay;
        }),
        signed_offer_with(|payload| {
            payload.relay_endpoint = "relay-stream://127.0.0.1:49153".to_string();
        }),
        signed_offer_with(|payload| payload.not_after = NOT_AFTER + 1),
    ];

    for variant in variants {
        assert_ne!(noise_prologue_for(&variant), base);
    }

    // Fase E2: compare an allowed resource so the audience binding is
    // exercised independently of the shared-audience PTY policy.
    let device_clawsite = signed_offer_with(|payload| {
        payload.resource = RelayStreamResource::ClawSite;
    });
    let group_clawsite = signed_offer_with(|payload| {
        payload.resource = RelayStreamResource::ClawSite;
        payload.authz = Some(RelayStreamAudience::Group {
            group_id: "g".to_string(),
            member_id: "g_a".to_string(),
        });
    });
    assert_ne!(
        noise_prologue_for(&group_clawsite),
        noise_prologue_for(&device_clawsite)
    );
}

#[test]
fn rendezvous_stream_relay_contract_noise_prologue_rejects_expired_offer() {
    let offer = signed_offer_with(|payload| payload.not_after = NOW);

    assert!(matches!(
        offer.to_noise_prologue(&owner_pub(), NOW),
        Err(RelayStreamContractError::Expired)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_noise_prologue_rejects_attacker_signed_offer() {
    let offer = RelayStreamOfferContract::sign(payload(), &attacker()).unwrap();

    assert!(matches!(
        offer.to_noise_prologue(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignerMismatch)
    ));
}

#[test]
fn rendezvous_stream_relay_contract_noise_prologue_debug_does_not_leak_token_or_secret() {
    let secret_text = b"0123456789abcdef";
    let offer = signed_offer_with(|payload| {
        payload.rendezvous_token = RendezvousToken::try_new(secret_text).unwrap();
    });
    let prologue = noise_prologue_for(&offer);
    let debug = format!("{prologue:?}");

    assert!(!debug.contains("0123456789abcdef"));
    assert!(!debug.contains("30313233343536373839616263646566"));
    assert!(debug.contains("redacted"));
}

// ── Fase E2: authz cannot be downgraded/confused after signing ───────────

#[test]
fn rendezvous_stream_relay_contract_authz_downgrade_or_cross_mode_fails_binding() {
    // The audience mode lives inside the signed canonical bytes (invariant
    // #6): a signed Group offer cannot be downgraded to Device (authz
    // stripped) or confused into Public, and a signed Device offer cannot be
    // upgraded to Group, without breaking the owner signature.
    let group = || {
        signed_offer_with(|payload| {
            payload.resource = RelayStreamResource::ClawSite;
            payload.authz = Some(RelayStreamAudience::Group {
                group_id: "g".to_string(),
                member_id: "g_a".to_string(),
            });
        })
    };

    // As signed (Group), it verifies.
    group().verify_owner_signature(&owner_pub(), NOW).unwrap();

    // Downgrade Group -> Device (strip authz) breaks the signature.
    let mut downgraded = group();
    downgraded.payload.authz = None;
    assert!(matches!(
        downgraded.verify_owner_signature(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));

    // Cross-mode Group -> Public breaks the signature.
    let mut to_public = group();
    to_public.payload.authz = Some(RelayStreamAudience::Public);
    assert!(matches!(
        to_public.verify_owner_signature(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));

    // Reverse: a signed Device offer (authz None) cannot be upgraded to Group.
    let mut upgraded = signed_offer_with(|payload| {
        payload.resource = RelayStreamResource::ClawSite;
    });
    upgraded.payload.authz = Some(RelayStreamAudience::Group {
        group_id: "g".to_string(),
        member_id: "g_a".to_string(),
    });
    assert!(matches!(
        upgraded.verify_owner_signature(&owner_pub(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));
}

#[test]
fn rendezvous_stream_relay_offer_rejects_unknown_field_and_unknown_audience_variant() {
    // Invariant #7: deny_unknown_fields rejects a stray top-level field, and
    // the closed audience enum rejects an unknown variant tag. We round-trip a
    // real payload through a CBOR Value, mutate it, and assert the typed decode
    // fails — exercising the wire-decode boundary, not just the serde attrs.
    use ciborium::value::Value;

    fn to_value(payload: &RelayStreamOfferPayload) -> Value {
        ciborium::de::from_reader(payload.to_canonical_bytes().unwrap().as_slice()).unwrap()
    }
    fn encode(value: &Value) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(value, &mut buf).unwrap();
        buf
    }

    // (1) Extra unknown top-level field -> rejected.
    let mut with_extra = to_value(&payload());
    if let Value::Map(entries) = &mut with_extra {
        entries.push((Value::Text("bogus".to_string()), Value::Bool(true)));
    } else {
        panic!("offer payload must encode as a CBOR map");
    }
    let decoded: Result<RelayStreamOfferPayload, _> =
        crate::cbor::from_canonical_slice(&encode(&with_extra));
    assert!(
        decoded.is_err(),
        "an unknown extra field must be rejected (deny_unknown_fields)"
    );

    // (2) Unknown audience variant tag -> rejected. A Group audience encodes
    // as a single-key map {"group": {...}}; rename the tag to an unknown one.
    let group = payload().with_authz(RelayStreamAudience::Group {
        group_id: "g".to_string(),
        member_id: "g_a".to_string(),
    });
    let mut with_bogus_variant = to_value(&group);
    if let Value::Map(entries) = &mut with_bogus_variant {
        for (key, val) in entries.iter_mut() {
            if matches!(key, Value::Text(t) if t == "authz") {
                let Value::Map(inner) = val else {
                    panic!("group authz must encode as a tagged map");
                };
                for (variant_key, _) in inner.iter_mut() {
                    if matches!(variant_key, Value::Text(t) if t == "group") {
                        *variant_key = Value::Text("bogus".to_string());
                    }
                }
            }
        }
    }
    let decoded: Result<RelayStreamOfferPayload, _> =
        crate::cbor::from_canonical_slice(&encode(&with_bogus_variant));
    assert!(
        decoded.is_err(),
        "an unknown audience variant must be rejected by the closed enum"
    );
}

// Cross-language fixture (Rust half): a deterministic relay_stream offer
// payload with authz=None (Device) MUST encode to byte-identical canonical CBOR
// as a pre-Fase-E2 v2 offer — the authz key is omitted from the wire
// (skip_serializing_if). This locks the Rust side and the byte-identity-to-v2
// migration invariant (design risk #5, the merge gate).
//
// TODO(cross-repo / iSoyehtTerm): mirror EXPECTED_OFFER_V2_AUTHZ_NONE_HEX below
// in the Swift RelayStream offer fixture (alongside the existing
// ClawShareCrossLanguageFixtureTests). The cross-stack guarantee lands when the
// Swift fixture asserts the SAME literal. Regenerate both in lockstep (run with
// --nocapture) only on an intentional wire-shape change.
//
// Deterministic inputs: rendezvous_token [0x42;16], claw_id "claw_alpha",
// slot_id [0x22;16], guest_device_pub = P-256 public for secret scalar
// [0x33;32], resource pty, expected_path relay_stream, relay_endpoint
// "relay-stream://127.0.0.1:49152", claw_static_pub [0x33;32], not_after
// 1_800_000_060.
#[test]
fn cross_language_fixture_relay_stream_offer_authz_none_v2_hex() {
    let payload = RelayStreamOfferPayload::new(
        token(0x42),
        "claw_alpha".to_string(),
        SlotId([0x22; 16]),
        guest_pub(),
        RelayStreamResource::Pty,
        RelayStreamExpectedPath::RelayStream,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
    );
    assert!(payload.authz.is_none());
    assert_eq!(payload.audience(), RelayStreamAudience::Device);

    let bytes = payload.to_canonical_bytes().unwrap();
    // Byte-identity to a pre-authz v2 offer: the authz key never appears.
    assert!(
        !bytes.windows(5).any(|w| w == b"authz"),
        "authz must be omitted from the wire when None"
    );

    let hex_actual = hex::encode(&bytes);
    assert_eq!(
        hex_actual, EXPECTED_OFFER_V2_AUTHZ_NONE_HEX,
        "relay_stream offer v2 wire drift — regenerate the Swift fixture in lockstep"
    );

    // Canonical encoding is deterministic within the same build.
    assert_eq!(
        hex::encode(payload.to_canonical_bytes().unwrap()),
        hex_actual
    );
}

// Group/Public counterparts of the Device fixture above (Fase E merge-gate: the
// Swift RelayStream offer fixture mirrors these). Same deterministic inputs as the
// Device fixture, only `authz` differs, so the diff vs the Device hex is EXACTLY the
// audience encoding. authz wire shape (serde externally-tagged, snake_case):
// Group => {"authz":{"group":{"group_id","member_id"}}}, header `ac` = map(12);
// Public => {"authz":"public"}, header `ac` = map(12). Group inputs: group_id
// "group_alpha", member_id "member_alpha". Regenerate BOTH these and the Swift
// fixtures in lockstep (run with --nocapture) only on an intentional wire-shape change.

#[test]
fn cross_language_fixture_relay_stream_offer_authz_group_v2_hex() {
    const EXPECTED_OFFER_V2_AUTHZ_GROUP_HEX: &str = "ac617602646b696e64781d636c61772d73686172652f72656c61792d73747265616d2d6f6666657265617574687aa16567726f7570a26867726f75705f69646b67726f75705f616c706861696d656d6265725f69646c6d656d6265725f616c70686167636c61775f69646a636c61775f616c70686167736c6f745f69645022222222222222222222222222222222687265736f7572636563707479696e6f745f61667465721a6b49d23c6d65787065637465645f706174686c72656c61795f73747265616d6e72656c61795f656e64706f696e74781e72656c61792d73747265616d3a2f2f3132372e302e302e313a34393135326f636c61775f7374617469635f707562582033333333333333333333333333333333333333333333333333333333333333337067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d7072656e64657a766f75735f746f6b656e5042424242424242424242424242424242";

    let payload = RelayStreamOfferPayload::new(
        token(0x42),
        "claw_alpha".to_string(),
        SlotId([0x22; 16]),
        guest_pub(),
        RelayStreamResource::Pty,
        RelayStreamExpectedPath::RelayStream,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
    )
    .with_authz(RelayStreamAudience::Group {
        group_id: "group_alpha".to_string(),
        member_id: "member_alpha".to_string(),
    });
    assert_eq!(
        payload.audience(),
        RelayStreamAudience::Group {
            group_id: "group_alpha".to_string(),
            member_id: "member_alpha".to_string(),
        }
    );

    let bytes = payload.to_canonical_bytes().unwrap();
    // The authz key IS on the wire for a Some(_) audience (cannot be downgraded).
    assert!(
        bytes.windows(5).any(|w| w == b"authz"),
        "authz must be present on the wire for a Group offer"
    );
    assert_eq!(
        hex::encode(&bytes),
        EXPECTED_OFFER_V2_AUTHZ_GROUP_HEX,
        "relay_stream Group offer v2 wire drift — regenerate the Swift fixture in lockstep"
    );
}

#[test]
fn cross_language_fixture_relay_stream_offer_authz_public_v2_hex() {
    const EXPECTED_OFFER_V2_AUTHZ_PUBLIC_HEX: &str = "ac617602646b696e64781d636c61772d73686172652f72656c61792d73747265616d2d6f6666657265617574687a667075626c696367636c61775f69646a636c61775f616c70686167736c6f745f69645022222222222222222222222222222222687265736f7572636563707479696e6f745f61667465721a6b49d23c6d65787065637465645f706174686c72656c61795f73747265616d6e72656c61795f656e64706f696e74781e72656c61792d73747265616d3a2f2f3132372e302e302e313a34393135326f636c61775f7374617469635f707562582033333333333333333333333333333333333333333333333333333333333333337067756573745f6465766963655f70756258210351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d7072656e64657a766f75735f746f6b656e5042424242424242424242424242424242";

    let payload = RelayStreamOfferPayload::new(
        token(0x42),
        "claw_alpha".to_string(),
        SlotId([0x22; 16]),
        guest_pub(),
        RelayStreamResource::Pty,
        RelayStreamExpectedPath::RelayStream,
        "relay-stream://127.0.0.1:49152".to_string(),
        static_pub(0x33),
        NOT_AFTER,
    )
    .with_authz(RelayStreamAudience::Public);
    assert_eq!(payload.audience(), RelayStreamAudience::Public);

    let bytes = payload.to_canonical_bytes().unwrap();
    assert!(
        bytes.windows(5).any(|w| w == b"authz"),
        "authz must be present on the wire for a Public offer"
    );
    assert_eq!(
        hex::encode(&bytes),
        EXPECTED_OFFER_V2_AUTHZ_PUBLIC_HEX,
        "relay_stream Public offer v2 wire drift — regenerate the Swift fixture in lockstep"
    );
}

// ── Slice B: signed app presentation ────────────────────────────────────

/// A credential whose `claw_id` IS a valid Share app id. The presentation
/// fence requires `presentation.app_id == payload.claw_id`, and the mint
/// takes `claw_id` from the credential — so satisfying the fence honestly
/// means minting from a credential like this, never relaxing the check.
fn app_credential(app_id: &str) -> GuestCredential {
    GuestCredential::sign(
        derive_household_id(&owner_pub()),
        derive_person_id(&owner_pub()),
        owner_pub(),
        app_id.to_string(),
        guest_pub(),
        SlotId([0x22; 16]),
        NOW - 60,
        NOW + 600,
        &signer(),
    )
    .unwrap()
}

fn share_app_id() -> String {
    format!("app_{:032x}", 0x5eed_u128)
}

#[test]
fn mint_without_presentation_stays_byte_identical_to_the_pinned_v2_fixture() {
    let credential = credential();
    let offer = mint_relay_stream_offer(mint_input_for(&credential), &signer()).unwrap();
    let bytes = offer.payload.to_canonical_bytes().unwrap();

    assert!(
        !bytes
            .windows(SHARE_APP_PRESENTATION_KEY.len())
            .any(|w| w == SHARE_APP_PRESENTATION_KEY),
        "app_presentation must be omitted from the wire when None"
    );
    // The anchor: adding the field to the mint input must not move a single
    // byte of an offer that does not carry a snapshot.
    assert_eq!(
        hex::encode(&bytes),
        EXPECTED_OFFER_V2_AUTHZ_NONE_HEX,
        "minting with app_presentation: None disturbed the v2 wire"
    );
}

#[test]
fn mint_carries_the_presentation_into_the_signed_payload() {
    let app_id = share_app_id();
    let credential = app_credential(&app_id);
    let presentation = ShareableAppPresentation::try_new(app_id.clone(), "Study", "Caio").unwrap();
    let input = RelayStreamOfferMintInput {
        resource: RelayStreamResource::ClawSite,
        app_presentation: Some(presentation.clone()),
        ..mint_input_for(&credential)
    };

    let offer = mint_relay_stream_offer(input, &signer()).unwrap();

    // Not silently dropped between the input and the payload.
    assert_eq!(offer.payload.app_presentation.as_ref(), Some(&presentation));
    assert_eq!(offer.payload.claw_id, app_id);
    // And covered by the signature: verify re-runs the whole fence
    // (Device + ClawSite + app_id == claw_id) and must accept.
    offer.verify_owner_signature(&owner_pub(), NOW).unwrap();
    offer
        .verify_for_audience(&owner_pub(), &guest_pub(), NOW)
        .unwrap();
}

#[test]
fn mint_input_and_payload_debug_show_presence_without_names() {
    let app_id = share_app_id();
    let credential = app_credential(&app_id);
    let presentation = ShareableAppPresentation::try_new(app_id.clone(), "Study", "Caio").unwrap();
    let input = RelayStreamOfferMintInput {
        resource: RelayStreamResource::ClawSite,
        app_presentation: Some(presentation),
        ..mint_input_for(&credential)
    };
    let input_debug = format!("{input:?}");
    let offer = mint_relay_stream_offer(input, &signer()).unwrap();
    let payload_debug = format!("{:?}", offer.payload);

    for (label, text) in [("mint input", &input_debug), ("payload", &payload_debug)] {
        assert!(
            text.contains("app_presentation: true"),
            "{label} Debug must record that a snapshot is present"
        );
        assert!(!text.contains("Study"), "{label} Debug leaked display_name");
        assert!(
            !text.contains("Caio"),
            "{label} Debug leaked owner_display_name"
        );
    }

    // The derived Debug on the type ITSELF is deliberately left intact —
    // the redaction belongs to the log-bearing containers, not the value.
    let direct = format!(
        "{:?}",
        ShareableAppPresentation::try_new(app_id, "Study", "Caio").unwrap()
    );
    assert!(direct.contains("Study") && direct.contains("Caio"));
}

fn device_clawsite_payload() -> RelayStreamOfferPayload {
    let mut payload = payload();
    payload.claw_id = format!("app_{:032x}", 0x5eed_u128);
    payload.resource = RelayStreamResource::ClawSite;
    payload
}

fn presentation_for(payload: &RelayStreamOfferPayload) -> ShareableAppPresentation {
    ShareableAppPresentation::try_new(payload.claw_id.clone(), "Study", "Caio").unwrap()
}

#[test]
fn presentation_round_trips_signed_and_tampering_breaks_verify() {
    let mut payload = device_clawsite_payload();
    payload.app_presentation = Some(presentation_for(&payload));

    let bytes = payload.to_canonical_bytes().unwrap();
    let decoded: RelayStreamOfferPayload = crate::cbor::from_canonical_slice(&bytes).unwrap();
    assert_eq!(decoded, payload);

    let contract = RelayStreamOfferContract::sign(payload.clone(), &signer()).unwrap();
    contract.verify(&signer().public(), NOW).unwrap();

    // The snapshot is INSIDE the signature: editing any presentation field
    // after minting breaks verification.
    let mut tampered = contract.clone();
    tampered
        .payload
        .app_presentation
        .as_mut()
        .unwrap()
        .display_name = "Other App".to_string();
    assert!(matches!(
        tampered.verify(&signer().public(), NOW),
        Err(RelayStreamContractError::SignatureRejected)
    ));
}

#[test]
fn presentation_is_rejected_outside_device_clawsite() {
    // Group audience with presentation: namespace violation even though
    // the signature would cover it.
    let mut group = device_clawsite_payload();
    group.app_presentation = Some(presentation_for(&group));
    group.authz = Some(RelayStreamAudience::Group {
        group_id: "g".to_string(),
        member_id: "g_a".to_string(),
    });
    let group = RelayStreamOfferContract::sign(group, &signer()).unwrap();
    assert!(matches!(
        group.verify(&signer().public(), NOW),
        Err(RelayStreamContractError::InvalidPresentation(
            "audience-resource"
        ))
    ));

    // Public audience with presentation.
    let mut public = device_clawsite_payload();
    public.app_presentation = Some(presentation_for(&public));
    public.authz = Some(RelayStreamAudience::Public);
    let public = RelayStreamOfferContract::sign(public, &signer()).unwrap();
    assert!(matches!(
        public.verify(&signer().public(), NOW),
        Err(RelayStreamContractError::InvalidPresentation(
            "audience-resource"
        ))
    ));

    // Device + Pty with presentation: legacy PTY must not grow a Share
    // presentation.
    let mut pty = device_clawsite_payload();
    pty.app_presentation = Some(presentation_for(&pty));
    pty.resource = RelayStreamResource::Pty;
    let pty = RelayStreamOfferContract::sign(pty, &signer()).unwrap();
    assert!(matches!(
        pty.verify(&signer().public(), NOW),
        Err(RelayStreamContractError::InvalidPresentation(
            "audience-resource"
        ))
    ));

    // Device + IpTunnel with presentation: Product A/nvpn boundary.
    let mut ip_tunnel = device_clawsite_payload();
    ip_tunnel.app_presentation = Some(presentation_for(&ip_tunnel));
    ip_tunnel.resource = RelayStreamResource::IpTunnel;
    let ip_tunnel = RelayStreamOfferContract::sign(ip_tunnel, &signer()).unwrap();
    assert!(matches!(
        ip_tunnel.verify(&signer().public(), NOW),
        Err(RelayStreamContractError::InvalidPresentation(
            "audience-resource"
        ))
    ));
}

#[test]
fn presentation_app_id_must_equal_offer_claw_id() {
    let mut payload = device_clawsite_payload();
    let mut presentation = presentation_for(&payload);
    presentation.app_id = format!("app_{:032x}", 0xdead_u128);
    payload.app_presentation = Some(presentation);
    let contract = RelayStreamOfferContract::sign(payload, &signer()).unwrap();
    assert!(matches!(
        contract.verify(&signer().public(), NOW),
        Err(RelayStreamContractError::InvalidPresentation(
            "app_id-claw-mismatch"
        ))
    ));
}

#[test]
fn presentation_validates_id_shape_and_names() {
    let app_id = format!("app_{:032x}", 0x5eed_u128);
    assert!(matches!(
        ShareableAppPresentation::try_new("claw_alpha", "Study", "Caio"),
        Err(RelayStreamContractError::InvalidPresentation("app_id"))
    ));
    for bad_name in ["", "   "] {
        assert!(matches!(
            ShareableAppPresentation::try_new(app_id.clone(), bad_name, "Caio"),
            Err(RelayStreamContractError::InvalidPresentation(
                "display_name"
            ))
        ));
        assert!(matches!(
            ShareableAppPresentation::try_new(app_id.clone(), "Study", bad_name),
            Err(RelayStreamContractError::InvalidPresentation(
                "owner_display_name"
            ))
        ));
    }
    let oversized = "x".repeat(129);
    assert!(matches!(
        ShareableAppPresentation::try_new(app_id.clone(), oversized, "Caio"),
        Err(RelayStreamContractError::InvalidPresentation(
            "display_name"
        ))
    ));
}

#[test]
fn presentation_nested_unknown_field_fails_closed() {
    let mut payload = device_clawsite_payload();
    payload.app_presentation = Some(presentation_for(&payload));
    let bytes = payload.to_canonical_bytes().unwrap();

    // Inject an extra key INSIDE the nested app_presentation map. The
    // nested deny_unknown_fields must reject the decode: an ignored key
    // would vanish on re-encode and let unauthenticated bytes verify.
    let mut value: ciborium::value::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    let ciborium::value::Value::Map(entries) = &mut value else {
        panic!("payload must decode to a map");
    };
    let presentation_entry = entries
            .iter_mut()
            .find(|(key, _)| matches!(key, ciborium::value::Value::Text(text) if text == "app_presentation"))
            .expect("presentation key present");
    let ciborium::value::Value::Map(nested) = &mut presentation_entry.1 else {
        panic!("presentation must be a map");
    };
    nested.push((
        ciborium::value::Value::Text("evil".to_string()),
        ciborium::value::Value::Text("injected".to_string()),
    ));
    let mut poisoned = Vec::new();
    ciborium::ser::into_writer(&value, &mut poisoned).unwrap();

    let decoded: Result<RelayStreamOfferPayload, _> = crate::cbor::from_canonical_slice(&poisoned);
    assert!(
        decoded.is_err(),
        "a nested unknown field must fail the decode, not be silently dropped"
    );
}
