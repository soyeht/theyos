#![cfg(test)]

use super::*;
use household_rs::machine_cert::{Platform, SignOptions};
use household_rs::{P256Keypair, PersonId, derive_household_id};

fn machine_attestation_fixture() -> (P256Keypair, P256Keypair, MachineCert) {
    let household = P256Keypair::from_secret_scalar(&[0x41; 32]).expect("household test scalar");
    let machine = P256Keypair::from_secret_scalar(&[0x42; 32]).expect("machine test scalar");
    let cert = MachineCert::sign(
        &household,
        &machine.public(),
        &SignOptions {
            hh_id: derive_household_id(&household.public()),
            hostname: "attested-mac".into(),
            platform: Platform::Macos,
            joined_at: 1_800_000_000,
        },
    )
    .expect("machine cert");
    (household, machine, cert)
}

#[test]
fn machine_attestation_is_root_verified_and_canonical_cbor_bstr() {
    let (household, machine, cert) = machine_attestation_fixture();
    let bytes =
        canonical_machine_attestation(&cert, &cert.hh_id, &household.public(), &machine.public())
            .expect("valid attestation");
    let expected = cbor::to_canonical_vec(&cert).expect("canonical cert");
    assert_eq!(bytes.as_ref(), expected.as_slice());

    let response = MintInviteResponse {
        v: 1,
        uri: "soyeht://claw-share/v1?e=test".into(),
        slot_id: serde_bytes::ByteBuf::from(vec![0x11; 16]),
        expires_at: 1_800_000_900,
        machine_cert: bytes,
    };
    let encoded = cbor::to_canonical_vec(&response).expect("response CBOR");
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DecodedResponse {
        v: u8,
        uri: String,
        slot_id: serde_bytes::ByteBuf,
        expires_at: u64,
        machine_cert: serde_bytes::ByteBuf,
    }
    let decoded: DecodedResponse = cbor::from_canonical_slice(&encoded).expect("response value");
    assert_eq!(decoded.v, 1);
    assert_eq!(decoded.uri, "soyeht://claw-share/v1?e=test");
    assert_eq!(decoded.slot_id.as_ref(), &[0x11; 16]);
    assert_eq!(decoded.expires_at, 1_800_000_900);
    assert_eq!(
        decoded.machine_cert.as_ref(),
        expected.as_slice(),
        "machine_cert must be a CBOR byte string containing the byte-exact canonical cert",
    );
}

#[test]
fn machine_attestation_rejects_wrong_root_household_signer_and_tamper() {
    let (household, machine, cert) = machine_attestation_fixture();
    let other_household =
        P256Keypair::from_secret_scalar(&[0x43; 32]).expect("other household scalar");
    let other_machine = P256Keypair::from_secret_scalar(&[0x44; 32]).expect("other machine scalar");

    assert_eq!(
        canonical_machine_attestation(
            &cert,
            &cert.hh_id,
            &other_household.public(),
            &machine.public(),
        ),
        Err(MintMachineAttestationError::CertificateInvalid),
    );
    assert_eq!(
        canonical_machine_attestation(
            &cert,
            &derive_household_id(&other_household.public()),
            &household.public(),
            &machine.public(),
        ),
        Err(MintMachineAttestationError::HouseholdMismatch),
    );
    assert_eq!(
        canonical_machine_attestation(
            &cert,
            &cert.hh_id,
            &household.public(),
            &other_machine.public(),
        ),
        Err(MintMachineAttestationError::SigningKeyMismatch),
    );

    let mut tampered = cert.clone();
    tampered.hostname = "tampered-mac".into();
    assert_eq!(
        canonical_machine_attestation(
            &tampered,
            &tampered.hh_id,
            &household.public(),
            &machine.public(),
        ),
        Err(MintMachineAttestationError::CertificateInvalid),
    );
}

#[test]
fn invite_must_match_attested_household_and_machine_key() {
    let (_household, machine, cert) = machine_attestation_fixture();
    let invite = ClawShareInvite::sign(
        cert.hh_id.clone(),
        PersonId(format!("p_{}", "a".repeat(52))),
        machine.public(),
        "claw-test".into(),
        SlotId::random(),
        TunnelHandle::Loopback {
            channel: "attestation-test".into(),
        },
        1_800_000_900,
        "relay-npub".into(),
        vec!["wss://relay.invalid".into()],
        &machine,
    )
    .expect("signed invite");
    verify_invite_machine_attestation(&invite, &cert).expect("matching invite");

    let mut wrong_household = invite.clone();
    let other_household =
        P256Keypair::from_secret_scalar(&[0x43; 32]).expect("other household scalar");
    wrong_household.hh_id = derive_household_id(&other_household.public());
    assert_eq!(
        verify_invite_machine_attestation(&wrong_household, &cert),
        Err(MintMachineAttestationError::InviteHouseholdMismatch),
    );

    let mut wrong_signer = invite;
    wrong_signer.owner_p_pub = P256Keypair::from_secret_scalar(&[0x44; 32])
        .expect("other machine scalar")
        .public();
    assert_eq!(
        verify_invite_machine_attestation(&wrong_signer, &cert),
        Err(MintMachineAttestationError::InviteSigningKeyMismatch),
    );
}

// ── Relay claim fields: single source of truth + fail closed ──

#[test]
fn relay_fields_resolve_from_identity_independent_of_mesh() {
    // `owner_engine_npub` comes straight from the relay receive identity
    // passed in — NOT from mesh. So an engine with mesh disabled still
    // mints a valid `owner_engine_npub` as long as a relay identity exists.
    let npub = "aa".repeat(32);
    let (owner_engine_npub, claim_relays) =
        resolve_relay_claim_fields(Some(&npub), Some("wss://relay.one, wss://relay.two ,,"))
            .expect("should resolve with identity + relays");
    assert_eq!(
        owner_engine_npub, npub,
        "owner_engine_npub passes through from the relay identity"
    );
    assert_eq!(claim_relays, vec!["wss://relay.one", "wss://relay.two"]);
}

#[test]
fn relay_fields_fail_closed_without_relay_identity() {
    // No identity → refuse to mint (would advertise an empty target).
    assert_eq!(
        resolve_relay_claim_fields(None, Some("wss://relay.one")),
        Err("relay_identity_unavailable"),
    );
    // Empty-string identity is also rejected — no silent empty field.
    assert_eq!(
        resolve_relay_claim_fields(Some(""), Some("wss://relay.one")),
        Err("relay_identity_unavailable"),
    );
}

#[test]
fn relay_fields_fail_closed_without_relays() {
    let npub = "bb".repeat(32);
    // No relay list configured at all.
    assert_eq!(
        resolve_relay_claim_fields(Some(&npub), None),
        Err("claim_relays_unconfigured"),
    );
    // Present but whitespace/empty-only → still fails closed (no silent
    // empty list slips through).
    assert_eq!(
        resolve_relay_claim_fields(Some(&npub), Some("   , ,")),
        Err("claim_relays_unconfigured"),
    );
}

// ── owner_engine_npub == relay-loop subscription key ──

/// The invite's `owner_engine_npub` is the engine relay key's x-only hex
/// (`public_key().to_hex()` — what bootstrap stores in `engine_relay_npub`
/// and the mint advertises). The relay claim loop subscribes/decrypts on
/// that SAME `public_key()`. A friend decoding the advertised npub MUST
/// arrive at the exact key the engine listens on, else the claim lands on a
/// pubkey nobody reads. This pins the single-source-of-truth invariant that
/// the prior bug (mint advertised the mesh npub) violated.
#[test]
fn advertised_owner_engine_npub_decodes_to_relay_subscription_key() {
    use nostr_relay_rs::nostr::{Keys, PublicKey};
    let engine_keys = Keys::generate();
    let advertised = engine_keys.public_key().to_hex(); // bootstrap → engine_relay_npub → mint
    let subscribed = engine_keys.public_key(); // claw_share_relay_loop Filter::pubkey(...)
    let decoded = PublicKey::from_hex(&advertised).expect("advertised npub is valid hex");
    assert_eq!(
        decoded, subscribed,
        "owner_engine_npub must decode to the relay subscription key",
    );
}

// ── Direct public data-tunnel address parsing ──

#[test]
fn public_data_tunnel_addr_parses_host_port() {
    assert_eq!(
        parse_public_data_tunnel_addr("192.168.15.12:7423"),
        Some(TunnelHandle::Direct {
            host: "192.168.15.12".into(),
            port: 7423
        }),
    );
    // trims whitespace.
    assert_eq!(
        parse_public_data_tunnel_addr("  mac.local : 7423 "),
        Some(TunnelHandle::Direct {
            host: "mac.local".into(),
            port: 7423
        }),
    );
}

#[test]
fn public_data_tunnel_addr_rejects_malformed() {
    // Never advertise a half-broken Direct handle.
    assert_eq!(parse_public_data_tunnel_addr(""), None);
    assert_eq!(parse_public_data_tunnel_addr("no-port"), None);
    assert_eq!(parse_public_data_tunnel_addr("host:notaport"), None);
    assert_eq!(parse_public_data_tunnel_addr("host:"), None);
    assert_eq!(parse_public_data_tunnel_addr(":7423"), None);
    assert_eq!(parse_public_data_tunnel_addr("host:99999"), None); // > u16::MAX
}

// ---- R134: public direct engine peer (CPE port-forward / WAN endpoint) ----

// ── F1: shared GroupOp → MeshEvent translation (post-auth apply helper) ──

#[test]
fn group_op_to_event_maps_membership_variants() {
    // The four ops the group-claim membership gate depends on must map to the
    // exact mesh events `check_relay_stream_group_membership` reads.
    let ev = group_op_to_event(&GroupOp::Create {
        group_id: "g".into(),
        name: "G".into(),
    })
    .expect("create translates");
    assert!(matches!(ev, MeshEvent::GroupCreated { .. }));

    let ev = group_op_to_event(&GroupOp::AddMember {
        group_id: "g".into(),
        member_id: "g_m".into(),
        label: "phone".into(),
    })
    .expect("add_member translates");
    assert!(matches!(ev, MeshEvent::GroupMemberAdded { .. }));

    let ev = group_op_to_event(&GroupOp::GrantClaw {
        group_id: "g".into(),
        claw_id: "claw_a".into(),
    })
    .expect("grant_claw translates");
    assert!(matches!(ev, MeshEvent::GroupClawGranted { .. }));
}

#[test]
fn group_op_to_event_enroll_verifies_binding_fail_closed() {
    use household_rs::keys::P256Keypair;
    use household_rs::member_identity::MemberDeviceBinding;

    let member = P256Keypair::generate();
    let device = P256Keypair::generate();
    let binding = MemberDeviceBinding::sign(
        &member,
        device.public(),
        "participant_npub_hex".into(),
        1_800_000_000,
    )
    .expect("sign member binding");

    // A valid self-signed binding records the enrol event.
    let ev = group_op_to_event(&GroupOp::EnrollMemberDevice {
        binding: binding.clone(),
    })
    .expect("valid binding accepted");
    assert!(matches!(ev, MeshEvent::MeshMemberDeviceEnrolled { .. }));

    // A forged member_id (no longer derives from member_pub) is rejected with
    // 400 — the SAME fail-closed validation the prod path enforced inline, now
    // shared verbatim by /group-op and the dev-only /dev-group-op fixture.
    let mut forged = binding;
    forged.member_id = "g_forged_member_id".into();
    let resp = group_op_to_event(&GroupOp::EnrollMemberDevice { binding: forged })
        .expect_err("forged member_id rejected");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── F2: the /dev-group-op seed satisfies the live group-claim gate ──

#[test]
fn dev_group_op_sequence_satisfies_live_membership_gate() {
    // The exact four ops /dev-group-op applies, run through the SAME
    // group_op_to_event + log_event the handler uses, must leave the live
    // projection in a state that PASSES check_relay_stream_group_membership
    // for the matching member+device — i.e. the live group claim will be
    // authorized. This is the F2↔F3 contract proven without a live engine.
    use crate::claw_share_relay_stream_contract::check_relay_stream_group_membership;
    use household_rs::household_mesh_log::MeshLogStore;
    use household_rs::keys::P256Keypair;
    use household_rs::member_identity::MemberDeviceBinding;

    let owner = P256Keypair::generate();
    // The SAME fixed secrets the smoke feeds to BOTH the dev seed and the
    // friend-cli claim → identical member_id + device_pub.
    let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).expect("member scalar");
    let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("device scalar");
    let device_pub = device.public();
    let binding = MemberDeviceBinding::sign(
        &member,
        device_pub.clone(),
        "participant_npub_hex".into(),
        1_800_000_000,
    )
    .expect("sign binding");
    let member_id = binding.member_id.clone();

    let mesh = MeshLogStore::new();
    let now = 1_800_000_100u64;
    let ops = [
        GroupOp::Create {
            group_id: "g".into(),
            name: "G".into(),
        },
        GroupOp::AddMember {
            group_id: "g".into(),
            member_id: member_id.clone(),
            label: "phone".into(),
        },
        GroupOp::EnrollMemberDevice { binding },
        GroupOp::GrantClaw {
            group_id: "g".into(),
            claw_id: "claw_a".into(),
        },
    ];
    for op in ops {
        let event = group_op_to_event(&op).expect("translate");
        log_event(&mesh, &owner as &dyn IdentityKey, now, event).expect("append");
    }

    let proj = mesh.project();
    check_relay_stream_group_membership(&proj, "g", &member_id, "claw_a", &device_pub)
        .expect("the dev-group-op sequence must satisfy the live membership gate");

    // Fail-closed negatives: a different device, claw, or group is rejected.
    let other_device = P256Keypair::from_secret_scalar(&[0x44u8; 32]).unwrap();
    assert!(
        check_relay_stream_group_membership(
            &proj,
            "g",
            &member_id,
            "claw_a",
            &other_device.public()
        )
        .is_err()
    );
    assert!(
        check_relay_stream_group_membership(&proj, "g", &member_id, "claw_other", &device_pub)
            .is_err()
    );
    assert!(
        check_relay_stream_group_membership(&proj, "other_g", &member_id, "claw_a", &device_pub)
            .is_err()
    );
}

#[cfg(feature = "dev_claw_share_mint")]
#[test]
fn dev_keypair_from_hex_matches_cross_language_fixture() {
    // Scalar [0x55;32] → the member_pub, and [0x33;32] → the device_pub,
    // pinned as the cross-language fixture. Proves the server parse
    // == friend-cli's member_key_from_hex == the cross-language fixture, so
    // the same --member-secret/--device-secret yield identical keys on both.
    let m = dev_keypair_from_hex(&"55".repeat(32)).expect("valid member scalar");
    assert_eq!(
        hex::encode(&m.public().as_bytes()[..]),
        "0257e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34"
    );
    let d = dev_keypair_from_hex(&"33".repeat(32)).expect("valid device scalar");
    assert_eq!(
        hex::encode(&d.public().as_bytes()[..]),
        "0351a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d"
    );
    // Shape-hiding 400 reasons (never panic, never leak).
    assert_eq!(
        dev_keypair_from_hex("abcd").err(),
        Some("secret_not_64_hex")
    );
    assert!(dev_keypair_from_hex(&"zz".repeat(32)).is_err());
}

// ── Ergonomic invite-to-claw endpoint (front half) ──

#[test]
fn invite_to_claw_ops_creates_group_only_when_absent() {
    use household_rs::keys::P256Keypair;

    let req = InviteToClawRequest {
        v: 1,
        group_id: "g".into(),
        group_name: "G".into(),
        member_id: "g_member".into(),
        label: "phone".into(),
        claw_id: "claw_a".into(),
    };

    // Absent group: Create is composed first, then AddMember + GrantClaw.
    let empty = MeshLogStore::new().project();
    let ops = invite_to_claw_ops(&empty, &req);
    assert_eq!(ops.len(), 3);
    assert!(matches!(ops[0], GroupOp::Create { .. }));
    assert!(matches!(ops[1], GroupOp::AddMember { .. }));
    assert!(matches!(ops[2], GroupOp::GrantClaw { .. }));

    // Existing group: Create is skipped (reused unchanged) — only AddMember + GrantClaw.
    let owner = P256Keypair::generate();
    let mesh = MeshLogStore::new();
    log_event(
        &mesh,
        &owner as &dyn IdentityKey,
        1_800_000_100,
        MeshEvent::GroupCreated {
            group_id: "g".into(),
            name: "G".into(),
        },
    )
    .expect("seed group");
    let ops = invite_to_claw_ops(&mesh.project(), &req);
    assert_eq!(ops.len(), 2);
    assert!(matches!(ops[0], GroupOp::AddMember { .. }));
    assert!(matches!(ops[1], GroupOp::GrantClaw { .. }));
}

#[test]
fn invite_to_claw_ops_applied_satisfy_membership_gate() {
    use household_rs::keys::P256Keypair;

    let owner = P256Keypair::generate();
    let member = P256Keypair::from_secret_scalar(&[0x55u8; 32]).expect("member scalar");
    let device = P256Keypair::from_secret_scalar(&[0x33u8; 32]).expect("device scalar");
    let device_pub = device.public();
    let binding = MemberDeviceBinding::sign(
        &member,
        device_pub.clone(),
        "participant_npub_hex".into(),
        1_800_000_000,
    )
    .expect("sign binding");
    let member_id = binding.member_id.clone();

    let mesh = MeshLogStore::new();
    let now = 1_800_000_100u64;
    let req = InviteToClawRequest {
        v: 1,
        group_id: "g".into(),
        group_name: "G".into(),
        member_id: member_id.clone(),
        label: "phone".into(),
        claw_id: "claw_a".into(),
    };

    // Apply the composed invite ops (Create + AddMember + GrantClaw)...
    for op in invite_to_claw_ops(&mesh.project(), &req) {
        let event = group_op_to_event(&op).expect("translate");
        log_event(&mesh, &owner as &dyn IdentityKey, now, event).expect("append");
    }
    // ...plus the guest's own self-signed device enrolment (a separate op the
    // invite does not — and must not — forge on the member's behalf).
    let enroll = group_op_to_event(&GroupOp::EnrollMemberDevice { binding }).expect("enroll");
    log_event(&mesh, &owner as &dyn IdentityKey, now, enroll).expect("append enroll");

    let proj = mesh.project();
    check_relay_stream_group_membership(&proj, "g", &member_id, "claw_a", &device_pub)
        .expect("invite must authorize the matching member + device + claw");

    // Fail-closed: the GrantClaw is load-bearing — a claw the invite did NOT
    // grant is rejected for the same member+device.
    assert!(
        check_relay_stream_group_membership(&proj, "g", &member_id, "claw_other", &device_pub)
            .is_err()
    );
}

#[test]
fn reinvite_into_existing_group_preserves_name_and_members() {
    use household_rs::keys::P256Keypair;

    let owner = P256Keypair::generate();
    let mesh = MeshLogStore::new();
    let now = 1_800_000_100u64;

    // First invite creates group "g" (name "Family") with member m1.
    let first = InviteToClawRequest {
        v: 1,
        group_id: "g".into(),
        group_name: "Family".into(),
        member_id: "g_m1".into(),
        label: "m1".into(),
        claw_id: "claw_a".into(),
    };
    for op in invite_to_claw_ops(&mesh.project(), &first) {
        log_event(
            &mesh,
            &owner as &dyn IdentityKey,
            now,
            group_op_to_event(&op).unwrap(),
        )
        .unwrap();
    }

    // Second invite of m2 into the SAME group carries a DIFFERENT group_name;
    // because the group already exists, Create is not composed, so the name
    // is never touched and m1 is preserved.
    let second = InviteToClawRequest {
        v: 1,
        group_id: "g".into(),
        group_name: "ATTACKER_RENAME".into(),
        member_id: "g_m2".into(),
        label: "m2".into(),
        claw_id: "claw_a".into(),
    };
    let ops = invite_to_claw_ops(&mesh.project(), &second);
    assert!(
        !ops.iter().any(|op| matches!(op, GroupOp::Create { .. })),
        "an existing group must never be re-created by a re-invite"
    );
    for op in ops {
        log_event(
            &mesh,
            &owner as &dyn IdentityKey,
            now + 1,
            group_op_to_event(&op).unwrap(),
        )
        .unwrap();
    }

    let proj = mesh.project();
    let group = proj.groups.get("g").expect("group exists");
    assert_eq!(group.name, "Family", "re-invite must not rename the group");
    assert_eq!(
        group.members.get("g_m1"),
        Some(&MeshMembership::Active),
        "the original member must be preserved"
    );
    assert_eq!(
        group.members.get("g_m2"),
        Some(&MeshMembership::Active),
        "the newly invited member must be added"
    );
}

#[test]
fn scope_conflict_none_when_group_absent() {
    let req = InviteToClawRequest {
        v: 1,
        group_id: "g".into(),
        group_name: "G".into(),
        member_id: "g_m1".into(),
        label: "m1".into(),
        claw_id: "claw_a".into(),
    };
    assert_eq!(
        invite_to_claw_scope_conflict(&ProjectedState::default(), &req),
        None
    );
}

#[test]
fn scope_conflict_none_when_group_only_grants_requested_claw() {
    use household_rs::household_mesh_log::ProjectedGroup;

    let mut projection = ProjectedState::default();
    projection.groups.insert(
        "g".to_string(),
        ProjectedGroup {
            group_id: "g".to_string(),
            name: "G".to_string(),
            members: Default::default(),
            member_labels: Default::default(),
            granted_claws: [("claw_a".to_string(), MeshMembership::Active)]
                .into_iter()
                .collect(),
            revision: 1,
        },
    );
    let req = InviteToClawRequest {
        v: 1,
        group_id: "g".into(),
        group_name: "G".into(),
        member_id: "g_m2".into(),
        label: "m2".into(),
        claw_id: "claw_a".into(),
    };
    // Idempotent re-invite / a second member into the same single-claw
    // group must still be allowed.
    assert_eq!(invite_to_claw_scope_conflict(&projection, &req), None);
}

#[test]
fn scope_conflict_rejects_group_already_granting_a_different_claw() {
    use household_rs::household_mesh_log::ProjectedGroup;

    let mut projection = ProjectedState::default();
    projection.groups.insert(
        "g".to_string(),
        ProjectedGroup {
            group_id: "g".to_string(),
            name: "G".to_string(),
            members: Default::default(),
            member_labels: Default::default(),
            granted_claws: [("claw_a".to_string(), MeshMembership::Active)]
                .into_iter()
                .collect(),
            revision: 1,
        },
    );
    let req = InviteToClawRequest {
        v: 1,
        group_id: "g".into(),
        group_name: "G".into(),
        member_id: "g_m2".into(),
        label: "m2".into(),
        claw_id: "claw_b".into(),
    };
    assert_eq!(
        invite_to_claw_scope_conflict(&projection, &req),
        Some("claw_a".to_string())
    );
}

#[test]
fn scope_conflict_ignores_revoked_grants() {
    use household_rs::household_mesh_log::ProjectedGroup;

    let mut projection = ProjectedState::default();
    projection.groups.insert(
        "g".to_string(),
        ProjectedGroup {
            group_id: "g".to_string(),
            name: "G".to_string(),
            members: Default::default(),
            member_labels: Default::default(),
            granted_claws: [("claw_a".to_string(), MeshMembership::Removed)]
                .into_iter()
                .collect(),
            revision: 1,
        },
    );
    let req = InviteToClawRequest {
        v: 1,
        group_id: "g".into(),
        group_name: "G".into(),
        member_id: "g_m2".into(),
        label: "m2".into(),
        claw_id: "claw_b".into(),
    };
    // claw_a's grant was revoked, so it no longer counts as "another claw"
    // this group is scoped to.
    assert_eq!(invite_to_claw_scope_conflict(&projection, &req), None);
}
