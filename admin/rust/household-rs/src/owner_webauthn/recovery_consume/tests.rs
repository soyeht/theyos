#![cfg(test)]

use serde_json::json;
use webauthn_rs::prelude::Passkey;

use super::*;
use crate::ids::{MachineId, derive_household_id};
use crate::keys::{IdentityKey, P256Keypair};
use crate::owner_webauthn::OwnerWebauthnCredential;
use crate::owner_webauthn::anchor::{
    OwnerWebauthnAuthorityAnchor, verified_owner_webauthn_authority_head,
};
use crate::owner_webauthn::authority::{
    OwnerWebauthnAuthority, OwnerWebauthnCredentialEventAction, OwnerWebauthnRecoveryAddInput,
    SignedOwnerWebauthnCredentialEvent,
};
use crate::owner_webauthn::recovery::{
    OwnerWebauthnRecoveryAuthority, RecoveryCodeVerifier, verified_owner_webauthn_recovery_head,
};
use crate::owner_webauthn::recovery_anchor::OwnerWebauthnRecoveryAnchor;
use crate::person_cert::{PersonCert, SignOwnerOptions};

const NOW: u64 = 1_800_000_000;

fn setup() -> (
    P256Keypair,
    crate::household_record::HouseholdRecord,
    PersonCert,
) {
    let root = P256Keypair::generate();
    let hh_pub = root.public();
    let record = crate::household_record::HouseholdRecord {
        version: crate::household_record::HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&hh_pub),
        hh_pub,
        name: "Alpha Household".to_string(),
        created_at: NOW,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()],
        is_follower: false,
    };
    let owner_key = P256Keypair::generate();
    let owner_cert = PersonCert::sign_owner(
        &root,
        SignOwnerOptions {
            hh_id: record.hh_id.clone(),
            p_pub: owner_key.public(),
            display_name: "Owner Alpha".to_string(),
            issued_at: NOW,
        },
    )
    .unwrap();
    (root, record, owner_cert)
}

fn verifier(code: &[u8]) -> RecoveryCodeVerifier {
    RecoveryCodeVerifier::from_code_bytes([0xA5; 32], code)
}

fn synthetic_passkey(id: &[u8]) -> Passkey {
    let encoded_id = data_encoding::BASE64URL_NOPAD.encode(id);
    serde_json::from_value(json!({
        "cred": {
            "cred_id": encoded_id,
            "cred": {
                "type_": "ES256",
                "key": {
                    "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": data_encoding::BASE64URL_NOPAD.encode(&[1_u8; 32]),
                        "y": data_encoding::BASE64URL_NOPAD.encode(&[2_u8; 32])
                    }
                }
            },
            "counter": 0,
            "transports": null,
            "user_verified": true,
            "backup_eligible": true,
            "backup_state": true,
            "registration_policy": "required",
            "extensions": {},
            "attestation": {
                "data": "None",
                "metadata": "None"
            },
            "attestation_format": "none"
        }
    }))
    .unwrap()
}

fn credential(id: &[u8]) -> OwnerWebauthnCredential {
    OwnerWebauthnCredential::new(synthetic_passkey(id))
}

fn webauthn_authority_with_genesis(
    root: &P256Keypair,
    record: &crate::household_record::HouseholdRecord,
    owner_cert: &PersonCert,
) -> (OwnerWebauthnAuthority, SignedOwnerWebauthnCredentialEvent) {
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        root,
        record,
        owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis.clone());
    (authority, genesis)
}

fn recovery_authority_with_provision(
    root: &P256Keypair,
    record: &crate::household_record::HouseholdRecord,
    owner_cert: &PersonCert,
) -> (
    OwnerWebauthnRecoveryAuthority,
    crate::owner_webauthn::recovery::SignedOwnerWebauthnRecoveryEvent,
) {
    let provision = OwnerWebauthnRecoveryAuthority::sign_next(
        root,
        record,
        owner_cert,
        None,
        b"owner-passkey-1",
        verifier(b"first-recovery-code"),
        NOW,
    )
    .unwrap();
    let mut authority = OwnerWebauthnRecoveryAuthority::new();
    authority.push_signed(provision.clone());
    (authority, provision)
}

fn webauthn_verified_status(
    authority: &OwnerWebauthnAuthority,
    record: &crate::household_record::HouseholdRecord,
    owner_cert: &PersonCert,
) -> OwnerWebauthnAnchorStatus {
    OwnerWebauthnAnchorStatus::Verified {
        head: verified_owner_webauthn_authority_head(authority, record, owner_cert)
            .unwrap()
            .unwrap(),
    }
}

fn recovery_verified_status(
    authority: &OwnerWebauthnRecoveryAuthority,
    record: &crate::household_record::HouseholdRecord,
    owner_cert: &PersonCert,
) -> OwnerWebauthnRecoveryAnchorStatus {
    OwnerWebauthnRecoveryAnchorStatus::Verified {
        head: verified_owner_webauthn_recovery_head(authority, record, owner_cert)
            .unwrap()
            .unwrap(),
    }
}

#[test]
fn verified_active_recovery_head_is_consumable_even_with_zero_active_count() {
    let (root, record, owner_cert) = setup();
    let (webauthn_authority, _) = webauthn_authority_with_genesis(&root, &record, &owner_cert);
    let (recovery_authority, provision) =
        recovery_authority_with_provision(&root, &record, &owner_cert);
    let readiness = classify_owner_webauthn_recovery_consume_readiness(
        &webauthn_authority,
        &webauthn_verified_status(&webauthn_authority, &record, &owner_cert),
        &recovery_authority,
        &recovery_verified_status(&recovery_authority, &record, &owner_cert),
        0,
    )
    .unwrap();

    assert_eq!(
        readiness,
        OwnerWebauthnRecoveryConsumeReadiness::Consumable {
            webauthn_head: verified_owner_webauthn_authority_head(
                &webauthn_authority,
                &record,
                &owner_cert,
            )
            .unwrap()
            .unwrap(),
            recovery_head: OwnerWebauthnRecoveryHead {
                sequence: 0,
                head_hash: provision.entry_hash().unwrap(),
            },
            pre_active_credential_count: 0,
        }
    );
}

#[test]
fn advanced_webauthn_anchor_is_eligible_for_recovery_consume() {
    let (root, record, owner_cert) = setup();
    let (mut webauthn_authority, genesis) =
        webauthn_authority_with_genesis(&root, &record, &owner_cert);
    let genesis_hash = genesis.entry_hash().unwrap();
    let actor_credential = credential(b"owner-passkey-1");
    let second = OwnerWebauthnAuthority::sign_append(
        &root,
        &record,
        &owner_cert,
        &genesis,
        actor_credential.credential_id_bytes(),
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential(b"owner-passkey-2")),
        },
        NOW + 1,
    )
    .unwrap();
    webauthn_authority.push_signed(second);
    webauthn_authority
        .reconstruct(&record, &owner_cert)
        .unwrap();
    let advanced_head =
        verified_owner_webauthn_authority_head(&webauthn_authority, &record, &owner_cert)
            .unwrap()
            .unwrap();
    let previous_anchor = OwnerWebauthnAuthorityAnchor::new(
        &record,
        &owner_cert,
        genesis.event.sequence,
        genesis_hash,
    );
    let (recovery_authority, _) = recovery_authority_with_provision(&root, &record, &owner_cert);

    let readiness = classify_owner_webauthn_recovery_consume_readiness(
        &webauthn_authority,
        &OwnerWebauthnAnchorStatus::Advanced {
            previous: previous_anchor,
            head: advanced_head.clone(),
        },
        &recovery_authority,
        &recovery_verified_status(&recovery_authority, &record, &owner_cert),
        2,
    )
    .unwrap();

    assert!(matches!(
        readiness,
        OwnerWebauthnRecoveryConsumeReadiness::Consumable {
            webauthn_head,
            pre_active_credential_count: 2,
            ..
        } if webauthn_head == advanced_head
    ));
}

#[test]
fn webauthn_recovery_add_makes_verified_head_repair_required_not_consumable() {
    let (root, record, owner_cert) = setup();
    let (mut webauthn_authority, genesis) =
        webauthn_authority_with_genesis(&root, &record, &owner_cert);
    let (recovery_authority, provision) =
        recovery_authority_with_provision(&root, &record, &owner_cert);
    let recovery_head_hash = provision.entry_hash().unwrap();
    let add = OwnerWebauthnAuthority::sign_recovery_add(
        &root,
        &record,
        &owner_cert,
        OwnerWebauthnRecoveryAddInput {
            previous_entry: &genesis,
            recovery_head_sequence: 0,
            recovery_head_hash,
            credential: credential(b"owner-passkey-2"),
            issued_at: NOW + 1,
        },
    )
    .unwrap();
    webauthn_authority.push_signed(add);
    webauthn_authority
        .reconstruct(&record, &owner_cert)
        .unwrap();

    let readiness = classify_owner_webauthn_recovery_consume_readiness(
        &webauthn_authority,
        &webauthn_verified_status(&webauthn_authority, &record, &owner_cert),
        &recovery_authority,
        &recovery_verified_status(&recovery_authority, &record, &owner_cert),
        1,
    )
    .unwrap();

    assert!(matches!(
        readiness,
        OwnerWebauthnRecoveryConsumeReadiness::RepairRequired {
            recovery_head: OwnerWebauthnRecoveryHead {
                sequence: 0,
                head_hash,
            },
            pre_active_credential_count: 1,
            ..
        } if head_hash == recovery_head_hash
    ));
}

#[test]
fn recovery_consume_tail_in_advanced_anchor_requires_repair() {
    let (root, record, owner_cert) = setup();
    let (webauthn_authority, _) = webauthn_authority_with_genesis(&root, &record, &owner_cert);
    let (mut recovery_authority, provision) =
        recovery_authority_with_provision(&root, &record, &owner_cert);
    let provision_hash = provision.entry_hash().unwrap();
    let consume = OwnerWebauthnRecoveryAuthority::sign_consume(
        &root,
        &record,
        &owner_cert,
        &provision,
        NOW + 1,
    )
    .unwrap();
    recovery_authority.push_signed(consume);
    recovery_authority.verify(&record, &owner_cert).unwrap();
    let full_head =
        verified_owner_webauthn_recovery_head(&recovery_authority, &record, &owner_cert)
            .unwrap()
            .unwrap();
    let previous_anchor = OwnerWebauthnRecoveryAnchor::new(&record, &owner_cert, 0, provision_hash);

    let readiness = classify_owner_webauthn_recovery_consume_readiness(
        &webauthn_authority,
        &webauthn_verified_status(&webauthn_authority, &record, &owner_cert),
        &recovery_authority,
        &OwnerWebauthnRecoveryAnchorStatus::Advanced {
            previous: previous_anchor,
            head: full_head,
        },
        1,
    )
    .unwrap();

    assert!(matches!(
        readiness,
        OwnerWebauthnRecoveryConsumeReadiness::RepairRequired {
            recovery_head: OwnerWebauthnRecoveryHead {
                sequence: 0,
                head_hash,
            },
            ..
        } if head_hash == provision_hash
    ));
}

#[test]
fn advanced_unanchored_rotate_is_not_a_consume_grant() {
    let (root, record, owner_cert) = setup();
    let (webauthn_authority, _) = webauthn_authority_with_genesis(&root, &record, &owner_cert);
    let (mut recovery_authority, provision) =
        recovery_authority_with_provision(&root, &record, &owner_cert);
    let provision_hash = provision.entry_hash().unwrap();
    let rotate = OwnerWebauthnRecoveryAuthority::sign_next(
        &root,
        &record,
        &owner_cert,
        Some(&provision),
        b"owner-passkey-1",
        verifier(b"second-recovery-code"),
        NOW + 1,
    )
    .unwrap();
    recovery_authority.push_signed(rotate);
    recovery_authority.verify(&record, &owner_cert).unwrap();
    let full_head =
        verified_owner_webauthn_recovery_head(&recovery_authority, &record, &owner_cert)
            .unwrap()
            .unwrap();
    let previous_anchor = OwnerWebauthnRecoveryAnchor::new(&record, &owner_cert, 0, provision_hash);

    let readiness = classify_owner_webauthn_recovery_consume_readiness(
        &webauthn_authority,
        &webauthn_verified_status(&webauthn_authority, &record, &owner_cert),
        &recovery_authority,
        &OwnerWebauthnRecoveryAnchorStatus::Advanced {
            previous: previous_anchor,
            head: full_head,
        },
        1,
    )
    .unwrap();

    assert_eq!(readiness, OwnerWebauthnRecoveryConsumeReadiness::NotReady);
}

#[test]
fn never_enrolled_webauthn_is_not_eligible_for_recovery_consume() {
    let (root, record, owner_cert) = setup();
    let webauthn_authority = OwnerWebauthnAuthority::new();
    let (recovery_authority, _) = recovery_authority_with_provision(&root, &record, &owner_cert);
    let err = classify_owner_webauthn_recovery_consume_readiness(
        &webauthn_authority,
        &OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor,
        &recovery_authority,
        &recovery_verified_status(&recovery_authority, &record, &owner_cert),
        0,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        OwnerWebauthnRecoveryConsumeClassifierError::WebauthnNeverEnrolled
    ));
}

#[test]
fn empty_recovery_log_is_not_ready() {
    let (root, record, owner_cert) = setup();
    let (webauthn_authority, _) = webauthn_authority_with_genesis(&root, &record, &owner_cert);
    let recovery_authority = OwnerWebauthnRecoveryAuthority::new();
    let readiness = classify_owner_webauthn_recovery_consume_readiness(
        &webauthn_authority,
        &webauthn_verified_status(&webauthn_authority, &record, &owner_cert),
        &recovery_authority,
        &OwnerWebauthnRecoveryAnchorStatus::EmptyRecoveryNoAnchor,
        1,
    )
    .unwrap();

    assert_eq!(readiness, OwnerWebauthnRecoveryConsumeReadiness::NotReady);
}
