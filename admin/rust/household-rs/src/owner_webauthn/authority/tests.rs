#![cfg(test)]

use serde_json::json;
use webauthn_rs::prelude::Passkey;

use super::*;
use crate::ids::{MachineId, derive_household_id};
use crate::keys::P256Keypair;
use crate::person_cert::{PersonCert, SignOwnerOptions};

const NOW: u64 = 1_800_000_000;

fn record_with(root: &P256Keypair) -> HouseholdRecord {
    let hh_pub = root.public();
    HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&hh_pub),
        hh_pub,
        name: "Alpha Household".to_string(),
        created_at: NOW,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![MachineId::parse(format!("m_{}", "b".repeat(52))).unwrap()],
        is_follower: false,
    }
}

fn owner_cert(root: &P256Keypair, record: &HouseholdRecord) -> PersonCert {
    let owner_key = P256Keypair::generate();
    PersonCert::sign_owner(
        root,
        SignOwnerOptions {
            hh_id: record.hh_id.clone(),
            p_pub: owner_key.public(),
            display_name: "Owner Alpha".to_string(),
            issued_at: NOW,
        },
    )
    .unwrap()
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

fn setup() -> (P256Keypair, HouseholdRecord, PersonCert) {
    let root = P256Keypair::generate();
    let record = record_with(&root);
    let owner_cert = owner_cert(&root, &record);
    (root, record, owner_cert)
}

#[test]
fn empty_authority_reconstructs_empty_store() {
    let (_root, record, owner_cert) = setup();
    let store = OwnerWebauthnAuthority::new()
        .reconstruct(&record, &owner_cert)
        .unwrap();
    assert_eq!(store.active_count(), 0);
}

#[test]
fn genesis_event_is_hh_root_signed_and_reconstructs_first_credential() {
    let (root, record, owner_cert) = setup();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);

    let store = authority.reconstruct(&record, &owner_cert).unwrap();
    assert_eq!(store.active_count(), 1);
    assert_eq!(
        store.active_credentials()[0].credential_id_bytes(),
        b"owner-passkey-1"
    );
}

#[test]
fn tampered_event_fails_signature_verification() {
    let (root, record, owner_cert) = setup();
    let mut genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    genesis.event.issued_at += 1;
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);

    let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
    assert!(matches!(err, OwnerWebauthnAuthorityError::Protocol(_)));
}

#[test]
fn append_event_requires_active_actor_and_hash_chain() {
    let (root, record, owner_cert) = setup();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let second = OwnerWebauthnAuthority::sign_append(
        &root,
        &record,
        &owner_cert,
        &genesis,
        b"owner-passkey-1",
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential(b"owner-passkey-2")),
        },
        NOW + 1,
    )
    .unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);
    authority.push_signed(second);

    let store = authority.reconstruct(&record, &owner_cert).unwrap();
    assert_eq!(store.active_count(), 2);
}

#[test]
fn append_event_from_revoked_actor_fails_closed() {
    let (root, record, owner_cert) = setup();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let revoke = OwnerWebauthnAuthority::sign_append(
        &root,
        &record,
        &owner_cert,
        &genesis,
        b"owner-passkey-1",
        OwnerWebauthnCredentialEventAction::Revoke {
            credential_id: ByteBuf::from(b"owner-passkey-1".to_vec()),
        },
        NOW + 1,
    )
    .unwrap();
    let after_revoke = OwnerWebauthnAuthority::sign_append(
        &root,
        &record,
        &owner_cert,
        &revoke,
        b"owner-passkey-1",
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential(b"owner-passkey-2")),
        },
        NOW + 2,
    )
    .unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);
    authority.push_signed(revoke);
    authority.push_signed(after_revoke);

    let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
    assert!(matches!(err, OwnerWebauthnAuthorityError::Invalid(_)));
}

#[test]
fn re_add_of_revoked_credential_id_fails_closed() {
    let (root, record, owner_cert) = setup();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let second = OwnerWebauthnAuthority::sign_append(
        &root,
        &record,
        &owner_cert,
        &genesis,
        b"owner-passkey-1",
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential(b"owner-passkey-2")),
        },
        NOW + 1,
    )
    .unwrap();
    let revoke = OwnerWebauthnAuthority::sign_append(
        &root,
        &record,
        &owner_cert,
        &second,
        b"owner-passkey-2",
        OwnerWebauthnCredentialEventAction::Revoke {
            credential_id: ByteBuf::from(b"owner-passkey-1".to_vec()),
        },
        NOW + 2,
    )
    .unwrap();
    let re_add = OwnerWebauthnAuthority::sign_append(
        &root,
        &record,
        &owner_cert,
        &revoke,
        b"owner-passkey-2",
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential(b"owner-passkey-1")),
        },
        NOW + 3,
    )
    .unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);
    authority.push_signed(second);
    authority.push_signed(revoke);
    authority.push_signed(re_add);

    let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
    assert!(matches!(
        err,
        OwnerWebauthnAuthorityError::CredentialStore(
            crate::owner_webauthn::OwnerWebauthnError::DuplicateCredential
        )
    ));
}

#[test]
fn recovery_actor_can_add_credential_with_recovery_head_reference() {
    let (root, record, owner_cert) = setup();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let recovery_head_hash = [0x51; HASH_LEN];
    let add = OwnerWebauthnAuthority::sign_recovery_add(
        &root,
        &record,
        &owner_cert,
        OwnerWebauthnRecoveryAddInput {
            previous_entry: &genesis,
            recovery_head_sequence: 7,
            recovery_head_hash,
            credential: credential(b"owner-passkey-2"),
            issued_at: NOW + 1,
        },
    )
    .unwrap();
    assert_eq!(
        add.event.actor,
        OwnerWebauthnEventActor::RecoveryProof {
            recovery_head_sequence: 7,
            recovery_head_hash: ByteBuf::from(recovery_head_hash.to_vec()),
        }
    );

    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);
    authority.push_signed(add);
    let store = authority.reconstruct(&record, &owner_cert).unwrap();
    assert_eq!(store.active_count(), 2);
}

#[test]
fn recovery_head_is_consumed_if_webauthn_add_references_it() {
    let (root, record, owner_cert) = setup();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let recovery_head_hash = [0x51; HASH_LEN];
    let add = OwnerWebauthnAuthority::sign_recovery_add(
        &root,
        &record,
        &owner_cert,
        OwnerWebauthnRecoveryAddInput {
            previous_entry: &genesis,
            recovery_head_sequence: 7,
            recovery_head_hash,
            credential: credential(b"owner-passkey-2"),
            issued_at: NOW + 1,
        },
    )
    .unwrap();

    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);
    assert!(!authority.recovery_head_consumed_by_webauthn_add(7, &recovery_head_hash));

    authority.push_signed(add);
    assert!(authority.recovery_head_consumed_by_webauthn_add(7, &recovery_head_hash));
    assert!(!authority.recovery_head_consumed_by_webauthn_add(8, &recovery_head_hash));
    assert!(!authority.recovery_head_consumed_by_webauthn_add(7, &[0x52; HASH_LEN]));

    authority.reconstruct(&record, &owner_cert).unwrap();
}

#[test]
fn recovery_actor_may_not_revoke_credentials() {
    let (root, record, owner_cert) = setup();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let revoke = SignedOwnerWebauthnCredentialEvent::sign(
        OwnerWebauthnCredentialEvent {
            version: EVENT_SCHEMA_VERSION,
            event_type: EVENT_TYPE.to_string(),
            hh_id: record.hh_id.clone(),
            owner_p_id: owner_cert.p_id.clone(),
            sequence: 1,
            prev_hash: Some(ByteBuf::from(genesis.entry_hash().unwrap().to_vec())),
            actor: OwnerWebauthnEventActor::RecoveryProof {
                recovery_head_sequence: 7,
                recovery_head_hash: ByteBuf::from(vec![0x51; HASH_LEN]),
            },
            issued_at: NOW + 1,
            action: OwnerWebauthnCredentialEventAction::Revoke {
                credential_id: ByteBuf::from(b"owner-passkey-1".to_vec()),
            },
        },
        &root,
    )
    .unwrap();

    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);
    authority.push_signed(revoke);
    let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
    assert!(matches!(err, OwnerWebauthnAuthorityError::Invalid(_)));
}

#[test]
fn wrong_prev_hash_fails_reconstruction() {
    let (root, record, owner_cert) = setup();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let mut second = OwnerWebauthnAuthority::sign_append(
        &root,
        &record,
        &owner_cert,
        &genesis,
        b"owner-passkey-1",
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential(b"owner-passkey-2")),
        },
        NOW + 1,
    )
    .unwrap();
    second.event.prev_hash = Some(ByteBuf::from(vec![0xAB; HASH_LEN]));
    second.signature = root.sign(&second.event.signing_bytes().unwrap()).unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);
    authority.push_signed(second);

    let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
    assert!(matches!(err, OwnerWebauthnAuthorityError::Invalid(_)));
}

#[test]
fn wrong_signer_fails_reconstruction() {
    let (root, record, owner_cert) = setup();
    let attacker = P256Keypair::generate();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &attacker,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);

    let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
    assert!(matches!(err, OwnerWebauthnAuthorityError::Protocol(_)));

    // The legitimate root still signs events accepted by the same record.
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);
    authority.reconstruct(&record, &owner_cert).unwrap();
}

#[test]
fn added_credential_must_not_be_pre_revoked() {
    let (root, record, owner_cert) = setup();
    let mut pre_revoked = credential(b"owner-passkey-1");
    pre_revoked.revoke();
    let genesis =
        OwnerWebauthnAuthority::sign_genesis(&root, &record, &owner_cert, pre_revoked, NOW)
            .unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);

    let err = authority.reconstruct(&record, &owner_cert).unwrap_err();
    assert!(matches!(err, OwnerWebauthnAuthorityError::Invalid(_)));
}

#[test]
fn rollback_truncation_requires_future_anchor() {
    let (root, record, owner_cert) = setup();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let second = OwnerWebauthnAuthority::sign_append(
        &root,
        &record,
        &owner_cert,
        &genesis,
        b"owner-passkey-1",
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential(b"owner-passkey-2")),
        },
        NOW + 1,
    )
    .unwrap();
    let mut full = OwnerWebauthnAuthority::new();
    full.push_signed(genesis.clone());
    full.push_signed(second);
    assert_eq!(
        full.reconstruct(&record, &owner_cert)
            .unwrap()
            .active_count(),
        2
    );

    let mut truncated = OwnerWebauthnAuthority::new();
    truncated.push_signed(genesis);
    assert_eq!(
        truncated
            .reconstruct(&record, &owner_cert)
            .unwrap()
            .active_count(),
        1
    );
}
