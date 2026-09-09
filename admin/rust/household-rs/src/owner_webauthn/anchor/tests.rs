#![cfg(test)]

use std::path::Path;

use keystore_rs::FileKeystore;
use serde_json::json;
use webauthn_rs::prelude::Passkey;

use super::*;
use crate::ids::{MachineId, derive_household_id};
use crate::keys::{IdentityKey, P256Keypair};
use crate::owner_webauthn::OwnerWebauthnCredential;
use crate::owner_webauthn::authority::{
    OwnerWebauthnCredentialEventAction, SignedOwnerWebauthnCredentialEvent,
};
use crate::person_cert::{PersonCert, SignOwnerOptions};

const NOW: u64 = 1_800_000_000;

fn file_keystore(root: &Path) -> FileKeystore {
    FileKeystore::new(root, keystore_rs::SERVICE)
}

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

fn two_entry_authority(
    root: &P256Keypair,
    record: &HouseholdRecord,
    owner_cert: &PersonCert,
) -> (
    OwnerWebauthnAuthority,
    SignedOwnerWebauthnCredentialEvent,
    SignedOwnerWebauthnCredentialEvent,
) {
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        root,
        record,
        owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let second = OwnerWebauthnAuthority::sign_append(
        root,
        record,
        owner_cert,
        &genesis,
        b"owner-passkey-1",
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential(b"owner-passkey-2")),
        },
        NOW + 1,
    )
    .unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis.clone());
    authority.push_signed(second.clone());
    (authority, genesis, second)
}

fn append_third(
    root: &P256Keypair,
    record: &HouseholdRecord,
    owner_cert: &PersonCert,
    genesis: &SignedOwnerWebauthnCredentialEvent,
    second: &SignedOwnerWebauthnCredentialEvent,
) -> OwnerWebauthnAuthority {
    let third = OwnerWebauthnAuthority::sign_append(
        root,
        record,
        owner_cert,
        second,
        b"owner-passkey-2",
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential(b"owner-passkey-3")),
        },
        NOW + 2,
    )
    .unwrap();
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis.clone());
    authority.push_signed(second.clone());
    authority.push_signed(third);
    authority
}

#[test]
fn account_label_is_stable_and_household_scoped() {
    let (_root, record, _owner_cert) = setup();
    let account = owner_webauthn_authority_anchor_account(&record.hh_id);
    assert!(account.starts_with("household.owner_webauthn_authority.anchor.hh_"));
    assert!(!account.contains('/'));
    assert!(!account.contains(".."));
}

#[test]
fn empty_authority_without_anchor_is_ok() {
    let tmp = tempfile::tempdir().unwrap();
    let store = file_keystore(tmp.path());
    let (_root, record, owner_cert) = setup();
    let authority = OwnerWebauthnAuthority::new();

    let status = verify_or_update_owner_webauthn_authority_anchor(
        &store,
        &authority,
        &record,
        &owner_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .unwrap();

    assert_eq!(status, OwnerWebauthnAnchorStatus::EmptyAuthorityNoAnchor);
    assert!(
        read_owner_webauthn_authority_anchor(&store, &record.hh_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn migration_mode_anchors_verified_non_empty_authority() {
    let tmp = tempfile::tempdir().unwrap();
    let store = file_keystore(tmp.path());
    let (root, record, owner_cert) = setup();
    let (authority, _genesis, second) = two_entry_authority(&root, &record, &owner_cert);

    let status = verify_or_update_owner_webauthn_authority_anchor(
        &store,
        &authority,
        &record,
        &owner_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .unwrap();

    assert_eq!(
        status,
        OwnerWebauthnAnchorStatus::Migrated {
            head: OwnerWebauthnAuthorityHead {
                sequence: 1,
                head_hash: second.entry_hash().unwrap(),
            },
        }
    );
    let anchor = read_owner_webauthn_authority_anchor(&store, &record.hh_id)
        .unwrap()
        .unwrap();
    assert_eq!(anchor.sequence(), 1);
    assert_eq!(anchor.head_hash(), second.entry_hash().unwrap());
}

#[test]
fn enforcement_mode_rejects_non_empty_authority_without_anchor() {
    let tmp = tempfile::tempdir().unwrap();
    let store = file_keystore(tmp.path());
    let (root, record, owner_cert) = setup();
    let (authority, _genesis, _second) = two_entry_authority(&root, &record, &owner_cert);

    let err = verify_or_update_owner_webauthn_authority_anchor(
        &store,
        &authority,
        &record,
        &owner_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .unwrap_err();

    assert!(matches!(err, OwnerWebauthnAnchorError::MissingAnchor));
}

#[test]
fn exact_anchor_at_head_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let store = file_keystore(tmp.path());
    let (root, record, owner_cert) = setup();
    let (authority, _genesis, second) = two_entry_authority(&root, &record, &owner_cert);
    let anchor =
        OwnerWebauthnAuthorityAnchor::new(&record, &owner_cert, 1, second.entry_hash().unwrap());
    write_owner_webauthn_authority_anchor(&store, &anchor).unwrap();

    let status = verify_or_update_owner_webauthn_authority_anchor(
        &store,
        &authority,
        &record,
        &owner_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .unwrap();

    assert_eq!(
        status,
        OwnerWebauthnAnchorStatus::Verified {
            head: OwnerWebauthnAuthorityHead {
                sequence: 1,
                head_hash: second.entry_hash().unwrap(),
            },
        }
    );
}

#[test]
fn anchor_rejects_truncated_log() {
    let tmp = tempfile::tempdir().unwrap();
    let store = file_keystore(tmp.path());
    let (root, record, owner_cert) = setup();
    let (_full, genesis, second) = two_entry_authority(&root, &record, &owner_cert);
    let anchor =
        OwnerWebauthnAuthorityAnchor::new(&record, &owner_cert, 1, second.entry_hash().unwrap());
    write_owner_webauthn_authority_anchor(&store, &anchor).unwrap();
    let mut truncated = OwnerWebauthnAuthority::new();
    truncated.push_signed(genesis);

    let err = verify_or_update_owner_webauthn_authority_anchor(
        &store,
        &truncated,
        &record,
        &owner_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .unwrap_err();

    assert!(matches!(err, OwnerWebauthnAnchorError::Rollback(_)));
}

#[test]
fn anchor_rejects_divergent_entry_at_anchored_sequence() {
    let tmp = tempfile::tempdir().unwrap();
    let store = file_keystore(tmp.path());
    let (root, record, owner_cert) = setup();
    let (_full, genesis, second) = two_entry_authority(&root, &record, &owner_cert);
    let anchor =
        OwnerWebauthnAuthorityAnchor::new(&record, &owner_cert, 1, second.entry_hash().unwrap());
    write_owner_webauthn_authority_anchor(&store, &anchor).unwrap();
    let alternate_second = OwnerWebauthnAuthority::sign_append(
        &root,
        &record,
        &owner_cert,
        &genesis,
        b"owner-passkey-1",
        OwnerWebauthnCredentialEventAction::Add {
            credential: Box::new(credential(b"owner-passkey-alt")),
        },
        NOW + 1,
    )
    .unwrap();
    let mut divergent = OwnerWebauthnAuthority::new();
    divergent.push_signed(genesis);
    divergent.push_signed(alternate_second);

    let err = verify_or_update_owner_webauthn_authority_anchor(
        &store,
        &divergent,
        &record,
        &owner_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .unwrap_err();

    assert!(matches!(err, OwnerWebauthnAnchorError::Rollback(_)));
}

#[test]
fn valid_log_extending_anchor_advances_anchor() {
    let tmp = tempfile::tempdir().unwrap();
    let store = file_keystore(tmp.path());
    let (root, record, owner_cert) = setup();
    let (_two, genesis, second) = two_entry_authority(&root, &record, &owner_cert);
    let anchor =
        OwnerWebauthnAuthorityAnchor::new(&record, &owner_cert, 1, second.entry_hash().unwrap());
    write_owner_webauthn_authority_anchor(&store, &anchor).unwrap();
    let extended = append_third(&root, &record, &owner_cert, &genesis, &second);
    let third_hash = extended.entries()[2].entry_hash().unwrap();

    let status = verify_or_update_owner_webauthn_authority_anchor(
        &store,
        &extended,
        &record,
        &owner_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .unwrap();

    assert_eq!(
        status,
        OwnerWebauthnAnchorStatus::Advanced {
            previous: anchor,
            head: OwnerWebauthnAuthorityHead {
                sequence: 2,
                head_hash: third_hash,
            },
        }
    );
    let advanced = read_owner_webauthn_authority_anchor(&store, &record.hh_id)
        .unwrap()
        .unwrap();
    assert_eq!(advanced.sequence(), 2);
    assert_eq!(advanced.head_hash(), third_hash);
}

#[test]
fn read_only_classifier_reports_advanced_without_writing_anchor() {
    let tmp = tempfile::tempdir().unwrap();
    let store = file_keystore(tmp.path());
    let (root, record, owner_cert) = setup();
    let (_two, genesis, second) = two_entry_authority(&root, &record, &owner_cert);
    let anchor =
        OwnerWebauthnAuthorityAnchor::new(&record, &owner_cert, 1, second.entry_hash().unwrap());
    write_owner_webauthn_authority_anchor(&store, &anchor).unwrap();
    let extended = append_third(&root, &record, &owner_cert, &genesis, &second);
    let third_hash = extended.entries()[2].entry_hash().unwrap();

    let status =
        classify_owner_webauthn_authority_anchor_read_only(&store, &extended, &record, &owner_cert)
            .unwrap();

    assert_eq!(
        status,
        OwnerWebauthnAnchorStatus::Advanced {
            previous: anchor,
            head: OwnerWebauthnAuthorityHead {
                sequence: 2,
                head_hash: third_hash,
            },
        }
    );
    let persisted = read_owner_webauthn_authority_anchor(&store, &record.hh_id)
        .unwrap()
        .unwrap();
    assert_eq!(persisted.sequence(), 1);
    assert_eq!(persisted.head_hash(), second.entry_hash().unwrap());
}

#[test]
fn invalid_signed_chain_fails_before_anchor_migration() {
    let tmp = tempfile::tempdir().unwrap();
    let store = file_keystore(tmp.path());
    let (root, record, owner_cert) = setup();
    let genesis = OwnerWebauthnAuthority::sign_genesis(
        &root,
        &record,
        &owner_cert,
        credential(b"owner-passkey-1"),
        NOW,
    )
    .unwrap();
    let mut tampered = OwnerWebauthnAuthority::sign_append(
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
    tampered.event.issued_at += 1;
    let mut authority = OwnerWebauthnAuthority::new();
    authority.push_signed(genesis);
    authority.push_signed(tampered);

    let err = verify_or_update_owner_webauthn_authority_anchor(
        &store,
        &authority,
        &record,
        &owner_cert,
        OwnerWebauthnAnchorMode::MigrationDefaultOff,
    )
    .unwrap_err();

    assert!(matches!(err, OwnerWebauthnAnchorError::Authority(_)));
    assert!(
        read_owner_webauthn_authority_anchor(&store, &record.hh_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_anchor_hash_length_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let store = file_keystore(tmp.path());
    let (root, record, owner_cert) = setup();
    let (authority, _genesis, _second) = two_entry_authority(&root, &record, &owner_cert);
    let malformed = OwnerWebauthnAuthorityAnchor {
        version: ANCHOR_SCHEMA_VERSION,
        purpose: ANCHOR_PURPOSE.to_string(),
        hh_id: record.hh_id.clone(),
        owner_p_id: owner_cert.p_id.clone(),
        sequence: 1,
        head_hash: ByteBuf::from(vec![0xAA; HEAD_HASH_LEN - 1]),
    };
    write_owner_webauthn_authority_anchor(&store, &malformed).unwrap();

    let err = verify_or_update_owner_webauthn_authority_anchor(
        &store,
        &authority,
        &record,
        &owner_cert,
        OwnerWebauthnAnchorMode::Enforcement,
    )
    .unwrap_err();

    assert!(matches!(err, OwnerWebauthnAnchorError::Invalid(_)));
}
