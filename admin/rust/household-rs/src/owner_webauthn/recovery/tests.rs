#![cfg(test)]

use serde_json::json;
use webauthn_rs::prelude::Passkey;

use super::*;
use crate::ids::{MachineId, derive_household_id};
use crate::keys::P256Keypair;
use crate::owner_webauthn::OwnerWebauthnCredential;
use crate::owner_webauthn::authority::{OwnerWebauthnAuthority, OwnerWebauthnRecoveryAddInput};
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

fn setup() -> (P256Keypair, HouseholdRecord, PersonCert) {
    let root = P256Keypair::generate();
    let record = record_with(&root);
    let owner_cert = owner_cert(&root, &record);
    (root, record, owner_cert)
}

fn verifier(code: &[u8]) -> RecoveryCodeVerifier {
    RecoveryCodeVerifier::from_code_bytes([0xA5; SALT_LEN], code)
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
    record: &HouseholdRecord,
    owner_cert: &PersonCert,
) -> (
    OwnerWebauthnAuthority,
    crate::owner_webauthn::authority::SignedOwnerWebauthnCredentialEvent,
) {
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

#[test]
fn recovery_verifier_matches_code_bytes_without_exposing_plaintext() {
    let verifier = verifier(b"high-entropy-recovery-code");
    assert!(
        verifier
            .matches_code_bytes(b"high-entropy-recovery-code")
            .unwrap()
    );
    assert!(!verifier.matches_code_bytes(b"wrong-code").unwrap());
}

#[test]
fn consume_invalidates_recovery_readiness_and_rejects_duplicate_consume() {
    let (root, record, owner_cert) = setup();
    let provision = OwnerWebauthnRecoveryAuthority::sign_next(
        &root,
        &record,
        &owner_cert,
        None,
        b"owner-passkey-1",
        verifier(b"high-entropy-recovery-code"),
        NOW,
    )
    .unwrap();
    let consume = OwnerWebauthnRecoveryAuthority::sign_consume(
        &root,
        &record,
        &owner_cert,
        &provision,
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        consume.event.actor,
        OwnerWebauthnRecoveryActor::RecoveryProof {
            verifier_head_sequence: 0,
            verifier_head_hash: ByteBuf::from(provision.entry_hash().unwrap().to_vec()),
        }
    );

    let mut authority = OwnerWebauthnRecoveryAuthority::new();
    authority.push_signed(provision.clone());
    assert!(authority.recovery_ready());
    authority.push_signed(consume.clone());
    authority.verify(&record, &owner_cert).unwrap();
    assert!(!authority.recovery_ready());
    assert!(authority.latest_verifier().is_none());

    let duplicate = OwnerWebauthnRecoveryAuthority::sign_consume(
        &root,
        &record,
        &owner_cert,
        &consume,
        NOW + 2,
    );
    assert!(matches!(
        duplicate,
        Err(OwnerWebauthnRecoveryError::Invalid(_))
    ));

    let consume_hash = consume.entry_hash().unwrap();
    let duplicate = SignedOwnerWebauthnRecoveryEvent::sign(
        OwnerWebauthnRecoveryEvent {
            version: EVENT_SCHEMA_VERSION,
            event_type: EVENT_TYPE.to_string(),
            hh_id: record.hh_id.clone(),
            owner_p_id: owner_cert.p_id.clone(),
            sequence: 2,
            prev_hash: Some(ByteBuf::from(consume_hash.to_vec())),
            actor: OwnerWebauthnRecoveryActor::RecoveryProof {
                verifier_head_sequence: 1,
                verifier_head_hash: ByteBuf::from(consume_hash.to_vec()),
            },
            issued_at: NOW + 2,
            action: OwnerWebauthnRecoveryEventAction::Consume,
        },
        &root,
    )
    .unwrap();
    let mut tampered_authority = OwnerWebauthnRecoveryAuthority::new();
    tampered_authority.push_signed(provision);
    tampered_authority.push_signed(consume);
    tampered_authority.push_signed(duplicate);
    let err = tampered_authority.verify(&record, &owner_cert).unwrap_err();
    assert!(matches!(err, OwnerWebauthnRecoveryError::Invalid(_)));
}

#[test]
fn consume_must_reference_immediate_recovery_head() {
    let (root, record, owner_cert) = setup();
    let provision = OwnerWebauthnRecoveryAuthority::sign_next(
        &root,
        &record,
        &owner_cert,
        None,
        b"owner-passkey-1",
        verifier(b"high-entropy-recovery-code"),
        NOW,
    )
    .unwrap();
    let mut consume = OwnerWebauthnRecoveryAuthority::sign_consume(
        &root,
        &record,
        &owner_cert,
        &provision,
        NOW + 1,
    )
    .unwrap();
    consume.event.actor = OwnerWebauthnRecoveryActor::RecoveryProof {
        verifier_head_sequence: 0,
        verifier_head_hash: ByteBuf::from(vec![0xEE; HASH_LEN]),
    };
    consume.signature = root.sign(&consume.event.signing_bytes().unwrap()).unwrap();

    let mut authority = OwnerWebauthnRecoveryAuthority::new();
    authority.push_signed(provision);
    authority.push_signed(consume);
    let err = authority.verify(&record, &owner_cert).unwrap_err();
    assert!(matches!(err, OwnerWebauthnRecoveryError::Invalid(_)));
}

#[test]
fn owner_credential_actor_may_not_consume_recovery() {
    let (root, record, owner_cert) = setup();
    let provision = OwnerWebauthnRecoveryAuthority::sign_next(
        &root,
        &record,
        &owner_cert,
        None,
        b"owner-passkey-1",
        verifier(b"high-entropy-recovery-code"),
        NOW,
    )
    .unwrap();
    let consume = SignedOwnerWebauthnRecoveryEvent::sign(
        OwnerWebauthnRecoveryEvent {
            version: EVENT_SCHEMA_VERSION,
            event_type: EVENT_TYPE.to_string(),
            hh_id: record.hh_id.clone(),
            owner_p_id: owner_cert.p_id.clone(),
            sequence: 1,
            prev_hash: Some(ByteBuf::from(provision.entry_hash().unwrap().to_vec())),
            actor: OwnerWebauthnRecoveryActor::OwnerCredential {
                credential_id: ByteBuf::from(b"owner-passkey-1".to_vec()),
            },
            issued_at: NOW + 1,
            action: OwnerWebauthnRecoveryEventAction::Consume,
        },
        &root,
    )
    .unwrap();

    let mut authority = OwnerWebauthnRecoveryAuthority::new();
    authority.push_signed(provision);
    authority.push_signed(consume);
    let err = authority.verify(&record, &owner_cert).unwrap_err();
    assert!(matches!(err, OwnerWebauthnRecoveryError::Invalid(_)));
}

#[test]
fn latest_active_verifier_head_tracks_rotate_and_consume() {
    let (root, record, owner_cert) = setup();
    let provision = OwnerWebauthnRecoveryAuthority::sign_next(
        &root,
        &record,
        &owner_cert,
        None,
        b"owner-passkey-1",
        verifier(b"first-recovery-code"),
        NOW,
    )
    .unwrap();
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
    let consume =
        OwnerWebauthnRecoveryAuthority::sign_consume(&root, &record, &owner_cert, &rotate, NOW + 2)
            .unwrap();

    let mut authority = OwnerWebauthnRecoveryAuthority::new();
    assert!(authority.latest_active_verifier_head().unwrap().is_none());

    authority.push_signed(provision.clone());
    assert_eq!(
        authority.latest_active_verifier_head().unwrap(),
        Some(OwnerWebauthnRecoveryHead {
            sequence: 0,
            head_hash: provision.entry_hash().unwrap(),
        })
    );

    authority.push_signed(rotate.clone());
    assert_eq!(
        authority.latest_active_verifier_head().unwrap(),
        Some(OwnerWebauthnRecoveryHead {
            sequence: 1,
            head_hash: rotate.entry_hash().unwrap(),
        })
    );

    authority.push_signed(consume);
    authority.verify(&record, &owner_cert).unwrap();
    assert!(authority.latest_active_verifier_head().unwrap().is_none());
    assert!(!authority.recovery_ready());
}

#[test]
fn recovery_head_consumed_by_recovery_log_requires_exact_consume_reference() {
    let (root, record, owner_cert) = setup();
    let provision = OwnerWebauthnRecoveryAuthority::sign_next(
        &root,
        &record,
        &owner_cert,
        None,
        b"owner-passkey-1",
        verifier(b"first-recovery-code"),
        NOW,
    )
    .unwrap();
    let consume = OwnerWebauthnRecoveryAuthority::sign_consume(
        &root,
        &record,
        &owner_cert,
        &provision,
        NOW + 1,
    )
    .unwrap();
    let provision_hash = provision.entry_hash().unwrap();

    let mut authority = OwnerWebauthnRecoveryAuthority::new();
    authority.push_signed(provision);
    assert!(!authority.recovery_head_consumed_by_recovery_log(0, &provision_hash));

    authority.push_signed(consume);
    assert!(authority.recovery_head_consumed_by_recovery_log(0, &provision_hash));
    assert!(!authority.recovery_head_consumed_by_recovery_log(1, &provision_hash));
    assert!(!authority.recovery_head_consumed_by_recovery_log(0, &[0x52; HASH_LEN]));
    authority.verify(&record, &owner_cert).unwrap();
}

#[test]
fn recovery_head_consumed_by_any_log_includes_webauthn_recovery_add() {
    let (root, record, owner_cert) = setup();
    let provision = OwnerWebauthnRecoveryAuthority::sign_next(
        &root,
        &record,
        &owner_cert,
        None,
        b"owner-passkey-1",
        verifier(b"first-recovery-code"),
        NOW,
    )
    .unwrap();
    let recovery_head_hash = provision.entry_hash().unwrap();
    let mut recovery_authority = OwnerWebauthnRecoveryAuthority::new();
    recovery_authority.push_signed(provision);
    let (mut webauthn_authority, webauthn_genesis) =
        webauthn_authority_with_genesis(&root, &record, &owner_cert);

    assert!(!recovery_authority.recovery_head_consumed_by_any_log(
        &webauthn_authority,
        0,
        &recovery_head_hash,
    ));
    assert_eq!(
        recovery_authority
            .latest_unconsumed_active_verifier_head(&webauthn_authority)
            .unwrap(),
        Some(OwnerWebauthnRecoveryHead {
            sequence: 0,
            head_hash: recovery_head_hash,
        })
    );

    let add = OwnerWebauthnAuthority::sign_recovery_add(
        &root,
        &record,
        &owner_cert,
        OwnerWebauthnRecoveryAddInput {
            previous_entry: &webauthn_genesis,
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

    assert!(recovery_authority.recovery_head_consumed_by_any_log(
        &webauthn_authority,
        0,
        &recovery_head_hash,
    ));
    assert!(
        recovery_authority
            .latest_unconsumed_active_verifier_head(&webauthn_authority)
            .unwrap()
            .is_none()
    );
}

#[test]
fn latest_unconsumed_active_verifier_head_excludes_recovery_consume_tail() {
    let (root, record, owner_cert) = setup();
    let provision = OwnerWebauthnRecoveryAuthority::sign_next(
        &root,
        &record,
        &owner_cert,
        None,
        b"owner-passkey-1",
        verifier(b"first-recovery-code"),
        NOW,
    )
    .unwrap();
    let consume = OwnerWebauthnRecoveryAuthority::sign_consume(
        &root,
        &record,
        &owner_cert,
        &provision,
        NOW + 1,
    )
    .unwrap();
    let provision_hash = provision.entry_hash().unwrap();
    let (webauthn_authority, _) = webauthn_authority_with_genesis(&root, &record, &owner_cert);
    let mut recovery_authority = OwnerWebauthnRecoveryAuthority::new();
    recovery_authority.push_signed(provision);
    recovery_authority.push_signed(consume);
    recovery_authority.verify(&record, &owner_cert).unwrap();

    assert!(recovery_authority.recovery_head_consumed_by_any_log(
        &webauthn_authority,
        0,
        &provision_hash,
    ));
    assert!(
        recovery_authority
            .latest_unconsumed_active_verifier_head(&webauthn_authority)
            .unwrap()
            .is_none()
    );
}
