#![cfg(test)]

use std::sync::{Arc, Barrier};

use ciborium::value::Value;

use super::*;
use crate::keys::{IdentityKey, P256Keypair};

const TEAM_ID: &str = "TEAMID1234";
const BUNDLE_ID: &str = "com.example.soyeht";
const HH_ID: &str = "hh_fnlwza7qi4rxuadflfmxocnx5rwdb3ef2meq6unnh7qqiosfyain";
const OWNER_P_ID: &str = "p_ty3yfdchyn7nethoiefhrolfjxavzfe2bngb4tzzqy7cl3uqjfcq";
const OWNER_KEY_ID: &str = "owner-key-ios-alpha";
const NOW: u64 = 1_714_972_800;

struct SyntheticAttestation {
    attestation_object_cbor: Vec<u8>,
    certificate_nonce: [u8; 32],
}

fn transcript(
    challenge_id: &str,
    owner_key_id: &str,
    platform: SecureUpgradePlatform,
) -> SecureUpgradeTranscript {
    transcript_with_owner_person_id(
        challenge_id,
        owner_key_id,
        platform,
        PersonId(OWNER_P_ID.to_string()),
    )
}

fn transcript_with_owner_person_id(
    challenge_id: &str,
    owner_key_id: &str,
    platform: SecureUpgradePlatform,
    owner_p_id: PersonId,
) -> SecureUpgradeTranscript {
    SecureUpgradeTranscript::app_attest(SecureUpgradeAppAttestTranscriptInput {
        hh_id: HouseholdId::parse(HH_ID.to_string()).expect("fixture hh_id parses"),
        owner_p_id,
        owner_key_id: owner_key_id.to_string(),
        challenge_id: challenge_id.to_string(),
        issued_at: NOW,
        expires_at: NOW + 300,
        app_team_id: TEAM_ID.to_string(),
        app_bundle_id: BUNDLE_ID.to_string(),
        proof_key_id: "app-attest-proof-key-alpha".to_string(),
        proof_environment: SecureUpgradeProofEnvironment::Development,
        platform,
    })
}

fn challenge_record_for_owner_person_id(
    challenge_id: &str,
    owner_key_id: &str,
    platform: SecureUpgradePlatform,
    owner_p_id: PersonId,
) -> SecureUpgradeChallengeRecord {
    let store = SecureUpgradeChallengeStore::new();
    store
        .issue(
            &transcript_with_owner_person_id(challenge_id, owner_key_id, platform, owner_p_id),
            NOW,
        )
        .unwrap()
}

fn challenge_record(
    challenge_id: &str,
    owner_key_id: &str,
    platform: SecureUpgradePlatform,
) -> SecureUpgradeChallengeRecord {
    let store = SecureUpgradeChallengeStore::new();
    store
        .issue(&transcript(challenge_id, owner_key_id, platform), NOW)
        .unwrap()
}

fn synthetic_auth_data(challenge_digest: [u8; 32]) -> Vec<u8> {
    let credential_id = challenge_digest;
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&app_attest_app_identifier_hash(TEAM_ID, BUNDLE_ID));
    auth_data.push(0x41);
    auth_data.extend_from_slice(&0_u32.to_be_bytes());
    auth_data.extend_from_slice(APP_ATTEST_AAGUID_DEVELOPMENT);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&credential_id);
    auth_data.extend_from_slice(&[0xa5, 0x01, 0x02]);
    auth_data
}

fn attestation_object(auth_data: Vec<u8>) -> Vec<u8> {
    let value = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text(SECURE_UPGRADE_APP_ATTEST_FORMAT.to_string()),
        ),
        (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
        (
            Value::Text("attStmt".to_string()),
            Value::Map(vec![(
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(vec![0x30, 0x03, 0x02, 0x01, 0x01])]),
            )]),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).expect("synthetic App Attest CBOR encodes");
    bytes
}

fn synthetic_attestation_for_record(record: &SecureUpgradeChallengeRecord) -> SyntheticAttestation {
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
            record.canonical_transcript_bytes(),
        );
    let auth_data = synthetic_auth_data(challenge_digest);
    let certificate_nonce = app_attest_nonce(&auth_data, challenge_digest);
    SyntheticAttestation {
        attestation_object_cbor: attestation_object(auth_data),
        certificate_nonce,
    }
}

fn app_attest_verification_for_record(
    record: &SecureUpgradeChallengeRecord,
) -> SecureUpgradeAppAttestVerification {
    let synthetic = synthetic_attestation_for_record(record);
    let bindings = verify_app_attest_commitment_bindings_for_transcript(
        &synthetic.attestation_object_cbor,
        record.canonical_transcript_bytes(),
        synthetic.certificate_nonce,
    )
    .unwrap();
    SecureUpgradeAppAttestVerification {
        bindings,
        proof_key_id_hash: [0x11; 32],
        leaf_public_key_sha256: [0x11; 32],
        root_ca_sha256: SECURE_UPGRADE_APP_ATTEST_ROOT_CA_SHA256,
        leaf_not_before_unix: NOW as i64 - 60,
        leaf_not_after_unix: NOW as i64 + 300,
    }
}

fn owner_signature_verification_for_record(
    record: &SecureUpgradeChallengeRecord,
    owner_key: &P256Keypair,
) -> SecureUpgradeOwnerSignatureVerification {
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
            record.canonical_transcript_bytes(),
        );
    let signature = owner_key.sign(&challenge_digest).unwrap();
    verify_owner_signature_for_transcript(
        record.canonical_transcript_bytes(),
        &record.scope().owner_key_id,
        &owner_key.public(),
        &signature,
    )
    .unwrap()
}

fn verified_ceremony_for_record(
    record: &SecureUpgradeChallengeRecord,
    owner_key: &P256Keypair,
) -> SecureUpgradeCeremonyVerification {
    let challenge_store = SecureUpgradeChallengeStore::new();
    let record = challenge_store
        .issue(
            &transcript_with_owner_person_id(
                record.challenge_id(),
                &record.scope().owner_key_id,
                record.scope().platform,
                record.scope().owner_p_id.clone(),
            ),
            NOW,
        )
        .unwrap();
    let canonical = record.canonical_transcript_bytes().to_vec();
    let proof = proof_verification_for_record(&record, owner_key);
    let replay_dir = tempfile::tempdir().expect("tempdir");
    let replay_store = SecureUpgradeDurableAppAttestReplayStore::new(replay_dir.path());
    verify_secure_upgrade_verified_ceremony_for_challenge(
        &challenge_store,
        &replay_store,
        record.challenge_id(),
        &canonical,
        NOW,
        proof,
    )
    .unwrap()
}

fn proof_verification_for_record(
    record: &SecureUpgradeChallengeRecord,
    owner_key: &P256Keypair,
) -> SecureUpgradeProofVerification {
    verify_secure_upgrade_verified_proofs_for_challenge_record(
        record,
        app_attest_verification_for_record(record),
        owner_signature_verification_for_record(record, owner_key),
    )
    .unwrap()
}

fn sign_owner_options_for_record(
    record: &SecureUpgradeChallengeRecord,
    owner_key: &P256Keypair,
) -> SignOwnerOptions {
    SignOwnerOptions {
        hh_id: record.scope().hh_id.clone(),
        p_pub: owner_key.public(),
        display_name: "Owner".to_string(),
        issued_at: NOW,
    }
}

#[test]
fn verified_app_attest_and_owner_signature_share_one_stored_digest() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let app_attest = app_attest_verification_for_record(&record);
    let owner_signature = owner_signature_verification_for_record(&record, &owner_key);
    let expected_digest = SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
        record.canonical_transcript_bytes(),
    );

    let verification = verify_secure_upgrade_verified_proofs_for_challenge_record(
        &record,
        app_attest,
        owner_signature,
    )
    .unwrap();

    assert_eq!(verification.challenge_digest(), expected_digest);
    assert_eq!(
        verification.app_attest().bindings().challenge_digest(),
        expected_digest
    );
    assert_eq!(
        verification.owner_signature().challenge_digest(),
        expected_digest
    );
    assert_eq!(verification.owner_signature().owner_key_id(), OWNER_KEY_ID);
}

#[test]
fn app_attest_from_another_challenge_is_rejected_by_single_digest_check() {
    let owner_key = P256Keypair::generate();
    let record_a = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let record_b = challenge_record(
        "su-challenge-beta",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let app_attest_b = app_attest_verification_for_record(&record_b);
    let owner_signature_a = owner_signature_verification_for_record(&record_a, &owner_key);

    assert_eq!(
        verify_secure_upgrade_verified_proofs_for_challenge_record(
            &record_a,
            app_attest_b,
            owner_signature_a,
        )
        .unwrap_err(),
        SecureUpgradeProofVerificationError::AppAttestChallengeDigestMismatch
    );
}

#[test]
fn owner_signature_from_another_challenge_is_rejected_by_single_digest_check() {
    let owner_key = P256Keypair::generate();
    let record_a = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let record_b = challenge_record(
        "su-challenge-beta",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let app_attest_a = app_attest_verification_for_record(&record_a);
    let owner_signature_b = owner_signature_verification_for_record(&record_b, &owner_key);

    assert_eq!(
        verify_secure_upgrade_verified_proofs_for_challenge_record(
            &record_a,
            app_attest_a,
            owner_signature_b,
        )
        .unwrap_err(),
        SecureUpgradeProofVerificationError::OwnerSignatureChallengeDigestMismatch
    );
}

#[test]
fn owner_key_id_mismatch_in_verified_outputs_is_rejected() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let app_attest = app_attest_verification_for_record(&record);
    let mut owner_signature = owner_signature_verification_for_record(&record, &owner_key);
    owner_signature.owner_key_id = "owner-key-ios-beta".to_string();

    assert_eq!(
        verify_secure_upgrade_verified_proofs_for_challenge_record(
            &record,
            app_attest,
            owner_signature,
        )
        .unwrap_err(),
        SecureUpgradeProofVerificationError::OwnerKeyIdMismatch
    );
}

#[test]
fn verified_ios_proof_derives_ios_app_attest_owner_provenance_without_minting() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof = proof_verification_for_record(&record, &owner_key);

    let provenance = verified_owner_provenance_from_secure_upgrade_proof(&record, &proof).unwrap();

    assert_eq!(provenance.challenge_digest(), proof.challenge_digest());
    assert_eq!(
        provenance.owner_provenance(),
        VerifiedOwnerProvenance::IosAppAttestOwner
    );
}

#[test]
fn verified_ipados_proof_derives_ipados_app_attest_owner_provenance_without_minting() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::IpadOs,
    );
    let proof = proof_verification_for_record(&record, &owner_key);

    let provenance = verified_owner_provenance_from_secure_upgrade_proof(&record, &proof).unwrap();

    assert_eq!(provenance.challenge_digest(), proof.challenge_digest());
    assert_eq!(
        provenance.owner_provenance(),
        VerifiedOwnerProvenance::IpadOsAppAttestOwner
    );
}

#[test]
fn provenance_derivation_rejects_top_level_proof_digest_mismatch() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let mut proof = proof_verification_for_record(&record, &owner_key);
    proof.challenge_digest[0] ^= 0xff;

    assert_eq!(
        verified_owner_provenance_from_secure_upgrade_proof(&record, &proof).unwrap_err(),
        SecureUpgradeProofVerificationError::ProofChallengeDigestMismatch
    );
}

#[test]
fn provenance_derivation_revalidates_inner_app_attest_digest() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let mut proof = proof_verification_for_record(&record, &owner_key);
    proof.app_attest.bindings.challenge_digest[0] ^= 0xff;

    assert_eq!(
        verified_owner_provenance_from_secure_upgrade_proof(&record, &proof).unwrap_err(),
        SecureUpgradeProofVerificationError::AppAttestChallengeDigestMismatch
    );
}

#[test]
fn provenance_derivation_revalidates_inner_owner_signature_digest() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let mut proof = proof_verification_for_record(&record, &owner_key);
    proof.owner_signature.challenge_digest[0] ^= 0xff;

    assert_eq!(
        verified_owner_provenance_from_secure_upgrade_proof(&record, &proof).unwrap_err(),
        SecureUpgradeProofVerificationError::OwnerSignatureChallengeDigestMismatch
    );
}

#[test]
fn replay_store_records_verified_attestation_without_minting() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof = proof_verification_for_record(&record, &owner_key);
    let replay_store = SecureUpgradeAppAttestReplayStore::new();

    let replay_record = replay_store
        .record_verified_attestation(&record, &proof)
        .unwrap();

    assert_eq!(replay_store.len(), 1);
    assert_eq!(
        replay_record.version(),
        SECURE_UPGRADE_APP_ATTEST_REPLAY_RECORD_VERSION
    );
    assert_eq!(replay_record.scope(), record.scope());
    assert_eq!(replay_record.challenge_digest(), proof.challenge_digest());
    assert_eq!(
        replay_record.proof_key_id_hash(),
        proof.app_attest().proof_key_id_hash()
    );
    assert_eq!(
        replay_record.leaf_public_key_sha256(),
        proof.app_attest().leaf_public_key_sha256()
    );
    assert_eq!(replay_record.attestation_counter(), 0);
}

#[test]
fn replay_store_rejects_same_challenge_digest_replay() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof = proof_verification_for_record(&record, &owner_key);
    let replay_store = SecureUpgradeAppAttestReplayStore::new();

    replay_store
        .record_verified_attestation(&record, &proof)
        .unwrap();

    assert_eq!(
        replay_store
            .record_verified_attestation(&record, &proof)
            .unwrap_err(),
        SecureUpgradeAppAttestReplayError::AttestationChallengeReplay
    );
    assert_eq!(replay_store.len(), 1);
}

#[test]
fn replay_store_rejects_same_proof_key_for_new_challenge() {
    let owner_key = P256Keypair::generate();
    let record_a = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let record_b = challenge_record(
        "su-challenge-beta",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof_a = proof_verification_for_record(&record_a, &owner_key);
    let proof_b = proof_verification_for_record(&record_b, &owner_key);
    let replay_store = SecureUpgradeAppAttestReplayStore::new();

    replay_store
        .record_verified_attestation(&record_a, &proof_a)
        .unwrap();

    assert_eq!(
        replay_store
            .record_verified_attestation(&record_b, &proof_b)
            .unwrap_err(),
        SecureUpgradeAppAttestReplayError::DuplicateProofKey
    );
}

#[test]
fn replay_store_rejects_proof_not_bound_to_record() {
    let owner_key = P256Keypair::generate();
    let record_a = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let record_b = challenge_record(
        "su-challenge-beta",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof_b = proof_verification_for_record(&record_b, &owner_key);
    let replay_store = SecureUpgradeAppAttestReplayStore::new();

    assert_eq!(
        replay_store
            .record_verified_attestation(&record_a, &proof_b)
            .unwrap_err(),
        SecureUpgradeAppAttestReplayError::Proof(
            SecureUpgradeProofVerificationError::ProofChallengeDigestMismatch
        )
    );
    assert!(replay_store.is_empty());
}

#[test]
fn replay_store_rejects_top_level_proof_digest_mismatch() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let mut proof = proof_verification_for_record(&record, &owner_key);
    proof.challenge_digest[0] ^= 0xff;
    let replay_store = SecureUpgradeAppAttestReplayStore::new();

    assert_eq!(
        replay_store
            .record_verified_attestation(&record, &proof)
            .unwrap_err(),
        SecureUpgradeAppAttestReplayError::Proof(
            SecureUpgradeProofVerificationError::ProofChallengeDigestMismatch
        )
    );
    assert!(replay_store.is_empty());
}

#[test]
fn replay_store_rejects_same_proof_key_with_changed_material() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof = proof_verification_for_record(&record, &owner_key);
    let mut changed_material = proof.clone();
    changed_material.app_attest.leaf_public_key_sha256[0] ^= 0xff;
    let replay_store = SecureUpgradeAppAttestReplayStore::new();

    replay_store
        .record_verified_attestation(&record, &proof)
        .unwrap();

    assert_eq!(
        replay_store
            .record_verified_attestation(&record, &changed_material)
            .unwrap_err(),
        SecureUpgradeAppAttestReplayError::ProofKeyMaterialMismatch
    );
}

#[test]
fn replay_store_rejects_nonzero_attestation_counter() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let mut proof = proof_verification_for_record(&record, &owner_key);
    proof.app_attest.bindings.attestation_object.counter = 1;
    let replay_store = SecureUpgradeAppAttestReplayStore::new();

    assert_eq!(
        replay_store
            .record_verified_attestation(&record, &proof)
            .unwrap_err(),
        SecureUpgradeAppAttestReplayError::AttestationCounterMismatch
    );
    assert!(replay_store.is_empty());
}

#[test]
fn durable_replay_store_persists_canonical_proof_key_record() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof = proof_verification_for_record(&record, &owner_key);
    let dir = tempfile::tempdir().expect("tempdir");
    let durable_store = SecureUpgradeDurableAppAttestReplayStore::new(dir.path());

    let replay_record = durable_store
        .record_verified_attestation(&record, &proof)
        .unwrap();

    let persisted_path = dir.path().join(format!(
        "{}.json",
        hex::encode(proof.app_attest().proof_key_id_hash())
    ));
    assert!(persisted_path.exists());
    let persisted: SecureUpgradeAppAttestReplayRecord =
        serde_json::from_str(&std::fs::read_to_string(persisted_path).unwrap()).unwrap();
    assert_eq!(persisted, replay_record);
    assert_eq!(
        replay_record.version(),
        SECURE_UPGRADE_APP_ATTEST_REPLAY_RECORD_VERSION
    );
}

#[test]
fn durable_replay_store_survives_reopen_and_rejects_same_digest_replay() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof = proof_verification_for_record(&record, &owner_key);
    let dir = tempfile::tempdir().expect("tempdir");
    SecureUpgradeDurableAppAttestReplayStore::new(dir.path())
        .record_verified_attestation(&record, &proof)
        .unwrap();

    let reopened = SecureUpgradeDurableAppAttestReplayStore::new(dir.path());

    assert_eq!(
        reopened
            .record_verified_attestation(&record, &proof)
            .unwrap_err(),
        SecureUpgradeAppAttestReplayError::AttestationChallengeReplay
    );
}

#[test]
fn durable_replay_store_survives_reopen_and_rejects_same_key_new_challenge() {
    let owner_key = P256Keypair::generate();
    let record_a = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let record_b = challenge_record(
        "su-challenge-beta",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof_a = proof_verification_for_record(&record_a, &owner_key);
    let proof_b = proof_verification_for_record(&record_b, &owner_key);
    let dir = tempfile::tempdir().expect("tempdir");
    SecureUpgradeDurableAppAttestReplayStore::new(dir.path())
        .record_verified_attestation(&record_a, &proof_a)
        .unwrap();

    let reopened = SecureUpgradeDurableAppAttestReplayStore::new(dir.path());

    assert_eq!(
        reopened
            .record_verified_attestation(&record_b, &proof_b)
            .unwrap_err(),
        SecureUpgradeAppAttestReplayError::DuplicateProofKey
    );
}

#[test]
fn durable_replay_store_rejects_changed_material_after_reopen() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof = proof_verification_for_record(&record, &owner_key);
    let mut changed_material = proof.clone();
    changed_material.app_attest.leaf_public_key_sha256[0] ^= 0xff;
    let dir = tempfile::tempdir().expect("tempdir");
    SecureUpgradeDurableAppAttestReplayStore::new(dir.path())
        .record_verified_attestation(&record, &proof)
        .unwrap();

    let reopened = SecureUpgradeDurableAppAttestReplayStore::new(dir.path());

    assert_eq!(
        reopened
            .record_verified_attestation(&record, &changed_material)
            .unwrap_err(),
        SecureUpgradeAppAttestReplayError::ProofKeyMaterialMismatch
    );
}

#[test]
fn durable_replay_store_fails_closed_on_corrupt_persisted_record() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let proof = proof_verification_for_record(&record, &owner_key);
    let dir = tempfile::tempdir().expect("tempdir");
    let durable_store = SecureUpgradeDurableAppAttestReplayStore::new(dir.path());
    durable_store
        .record_verified_attestation(&record, &proof)
        .unwrap();
    let persisted_path = dir.path().join(format!(
        "{}.json",
        hex::encode(proof.app_attest().proof_key_id_hash())
    ));
    std::fs::write(persisted_path, "{not-json").unwrap();

    let err = durable_store
        .record_verified_attestation(&record, &proof)
        .unwrap_err();

    assert!(matches!(
        err,
        SecureUpgradeAppAttestReplayError::StorageJson(_)
    ));
}

#[test]
fn durable_replay_store_allows_one_atomic_writer_across_instances() {
    let owner_key = P256Keypair::generate();
    let record = Arc::new(challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    ));
    let proof = Arc::new(proof_verification_for_record(&record, &owner_key));
    let dir = tempfile::tempdir().expect("tempdir");
    let store_a = Arc::new(SecureUpgradeDurableAppAttestReplayStore::new(dir.path()));
    let store_b = Arc::new(SecureUpgradeDurableAppAttestReplayStore::new(dir.path()));
    let barrier = Arc::new(Barrier::new(2));

    let (result_a, result_b) = std::thread::scope(|scope| {
        let record_a = Arc::clone(&record);
        let proof_a = Arc::clone(&proof);
        let store_a = Arc::clone(&store_a);
        let barrier_a = Arc::clone(&barrier);
        let handle_a = scope.spawn(move || {
            barrier_a.wait();
            store_a.record_verified_attestation(&record_a, &proof_a)
        });

        let record_b = Arc::clone(&record);
        let proof_b = Arc::clone(&proof);
        let store_b = Arc::clone(&store_b);
        let barrier_b = Arc::clone(&barrier);
        let handle_b = scope.spawn(move || {
            barrier_b.wait();
            store_b.record_verified_attestation(&record_b, &proof_b)
        });

        (handle_a.join().unwrap(), handle_b.join().unwrap())
    });

    let successes = usize::from(result_a.is_ok()) + usize::from(result_b.is_ok());
    assert_eq!(successes, 1);
    let replay_errors = [result_a, result_b]
        .into_iter()
        .filter_map(Result::err)
        .filter(|err| *err == SecureUpgradeAppAttestReplayError::AttestationChallengeReplay)
        .count();
    assert_eq!(replay_errors, 1);
}

#[test]
fn verified_ceremony_consumes_challenge_records_replay_and_returns_provenance_without_minting() {
    let owner_key = P256Keypair::generate();
    let challenge_store = SecureUpgradeChallengeStore::new();
    let transcript = transcript(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let record = challenge_store.issue(&transcript, NOW).unwrap();
    let canonical = record.canonical_transcript_bytes().to_vec();
    let proof = proof_verification_for_record(&record, &owner_key);
    let replay_dir = tempfile::tempdir().expect("tempdir");
    let replay_store = SecureUpgradeDurableAppAttestReplayStore::new(replay_dir.path());

    let verification = verify_secure_upgrade_verified_ceremony_for_challenge(
        &challenge_store,
        &replay_store,
        "su-challenge-alpha",
        &canonical,
        NOW,
        proof.clone(),
    )
    .unwrap();

    assert!(challenge_store.is_empty());
    assert_eq!(
        verification.challenge_record().challenge_id(),
        "su-challenge-alpha"
    );
    assert_eq!(
        verification.proof().challenge_digest(),
        proof.challenge_digest()
    );
    assert_eq!(
        verification.replay_record().challenge_digest(),
        proof.challenge_digest()
    );
    assert_eq!(
        verification.verified_owner_provenance().owner_provenance(),
        VerifiedOwnerProvenance::IosAppAttestOwner
    );
    assert_eq!(
        std::fs::read_dir(replay_dir.path()).unwrap().count(),
        1,
        "durable replay record is written exactly once"
    );
}

#[test]
fn secure_upgrade_minter_signs_owner_cert_only_from_verified_ceremony() {
    let hh_key = P256Keypair::generate();
    let owner_key = P256Keypair::generate();
    let owner_p_id = derive_person_id(&owner_key.public());
    let record = challenge_record_for_owner_person_id(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
        owner_p_id.clone(),
    );
    let verification = verified_ceremony_for_record(&record, &owner_key);

    let cert = sign_owner_cert_with_secure_upgrade_verification(
        &hh_key,
        sign_owner_options_for_record(&record, &owner_key),
        &verification,
    )
    .unwrap();

    assert_eq!(cert.hh_id, record.scope().hh_id);
    assert_eq!(cert.p_id, owner_p_id);
    assert_eq!(
        cert.owner_auth_tier_text(),
        Some(PersonCert::OWNER_AUTH_TIER_STRONG)
    );
    assert_eq!(
        cert.owner_provenance_text(),
        Some(PersonCert::OWNER_PROVENANCE_IOS_APP_ATTEST_OWNER)
    );
    assert!(cert.has_strong_owner_provenance());
    cert.verify(&record.scope().hh_id, &hh_key.public(), NOW)
        .unwrap();
}

#[test]
fn secure_upgrade_minter_rejects_household_id_mismatch() {
    let hh_key = P256Keypair::generate();
    let owner_key = P256Keypair::generate();
    let owner_p_id = derive_person_id(&owner_key.public());
    let record = challenge_record_for_owner_person_id(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
        owner_p_id,
    );
    let verification = verified_ceremony_for_record(&record, &owner_key);
    let mut opts = sign_owner_options_for_record(&record, &owner_key);
    opts.hh_id = crate::ids::derive_household_id(&P256Keypair::generate().public());

    assert!(matches!(
        sign_owner_cert_with_secure_upgrade_verification(&hh_key, opts, &verification).unwrap_err(),
        SecureUpgradeOwnerCertMintError::HouseholdIdMismatch
    ));
}

#[test]
fn secure_upgrade_minter_rejects_owner_person_id_mismatch() {
    let hh_key = P256Keypair::generate();
    let owner_key = P256Keypair::generate();
    let record = challenge_record(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let verification = verified_ceremony_for_record(&record, &owner_key);

    assert!(matches!(
        sign_owner_cert_with_secure_upgrade_verification(
            &hh_key,
            sign_owner_options_for_record(&record, &owner_key),
            &verification,
        )
        .unwrap_err(),
        SecureUpgradeOwnerCertMintError::OwnerPersonIdMismatch
    ));
}

#[test]
fn secure_upgrade_minter_rejects_owner_public_key_mismatch() {
    let hh_key = P256Keypair::generate();
    let minted_owner_key = P256Keypair::generate();
    let proof_owner_key = P256Keypair::generate();
    let owner_p_id = derive_person_id(&minted_owner_key.public());
    let record = challenge_record_for_owner_person_id(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
        owner_p_id,
    );
    let verification = verified_ceremony_for_record(&record, &proof_owner_key);

    assert!(matches!(
        sign_owner_cert_with_secure_upgrade_verification(
            &hh_key,
            sign_owner_options_for_record(&record, &minted_owner_key),
            &verification,
        )
        .unwrap_err(),
        SecureUpgradeOwnerCertMintError::OwnerPublicKeyMismatch
    ));
}

#[test]
fn verified_ceremony_rejects_second_challenge_for_same_app_attest_key() {
    let owner_key = P256Keypair::generate();
    let challenge_store = SecureUpgradeChallengeStore::new();
    let record_a = challenge_store
        .issue(
            &transcript(
                "su-challenge-alpha",
                OWNER_KEY_ID,
                SecureUpgradePlatform::Ios,
            ),
            NOW,
        )
        .unwrap();
    let record_b = challenge_store
        .issue(
            &transcript(
                "su-challenge-beta",
                OWNER_KEY_ID,
                SecureUpgradePlatform::Ios,
            ),
            NOW,
        )
        .unwrap();
    let canonical_a = record_a.canonical_transcript_bytes().to_vec();
    let canonical_b = record_b.canonical_transcript_bytes().to_vec();
    let proof_a = proof_verification_for_record(&record_a, &owner_key);
    let proof_b = proof_verification_for_record(&record_b, &owner_key);
    let replay_dir = tempfile::tempdir().expect("tempdir");
    let replay_store = SecureUpgradeDurableAppAttestReplayStore::new(replay_dir.path());

    verify_secure_upgrade_verified_ceremony_for_challenge(
        &challenge_store,
        &replay_store,
        "su-challenge-alpha",
        &canonical_a,
        NOW,
        proof_a,
    )
    .unwrap();

    assert_eq!(
        verify_secure_upgrade_verified_ceremony_for_challenge(
            &challenge_store,
            &replay_store,
            "su-challenge-beta",
            &canonical_b,
            NOW,
            proof_b,
        )
        .unwrap_err(),
        SecureUpgradeCeremonyVerificationError::Replay(
            SecureUpgradeAppAttestReplayError::DuplicateProofKey
        )
    );
    assert!(challenge_store.is_empty());
}

#[test]
fn full_ceremony_fails_closed_until_real_app_attest_fixture_is_available() {
    let owner_key = P256Keypair::generate();
    let challenge_store = SecureUpgradeChallengeStore::new();
    let transcript = transcript(
        "su-challenge-alpha",
        OWNER_KEY_ID,
        SecureUpgradePlatform::Ios,
    );
    let record = challenge_store.issue(&transcript, NOW).unwrap();
    let canonical = record.canonical_transcript_bytes().to_vec();
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);
    let owner_signature = owner_key.sign(&challenge_digest).unwrap();
    let synthetic = synthetic_attestation_for_record(&record);
    let replay_dir = tempfile::tempdir().expect("tempdir");
    let replay_store = SecureUpgradeDurableAppAttestReplayStore::new(replay_dir.path());

    let err = verify_secure_upgrade_ceremony_for_challenge(
        &challenge_store,
        &replay_store,
        "su-challenge-alpha",
        &canonical,
        SecureUpgradeProofVerificationInput {
            attestation_object_cbor: &synthetic.attestation_object_cbor,
            owner_public_key: &owner_key.public(),
            owner_signature: &owner_signature,
            now_unix: NOW,
        },
    )
    .unwrap_err();

    assert!(matches!(
        err,
        SecureUpgradeCeremonyVerificationError::Proof(
            SecureUpgradeProofVerificationError::AppAttest(_)
        )
    ));
    assert!(challenge_store.is_empty());
    assert_eq!(std::fs::read_dir(replay_dir.path()).unwrap().count(), 0);
}
