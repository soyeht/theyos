use ciborium::value::Value;
use household_rs::ids::HouseholdId;
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::machine_cert::PersonId;
use household_rs::secure_upgrade::{
    SecureUpgradeAppAttestTranscriptInput, SecureUpgradeOwnerSignatureError, SecureUpgradePlatform,
    SecureUpgradeProofEnvironment, SecureUpgradeTranscript, verify_owner_signature_for_transcript,
};
use sha2::{Digest, Sha256};

const TEAM_ID: &str = "TEAMID1234";
const BUNDLE_ID: &str = "com.example.soyeht";
const HH_ID: &str = "hh_fnlwza7qi4rxuadflfmxocnx5rwdb3ef2meq6unnh7qqiosfyain";
const OWNER_P_ID: &str = "p_ty3yfdchyn7nethoiefhrolfjxavzfe2bngb4tzzqy7cl3uqjfcq";
const OWNER_KEY_ID: &str = "owner-key-ios-alpha";
const NOW: u64 = 1_714_972_800;

fn transcript(challenge_id: &str, owner_key_id: &str) -> SecureUpgradeTranscript {
    SecureUpgradeTranscript::app_attest(SecureUpgradeAppAttestTranscriptInput {
        hh_id: HouseholdId::parse(HH_ID.to_string()).expect("fixture hh_id parses"),
        owner_p_id: PersonId(OWNER_P_ID.to_string()),
        owner_key_id: owner_key_id.to_string(),
        challenge_id: challenge_id.to_string(),
        issued_at: NOW,
        expires_at: NOW + 300,
        app_team_id: TEAM_ID.to_string(),
        app_bundle_id: BUNDLE_ID.to_string(),
        proof_key_id: "app-attest-proof-key-alpha".to_string(),
        proof_environment: SecureUpgradeProofEnvironment::Development,
        platform: SecureUpgradePlatform::Ios,
    })
}

#[test]
fn verifies_owner_signature_over_domain_separated_transcript_digest() {
    let owner_key = P256Keypair::generate();
    let transcript = transcript("su-challenge-alpha", OWNER_KEY_ID);
    let canonical = transcript.to_canonical_bytes().unwrap();
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);
    let signature = owner_key.sign(&challenge_digest).unwrap();

    let verification = verify_owner_signature_for_transcript(
        &canonical,
        OWNER_KEY_ID,
        &owner_key.public(),
        &signature,
    )
    .unwrap();

    assert_eq!(verification.challenge_digest(), challenge_digest);
    assert_eq!(verification.owner_key_id(), OWNER_KEY_ID);
    assert_eq!(verification.owner_public_key(), &owner_key.public());
}

#[test]
fn raw_cbor_without_domain_prefix_owner_signature_is_rejected() {
    let owner_key = P256Keypair::generate();
    let transcript = transcript("su-challenge-alpha", OWNER_KEY_ID);
    let canonical = transcript.to_canonical_bytes().unwrap();
    let raw_cbor_digest: [u8; 32] = Sha256::digest(&canonical).into();
    let signature = owner_key.sign(&raw_cbor_digest).unwrap();

    assert_eq!(
        verify_owner_signature_for_transcript(
            &canonical,
            OWNER_KEY_ID,
            &owner_key.public(),
            &signature,
        )
        .unwrap_err(),
        SecureUpgradeOwnerSignatureError::SignatureRejected
    );
}

#[test]
fn owner_signature_from_another_challenge_is_rejected() {
    let owner_key = P256Keypair::generate();
    let transcript_a = transcript("su-challenge-alpha", OWNER_KEY_ID);
    let transcript_b = transcript("su-challenge-beta", OWNER_KEY_ID);
    let canonical_a = transcript_a.to_canonical_bytes().unwrap();
    let canonical_b = transcript_b.to_canonical_bytes().unwrap();
    let digest_a =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical_a);
    let signature_a = owner_key.sign(&digest_a).unwrap();

    assert_eq!(
        verify_owner_signature_for_transcript(
            &canonical_b,
            OWNER_KEY_ID,
            &owner_key.public(),
            &signature_a,
        )
        .unwrap_err(),
        SecureUpgradeOwnerSignatureError::SignatureRejected
    );
}

#[test]
fn owner_signature_from_wrong_key_is_rejected() {
    let owner_key = P256Keypair::generate();
    let attacker_key = P256Keypair::generate();
    let transcript = transcript("su-challenge-alpha", OWNER_KEY_ID);
    let canonical = transcript.to_canonical_bytes().unwrap();
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);
    let attacker_signature = attacker_key.sign(&challenge_digest).unwrap();

    assert_eq!(
        verify_owner_signature_for_transcript(
            &canonical,
            OWNER_KEY_ID,
            &owner_key.public(),
            &attacker_signature,
        )
        .unwrap_err(),
        SecureUpgradeOwnerSignatureError::SignatureRejected
    );
}

#[test]
fn owner_key_id_mismatch_is_rejected_before_signature_success() {
    let owner_key = P256Keypair::generate();
    let transcript = transcript("su-challenge-alpha", "owner-key-ios-beta");
    let canonical = transcript.to_canonical_bytes().unwrap();
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);
    let signature = owner_key.sign(&challenge_digest).unwrap();

    assert_eq!(
        verify_owner_signature_for_transcript(
            &canonical,
            OWNER_KEY_ID,
            &owner_key.public(),
            &signature,
        )
        .unwrap_err(),
        SecureUpgradeOwnerSignatureError::OwnerKeyIdMismatch
    );
}

#[test]
fn non_canonical_transcript_is_rejected_before_owner_signature_verify() {
    let owner_key = P256Keypair::generate();
    let transcript = transcript("su-challenge-alpha", OWNER_KEY_ID);
    let canonical = transcript.to_canonical_bytes().unwrap();
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);
    let signature = owner_key.sign(&challenge_digest).unwrap();
    let non_canonical = non_canonical_map_order(&canonical);

    let error = verify_owner_signature_for_transcript(
        &non_canonical,
        OWNER_KEY_ID,
        &owner_key.public(),
        &signature,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        SecureUpgradeOwnerSignatureError::Transcript(message)
            if message.contains("not canonical")
    ));
}

fn non_canonical_map_order(canonical: &[u8]) -> Vec<u8> {
    let mut value: Value =
        ciborium::de::from_reader(canonical).expect("canonical transcript decodes");
    let Value::Map(entries) = &mut value else {
        panic!("transcript fixture is encoded as a CBOR map");
    };
    entries.reverse();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).expect("non-canonical transcript encodes");
    bytes
}
