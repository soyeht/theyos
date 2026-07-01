use ciborium::value::Value;
use household_rs::ids::HouseholdId;
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::machine_cert::PersonId;
use household_rs::secure_upgrade::{
    SECURE_UPGRADE_APP_ATTEST_FORMAT, SecureUpgradeAppAttestError,
    SecureUpgradeAppAttestTranscriptInput, SecureUpgradeChallengeRecord,
    SecureUpgradeChallengeStore, SecureUpgradePlatform, SecureUpgradeProofEnvironment,
    SecureUpgradeProofVerificationError, SecureUpgradeProofVerificationInput,
    SecureUpgradeTranscript, app_attest_app_identifier_hash, app_attest_nonce,
    verify_secure_upgrade_proof_for_challenge_record,
};

const TEAM_ID: &str = "TEAMID1234";
const BUNDLE_ID: &str = "com.example.soyeht";
const HH_ID: &str = "hh_fnlwza7qi4rxuadflfmxocnx5rwdb3ef2meq6unnh7qqiosfyain";
const OWNER_P_ID: &str = "p_ty3yfdchyn7nethoiefhrolfjxavzfe2bngb4tzzqy7cl3uqjfcq";
const OWNER_KEY_ID: &str = "owner-key-ios-alpha";
const NOW: u64 = 1_714_972_800;

struct SyntheticAttestation {
    attestation_object_cbor: Vec<u8>,
}

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

fn challenge_record(challenge_id: &str, owner_key_id: &str) -> SecureUpgradeChallengeRecord {
    let store = SecureUpgradeChallengeStore::new();
    store
        .issue(transcript(challenge_id, owner_key_id), NOW)
        .unwrap()
}

fn synthetic_auth_data(challenge_digest: [u8; 32]) -> Vec<u8> {
    let credential_id = challenge_digest;
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&app_attest_app_identifier_hash(TEAM_ID, BUNDLE_ID));
    auth_data.push(0x41);
    auth_data.extend_from_slice(&0_u32.to_be_bytes());
    auth_data.extend_from_slice(b"appattestdevelop");
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
    let _certificate_nonce = app_attest_nonce(&auth_data, challenge_digest);
    SyntheticAttestation {
        attestation_object_cbor: attestation_object(auth_data),
    }
}

#[test]
fn full_orchestrator_fails_closed_until_real_app_attest_fixture_is_available() {
    let owner_key = P256Keypair::generate();
    let record = challenge_record("su-challenge-alpha", OWNER_KEY_ID);
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
            record.canonical_transcript_bytes(),
        );
    let owner_signature = owner_key.sign(&challenge_digest).unwrap();
    let synthetic = synthetic_attestation_for_record(&record);

    assert!(matches!(
        verify_secure_upgrade_proof_for_challenge_record(
            &record,
            SecureUpgradeProofVerificationInput {
                attestation_object_cbor: &synthetic.attestation_object_cbor,
                owner_public_key: &owner_key.public(),
                owner_signature: &owner_signature,
                now_unix: NOW,
            },
        )
        .unwrap_err(),
        SecureUpgradeProofVerificationError::AppAttest(
            SecureUpgradeAppAttestError::CertificateParse(_)
                | SecureUpgradeAppAttestError::CertificateChain(_)
        )
    ));
}
