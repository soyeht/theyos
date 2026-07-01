use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ciborium::value::Value;
use household_rs::ids::HouseholdId;
use household_rs::machine_cert::PersonId;
use household_rs::secure_upgrade::{
    SECURE_UPGRADE_APP_ATTEST_FORMAT, SECURE_UPGRADE_APP_ATTEST_ROOT_CA_SHA256,
    SecureUpgradeAppAttestError, SecureUpgradeAppAttestObject,
    SecureUpgradeAppAttestTranscriptInput, SecureUpgradePlatform, SecureUpgradeProofEnvironment,
    SecureUpgradeTranscript, app_attest_app_identifier_hash, app_attest_nonce,
    app_attest_root_certificate_der, verify_app_attest_attestation,
    verify_app_attest_attestation_for_transcript, verify_app_attest_commitment_bindings,
    verify_app_attest_commitment_bindings_for_transcript,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{env, fs};

const TEAM_ID: &str = "TEAMID1234";
const BUNDLE_ID: &str = "com.example.soyeht";
const CHALLENGE_DIGEST: [u8; 32] = [0x42; 32];
const CREDENTIAL_ID: &[u8] = b"appattest-credential-alpha";
const RECEIPT: &[u8] = b"synthetic-receipt";
const NOW: u64 = 1_714_972_800;
const HH_ID: &str = "hh_fnlwza7qi4rxuadflfmxocnx5rwdb3ef2meq6unnh7qqiosfyain";
const OWNER_P_ID: &str = "p_ty3yfdchyn7nethoiefhrolfjxavzfe2bngb4tzzqy7cl3uqjfcq";

struct SyntheticAttestation {
    attestation_object_cbor: Vec<u8>,
    auth_data: Vec<u8>,
    certificate_nonce: [u8; 32],
}

fn synthetic_auth_data(team_id: &str, bundle_id: &str, credential_id: &[u8]) -> Vec<u8> {
    assert!(credential_id.len() <= u16::MAX as usize);
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&app_attest_app_identifier_hash(team_id, bundle_id));
    auth_data.push(0x41);
    auth_data.extend_from_slice(&0_u32.to_be_bytes());
    auth_data.extend_from_slice(&[0xa5; 16]);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(&[0xa5, 0x01, 0x02]);
    auth_data
}

fn attestation_object(
    fmt: &str,
    auth_data: Vec<u8>,
    x5c: Vec<Vec<u8>>,
    receipt: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut att_stmt = vec![(
        Value::Text("x5c".to_string()),
        Value::Array(x5c.into_iter().map(Value::Bytes).collect()),
    )];
    if let Some(receipt) = receipt {
        att_stmt.push((Value::Text("receipt".to_string()), Value::Bytes(receipt)));
    }
    let value = Value::Map(vec![
        (Value::Text("fmt".to_string()), Value::Text(fmt.to_string())),
        (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
        (Value::Text("attStmt".to_string()), Value::Map(att_stmt)),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).expect("synthetic App Attest CBOR encodes");
    bytes
}

fn synthetic_attestation(challenge_digest: [u8; 32]) -> SyntheticAttestation {
    let auth_data = synthetic_auth_data(TEAM_ID, BUNDLE_ID, CREDENTIAL_ID);
    let certificate_nonce = app_attest_nonce(&auth_data, challenge_digest);
    let attestation_object_cbor = attestation_object(
        SECURE_UPGRADE_APP_ATTEST_FORMAT,
        auth_data.clone(),
        vec![vec![0x30, 0x03, 0x02, 0x01, 0x01]],
        Some(RECEIPT.to_vec()),
    );
    SyntheticAttestation {
        attestation_object_cbor,
        auth_data,
        certificate_nonce,
    }
}

fn transcript() -> SecureUpgradeTranscript {
    SecureUpgradeTranscript::app_attest(SecureUpgradeAppAttestTranscriptInput {
        hh_id: HouseholdId::parse(HH_ID.to_string()).expect("fixture hh_id parses"),
        owner_p_id: PersonId(OWNER_P_ID.to_string()),
        owner_key_id: "owner-key-alpha".to_string(),
        challenge_id: "su-challenge-alpha".to_string(),
        issued_at: NOW,
        expires_at: NOW + 300,
        app_team_id: TEAM_ID.to_string(),
        app_bundle_id: BUNDLE_ID.to_string(),
        proof_key_id: "YXBwYXR0ZXN0LWNyZWRlbnRpYWwtYWxwaGE=".to_string(),
        proof_environment: SecureUpgradeProofEnvironment::Production,
        platform: SecureUpgradePlatform::Ios,
    })
}

#[test]
fn parses_app_attest_object_and_commitment_bindings() {
    let fixture = synthetic_attestation(CHALLENGE_DIGEST);
    let parsed = SecureUpgradeAppAttestObject::parse(&fixture.attestation_object_cbor).unwrap();

    assert_eq!(parsed.fmt(), SECURE_UPGRADE_APP_ATTEST_FORMAT);
    assert_eq!(parsed.auth_data(), fixture.auth_data.as_slice());
    assert_eq!(
        parsed.rp_id_hash(),
        app_attest_app_identifier_hash(TEAM_ID, BUNDLE_ID)
    );
    assert_eq!(parsed.flags(), 0x41);
    assert_eq!(parsed.counter(), 0);
    assert_eq!(parsed.aaguid(), [0xa5; 16]);
    assert_eq!(parsed.credential_id(), CREDENTIAL_ID);
    assert_eq!(parsed.credential_public_key_cose(), &[0xa5, 0x01, 0x02]);
    assert_eq!(parsed.x5c().len(), 1);
    assert_eq!(parsed.receipt(), Some(RECEIPT));

    let bindings = verify_app_attest_commitment_bindings(
        &fixture.attestation_object_cbor,
        CHALLENGE_DIGEST,
        TEAM_ID,
        BUNDLE_ID,
        fixture.certificate_nonce,
    )
    .unwrap();
    assert_eq!(bindings.challenge_digest(), CHALLENGE_DIGEST);
    assert_eq!(
        bindings.app_identifier_hash(),
        app_attest_app_identifier_hash(TEAM_ID, BUNDLE_ID)
    );
    assert_eq!(bindings.certificate_nonce(), fixture.certificate_nonce);
    assert_eq!(bindings.attestation_object(), &parsed);
}

#[test]
fn rejects_non_app_attest_format() {
    let auth_data = synthetic_auth_data(TEAM_ID, BUNDLE_ID, CREDENTIAL_ID);
    let cbor = attestation_object(
        "apple",
        auth_data,
        vec![vec![0x30, 0x03, 0x02, 0x01, 0x01]],
        None,
    );

    assert_eq!(
        SecureUpgradeAppAttestObject::parse(&cbor).unwrap_err(),
        SecureUpgradeAppAttestError::UnsupportedFormat("apple".to_string())
    );
}

#[test]
fn rejects_certificate_nonce_that_is_not_bound_to_challenge_digest() {
    let fixture = synthetic_attestation(CHALLENGE_DIGEST);
    let mut wrong_nonce = fixture.certificate_nonce;
    wrong_nonce[0] ^= 0xff;

    assert_eq!(
        verify_app_attest_commitment_bindings(
            &fixture.attestation_object_cbor,
            CHALLENGE_DIGEST,
            TEAM_ID,
            BUNDLE_ID,
            wrong_nonce,
        )
        .unwrap_err(),
        SecureUpgradeAppAttestError::CertificateNonceMismatch
    );
}

#[test]
fn rejects_rp_id_hash_that_does_not_match_app_identifier() {
    let fixture = synthetic_attestation(CHALLENGE_DIGEST);

    assert_eq!(
        verify_app_attest_commitment_bindings(
            &fixture.attestation_object_cbor,
            CHALLENGE_DIGEST,
            TEAM_ID,
            "com.example.other",
            fixture.certificate_nonce,
        )
        .unwrap_err(),
        SecureUpgradeAppAttestError::AppIdentifierHashMismatch
    );
}

#[test]
fn rejects_attestation_without_certificate_chain() {
    let auth_data = synthetic_auth_data(TEAM_ID, BUNDLE_ID, CREDENTIAL_ID);
    let cbor = attestation_object(
        SECURE_UPGRADE_APP_ATTEST_FORMAT,
        auth_data,
        Vec::new(),
        None,
    );

    assert_eq!(
        SecureUpgradeAppAttestObject::parse(&cbor).unwrap_err(),
        SecureUpgradeAppAttestError::MissingCertificateChain
    );
}

#[test]
fn rejects_truncated_auth_data() {
    let cbor = attestation_object(
        SECURE_UPGRADE_APP_ATTEST_FORMAT,
        vec![0; 36],
        vec![vec![0x30, 0x03, 0x02, 0x01, 0x01]],
        None,
    );

    assert_eq!(
        SecureUpgradeAppAttestObject::parse(&cbor).unwrap_err(),
        SecureUpgradeAppAttestError::AuthDataTooShort
    );
}

#[test]
fn full_attestation_verification_rejects_malformed_certificate_chain() {
    let fixture = synthetic_attestation(CHALLENGE_DIGEST);

    assert!(matches!(
        verify_app_attest_attestation(
            &fixture.attestation_object_cbor,
            CHALLENGE_DIGEST,
            TEAM_ID,
            BUNDLE_ID,
            "YXBwYXR0ZXN0LWNyZWRlbnRpYWwtYWxwaGE=",
            SecureUpgradeProofEnvironment::Production,
            NOW,
        )
        .unwrap_err(),
        SecureUpgradeAppAttestError::CertificateParse(_)
            | SecureUpgradeAppAttestError::CertificateChain(_)
    ));
}

#[test]
fn transcript_entrypoint_recomputes_digest_and_app_identity_from_canonical_transcript() {
    let transcript = transcript();
    let canonical = transcript.to_canonical_bytes().unwrap();
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);
    let fixture = synthetic_attestation(challenge_digest);

    let bindings = verify_app_attest_commitment_bindings_for_transcript(
        &fixture.attestation_object_cbor,
        &canonical,
        fixture.certificate_nonce,
    )
    .unwrap();

    assert_eq!(bindings.challenge_digest(), challenge_digest);
    assert_eq!(
        bindings.app_identifier_hash(),
        app_attest_app_identifier_hash(TEAM_ID, BUNDLE_ID)
    );
}

#[test]
fn transcript_attestation_entrypoint_rejects_malformed_certificate_chain() {
    let transcript = transcript();
    let canonical = transcript.to_canonical_bytes().unwrap();
    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);
    let fixture = synthetic_attestation(challenge_digest);

    assert!(matches!(
        verify_app_attest_attestation_for_transcript(
            &fixture.attestation_object_cbor,
            &canonical,
            NOW,
        )
        .unwrap_err(),
        SecureUpgradeAppAttestError::CertificateParse(_)
            | SecureUpgradeAppAttestError::CertificateChain(_)
    ));
}

#[test]
fn apple_app_attest_root_ca_matches_pinned_fingerprint() {
    let root = app_attest_root_certificate_der().unwrap();
    let digest: [u8; 32] = Sha256::digest(&root).into();

    assert_eq!(digest, SECURE_UPGRADE_APP_ATTEST_ROOT_CA_SHA256);
}

#[derive(Debug, Deserialize)]
struct RealIphoneAppAttestFixture {
    contract: String,
    capture_run_id: String,
    environment: String,
    canonical_transcript_cbor_hex: String,
    challenge_sha256_hex: String,
    app_attest_key_id: String,
    attestation_object_cbor_base64: String,
    verification_time_unix: u64,
}

#[test]
#[ignore = "requires a local real-iPhone App Attest fixture"]
fn real_iphone_app_attest_fixture_verifies_current_apple_chain() {
    let path = env::var("SOYEHT_SECURE_UPGRADE_APP_ATTEST_FIXTURE")
        .expect("set SOYEHT_SECURE_UPGRADE_APP_ATTEST_FIXTURE to the local fixture JSON path");
    let raw = fs::read_to_string(path).expect("real iPhone App Attest fixture is readable");
    let fixture: RealIphoneAppAttestFixture =
        serde_json::from_str(&raw).expect("real iPhone App Attest fixture is valid JSON");
    assert_eq!(
        fixture.contract,
        "secure_upgrade_app_attest_positive_fixture_v1"
    );
    let capture_run_id = env::var("SOYEHT_SECURE_UPGRADE_APP_ATTEST_CAPTURE_RUN_ID")
        .expect("set SOYEHT_SECURE_UPGRADE_APP_ATTEST_CAPTURE_RUN_ID for a fresh capture");
    assert_eq!(fixture.capture_run_id, capture_run_id);

    let canonical_transcript_bytes = decode_hex(&fixture.canonical_transcript_cbor_hex);
    let transcript = SecureUpgradeTranscript::from_canonical_bytes(&canonical_transcript_bytes)
        .expect("captured fixture transcript is valid canonical Secure/Upgrade CBOR");
    assert_eq!(
        transcript.challenge_id,
        format!("su-capture-{capture_run_id}")
    );
    assert_eq!(transcript.proof_key_id, fixture.app_attest_key_id);
    assert_eq!(
        transcript.proof_environment,
        match fixture.environment.as_str() {
            "development" => SecureUpgradeProofEnvironment::Development,
            "production" => SecureUpgradeProofEnvironment::Production,
            other => panic!("unsupported fixture environment: {other}"),
        }
    );

    let challenge_digest =
        SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
            &canonical_transcript_bytes,
        );
    assert_eq!(
        challenge_digest.to_vec(),
        decode_hex(&fixture.challenge_sha256_hex)
    );

    let attestation_object_cbor = BASE64_STANDARD
        .decode(fixture.attestation_object_cbor_base64)
        .expect("attestation_object_cbor_base64 is valid standard Base64");
    let verification = verify_app_attest_attestation_for_transcript(
        &attestation_object_cbor,
        &canonical_transcript_bytes,
        fixture.verification_time_unix,
    )
    .expect("real iPhone App Attest fixture verifies against the pinned Apple chain");

    assert_eq!(verification.bindings().challenge_digest(), challenge_digest);
    assert_eq!(
        verification.root_ca_sha256(),
        SECURE_UPGRADE_APP_ATTEST_ROOT_CA_SHA256
    );
}

fn decode_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex strings must have even length");
    (0..hex.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&hex[offset..offset + 2], 16)
                .expect("fixture hex strings contain only hex digits")
        })
        .collect()
}
