use household_rs::ids::HouseholdId;
use household_rs::machine_cert::PersonId;
use household_rs::secure_upgrade::{
    SecureUpgradeAppAttestTranscriptInput, SecureUpgradeCommitmentError, SecureUpgradePlatform,
    SecureUpgradeProofCommitments, SecureUpgradeProofEnvironment, SecureUpgradeProofModel,
    SecureUpgradeTranscript,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Deserialize)]
struct Fixture {
    contract: String,
    version: u8,
    commitment_model: Option<CommitmentModel>,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct CommitmentModel {
    digest: String,
    app_attest_client_data_hash: String,
    owner_signature_input: String,
    verify_only: bool,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    input: Input,
    canonical_cbor_hex: String,
    challenge_sha256_hex: String,
    commitments: Option<Commitments>,
}

#[derive(Deserialize)]
struct Commitments {
    app_attest_client_data_hash_hex: String,
    owner_signature_input_hex: String,
    raw_cbor_sha256_hex: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct Input {
    v: u8,
    purpose: String,
    op: String,
    hh_id: String,
    owner_p_id: String,
    owner_key_id: String,
    challenge_id: String,
    issued_at: u64,
    expires_at: u64,
    app_team_id: String,
    app_bundle_id: String,
    proof_model: String,
    proof_key_id: String,
    proof_environment: String,
    platform: String,
    target_provenance: String,
}

#[derive(Serialize)]
struct OutputFixture<'a> {
    contract: &'a str,
    version: u8,
    commitment_model: OutputCommitmentModel<'a>,
    vectors: Vec<OutputVector<'a>>,
}

#[derive(Serialize)]
struct OutputCommitmentModel<'a> {
    digest: &'a str,
    app_attest_client_data_hash: &'a str,
    owner_signature_input: &'a str,
    verify_only: bool,
}

#[derive(Serialize)]
struct OutputVector<'a> {
    id: &'a str,
    input: &'a Input,
    canonical_cbor_hex: String,
    challenge_sha256_hex: String,
    commitments: OutputCommitments,
}

#[derive(Serialize)]
struct OutputCommitments {
    app_attest_client_data_hash_hex: String,
    owner_signature_input_hex: String,
    raw_cbor_sha256_hex: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "fixtures/secure_upgrade_transcript_vectors.json"
    ))
    .expect("secure_upgrade_transcript_vectors.json must be valid JSON")
}

fn fixture_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("secure_upgrade_transcript_vectors.json")
}

fn platform(value: &str) -> SecureUpgradePlatform {
    match value {
        "ios" => SecureUpgradePlatform::Ios,
        "ipados" => SecureUpgradePlatform::IpadOs,
        other => panic!("unknown platform in fixture: {other}"),
    }
}

fn environment(value: &str) -> SecureUpgradeProofEnvironment {
    match value {
        "development" => SecureUpgradeProofEnvironment::Development,
        "production" => SecureUpgradeProofEnvironment::Production,
        other => panic!("unknown proof environment in fixture: {other}"),
    }
}

fn transcript(input: &Input) -> SecureUpgradeTranscript {
    assert_eq!(input.v, 1);
    assert_eq!(input.purpose, "secure-upgrade-owner");
    assert_eq!(input.op, "secure-upgrade-with-iphone");
    assert_eq!(input.proof_model, "app-attest");
    let platform = platform(&input.platform);
    assert_eq!(input.target_provenance, platform.app_attest_provenance());
    SecureUpgradeTranscript::app_attest(SecureUpgradeAppAttestTranscriptInput {
        hh_id: HouseholdId::parse(input.hh_id.clone()).expect("fixture hh_id must parse"),
        owner_p_id: PersonId(input.owner_p_id.clone()),
        owner_key_id: input.owner_key_id.clone(),
        challenge_id: input.challenge_id.clone(),
        issued_at: input.issued_at,
        expires_at: input.expires_at,
        app_team_id: input.app_team_id.clone(),
        app_bundle_id: input.app_bundle_id.clone(),
        proof_key_id: input.proof_key_id.clone(),
        proof_environment: environment(&input.proof_environment),
        platform,
    })
}

fn commitments(vector: &Vector) -> &Commitments {
    vector
        .commitments
        .as_ref()
        .expect("fixture vector must include proof commitments")
}

fn hex_to_digest(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value).expect("fixture digest hex must decode");
    bytes
        .try_into()
        .expect("fixture digest hex must be 32 bytes")
}

fn raw_cbor_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn derived_output_fixture(fixture: &Fixture) -> OutputFixture<'_> {
    OutputFixture {
        contract: "secure_upgrade_transcript_v1",
        version: 1,
        commitment_model: OutputCommitmentModel {
            digest: "SHA256(soyeht-secure-upgrade-v1\\0 || canonical_transcript_cbor)",
            app_attest_client_data_hash: "challenge_digest",
            owner_signature_input: "challenge_digest",
            verify_only: true,
        },
        vectors: fixture
            .vectors
            .iter()
            .map(|vector| {
                let transcript = transcript(&vector.input);
                let canonical = transcript.to_canonical_bytes().unwrap();
                let challenge_digest =
                    SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
                        &canonical,
                    );
                let challenge_digest_hex = hex::encode(challenge_digest);
                OutputVector {
                    id: &vector.id,
                    input: &vector.input,
                    canonical_cbor_hex: hex::encode(&canonical),
                    challenge_sha256_hex: challenge_digest_hex.clone(),
                    commitments: OutputCommitments {
                        app_attest_client_data_hash_hex: challenge_digest_hex.clone(),
                        owner_signature_input_hex: challenge_digest_hex,
                        raw_cbor_sha256_hex: hex::encode(raw_cbor_sha256(&canonical)),
                    },
                }
            })
            .collect(),
    }
}

#[test]
fn secure_upgrade_transcript_vectors_are_canonical() {
    let fixture = fixture();
    assert_eq!(fixture.contract, "secure_upgrade_transcript_v1");
    assert_eq!(fixture.version, 1);
    let commitment_model = fixture
        .commitment_model
        .as_ref()
        .expect("fixture must declare commitment model");
    assert_eq!(
        commitment_model.digest,
        "SHA256(soyeht-secure-upgrade-v1\\0 || canonical_transcript_cbor)"
    );
    assert_eq!(
        commitment_model.app_attest_client_data_hash,
        "challenge_digest"
    );
    assert_eq!(commitment_model.owner_signature_input, "challenge_digest");
    assert!(commitment_model.verify_only);
    assert_eq!(fixture.vectors.len(), 2);

    for vector in fixture.vectors {
        let transcript = transcript(&vector.input);
        let canonical = transcript.to_canonical_bytes().unwrap();
        let stored_canonical = hex::decode(&vector.canonical_cbor_hex).unwrap();
        let server_recomputed_digest =
            SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
                &stored_canonical,
            );
        assert_eq!(
            hex::encode(&canonical),
            vector.canonical_cbor_hex,
            "{}",
            vector.id
        );
        assert_eq!(
            hex::encode(transcript.challenge_digest().unwrap()),
            hex::encode(server_recomputed_digest),
            "{}",
            vector.id
        );
        assert_eq!(
            hex::encode(server_recomputed_digest),
            vector.challenge_sha256_hex,
            "{}",
            vector.id
        );
        assert_eq!(
            hex::encode(transcript.app_attest_client_data_hash().unwrap()),
            vector.challenge_sha256_hex,
            "{}",
            vector.id
        );
        assert_eq!(
            hex::encode(transcript.owner_signature_input().unwrap()),
            vector.challenge_sha256_hex,
            "{}",
            vector.id
        );
        let commitments = commitments(&vector);
        assert_eq!(
            commitments.app_attest_client_data_hash_hex,
            vector.challenge_sha256_hex
        );
        assert_eq!(
            commitments.owner_signature_input_hex,
            vector.challenge_sha256_hex
        );
        assert_eq!(
            SecureUpgradeTranscript::from_canonical_bytes(&canonical).unwrap(),
            transcript,
            "{}",
            vector.id
        );
    }
}

#[test]
fn transcript_digest_changes_when_bound_fields_change() {
    let fixture = fixture();
    let vector = fixture.vectors.first().expect("at least one vector");
    let baseline = transcript(&vector.input);
    let baseline_digest = baseline.challenge_digest().unwrap();

    let mut changed_challenge = baseline.clone();
    changed_challenge.challenge_id = "su-challenge-ios-alpha-rotated".to_string();
    assert_ne!(
        changed_challenge.challenge_digest().unwrap(),
        baseline_digest
    );
    assert_ne!(
        changed_challenge.app_attest_client_data_hash().unwrap(),
        baseline_digest
    );
    assert_ne!(
        changed_challenge.owner_signature_input().unwrap(),
        baseline_digest
    );

    let mut changed_proof_key = baseline.clone();
    changed_proof_key.proof_key_id = "appattest-key-ios-beta".to_string();
    assert_ne!(
        changed_proof_key.challenge_digest().unwrap(),
        baseline_digest
    );
    assert_ne!(
        changed_proof_key.app_attest_client_data_hash().unwrap(),
        baseline_digest
    );
    assert_ne!(
        changed_proof_key.owner_signature_input().unwrap(),
        baseline_digest
    );

    let mut changed_owner_key = baseline;
    changed_owner_key.owner_key_id = "owner-key-ios-beta".to_string();
    assert_ne!(
        changed_owner_key.challenge_digest().unwrap(),
        baseline_digest
    );
    assert_ne!(
        changed_owner_key.app_attest_client_data_hash().unwrap(),
        baseline_digest
    );
    assert_ne!(
        changed_owner_key.owner_signature_input().unwrap(),
        baseline_digest
    );
}

#[test]
fn proof_commitments_must_match_server_recomputed_digest() {
    for vector in fixture().vectors {
        let canonical = hex::decode(&vector.canonical_cbor_hex).unwrap();
        let server_recomputed_digest =
            SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);
        let commitments = commitments(&vector);
        let verification = SecureUpgradeTranscript::verify_proof_commitments(
            &canonical,
            SecureUpgradeProofCommitments {
                client_data_hash: hex_to_digest(&commitments.app_attest_client_data_hash_hex),
                owner_signature_input: hex_to_digest(&commitments.owner_signature_input_hex),
            },
        )
        .unwrap();
        assert_eq!(verification.challenge_digest(), server_recomputed_digest);
    }
}

#[test]
fn bound_field_tamper_breaks_both_commitment_paths() {
    let fixture = fixture();
    let vector = fixture.vectors.first().expect("at least one vector");
    let baseline = transcript(&vector.input);
    let baseline_digest = baseline.challenge_digest().unwrap();

    let mut changed = baseline;
    changed.owner_key_id = "owner-key-ios-beta".to_string();
    let changed_canonical = changed.to_canonical_bytes().unwrap();
    let changed_digest = SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(
        &changed_canonical,
    );
    assert_ne!(changed_digest, baseline_digest);

    assert_eq!(
        SecureUpgradeTranscript::verify_proof_commitments(
            &changed_canonical,
            SecureUpgradeProofCommitments {
                client_data_hash: baseline_digest,
                owner_signature_input: changed_digest,
            },
        )
        .unwrap_err(),
        SecureUpgradeCommitmentError::ClientDataHashMismatch
    );
    assert_eq!(
        SecureUpgradeTranscript::verify_proof_commitments(
            &changed_canonical,
            SecureUpgradeProofCommitments {
                client_data_hash: changed_digest,
                owner_signature_input: baseline_digest,
            },
        )
        .unwrap_err(),
        SecureUpgradeCommitmentError::OwnerSignatureInputMismatch
    );
}

#[test]
fn mixed_challenge_proofs_are_rejected() {
    let fixture = fixture();
    let ios = fixture
        .vectors
        .iter()
        .find(|vector| vector.id == "ios_app_attest_production")
        .expect("ios vector");
    let ipados = fixture
        .vectors
        .iter()
        .find(|vector| vector.id == "ipados_app_attest_development")
        .expect("ipados vector");
    let ios_canonical = hex::decode(&ios.canonical_cbor_hex).unwrap();
    let ios_digest = hex_to_digest(&ios.challenge_sha256_hex);
    let ipados_digest = hex_to_digest(&ipados.challenge_sha256_hex);
    assert_ne!(ios_digest, ipados_digest);

    assert_eq!(
        SecureUpgradeTranscript::verify_proof_commitments(
            &ios_canonical,
            SecureUpgradeProofCommitments {
                client_data_hash: ios_digest,
                owner_signature_input: ipados_digest,
            },
        )
        .unwrap_err(),
        SecureUpgradeCommitmentError::OwnerSignatureInputMismatch
    );
    assert_eq!(
        SecureUpgradeTranscript::verify_proof_commitments(
            &ios_canonical,
            SecureUpgradeProofCommitments {
                client_data_hash: ipados_digest,
                owner_signature_input: ios_digest,
            },
        )
        .unwrap_err(),
        SecureUpgradeCommitmentError::ClientDataHashMismatch
    );
}

#[test]
fn raw_cbor_without_domain_prefix_rejected() {
    for vector in fixture().vectors {
        let canonical = hex::decode(&vector.canonical_cbor_hex).unwrap();
        let domain_separated_digest =
            SecureUpgradeTranscript::challenge_digest_from_canonical_transcript_bytes(&canonical);
        let raw_cbor_digest = hex_to_digest(&commitments(&vector).raw_cbor_sha256_hex);
        assert_ne!(raw_cbor_digest, domain_separated_digest);

        assert_eq!(
            SecureUpgradeTranscript::verify_proof_commitments(
                &canonical,
                SecureUpgradeProofCommitments {
                    client_data_hash: raw_cbor_digest,
                    owner_signature_input: domain_separated_digest,
                },
            )
            .unwrap_err(),
            SecureUpgradeCommitmentError::ClientDataHashMismatch
        );
        assert_eq!(
            SecureUpgradeTranscript::verify_proof_commitments(
                &canonical,
                SecureUpgradeProofCommitments {
                    client_data_hash: domain_separated_digest,
                    owner_signature_input: raw_cbor_digest,
                },
            )
            .unwrap_err(),
            SecureUpgradeCommitmentError::OwnerSignatureInputMismatch
        );
        assert_eq!(
            SecureUpgradeTranscript::verify_proof_commitments(
                &canonical,
                SecureUpgradeProofCommitments {
                    client_data_hash: raw_cbor_digest,
                    owner_signature_input: raw_cbor_digest,
                },
            )
            .unwrap_err(),
            SecureUpgradeCommitmentError::ClientDataHashMismatch
        );
    }
}

#[test]
fn app_attest_provenance_must_match_platform() {
    let fixture = fixture();
    let mut transcript = transcript(&fixture.vectors[0].input);
    transcript.target_provenance = "ipados-app-attest-owner".to_string();
    assert!(transcript.to_canonical_bytes().is_err());
}

#[test]
#[ignore = "manual regeneration helper for secure_upgrade_transcript_vectors.json"]
fn regenerate_secure_upgrade_transcript_vectors_json() {
    let fixture = fixture();
    let output = derived_output_fixture(&fixture);
    let payload = serde_json::to_string_pretty(&output).unwrap();
    std::fs::write(fixture_path(), format!("{payload}\n"))
        .expect("write secure_upgrade_transcript_vectors.json");
}

#[test]
fn regenerated_fixture_matches_checked_in_fixture() {
    let fixture = fixture();
    let output = derived_output_fixture(&fixture);
    let payload = serde_json::to_string_pretty(&output).unwrap();
    let checked_in = std::fs::read_to_string(fixture_path()).unwrap();
    assert_eq!(
        checked_in,
        format!("{payload}\n"),
        "run: cargo test -p household-rs regenerate_secure_upgrade_transcript_vectors_json -- --ignored --exact"
    );
}

#[test]
#[ignore = "manual debug helper for secure_upgrade_transcript_vectors.json"]
fn print_secure_upgrade_transcript_vector_hexes() {
    for vector in fixture().vectors {
        let fixture = Fixture {
            contract: "secure_upgrade_transcript_v1".to_string(),
            version: 1,
            commitment_model: None,
            vectors: vec![vector],
        };
        let output = derived_output_fixture(&fixture);
        for vector in output.vectors {
            println!(
                "{} {} {} {}",
                vector.id,
                vector.canonical_cbor_hex,
                vector.challenge_sha256_hex,
                vector.commitments.raw_cbor_sha256_hex
            );
        }
    }

    // Keep this import exercised in the test target so any proof-model enum
    // rename breaks the fixture code at compile time.
    assert_eq!(
        SecureUpgradeProofModel::AppAttest,
        SecureUpgradeProofModel::AppAttest
    );
}
