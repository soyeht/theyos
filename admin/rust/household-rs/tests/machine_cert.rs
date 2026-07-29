use ciborium::value::Value;
use household_rs::cbor;
use household_rs::machine_cert::SignOptions;
use household_rs::{
    CertType, IdentityKey, MachineCert, P256Keypair, PersonId, Platform, SubjectId,
    derive_household_id,
};
use serde::Deserialize;

fn signed_cert() -> (P256Keypair, P256Keypair, MachineCert) {
    let household = P256Keypair::generate();
    let machine = P256Keypair::generate();
    let hh_id = derive_household_id(&household.public());
    let cert = MachineCert::sign(
        &household,
        &machine.public(),
        &SignOptions {
            hh_id,
            hostname: "studio-mac".into(),
            platform: Platform::Macos,
            joined_at: 1_714_972_800,
        },
    )
    .unwrap();

    (household, machine, cert)
}

#[test]
fn sign_then_verify_round_trip() {
    let (household, _machine, cert) = signed_cert();

    cert.verify(&household.public()).unwrap();
}

#[test]
fn tampering_signed_payload_fails_verify() {
    let (household, _machine, mut cert) = signed_cert();
    cert.hostname = "studio-mac-renamed".into();

    cert.verify(&household.public()).unwrap_err();
}

#[test]
fn mismatched_household_public_key_fails_verify() {
    let (_household, _machine, cert) = signed_cert();
    let other_household = P256Keypair::generate();

    cert.verify(&other_household.public()).unwrap_err();
}

#[test]
fn unknown_cert_type_is_rejected() {
    let (household, _machine, mut cert) = signed_cert();
    cert.cert_type = CertType::Person;

    cert.verify(&household.public()).unwrap_err();
}

#[test]
fn non_household_issuer_is_rejected() {
    let (household, _machine, mut cert) = signed_cert();
    cert.issued_by = SubjectId::Person(PersonId(format!("p_{}", "a".repeat(52))));

    cert.verify(&household.public()).unwrap_err();
}

#[test]
fn non_empty_caveats_are_refused_by_phase1_schema() {
    let (_household, _machine, cert) = signed_cert();
    let bytes = cbor::to_canonical_vec(&cert).unwrap();
    let mut value: Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();

    let Value::Map(fields) = &mut value else {
        panic!("MachineCert encoded to non-map CBOR");
    };
    let caveats = fields
        .iter_mut()
        .find_map(|(key, value)| match key {
            Value::Text(key) if key == "caveats" => Some(value),
            _ => None,
        })
        .expect("caveats field exists");
    *caveats = Value::Array(vec![Value::Null]);

    let mut tampered = Vec::new();
    ciborium::ser::into_writer(&value, &mut tampered).unwrap();

    let decoded: Result<MachineCert, _> = cbor::from_canonical_slice(&tampered);
    assert!(decoded.is_err(), "non-empty caveats decoded successfully");
}

// ---------------------------------------------------------------------------
// Claw-share MachineCert attestation cross-language vector.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ClawShareAttestationFixture {
    contract: String,
    version: u8,
    about: Vec<String>,
    root_public_key_sec1_compressed_hex: String,
    household_id: String,
    machine_public_key_sec1_compressed_hex: String,
    machine_id: String,
    canonical_machine_cert_cbor_hex: String,
}

fn deterministic_claw_share_cert() -> (P256Keypair, MachineCert) {
    let root = P256Keypair::from_secret_scalar(&[0x41; 32]).expect("root scalar");
    let machine = P256Keypair::from_secret_scalar(&[0x42; 32]).expect("machine scalar");
    let cert = MachineCert::sign(
        &root,
        &machine.public(),
        &SignOptions {
            hh_id: derive_household_id(&root.public()),
            hostname: "attested-mac".into(),
            platform: Platform::Macos,
            joined_at: 1_800_000_000,
        },
    )
    .expect("sign deterministic cert");
    (root, cert)
}

fn claw_share_attestation_fixture() -> ClawShareAttestationFixture {
    serde_json::from_str(include_str!("data/claw_share_machine_attestation_v1.json"))
        .expect("machine attestation fixture JSON")
}

#[test]
fn claw_share_machine_attestation_vector_is_byte_exact_and_root_verifiable() {
    let fixture = claw_share_attestation_fixture();
    assert_eq!(fixture.contract, "claw-share-machine-attestation-v1");
    assert_eq!(fixture.version, 1);
    assert!(
        fixture
            .about
            .iter()
            .any(|line| line.contains("does not prove current roster membership")),
        "fixture must preserve the provenance-only boundary",
    );

    let (root, cert) = deterministic_claw_share_cert();
    cert.verify(&root.public()).expect("root-signed cert");
    let canonical = cbor::to_canonical_vec(&cert).expect("canonical cert");

    assert_eq!(
        fixture.root_public_key_sec1_compressed_hex,
        hex::encode(root.public().as_bytes()),
    );
    assert_eq!(fixture.household_id, cert.hh_id.as_str());
    assert_eq!(
        fixture.machine_public_key_sec1_compressed_hex,
        hex::encode(cert.m_pub.as_bytes()),
    );
    assert_eq!(fixture.machine_id, cert.m_id.as_str());
    assert_eq!(
        fixture.canonical_machine_cert_cbor_hex,
        hex::encode(&canonical),
        "canonical MachineCert CBOR drifted; update all cross-language consumers intentionally",
    );

    let decoded: MachineCert =
        cbor::from_canonical_slice(&canonical).expect("decode canonical cert");
    assert_eq!(decoded, cert);
}

#[test]
fn tampering_the_published_claw_share_machine_cert_vector_fails_root_verification() {
    let fixture = claw_share_attestation_fixture();
    let bytes = hex::decode(fixture.canonical_machine_cert_cbor_hex).expect("fixture hex");
    let mut cert: MachineCert = cbor::from_canonical_slice(&bytes).expect("fixture cert");
    let (root, _) = deterministic_claw_share_cert();
    cert.hostname.push_str("-tampered");
    assert!(cert.verify(&root.public()).is_err());
}

#[test]
#[ignore = "manual fixture regeneration helper; prints public material only"]
fn print_claw_share_machine_attestation_fixture_fields() {
    let (root, cert) = deterministic_claw_share_cert();
    let canonical = cbor::to_canonical_vec(&cert).expect("canonical cert");
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "root_public_key_sec1_compressed_hex": hex::encode(root.public().as_bytes()),
            "household_id": cert.hh_id.as_str(),
            "machine_public_key_sec1_compressed_hex": hex::encode(cert.m_pub.as_bytes()),
            "machine_id": cert.m_id.as_str(),
            "canonical_machine_cert_cbor_hex": hex::encode(canonical),
        }))
        .expect("fixture JSON")
    );
}

// ---------------------------------------------------------------------------
// Phase 3 candidate-issuance + household-root verify (T014/T015).
// ---------------------------------------------------------------------------

mod phase3 {
    use household_rs::machine_cert::{
        CertError, MachineCert, Platform, issue_for_candidate, verify_against_household_root,
    };
    use household_rs::{IdentityKey, P256Keypair, derive_household_id};
    use zeroize::Zeroizing;

    fn hh_keypair() -> (
        P256Keypair,
        [u8; 33],
        household_rs::HouseholdId,
        Zeroizing<[u8; 32]>,
    ) {
        let kp = P256Keypair::generate();
        let pub_arr = *kp.public().as_bytes();
        let hh_id = derive_household_id(&kp.public());
        let priv_arr = *kp.as_software_secret().expect("software backed");
        (kp, pub_arr, hh_id, Zeroizing::new(priv_arr))
    }

    fn candidate_pub() -> [u8; 33] {
        *P256Keypair::generate().public().as_bytes()
    }

    #[test]
    fn issue_then_verify_roundtrip() {
        let (_kp, hh_pub, hh_id, hh_priv) = hh_keypair();
        let m_pub = candidate_pub();
        let cert = issue_for_candidate(
            &hh_priv,
            &hh_id,
            &m_pub,
            "studio-linux",
            Platform::LinuxNix,
            1_714_972_800,
        )
        .expect("issue cert");
        verify_against_household_root(&cert, &hh_pub).expect("verify happy");
        assert_eq!(cert.hostname, "studio-linux");
        assert_eq!(cert.platform, Platform::LinuxNix);
    }

    #[test]
    fn tampered_hostname_fails_verify() {
        let (_kp, hh_pub, hh_id, hh_priv) = hh_keypair();
        let m_pub = candidate_pub();
        let mut cert = issue_for_candidate(
            &hh_priv,
            &hh_id,
            &m_pub,
            "studio-linux",
            Platform::LinuxNix,
            1_714_972_800,
        )
        .expect("issue cert");
        cert.hostname = "studio-pwned".into();
        let err = verify_against_household_root(&cert, &hh_pub).unwrap_err();
        assert!(matches!(err, CertError::Verify(_)));
    }

    #[test]
    fn tampered_signature_fails_verify() {
        let (_kp, hh_pub, hh_id, hh_priv) = hh_keypair();
        let m_pub = candidate_pub();
        let mut cert = issue_for_candidate(
            &hh_priv,
            &hh_id,
            &m_pub,
            "studio-linux",
            Platform::LinuxNix,
            1_714_972_800,
        )
        .expect("issue cert");
        cert.signature.0[0] ^= 0x40;
        let err = verify_against_household_root(&cert, &hh_pub).unwrap_err();
        assert!(matches!(err, CertError::Verify(_)));
    }

    #[test]
    fn wrong_household_pub_fails_verify() {
        let (_kp, _hh_pub, hh_id, hh_priv) = hh_keypair();
        let m_pub = candidate_pub();
        let cert = issue_for_candidate(
            &hh_priv,
            &hh_id,
            &m_pub,
            "studio-linux",
            Platform::LinuxNix,
            1_714_972_800,
        )
        .expect("issue cert");
        let other_pub = *P256Keypair::generate().public().as_bytes();
        let err = verify_against_household_root(&cert, &other_pub).unwrap_err();
        assert!(matches!(err, CertError::Verify(_)));
    }

    #[test]
    fn deterministic_cbor_property_after_issue() {
        let (_kp, _hh_pub, hh_id, hh_priv) = hh_keypair();
        let m_pub = candidate_pub();
        let cert = issue_for_candidate(
            &hh_priv,
            &hh_id,
            &m_pub,
            "studio-linux",
            Platform::LinuxNix,
            1_714_972_800,
        )
        .expect("issue cert");
        let bytes_a = household_rs::cbor::to_canonical_vec(&cert).unwrap();
        let bytes_b = household_rs::cbor::to_canonical_vec(&cert).unwrap();
        assert_eq!(bytes_a, bytes_b);
        let decoded: MachineCert = household_rs::cbor::from_canonical_slice(&bytes_a).unwrap();
        assert_eq!(decoded, cert);
    }
}
