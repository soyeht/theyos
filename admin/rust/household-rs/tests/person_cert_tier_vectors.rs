use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::person_cert::{OwnerAuthClaimValue, SignOwnerOptions};
use household_rs::{PersonCert, derive_household_id};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    contract: String,
    version: u8,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    canonical_cbor_hex: String,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    owner_auth_tier: Option<String>,
    owner_provenance: Option<String>,
    can_fan_out: bool,
}

fn fixed_key(byte: u8) -> P256Keypair {
    P256Keypair::from_secret_scalar(&[byte; 32]).unwrap()
}

fn generated_vector_bytes(id: &str) -> Vec<u8> {
    let tier_and_provenance = match id {
        "legacy_tierless_reads_weak" => (None, None),
        "strong_ios_reads_strong" => (
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER.to_string(),
            )),
        ),
        "strong_ipados_secure_enclave_reads_strong" => (
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_PROVENANCE_IPADOS_SECURE_ENCLAVE_OWNER.to_string(),
            )),
        ),
        "strong_ios_app_attest_reads_strong" => (
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_PROVENANCE_IOS_APP_ATTEST_OWNER.to_string(),
            )),
        ),
        "strong_ipados_app_attest_reads_strong" => (
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_PROVENANCE_IPADOS_APP_ATTEST_OWNER.to_string(),
            )),
        ),
        "strong_macos_app_attest_reads_weak" => (
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            Some(OwnerAuthClaimValue::Text(
                "macos-app-attest-owner".to_string(),
            )),
        ),
        "strong_ios_app_attest_without_owner_suffix_reads_weak" => (
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            Some(OwnerAuthClaimValue::Text("ios-app-attest".to_string())),
        ),
        "unknown_tier_reads_weak" => (
            Some(OwnerAuthClaimValue::Text("future-strong".to_string())),
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER.to_string(),
            )),
        ),
        "malformed_tier_reads_weak" => (
            Some(OwnerAuthClaimValue::Unsigned(7)),
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER.to_string(),
            )),
        ),
        "null_tier_reads_weak" => (
            Some(OwnerAuthClaimValue::Null),
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER.to_string(),
            )),
        ),
        "strong_missing_provenance_reads_weak" => (
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            None,
        ),
        "strong_unknown_provenance_reads_weak" => (
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            Some(OwnerAuthClaimValue::Text("future-provenance".to_string())),
        ),
        "strong_malformed_provenance_reads_weak" => (
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            Some(OwnerAuthClaimValue::Unsigned(7)),
        ),
        "strong_null_provenance_reads_weak" => (
            Some(OwnerAuthClaimValue::Text(
                PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            Some(OwnerAuthClaimValue::Null),
        ),
        other => panic!("unknown vector id: {other}"),
    };

    let hh = fixed_key(0x31);
    let person = fixed_key(0x32);
    let hh_id = derive_household_id(&hh.public());
    let mut cert = PersonCert::sign_owner(
        &hh,
        SignOwnerOptions {
            hh_id,
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
    )
    .unwrap();
    cert.nonce = vec![0x42; 16];
    cert.owner_auth_tier = tier_and_provenance.0;
    cert.owner_provenance = tier_and_provenance.1;
    cert.signature = hh.sign(&cert.signing_bytes().unwrap()).unwrap();
    household_rs::cbor::to_canonical_vec(&cert).unwrap()
}

#[test]
fn person_cert_tier_vectors_are_canonical_and_fail_closed() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/person_cert_tier_vectors.json")).unwrap();
    assert_eq!(fixture.contract, "person_cert_owner_tier_v1");
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.vectors.len(), 14);

    let hh = fixed_key(0x31);
    let hh_id = derive_household_id(&hh.public());
    for vector in fixture.vectors {
        let bytes = hex::decode(&vector.canonical_cbor_hex).unwrap();
        assert_eq!(bytes, generated_vector_bytes(&vector.id), "{}", vector.id);

        let cert: PersonCert = household_rs::cbor::from_canonical_slice(&bytes).unwrap();
        cert.verify(&hh_id, &hh.public(), cert.issued_at).unwrap();
        assert_eq!(
            cert.owner_auth_tier_text().map(ToString::to_string),
            vector.expected.owner_auth_tier,
            "{}",
            vector.id
        );
        assert_eq!(
            cert.owner_provenance_text().map(ToString::to_string),
            vector.expected.owner_provenance,
            "{}",
            vector.id
        );
        assert_eq!(
            cert.has_strong_owner_provenance(),
            vector.expected.can_fan_out,
            "{}",
            vector.id
        );
    }
}

#[test]
#[ignore = "manual regeneration helper for person_cert_tier_vectors.json"]
fn print_person_cert_tier_vector_hexes() {
    for id in [
        "legacy_tierless_reads_weak",
        "strong_ios_reads_strong",
        "strong_ipados_secure_enclave_reads_strong",
        "strong_ios_app_attest_reads_strong",
        "strong_ipados_app_attest_reads_strong",
        "strong_macos_app_attest_reads_weak",
        "strong_ios_app_attest_without_owner_suffix_reads_weak",
        "unknown_tier_reads_weak",
        "malformed_tier_reads_weak",
        "null_tier_reads_weak",
        "strong_missing_provenance_reads_weak",
        "strong_unknown_provenance_reads_weak",
        "strong_malformed_provenance_reads_weak",
        "strong_null_provenance_reads_weak",
    ] {
        println!("{id} {}", hex::encode(generated_vector_bytes(id)));
    }
}
