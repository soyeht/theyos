use household_rs::cbor;
use household_rs::machine_cert::SignOptions;
use household_rs::{
    HouseholdRecord, IdentityKey, MachineCert, P256Keypair, Platform, derive_household_id,
    derive_machine_id, verify_loaded_chain,
};

fn chain_fixture() -> (HouseholdRecord, MachineCert) {
    let household = P256Keypair::generate();
    let machine = P256Keypair::generate();
    let hh_pub = household.public();
    let m_pub = machine.public();
    let hh_id = derive_household_id(&hh_pub);
    let m_id = derive_machine_id(&m_pub);

    let record = HouseholdRecord {
        version: HouseholdRecord::SCHEMA_VERSION,
        hh_id: hh_id.clone(),
        hh_pub,
        name: "Sample Home".into(),
        created_at: 1_714_972_800,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![m_id],
        is_follower: false,
    };
    let cert = MachineCert::sign(
        &household,
        &m_pub,
        &SignOptions {
            hh_id,
            hostname: "studio-mac".into(),
            platform: Platform::Macos,
            joined_at: 1_714_972_800,
        },
    )
    .unwrap();

    (record, cert)
}

fn flip_first_embedded_byte(encoded: &mut [u8], needle: &[u8]) {
    let start = encoded
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("needle appears in encoded CBOR");
    encoded[start] ^= 0x01;
}

#[test]
fn success_path_verifies() {
    let (record, cert) = chain_fixture();

    verify_loaded_chain(&record, &cert).unwrap();
}

#[test]
fn household_id_mismatch_fails() {
    let (mut record, cert) = chain_fixture();
    record.hh_id = derive_household_id(&P256Keypair::generate().public());

    verify_loaded_chain(&record, &cert).unwrap_err();
}

#[test]
fn machine_id_mismatch_fails() {
    let (record, mut cert) = chain_fixture();
    cert.m_id = derive_machine_id(&P256Keypair::generate().public());

    verify_loaded_chain(&record, &cert).unwrap_err();
}

#[test]
fn signature_mismatch_fails() {
    let (record, mut cert) = chain_fixture();
    cert.signature.0[0] ^= 0x01;

    verify_loaded_chain(&record, &cert).unwrap_err();
}

#[test]
fn single_byte_cbor_tamper_on_household_record_fails_chain_verify() {
    let (record, cert) = chain_fixture();
    let mut encoded = cbor::to_canonical_vec(&record).unwrap();
    flip_first_embedded_byte(&mut encoded, record.hh_pub.as_bytes());
    let tampered: HouseholdRecord = cbor::from_canonical_slice(&encoded).unwrap();

    verify_loaded_chain(&tampered, &cert).unwrap_err();
}

#[test]
fn single_byte_cbor_tamper_on_machine_cert_fails_chain_verify() {
    let (record, cert) = chain_fixture();
    let mut encoded = cbor::to_canonical_vec(&cert).unwrap();
    flip_first_embedded_byte(&mut encoded, cert.signature.as_bytes());
    let tampered: MachineCert = cbor::from_canonical_slice(&encoded).unwrap();

    verify_loaded_chain(&record, &tampered).unwrap_err();
}
