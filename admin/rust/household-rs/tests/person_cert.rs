use household_rs::caveats::{Operation, permits};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::person_cert::{SignOwnerOptions, derive_person_id};
use household_rs::{PersonCert, derive_household_id};

fn signed_owner() -> (P256Keypair, P256Keypair, PersonCert) {
    let hh = P256Keypair::generate();
    let person = P256Keypair::generate();
    let hh_id = derive_household_id(&hh.public());
    let cert = PersonCert::sign_owner(
        &hh,
        SignOwnerOptions {
            hh_id,
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
    )
    .unwrap();
    (hh, person, cert)
}

#[test]
fn owner_person_cert_signs_and_verifies() {
    let (hh, person, cert) = signed_owner();
    cert.verify(
        &derive_household_id(&hh.public()),
        &hh.public(),
        cert.issued_at,
    )
    .unwrap();
    assert_eq!(cert.p_id, derive_person_id(&person.public()));
    assert!(permits(&cert.caveats, &Operation::HouseholdInvite));
    assert!(permits(&cert.caveats, &Operation::ClawsCreate));
    assert!(
        !permits(&cert.caveats, &Operation::OwnerAuthEnrollInitial),
        "old owner certificates remain valid without the dedicated enrollment operation"
    );
}

#[test]
fn owner_person_cert_without_owner_auth_enroll_initial_still_verifies() {
    let (hh, _person, cert) = signed_owner();
    assert!(
        !cert
            .caveats
            .iter()
            .any(|caveat| caveat.op == Operation::OwnerAuthEnrollInitial)
    );
    cert.verify(
        &derive_household_id(&hh.public()),
        &hh.public(),
        cert.issued_at,
    )
    .unwrap();
}

#[test]
fn tampered_cert_fails_verification() {
    let (hh, _person, mut cert) = signed_owner();
    cert.display_name = "Mallory".into();
    cert.verify(
        &derive_household_id(&hh.public()),
        &hh.public(),
        cert.issued_at,
    )
    .unwrap_err();
}

#[test]
fn wrong_household_key_fails_verification() {
    let (_hh, _person, cert) = signed_owner();
    let other = P256Keypair::generate();
    cert.verify(
        &derive_household_id(&other.public()),
        &other.public(),
        cert.issued_at,
    )
    .unwrap_err();
}

#[test]
fn first_owner_cert_has_no_device_cert_material() {
    let (_hh, _person, cert) = signed_owner();
    let encoded = household_rs::cbor::to_canonical_vec(&cert).unwrap();
    let decoded: ciborium::value::Value = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    let ciborium::value::Value::Map(entries) = decoded else {
        panic!("expected cbor map");
    };
    let keys: Vec<String> = entries
        .into_iter()
        .filter_map(|(key, _)| match key {
            ciborium::value::Value::Text(s) => Some(s),
            _ => None,
        })
        .collect();
    assert!(
        !keys
            .iter()
            .any(|k| k.contains("device") || k == "d_pub" || k == "d_id")
    );
}
