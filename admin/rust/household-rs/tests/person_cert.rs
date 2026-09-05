use household_rs::caveats::{Operation, permits};
use household_rs::keys::{IdentityKey, P256Keypair};
use household_rs::person_cert::{
    OwnerAuthClaimValue, SignOwnerOptions, VerifiedOwnerProvenance, derive_person_id,
};
use household_rs::{HouseholdAuthState, PersonCert, derive_household_id};

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

fn fixed_key(byte: u8) -> P256Keypair {
    P256Keypair::from_secret_scalar(&[byte; 32]).unwrap()
}

fn resign_cert(mut cert: PersonCert, hh: &P256Keypair) -> PersonCert {
    cert.signature = hh.sign(&cert.signing_bytes().unwrap()).unwrap();
    cert
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
fn legacy_owner_cert_is_tierless_weak_for_fanout() {
    let (hh, _person, cert) = signed_owner();
    assert_eq!(cert.owner_auth_tier, None);
    assert_eq!(cert.owner_provenance, None);
    assert!(!cert.has_strong_owner_provenance());

    let record = household_rs::HouseholdRecord {
        version: household_rs::HouseholdRecord::SCHEMA_VERSION,
        hh_id: derive_household_id(&hh.public()),
        hh_pub: hh.public(),
        name: "Test Home".to_string(),
        shamir_n: 1,
        shamir_k: 1,
        members: vec![household_rs::derive_machine_id(&hh.public())],
        created_at: cert.issued_at,
        is_follower: false,
    };
    let auth = HouseholdAuthState::new(&record, cert);
    assert!(!auth.owner_can_fan_out());
}

#[test]
fn strong_owner_cert_requires_verified_provenance() {
    let hh = fixed_key(0x11);
    let person = fixed_key(0x22);
    let hh_id = derive_household_id(&hh.public());
    let cert = PersonCert::sign_owner_with_verified_provenance(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
        VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();

    assert_eq!(
        cert.owner_auth_tier_text(),
        Some(PersonCert::OWNER_AUTH_TIER_STRONG)
    );
    assert_eq!(
        cert.owner_provenance_text(),
        Some(PersonCert::OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER)
    );
    assert!(cert.has_strong_owner_provenance());
    cert.verify(&hh_id, &hh.public(), cert.issued_at).unwrap();
}

#[test]
fn app_attest_owner_provenance_can_fan_out_when_signed() {
    let hh = fixed_key(0x41);
    let person = fixed_key(0x42);
    let hh_id = derive_household_id(&hh.public());
    let cert = PersonCert::sign_owner_with_verified_provenance(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
        VerifiedOwnerProvenance::IosAppAttestOwner,
    )
    .unwrap();
    cert.verify(&hh_id, &hh.public(), 1_714_972_800).unwrap();
    assert_eq!(
        cert.owner_auth_tier_text(),
        Some(PersonCert::OWNER_AUTH_TIER_STRONG)
    );
    assert_eq!(
        cert.owner_provenance_text(),
        Some(PersonCert::OWNER_PROVENANCE_IOS_APP_ATTEST_OWNER)
    );
    assert!(cert.has_strong_owner_provenance());
}

#[test]
fn unknown_owner_tier_is_signed_but_reads_weak() {
    let hh = fixed_key(0x12);
    let person = fixed_key(0x23);
    let hh_id = derive_household_id(&hh.public());
    let mut cert = PersonCert::sign_owner_with_verified_provenance(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
        VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    cert.owner_auth_tier = Some(OwnerAuthClaimValue::Text("future-strong".to_string()));
    cert = resign_cert(cert, &hh);

    cert.verify(&hh_id, &hh.public(), cert.issued_at).unwrap();
    assert!(!cert.has_strong_owner_provenance());
}

#[test]
fn malformed_owner_tier_decodes_as_weak_not_strong() {
    use ciborium::value::Value;

    let hh = fixed_key(0x13);
    let person = fixed_key(0x24);
    let hh_id = derive_household_id(&hh.public());
    let cert = PersonCert::sign_owner_with_verified_provenance(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
        VerifiedOwnerProvenance::IosSecureEnclaveOwner,
    )
    .unwrap();
    let encoded = household_rs::cbor::to_canonical_vec(&cert).unwrap();
    let mut value: Value = ciborium::de::from_reader(encoded.as_slice()).unwrap();
    let Value::Map(entries) = &mut value else {
        panic!("expected cert map");
    };
    for (key, value) in entries.iter_mut() {
        if matches!(key, Value::Text(text) if text == "owner_auth_tier") {
            *value = Value::Integer(7.into());
        }
    }
    let mut unsigned = value.clone();
    let Value::Map(unsigned_entries) = &mut unsigned else {
        panic!("expected unsigned cert map");
    };
    unsigned_entries.retain(|(key, _)| !matches!(key, Value::Text(text) if text == "signature"));
    let signing_bytes = household_rs::cbor::to_canonical_vec(&unsigned).unwrap();
    let signature = hh.sign(&signing_bytes).unwrap();
    let Value::Map(entries) = &mut value else {
        panic!("expected cert map");
    };
    for (key, value) in entries.iter_mut() {
        if matches!(key, Value::Text(text) if text == "signature") {
            *value = Value::Bytes(signature.as_bytes().to_vec());
        }
    }
    let bytes = household_rs::cbor::to_canonical_vec(&value).unwrap();
    let decoded: PersonCert = household_rs::cbor::from_canonical_slice(&bytes).unwrap();

    decoded
        .verify(&hh_id, &hh.public(), decoded.issued_at)
        .unwrap();
    assert!(matches!(
        decoded.owner_auth_tier,
        Some(OwnerAuthClaimValue::Unsigned(7))
    ));
    assert_eq!(decoded.owner_auth_tier_text(), None);
    assert_eq!(
        decoded.owner_provenance_text(),
        Some(PersonCert::OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER)
    );
    assert!(!decoded.has_strong_owner_provenance());
}

#[test]
fn null_owner_tier_decodes_as_weak_and_preserves_signature() {
    let hh = fixed_key(0x17);
    let person = fixed_key(0x28);
    let hh_id = derive_household_id(&hh.public());
    let mut cert = PersonCert::sign_owner(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
    )
    .unwrap();
    cert.owner_auth_tier = Some(OwnerAuthClaimValue::Null);
    cert.owner_provenance = Some(OwnerAuthClaimValue::Text(
        PersonCert::OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER.to_string(),
    ));
    cert = resign_cert(cert, &hh);
    let bytes = household_rs::cbor::to_canonical_vec(&cert).unwrap();
    let decoded: PersonCert = household_rs::cbor::from_canonical_slice(&bytes).unwrap();

    decoded
        .verify(&hh_id, &hh.public(), decoded.issued_at)
        .unwrap();
    assert!(matches!(
        decoded.owner_auth_tier,
        Some(OwnerAuthClaimValue::Null)
    ));
    assert_eq!(decoded.owner_auth_tier_text(), None);
    assert_eq!(
        decoded.owner_provenance_text(),
        Some(PersonCert::OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER)
    );
    assert!(!decoded.has_strong_owner_provenance());
}

#[test]
fn strong_tier_with_missing_provenance_reads_weak_not_invalid() {
    let hh = fixed_key(0x14);
    let person = fixed_key(0x25);
    let hh_id = derive_household_id(&hh.public());
    let mut cert = PersonCert::sign_owner(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
    )
    .unwrap();
    cert.owner_auth_tier = Some(OwnerAuthClaimValue::Text(
        PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
    ));
    cert = resign_cert(cert, &hh);

    cert.verify(&hh_id, &hh.public(), cert.issued_at).unwrap();
    assert_eq!(
        cert.owner_auth_tier_text(),
        Some(PersonCert::OWNER_AUTH_TIER_STRONG)
    );
    assert_eq!(cert.owner_provenance_text(), None);
    assert!(!cert.has_strong_owner_provenance());
}

#[test]
fn strong_tier_with_unknown_provenance_reads_weak_not_invalid() {
    let hh = fixed_key(0x15);
    let person = fixed_key(0x26);
    let hh_id = derive_household_id(&hh.public());
    let mut cert = PersonCert::sign_owner(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
    )
    .unwrap();
    cert.owner_auth_tier = Some(OwnerAuthClaimValue::Text(
        PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
    ));
    cert.owner_provenance = Some(OwnerAuthClaimValue::Text("future-provenance".to_string()));
    cert = resign_cert(cert, &hh);

    cert.verify(&hh_id, &hh.public(), cert.issued_at).unwrap();
    assert_eq!(
        cert.owner_auth_tier_text(),
        Some(PersonCert::OWNER_AUTH_TIER_STRONG)
    );
    assert_eq!(cert.owner_provenance_text(), Some("future-provenance"));
    assert!(!cert.has_strong_owner_provenance());
}

#[test]
fn strong_tier_with_malformed_provenance_reads_weak_not_invalid() {
    let hh = fixed_key(0x16);
    let person = fixed_key(0x27);
    let hh_id = derive_household_id(&hh.public());
    let mut cert = PersonCert::sign_owner(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
    )
    .unwrap();
    cert.owner_auth_tier = Some(OwnerAuthClaimValue::Text(
        PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
    ));
    cert.owner_provenance = Some(OwnerAuthClaimValue::Unsigned(7));
    cert = resign_cert(cert, &hh);

    cert.verify(&hh_id, &hh.public(), cert.issued_at).unwrap();
    assert_eq!(
        cert.owner_auth_tier_text(),
        Some(PersonCert::OWNER_AUTH_TIER_STRONG)
    );
    assert_eq!(cert.owner_provenance_text(), None);
    assert!(!cert.has_strong_owner_provenance());
}

#[test]
fn strong_tier_with_null_provenance_reads_weak_not_invalid() {
    let hh = fixed_key(0x18);
    let person = fixed_key(0x29);
    let hh_id = derive_household_id(&hh.public());
    let mut cert = PersonCert::sign_owner(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at: 1_714_972_800,
        },
    )
    .unwrap();
    cert.owner_auth_tier = Some(OwnerAuthClaimValue::Text(
        PersonCert::OWNER_AUTH_TIER_STRONG.to_string(),
    ));
    cert.owner_provenance = Some(OwnerAuthClaimValue::Null);
    cert = resign_cert(cert, &hh);
    let bytes = household_rs::cbor::to_canonical_vec(&cert).unwrap();
    let decoded: PersonCert = household_rs::cbor::from_canonical_slice(&bytes).unwrap();

    decoded
        .verify(&hh_id, &hh.public(), decoded.issued_at)
        .unwrap();
    assert_eq!(
        decoded.owner_auth_tier_text(),
        Some(PersonCert::OWNER_AUTH_TIER_STRONG)
    );
    assert!(matches!(
        decoded.owner_provenance,
        Some(OwnerAuthClaimValue::Null)
    ));
    assert_eq!(decoded.owner_provenance_text(), None);
    assert!(!decoded.has_strong_owner_provenance());
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

/// The intermittent `certInvalid` this test exists to close.
///
/// `not_before` is whole seconds and the phone checks `now >= not_before` with
/// no tolerance, so a certificate minted at `issued_at` was only acceptable to
/// a phone whose clock had already reached that same second. MEASURED on the
/// owner's Dev pair 2026-09-05, on a run that SUCCEEDED:
/// `notBefore=1788610348 issuedAt=1788610348 now=1788610348 skewMs=340` — 340 ms
/// of margin, out of a one-second budget, with a 191 ms round trip inside it.
/// A phone a few hundred milliseconds behind the Mac refused a certificate the
/// Mac had just minted for it.
#[test]
fn a_freshly_minted_owner_cert_is_accepted_by_a_phone_whose_clock_trails() {
    let hh = P256Keypair::generate();
    let person = P256Keypair::generate();
    let hh_id = derive_household_id(&hh.public());
    let issued_at = 1_788_610_348;
    let cert = PersonCert::sign_owner(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at,
        },
    )
    .unwrap();

    // One second behind — the shape the diagnostics captured.
    cert.verify(&hh_id, &hh.public(), issued_at - 1)
        .expect("a phone one second behind the Mac must still pair");
    // And the ordinary NTP allowance, which is what the constant buys.
    cert.verify(&hh_id, &hh.public(), issued_at - 60)
        .expect("sixty seconds of skew is the stated allowance");
}

/// The allowance is a floor, not a licence: a clock far enough behind is still
/// refused, so the certificate cannot be replayed to a machine whose clock has
/// been dragged backwards.
#[test]
fn a_clock_further_back_than_the_allowance_is_still_refused() {
    let hh = P256Keypair::generate();
    let person = P256Keypair::generate();
    let hh_id = derive_household_id(&hh.public());
    let issued_at = 1_788_610_348;
    let cert = PersonCert::sign_owner(
        &hh,
        SignOwnerOptions {
            hh_id: hh_id.clone(),
            p_pub: person.public(),
            display_name: "Owner".into(),
            issued_at,
        },
    )
    .unwrap();

    assert!(
        cert.verify(&hh_id, &hh.public(), issued_at - 61).is_err(),
        "a clock beyond the allowance must still read the cert as not yet valid"
    );
}

/// `not_before <= issued_at` is the invariant the verifier checks first. The
/// allowance must keep it true rather than trade one refusal for another.
#[test]
fn the_allowance_keeps_not_before_at_or_before_issued_at() {
    let hh = P256Keypair::generate();
    let person = P256Keypair::generate();
    let hh_id = derive_household_id(&hh.public());
    for issued_at in [0_u64, 1, 59, 60, 61, 1_788_610_348] {
        let cert = PersonCert::sign_owner(
            &hh,
            SignOwnerOptions {
                hh_id: hh_id.clone(),
                p_pub: person.public(),
                display_name: "Owner".into(),
                issued_at,
            },
        )
        .unwrap();
        assert!(
            cert.not_before <= cert.issued_at,
            "issued_at={issued_at} produced not_before={} above issued_at",
            cert.not_before
        );
        // A clock near the epoch must not wrap into the far future.
        assert!(cert.not_before <= issued_at);
    }
}
