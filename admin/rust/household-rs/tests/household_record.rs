use household_rs::{
    HouseholdRecord, IdentityKey, MachineId, P256Keypair, derive_household_id, derive_machine_id,
};

fn fresh_record() -> HouseholdRecord {
    let kp = P256Keypair::generate();
    let hh_pub = kp.public();
    let hh_id = derive_household_id(&hh_pub);

    let m_kp = P256Keypair::generate();
    let m_id: MachineId = derive_machine_id(&m_kp.public());

    HouseholdRecord {
        version: 1,
        hh_id,
        hh_pub,
        name: "Sample Home".into(),
        created_at: 1_714_972_800,
        shamir_k: 1,
        shamir_n: 1,
        members: vec![m_id],
        is_follower: false,
    }
}

#[test]
fn happy_path_validates() {
    fresh_record().validate().unwrap();
}

#[test]
fn name_too_long_rejected() {
    let mut r = fresh_record();
    r.name = "x".repeat(65);
    assert!(r.validate().is_err());
}

#[test]
fn name_empty_rejected() {
    let mut r = fresh_record();
    r.name = String::new();
    assert!(r.validate().is_err());
}

#[test]
fn version_mismatch_rejected() {
    let mut r = fresh_record();
    r.version = 2;
    assert!(r.validate().is_err());
}

#[test]
fn hh_id_mismatch_rejected() {
    let mut r = fresh_record();
    let other = derive_household_id(&P256Keypair::generate().public());
    r.hh_id = other;
    assert!(r.validate().is_err());
}

#[test]
fn phase3_2_of_2_validates() {
    // Post-Phase-3 record with two members and shamir_k=n=2 must validate.
    let mut r = fresh_record();
    r.shamir_k = 2;
    r.shamir_n = 2;
    let other_m_id = derive_machine_id(&P256Keypair::generate().public());
    r.members.push(other_m_id);
    r.validate().unwrap();
}

#[test]
fn members_len_must_match_n() {
    let mut r = fresh_record();
    r.shamir_n = 2;
    // members still has 1 entry — invariant violation.
    assert!(r.validate().is_err());
}

#[test]
fn k_greater_than_n_rejected() {
    let mut r = fresh_record();
    r.shamir_k = 2;
    r.shamir_n = 1;
    assert!(r.validate().is_err());
}

#[test]
fn duplicate_members_rejected() {
    let mut r = fresh_record();
    r.shamir_k = 2;
    r.shamir_n = 2;
    let dup = r.members[0].clone();
    r.members.push(dup);
    let err = r.validate().unwrap_err();
    assert!(format!("{err}").contains("duplicate"));
}

#[test]
fn follower_record_uses_zero_shamir_counts() {
    let mut r = fresh_record();
    r.is_follower = true;
    r.shamir_k = 0;
    r.shamir_n = 0;
    r.validate().unwrap();
    assert!(!r.has_local_household_private_key());
}
