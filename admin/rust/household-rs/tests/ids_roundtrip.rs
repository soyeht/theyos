use household_rs::HouseholdId;
use household_rs::ids::{base32_lower_nopad_decode, base32_lower_nopad_encode};

#[test]
fn hh_id_well_formed() {
    let s = format!("hh_{}", "a".repeat(52));
    assert!(HouseholdId::is_well_formed(&s));
    assert!(HouseholdId::parse(&s).is_ok());
}

#[test]
fn hh_id_rejects_bad_prefix() {
    assert!(!HouseholdId::is_well_formed("xx_aaaa"));
    assert!(HouseholdId::parse(format!("xx_{}", "a".repeat(52))).is_err());
}

#[test]
fn hh_id_rejects_bad_length() {
    assert!(!HouseholdId::is_well_formed("hh_aaa"));
}

#[test]
fn hh_id_rejects_bad_char() {
    let s = format!("hh_{}{}", "a".repeat(51), "1");
    assert!(!HouseholdId::is_well_formed(&s));
}

#[test]
fn base32_round_trip() {
    let bytes: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).expect("i < 32"));
    let s = base32_lower_nopad_encode(&bytes);
    assert_eq!(s.len(), 52);
    let back = base32_lower_nopad_decode(&s).unwrap();
    assert_eq!(back, bytes);
}
