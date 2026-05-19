//! T010 round-trip and tamper coverage for the Phase 3 Shamir 2-of-2
//! wrapper exposed by `household_rs::shamir`.

use household_rs::shamir::{SHARD_X_M1, SHARD_X_M2, ShamirError, reconstruct_from_2, split_2_of_2};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

#[test]
fn one_thousand_random_round_trips() {
    for _ in 0..1000 {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let secret = Zeroizing::new(buf);
        let [s1, s2] = split_2_of_2(&secret);
        let recon = reconstruct_from_2([(SHARD_X_M1, &s1), (SHARD_X_M2, &s2)]).unwrap();
        assert_eq!(*recon, *secret);
    }
}

#[test]
fn altered_share_yields_wrong_secret() {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let secret = Zeroizing::new(buf);
    let [mut s1, s2] = split_2_of_2(&secret);
    s1[5] ^= 0x80;
    let recon = reconstruct_from_2([(SHARD_X_M1, &s1), (SHARD_X_M2, &s2)]).unwrap();
    // Shamir is "non-magical" — tampering produces a wrong secret rather
    // than an error. Tamper detection lives at the AEAD layer in
    // `shard_at_rest`.
    assert_ne!(*recon, *secret);
}

#[test]
fn zero_index_rejected() {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let secret = Zeroizing::new(buf);
    let [s1, s2] = split_2_of_2(&secret);
    let err = reconstruct_from_2([(0, &s1), (SHARD_X_M2, &s2)]).unwrap_err();
    assert!(matches!(err, ShamirError::ShareIndexZero));
}

#[test]
fn duplicate_index_rejected() {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let secret = Zeroizing::new(buf);
    let [s1, _s2] = split_2_of_2(&secret);
    let err = reconstruct_from_2([(SHARD_X_M1, &s1), (SHARD_X_M1, &s1)]).unwrap_err();
    assert!(matches!(err, ShamirError::DuplicateShareIndex));
}

#[test]
fn shares_diverge_from_secret() {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let secret = Zeroizing::new(buf);
    let [s1, s2] = split_2_of_2(&secret);
    assert_ne!(*s1, *secret);
    assert_ne!(*s2, *secret);
    assert_ne!(*s1, *s2);
}
