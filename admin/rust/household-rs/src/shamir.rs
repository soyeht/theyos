//! Phase 3 Shamir 2-of-2 secret-sharing over GF(256), byte-wise.
//!
//! Implements `split_2_of_2` and `reconstruct_from_2` per
//! `specs/003-machine-join/contracts/shamir-transition.md`. The
//! 32-byte household private scalar is split into two 32-byte y-value
//! shares at fixed x-coordinates `1` and `2`. Both shares are required
//! for reconstruction (n=k=2). Future re-sharings (Phase 5+) raise `n`
//! while keeping `k` flexible; only the (2,2) form is implemented here.
//!
//! All plaintext material lives inside [`Zeroizing`] and is wiped on
//! drop. Share indices are not zeroized (they are public knowledge by
//! contract).

use rand::rngs::OsRng;
use rand::RngCore;
use vsss_rs::Gf256;
use zeroize::Zeroizing;

/// X-coordinates assigned to the two participants. Encoded into the
/// [`EncryptedShard`] CBOR layer (see `shard_at_rest::EncryptedShard`)
/// so reconstruction can pair the right share with the right x-value.
pub const SHARD_X_M1: u8 = 1;
pub const SHARD_X_M2: u8 = 2;

/// Errors observable while combining shares. Constructed only from
/// programmer-error preconditions; AEAD failures and authentication
/// belong to [`crate::shard_at_rest`].
#[derive(Debug, thiserror::Error)]
pub enum ShamirError {
    #[error("share x-coordinate is zero (the secret slot)")]
    ShareIndexZero,
    #[error("the two shares share the same x-coordinate")]
    DuplicateShareIndex,
}

/// Split a 32-byte secret into two byte-wise GF(256) Shamir shares at
/// `x=1` and `x=2`. Each output is a 32-byte y-vector aligned with the
/// `x` constant of its slot.
#[must_use]
pub fn split_2_of_2(secret: &Zeroizing<[u8; 32]>) -> [Zeroizing<[u8; 32]>; 2] {
    let mut share_1 = Zeroizing::new([0u8; 32]);
    let mut share_2 = Zeroizing::new([0u8; 32]);
    let mut a = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(a.as_mut_slice());
    for i in 0..32 {
        // Polynomial: f(x) = secret + a*x  (degree 1 → threshold 2).
        let s = Gf256(secret[i]);
        let a_i = Gf256(a[i]);
        let p1 = s + a_i * Gf256(SHARD_X_M1);
        let p2 = s + a_i * Gf256(SHARD_X_M2);
        share_1[i] = p1.0;
        share_2[i] = p2.0;
    }
    [share_1, share_2]
}

/// Reconstruct the 32-byte secret from two byte-wise GF(256) Shamir
/// shares evaluated at distinct, non-zero x-coordinates.
///
/// The caller MUST hold both shares (single-shard recovery is
/// impossible by construction at k=2). `x` indices are typed at the
/// wire level in [`crate::shard_at_rest::EncryptedShard::index`].
pub fn reconstruct_from_2(
    shares: [(u8, &[u8; 32]); 2],
) -> Result<Zeroizing<[u8; 32]>, ShamirError> {
    let (x1, y1) = shares[0];
    let (x2, y2) = shares[1];
    if x1 == 0 || x2 == 0 {
        return Err(ShamirError::ShareIndexZero);
    }
    if x1 == x2 {
        return Err(ShamirError::DuplicateShareIndex);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    let xa = Gf256(x1);
    let xb = Gf256(x2);
    // Lagrange interpolation at x=0:
    //   secret = y1 * x2/(x2 - x1)  +  y2 * x1/(x1 - x2)
    // In GF(256), subtract == XOR (additive inverse is self).
    let diff = xb - xa; // non-zero because x1 != x2
    for i in 0..32 {
        let ya = Gf256(y1[i]);
        let yb = Gf256(y2[i]);
        let l1 = xb / diff; // x2 / (x2 - x1)
        let l2 = xa / diff; // x1 / (x2 - x1) (since (x1 - x2) = -(x2 - x1) = (x2 - x1) in GF(2^8))
        let v = ya * l1 + yb * l2;
        out[i] = v.0;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn fixed_secret(seed: u8) -> Zeroizing<[u8; 32]> {
        let mut s = Zeroizing::new([0u8; 32]);
        for (i, b) in s.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8).wrapping_mul(0x9b);
        }
        s
    }

    #[test]
    fn round_trip_yields_secret() {
        let secret = fixed_secret(0xa5);
        let [s1, s2] = split_2_of_2(&secret);
        let recon = reconstruct_from_2([(SHARD_X_M1, &s1), (SHARD_X_M2, &s2)]).unwrap();
        assert_eq!(*recon, *secret);
    }

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
    fn shares_are_pairwise_unequal() {
        let secret = fixed_secret(0x11);
        let [s1, s2] = split_2_of_2(&secret);
        // With overwhelming probability the shares differ from each other and
        // from the secret. (a is uniform 32 bytes; the only way for s1==s2 is
        // a==0, which is one in 2^256.)
        assert_ne!(*s1, *s2);
        assert_ne!(*s1, *secret);
        assert_ne!(*s2, *secret);
    }

    #[test]
    fn altered_share_yields_wrong_secret() {
        let secret = fixed_secret(0x77);
        let [mut s1, s2] = split_2_of_2(&secret);
        s1[0] ^= 0x01;
        let recon = reconstruct_from_2([(SHARD_X_M1, &s1), (SHARD_X_M2, &s2)]).unwrap();
        // Reconstruction silently produces the wrong scalar — Shamir
        // is "non-magical": it does not detect tampering on its own. The
        // shard-at-rest AEAD layer (chacha20poly1305) is what catches
        // tampering before reconstruction is attempted.
        assert_ne!(*recon, *secret);
    }

    #[test]
    fn zero_index_is_rejected() {
        let secret = fixed_secret(0x42);
        let [s1, _] = split_2_of_2(&secret);
        let err = reconstruct_from_2([(0, &s1), (SHARD_X_M2, &s1)]).unwrap_err();
        assert!(matches!(err, ShamirError::ShareIndexZero));
    }

    #[test]
    fn duplicate_index_is_rejected() {
        let secret = fixed_secret(0x42);
        let [s1, _] = split_2_of_2(&secret);
        let err = reconstruct_from_2([(SHARD_X_M1, &s1), (SHARD_X_M1, &s1)]).unwrap_err();
        assert!(matches!(err, ShamirError::DuplicateShareIndex));
    }
}
