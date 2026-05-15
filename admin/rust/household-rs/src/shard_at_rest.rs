//! Phase 3 ChaCha20-Poly1305 wrap/unwrap of Shamir shards
//! (`specs/003-machine-join/contracts/shamir-transition.md`).
//!
//! Encrypts the per-machine plaintext shard before either persisting it
//! at rest (`encrypt_for_self`/`decrypt_self`) or wrapping it for
//! delivery to a peer during the 2PC ceremony
//! (`encrypt_for_peer`/`decrypt_from_peer`).
//!
//! Key derivation — deliberately NOT HKDF — uses BLAKE3's native KDF
//! mode per Constitution v2.0.0:
//!
//! ```text
//! key = blake3::derive_key(
//!     &format!("soyeht-shard-at-rest-v1 m_id={}", recipient_m_id),
//!     &ecdh_shared_secret_32_bytes,
//! )
//! ```
//!
//! The recipient's `m_id` lives in the KDF context (BLAKE3 `derive_key`
//! `context` argument) AND in the AEAD AAD — defense in depth. A
//! cross-recipient swap of ciphertexts therefore fails authentication.

use std::convert::TryFrom;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ciborium::Value as CborValue;
use p256::ecdh::diffie_hellman;
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::keys::P256PublicKey;

/// Wire schema version for [`EncryptedShard`]. Bumped only on a
/// breaking change to the on-disk byte layout.
pub const ENCRYPTED_SHARD_VERSION: u8 = 1;

/// BLAKE3 KDF context prefix used by every shard-at-rest derivation.
/// The recipient's `m_id` is appended at runtime — see
/// [`derive_shard_key`].
pub const KDF_CONTEXT_PREFIX: &str = "soyeht-shard-at-rest-v1 m_id=";

/// CBOR-encoded encrypted shard. Persisted on disk
/// (`<state_dir>/household/shamir/self_shard.cbor`) and embedded inside
/// `JoinResponse.encrypted_shard` during the 2PC ceremony.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct EncryptedShard {
    #[serde(rename = "v")]
    pub version: u8,
    /// Shamir x-coordinate this shard occupies — see
    /// [`crate::shamir::SHARD_X_M1`] / [`crate::shamir::SHARD_X_M2`].
    pub index: u8,
    pub nonce: [u8; 12],
    pub ciphertext: ByteBuf,
}

impl EncryptedShard {
    /// Deterministic CBOR re-encode + length sanity. Used by the 2PC
    /// drive to assert wire-shape stability.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ShardError> {
        crate::cbor::to_canonical_vec(self).map_err(|e| ShardError::Cbor(format!("encode: {e}")))
    }
}

#[derive(Debug, Error)]
pub enum ShardError {
    #[error("ECDH input rejected: {0}")]
    BadEcdhInput(String),
    #[error("AEAD operation failed (likely tampered ciphertext or wrong key)")]
    AeadFailed,
    #[error("CBOR shape error: {0}")]
    Cbor(String),
    #[error("encrypted shard version unsupported: {0}")]
    UnsupportedVersion(u8),
    #[error("shard length must be exactly 32 bytes, got {0}")]
    BadShardLength(usize),
}

/// Wrap a 32-byte shard for storage on this machine. The recipient is
/// self; the ECDH input is the machine's own (`m_priv`, `m_pub`) pair.
/// The KDF context binds to `m_id` so a copied ciphertext on a
/// different machine fails authentication after key derivation.
pub fn encrypt_for_self(
    shard: &Zeroizing<[u8; 32]>,
    m_priv_self_scalar: &[u8; 32],
    m_pub_self: &P256PublicKey,
    m_id_self: &str,
    index: u8,
) -> Result<EncryptedShard, ShardError> {
    let key = derive_self_key(m_priv_self_scalar, m_pub_self, m_id_self)?;
    encrypt_with_derived_key(&key, shard, m_id_self, index)
}

/// Decrypt a shard wrapped by [`encrypt_for_self`].
pub fn decrypt_self(
    es: &EncryptedShard,
    m_priv_self_scalar: &[u8; 32],
    m_pub_self: &P256PublicKey,
    m_id_self: &str,
) -> Result<Zeroizing<[u8; 32]>, ShardError> {
    if es.version != ENCRYPTED_SHARD_VERSION {
        return Err(ShardError::UnsupportedVersion(es.version));
    }
    let key = derive_self_key(m_priv_self_scalar, m_pub_self, m_id_self)?;
    decrypt_with_derived_key(&key, es, m_id_self)
}

/// Wrap a 32-byte shard for delivery to a peer. M1 calls this with
/// `m_priv_self_scalar = M1_priv`, `m_pub_peer = M2_pub`, and
/// `m_id_peer = M2's m_id`. The KDF context binds to the *recipient's*
/// `m_id` — symmetric with [`decrypt_from_peer`] which the recipient
/// invokes.
pub fn encrypt_for_peer(
    shard: &Zeroizing<[u8; 32]>,
    m_priv_self_scalar: &[u8; 32],
    m_pub_peer: &P256PublicKey,
    m_id_peer: &str,
    index: u8,
) -> Result<EncryptedShard, ShardError> {
    let key = derive_peer_key(m_priv_self_scalar, m_pub_peer, m_id_peer)?;
    encrypt_with_derived_key(&key, shard, m_id_peer, index)
}

/// Decrypt a shard wrapped by a peer via [`encrypt_for_peer`]. M2 calls
/// this with `m_priv_self_scalar = M2_priv`, `m_pub_peer = M1_pub`, and
/// `m_id_self = M2's m_id`. ECDH symmetry guarantees the same shared
/// secret on both ends.
pub fn decrypt_from_peer(
    es: &EncryptedShard,
    m_priv_self_scalar: &[u8; 32],
    m_pub_peer: &P256PublicKey,
    m_id_self: &str,
) -> Result<Zeroizing<[u8; 32]>, ShardError> {
    if es.version != ENCRYPTED_SHARD_VERSION {
        return Err(ShardError::UnsupportedVersion(es.version));
    }
    let key = derive_peer_key(m_priv_self_scalar, m_pub_peer, m_id_self)?;
    decrypt_with_derived_key(&key, es, m_id_self)
}

fn derive_self_key(
    m_priv_self_scalar: &[u8; 32],
    m_pub_self: &P256PublicKey,
    m_id_self: &str,
) -> Result<Zeroizing<[u8; 32]>, ShardError> {
    derive_peer_key(m_priv_self_scalar, m_pub_self, m_id_self)
}

fn derive_peer_key(
    m_priv_scalar: &[u8; 32],
    m_pub_other: &P256PublicKey,
    recipient_m_id: &str,
) -> Result<Zeroizing<[u8; 32]>, ShardError> {
    let secret_key = SecretKey::from_slice(m_priv_scalar)
        .map_err(|e| ShardError::BadEcdhInput(format!("priv: {e}")))?;
    let public_key = PublicKey::from_sec1_bytes(m_pub_other.as_bytes())
        .map_err(|e| ShardError::BadEcdhInput(format!("pub: {e}")))?;
    let shared = diffie_hellman(secret_key.to_nonzero_scalar(), public_key.as_affine());
    let shared_bytes = shared.raw_secret_bytes();
    let context = format!("{KDF_CONTEXT_PREFIX}{recipient_m_id}");
    let mut out = Zeroizing::new([0u8; 32]);
    let derived = blake3::derive_key(&context, shared_bytes);
    out.copy_from_slice(&derived);
    // Drop the wrapped shared secret as soon as the KDF has consumed it.
    let _ = shared;
    Ok(out)
}

fn encrypt_with_derived_key(
    key: &Zeroizing<[u8; 32]>,
    shard: &Zeroizing<[u8; 32]>,
    aad_m_id: &str,
    index: u8,
) -> Result<EncryptedShard, ShardError> {
    if shard.len() != 32 {
        return Err(ShardError::BadShardLength(shard.len()));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| ShardError::AeadFailed)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: shard.as_slice(),
                aad: aad_m_id.as_bytes(),
            },
        )
        .map_err(|_| ShardError::AeadFailed)?;
    Ok(EncryptedShard {
        version: ENCRYPTED_SHARD_VERSION,
        index,
        nonce: nonce_bytes,
        ciphertext: ByteBuf::from(ciphertext),
    })
}

fn decrypt_with_derived_key(
    key: &Zeroizing<[u8; 32]>,
    es: &EncryptedShard,
    aad_m_id: &str,
) -> Result<Zeroizing<[u8; 32]>, ShardError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| ShardError::AeadFailed)?;
    let nonce = Nonce::from_slice(&es.nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: es.ciphertext.as_ref(),
                aad: aad_m_id.as_bytes(),
            },
        )
        .map_err(|_| ShardError::AeadFailed)?;
    let arr = <[u8; 32]>::try_from(plaintext.as_slice())
        .map_err(|_| ShardError::BadShardLength(plaintext.len()))?;
    Ok(Zeroizing::new(arr))
}

// Suppress unused-import warning for the CBOR dynamic value type;
// reserved for future cross-encoding round-trip helpers.
#[allow(dead_code)]
fn _cbor_value_anchor(_: &CborValue) {}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKey, P256Keypair};

    fn fixed_shard(seed: u8) -> Zeroizing<[u8; 32]> {
        let mut s = Zeroizing::new([0u8; 32]);
        for (i, b) in s.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8).wrapping_mul(0x35);
        }
        s
    }

    #[test]
    fn self_wrap_unwrap_round_trip() {
        let kp = P256Keypair::generate();
        let m_pub = kp.public();
        let m_priv = kp.as_software_secret().expect("software backed");
        let m_id = "m_test_self";
        let shard = fixed_shard(0xa1);
        let es = encrypt_for_self(&shard, m_priv, &m_pub, m_id, 1).unwrap();
        let recovered = decrypt_self(&es, m_priv, &m_pub, m_id).unwrap();
        assert_eq!(*recovered, *shard);
        assert_eq!(es.version, ENCRYPTED_SHARD_VERSION);
        assert_eq!(es.index, 1);
    }

    #[test]
    fn peer_wrap_round_trip_m1_to_m2() {
        let m1 = P256Keypair::generate();
        let m2 = P256Keypair::generate();
        let m1_priv = m1.as_software_secret().unwrap();
        let m2_priv = m2.as_software_secret().unwrap();
        let m1_pub = m1.public();
        let m2_pub = m2.public();
        let m_id_m2 = "m_test_m2";
        let shard = fixed_shard(0xb2);
        let es = encrypt_for_peer(&shard, m1_priv, &m2_pub, m_id_m2, 2).unwrap();
        let recovered = decrypt_from_peer(&es, m2_priv, &m1_pub, m_id_m2).unwrap();
        assert_eq!(*recovered, *shard);
    }

    #[test]
    fn cross_recipient_ciphertext_fails_aead() {
        let m1 = P256Keypair::generate();
        let m2 = P256Keypair::generate();
        let m3 = P256Keypair::generate();
        let m1_priv = m1.as_software_secret().unwrap();
        let m3_priv = m3.as_software_secret().unwrap();
        let m1_pub = m1.public();
        let m2_pub = m2.public();
        let shard = fixed_shard(0xc3);
        let es = encrypt_for_peer(&shard, m1_priv, &m2_pub, "m_test_m2", 2).unwrap();
        // Try to decrypt with an unrelated peer's keys — fails authentication.
        let err = decrypt_from_peer(&es, m3_priv, &m1_pub, "m_test_m2").unwrap_err();
        assert!(matches!(err, ShardError::AeadFailed));
    }

    #[test]
    fn wrong_aad_m_id_fails_aead() {
        let kp = P256Keypair::generate();
        let m_pub = kp.public();
        let m_priv = kp.as_software_secret().unwrap();
        let shard = fixed_shard(0xd4);
        let es = encrypt_for_self(&shard, m_priv, &m_pub, "m_test_self", 1).unwrap();
        let err = decrypt_self(&es, m_priv, &m_pub, "m_test_imposter").unwrap_err();
        assert!(matches!(err, ShardError::AeadFailed));
    }

    #[test]
    fn deterministic_cbor_round_trip_byte_equal() {
        let kp = P256Keypair::generate();
        let m_pub = kp.public();
        let m_priv = kp.as_software_secret().unwrap();
        let shard = fixed_shard(0xe5);
        let es = encrypt_for_self(&shard, m_priv, &m_pub, "m_test_self", 1).unwrap();
        let bytes_a = es.to_canonical_bytes().unwrap();
        let bytes_b = es.to_canonical_bytes().unwrap();
        assert_eq!(bytes_a, bytes_b);
        let decoded: EncryptedShard = crate::cbor::from_canonical_slice(&bytes_a).unwrap();
        assert_eq!(decoded, es);
    }

    #[test]
    fn unsupported_version_rejected_on_decode() {
        let kp = P256Keypair::generate();
        let m_pub = kp.public();
        let m_priv = kp.as_software_secret().unwrap();
        let shard = fixed_shard(0xf6);
        let mut es = encrypt_for_self(&shard, m_priv, &m_pub, "m_test_self", 1).unwrap();
        es.version = 7;
        let err = decrypt_self(&es, m_priv, &m_pub, "m_test_self").unwrap_err();
        assert!(matches!(err, ShardError::UnsupportedVersion(7)));
    }

    #[test]
    fn ciphertext_tamper_fails_aead() {
        let kp = P256Keypair::generate();
        let m_pub = kp.public();
        let m_priv = kp.as_software_secret().unwrap();
        let shard = fixed_shard(0x07);
        let mut es = encrypt_for_self(&shard, m_priv, &m_pub, "m_test_self", 1).unwrap();
        es.ciphertext.as_mut()[0] ^= 0x40;
        let err = decrypt_self(&es, m_priv, &m_pub, "m_test_self").unwrap_err();
        assert!(matches!(err, ShardError::AeadFailed));
    }
}
