//! P-256 identity keys (Constitution v2.0.0).
//!
//! Wire encoding contract:
//! - **Public key**: 33-byte SEC1 compressed form.
//! - **Signature**: 64-byte raw `r || s` ECDSA P-256 (NOT DER).
//!
//! Two backing implementations coexist behind the [`IdentityKey`] trait:
//!
//! | Backing | Where it runs | Where the private scalar lives |
//! |--------|---------------|--------------------------------|
//! | [`P256Keypair`] | Linux + tests | process memory (zeroized on Drop) |
//! | [`crate::keys_se::P256SeKeypair`] (macOS only) | macOS 14+ on SE-equipped hardware | inside the Secure Enclave |
//!
//! `THEYOS_FORCE_SOFTWARE_KEYS=1` overrides the macOS default to fall back to
//! `P256Keypair`. Production hardware MUST NOT set this flag.

use std::fmt;

use p256::{
    ecdsa::{
        Signature as EcdsaSignature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    elliptic_curve::sec1::FromEncodedPoint,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{HouseholdError, KeystoreError};

/// 33-byte SEC1-compressed P-256 public key.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct P256PublicKey(#[serde(with = "serde_bytes_33")] pub [u8; 33]);

/// 64-byte raw `r || s` ECDSA P-256 signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct P256Signature(#[serde(with = "serde_bytes_64")] pub [u8; 64]);

impl P256PublicKey {
    pub const LEN: usize = 33;

    /// Construct from raw bytes; verifies the SEC1 prefix tag (0x02 / 0x03)
    /// and that the encoded point is on-curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HouseholdError> {
        if bytes.len() != Self::LEN {
            return Err(HouseholdError::PublicKeyMalformed);
        }
        if bytes[0] != 0x02 && bytes[0] != 0x03 {
            return Err(HouseholdError::PublicKeyMalformed);
        }
        // Cheap on-curve check via p256 decoder.
        let encoded = p256::EncodedPoint::from_bytes(bytes)
            .map_err(|_| HouseholdError::PublicKeyMalformed)?;
        let _: p256::PublicKey = Option::from(p256::PublicKey::from_encoded_point(&encoded))
            .ok_or(HouseholdError::PublicKeyMalformed)?;
        let mut out = [0u8; Self::LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Convert to a `p256::ecdsa::VerifyingKey` for `verify` calls.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, HouseholdError> {
        VerifyingKey::from_sec1_bytes(&self.0).map_err(|_| HouseholdError::PublicKeyMalformed)
    }
}

impl fmt::Debug for P256PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print full pubkey as hex — it's public material; safe to log.
        write!(f, "P256PublicKey({})", hex::encode(self.0))
    }
}

impl P256Signature {
    pub const LEN: usize = 64;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HouseholdError> {
        if bytes.len() != Self::LEN {
            return Err(HouseholdError::SignatureMalformed);
        }
        let mut out = [0u8; Self::LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Convert to a `p256::ecdsa::Signature` for `verify` calls.
    ///
    /// `self.0` is `[u8; 64]` — structurally raw `r || s` per FR-013.
    /// `EcdsaSignature::try_from(&[u8])` is length-strict (no DER fallback);
    /// any deviation from 64 bytes returns `SignatureMalformed`.
    pub fn to_ecdsa(&self) -> Result<EcdsaSignature, HouseholdError> {
        EcdsaSignature::try_from(&self.0[..]).map_err(|_| HouseholdError::SignatureMalformed)
    }
}

impl fmt::Debug for P256Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "P256Signature({})", hex::encode(self.0))
    }
}

/// 32-byte ECDSA P-256 private scalar; zeroed on Drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct P256SecretScalar(pub [u8; 32]);

impl fmt::Debug for P256SecretScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the private scalar.
        f.debug_struct("P256SecretScalar")
            .field("len", &32)
            .finish()
    }
}

/// Polymorphic signing trait. Both software and SE-backed keypairs implement it.
pub trait IdentityKey: Send + Sync {
    fn public(&self) -> P256PublicKey;
    fn sign(&self, message: &[u8]) -> Result<P256Signature, KeystoreError>;
    /// Backing for the structured-log `backing` field
    /// (`secure_enclave` on macOS SE; `software` on Linux/CI fallback).
    fn backing(&self) -> &'static str;
    /// Returns the 32-byte private scalar **only** for software-backed keys.
    /// SE-backed keys MUST return `None`; the scalar never materializes outside
    /// the Secure Enclave on Apple hardware.
    fn as_software_secret(&self) -> Option<&[u8; 32]> {
        None
    }
}

/// Verify an ECDSA P-256 signature with a 33-byte SEC1 verifier key.
pub fn verify_signature(
    pubkey: &P256PublicKey,
    message: &[u8],
    signature: &P256Signature,
) -> Result<(), HouseholdError> {
    let vk = pubkey.to_verifying_key()?;
    let sig = signature.to_ecdsa()?;
    vk.verify(message, &sig)
        .map_err(|_| HouseholdError::SignatureMismatch)
}

/// Software-backed P-256 keypair. Used on Linux and in tests.
///
/// The pre-derived [`SigningKey`] is held alongside the raw secret scalar so
/// that `sign()` can avoid the non-constant-time `SigningKey::from_slice`
/// path (which performs `mod n` reduction and could leak scalar bits via a
/// timing side-channel under repeated signing). The raw scalar is retained
/// so the keystore wrapper can persist it for the Linux/file-fallback paths.
pub struct P256Keypair {
    public: P256PublicKey,
    secret: P256SecretScalar,
    signing_key: SigningKey,
}

// Explicitly NOT Clone — the secret should never be duplicated.

impl P256Keypair {
    /// Generate a fresh keypair using the OS RNG.
    #[must_use]
    pub fn generate() -> Self {
        let signing = SigningKey::random(&mut OsRng);
        Self::from_signing_key(signing)
    }

    /// Reconstruct from a previously-stored 32-byte private scalar
    /// (used by the keystore wrapper on Linux).
    pub fn from_secret_scalar(scalar: &[u8; 32]) -> Result<Self, KeystoreError> {
        let signing = SigningKey::from_slice(scalar)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("p256 from_slice: {e}")))?;
        Ok(Self::from_signing_key(signing))
    }

    fn from_signing_key(signing: SigningKey) -> Self {
        let verifying = signing.verifying_key();
        let pub_bytes = verifying.to_encoded_point(true).as_bytes().to_vec();
        debug_assert_eq!(pub_bytes.len(), 33);
        let mut pub_arr = [0u8; 33];
        pub_arr.copy_from_slice(&pub_bytes);
        let secret_bytes = signing.to_bytes();
        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(secret_bytes.as_slice());
        Self {
            public: P256PublicKey(pub_arr),
            secret: P256SecretScalar(secret_arr),
            signing_key: signing,
        }
    }
}

impl IdentityKey for P256Keypair {
    fn public(&self) -> P256PublicKey {
        self.public.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<P256Signature, KeystoreError> {
        // Use the pre-derived SigningKey to avoid the non-constant-time
        // `from_slice` path on every call.
        let sig: EcdsaSignature = self.signing_key.sign(message);
        let raw = sig.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(raw.as_slice());
        Ok(P256Signature(out))
    }

    fn backing(&self) -> &'static str {
        "software"
    }

    fn as_software_secret(&self) -> Option<&[u8; 32]> {
        Some(&self.secret.0)
    }
}

mod serde_bytes_33 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(bytes: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        let bytes: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        if bytes.len() != 33 {
            return Err(Error::custom(format!(
                "expected 33-byte SEC1 P-256 public key, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 33];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        if bytes.len() != 64 {
            return Err(Error::custom(format!(
                "expected 64-byte raw r||s ECDSA signature, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}
