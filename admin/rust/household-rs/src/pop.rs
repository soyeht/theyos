//! Soyeht proof-of-possession signed payloads.

use serde::{Deserialize, Serialize};

use crate::cbor;
use crate::error::HouseholdError;
use crate::ids::HouseholdId;
use crate::keys::{P256PublicKey, P256Signature, verify_signature};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(transparent)]
pub struct Bytes32(#[serde(with = "serde_bytes_32")] pub [u8; 32]);

/// Canonical CBOR signed by the first owner app during pair confirm.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct PairingProofContext {
    #[serde(rename = "v")]
    pub version: u8,
    pub purpose: String,
    pub hh_id: HouseholdId,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub p_pub: P256PublicKey,
}

impl PairingProofContext {
    pub const PURPOSE: &'static str = "pair-device-confirm";

    #[must_use]
    pub fn new(hh_id: HouseholdId, nonce: [u8; 32], p_pub: P256PublicKey) -> Self {
        Self {
            version: 1,
            purpose: Self::PURPOSE.to_string(),
            hh_id,
            nonce: nonce.to_vec(),
            p_pub,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        if self.version != 1 || self.purpose != Self::PURPOSE || self.nonce.len() != 32 {
            return Err(HouseholdError::InvalidRecord(
                "invalid pairing proof context".into(),
            ));
        }
        cbor::to_canonical_vec(self)
    }

    pub fn verify(&self, signature: &P256Signature) -> Result<(), HouseholdError> {
        verify_signature(&self.p_pub, &self.canonical_bytes()?, signature)
    }
}

/// Canonical CBOR signed for household-scoped requests.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct RequestSigningContext {
    #[serde(rename = "v")]
    pub version: u8,
    pub method: String,
    pub path_and_query: String,
    pub timestamp: u64,
    pub body_hash: Bytes32,
}

impl RequestSigningContext {
    #[must_use]
    pub fn new(
        method: impl AsRef<str>,
        path_and_query: impl Into<String>,
        timestamp: u64,
        body: &[u8],
    ) -> Self {
        let method = method.as_ref().to_ascii_uppercase();
        let body_hash = Bytes32(*blake3::hash(body).as_bytes());
        Self {
            version: 1,
            method,
            path_and_query: path_and_query.into(),
            timestamp,
            body_hash,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        if self.version != 1 || self.method.is_empty() || self.path_and_query.is_empty() {
            return Err(HouseholdError::InvalidRecord(
                "invalid request signing context".into(),
            ));
        }
        cbor::to_canonical_vec(self)
    }

    pub fn verify(
        &self,
        public_key: &P256PublicKey,
        signature: &P256Signature,
    ) -> Result<(), HouseholdError> {
        verify_signature(public_key, &self.canonical_bytes()?, signature)
    }
}

mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let bytes: serde_bytes::ByteBuf = Deserialize::deserialize(d)?;
        if bytes.len() != 32 {
            return Err(Error::custom(format!(
                "expected 32-byte hash, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}
