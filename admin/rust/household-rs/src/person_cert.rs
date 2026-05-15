//! First-owner `PersonCert` issuance and verification.

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::caveats::{self, Caveat};
use crate::cbor;
use crate::error::{HouseholdError, KeystoreError};
use crate::ids::{HouseholdId, base32_lower_nopad_encode, hash_public_key};
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};
use crate::machine_cert::{PersonId, SubjectId};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct PersonCert {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "type")]
    pub cert_type: String,
    pub hh_id: HouseholdId,
    pub p_id: PersonId,
    pub p_pub: P256PublicKey,
    pub display_name: String,
    pub caveats: Vec<Caveat>,
    pub not_before: u64,
    pub not_after: Option<u64>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub issued_at: u64,
    pub issued_by: SubjectId,
    pub signature: P256Signature,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
struct PersonCertUnsigned {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "type")]
    pub cert_type: String,
    pub hh_id: HouseholdId,
    pub p_id: PersonId,
    pub p_pub: P256PublicKey,
    pub display_name: String,
    pub caveats: Vec<Caveat>,
    pub not_before: u64,
    pub not_after: Option<u64>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    pub issued_at: u64,
    pub issued_by: SubjectId,
}

pub struct SignOwnerOptions {
    pub hh_id: HouseholdId,
    pub p_pub: P256PublicKey,
    pub display_name: String,
    pub issued_at: u64,
}

impl PersonCert {
    pub const SCHEMA_VERSION: u8 = 1;

    pub fn sign_owner(
        hh_key: &dyn IdentityKey,
        opts: SignOwnerOptions,
    ) -> Result<Self, KeystoreError> {
        validate_display_name(&opts.display_name)
            .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("display_name: {e}")))?;
        let p_id = derive_person_id(&opts.p_pub);
        let mut nonce = vec![0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let unsigned = PersonCertUnsigned {
            version: Self::SCHEMA_VERSION,
            cert_type: "person".to_string(),
            hh_id: opts.hh_id.clone(),
            p_id: p_id.clone(),
            p_pub: opts.p_pub,
            display_name: opts.display_name,
            caveats: caveats::owner_caveats(),
            not_before: opts.issued_at,
            not_after: None,
            nonce,
            issued_at: opts.issued_at,
            issued_by: SubjectId::Household(opts.hh_id),
        };
        let canonical = cbor::to_canonical_vec(&unsigned)
            .map_err(|e| KeystoreError::SigningFailed(format!("encode person cert: {e}")))?;
        let signature = hh_key.sign(&canonical)?;
        Ok(Self {
            version: unsigned.version,
            cert_type: unsigned.cert_type,
            hh_id: unsigned.hh_id,
            p_id: unsigned.p_id,
            p_pub: unsigned.p_pub,
            display_name: unsigned.display_name,
            caveats: unsigned.caveats,
            not_before: unsigned.not_before,
            not_after: unsigned.not_after,
            nonce: unsigned.nonce,
            issued_at: unsigned.issued_at,
            issued_by: unsigned.issued_by,
            signature,
        })
    }

    pub fn verify(
        &self,
        expected_hh_id: &HouseholdId,
        hh_pub: &P256PublicKey,
        now: u64,
    ) -> Result<(), HouseholdError> {
        if self.version != Self::SCHEMA_VERSION {
            return Err(HouseholdError::InvalidCert(format!(
                "version {} unsupported",
                self.version
            )));
        }
        if self.cert_type != "person" {
            return Err(HouseholdError::InvalidCert(format!(
                "expected person cert, got {:?}",
                self.cert_type
            )));
        }
        if &self.hh_id != expected_hh_id {
            return Err(HouseholdError::IdentifierMismatch {
                expected: expected_hh_id.to_string(),
                actual: self.hh_id.to_string(),
            });
        }
        P256PublicKey::from_bytes(self.p_pub.as_bytes())?;
        let recomputed = derive_person_id(&self.p_pub);
        if recomputed != self.p_id {
            return Err(HouseholdError::IdentifierMismatch {
                expected: recomputed.0,
                actual: self.p_id.0.clone(),
            });
        }
        validate_display_name(&self.display_name)?;
        match &self.issued_by {
            SubjectId::Household(h) if h == expected_hh_id => {}
            other => {
                return Err(HouseholdError::InvalidCert(format!(
                    "issued_by must be Household({expected_hh_id}); got {}",
                    other.as_str()
                )));
            }
        }
        if self.nonce.len() != 16 {
            return Err(HouseholdError::InvalidCert(format!(
                "person cert nonce must be 16 bytes, got {}",
                self.nonce.len()
            )));
        }
        if self.not_before > self.issued_at {
            return Err(HouseholdError::InvalidCert(
                "not_before must be <= issued_at".into(),
            ));
        }
        if now < self.not_before {
            return Err(HouseholdError::InvalidCert(
                "person cert not yet valid".into(),
            ));
        }
        if self.not_after.is_some_and(|expires| now >= expires) {
            return Err(HouseholdError::InvalidCert("person cert expired".into()));
        }
        for op in caveats::owner_caveats().iter().map(|c| c.op.clone()) {
            if !caveats::permits(&self.caveats, &op) {
                return Err(HouseholdError::InvalidCert(format!(
                    "owner caveat missing: {op}"
                )));
            }
        }
        verify_signature(hh_pub, &self.signing_bytes()?, &self.signature)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, HouseholdError> {
        let unsigned = PersonCertUnsigned {
            version: self.version,
            cert_type: self.cert_type.clone(),
            hh_id: self.hh_id.clone(),
            p_id: self.p_id.clone(),
            p_pub: self.p_pub.clone(),
            display_name: self.display_name.clone(),
            caveats: self.caveats.clone(),
            not_before: self.not_before,
            not_after: self.not_after,
            nonce: self.nonce.clone(),
            issued_at: self.issued_at,
            issued_by: self.issued_by.clone(),
        };
        cbor::to_canonical_vec(&unsigned)
    }
}

#[must_use]
pub fn derive_person_id(p_pub: &P256PublicKey) -> PersonId {
    let h = hash_public_key(p_pub.as_bytes());
    PersonId(format!("p_{}", base32_lower_nopad_encode(&h)))
}

pub fn validate_display_name(name: &str) -> Result<(), HouseholdError> {
    if name.is_empty() {
        return Err(HouseholdError::InvalidCert(
            "display name must be non-empty".into(),
        ));
    }
    if name.len() > 64 {
        return Err(HouseholdError::InvalidCert(format!(
            "display name must be <= 64 UTF-8 bytes (got {})",
            name.len()
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(HouseholdError::InvalidCert(
            "display name contains control character".into(),
        ));
    }
    Ok(())
}
