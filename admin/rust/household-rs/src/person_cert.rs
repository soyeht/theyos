//! First-owner `PersonCert` issuance and verification.

use rand::{RngCore, rngs::OsRng};
use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

use crate::caveats::{self, Caveat};
use crate::cbor;
use crate::error::{HouseholdError, KeystoreError};
use crate::ids::{HouseholdId, base32_lower_nopad_encode, hash_public_key};
use crate::keys::{IdentityKey, P256PublicKey, P256Signature, verify_signature};
use crate::machine_cert::{PersonId, SubjectId};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum OwnerAuthClaimValue {
    Null,
    Text(String),
    Unsigned(u64),
    Signed(i64),
    Bool(bool),
    Bytes(serde_bytes::ByteBuf),
    Array(Vec<OwnerAuthClaimValue>),
    Map(BTreeMap<String, OwnerAuthClaimValue>),
}

impl OwnerAuthClaimValue {
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }
}

fn deserialize_optional_owner_auth_claim<'de, D>(
    deserializer: D,
) -> Result<Option<OwnerAuthClaimValue>, D::Error>
where
    D: Deserializer<'de>,
{
    OwnerAuthClaimValue::deserialize(deserializer).map(Some)
}

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
    #[serde(
        default,
        deserialize_with = "deserialize_optional_owner_auth_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_auth_tier: Option<OwnerAuthClaimValue>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_owner_auth_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_provenance: Option<OwnerAuthClaimValue>,
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
    #[serde(
        default,
        deserialize_with = "deserialize_optional_owner_auth_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_auth_tier: Option<OwnerAuthClaimValue>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_owner_auth_claim",
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_provenance: Option<OwnerAuthClaimValue>,
}

pub struct SignOwnerOptions {
    pub hh_id: HouseholdId,
    pub p_pub: P256PublicKey,
    pub display_name: String,
    pub issued_at: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerifiedOwnerProvenance {
    IosSecureEnclaveOwner,
    IpadOsSecureEnclaveOwner,
    IosAppAttestOwner,
    IpadOsAppAttestOwner,
}

impl VerifiedOwnerProvenance {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IosSecureEnclaveOwner => PersonCert::OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER,
            Self::IpadOsSecureEnclaveOwner => {
                PersonCert::OWNER_PROVENANCE_IPADOS_SECURE_ENCLAVE_OWNER
            }
            Self::IosAppAttestOwner => PersonCert::OWNER_PROVENANCE_IOS_APP_ATTEST_OWNER,
            Self::IpadOsAppAttestOwner => PersonCert::OWNER_PROVENANCE_IPADOS_APP_ATTEST_OWNER,
        }
    }
}

impl PersonCert {
    pub const SCHEMA_VERSION: u8 = 1;
    pub const OWNER_AUTH_TIER_STRONG: &'static str = "strong";
    pub const OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER: &'static str = "ios-secure-enclave-owner";
    pub const OWNER_PROVENANCE_IPADOS_SECURE_ENCLAVE_OWNER: &'static str =
        "ipados-secure-enclave-owner";
    pub const OWNER_PROVENANCE_IOS_APP_ATTEST_OWNER: &'static str = "ios-app-attest-owner";
    pub const OWNER_PROVENANCE_IPADOS_APP_ATTEST_OWNER: &'static str = "ipados-app-attest-owner";

    pub fn sign_owner(
        hh_key: &dyn IdentityKey,
        opts: SignOwnerOptions,
    ) -> Result<Self, KeystoreError> {
        Self::sign_owner_internal(hh_key, opts, None, None)
    }

    pub fn sign_owner_with_verified_provenance(
        hh_key: &dyn IdentityKey,
        opts: SignOwnerOptions,
        owner_provenance: VerifiedOwnerProvenance,
    ) -> Result<Self, KeystoreError> {
        Self::sign_owner_internal(
            hh_key,
            opts,
            Some(OwnerAuthClaimValue::Text(
                Self::OWNER_AUTH_TIER_STRONG.to_string(),
            )),
            Some(OwnerAuthClaimValue::Text(
                owner_provenance.as_str().to_string(),
            )),
        )
    }

    fn sign_owner_internal(
        hh_key: &dyn IdentityKey,
        opts: SignOwnerOptions,
        owner_auth_tier: Option<OwnerAuthClaimValue>,
        owner_provenance: Option<OwnerAuthClaimValue>,
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
            owner_auth_tier,
            owner_provenance,
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
            owner_auth_tier: unsigned.owner_auth_tier,
            owner_provenance: unsigned.owner_provenance,
            signature,
        })
    }

    pub fn verify(
        &self,
        expected_hh_id: &HouseholdId,
        hh_pub: &P256PublicKey,
        now: u64,
    ) -> Result<(), HouseholdError> {
        self.verify_rooted_identity(expected_hh_id, hh_pub, now)?;
        for op in caveats::owner_caveats().iter().map(|c| c.op.clone()) {
            if !caveats::permits(&self.caveats, &op) {
                return Err(HouseholdError::InvalidCert(format!(
                    "owner caveat missing: {op}"
                )));
            }
        }
        Ok(())
    }

    /// Structural/identity/temporal + root signature verification WITHOUT caveats.
    /// Used by roster authority core which checks caveats separately.
    pub(crate) fn verify_rooted_identity(
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
            owner_auth_tier: self.owner_auth_tier.clone(),
            owner_provenance: self.owner_provenance.clone(),
        };
        cbor::to_canonical_vec(&unsigned)
    }

    #[must_use]
    pub fn has_strong_owner_provenance(&self) -> bool {
        self.owner_auth_tier_text() == Some(Self::OWNER_AUTH_TIER_STRONG)
            && matches!(
                self.owner_provenance_text(),
                Some(
                    Self::OWNER_PROVENANCE_IOS_SECURE_ENCLAVE_OWNER
                        | Self::OWNER_PROVENANCE_IPADOS_SECURE_ENCLAVE_OWNER
                        | Self::OWNER_PROVENANCE_IOS_APP_ATTEST_OWNER
                        | Self::OWNER_PROVENANCE_IPADOS_APP_ATTEST_OWNER
                )
            )
    }

    #[must_use]
    pub fn owner_auth_tier_text(&self) -> Option<&str> {
        self.owner_auth_tier
            .as_ref()
            .and_then(OwnerAuthClaimValue::as_text)
    }

    #[must_use]
    pub fn owner_provenance_text(&self) -> Option<&str> {
        self.owner_provenance
            .as_ref()
            .and_then(OwnerAuthClaimValue::as_text)
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
