//! macOS Secure Enclave-resident P-256 keypair (`P256SeKeypair`).
//!
//! The private scalar is created by Security.framework with
//! `kSecAttrTokenIDSecureEnclave`; signing is delegated to `SecKey`.

use p256::elliptic_curve::sec1::ToEncodedPoint;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};

use crate::error::KeystoreError;
use crate::keys::{IdentityKey, P256PublicKey, P256Signature};

pub struct P256SeKeypair {
    label: String,
    sec_key_ref: SecKey,
    public: P256PublicKey,
}

impl std::fmt::Debug for P256SeKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P256SeKeypair")
            .field("label", &self.label)
            .field("public", &self.public)
            .field("key_handle", &"<secure-enclave>")
            .finish_non_exhaustive()
    }
}

impl P256SeKeypair {
    pub fn create(label: &str, for_subject_signing: bool) -> Result<Self, KeystoreError> {
        let access_control = access_control(for_subject_signing)?;
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_label(label)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DefaultFileKeychain)
            .set_access_control(access_control);

        let sec_key_ref = SecKey::generate(opts.to_dictionary())
            .map_err(|e| map_create_error(e.code(), &e.to_string()))?;
        Self::from_sec_key(label.to_string(), sec_key_ref)
    }

    pub fn load(label: &str) -> Result<Self, KeystoreError> {
        let results = ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(label)
            .load_refs(true)
            .search()
            .map_err(|e| KeystoreError::Io {
                kind: format!("{e:?}"),
                hint: "Check that theyos can read its Secure Enclave key from the Keychain.".into(),
            })?;
        let sec_key_ref = results
            .into_iter()
            .find_map(|item| match item {
                SearchResult::Ref(Reference::Key(key)) => Some(key),
                _ => None,
            })
            .ok_or_else(|| KeystoreError::NotFound {
                label: label.to_string(),
            })?;
        Self::from_sec_key(label.to_string(), sec_key_ref)
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Destroy the SE-resident key. After this call the Keychain entry under
    /// `self.label` is gone; signing returns `NotFound` and `load(label)`
    /// fails. Used by the Phase 3 Shamir transition (`CeremonyTxn::commit`)
    /// to wipe `HH_priv` once the household has grown to N≥2.
    pub fn destroy(self) -> Result<(), KeystoreError> {
        self.sec_key_ref.delete().map_err(|e| KeystoreError::Io {
            kind: format!("{e:?}"),
            hint: format!("Failed to remove {} from Keychain: {e}", self.label),
        })
    }

    fn from_sec_key(label: String, sec_key_ref: SecKey) -> Result<Self, KeystoreError> {
        let public = public_from_sec_key(&sec_key_ref)?;
        Ok(Self {
            label,
            sec_key_ref,
            public,
        })
    }
}

/// Idempotent destruction of an SE-resident key by Keychain label. Returns
/// `Ok(())` when the entry is already absent — the post-condition is "the
/// SE entry is gone", not "we deleted it ourselves".
pub fn destroy_by_label(label: &str) -> Result<(), KeystoreError> {
    match P256SeKeypair::load(label) {
        Ok(kp) => kp.destroy(),
        Err(KeystoreError::NotFound { .. }) => Ok(()),
        Err(e) => Err(e),
    }
}

impl IdentityKey for P256SeKeypair {
    fn public(&self) -> P256PublicKey {
        self.public.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<P256Signature, KeystoreError> {
        let der = self
            .sec_key_ref
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|e| map_sign_error(e.code(), &e.to_string()))?;
        let raw = der_to_raw_rs(&der).map_err(KeystoreError::SigningFailed)?;
        Ok(P256Signature(raw))
    }

    fn backing(&self) -> &'static str {
        "secure_enclave"
    }
}

fn access_control(for_subject_signing: bool) -> Result<SecAccessControl, KeystoreError> {
    let mut flags = kSecAccessControlPrivateKeyUsage;
    if for_subject_signing {
        flags |= kSecAccessControlBiometryCurrentSet;
    }
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        flags,
    )
    .map_err(|e| KeystoreError::Io {
        kind: format!("{e:?}"),
        hint: "Check that this Mac has Keychain access enabled for theyos.".into(),
    })
}

fn public_from_sec_key(sec_key: &SecKey) -> Result<P256PublicKey, KeystoreError> {
    let public_key = sec_key.public_key().ok_or_else(|| {
        KeystoreError::InvalidKeyMaterial("Secure Enclave key has no public key".into())
    })?;
    let raw = public_key.external_representation().ok_or_else(|| {
        KeystoreError::InvalidKeyMaterial("Secure Enclave public key export failed".into())
    })?;
    let public = p256::PublicKey::from_sec1_bytes(raw.bytes()).map_err(|e| {
        KeystoreError::InvalidKeyMaterial(format!("SEC1 public key from SecKey: {e}"))
    })?;
    let compressed = public.to_encoded_point(true);
    P256PublicKey::from_bytes(compressed.as_bytes())
        .map_err(|e| KeystoreError::InvalidKeyMaterial(format!("compressed SEC1 public key: {e}")))
}

fn map_create_error(code: isize, message: &str) -> KeystoreError {
    KeystoreError::SeUnavailable {
        hint: format!(
            "Secure Enclave is unavailable on this Mac. Bootstrap requires Apple Silicon or a T2-equipped Mac with a working Secure Enclave. Security.framework returned code {code}: {message}"
        ),
    }
}

fn map_sign_error(code: isize, message: &str) -> KeystoreError {
    let lower = message.to_lowercase();
    if lower.contains("denied")
        || lower.contains("not allowed")
        || lower.contains("cancel")
        || lower.contains("authorization")
    {
        return KeystoreError::PermissionDenied {
            hint: crate::keystore::MACOS_KEYCHAIN_DENIED_HINT.into(),
        };
    }
    KeystoreError::SigningFailed(format!(
        "Secure Enclave sign failed with code {code}: {message}",
    ))
}

pub(crate) fn der_to_raw_rs(der: &[u8]) -> Result<[u8; 64], String> {
    use ecdsa::der::Signature as DerSig;
    use p256::NistP256;
    let parsed: DerSig<NistP256> =
        DerSig::try_from(der).map_err(|e| format!("ecdsa DER parse: {e}"))?;
    let raw_sig: ecdsa::Signature<NistP256> = parsed
        .try_into()
        .map_err(|e| format!("ecdsa DER to fixed: {e}"))?;
    let raw = raw_sig.to_bytes();
    if raw.len() != 64 {
        return Err(format!("expected 64 raw bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(raw.as_slice());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_expose_scalar_wording() {
        let text = format!(
            "{:?}",
            P256SeKeypair {
                label: "x".into(),
                sec_key_ref: SecKey::generate(
                    GenerateKeyOptions::default()
                        .set_key_type(KeyType::ec())
                        .set_size_in_bits(256)
                        .to_dictionary(),
                )
                .expect("software sec key for debug smoke"),
                public: crate::keys::P256Keypair::generate().public(),
            }
        );
        assert!(text.contains("<secure-enclave>"));
        assert!(!text.contains("scalar"));
    }
}
