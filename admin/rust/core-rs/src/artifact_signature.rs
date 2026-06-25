//! Detached signature verification for Claw Store artifact manifests.
//!
//! This module is deliberately pure: callers provide the exact `latest.json`
//! bytes, detached signature bytes, and public-key pins. It does not fetch
//! registry objects, does not parse artifact manifests, and does not contain
//! production key material.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use p256::ecdsa::{
    Signature, VerifyingKey,
    signature::{Error as SignatureError, Verifier},
};
use serde::{Deserialize, Serialize};

pub const ARTIFACT_SIGNATURE_SCHEMA_VERSION: u32 = 1;
pub const ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW: &str = "p256_ecdsa_sha256_raw";
pub const ARTIFACT_SIGNATURE_DOMAIN: &[u8] = b"theyos-claw-artifact-manifest-v1\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSignatureEnvelope {
    pub schema_version: u32,
    pub alg: String,
    pub key_id: String,
    pub signature_b64url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSignatureKey {
    pub key_id: String,
    pub alg: String,
    pub public_key_sec1_compressed: Vec<u8>,
}

impl ArtifactSignatureKey {
    #[must_use]
    pub fn new(
        key_id: impl Into<String>,
        alg: impl Into<String>,
        public_key_sec1_compressed: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            alg: alg.into(),
            public_key_sec1_compressed: public_key_sec1_compressed.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactSignatureError {
    #[error("artifact signature is required")]
    MissingSignature,
    #[error("signature JSON is invalid: {0}")]
    SignatureJson(String),
    #[error("unsupported signature schema_version {0}")]
    UnsupportedSchemaVersion(u32),
    #[error("unsupported artifact signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("unknown artifact signature key_id: {0}")]
    UnknownKeyId(String),
    #[error(
        "artifact signature key algorithm mismatch for {key_id}: signature={signature_alg}, key={key_alg}"
    )]
    KeyAlgorithmMismatch {
        key_id: String,
        signature_alg: String,
        key_alg: String,
    },
    #[error("artifact signature public key is malformed")]
    MalformedPublicKey,
    #[error("artifact signature base64url is invalid: {0}")]
    InvalidSignatureBase64(String),
    #[error("artifact signature bytes are malformed")]
    MalformedSignature,
    #[error("artifact signature mismatch")]
    SignatureMismatch,
}

pub fn verify_required_latest_json_signature(
    latest_json_bytes: &[u8],
    signature_json_bytes: Option<&[u8]>,
    keys: &[ArtifactSignatureKey],
) -> Result<(), ArtifactSignatureError> {
    let signature_json_bytes =
        signature_json_bytes.ok_or(ArtifactSignatureError::MissingSignature)?;
    verify_latest_json_signature(latest_json_bytes, signature_json_bytes, keys)
}

pub fn verify_latest_json_signature(
    latest_json_bytes: &[u8],
    signature_json_bytes: &[u8],
    keys: &[ArtifactSignatureKey],
) -> Result<(), ArtifactSignatureError> {
    let envelope: ArtifactSignatureEnvelope = serde_json::from_slice(signature_json_bytes)
        .map_err(|err| ArtifactSignatureError::SignatureJson(err.to_string()))?;

    verify_envelope(latest_json_bytes, &envelope, keys)
}

pub fn verify_envelope(
    latest_json_bytes: &[u8],
    envelope: &ArtifactSignatureEnvelope,
    keys: &[ArtifactSignatureKey],
) -> Result<(), ArtifactSignatureError> {
    if envelope.schema_version != ARTIFACT_SIGNATURE_SCHEMA_VERSION {
        return Err(ArtifactSignatureError::UnsupportedSchemaVersion(
            envelope.schema_version,
        ));
    }

    if envelope.alg != ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW {
        return Err(ArtifactSignatureError::UnsupportedAlgorithm(
            envelope.alg.clone(),
        ));
    }

    let key = keys
        .iter()
        .find(|key| key.key_id == envelope.key_id)
        .ok_or_else(|| ArtifactSignatureError::UnknownKeyId(envelope.key_id.clone()))?;

    if key.alg != envelope.alg {
        return Err(ArtifactSignatureError::KeyAlgorithmMismatch {
            key_id: envelope.key_id.clone(),
            signature_alg: envelope.alg.clone(),
            key_alg: key.alg.clone(),
        });
    }

    let verifying_key = VerifyingKey::from_sec1_bytes(&key.public_key_sec1_compressed)
        .map_err(|_| ArtifactSignatureError::MalformedPublicKey)?;

    let signature_bytes = B64URL
        .decode(envelope.signature_b64url.as_bytes())
        .map_err(|err| ArtifactSignatureError::InvalidSignatureBase64(err.to_string()))?;

    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| ArtifactSignatureError::MalformedSignature)?;

    verifying_key
        .verify(&signature_payload(latest_json_bytes), &signature)
        .map_err(signature_mismatch)
}

#[must_use]
pub fn signature_payload(latest_json_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ARTIFACT_SIGNATURE_DOMAIN.len() + latest_json_bytes.len());
    payload.extend_from_slice(ARTIFACT_SIGNATURE_DOMAIN);
    payload.extend_from_slice(latest_json_bytes);
    payload
}

fn signature_mismatch(_: SignatureError) -> ArtifactSignatureError {
    ArtifactSignatureError::SignatureMismatch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_registry::ArtifactManifest;
    use p256::ecdsa::{SigningKey, signature::Signer};

    const TEST_KEY_ID: &str = "test-p256-2026-06";
    const LATEST_JSON_PRETTY: &[u8] = br#"{
  "manifest_version": 1,
  "claw": "picoclaw",
  "version": "0.1.0"
}
"#;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).expect("fixed test scalar is valid")
    }

    fn test_key_pin() -> ArtifactSignatureKey {
        let public = test_signing_key()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        ArtifactSignatureKey::new(
            TEST_KEY_ID,
            ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW,
            public,
        )
    }

    fn sign_with_domain(latest_json_bytes: &[u8], domain: &[u8]) -> ArtifactSignatureEnvelope {
        let mut payload = Vec::with_capacity(domain.len() + latest_json_bytes.len());
        payload.extend_from_slice(domain);
        payload.extend_from_slice(latest_json_bytes);
        sign_payload(&payload)
    }

    fn sign_payload(payload: &[u8]) -> ArtifactSignatureEnvelope {
        let signature: Signature = test_signing_key().sign(payload);
        ArtifactSignatureEnvelope {
            schema_version: ARTIFACT_SIGNATURE_SCHEMA_VERSION,
            alg: ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW.to_string(),
            key_id: TEST_KEY_ID.to_string(),
            signature_b64url: B64URL.encode(signature.to_bytes()),
        }
    }

    fn signature_json(envelope: &ArtifactSignatureEnvelope) -> Vec<u8> {
        serde_json::to_vec(envelope).expect("signature json")
    }

    #[test]
    fn valid_signature_passes() {
        let envelope = sign_with_domain(LATEST_JSON_PRETTY, ARTIFACT_SIGNATURE_DOMAIN);
        verify_latest_json_signature(
            LATEST_JSON_PRETTY,
            &signature_json(&envelope),
            &[test_key_pin()],
        )
        .expect("valid signature verifies");
    }

    #[test]
    fn tampered_latest_json_byte_fails() {
        let envelope = sign_with_domain(LATEST_JSON_PRETTY, ARTIFACT_SIGNATURE_DOMAIN);
        let mut tampered = LATEST_JSON_PRETTY.to_vec();
        let claw = tampered
            .windows("picoclaw".len())
            .position(|window| window == b"picoclaw")
            .expect("fixture contains claw");
        tampered[claw] = b'P';

        assert_eq!(
            verify_latest_json_signature(&tampered, &signature_json(&envelope), &[test_key_pin()])
                .unwrap_err(),
            ArtifactSignatureError::SignatureMismatch
        );
    }

    #[test]
    fn unknown_key_fails() {
        let envelope = sign_with_domain(LATEST_JSON_PRETTY, ARTIFACT_SIGNATURE_DOMAIN);

        assert_eq!(
            verify_latest_json_signature(LATEST_JSON_PRETTY, &signature_json(&envelope), &[])
                .unwrap_err(),
            ArtifactSignatureError::UnknownKeyId(TEST_KEY_ID.to_string())
        );
    }

    #[test]
    fn missing_signature_required_mode_fails() {
        assert_eq!(
            verify_required_latest_json_signature(LATEST_JSON_PRETTY, None, &[test_key_pin()])
                .unwrap_err(),
            ArtifactSignatureError::MissingSignature
        );
    }

    #[test]
    fn wrong_domain_fails() {
        let envelope = sign_with_domain(LATEST_JSON_PRETTY, b"theyos-claw-artifact-manifest-v2\n");

        assert_eq!(
            verify_latest_json_signature(
                LATEST_JSON_PRETTY,
                &signature_json(&envelope),
                &[test_key_pin()]
            )
            .unwrap_err(),
            ArtifactSignatureError::SignatureMismatch
        );
    }

    #[test]
    fn parse_reserialize_minified_json_fails_because_exact_bytes_are_signed() {
        let envelope = sign_with_domain(LATEST_JSON_PRETTY, ARTIFACT_SIGNATURE_DOMAIN);
        let value: serde_json::Value =
            serde_json::from_slice(LATEST_JSON_PRETTY).expect("fixture parses");
        let minified = serde_json::to_vec(&value).expect("minified json");
        assert_ne!(LATEST_JSON_PRETTY, minified.as_slice());

        assert_eq!(
            verify_latest_json_signature(&minified, &signature_json(&envelope), &[test_key_pin()])
                .unwrap_err(),
            ArtifactSignatureError::SignatureMismatch
        );
    }

    #[test]
    fn unsupported_schema_and_algorithm_fail() {
        let mut envelope = sign_with_domain(LATEST_JSON_PRETTY, ARTIFACT_SIGNATURE_DOMAIN);
        envelope.schema_version = 2;
        assert_eq!(
            verify_latest_json_signature(
                LATEST_JSON_PRETTY,
                &signature_json(&envelope),
                &[test_key_pin()]
            )
            .unwrap_err(),
            ArtifactSignatureError::UnsupportedSchemaVersion(2)
        );

        let mut envelope = sign_with_domain(LATEST_JSON_PRETTY, ARTIFACT_SIGNATURE_DOMAIN);
        envelope.alg = "ed25519".to_string();
        assert_eq!(
            verify_latest_json_signature(
                LATEST_JSON_PRETTY,
                &signature_json(&envelope),
                &[test_key_pin()]
            )
            .unwrap_err(),
            ArtifactSignatureError::UnsupportedAlgorithm("ed25519".to_string())
        );
    }

    #[test]
    fn invalid_base64url_fails() {
        let mut envelope = sign_with_domain(LATEST_JSON_PRETTY, ARTIFACT_SIGNATURE_DOMAIN);
        envelope.signature_b64url = "not valid base64url!".to_string();

        assert!(matches!(
            verify_latest_json_signature(
                LATEST_JSON_PRETTY,
                &signature_json(&envelope),
                &[test_key_pin()]
            )
            .unwrap_err(),
            ArtifactSignatureError::InvalidSignatureBase64(_)
        ));
    }

    #[test]
    fn authenticated_bytes_are_not_parsed_by_the_verifier() {
        let invalid_json = br#"{"manifest_version":"#;
        let envelope = sign_with_domain(invalid_json, ARTIFACT_SIGNATURE_DOMAIN);

        verify_latest_json_signature(invalid_json, &signature_json(&envelope), &[test_key_pin()])
            .expect("verifier authenticates exact bytes only");
        assert!(serde_json::from_slice::<ArtifactManifest>(invalid_json).is_err());
    }

    #[test]
    fn key_algorithm_mismatch_fails() {
        let envelope = sign_with_domain(LATEST_JSON_PRETTY, ARTIFACT_SIGNATURE_DOMAIN);
        let mut key = test_key_pin();
        key.alg = "other".to_string();

        assert_eq!(
            verify_latest_json_signature(LATEST_JSON_PRETTY, &signature_json(&envelope), &[key])
                .unwrap_err(),
            ArtifactSignatureError::KeyAlgorithmMismatch {
                key_id: TEST_KEY_ID.to_string(),
                signature_alg: ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW.to_string(),
                key_alg: "other".to_string(),
            }
        );
    }
}
