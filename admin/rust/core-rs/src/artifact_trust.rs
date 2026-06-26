//! Runtime keyring + trust policy for Claw Store artifact-manifest signatures.
//!
//! The pure verifier in [`crate::artifact_signature`] takes a flat slice of
//! candidate keys and authenticates the exact `latest.json` bytes. This module
//! adds the operational policy decided for P0.1:
//!
//! * a pinned keyring with a `current` key, an optional rotation `next` key, and
//!   a revocation denylist of `key_id`s;
//! * a trust mode that says whether a signature is REQUIRED (production / remote
//!   sources hard-fail without one) or OPTIONAL when absent (the caller's
//!   explicit decision for dev / loopback).
//!
//! It holds NO production key material - the caller pins the real `key_id`s and
//! public keys. It does not fetch signatures, parse artifact manifests, or wire
//! the resolver; those are later P0.1 slices.

use crate::artifact_signature::{
    verify_envelope, ArtifactSignatureEnvelope, ArtifactSignatureError, ArtifactSignatureKey,
    ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW,
};

/// Whether an artifact-manifest signature is mandatory for the source being
/// resolved. Production / remote artifacts use [`ArtifactTrustMode::Required`]
/// and hard-fail without a valid signature; dev / loopback may use
/// [`ArtifactTrustMode::OptionalIfAbsent`] - an explicit caller decision. This
/// slice provides the type only; choosing the mode per source is the resolver's
/// job (a later slice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactTrustMode {
    /// A valid signature from a non-revoked pinned key is required; a missing
    /// signature is an error.
    Required,
    /// A present signature is fully verified; an absent signature is allowed.
    OptionalIfAbsent,
}

/// A trust failure: either a revoked `key_id` was used, or the underlying
/// signature verification failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactTrustError {
    /// The signature's `key_id` is on the revocation denylist. Rejected before
    /// verification, so a still-cryptographically-valid signature from a revoked
    /// key never passes.
    #[error("artifact signature key_id is revoked: {0}")]
    RevokedKeyId(String),
    /// The underlying verifier rejected the signature (unknown key, algorithm
    /// mismatch, signature mismatch, malformed input, or a missing required
    /// signature).
    #[error(transparent)]
    Signature(#[from] ArtifactSignatureError),
}

/// A pinned keyring: the active `current` signing key, an optional rotation
/// `next` key, and a revocation denylist. Supplied by the caller; this type
/// embeds no production keys.
#[derive(Debug, Clone, Default)]
pub struct ArtifactSignatureKeyring {
    current: Option<ArtifactSignatureKey>,
    next: Option<ArtifactSignatureKey>,
    revoked_key_ids: Vec<String>,
}

impl ArtifactSignatureKeyring {
    /// An empty keyring (no keys, no revocations).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `current` (active) signing key.
    #[must_use]
    pub fn with_current(mut self, key: ArtifactSignatureKey) -> Self {
        self.current = Some(key);
        self
    }

    /// Set the `next` (rotation successor) key.
    #[must_use]
    pub fn with_next(mut self, key: ArtifactSignatureKey) -> Self {
        self.next = Some(key);
        self
    }

    /// Add a `key_id` to the revocation denylist.
    #[must_use]
    pub fn revoke(mut self, key_id: impl Into<String>) -> Self {
        self.revoked_key_ids.push(key_id.into());
        self
    }

    /// Whether `key_id` is on the revocation denylist.
    #[must_use]
    pub fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked_key_ids.iter().any(|id| id == key_id)
    }

    /// The keys handed to the verifier: `current` then `next`, with any revoked
    /// `key_id` removed. Deterministic order.
    #[must_use]
    pub fn accepted_keys(&self) -> Vec<ArtifactSignatureKey> {
        [self.current.as_ref(), self.next.as_ref()]
            .into_iter()
            .flatten()
            .filter(|key| !self.is_revoked(&key.key_id))
            .cloned()
            .collect()
    }

    /// Verify `latest.json` bytes against this keyring under `mode`.
    ///
    /// * `Required` + no signature -> [`ArtifactSignatureError::MissingSignature`].
    /// * `OptionalIfAbsent` + no signature -> `Ok(())`.
    /// * a present signature is always parsed and verified: a revoked `key_id`
    ///   is rejected up front ([`ArtifactTrustError::RevokedKeyId`]) even if the
    ///   signature would otherwise verify; an unknown `key_id` or algorithm
    ///   mismatch flows from the verifier.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactTrustError`] on any trust or verification failure.
    pub fn verify_latest_json(
        &self,
        mode: ArtifactTrustMode,
        latest_json_bytes: &[u8],
        signature_json_bytes: Option<&[u8]>,
    ) -> Result<(), ArtifactTrustError> {
        match signature_json_bytes {
            None => match mode {
                ArtifactTrustMode::Required => Err(ArtifactSignatureError::MissingSignature.into()),
                ArtifactTrustMode::OptionalIfAbsent => Ok(()),
            },
            Some(signature_json_bytes) => {
                self.verify_present_signature(latest_json_bytes, signature_json_bytes)
            }
        }
    }

    /// Parse the signature envelope, reject a revoked `key_id` up front, then
    /// delegate to the verifier over the accepted (non-revoked) keys.
    fn verify_present_signature(
        &self,
        latest_json_bytes: &[u8],
        signature_json_bytes: &[u8],
    ) -> Result<(), ArtifactTrustError> {
        let envelope: ArtifactSignatureEnvelope = serde_json::from_slice(signature_json_bytes)
            .map_err(|err| ArtifactSignatureError::SignatureJson(err.to_string()))?;
        if self.is_revoked(&envelope.key_id) {
            return Err(ArtifactTrustError::RevokedKeyId(envelope.key_id));
        }
        verify_envelope(latest_json_bytes, &envelope, &self.accepted_keys()).map_err(Into::into)
    }
}

/// The pinned production artifact-signing key identifier, baked into the client
/// so it can verify manifests signed by the release key. See
/// `docs/artifact-signing-runbook.md`.
pub const PRODUCTION_ARTIFACT_KEY_ID: &str = "artifact-prod-p256-2026q2";

/// SEC1-compressed P-256 public key (33 bytes) for [`PRODUCTION_ARTIFACT_KEY_ID`].
///
/// This is a PUBLIC key - it is not secret. The matching private key lives only
/// on the release / builder machine and never appears in this repo. Verified
/// 2026-06-25 by an `openssl pkeyutl` round-trip against that private key; the
/// base64 form is `A+5hT7nQ+uckDKxwl8ym9kfxWcS+0A7tOG+0MDbAoWU/`.
const PRODUCTION_ARTIFACT_PUBLIC_KEY_SEC1: [u8; 33] = [
    0x03, 0xee, 0x61, 0x4f, 0xb9, 0xd0, 0xfa, 0xe7, 0x24, 0x0c, 0xac, 0x70, 0x97, 0xcc, 0xa6, 0xf6,
    0x47, 0xf1, 0x59, 0xc4, 0xbe, 0xd0, 0x0e, 0xed, 0x38, 0x6f, 0xb4, 0x30, 0x36, 0xc0, 0xa1, 0x65,
    0x3f,
];

/// The production artifact-signature keyring: the pinned release key as
/// `current`, with no rotation successor and no revocations yet.
///
/// This builds the trusted-key set only. It does NOT by itself enable
/// enforcement - the resolver still configures no trust in production until the
/// activation slice wires it in. Holds only the public key; no private material.
#[must_use]
pub fn production_keyring() -> ArtifactSignatureKeyring {
    ArtifactSignatureKeyring::new().with_current(ArtifactSignatureKey::new(
        PRODUCTION_ARTIFACT_KEY_ID,
        ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW,
        PRODUCTION_ARTIFACT_PUBLIC_KEY_SEC1.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_signature::{
        signature_payload, ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW,
        ARTIFACT_SIGNATURE_SCHEMA_VERSION,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    const LATEST_JSON: &[u8] = br#"{"manifest_version":1,"claw":"picoclaw","version":"0.1.0"}"#;
    const CURRENT_ID: &str = "current-p256-2026-06";
    const NEXT_ID: &str = "next-p256-2026-12";
    const OTHER_ID: &str = "rotated-out-2025";

    fn signing_key(scalar: u8) -> SigningKey {
        SigningKey::from_slice(&[scalar; 32]).expect("valid test scalar")
    }

    fn pin(key_id: &str, scalar: u8, alg: &str) -> ArtifactSignatureKey {
        let public = signing_key(scalar)
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        ArtifactSignatureKey::new(key_id, alg, public)
    }

    fn sign(key_id: &str, scalar: u8, latest_json_bytes: &[u8]) -> Vec<u8> {
        let signature: Signature = signing_key(scalar).sign(&signature_payload(latest_json_bytes));
        let envelope = ArtifactSignatureEnvelope {
            schema_version: ARTIFACT_SIGNATURE_SCHEMA_VERSION,
            alg: ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW.to_string(),
            key_id: key_id.to_string(),
            signature_b64url: B64URL.encode(signature.to_bytes()),
        };
        serde_json::to_vec(&envelope).expect("signature json")
    }

    fn keyring() -> ArtifactSignatureKeyring {
        ArtifactSignatureKeyring::new()
            .with_current(pin(
                CURRENT_ID,
                7,
                ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW,
            ))
            .with_next(pin(
                NEXT_ID,
                9,
                ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW,
            ))
    }

    #[test]
    fn current_key_signature_is_accepted() {
        let sig = sign(CURRENT_ID, 7, LATEST_JSON);
        keyring()
            .verify_latest_json(ArtifactTrustMode::Required, LATEST_JSON, Some(&sig))
            .expect("current key accepted");
    }

    #[test]
    fn next_key_signature_is_accepted() {
        let sig = sign(NEXT_ID, 9, LATEST_JSON);
        keyring()
            .verify_latest_json(ArtifactTrustMode::Required, LATEST_JSON, Some(&sig))
            .expect("next key accepted");
    }

    #[test]
    fn unknown_key_is_rejected() {
        let sig = sign(OTHER_ID, 11, LATEST_JSON);
        assert_eq!(
            keyring()
                .verify_latest_json(ArtifactTrustMode::Required, LATEST_JSON, Some(&sig))
                .unwrap_err(),
            ArtifactTrustError::Signature(ArtifactSignatureError::UnknownKeyId(
                OTHER_ID.to_string()
            ))
        );
    }

    #[test]
    fn revoked_key_is_rejected_even_with_valid_signature() {
        // A cryptographically valid signature from the current key, whose key_id
        // is on the denylist, must be rejected as revoked - not accepted.
        let sig = sign(CURRENT_ID, 7, LATEST_JSON);
        assert_eq!(
            keyring()
                .revoke(CURRENT_ID)
                .verify_latest_json(ArtifactTrustMode::Required, LATEST_JSON, Some(&sig))
                .unwrap_err(),
            ArtifactTrustError::RevokedKeyId(CURRENT_ID.to_string())
        );
        // The same signature verifies when the key is not revoked.
        keyring()
            .verify_latest_json(ArtifactTrustMode::Required, LATEST_JSON, Some(&sig))
            .expect("same signature verifies when not revoked");
    }

    #[test]
    fn algorithm_mismatch_is_rejected() {
        // The pinned key claims a different alg than the signature envelope.
        let sig = sign(CURRENT_ID, 7, LATEST_JSON);
        let keyring =
            ArtifactSignatureKeyring::new().with_current(pin(CURRENT_ID, 7, "p256_ecdsa_other"));
        assert_eq!(
            keyring
                .verify_latest_json(ArtifactTrustMode::Required, LATEST_JSON, Some(&sig))
                .unwrap_err(),
            ArtifactTrustError::Signature(ArtifactSignatureError::KeyAlgorithmMismatch {
                key_id: CURRENT_ID.to_string(),
                signature_alg: ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW.to_string(),
                key_alg: "p256_ecdsa_other".to_string(),
            })
        );
    }

    #[test]
    fn required_mode_rejects_missing_signature() {
        assert_eq!(
            keyring()
                .verify_latest_json(ArtifactTrustMode::Required, LATEST_JSON, None)
                .unwrap_err(),
            ArtifactTrustError::Signature(ArtifactSignatureError::MissingSignature)
        );
    }

    #[test]
    fn optional_mode_allows_missing_but_still_verifies_present() {
        // Absent signature is allowed in optional mode.
        keyring()
            .verify_latest_json(ArtifactTrustMode::OptionalIfAbsent, LATEST_JSON, None)
            .expect("absent signature allowed in optional mode");
        // A present-but-tampered signature still fails, even in optional mode.
        let sig = sign(CURRENT_ID, 7, LATEST_JSON);
        let mut tampered = LATEST_JSON.to_vec();
        tampered[0] = b' ';
        assert_eq!(
            keyring()
                .verify_latest_json(ArtifactTrustMode::OptionalIfAbsent, &tampered, Some(&sig))
                .unwrap_err(),
            ArtifactTrustError::Signature(ArtifactSignatureError::SignatureMismatch)
        );
    }

    #[test]
    fn accepted_keys_excludes_revoked() {
        let keyring = keyring().revoke(NEXT_ID);
        let accepted = keyring.accepted_keys();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].key_id, CURRENT_ID);
        assert!(keyring.is_revoked(NEXT_ID));
        assert!(!keyring.is_revoked(CURRENT_ID));
    }

    // P0.1-F1: the pinned production keyring (real public key, no activation).

    #[test]
    fn production_keyring_pins_exactly_the_expected_key() {
        let accepted = production_keyring().accepted_keys();
        assert_eq!(accepted.len(), 1, "only the current production key");
        let key = &accepted[0];
        assert_eq!(key.key_id, PRODUCTION_ARTIFACT_KEY_ID);
        assert_eq!(key.key_id, "artifact-prod-p256-2026q2");
        assert_eq!(key.alg, ARTIFACT_SIGNATURE_ALG_P256_ECDSA_SHA256_RAW);
        assert_eq!(
            key.public_key_sec1_compressed.as_slice(),
            &PRODUCTION_ARTIFACT_PUBLIC_KEY_SEC1
        );
        assert_eq!(key.public_key_sec1_compressed.len(), 33);
    }

    #[test]
    fn production_public_key_is_a_valid_p256_point() {
        // Auditability: a transcription typo in the pinned bytes fails here, not
        // silently at verify time.
        assert_eq!(PRODUCTION_ARTIFACT_PUBLIC_KEY_SEC1[0] & 0xfe, 0x02);
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&PRODUCTION_ARTIFACT_PUBLIC_KEY_SEC1)
            .expect("pinned production key is a valid SEC1-compressed P-256 point");
    }

    #[test]
    fn production_keyring_rejects_unknown_key_id() {
        // A signature whose key_id is not the pinned one is rejected.
        let sig = sign("rogue-key-2025", 7, LATEST_JSON);
        assert_eq!(
            production_keyring()
                .verify_latest_json(ArtifactTrustMode::Required, LATEST_JSON, Some(&sig))
                .unwrap_err(),
            ArtifactTrustError::Signature(ArtifactSignatureError::UnknownKeyId(
                "rogue-key-2025".to_string()
            ))
        );
    }

    #[test]
    fn production_keyring_rejects_revoked_production_key_id() {
        // Revoking the pinned key_id rejects it up front, before signature checks.
        let sig = sign(PRODUCTION_ARTIFACT_KEY_ID, 7, LATEST_JSON);
        assert_eq!(
            production_keyring()
                .revoke(PRODUCTION_ARTIFACT_KEY_ID)
                .verify_latest_json(ArtifactTrustMode::Required, LATEST_JSON, Some(&sig))
                .unwrap_err(),
            ArtifactTrustError::RevokedKeyId(PRODUCTION_ARTIFACT_KEY_ID.to_string())
        );
    }

    #[test]
    fn production_keyring_rejects_unsupported_algorithm() {
        // An envelope claiming the production key_id but an unsupported alg fails.
        let envelope = ArtifactSignatureEnvelope {
            schema_version: ARTIFACT_SIGNATURE_SCHEMA_VERSION,
            alg: "ed25519".to_string(),
            key_id: PRODUCTION_ARTIFACT_KEY_ID.to_string(),
            signature_b64url: B64URL.encode([0u8; 64]),
        };
        let sig = serde_json::to_vec(&envelope).expect("signature json");
        assert_eq!(
            production_keyring()
                .verify_latest_json(ArtifactTrustMode::Required, LATEST_JSON, Some(&sig))
                .unwrap_err(),
            ArtifactTrustError::Signature(ArtifactSignatureError::UnsupportedAlgorithm(
                "ed25519".to_string()
            ))
        );
    }
}
