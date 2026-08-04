//! `MeshSessionDelegation` schema, policy, and partial binding (Fila 1 item
//! 3a, `daisy-bsessao-implementable-queue-post-d4.452cdaf2…` + erratum
//! `0107bd2…`).
//!
//! Scope is deliberately narrower than the full B-SESSAO v6 §5 binding
//! requirement: only the two triple-equality members that do not require a
//! live roster (`proof.hh_id == local.hh_id == delegation.hh_id` and
//! `proof.self_m_id == delegation.delegator_m_id`, plus the matching
//! fingerprint pair) are checked here. The third member of each triple
//! (`roster.m_id` / roster fingerprint) is item 3b, blocked on D-1's
//! `current_snapshot()` — this crate does not implement it and must not be
//! extended to.
//!
//! **Signature (decided 2026-08-04, @kiana): no preimage formula is frozen
//! here.** v6 §5 line 282 fixes only that `sig` is M_priv, user-present;
//! the `signed_preimage = type_byte || canonical_cbor(unsigned_body)`
//! formula in §3 is explicitly scoped to the outer K_mesh-signed frames,
//! not restated for the delegation sub-map. This module therefore does
//! *not* implement `sign`/`verify` and does not expose any function that
//! claims a specific preimage. `sig` is carried and shape-checked (64
//! bytes) as an opaque wire field only. The only signature-shaped surface
//! is [`DelegationSignatureVerifier`], a trait with no implementation in
//! this crate — verifying a real delegation requires an implementation
//! injected from wherever the preimage decision eventually lands, and
//! nothing here accepts a bare P-256 key as a substitute.

use serde::{Deserialize, Serialize};

use crate::cbor;
use crate::error::DelegationError;

pub const DELEGATION_KIND: &str = "soyeht/mesh-session/delegation/v1";
pub const DELEGATION_DOMAIN: &str = "soyeht/mesh-session/v1";

/// B-SESSAO v6 §5 schema. Every `bstr .size N` field is carried as a
/// length-checked `Vec<u8>` (serde_bytes gives the CBOR-level bstr
/// encoding; `validate_shape` enforces the exact size the schema comment
/// declares, since CBOR itself has no fixed-length byte-string type).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeshSessionDelegation {
    pub version: u64,
    pub kind: String,
    pub domain: String,
    pub hh_id: String,
    pub delegator_m_id: String,
    #[serde(with = "serde_bytes")]
    pub delegator_cert_fingerprint: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub delegated_pub: Vec<u8>,
    pub delegated_key_id: String,
    pub profile: String,
    pub transcript_kinds: Vec<String>,
    pub roles: Vec<String>,
    pub channel: String,
    pub serial: u64,
    pub not_before: u64,
    pub not_after: u64,
    /// Opaque wire field — M_priv, user-present (v6 §5 line 282). Only its
    /// size is validated here; no function in this crate computes or
    /// checks what it signs. See [`DelegationSignatureVerifier`].
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl MeshSessionDelegation {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DelegationError> {
        cbor::to_canonical_vec(self).map_err(|_| DelegationError::NonCanonical)
    }

    /// Decode + reject anything that is not exactly the closed canonical
    /// encoding, then enforce the fixed-size `bstr` fields the CBOR schema
    /// comments declare but CBOR itself cannot express.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DelegationError> {
        let d: Self =
            cbor::from_canonical_bytes(bytes).map_err(|_| DelegationError::NonCanonical)?;
        d.validate_shape()?;
        Ok(d)
    }

    fn validate_shape(&self) -> Result<(), DelegationError> {
        if self.delegator_cert_fingerprint.len() != 32
            || self.delegated_pub.len() != 33
            || self.sig.len() != 64
        {
            return Err(DelegationError::NonCanonical);
        }
        Ok(())
    }

    /// Verify `sig` via an injected [`DelegationSignatureVerifier`]. This
    /// crate ships no implementation of that trait — call sites must bring
    /// their own once the preimage decision lands. There is deliberately
    /// no method here that takes a raw `p256::ecdsa::VerifyingKey` (or any
    /// other bare key type, e.g. a generic K_mesh key) as a substitute; a
    /// bare `VerifyingKey` does not implement `DelegationSignatureVerifier`,
    /// so passing one does not compile:
    ///
    /// ```compile_fail
    /// use mesh_session_core_rs::delegation::{MeshSessionDelegation, DELEGATION_KIND, DELEGATION_DOMAIN};
    /// use p256::ecdsa::{SigningKey, VerifyingKey};
    /// use rand_core::OsRng;
    ///
    /// let d = MeshSessionDelegation {
    ///     version: 1,
    ///     kind: DELEGATION_KIND.to_string(),
    ///     domain: DELEGATION_DOMAIN.to_string(),
    ///     hh_id: "hh-1".to_string(),
    ///     delegator_m_id: "m-1".to_string(),
    ///     delegator_cert_fingerprint: vec![0xAB; 32],
    ///     delegated_pub: vec![0x02; 33],
    ///     delegated_key_id: "key-1".to_string(),
    ///     profile: "mesh-session".to_string(),
    ///     transcript_kinds: vec![],
    ///     roles: vec![],
    ///     channel: "dev".to_string(),
    ///     serial: 1,
    ///     not_before: 0,
    ///     not_after: 1,
    ///     sig: vec![0u8; 64],
    /// };
    /// let generic_key = SigningKey::random(&mut OsRng);
    /// let generic_verifying_key = VerifyingKey::from(&generic_key);
    /// // A bare p256 VerifyingKey does not implement
    /// // DelegationSignatureVerifier, so this does not compile.
    /// d.verify_signature(&generic_verifying_key).unwrap();
    /// ```
    pub fn verify_signature(
        &self,
        verifier: &impl DelegationSignatureVerifier,
    ) -> Result<(), DelegationError> {
        verifier.verify_delegation(self)
    }

    /// The two triple-equality members that do not require a live roster.
    /// The third member of each triple (`roster.m_id`, roster fingerprint)
    /// is item 3b and is not checked here — see the module doc.
    pub fn check_partial_binding(&self, ctx: &PartialBindingInputs) -> Result<(), DelegationError> {
        if ctx.proof_hh_id != ctx.local_hh_id || ctx.local_hh_id != self.hh_id {
            return Err(DelegationError::HouseholdBindingMismatch);
        }
        if ctx.proof_self_m_id != self.delegator_m_id {
            return Err(DelegationError::DelegatorBindingMismatch);
        }
        if ctx.proof_self_cert_fingerprint != self.delegator_cert_fingerprint {
            return Err(DelegationError::DelegatorBindingMismatch);
        }
        Ok(())
    }
}

/// Injected verification for a `MeshSessionDelegation`'s `sig`. No
/// implementation of this trait exists in this crate — deciding what
/// `sig` actually covers (the preimage) is explicitly deferred (GATE,
/// @kiana). This trait exists only so a *future*, real implementation has
/// a fail-closed-shaped seam to plug into; it decides nothing about bytes.
pub trait DelegationSignatureVerifier {
    fn verify_delegation(&self, delegation: &MeshSessionDelegation) -> Result<(), DelegationError>;
}

/// The only verifier this crate provides: always fails closed. Standing in
/// for "no real verifier has been injected yet" so an unverified
/// delegation can never be silently treated as valid by omission.
pub struct NoVerifierConfigured;

impl DelegationSignatureVerifier for NoVerifierConfigured {
    fn verify_delegation(
        &self,
        _delegation: &MeshSessionDelegation,
    ) -> Result<(), DelegationError> {
        Err(DelegationError::BadSignature)
    }
}

/// The subset of Proof-R/Proof-I/local-identity fields needed to check the
/// non-roster half of B-SESSAO v6 §5's triple equalities. This is
/// deliberately not the full Proof-R/Proof-I frame type — those belong to
/// the state-machine track, out of this crate's scope.
pub struct PartialBindingInputs {
    pub proof_hh_id: String,
    pub local_hh_id: String,
    pub proof_self_m_id: String,
    pub proof_self_cert_fingerprint: Vec<u8>,
}

/// `DelegationPolicy` — production fail-closed until measured, test
/// injectable. B-SESSAO v6 §5.
#[derive(Debug, Clone, Copy)]
pub struct DelegationPolicy {
    max_ttl: u64,
}

impl DelegationPolicy {
    /// `max_ttl = 0` rejects every delegation until this is deliberately
    /// configured from a real measurement.
    pub fn production() -> Self {
        Self { max_ttl: 0 }
    }

    pub fn test(max_ttl: u64) -> Self {
        Self { max_ttl }
    }

    /// `not_before < not_after` is mandatory (RED-45/RED-46); `checked_sub`
    /// makes the reversed-window case (`not_after < not_before`) a `None`
    /// rather than a wrapping/panicking subtraction.
    pub fn validate_window(&self, not_before: u64, not_after: u64) -> Result<(), DelegationError> {
        let ttl = not_after
            .checked_sub(not_before)
            .ok_or(DelegationError::InvalidTtlWindow)?;
        if ttl == 0 {
            return Err(DelegationError::InvalidTtlWindow);
        }
        if ttl > self.max_ttl {
            return Err(DelegationError::TtlExceedsPolicy {
                ttl,
                max_ttl: self.max_ttl,
            });
        }
        Ok(())
    }

    pub fn validate(&self, delegation: &MeshSessionDelegation) -> Result<(), DelegationError> {
        self.validate_window(delegation.not_before, delegation.not_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(not_before: u64, not_after: u64) -> MeshSessionDelegation {
        MeshSessionDelegation {
            version: 1,
            kind: DELEGATION_KIND.to_string(),
            domain: DELEGATION_DOMAIN.to_string(),
            hh_id: "hh-1".to_string(),
            delegator_m_id: "m-1".to_string(),
            delegator_cert_fingerprint: vec![0xAB; 32],
            delegated_pub: vec![0x02; 33],
            delegated_key_id: "key-1".to_string(),
            profile: "mesh-session".to_string(),
            transcript_kinds: vec!["identity-proof".to_string()],
            roles: vec!["initiator".to_string(), "responder".to_string()],
            channel: "dev".to_string(),
            serial: 1,
            not_before,
            not_after,
            sig: vec![0u8; 64],
        }
    }

    #[test]
    fn round_trip_canonical() {
        let d = sample(100, 200);
        let bytes = d.to_canonical_bytes().unwrap();
        let back = MeshSessionDelegation::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn round_trip_rejects_noncanonical_bytes() {
        use ciborium::Value;
        // Same fields, declared out of canonical (sorted) order.
        let raw = Value::Map(vec![
            (Value::Text("version".into()), Value::Integer(1.into())),
            (
                Value::Text("kind".into()),
                Value::Text(DELEGATION_KIND.into()),
            ),
            (Value::Text("hh_id".into()), Value::Text("hh-1".into())),
            (
                Value::Text("domain".into()),
                Value::Text(DELEGATION_DOMAIN.into()),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&raw, &mut bytes).unwrap();
        assert!(MeshSessionDelegation::from_canonical_bytes(&bytes).is_err());
    }

    #[test]
    fn wrong_size_bstr_is_rejected() {
        let mut d = sample(100, 200);
        d.delegator_cert_fingerprint = vec![0xAB; 31]; // one byte short
        let bytes = d.to_canonical_bytes().unwrap();
        assert!(matches!(
            MeshSessionDelegation::from_canonical_bytes(&bytes),
            Err(DelegationError::NonCanonical)
        ));
    }

    #[test]
    fn wrong_size_sig_is_rejected() {
        let mut d = sample(100, 200);
        d.sig = vec![0xAB; 63]; // one byte short of the wire-field size
        let bytes = d.to_canonical_bytes().unwrap();
        assert!(matches!(
            MeshSessionDelegation::from_canonical_bytes(&bytes),
            Err(DelegationError::NonCanonical)
        ));
    }

    #[test]
    fn no_verifier_configured_fails_closed_even_for_an_internally_consistent_delegation() {
        let d = sample(100, 200);
        assert_eq!(
            d.verify_signature(&NoVerifierConfigured),
            Err(DelegationError::BadSignature)
        );
    }

    #[test]
    fn red45_ttl_reversed_rejected() {
        let policy = DelegationPolicy::test(3600);
        assert_eq!(
            policy.validate_window(200, 100),
            Err(DelegationError::InvalidTtlWindow)
        );
    }

    #[test]
    fn red46_ttl_equal_rejected() {
        let policy = DelegationPolicy::test(3600);
        assert_eq!(
            policy.validate_window(200, 200),
            Err(DelegationError::InvalidTtlWindow)
        );
    }

    #[test]
    fn production_policy_rejects_everything_until_measured() {
        let policy = DelegationPolicy::production();
        assert!(matches!(
            policy.validate_window(0, 1),
            Err(DelegationError::TtlExceedsPolicy { ttl: 1, max_ttl: 0 })
        ));
    }

    #[test]
    fn pos3_fixture_with_test_policy_is_accepted() {
        let policy = DelegationPolicy::test(3600);
        let d = sample(1_000, 1_000 + 3600);
        policy.validate(&d).unwrap();
    }

    #[test]
    fn ttl_over_policy_max_is_rejected() {
        let policy = DelegationPolicy::test(3600);
        let d = sample(1_000, 1_000 + 3601);
        assert!(matches!(
            policy.validate(&d),
            Err(DelegationError::TtlExceedsPolicy {
                ttl: 3601,
                max_ttl: 3600
            })
        ));
    }

    #[test]
    fn partial_binding_matching_inputs_accepted() {
        let d = sample(100, 200);
        let ctx = PartialBindingInputs {
            proof_hh_id: "hh-1".to_string(),
            local_hh_id: "hh-1".to_string(),
            proof_self_m_id: "m-1".to_string(),
            proof_self_cert_fingerprint: vec![0xAB; 32],
        };
        d.check_partial_binding(&ctx).unwrap();
    }

    #[test]
    fn partial_binding_household_mismatch_rejected() {
        let d = sample(100, 200);
        let ctx = PartialBindingInputs {
            proof_hh_id: "hh-1".to_string(),
            local_hh_id: "hh-DIFFERENT".to_string(),
            proof_self_m_id: "m-1".to_string(),
            proof_self_cert_fingerprint: vec![0xAB; 32],
        };
        assert_eq!(
            d.check_partial_binding(&ctx),
            Err(DelegationError::HouseholdBindingMismatch)
        );
    }

    #[test]
    fn partial_binding_delegator_m_id_mismatch_rejected() {
        let d = sample(100, 200);
        let ctx = PartialBindingInputs {
            proof_hh_id: "hh-1".to_string(),
            local_hh_id: "hh-1".to_string(),
            proof_self_m_id: "m-DIFFERENT".to_string(),
            proof_self_cert_fingerprint: vec![0xAB; 32],
        };
        assert_eq!(
            d.check_partial_binding(&ctx),
            Err(DelegationError::DelegatorBindingMismatch)
        );
    }

    #[test]
    fn partial_binding_fingerprint_mismatch_rejected() {
        let d = sample(100, 200);
        let ctx = PartialBindingInputs {
            proof_hh_id: "hh-1".to_string(),
            local_hh_id: "hh-1".to_string(),
            proof_self_m_id: "m-1".to_string(),
            proof_self_cert_fingerprint: vec![0xFF; 32],
        };
        assert_eq!(
            d.check_partial_binding(&ctx),
            Err(DelegationError::DelegatorBindingMismatch)
        );
    }
}
