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
//!
//! **Hardened 2026-08-04, independent audit of `911409eb`:** every field
//! used to be `pub`, so a caller could mutate a validated instance after
//! the fact (`d.channel = "whatever"`) with nothing re-checking it. Fields
//! are now private; the only way to *produce* a `MeshSessionDelegation` is
//! [`MeshSessionDelegation::from_canonical_bytes`] or the crate-internal
//! `TryFrom<DelegationWire>` impl (used by `#[serde(try_from = ..)]`, so
//! *any* deserialization path — including a `MeshSessionDelegation`
//! embedded as a field inside a larger struct, e.g. an auth frame — goes
//! through the same validation, not just the top-level entry point).
//! There is no way to obtain a validated instance and then desync it from
//! its own validation. Read access is via accessor methods.
//! `DelegationPolicy::test` is now `#[cfg(test)]`-gated: it does not exist
//! at all in a non-test build, so production code cannot reach for the
//! fail-open constructor by mistake.

use serde::{Deserialize, Serialize};

use crate::cbor;
use crate::error::DelegationError;

pub const DELEGATION_KIND: &str = "soyeht/mesh-session/delegation/v1";
pub const DELEGATION_DOMAIN: &str = "soyeht/mesh-session/v1";
pub const DELEGATION_PROFILE: &str = "mesh-session";
pub const DELEGATION_VERSION: u64 = 1;

/// Plain wire-shape shadow of [`MeshSessionDelegation`] — every field
/// public *within this crate only* (`pub(crate)`), used solely as the
/// serde `try_from`/`into` intermediate so construction always runs
/// through [`MeshSessionDelegation::validate_shape`]. Other modules in
/// this crate (auth frame tests, primarily) use this to build fixtures
/// without a full CBOR round-trip; it is never part of the public API.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct DelegationWire {
    pub(crate) version: u64,
    pub(crate) kind: String,
    pub(crate) domain: String,
    pub(crate) hh_id: String,
    pub(crate) delegator_m_id: String,
    #[serde(with = "serde_bytes")]
    pub(crate) delegator_cert_fingerprint: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub(crate) delegated_pub: Vec<u8>,
    pub(crate) delegated_key_id: String,
    pub(crate) profile: String,
    pub(crate) transcript_kinds: Vec<String>,
    pub(crate) roles: Vec<String>,
    pub(crate) channel: String,
    pub(crate) serial: u64,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
    #[serde(with = "serde_bytes")]
    pub(crate) sig: Vec<u8>,
}

/// B-SESSAO v6 §5 schema. Opaque outside this crate: fields are private,
/// the only public constructors are [`Self::from_canonical_bytes`] (real
/// wire bytes) and, crate-internally, `TryFrom<DelegationWire>` (test
/// fixtures elsewhere in this crate). Every construction path validates —
/// see the module-level hardening note.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DelegationWire", into = "DelegationWire")]
pub struct MeshSessionDelegation {
    version: u64,
    kind: String,
    domain: String,
    hh_id: String,
    delegator_m_id: String,
    delegator_cert_fingerprint: Vec<u8>,
    delegated_pub: Vec<u8>,
    delegated_key_id: String,
    profile: String,
    transcript_kinds: Vec<String>,
    roles: Vec<String>,
    channel: String,
    serial: u64,
    not_before: u64,
    not_after: u64,
    sig: Vec<u8>,
}

impl TryFrom<DelegationWire> for MeshSessionDelegation {
    type Error = DelegationError;

    fn try_from(w: DelegationWire) -> Result<Self, DelegationError> {
        let d = Self {
            version: w.version,
            kind: w.kind,
            domain: w.domain,
            hh_id: w.hh_id,
            delegator_m_id: w.delegator_m_id,
            delegator_cert_fingerprint: w.delegator_cert_fingerprint,
            delegated_pub: w.delegated_pub,
            delegated_key_id: w.delegated_key_id,
            profile: w.profile,
            transcript_kinds: w.transcript_kinds,
            roles: w.roles,
            channel: w.channel,
            serial: w.serial,
            not_before: w.not_before,
            not_after: w.not_after,
            sig: w.sig,
        };
        d.validate_shape()?;
        Ok(d)
    }
}

impl From<MeshSessionDelegation> for DelegationWire {
    fn from(d: MeshSessionDelegation) -> Self {
        DelegationWire {
            version: d.version,
            kind: d.kind,
            domain: d.domain,
            hh_id: d.hh_id,
            delegator_m_id: d.delegator_m_id,
            delegator_cert_fingerprint: d.delegator_cert_fingerprint,
            delegated_pub: d.delegated_pub,
            delegated_key_id: d.delegated_key_id,
            profile: d.profile,
            transcript_kinds: d.transcript_kinds,
            roles: d.roles,
            channel: d.channel,
            serial: d.serial,
            not_before: d.not_before,
            not_after: d.not_after,
            sig: d.sig,
        }
    }
}

impl MeshSessionDelegation {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DelegationError> {
        cbor::to_canonical_vec(self).map_err(|_| DelegationError::NonCanonical)
    }

    /// Decode + reject anything that is not exactly the closed canonical
    /// encoding, then run the same validation `TryFrom<DelegationWire>`
    /// runs for every other construction path — but via an explicit,
    /// non-serde-wrapped call, so callers get a precise [`DelegationError`]
    /// variant instead of a generic decode error.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DelegationError> {
        let wire: DelegationWire =
            cbor::from_canonical_bytes(bytes).map_err(|_| DelegationError::NonCanonical)?;
        Self::try_from(wire)
    }

    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn kind(&self) -> &str {
        &self.kind
    }
    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn hh_id(&self) -> &str {
        &self.hh_id
    }
    pub fn delegator_m_id(&self) -> &str {
        &self.delegator_m_id
    }
    pub fn delegator_cert_fingerprint(&self) -> &[u8] {
        &self.delegator_cert_fingerprint
    }
    pub fn delegated_pub(&self) -> &[u8] {
        &self.delegated_pub
    }
    pub fn delegated_key_id(&self) -> &str {
        &self.delegated_key_id
    }
    pub fn profile(&self) -> &str {
        &self.profile
    }
    pub fn transcript_kinds(&self) -> &[String] {
        &self.transcript_kinds
    }
    pub fn roles(&self) -> &[String] {
        &self.roles
    }
    pub fn channel(&self) -> &str {
        &self.channel
    }
    pub fn serial(&self) -> u64 {
        self.serial
    }
    pub fn not_before(&self) -> u64 {
        self.not_before
    }
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
    /// Opaque wire field — M_priv, user-present (v6 §5 line 282). Only its
    /// size is validated here; no function in this crate computes or
    /// checks what it signs. See [`DelegationSignatureVerifier`].
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }

    /// Enforces the fixed-size `bstr` fields the CBOR schema comments
    /// declare but CBOR itself cannot express, plus every schema field
    /// that has a *frozen literal* value (`version`, `kind`, `domain`,
    /// `profile`, `channel` ∈ {"dev","release"}). `transcript_kinds` and
    /// `roles` are deliberately not checked against a fixed list — v6 §5
    /// fixes only their shape (`[text]`), never their exact contents, so
    /// inventing an allowed-values list here would be exactly the kind of
    /// unfrozen-byte guess this crate avoids elsewhere.
    fn validate_shape(&self) -> Result<(), DelegationError> {
        if self.delegator_cert_fingerprint.len() != 32
            || self.delegated_pub.len() != 33
            || self.sig.len() != 64
        {
            return Err(DelegationError::NonCanonical);
        }
        if self.version != DELEGATION_VERSION {
            return Err(DelegationError::VersionMismatch);
        }
        if self.kind != DELEGATION_KIND {
            return Err(DelegationError::KindMismatch);
        }
        if self.domain != DELEGATION_DOMAIN {
            return Err(DelegationError::DomainMismatch);
        }
        if self.profile != DELEGATION_PROFILE {
            return Err(DelegationError::ProfileMismatch);
        }
        if self.channel != "dev" && self.channel != "release" {
            return Err(DelegationError::ChannelInvalid);
        }
        // 2026-08-04, @kiana: len==33 alone accepts 33 arbitrary bytes that
        // are not actually a point on the curve. Parse it for real.
        if p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.delegated_pub).is_err() {
            return Err(DelegationError::InvalidDelegatedPubPoint);
        }
        Ok(())
    }

    /// Verify `sig` via an injected [`DelegationSignatureVerifier`]. This
    /// crate ships no implementation of that trait — call sites must bring
    /// their own once the preimage decision lands. There is deliberately
    /// no method here that takes a raw `p256::ecdsa::VerifyingKey` (or any
    /// other bare key type, e.g. a generic K_mesh key) as a substitute; a
    /// bare `VerifyingKey` does not implement `DelegationSignatureVerifier`,
    /// so passing one does not compile. (The delegation value below is
    /// never actually produced — `unimplemented!()` only needs to
    /// type-check for this to demonstrate the property; the point under
    /// test is the argument type of `verify_signature`, not any runtime
    /// behavior.)
    ///
    /// ```compile_fail
    /// use mesh_session_core_rs::delegation::MeshSessionDelegation;
    /// use p256::ecdsa::{SigningKey, VerifyingKey};
    /// use rand_core::OsRng;
    ///
    /// fn some_delegation() -> MeshSessionDelegation { unimplemented!() }
    /// let d = some_delegation();
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

    /// `#[cfg(test)]`-gated (hardened 2026-08-04, independent audit): this
    /// constructor does not exist at all in a non-test build, so
    /// production code cannot reach for the injectable/fail-open policy
    /// by mistake — there is no `DelegationPolicy::test` to call.
    #[cfg(test)]
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
pub(crate) mod test_support {
    //! Crate-internal delegation fixtures, shared with other modules'
    //! tests (auth_frames, primarily) so they don't need to reach into
    //! `DelegationWire` themselves.
    use super::*;

    pub(crate) fn sample_delegation(not_before: u64, not_after: u64) -> MeshSessionDelegation {
        DelegationWire {
            version: DELEGATION_VERSION,
            kind: DELEGATION_KIND.to_string(),
            domain: DELEGATION_DOMAIN.to_string(),
            hh_id: "hh-1".to_string(),
            delegator_m_id: "m-1".to_string(),
            delegator_cert_fingerprint: vec![0xAB; 32],
            delegated_pub: vec![0x02; 33],
            delegated_key_id: "key-1".to_string(),
            profile: DELEGATION_PROFILE.to_string(),
            transcript_kinds: vec!["identity-proof".to_string()],
            roles: vec!["initiator".to_string(), "responder".to_string()],
            channel: "dev".to_string(),
            serial: 1,
            not_before,
            not_after,
            sig: vec![0u8; 64],
        }
        .try_into()
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::sample_delegation as sample;

    fn wire(not_before: u64, not_after: u64) -> DelegationWire {
        DelegationWire {
            version: DELEGATION_VERSION,
            kind: DELEGATION_KIND.to_string(),
            domain: DELEGATION_DOMAIN.to_string(),
            hh_id: "hh-1".to_string(),
            delegator_m_id: "m-1".to_string(),
            delegator_cert_fingerprint: vec![0xAB; 32],
            delegated_pub: vec![0x02; 33],
            delegated_key_id: "key-1".to_string(),
            profile: DELEGATION_PROFILE.to_string(),
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
    fn wrong_version_rejected() {
        let mut w = wire(100, 200);
        w.version = 2;
        assert_eq!(
            MeshSessionDelegation::try_from(w),
            Err(DelegationError::VersionMismatch)
        );
    }

    #[test]
    fn wrong_kind_rejected() {
        let mut w = wire(100, 200);
        w.kind = "not-the-frozen-kind".to_string();
        assert_eq!(
            MeshSessionDelegation::try_from(w),
            Err(DelegationError::KindMismatch)
        );
    }

    #[test]
    fn wrong_domain_rejected() {
        let mut w = wire(100, 200);
        w.domain = "soyeht/mesh-connection-intent/v1".to_string(); // a real, but WRONG, domain literal
        assert_eq!(
            MeshSessionDelegation::try_from(w),
            Err(DelegationError::DomainMismatch)
        );
    }

    #[test]
    fn wrong_profile_rejected() {
        let mut w = wire(100, 200);
        w.profile = "roster-sync".to_string();
        assert_eq!(
            MeshSessionDelegation::try_from(w),
            Err(DelegationError::ProfileMismatch)
        );
    }

    #[test]
    fn channel_outside_dev_or_release_rejected() {
        let mut w = wire(100, 200);
        w.channel = "staging".to_string();
        assert_eq!(
            MeshSessionDelegation::try_from(w),
            Err(DelegationError::ChannelInvalid)
        );
    }

    #[test]
    fn release_channel_is_accepted() {
        let mut w = wire(100, 200);
        w.channel = "release".to_string();
        MeshSessionDelegation::try_from(w).unwrap();
    }

    #[test]
    fn transcript_kinds_and_roles_accept_arbitrary_text_not_a_fixed_list() {
        // v6 §5 fixes only the shape ([text]), never the exact allowed
        // values — this crate must not invent a list to check against.
        let mut w = wire(100, 200);
        w.transcript_kinds = vec!["anything-goes-here".to_string()];
        w.roles = vec!["also-anything".to_string()];
        MeshSessionDelegation::try_from(w).unwrap();
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
        let mut w = wire(100, 200);
        w.delegator_cert_fingerprint = vec![0xAB; 31]; // one byte short
        assert_eq!(
            MeshSessionDelegation::try_from(w),
            Err(DelegationError::NonCanonical)
        );
    }

    #[test]
    fn red_delegated_pub_right_length_wrong_curve_point_is_rejected() {
        // 33 bytes, correctly shaped, but 0xAB is not a valid SEC1 compressed-
        // point prefix (must be 0x02 or 0x03) — proves the check is a real
        // curve-point parse, not just a length check.
        let mut w = wire(100, 200);
        w.delegated_pub = vec![0xAB; 33];
        assert_eq!(
            MeshSessionDelegation::try_from(w),
            Err(DelegationError::InvalidDelegatedPubPoint)
        );
    }

    #[test]
    fn wrong_size_sig_is_rejected() {
        let mut w = wire(100, 200);
        w.sig = vec![0xAB; 63]; // one byte short of the wire-field size
        assert_eq!(
            MeshSessionDelegation::try_from(w),
            Err(DelegationError::NonCanonical)
        );
    }

    #[test]
    fn embedding_in_a_larger_struct_validates_too() {
        // Regression for the audit finding: validation used to run only in
        // from_canonical_bytes's own explicit call, so a
        // MeshSessionDelegation deserialized as a *field* of some other
        // struct (e.g. an auth frame) skipped it entirely. The
        // try_from-based Deserialize impl means any embedding struct's
        // derive now validates automatically.
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            delegation: MeshSessionDelegation,
        }
        let mut w = wire(100, 200);
        w.channel = "not-dev-or-release".to_string();
        let bad_wire_bytes = cbor::to_canonical_vec(&w).unwrap();
        // Build the envelope's bytes by hand: a map with one key
        // "delegation" whose value is the (invalid) delegation map.
        let delegation_value: ciborium::Value =
            ciborium::de::from_reader(std::io::Cursor::new(&bad_wire_bytes)).unwrap();
        let envelope_value = ciborium::Value::Map(vec![(
            ciborium::Value::Text("delegation".into()),
            delegation_value,
        )]);
        let mut envelope_bytes = Vec::new();
        ciborium::ser::into_writer(&envelope_value, &mut envelope_bytes).unwrap();
        assert!(cbor::from_canonical_bytes::<Envelope>(&envelope_bytes).is_err());
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

    #[test]
    fn accessors_reflect_constructed_fields() {
        let d = sample(100, 200);
        assert_eq!(d.version(), 1);
        assert_eq!(d.kind(), DELEGATION_KIND);
        assert_eq!(d.domain(), DELEGATION_DOMAIN);
        assert_eq!(d.hh_id(), "hh-1");
        assert_eq!(d.delegator_m_id(), "m-1");
        assert_eq!(d.delegator_cert_fingerprint(), &[0xABu8; 32][..]);
        assert_eq!(d.delegated_pub(), &[0x02u8; 33][..]);
        assert_eq!(d.delegated_key_id(), "key-1");
        assert_eq!(d.profile(), DELEGATION_PROFILE);
        assert_eq!(d.channel(), "dev");
        assert_eq!(d.serial(), 1);
        assert_eq!(d.not_before(), 100);
        assert_eq!(d.not_after(), 200);
        assert_eq!(d.sig(), &[0u8; 64][..]);
    }
}
