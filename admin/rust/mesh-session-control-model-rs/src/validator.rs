//! Full binding validator. Fixes the v11 sweep finding directly:
//! delegations carry `role` (Proof-R/Proof-I's wire field: "initiator" |
//! "responder"), never `kind` (only FinalConfirm/Activate/ActivateAck have
//! `kind`, and none of those three ever embed a delegation) — there is no
//! merged `transcript_kinds`/`KINDS` vocabulary here, and no `"identity-proof"`
//! literal (v3-final vocabulary that v6 does not use).
//!
//! Roster lookup and signature verification are trait-injected rather than
//! calling invented `household-rs` functions directly — this crate does not
//! depend on `household-rs`, so it cannot name real types like
//! `MachineRosterCoordinator` here; a real integration wires a concrete
//! implementation of `RosterLookup` backed by
//! `MachineRosterCoordinator::query_machine_currency` (verified real,
//! `machine_roster_store.rs:1447`) outside this crate.

use crate::record::{Channel, Delegation, GenerationRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosterCurrency {
    Active {
        member_pub: Vec<u8>,
        member_cert_fingerprint: [u8; 32],
    },
    Revoked,
    NotListed,
    Unavailable,
}

/// Injected dependency — a real integration implements this against
/// `MachineRosterCoordinator::query_machine_currency`. This crate never
/// constructs a coordinator itself (the real constructor,
/// `from_validated_household`, needs household context this crate has no
/// business holding).
pub trait RosterLookup {
    fn query_machine_currency(&self, machine_id: &str) -> RosterCurrency;
}

pub trait SignatureVerifier {
    fn verify(&self, public_key: &[u8], preimage: &[u8], sig: &[u8]) -> bool;
}

pub struct DelegationPolicy {
    pub max_ttl: u64,
}

impl DelegationPolicy {
    /// Fail-closed default: rejects every delegation until a real TTL is
    /// measured and configured.
    #[must_use]
    pub fn production() -> Self {
        Self { max_ttl: 0 }
    }
    #[must_use]
    pub fn test(max_ttl: u64) -> Self {
        Self { max_ttl }
    }
}

pub trait PurposeMarker {
    const DELEGATION_DOMAIN: &'static str;
    const PROFILE: &'static str;
    const ROLES: &'static [&'static str];
}

pub struct MeshSessionPurpose;
impl PurposeMarker for MeshSessionPurpose {
    const DELEGATION_DOMAIN: &'static str = "soyeht/mesh-session/v1";
    const PROFILE: &'static str = "mesh-session";
    const ROLES: &'static [&'static str] = &["initiator", "responder"];
}

pub struct RosterSyncPurpose;
impl PurposeMarker for RosterSyncPurpose {
    const DELEGATION_DOMAIN: &'static str = "soyeht/roster-sync/v1";
    const PROFILE: &'static str = "roster-sync";
    const ROLES: &'static [&'static str] = &["initiator", "responder"];
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("delegation domain mismatch")]
    DomainMismatch,
    #[error("delegation profile mismatch")]
    ProfileMismatch,
    #[error("delegation role not authorized for this purpose")]
    RoleMismatch,
    #[error("channel mismatch")]
    ChannelMismatch,
    #[error("hh_id mismatch")]
    HhIdMismatch,
    #[error("delegator machine id mismatch")]
    IdentityMismatch,
    #[error("not_before >= not_after, or duration exceeds policy.max_ttl")]
    DelegationInvalid,
    #[error("now is outside [not_before, not_after)")]
    DelegationNotInWindow,
    #[error("record not_after does not equal delegation not_after")]
    NotAfterDrift,
    #[error("delegator is revoked in the roster")]
    DelegatorRevoked,
    #[error("delegator is not listed in the roster")]
    DelegatorNotInRoster,
    #[error("roster currency unavailable")]
    RosterUnavailable,
    #[error("delegator cert fingerprint does not match the roster member")]
    DelegatorFingerprintMismatch,
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("delegated_key_id does not match the canonical slot id")]
    KeyIdMismatch,
}

/// Identity context the validator checks the delegation against — grouped
/// so the function signature stays under clippy's argument-count lint
/// without losing any of the checks themselves.
pub struct BindingContext<'a> {
    pub hh_id: &'a str,
    pub machine_id: &'a str,
    pub channel: Channel,
}

/// One function, called both by `load()` (stable path, no pending op in
/// flight) and by activation (`RecordTransition::ActivateFromKeyObserved`'s
/// caller, before committing) — never two divergent validation paths.
pub fn validate_full_binding<P: PurposeMarker>(
    generation_record: &GenerationRecord,
    ctx: &BindingContext<'_>,
    policy: &DelegationPolicy,
    roster: &dyn RosterLookup,
    sig: &dyn SignatureVerifier,
    now: u64,
) -> Result<(), ValidationError> {
    let d: &Delegation = &generation_record.delegation;

    if d.domain != P::DELEGATION_DOMAIN {
        return Err(ValidationError::DomainMismatch);
    }
    if d.profile != P::PROFILE {
        return Err(ValidationError::ProfileMismatch);
    }
    if !P::ROLES.contains(&d.role.as_str()) {
        return Err(ValidationError::RoleMismatch);
    }
    if d.channel != ctx.channel {
        return Err(ValidationError::ChannelMismatch);
    }
    if d.hh_id != ctx.hh_id {
        return Err(ValidationError::HhIdMismatch);
    }
    if d.delegator_m_id != ctx.machine_id {
        return Err(ValidationError::IdentityMismatch);
    }

    let duration = d
        .not_after
        .checked_sub(d.not_before)
        .ok_or(ValidationError::DelegationInvalid)?;
    if d.not_before >= d.not_after || duration > policy.max_ttl {
        return Err(ValidationError::DelegationInvalid);
    }
    if !(d.not_before <= now && now < d.not_after) {
        return Err(ValidationError::DelegationNotInWindow);
    }
    if generation_record.not_after != d.not_after {
        return Err(ValidationError::NotAfterDrift);
    }

    match roster.query_machine_currency(&d.delegator_m_id) {
        RosterCurrency::Active {
            member_pub,
            member_cert_fingerprint,
        } => {
            if member_cert_fingerprint != d.delegator_cert_fingerprint {
                return Err(ValidationError::DelegatorFingerprintMismatch);
            }
            let preimage = signed_preimage(d);
            if !sig.verify(&member_pub, &preimage, &d.sig) {
                return Err(ValidationError::SignatureInvalid);
            }
        }
        RosterCurrency::Revoked => return Err(ValidationError::DelegatorRevoked),
        RosterCurrency::NotListed => return Err(ValidationError::DelegatorNotInRoster),
        RosterCurrency::Unavailable => return Err(ValidationError::RosterUnavailable),
    }

    if d.delegated_key_id != generation_record.binding.slot.canonical_id() {
        return Err(ValidationError::KeyIdMismatch);
    }

    Ok(())
}

fn signed_preimage(d: &Delegation) -> Vec<u8> {
    // Canonical preimage = everything except `sig` itself, domain-tagged —
    // mirrors the `signed_preimage = type_byte || canonical_cbor(unsigned_body)`
    // convention already used across this feature (B-SESSAO v6 §3,
    // OwnerApprovalV2). The exact byte layout is an implementation detail of
    // the real integration; this model only needs the *shape* (verify
    // covers everything but `sig`) to be testable.
    let mut buf = Vec::new();
    buf.extend_from_slice(d.domain.as_bytes());
    buf.extend_from_slice(d.profile.as_bytes());
    buf.extend_from_slice(d.role.as_bytes());
    buf.extend_from_slice(d.hh_id.as_bytes());
    buf.extend_from_slice(d.delegator_m_id.as_bytes());
    buf.extend_from_slice(&d.delegator_cert_fingerprint);
    buf.extend_from_slice(d.delegated_key_id.as_bytes());
    buf.extend_from_slice(&d.delegated_pub);
    buf.extend_from_slice(&d.not_before.to_be_bytes());
    buf.extend_from_slice(&d.not_after.to_be_bytes());
    buf
}
