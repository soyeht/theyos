//! Full binding validator. Fixes the v11 sweep finding directly: no merged
//! `transcript_kinds`/`KINDS` vocabulary conflating a *frame*'s `kind`
//! (FinalConfirm/Activate/ActivateAck's own field — none of those three
//! ever embed a delegation) with anything at the delegation level, and no
//! `"identity-proof"` literal (v3-final vocabulary that v6 does not use).
//!
//! Third-round correction: the `Delegation` shape itself (see `record.rs`)
//! is now modeled directly against the frozen wire schema
//! (`daisy-bsessao-v6.7343d075…` §5 + `daisy-bsessao-v6-erratum1.63222d40…`,
//! self-hash verified), not reconstructed from prose a second time. That
//! schema turned out to have its own `kind` field
//! (`"soyeht/mesh-session/delegation/v1"`) at the *delegation* level — this
//! module's own prior doc comment claiming "delegations never carry kind"
//! was itself the exact conflation it warned about, just inverted: it
//! correctly separated frame-kind from delegation-kind but then denied the
//! latter existed at all.
//!
//! Roster lookup and signature verification are trait-injected rather than
//! calling invented `household-rs` functions directly — this crate does not
//! depend on `household-rs`, so it cannot name real types like
//! `MachineRosterCoordinator` here; a real integration wires a concrete
//! implementation of `RosterLookup` backed by
//! `MachineRosterCoordinator::query_machine_currency` (verified real,
//! `machine_roster_store.rs:1447`) outside this crate.
//!
//! Second-round fixes, both from the same root cause — this crate must
//! never invent authority it has no basis for:
//! - `PurposeMarker` carried `DELEGATION_DOMAIN`/`PROFILE`/`ROLES` but
//!   nothing tying the *type* parameter to the record's actual *runtime*
//!   `PurposeId` — nothing stopped
//!   `activate_from_key_observed::<RosterSyncPurpose>` from validating and
//!   activating a record whose `purpose` was really `MeshSession`, as long
//!   as the caller also supplied a delegation with RosterSync's
//!   domain/profile/role. `PURPOSE_ID` closes that: callers (`activate.rs`)
//!   check it against the record's own `purpose` before doing anything
//!   else.
//! - `signed_preimage` computed an ad hoc byte concatenation and called it
//!   canonical, but the real delegation preimage format is owned by
//!   mesh-core and has not been frozen there — this model has no authority
//!   to invent and promote its own wire bytes as if they were that frozen
//!   form. `SignatureVerifier` now receives the typed `Delegation` itself,
//!   not preimage bytes this crate fabricated; a real integration
//!   implements `verify` against mesh-core's eventual frozen preimage
//!   function.

use crate::record::{Channel, ControlIdentity, Delegation, GenerationRecord, PurposeId};

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

    /// Round 6 fix (item 3): `activate_from_key_observed` used to call
    /// `query_machine_currency` once, with no guard held (deliberately —
    /// see that function's own doc comment on why slow I/O must never
    /// block a concurrent urgent revoke), and then commit against a
    /// *stale* answer: if the roster flipped `Active` → `Revoked` for this
    /// machine in the gap between that call and the eventual commit, the
    /// activation still went through. Closing that gap with a second full
    /// `query_machine_currency` call *inside* the commit guard would just
    /// reopen the original blocking problem this crate already fixed once.
    /// This method exists to let a real integration expose a CHEAP, purely
    /// local staleness signal instead — no I/O, safe to call while holding
    /// the guard — so the caller can prove nothing changed between the
    /// slow lookup and the moment of commit without ever doing slow I/O
    /// under lock. A real integration bumps its own revision counter on
    /// any change to any machine's currency; comparing two calls' results
    /// for the same `machine_id` is the whole contract. No default impl:
    /// a test double or integration that cannot honor "no I/O" should not
    /// silently inherit one that pretends to.
    fn currency_revision(&self, machine_id: &str) -> u64;
}

/// Deliberately receives the typed `Delegation`, not preimage bytes — see
/// the module doc's second-round fix. A real integration is expected to
/// derive whatever bytes mesh-core's eventual frozen preimage function
/// specifies from `delegation`, entirely inside its own implementation of
/// this trait; this crate does not get a vote on that byte layout.
pub trait SignatureVerifier {
    fn verify(&self, public_key: &[u8], delegation: &Delegation, sig: &[u8]) -> bool;
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

/// The delegation object's own schema version — frozen at `uint = 1`
/// (§5); there is only one defined version, so this is a fixed expected
/// value, not something `PurposeMarker` varies.
pub const DELEGATION_SCHEMA_VERSION: u64 = 1;

pub trait PurposeMarker {
    /// The runtime `PurposeId` this type parameter stands for. Callers
    /// (`activate.rs`) must check this against the record's actual
    /// `purpose` field — the type parameter alone proves nothing about
    /// which record it is being used against.
    const PURPOSE_ID: PurposeId;
    const DELEGATION_DOMAIN: &'static str;
    /// The delegation object's own `kind` field. For `MeshSessionPurpose`
    /// this is the frozen literal from §5,
    /// `"soyeht/mesh-session/delegation/v1"`. `RosterSyncPurpose`'s value
    /// is *mechanically derived* from that same frozen naming pattern
    /// (`soyeht/{profile}/delegation/v1`) applied to its own profile, not
    /// independently frozen anywhere — flagged for confirmation, not
    /// treated as equally authoritative.
    const DELEGATION_KIND: &'static str;
    const PROFILE: &'static str;
    /// Legacy vocabulary used only by the `required_scope() == None`
    /// fallback path — a nonempty-subset check, not an exact-set one. Kept
    /// for purposes (`RosterSyncPurpose`) that have no ratified production
    /// scope; see `required_scope`'s doc comment.
    const ROLES: &'static [&'static str];

    /// `Some` only for a purpose with a real, *ratified* production scope
    /// (see `DelegationScopePolicy`'s doc comment for what "ratified"
    /// means here and why). `None` means this purpose has no production
    /// exact-scope requirement, and `validate_full_binding` falls back to
    /// the legacy nonempty/subset check against `ROLES` plus a bare
    /// nonempty check on `transcript_kinds`.
    ///
    /// Default `None` so the validator body never has to special-case a
    /// purpose by name — it only ever asks "does this purpose have a
    /// ratified scope," never "is this purpose == MeshSession."
    /// `RosterSyncPurpose` deliberately keeps the default: it has no
    /// ratified production scope here (D6 owns RosterSync's real authority
    /// model — `M_priv` — and stays out of D4's production path);
    /// overriding this to `Some` would invent authority this crate has no
    /// basis for, the exact failure mode this crate's own history keeps
    /// correcting (see the module doc's second-round fixes).
    fn required_scope() -> Option<DelegationScopePolicy> {
        None
    }
}

/// Exact delegation scope required for a purpose's *production* path.
///
/// Round 5, item C8 — provenance, tracked explicitly because it was
/// initially mis-cited: this is **not** a restatement of the frozen
/// B-SESSAO v6 wire schema. §5 of that schema (self-hash verified,
/// `daisy-bsessao-v6.7343d075…md`) declares `roles: [text]` and
/// `transcript_kinds: [text]` as open lists with no stated exactness
/// constraint — re-checked directly against the frozen text before this
/// comment was written, specifically to avoid repeating this crate's own
/// history of modeling from a remembered paraphrase instead of the source.
/// This is a **new integration-level clause**, ratified by kiana for THIS
/// implementation's `MeshSessionPurpose` on top of that open schema: the
/// current slot/signer is not role-specific (one key signs both sides of a
/// session), so accepting a delegation listing only a *subset* of roles
/// would still let that same key act in a role the delegation never
/// authorized, and accepting *extra* roles/transcript_kinds would broaden
/// authority to scope the delegation never actually granted. Both
/// directions — subset and superset — are closed by exact-set equality
/// (order-independent, no duplicates), not subset containment.
pub struct DelegationScopePolicy {
    pub roles: &'static [&'static str],
    pub transcript_kinds: &'static [&'static str],
}

/// `actual`, as a set (duplicates are a hard rejection, not silently
/// collapsed), must equal `required` exactly — every required entry
/// present, nothing else. Order-independent.
fn is_exact_scope(actual: &[String], required: &[&str]) -> bool {
    if actual.len() != required.len() {
        return false;
    }
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for a in actual {
        if !seen.insert(a.as_str()) {
            return false; // duplicate entry
        }
    }
    required.iter().all(|r| seen.contains(r))
}

pub struct MeshSessionPurpose;
impl PurposeMarker for MeshSessionPurpose {
    const PURPOSE_ID: PurposeId = PurposeId::MeshSession;
    const DELEGATION_DOMAIN: &'static str = "soyeht/mesh-session/v1";
    const DELEGATION_KIND: &'static str = "soyeht/mesh-session/delegation/v1";
    const PROFILE: &'static str = "mesh-session";
    const ROLES: &'static [&'static str] = &["initiator", "responder"];

    fn required_scope() -> Option<DelegationScopePolicy> {
        Some(DelegationScopePolicy {
            roles: &["initiator", "responder"],
            transcript_kinds: &["final-confirm", "activate", "activate-ack"],
        })
    }
}

/// Round 6 fix (item 5): gated behind `roster-sync-unratified`, off by
/// default. A doc comment saying "no production path here, D6 owns it"
/// was not a control — in a normal build this type was fully `pub` and
/// activatable through `activate::activate_from_key_observed::<RosterSyncPurpose>`
/// exactly like `MeshSessionPurpose`, despite having no ratified
/// production authority model at all. `PurposeId::RosterSync` itself stays
/// part of the wire format (it is a real value other purposes' data must
/// coexist with), but the ability to validate/activate a record AS that
/// purpose through the `PurposeMarker` mechanism is now gated.
#[cfg(feature = "roster-sync-unratified")]
pub struct RosterSyncPurpose;
#[cfg(feature = "roster-sync-unratified")]
impl PurposeMarker for RosterSyncPurpose {
    const PURPOSE_ID: PurposeId = PurposeId::RosterSync;
    const DELEGATION_DOMAIN: &'static str = "soyeht/roster-sync/v1";
    // Derived, not frozen -- see PurposeMarker::DELEGATION_KIND doc.
    const DELEGATION_KIND: &'static str = "soyeht/roster-sync/delegation/v1";
    const PROFILE: &'static str = "roster-sync";
    const ROLES: &'static [&'static str] = &["initiator", "responder"];
    // required_scope() deliberately left at the trait's default `None` --
    // see that default's doc comment. D6 owns RosterSync's real scope.
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("delegation schema version mismatch")]
    VersionMismatch,
    #[error("delegation object kind mismatch")]
    DelegationKindMismatch,
    #[error("delegation domain mismatch")]
    DomainMismatch,
    #[error("delegation profile mismatch")]
    ProfileMismatch,
    #[error("delegation roles empty, or contains a role not authorized for this purpose")]
    RoleMismatch,
    #[error("delegation transcript_kinds is empty")]
    TranscriptKindsEmpty,
    #[error(
        "delegation roles do not exactly equal this purpose's ratified production scope (subset, extra, or duplicate entries)"
    )]
    RoleScopeMismatch,
    #[error(
        "delegation transcript_kinds do not exactly equal this purpose's ratified production scope (subset, extra, or duplicate entries)"
    )]
    TranscriptKindsScopeMismatch,
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
    #[error("delegation's delegated_pub does not match the physical binding's public_key")]
    DelegatedPubBindingMismatch,
    #[error("the type parameter's PURPOSE_ID does not match the record's own runtime purpose")]
    PurposeMismatch,
    #[error(
        "a live generation's physical key is no longer present in the backend with a matching public key -- replaced or deleted outside this record's own state machine"
    )]
    PhysicalKeyNotConfirmed,
    #[error(
        "roster currency for the delegator changed between validation and commit -- the delegation may no longer be authorized; retry to re-validate against current state"
    )]
    RosterChangedDuringActivation,
}

/// Identity context the validator checks the delegation against — grouped
/// so the function signature stays under clippy's argument-count lint
/// without losing any of the checks themselves.
///
/// Round 5, item B4: this used to be an independent parameter callers
/// supplied to `activate.rs`'s orchestration functions, never cross-checked
/// against the record actually being acted on — only `purpose` was
/// verified (`PURPOSE_ID`), so a caller could activate record A while
/// supplying a `ctx`/delegation for an unrelated identity B, and nothing
/// caught it. Its three fields map 1:1 onto `ControlIdentity`, so it is now
/// only ever constructed via `from_identity`, directly from the record's
/// own `identity` — never independently caller-supplied.
pub struct BindingContext<'a> {
    pub hh_id: &'a str,
    pub machine_id: &'a str,
    pub channel: Channel,
}

impl<'a> BindingContext<'a> {
    #[must_use]
    pub fn from_identity(identity: &'a ControlIdentity) -> Self {
        Self {
            hh_id: &identity.hh_id,
            machine_id: &identity.machine_id,
            channel: identity.channel,
        }
    }
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

    if d.version != DELEGATION_SCHEMA_VERSION {
        return Err(ValidationError::VersionMismatch);
    }
    if d.kind != P::DELEGATION_KIND {
        return Err(ValidationError::DelegationKindMismatch);
    }
    if d.domain != P::DELEGATION_DOMAIN {
        return Err(ValidationError::DomainMismatch);
    }
    if d.profile != P::PROFILE {
        return Err(ValidationError::ProfileMismatch);
    }
    match P::required_scope() {
        Some(scope) => {
            // Round 5, item C8 -- exact-set, both directions closed. See
            // `DelegationScopePolicy`'s doc comment for provenance and why.
            if !is_exact_scope(&d.roles, scope.roles) {
                return Err(ValidationError::RoleScopeMismatch);
            }
            if !is_exact_scope(&d.transcript_kinds, scope.transcript_kinds) {
                return Err(ValidationError::TranscriptKindsScopeMismatch);
            }
        }
        None => {
            if d.roles.is_empty() || !d.roles.iter().all(|r| P::ROLES.contains(&r.as_str())) {
                return Err(ValidationError::RoleMismatch);
            }
            if d.transcript_kinds.is_empty() {
                return Err(ValidationError::TranscriptKindsEmpty);
            }
        }
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
            if !sig.verify(&member_pub, d, &d.sig) {
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
    if d.delegated_pub.as_slice() != generation_record.binding.public_key.as_slice() {
        return Err(ValidationError::DelegatedPubBindingMismatch);
    }

    Ok(())
}
