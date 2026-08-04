//! Orchestration for activation — the one place outside tests that actually
//! drives `transition::RecordTransition::ActivateFromKeyObserved`.
//!
//! `transition::apply` is deliberately I/O-free (see its module doc), so it
//! cannot call the secret backend or the validator itself. Successor to the
//! generation audited at commit `d4ecb658` (NO-GO, finding 8): the prior
//! generation left `validator::validate_full_binding` as a free function a
//! caller could simply forget to call before activating, and nothing ever
//! confirmed the physical key material actually existed via
//! `SecretBackend::load_exact` before trusting it. Both are now mandatory
//! steps of this one function, not optional helpers.

use crate::commit::{CommitError, commit_new_bytes};
use crate::locks::MeshSignerLocks;
use crate::record::{GenerationRecord, MeshSignerControlRecordV1, PendingPhase};
use crate::secret_backend::{LoadExactOutcome, SecretBackend};
use crate::store::{AtomicControlRecordStore, LoadOutcome};
use crate::transition::{RecordTransition, TransitionError, apply};
use crate::validator::{
    BindingContext, DelegationPolicy, PurposeMarker, RosterLookup, SignatureVerifier,
    ValidationError, validate_full_binding,
};

#[derive(Debug, thiserror::Error)]
pub enum ActivateError {
    #[error("store has no record for this identity")]
    NoRecord,
    #[error("record is corrupt")]
    RecordCorrupt,
    #[error("no pending op, or not in KeyObserved phase, to activate")]
    NothingToActivate,
    #[error(
        "pending op's observed binding is not present in the secret backend with a matching kind/instance/attrs"
    )]
    PhysicalKeyNotConfirmed,
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Transition(#[from] TransitionError),
    #[error(transparent)]
    Commit(#[from] CommitError),
}

/// Loads fresh under an exclusive guard, confirms the physical key exists
/// via `backend.load_exact`, runs the full validator, then commits
/// `ActivateFromKeyObserved` — all in one continuously held critical
/// section, so nothing observed here can go stale before the write.
#[allow(clippy::too_many_arguments)]
pub fn activate_from_key_observed<P: PurposeMarker>(
    store: &dyn AtomicControlRecordStore,
    backend: &dyn SecretBackend,
    locks: &MeshSignerLocks,
    roster: &dyn RosterLookup,
    sig: &dyn SignatureVerifier,
    policy: &DelegationPolicy,
    ctx: &BindingContext<'_>,
    delegation: crate::record::Delegation,
    now: u64,
    max_cap: usize,
) -> Result<MeshSignerControlRecordV1, ActivateError> {
    let guard = locks.acquire_for_mutation();
    let base = match store.load_canonical() {
        LoadOutcome::Exact(r) => *r,
        LoadOutcome::Missing => return Err(ActivateError::NoRecord),
        LoadOutcome::Corrupt => return Err(ActivateError::RecordCorrupt),
    };
    if base.purpose != P::PURPOSE_ID {
        // The type parameter alone proves nothing about which record this
        // is — without this, `activate_from_key_observed::<RosterSyncPurpose>`
        // could validate and activate a record whose runtime `purpose` is
        // really `MeshSession`, as long as the caller also supplied a
        // delegation with RosterSync's domain/profile/role.
        return Err(ActivateError::Validation(ValidationError::PurposeMismatch));
    }
    let p = base
        .pending_op
        .as_ref()
        .ok_or(ActivateError::NothingToActivate)?;
    if p.phase != PendingPhase::KeyObserved {
        return Err(ActivateError::NothingToActivate);
    }
    let binding = p.binding.clone().ok_or(ActivateError::NothingToActivate)?;

    match backend.load_exact(&p.canonical_slot, &binding.public_key) {
        LoadExactOutcome::Ready(observed) if observed == binding => {}
        _ => return Err(ActivateError::PhysicalKeyNotConfirmed),
    }

    let generation_record = GenerationRecord {
        generation: p.generation,
        delegation: delegation.clone(),
        binding: binding.clone(),
        not_after: delegation.not_after,
    };
    validate_full_binding::<P>(&generation_record, ctx, policy, roster, sig, now)?;

    let t = RecordTransition::ActivateFromKeyObserved {
        expected_txn_id: p.txn_id,
        expected_kind: p.kind,
        expected_generation: p.generation,
        expected_epoch: p.epoch,
        expected_purpose: p.purpose,
        expected_slot_id: p.canonical_slot.canonical_id(),
        expected_revision: base.revision,
        delegation,
    };
    let new = apply(&base, &t, now, max_cap)?;
    commit_new_bytes(store, &guard, base.revision, &new, 8)?;
    Ok(new)
}

/// Re-validates every live generation's delegation/binding against the
/// current roster/policy — the "em load" half of finding 8: a delegation
/// valid at activation time can rot (roster revocation, TTL/clock drift)
/// without the record itself ever being mutated again.
pub fn revalidate_on_load<P: PurposeMarker>(
    record: &MeshSignerControlRecordV1,
    ctx: &BindingContext<'_>,
    policy: &DelegationPolicy,
    roster: &dyn RosterLookup,
    sig: &dyn SignatureVerifier,
    now: u64,
) -> Result<(), ValidationError> {
    if record.purpose != P::PURPOSE_ID {
        return Err(ValidationError::PurposeMismatch);
    }
    for g in &record.live_generations {
        validate_full_binding::<P>(g, ctx, policy, roster, sig, now)?;
    }
    Ok(())
}
