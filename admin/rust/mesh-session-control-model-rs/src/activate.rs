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
//!
//! Round 5 fixes:
//! - item B4: `BindingContext` used to be an independent parameter never
//!   cross-checked against the record actually being acted on — only
//!   `purpose` was verified, so a caller could activate record A while
//!   supplying a context/delegation for an unrelated identity B. It is now
//!   always derived from `base.identity`/`record.identity`, never
//!   caller-supplied.
//! - item D9: the prior version read `base.pending_op`, and if it was
//!   already `None` (activation already committed by an earlier attempt)
//!   immediately returned `NothingToActivate` — *before* ever reaching
//!   `apply`'s own idempotent-replay logic. A lost-ack retry of an
//!   already-succeeded activation therefore got a confusing error instead
//!   of its own prior success, even though `apply` called directly proves
//!   the replay logic itself is correct — the public surface a real caller
//!   actually uses defeated it. `expected_txn_id` is now an explicit
//!   parameter (the caller already knows it, from having driven
//!   `IntentRecorded`/`KeyObserved` themselves), checked against
//!   `recent_terminal_results` before any pending-op-presence check.
//! - item A3: `store`/`locks` used to be independent parameters, which
//!   required `ControlRecordCell` to hand back a raw store to any external
//!   caller of this function — reopening exactly the bypass A3 closes.
//!   This now takes `&ControlRecordCell` and commits only through
//!   `commit_built`, which always goes through `transition::apply`.

use crate::cell::{CommitTransitionError, ControlRecordCell};
use crate::record::{GenerationRecord, MeshSignerControlRecordV1, PendingPhase, TerminalOutcome};
use crate::secret_backend::{LoadExactOutcome, SecretBackend};
use crate::store::LoadOutcome;
use crate::transition::{RecordTransition, TransitionError};
use crate::validator::{
    BindingContext, DelegationPolicy, PurposeMarker, RosterLookup, SignatureVerifier,
    ValidationError, validate_full_binding,
};

#[derive(Debug, thiserror::Error)]
pub enum ActivateError {
    #[error("no pending op, or not in KeyObserved phase, to activate")]
    NothingToActivate,
    #[error(
        "pending op's observed binding is not present in the secret backend with a matching kind/instance/attrs"
    )]
    PhysicalKeyNotConfirmed,
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Commit(#[from] CommitTransitionError),
}

impl From<TransitionError> for ActivateError {
    fn from(e: TransitionError) -> Self {
        ActivateError::Commit(CommitTransitionError::Transition(e))
    }
}

/// Confirms the physical key exists via `backend.load_exact` and runs the
/// full validator with **no exclusive guard held**, then reacquires the
/// guard only for a fresh reread-and-commit.
///
/// Second-round fix (round 4, item 5): the prior version acquired the
/// `MutateGuard` before `backend.load_exact`/`roster.query_machine_currency`/
/// `sig.verify` and held it through all three, blocking every other
/// mutation — including an *urgent* `RevokeUrgent` — for however long those
/// external calls took. Revocation must never be able to queue behind an
/// unrelated, possibly slow activation attempt's I/O. The snapshot read and
/// all slow validation now happen with no guard held at all; the guard is
/// acquired only immediately before the commit, against a freshly reread
/// base. If something preempted the pending op in the meantime (a revoke
/// that ran while this was busy with I/O), the freshly built transition's
/// own exact-token check (`apply`'s existing `StaleWorkerToken`/
/// `NoPendingOp`/`WrongPhase`) rejects it — never silently activating a
/// snapshot that has gone stale.
#[allow(clippy::too_many_arguments)]
pub fn activate_from_key_observed<P: PurposeMarker>(
    cell: &ControlRecordCell,
    backend: &dyn SecretBackend,
    roster: &dyn RosterLookup,
    sig: &dyn SignatureVerifier,
    policy: &DelegationPolicy,
    expected_txn_id: [u8; 16],
    delegation: crate::record::Delegation,
    now: u64,
    max_cap: usize,
) -> Result<MeshSignerControlRecordV1, ActivateError> {
    // No guard held for this read.
    let base = match cell.load_canonical() {
        LoadOutcome::Exact(r) => *r,
        LoadOutcome::Missing => return Err(ActivateError::Commit(CommitTransitionError::NoRecord)),
        LoadOutcome::Corrupt => {
            return Err(ActivateError::Commit(CommitTransitionError::RecordCorrupt));
        }
    };
    if base.purpose != P::PURPOSE_ID {
        // The type parameter alone proves nothing about which record this
        // is — without this, `activate_from_key_observed::<RosterSyncPurpose>`
        // could validate and activate a record whose runtime `purpose` is
        // really `MeshSession`, as long as the caller also supplied a
        // delegation with RosterSync's domain/profile/role.
        return Err(ActivateError::Validation(ValidationError::PurposeMismatch));
    }

    // Idempotent-replay check FIRST, before any pending-op-presence check
    // (item D9) -- a prior successful commit of this exact activation
    // clears pending_op, so checking pending_op first would reject a
    // legitimate lost-ack retry with a confusing NothingToActivate instead
    // of recognizing its own earlier success.
    if let Some(existing) = base
        .recent_terminal_results
        .iter()
        .find(|r| r.txn_id == expected_txn_id)
    {
        return match &existing.outcome {
            TerminalOutcome::Activated { .. } => Ok(base),
            _ => Err(TransitionError::TerminalTxnReused.into()),
        };
    }

    let p = base
        .pending_op
        .as_ref()
        .filter(|p| p.txn_id == expected_txn_id)
        .ok_or(ActivateError::NothingToActivate)?;
    if p.phase != PendingPhase::KeyObserved {
        return Err(ActivateError::NothingToActivate);
    }
    let binding = p.binding.clone().ok_or(ActivateError::NothingToActivate)?;
    let (expected_kind, expected_generation, expected_epoch, expected_purpose, expected_slot_id) = (
        p.kind,
        p.generation,
        p.epoch,
        p.purpose,
        p.canonical_slot.canonical_id(),
    );
    // Derived from the record's own identity -- never independently
    // caller-supplied (item B4).
    let ctx = BindingContext::from_identity(&base.identity);

    // Slow I/O below — no guard held, so an urgent RevokeUrgent (or
    // anything else) can freely interleave.
    match backend.load_exact(&p.canonical_slot, &binding.public_key) {
        LoadExactOutcome::Ready(observed) if observed == binding => {}
        _ => return Err(ActivateError::PhysicalKeyNotConfirmed),
    }
    let generation_record = GenerationRecord {
        generation: p.generation,
        delegation: delegation.clone(),
        binding,
        not_after: delegation.not_after,
    };
    validate_full_binding::<P>(&generation_record, &ctx, policy, roster, sig, now)?;

    // Reacquire only now, and build against a fresh read taken under that
    // same guard (`commit_built`) — apply()'s own exact-token check catches
    // any divergence against this snapshot (e.g. an urgent revoke that ran
    // while the slow I/O above was in flight).
    let new = cell
        .commit_built(
            |fresh| {
                Some(RecordTransition::ActivateFromKeyObserved {
                    expected_txn_id,
                    expected_kind,
                    expected_generation,
                    expected_epoch,
                    expected_purpose,
                    expected_slot_id,
                    expected_revision: fresh.revision,
                    delegation,
                })
            },
            now,
            max_cap,
        )?
        .expect("build always returns Some");
    Ok(new)
}

/// Re-validates every live generation's delegation/binding against the
/// current roster/policy — the "em load" half of finding 8: a delegation
/// valid at activation time can rot (roster revocation, TTL/clock drift)
/// without the record itself ever being mutated again.
pub fn revalidate_on_load<P: PurposeMarker>(
    record: &MeshSignerControlRecordV1,
    policy: &DelegationPolicy,
    roster: &dyn RosterLookup,
    sig: &dyn SignatureVerifier,
    now: u64,
) -> Result<(), ValidationError> {
    if record.purpose != P::PURPOSE_ID {
        return Err(ValidationError::PurposeMismatch);
    }
    // Derived from the record's own identity -- never independently
    // caller-supplied (item B4).
    let ctx = BindingContext::from_identity(&record.identity);
    for g in &record.live_generations {
        validate_full_binding::<P>(g, &ctx, policy, roster, sig, now)?;
    }
    Ok(())
}
