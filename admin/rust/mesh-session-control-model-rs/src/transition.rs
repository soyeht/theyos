//! Typed old→new record transitions. There is deliberately no generic
//! `validate_transition(old, new)` consulting an underspecified
//! `pending_resolved(old)` predicate (v10/v11 bug: such a predicate rejected
//! the design's own two success paths). Each transition constructs its own
//! evidence in the returned record and is checked against the *shared*
//! invariants at the end of `apply`.

use crate::record::{
    Authority, ExactBinding, GcEntry, GcState, GenerationRecord, MeshSignerControlRecordV1,
    PendingOp, PendingOpKind, PendingPhase, RevocationReason, TerminalResult,
    push_bounded_terminal,
};
use std::num::NonZeroU64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error("revision counter exhausted")]
    RevisionExhausted,
    #[error("epoch counter exhausted")]
    EpochExhausted,
    #[error("generation counter exhausted")]
    GenerationExhausted,
    #[error("a pending operation already exists")]
    PendingAlreadyExists,
    #[error("no pending operation to act on")]
    NoPendingOp,
    #[error("pending operation is in the wrong phase for this transition")]
    WrongPhase,
    #[error("KeyObserved pending has no binding recorded")]
    MissingBinding,
    #[error("authority is not Revoked")]
    NotRevoked,
    #[error("no GC entry for that slot")]
    NoSuchGcEntry,
    #[error("GC entry is not fully resolved (observation incomplete or residual != 0)")]
    GcNotResolved,
    #[error("transition changed identity or purpose")]
    IdentityPurposeChanged,
    #[error("transition mutated or dropped a still-live retained generation")]
    RetainedGenerationMutated,
    #[error("transition removed the current generation")]
    RemovesCurrent,
    #[error("transition decreased generation_high_water")]
    HighWaterDecreased,
    #[error("transition decreased epoch_high_water")]
    EpochHighWaterDecreased,
}

pub enum RecordTransition {
    IntentRecorded {
        pending: PendingOp,
    },
    KeyObserved {
        binding: ExactBinding,
    },
    ActivateFromKeyObserved {
        delegation: crate::record::Delegation,
        terminal: TerminalResult,
    },
    RevokeUrgent {
        reason: RevocationReason,
    },
    ReactivateFromRevoked {
        new_pending: PendingOp,
    },
    /// Only valid on a `GcEntry::AwaitingInspection` entry. `found = None`
    /// means the backend confirmed nothing physical was ever created (or it
    /// is already gone) — resolves straight to `Done`. `found = Some(b)`
    /// means a real binding was observed and must now go through
    /// best-effort destruction — moves to `Bound { state: Pending }`.
    GcInspected {
        slot_id: String,
        found: Option<ExactBinding>,
    },
    /// Only valid on a `GcEntry::Bound` entry.
    GcResolved {
        slot_id: String,
        residual_zero: bool,
        quarantine: bool,
    },
    GcRemoval {
        slot_id: String,
    },
    /// Rewrite of byte-identical content to (re)confirm durability. The
    /// only transition that does *not* bump `revision` — see `apply`.
    StabilizationRewrite,
}

/// `now` is injected (never `SystemTime::now()`/wall clock read internally)
/// so tests can exercise TTL/`not_after` edges deterministically.
pub fn apply(
    old: &MeshSignerControlRecordV1,
    t: &RecordTransition,
    now: u64,
) -> Result<MeshSignerControlRecordV1, TransitionError> {
    let mut new = old.clone();

    match t {
        RecordTransition::StabilizationRewrite => {
            // new == old; revision intentionally left unchanged below.
        }

        RecordTransition::IntentRecorded { pending } => {
            if old.pending_op.is_some() {
                return Err(TransitionError::PendingAlreadyExists);
            }
            new.pending_op = Some(pending.clone());
            bump_revision(&mut new, old)?;
        }

        RecordTransition::KeyObserved { binding } => {
            let p = old
                .pending_op
                .as_ref()
                .ok_or(TransitionError::NoPendingOp)?;
            if p.phase != PendingPhase::Intent {
                return Err(TransitionError::WrongPhase);
            }
            let mut np = p.clone();
            np.phase = PendingPhase::KeyObserved;
            np.binding = Some(binding.clone());
            new.pending_op = Some(np);
            bump_revision(&mut new, old)?;
        }

        RecordTransition::ActivateFromKeyObserved {
            delegation,
            terminal,
        } => {
            let p = old
                .pending_op
                .as_ref()
                .ok_or(TransitionError::NoPendingOp)?;
            if p.phase != PendingPhase::KeyObserved {
                return Err(TransitionError::WrongPhase);
            }
            let binding = p.binding.clone().ok_or(TransitionError::MissingBinding)?;
            new.live_generations.push(GenerationRecord {
                generation: p.generation,
                delegation: delegation.clone(),
                binding,
                not_after: delegation.not_after,
            });
            new.current_generation = Some(p.generation);
            new.authority = Authority::Active;
            new.pending_op = None;
            new.recent_terminal_results =
                push_bounded_terminal(old.recent_terminal_results.clone(), *terminal);
            if p.generation > new.generation_high_water {
                new.generation_high_water = p.generation;
            }
            bump_revision(&mut new, old)?;
        }

        RecordTransition::RevokeUrgent { reason } => {
            new.epoch_high_water = old
                .epoch_high_water
                .checked_add(1)
                .ok_or(TransitionError::EpochExhausted)?;
            new.authority = Authority::Revoked { reason: *reason };
            if let Some(p) = &old.pending_op {
                let entry = match &p.binding {
                    None => GcEntry::AwaitingInspection {
                        slot: p.canonical_slot.clone(),
                        txn_id: p.txn_id,
                    },
                    Some(b) => GcEntry::Bound {
                        slot: p.canonical_slot.clone(),
                        txn_id: p.txn_id,
                        binding: b.clone(),
                        state: GcState::Pending,
                    },
                };
                new.gc_pending.push(entry);
            }
            new.pending_op = None;
            bump_revision(&mut new, old)?;
        }

        RecordTransition::ReactivateFromRevoked { new_pending } => {
            if !matches!(old.authority, Authority::Revoked { .. }) {
                return Err(TransitionError::NotRevoked);
            }
            new.epoch_high_water = old
                .epoch_high_water
                .checked_add(1)
                .ok_or(TransitionError::EpochExhausted)?;
            new.pending_op = Some(new_pending.clone());
            bump_revision(&mut new, old)?;
        }

        RecordTransition::GcInspected { slot_id, found } => {
            let idx = new
                .gc_pending
                .iter()
                .position(|e| e.slot().canonical_id() == *slot_id)
                .ok_or(TransitionError::NoSuchGcEntry)?;
            let (slot, txn_id) = match &new.gc_pending[idx] {
                GcEntry::AwaitingInspection { slot, txn_id } => (slot.clone(), *txn_id),
                GcEntry::Bound { .. } => return Err(TransitionError::WrongPhase),
            };
            new.gc_pending[idx] = match found {
                None => GcEntry::Bound {
                    binding: dummy_binding_placeholder(&slot),
                    slot,
                    txn_id,
                    state: GcState::Done,
                },
                Some(b) => GcEntry::Bound {
                    slot,
                    txn_id,
                    binding: b.clone(),
                    state: GcState::Pending,
                },
            };
            bump_revision(&mut new, old)?;
        }

        RecordTransition::GcResolved {
            slot_id,
            residual_zero,
            quarantine,
        } => {
            let entry = new
                .gc_pending
                .iter_mut()
                .find(|e| e.slot().canonical_id() == *slot_id)
                .ok_or(TransitionError::NoSuchGcEntry)?;
            match entry {
                GcEntry::Bound { state, .. } => {
                    *state = if *quarantine {
                        GcState::Quarantine
                    } else if *residual_zero {
                        GcState::Done
                    } else {
                        GcState::Pending
                    };
                }
                GcEntry::AwaitingInspection { .. } => return Err(TransitionError::WrongPhase),
            }
            bump_revision(&mut new, old)?;
        }

        RecordTransition::GcRemoval { slot_id } => {
            let entry = old
                .gc_pending
                .iter()
                .find(|e| e.slot().canonical_id() == *slot_id)
                .ok_or(TransitionError::NoSuchGcEntry)?;
            if !entry.observation_complete_and_residual_zero() {
                return Err(TransitionError::GcNotResolved);
            }
            new.gc_pending
                .retain(|e| e.slot().canonical_id() != *slot_id);
            bump_revision(&mut new, old)?;
        }
    }

    validate_shared_invariants(old, &new, now)?;
    Ok(new)
}

fn bump_revision(
    new: &mut MeshSignerControlRecordV1,
    old: &MeshSignerControlRecordV1,
) -> Result<(), TransitionError> {
    new.revision = old
        .revision
        .checked_add(1)
        .ok_or(TransitionError::RevisionExhausted)?;
    Ok(())
}

/// Placeholder used only when `AwaitingInspection` resolves to "nothing was
/// ever created" (`observed == None`) — `Done` never inspects `binding`
/// again once `observation_complete_and_residual_zero()` is true, but the
/// field must still be populated because `GcEntry::Bound` is not optional
/// over it. Real GC call sites always pass a real `ExactBinding` when
/// `observed.is_some()`.
fn dummy_binding_placeholder(slot: &crate::record::SlotId) -> ExactBinding {
    ExactBinding {
        slot: slot.clone(),
        public_key: Vec::new(),
        attributes: Vec::new(),
    }
}

/// Invariants shared by every transition except `StabilizationRewrite`
/// (checked separately: it must leave `new == old` byte-for-byte, so none
/// of these can fire).
fn validate_shared_invariants(
    old: &MeshSignerControlRecordV1,
    new: &MeshSignerControlRecordV1,
    now: u64,
) -> Result<(), TransitionError> {
    let _ = now; // reserved for a future not_after-vs-now check at the transition layer;
    // TTL enforcement itself lives in the validator (validator.rs), not here.
    if new.identity != old.identity || new.purpose != old.purpose {
        return Err(TransitionError::IdentityPurposeChanged);
    }
    for g in &old.live_generations {
        if !new.live_generations.contains(g) {
            // A retained generation must be byte-identical, not just
            // present-by-number — `Vec::contains` uses `GenerationRecord`'s
            // full `PartialEq`.
            let still_referenced_by_number = new
                .live_generations
                .iter()
                .any(|ng| ng.generation == g.generation);
            if still_referenced_by_number {
                return Err(TransitionError::RetainedGenerationMutated);
            }
            // Fully removed: only acceptable if it had already lapsed.
            // (Expiry-driven removal is a distinct, not-yet-modeled
            // transition kind; conservatively reject removal here so a
            // silent drop can never masquerade as one.)
            return Err(TransitionError::RetainedGenerationMutated);
        }
    }
    if let Some(cur) = old.current_generation {
        if !new.live_generations.iter().any(|g| g.generation == cur) {
            return Err(TransitionError::RemovesCurrent);
        }
    }
    if new.generation_high_water < old.generation_high_water {
        return Err(TransitionError::HighWaterDecreased);
    }
    if new.epoch_high_water < old.epoch_high_water {
        return Err(TransitionError::EpochHighWaterDecreased);
    }
    Ok(())
}

/// Cap occupancy is non-increasing across `RevokeUrgent`: the transition
/// removes at most one `pending_op` slot and adds at most one `gc_pending`
/// slot, and never touches `live_generations`. This is asserted as a
/// regression test (see `tests/`), not just claimed in prose.
pub fn revoke_urgent(
    old: &MeshSignerControlRecordV1,
    reason: RevocationReason,
    now: u64,
) -> Result<MeshSignerControlRecordV1, TransitionError> {
    apply(old, &RecordTransition::RevokeUrgent { reason }, now)
}

pub fn new_pending_intent(
    old: &MeshSignerControlRecordV1,
    kind: PendingOpKind,
    canonical_slot: crate::record::SlotId,
    txn_id: [u8; 16],
) -> Result<PendingOp, TransitionError> {
    let generation = if old.current_generation.is_some() {
        old.generation_high_water
            .checked_add(1)
            .ok_or(TransitionError::GenerationExhausted)?
    } else {
        NonZeroU64::new(1).unwrap()
    };
    Ok(PendingOp {
        txn_id,
        kind,
        generation,
        purpose: old.purpose,
        backend: canonical_slot.backend_instance,
        canonical_slot,
        phase: PendingPhase::Intent,
        binding: None,
    })
}
