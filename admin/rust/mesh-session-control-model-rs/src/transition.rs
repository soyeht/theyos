//! Typed old→new record transitions. There is deliberately no generic
//! `validate_transition(old, new)` consulting an underspecified
//! `pending_resolved(old)` predicate (v10/v11 bug: such a predicate rejected
//! the design's own two success paths). Each transition constructs its own
//! evidence in the returned record and is checked against the *shared*
//! invariants at the end of `apply`.
//!
//! Successor to the generation audited at commit `d4ecb658` (NO-GO). Every
//! change below traces to a specific finding from that audit:
//! - finding 1: `KeyObserved`/`ActivateFromKeyObserved` now require the
//!   caller to state the exact `txn_id`/`kind`/`generation`/`epoch`/
//!   `purpose`/`slot`/`revision` they expect to be acting on, checked
//!   against `old.pending_op` and `old`; a late worker whose pending op was
//!   preempted (revoke bumps `epoch_high_water` and clears `pending_op`; a
//!   subsequent reactivate creates an unrelated new one) is rejected with
//!   `StaleWorkerToken` instead of silently binding onto the wrong op.
//!   `ReactivateFromRevoked` now rejects if a pending op already exists,
//!   instead of overwriting it.
//! - finding 3/4: `IntentRecorded`/`ReactivateFromRevoked` no longer accept
//!   a caller-built `PendingOp` — `generation` and `canonical_slot` are
//!   always derived from `old`, never caller-supplied. `apply` now takes an
//!   injected `max_cap`, enforced for every transition. A new
//!   `GenerationExpired` transition gives expiry a real path into GC and
//!   out of `live_generations` (closing "invariant proíbe remoção").
//! - finding 5: `RevokeUrgent`/`ReactivateFromRevoked` now record a
//!   `TerminalResult` (`Revoked`/`Reactivated`); `push_bounded_terminal`
//!   (record.rs) is fail-closed on a same-txn_id outcome conflict and never
//!   silently evicts an unacknowledged entry — a new `TerminalAcked`
//!   transition is the only way to make an entry eviction-eligible.
//! - finding 6: `GcInspected` no longer resolves a first absent reading
//!   straight to `Done` with a fabricated placeholder binding — see
//!   `record::GcEntry::AbsentUnconfirmed`/`Absent`. `GcRemoval` now matches
//!   the exact `(slot_id, txn_id)` pair, not `slot_id` alone.

use crate::record::{
    Authority, BackendKind, ExactBinding, GcEntry, GcState, GenerationRecord,
    MeshSignerControlRecordV1, PendingOp, PendingOpKind, PendingPhase, PurposeId, RevocationReason,
    SlotId, TerminalOutcome, TerminalPushError, TerminalResult, ack_terminal, identity_digest,
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
    #[error("no GC entry for that slot/txn")]
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
    #[error(
        "caller's expected txn/kind/generation/epoch/purpose/slot/revision did not match the live pending op — a late or preempted worker"
    )]
    StaleWorkerToken,
    #[error("transition would push cap_occupancy over the injected max_cap")]
    CapExceeded,
    #[error(transparent)]
    Terminal(#[from] TerminalPushError),
    #[error("no live generation with that number")]
    NoSuchGeneration,
    #[error("generation has not reached its not_after yet")]
    GenerationNotExpired,
    #[error("no recorded terminal result for that txn_id")]
    NoSuchTerminalResult,
    #[error("two gc_pending entries would share the same slot")]
    DuplicateGcSlot,
}

pub enum RecordTransition {
    /// `generation` and `canonical_slot` are always derived from `old`
    /// inside `apply` — never caller-supplied (finding 4).
    IntentRecorded {
        txn_id: [u8; 16],
        kind: PendingOpKind,
        backend: BackendKind,
    },
    KeyObserved {
        expected_txn_id: [u8; 16],
        expected_kind: PendingOpKind,
        expected_generation: NonZeroU64,
        expected_epoch: NonZeroU64,
        expected_purpose: PurposeId,
        expected_slot_id: String,
        expected_revision: u64,
        binding: ExactBinding,
    },
    ActivateFromKeyObserved {
        expected_txn_id: [u8; 16],
        expected_kind: PendingOpKind,
        expected_generation: NonZeroU64,
        expected_epoch: NonZeroU64,
        expected_purpose: PurposeId,
        expected_slot_id: String,
        expected_revision: u64,
        delegation: crate::record::Delegation,
    },
    RevokeUrgent {
        reason: RevocationReason,
        /// Idempotency key for *this* revoke request/terminal result — not
        /// the preempted pending op's own `txn_id` (that op was never
        /// activated, so it never gets an `Activated` terminal result; if
        /// it later gets one anyway from a buggy caller, that would
        /// legitimately conflict, which is exactly what fail-closed is
        /// for).
        txn_id: [u8; 16],
    },
    /// `generation`/`canonical_slot` are derived, same as `IntentRecorded`.
    /// Fails with `PendingAlreadyExists` if `old.pending_op` is already
    /// `Some` — never silently overwrites (finding 1).
    ReactivateFromRevoked {
        /// Idempotency key for the reactivate request itself (the
        /// `Reactivated` terminal result). Distinct from `next_txn_id` —
        /// the two must never collide, or a later `Activated` terminal
        /// result for `next_txn_id` would conflict with this one.
        txn_id: [u8; 16],
        next_txn_id: [u8; 16],
        kind: PendingOpKind,
        backend: BackendKind,
    },
    /// Moves a non-current, lapsed `live_generations` entry into GC and out
    /// of `live_generations` — the only transition allowed to remove a
    /// retained generation, and only this one specific generation.
    GenerationExpired { generation: NonZeroU64 },
    /// Valid on `AwaitingInspection` (first observation) or
    /// `AbsentUnconfirmed` (second, confirming observation) entries.
    /// `found = None` on a first observation moves to `AbsentUnconfirmed`,
    /// never straight to a terminal state — a backend may be eventually
    /// consistent, so one absent reading is not proof nothing will ever
    /// appear (finding 6). `found = None` on a second observation confirms
    /// `Absent` (terminal, no binding). `found = Some(b)` at either stage
    /// moves to `Bound { state: Pending }` with the real observed binding —
    /// including the "late apparition" case where a first-absent entry's
    /// second inspection *does* find something.
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
    /// Matches the exact `(slot_id, txn_id)` pair — finding 6 ("remove só
    /// entry_id exato").
    GcRemoval { slot_id: String, txn_id: [u8; 16] },
    /// Marks a recorded terminal result acknowledged, making it eligible
    /// for eviction once `recent_terminal_results` is at capacity.
    TerminalAcked { txn_id: [u8; 16] },
    /// Rewrite of byte-identical content to (re)confirm durability. The
    /// only transition that does *not* bump `revision` — see `apply`.
    StabilizationRewrite,
}

/// `now` is injected (never `SystemTime::now()`/wall clock read internally)
/// so tests can exercise TTL/`not_after` edges deterministically. `max_cap`
/// is injected too (finding 4, "cap injetado") — never a constant baked
/// into this crate.
pub fn apply(
    old: &MeshSignerControlRecordV1,
    t: &RecordTransition,
    now: u64,
    max_cap: usize,
) -> Result<MeshSignerControlRecordV1, TransitionError> {
    let mut new = old.clone();
    let mut allowed_removal: Option<NonZeroU64> = None;

    match t {
        RecordTransition::StabilizationRewrite => {
            // new == old; revision intentionally left unchanged below.
        }

        RecordTransition::IntentRecorded {
            txn_id,
            kind,
            backend,
        } => {
            if old.pending_op.is_some() {
                return Err(TransitionError::PendingAlreadyExists);
            }
            let generation = derive_next_generation(old)?;
            let canonical_slot = SlotId {
                identity_digest: identity_digest(&old.identity),
                purpose: old.purpose,
                generation,
                txn_id: *txn_id,
                backend_instance: *backend,
            };
            new.pending_op = Some(PendingOp {
                txn_id: *txn_id,
                kind: *kind,
                generation,
                epoch: old.epoch_high_water,
                purpose: old.purpose,
                backend: *backend,
                canonical_slot,
                phase: PendingPhase::Intent,
                binding: None,
            });
            bump_revision(&mut new, old)?;
        }

        RecordTransition::KeyObserved {
            expected_txn_id,
            expected_kind,
            expected_generation,
            expected_epoch,
            expected_purpose,
            expected_slot_id,
            expected_revision,
            binding,
        } => {
            if old.revision != *expected_revision {
                return Err(TransitionError::StaleWorkerToken);
            }
            let p = old
                .pending_op
                .as_ref()
                .ok_or(TransitionError::NoPendingOp)?;
            if p.phase != PendingPhase::Intent {
                return Err(TransitionError::WrongPhase);
            }
            if !pending_matches_token(
                p,
                expected_txn_id,
                expected_kind,
                expected_generation,
                expected_epoch,
                expected_purpose,
                expected_slot_id,
            ) {
                return Err(TransitionError::StaleWorkerToken);
            }
            let mut np = p.clone();
            np.phase = PendingPhase::KeyObserved;
            np.binding = Some(binding.clone());
            new.pending_op = Some(np);
            bump_revision(&mut new, old)?;
        }

        RecordTransition::ActivateFromKeyObserved {
            expected_txn_id,
            expected_kind,
            expected_generation,
            expected_epoch,
            expected_purpose,
            expected_slot_id,
            expected_revision,
            delegation,
        } => {
            if old.revision != *expected_revision {
                return Err(TransitionError::StaleWorkerToken);
            }
            let p = old
                .pending_op
                .as_ref()
                .ok_or(TransitionError::NoPendingOp)?;
            if p.phase != PendingPhase::KeyObserved {
                return Err(TransitionError::WrongPhase);
            }
            if !pending_matches_token(
                p,
                expected_txn_id,
                expected_kind,
                expected_generation,
                expected_epoch,
                expected_purpose,
                expected_slot_id,
            ) {
                return Err(TransitionError::StaleWorkerToken);
            }
            let binding = p.binding.clone().ok_or(TransitionError::MissingBinding)?;
            let generation = p.generation;
            let txn_id = p.txn_id;
            new.live_generations.push(GenerationRecord {
                generation,
                delegation: delegation.clone(),
                binding,
                not_after: delegation.not_after,
            });
            new.current_generation = Some(generation);
            new.authority = Authority::Active;
            new.pending_op = None;
            new.recent_terminal_results = push_bounded_terminal(
                old.recent_terminal_results.clone(),
                TerminalResult {
                    txn_id,
                    outcome: TerminalOutcome::Activated { generation },
                    recorded_at: now,
                    acked: false,
                },
            )?;
            if generation > new.generation_high_water {
                new.generation_high_water = generation;
            }
            bump_revision(&mut new, old)?;
        }

        RecordTransition::RevokeUrgent { reason, txn_id } => {
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
            new.recent_terminal_results = push_bounded_terminal(
                old.recent_terminal_results.clone(),
                TerminalResult {
                    txn_id: *txn_id,
                    outcome: TerminalOutcome::Revoked {
                        epoch: new.epoch_high_water,
                    },
                    recorded_at: now,
                    acked: false,
                },
            )?;
            bump_revision(&mut new, old)?;
        }

        RecordTransition::ReactivateFromRevoked {
            txn_id,
            next_txn_id,
            kind,
            backend,
        } => {
            if !matches!(old.authority, Authority::Revoked { .. }) {
                return Err(TransitionError::NotRevoked);
            }
            if old.pending_op.is_some() {
                return Err(TransitionError::PendingAlreadyExists);
            }
            new.epoch_high_water = old
                .epoch_high_water
                .checked_add(1)
                .ok_or(TransitionError::EpochExhausted)?;
            let generation = derive_next_generation(old)?;
            let canonical_slot = SlotId {
                identity_digest: identity_digest(&old.identity),
                purpose: old.purpose,
                generation,
                txn_id: *next_txn_id,
                backend_instance: *backend,
            };
            new.pending_op = Some(PendingOp {
                txn_id: *next_txn_id,
                kind: *kind,
                generation,
                epoch: new.epoch_high_water,
                purpose: old.purpose,
                backend: *backend,
                canonical_slot,
                phase: PendingPhase::Intent,
                binding: None,
            });
            new.recent_terminal_results = push_bounded_terminal(
                old.recent_terminal_results.clone(),
                TerminalResult {
                    txn_id: *txn_id,
                    outcome: TerminalOutcome::Reactivated {
                        epoch: new.epoch_high_water,
                    },
                    recorded_at: now,
                    acked: false,
                },
            )?;
            bump_revision(&mut new, old)?;
        }

        RecordTransition::GenerationExpired { generation } => {
            if old.current_generation == Some(*generation) {
                return Err(TransitionError::RemovesCurrent);
            }
            let g = old
                .live_generations
                .iter()
                .find(|g| g.generation == *generation)
                .ok_or(TransitionError::NoSuchGeneration)?;
            if now < g.not_after {
                return Err(TransitionError::GenerationNotExpired);
            }
            new.gc_pending.push(GcEntry::Bound {
                slot: g.binding.slot.clone(),
                txn_id: g.binding.slot.txn_id,
                binding: g.binding.clone(),
                state: GcState::Pending,
            });
            new.live_generations
                .retain(|lg| lg.generation != *generation);
            allowed_removal = Some(*generation);
            bump_revision(&mut new, old)?;
        }

        RecordTransition::GcInspected { slot_id, found } => {
            let idx = new
                .gc_pending
                .iter()
                .position(|e| e.slot().canonical_id() == *slot_id)
                .ok_or(TransitionError::NoSuchGcEntry)?;
            let (slot, txn_id, is_first_observation) = match &new.gc_pending[idx] {
                GcEntry::AwaitingInspection { slot, txn_id } => (slot.clone(), *txn_id, true),
                GcEntry::AbsentUnconfirmed { slot, txn_id } => (slot.clone(), *txn_id, false),
                GcEntry::Bound { .. } | GcEntry::Absent { .. } => {
                    return Err(TransitionError::WrongPhase);
                }
            };
            new.gc_pending[idx] = match (found, is_first_observation) {
                (None, true) => GcEntry::AbsentUnconfirmed { slot, txn_id },
                (None, false) => GcEntry::Absent { slot, txn_id },
                (Some(b), _) => GcEntry::Bound {
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
                GcEntry::AwaitingInspection { .. }
                | GcEntry::AbsentUnconfirmed { .. }
                | GcEntry::Absent { .. } => return Err(TransitionError::WrongPhase),
            }
            bump_revision(&mut new, old)?;
        }

        RecordTransition::GcRemoval { slot_id, txn_id } => {
            let entry = old
                .gc_pending
                .iter()
                .find(|e| e.slot().canonical_id() == *slot_id && e.txn_id() == *txn_id)
                .ok_or(TransitionError::NoSuchGcEntry)?;
            if !entry.observation_complete_and_residual_zero() {
                return Err(TransitionError::GcNotResolved);
            }
            new.gc_pending
                .retain(|e| !(e.slot().canonical_id() == *slot_id && e.txn_id() == *txn_id));
            bump_revision(&mut new, old)?;
        }

        RecordTransition::TerminalAcked { txn_id } => {
            if !old
                .recent_terminal_results
                .iter()
                .any(|r| r.txn_id == *txn_id)
            {
                return Err(TransitionError::NoSuchTerminalResult);
            }
            new.recent_terminal_results =
                ack_terminal(old.recent_terminal_results.clone(), *txn_id);
            bump_revision(&mut new, old)?;
        }
    }

    validate_shared_invariants(old, &new, allowed_removal, max_cap)?;
    Ok(new)
}

#[allow(clippy::too_many_arguments)]
fn pending_matches_token(
    p: &PendingOp,
    expected_txn_id: &[u8; 16],
    expected_kind: &PendingOpKind,
    expected_generation: &NonZeroU64,
    expected_epoch: &NonZeroU64,
    expected_purpose: &PurposeId,
    expected_slot_id: &str,
) -> bool {
    p.txn_id == *expected_txn_id
        && p.kind == *expected_kind
        && p.generation == *expected_generation
        && p.epoch == *expected_epoch
        && p.purpose == *expected_purpose
        && p.canonical_slot.canonical_id() == *expected_slot_id
}

fn derive_next_generation(old: &MeshSignerControlRecordV1) -> Result<NonZeroU64, TransitionError> {
    if old.current_generation.is_some() {
        old.generation_high_water
            .checked_add(1)
            .ok_or(TransitionError::GenerationExhausted)
    } else {
        Ok(NonZeroU64::new(1).unwrap())
    }
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

/// Invariants shared by every transition except `StabilizationRewrite`
/// (checked separately: it must leave `new == old` byte-for-byte, so none
/// of these can fire). `allowed_removal`, when `Some(g)`, permits exactly
/// one live-generation removal — `g` — for `GenerationExpired`; every other
/// transition passes `None` and the blanket prohibition applies.
fn validate_shared_invariants(
    old: &MeshSignerControlRecordV1,
    new: &MeshSignerControlRecordV1,
    allowed_removal: Option<NonZeroU64>,
    max_cap: usize,
) -> Result<(), TransitionError> {
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
            if allowed_removal == Some(g.generation) {
                continue; // deliberately, provably removed by GenerationExpired
            }
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
    let mut seen_slots = std::collections::HashSet::new();
    for e in &new.gc_pending {
        if !seen_slots.insert(e.slot().canonical_id()) {
            // Two gc_pending entries sharing a slot would make GC's
            // per-slot destroy/inspect calls ambiguous — never legitimate.
            return Err(TransitionError::DuplicateGcSlot);
        }
    }
    if new.cap_occupancy() > max_cap {
        return Err(TransitionError::CapExceeded);
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
    txn_id: [u8; 16],
    now: u64,
    max_cap: usize,
) -> Result<MeshSignerControlRecordV1, TransitionError> {
    apply(
        old,
        &RecordTransition::RevokeUrgent { reason, txn_id },
        now,
        max_cap,
    )
}
