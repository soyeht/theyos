//! `MeshSignerControlRecordV1` — the single-record control state (GO
//! `aecc5ecf`, erratum1 `4d0e7e25`). One record per `(ControlIdentity,
//! PurposeId)`; no satellite files. This module holds only data + pure
//! invariant checks, no I/O.
//!
//! Successor to the generation audited at commit `d4ecb658` (NO-GO). Every
//! type change here traces to a specific finding from that audit — see the
//! doc comment on each item.

use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

pub const INITIAL_REVISION: u64 = 0;
pub const MAX_RECENT_TERMINAL_RESULTS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlIdentity {
    pub hh_id: String,
    pub machine_id: String,
    pub channel: Channel,
}

/// Canonical, injective digest of `ControlIdentity` — length-prefixed so
/// `("ab", "c")` and `("a", "bc")` can never collide. This is what
/// `SlotId::identity_digest` must always be derived from (audit finding 4:
/// generation/slot must be *derived*, never caller-supplied).
#[must_use]
pub fn identity_digest(identity: &ControlIdentity) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((identity.hh_id.len() as u64).to_be_bytes());
    h.update(identity.hh_id.as_bytes());
    h.update((identity.machine_id.len() as u64).to_be_bytes());
    h.update(identity.machine_id.as_bytes());
    h.update([match identity.channel {
        Channel::Dev => 0u8,
        Channel::Release => 1u8,
    }]);
    h.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Channel {
    Dev,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PurposeId {
    MeshSession,
    RosterSync,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Authority {
    Empty,
    Active,
    Revoked { reason: RevocationReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    Compromised,
    Lost,
    OwnerAction,
    MachineRevoked,
}

impl RevocationReason {
    /// Compromised/Lost/OwnerAction/MachineRevoked are all urgent — the
    /// mapping table (D-4 v3 §8) never had a routine urgent reason. Routine
    /// rotation (`Retired`/`Replaced`) never calls `RevokeUrgent` at all, so
    /// it is not a variant of this enum.
    #[must_use]
    pub fn is_urgent(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingPhase {
    Intent,
    KeyObserved,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SlotId {
    pub identity_digest: [u8; 32],
    pub purpose: PurposeId,
    pub generation: NonZeroU64,
    pub txn_id: [u8; 16],
    pub backend_instance: BackendKind,
}

impl SlotId {
    /// Injective encoding of every field, including `backend_instance` —
    /// two slots identical except for backend (e.g. the same identity/
    /// purpose/generation/txn_id once on `SecureEnclave` and once on
    /// `TpmSealedSoftware`) must never collide on the string used
    /// pervasively for GC-entry and delegation key-id lookups, since
    /// `SlotId`'s own `Eq`/`Hash` already treat them as distinct.
    #[must_use]
    pub fn canonical_id(&self) -> String {
        let mut s = hex::encode(self.identity_digest);
        s.push('.');
        s.push_str(match self.purpose {
            PurposeId::MeshSession => "mesh-session",
            PurposeId::RosterSync => "roster-sync",
        });
        s.push_str(".gen");
        s.push_str(&self.generation.get().to_string());
        s.push('.');
        s.push_str(&hex::encode(self.txn_id));
        s.push('.');
        s.push_str(match self.backend_instance {
            BackendKind::SecureEnclave => "se",
            BackendKind::TpmSealedSoftware => "tpm",
            BackendKind::File => "file",
        });
        s
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BackendKind {
    SecureEnclave,
    TpmSealedSoftware,
    File,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactBinding {
    pub slot: SlotId,
    pub public_key: Vec<u8>,
    pub attributes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOp {
    pub txn_id: [u8; 16],
    pub kind: PendingOpKind,
    pub generation: NonZeroU64,
    /// `epoch_high_water` at the moment this pending op was created (by
    /// `IntentRecorded` or `ReactivateFromRevoked`). `KeyObserved`/
    /// `ActivateFromKeyObserved` must be called with this exact value as
    /// `expected_epoch` — audit finding 1: a worker holding a stale
    /// reference to an *earlier* pending op (preempted by a revoke, which
    /// bumps `epoch_high_water`) must not be able to complete a *later*
    /// pending op just because both happen to share the same `phase`.
    pub epoch: NonZeroU64,
    pub purpose: PurposeId,
    pub backend: BackendKind,
    pub canonical_slot: SlotId,
    pub phase: PendingPhase,
    /// `None` while `phase == Intent`; `Some` once `phase == KeyObserved`.
    /// There is deliberately no persisted `DelegationReady` phase (erratum1
    /// E2) — activation is a single transition straight from `KeyObserved`.
    pub binding: Option<ExactBinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingOpKind {
    Create,
    RoutineRotate,
    Reactivate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationRecord {
    pub generation: NonZeroU64,
    pub delegation: Delegation,
    pub binding: ExactBinding,
    pub not_after: u64,
}

/// Minimal delegation shape sufficient to model D-9/B-SESSAO v6 binding
/// checks. `role` mirrors Proof-R/Proof-I's wire field; delegations never
/// carry a frame `kind` (FinalConfirm/Activate/ActivateAck never embed a
/// delegation at all) — the earlier v10/v11 `transcript_kinds`/`KINDS`
/// vocabulary conflated the two and is not reproduced here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    pub domain: String,
    pub profile: String,
    pub role: String,
    pub channel: Channel,
    pub hh_id: String,
    pub delegator_m_id: String,
    pub delegator_cert_fingerprint: [u8; 32],
    pub delegated_key_id: String,
    pub delegated_pub: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    pub sig: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GcState {
    /// A physical binding is known; best-effort destruction has been
    /// attempted zero or more times and has not yet resolved. Deliberately
    /// *not* named `Claimed` (v10 bug: a `Claimed`-and-skip state let a
    /// crash mid-attempt strand the entry forever). Every tick reprocesses
    /// every entry not in `Done`, including this one.
    Pending,
    Done,
    Residual,
    Quarantine,
}

impl GcState {
    #[must_use]
    pub fn observation_complete_and_residual_zero(&self) -> bool {
        matches!(self, GcState::Done)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GcEntry {
    AwaitingInspection {
        slot: SlotId,
        txn_id: [u8; 16],
    },
    /// First inspection observed nothing at this slot. Audit finding 6: a
    /// backend may be eventually consistent, so a single absent reading is
    /// not proof nothing will ever appear there — treating it as terminal
    /// immediately risks leaking a late-materializing key with nothing left
    /// tracking it. A second, independently fresh inspection is required
    /// before this can be trusted as `Absent`. If that second inspection
    /// instead observes a real item (a late apparition), this moves to
    /// `Bound` with the real observed binding, never straight to `Absent`.
    AbsentUnconfirmed {
        slot: SlotId,
        txn_id: [u8; 16],
    },
    Bound {
        slot: SlotId,
        txn_id: [u8; 16],
        binding: ExactBinding,
        state: GcState,
    },
    /// Terminal: confirmed on two independent inspections that nothing was
    /// ever created at this slot. No `binding` field — audit finding 6
    /// ("nenhum binding fabricado"): the prior design forced a placeholder
    /// `ExactBinding` into this state purely to satisfy `Bound`'s shape;
    /// this variant has nothing to fabricate a placeholder for.
    Absent {
        slot: SlotId,
        txn_id: [u8; 16],
    },
}

impl GcEntry {
    #[must_use]
    pub fn slot(&self) -> &SlotId {
        match self {
            GcEntry::AwaitingInspection { slot, .. }
            | GcEntry::AbsentUnconfirmed { slot, .. }
            | GcEntry::Bound { slot, .. }
            | GcEntry::Absent { slot, .. } => slot,
        }
    }

    #[must_use]
    pub fn txn_id(&self) -> [u8; 16] {
        match self {
            GcEntry::AwaitingInspection { txn_id, .. }
            | GcEntry::AbsentUnconfirmed { txn_id, .. }
            | GcEntry::Bound { txn_id, .. }
            | GcEntry::Absent { txn_id, .. } => *txn_id,
        }
    }

    #[must_use]
    pub fn observation_complete_and_residual_zero(&self) -> bool {
        match self {
            GcEntry::AwaitingInspection { .. } | GcEntry::AbsentUnconfirmed { .. } => false,
            GcEntry::Bound { state, .. } => state.observation_complete_and_residual_zero(),
            GcEntry::Absent { .. } => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminalOutcome {
    Activated { generation: NonZeroU64 },
    Revoked { epoch: NonZeroU64 },
    Reactivated { epoch: NonZeroU64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalResult {
    pub txn_id: [u8; 16],
    pub outcome: TerminalOutcome,
    pub recorded_at: u64,
    /// Explicit retention: an unacked entry is never silently evicted, even
    /// once the list is at `MAX_RECENT_TERMINAL_RESULTS`. Audit finding 5
    /// ("sem FIFO silencioso"): a blind FIFO can drop a result a caller has
    /// not yet observed, which is indistinguishable from that result never
    /// having been recorded at all.
    pub acked: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TerminalPushError {
    #[error("txn_id already has a different recorded outcome")]
    OutcomeConflict,
    #[error("terminal-result retention is full and no acked entry can be evicted")]
    RetentionExhausted,
}

/// Idempotent-by-txn_id, bounded, fail-closed on conflict, ack-aware
/// retention. Re-recording an existing `txn_id` with the *same* outcome is
/// a no-op (lost-ack recovery re-derives the same terminal result and must
/// not grow the list or disturb its ack state). Re-recording an existing
/// `txn_id` with a *different* outcome is rejected — audit finding 5
/// ("conflito fail-closed"): two different outcomes for one txn_id is an
/// invariant violation, never something to silently paper over. When the
/// list is full, only an already-acked entry may be evicted to make room
/// (oldest-acked-first); if every entry is unacked, the push fails rather
/// than dropping one nobody has observed yet.
pub fn push_bounded_terminal(
    mut v: Vec<TerminalResult>,
    r: TerminalResult,
) -> Result<Vec<TerminalResult>, TerminalPushError> {
    if let Some(existing) = v.iter().find(|e| e.txn_id == r.txn_id) {
        if existing.outcome != r.outcome {
            return Err(TerminalPushError::OutcomeConflict);
        }
        return Ok(v);
    }
    if v.len() >= MAX_RECENT_TERMINAL_RESULTS {
        match v.iter().position(|e| e.acked) {
            Some(idx) => {
                v.remove(idx);
            }
            None => return Err(TerminalPushError::RetentionExhausted),
        }
    }
    v.push(r);
    Ok(v)
}

/// Marks `txn_id` acknowledged so it becomes eligible for eviction once the
/// retention list is full. A no-op if `txn_id` is not present.
pub fn ack_terminal(mut v: Vec<TerminalResult>, txn_id: [u8; 16]) -> Vec<TerminalResult> {
    for e in &mut v {
        if e.txn_id == txn_id {
            e.acked = true;
        }
    }
    v
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshSignerControlRecordV1 {
    pub identity: ControlIdentity,
    pub purpose: PurposeId,
    pub revision: u64,
    pub epoch_high_water: NonZeroU64,
    pub generation_high_water: NonZeroU64,
    pub authority: Authority,
    pub current_generation: Option<NonZeroU64>,
    pub live_generations: Vec<GenerationRecord>,
    pub pending_op: Option<PendingOp>,
    pub gc_pending: Vec<GcEntry>,
    pub recent_terminal_results: Vec<TerminalResult>,
}

impl MeshSignerControlRecordV1 {
    #[must_use]
    pub fn bootstrap(identity: ControlIdentity, purpose: PurposeId) -> Self {
        Self {
            identity,
            purpose,
            revision: INITIAL_REVISION,
            epoch_high_water: NonZeroU64::new(1).unwrap(),
            generation_high_water: NonZeroU64::new(1).unwrap(),
            authority: Authority::Empty,
            current_generation: None,
            live_generations: Vec::new(),
            pending_op: None,
            gc_pending: Vec::new(),
            recent_terminal_results: Vec::new(),
        }
    }

    /// Cap counts every slot the record is currently occupying: live
    /// generations, an in-flight pending op (0 or 1), and unresolved GC
    /// entries. `RevokeUrgent` is provably cap-neutral (see
    /// `transition::apply`'s doc comment) precisely because it trades one
    /// `pending_op` for at most one `gc_pending` entry. Deliberately
    /// excludes `recent_terminal_results`, which has its own separate,
    /// ack-gated retention cap (`MAX_RECENT_TERMINAL_RESULTS`) — audit
    /// finding 5 ("cap separado").
    #[must_use]
    pub fn cap_occupancy(&self) -> usize {
        self.live_generations.len()
            + usize::from(self.pending_op.is_some())
            + self
                .gc_pending
                .iter()
                .filter(|e| !e.observation_complete_and_residual_zero())
                .count()
    }
}
