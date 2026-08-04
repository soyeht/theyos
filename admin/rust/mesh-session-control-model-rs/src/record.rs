//! `MeshSignerControlRecordV1` — the single-record control state (GO
//! `aecc5ecf`, erratum1 `4d0e7e25`). One record per `(ControlIdentity,
//! PurposeId)`; no satellite files. This module holds only data + pure
//! invariant checks, no I/O.

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Channel {
    Dev,
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotId {
    pub identity_digest: [u8; 32],
    pub purpose: PurposeId,
    pub generation: NonZeroU64,
    pub txn_id: [u8; 16],
    pub backend_instance: BackendKind,
}

impl SlotId {
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
        s
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    Bound {
        slot: SlotId,
        txn_id: [u8; 16],
        binding: ExactBinding,
        state: GcState,
    },
}

impl GcEntry {
    #[must_use]
    pub fn slot(&self) -> &SlotId {
        match self {
            GcEntry::AwaitingInspection { slot, .. } | GcEntry::Bound { slot, .. } => slot,
        }
    }

    #[must_use]
    pub fn observation_complete_and_residual_zero(&self) -> bool {
        match self {
            GcEntry::AwaitingInspection { .. } => false,
            GcEntry::Bound { state, .. } => state.observation_complete_and_residual_zero(),
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
}

/// Idempotent bounded push: re-recording the same `txn_id` replaces the
/// prior entry instead of duplicating it (lost-ack recovery re-derives the
/// same terminal result and must not grow the list).
pub fn push_bounded_terminal(mut v: Vec<TerminalResult>, r: TerminalResult) -> Vec<TerminalResult> {
    v.retain(|e| e.txn_id != r.txn_id);
    v.push(r);
    if v.len() > MAX_RECENT_TERMINAL_RESULTS {
        v.remove(0);
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
    /// `pending_op` for at most one `gc_pending` entry.
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
