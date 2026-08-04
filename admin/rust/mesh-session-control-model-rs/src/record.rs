//! `MeshSignerControlRecordV1` — the single-record control state (GO
//! `aecc5ecf`, erratum1 `4d0e7e25`). One record per `(ControlIdentity,
//! PurposeId)`; no satellite files. This module holds only data + pure
//! invariant checks, no I/O.
//!
//! Fifth-round fix (wire-shape closure, verified with an executable probe
//! against ciborium before touching this file): `Vec<u8>`/`[u8; N]` fields
//! serialize as CBOR arrays of individual integers by default, not
//! byte-strings (`bstr`) — confirmed empirically (`83 01 02 03`, a 3-item
//! array, not `43 01 02 03`, a 3-byte string). Every field that represents
//! wire byte-string content now carries `#[serde(with = "serde_bytes")]`,
//! which the same probe confirmed produces the correct `bstr` encoding for
//! both `Vec<u8>` and fixed-size arrays. Every struct (and every enum with
//! at least one struct-like variant) now carries
//! `#[serde(deny_unknown_fields)]`: without it, an extra/unknown CBOR key
//! survived `store::canonicalize_value`'s round-trip check unchanged (it is
//! preserved faithfully on the generic `Value` tree), so bytes containing
//! one were wrongly accepted as canonical — then silently dropped by the
//! typed decode, meaning `LoadOutcome::Exact` implied a closure the schema
//! never actually enforced, and a "stabilization" rewrite of such a record
//! would silently strip the key while its own revision-equality check
//! claimed byte-for-byte identity. `Channel` now serializes as lowercase
//! (`"dev"`/`"release"`), matching the frozen wire schema — the derive
//! default would have emitted `"Dev"`/`"Release"`.
//!
//! Successor to the generation audited at commit `d4ecb658` (NO-GO). Every
//! type change here traces to a specific finding from that audit — see the
//! doc comment on each item.

use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

pub const INITIAL_REVISION: u64 = 0;
pub const MAX_RECENT_TERMINAL_RESULTS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(rename_all = "lowercase")]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct SlotId {
    #[serde(with = "serde_bytes")]
    pub identity_digest: [u8; 32],
    pub purpose: PurposeId,
    pub generation: NonZeroU64,
    #[serde(with = "serde_bytes")]
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
#[serde(deny_unknown_fields)]
pub struct ExactBinding {
    pub slot: SlotId,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub attributes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingOp {
    #[serde(with = "serde_bytes")]
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
#[serde(deny_unknown_fields)]
pub struct GenerationRecord {
    pub generation: NonZeroU64,
    pub delegation: Delegation,
    pub binding: ExactBinding,
    pub not_after: u64,
}

/// `MeshSessionDelegation` §5 of the frozen wire schema
/// (`daisy-bsessao-v6.7343d075…` + `daisy-bsessao-v6-erratum1.63222d40…`,
/// self-hash verified). Second-round correction: the prior shape here
/// (`role: String`, no `version`/`kind`/`transcript_kinds`/`serial`) was
/// modeled from prose a second time despite this crate's own history of
/// exactly that failure mode — its doc comment even claimed "delegations
/// never carry a frame kind," conflating the *frame*-level `kind`
/// (FinalConfirm/Activate/ActivateAck's own field, still never embedded
/// alongside a delegation) with the *delegation object's own* `kind`
/// (`"soyeht/mesh-session/delegation/v1"`), which the frozen schema does
/// carry — a distinct field, orthogonal to any frame's `kind`. `roles` is
/// genuinely plural at the delegation level (a delegation may authorize
/// more than one role) even though each individual Proof-R/Proof-I frame
/// still asserts a single `role`. `delegated_pub`/`sig` are fixed-size on
/// the wire (`bstr .size 33`/`.size 64` — P-256 compressed public key and
/// ECDSA signature) but modeled as `Vec<u8>` rather than `[u8; N]` purely
/// because serde's derive does not cover fixed arrays past length 32
/// without an extra dependency; the length is a wire fact this crate does
/// not itself enforce via the type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub version: u64,
    /// The delegation object's own schema kind
    /// (`"soyeht/mesh-session/delegation/v1"`) — never a frame `kind`.
    pub kind: String,
    pub domain: String,
    pub hh_id: String,
    pub delegator_m_id: String,
    #[serde(with = "serde_bytes")]
    pub delegator_cert_fingerprint: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub delegated_pub: Vec<u8>,
    pub delegated_key_id: String,
    pub profile: String,
    /// Session-transcript-kind vocabulary this delegation is scoped to.
    /// This crate models the field for schema fidelity but does not (and
    /// has no data to) validate its contents against a live transcript —
    /// that cross-check belongs to the mesh-session protocol layer, not
    /// this control-record model.
    pub transcript_kinds: Vec<String>,
    pub roles: Vec<String>,
    pub channel: Channel,
    /// Informative only per the frozen spec ("Serial é informativo.
    /// checkpoint_floor não é autoridade.") — not itself a source of
    /// authority, so `validate_full_binding` does not gate on its value.
    pub serial: u64,
    pub not_before: u64,
    pub not_after: u64,
    #[serde(with = "serde_bytes")]
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
#[serde(deny_unknown_fields)]
pub enum GcEntry {
    AwaitingInspection {
        slot: SlotId,
        #[serde(with = "serde_bytes")]
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
        #[serde(with = "serde_bytes")]
        txn_id: [u8; 16],
    },
    Bound {
        slot: SlotId,
        #[serde(with = "serde_bytes")]
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
        #[serde(with = "serde_bytes")]
        txn_id: [u8; 16],
    },
    /// Terminal-for-automation, not clean: the backend reported
    /// `InspectOutcome::Conflict` (more than one candidate observed at a
    /// slot that should hold at most one item). Audit finding (round 4,
    /// item 6): a prior version treated `Conflict` identically to
    /// `Indeterminate` — added to an in-memory, per-tick-only set and
    /// silently discarded at the end of every tick, so an inherent
    /// ambiguity was retried forever with zero durable trace it was ever
    /// observed. This variant persists it in the record itself, excluded
    /// from automatic re-selection like `GcState::Quarantine`, awaiting
    /// administrative resolution — never auto-resolved, never fabricating
    /// a single binding out of an ambiguous read.
    InspectionConflict {
        slot: SlotId,
        #[serde(with = "serde_bytes")]
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
            | GcEntry::Absent { slot, .. }
            | GcEntry::InspectionConflict { slot, .. } => slot,
        }
    }

    #[must_use]
    pub fn txn_id(&self) -> [u8; 16] {
        match self {
            GcEntry::AwaitingInspection { txn_id, .. }
            | GcEntry::AbsentUnconfirmed { txn_id, .. }
            | GcEntry::Bound { txn_id, .. }
            | GcEntry::Absent { txn_id, .. }
            | GcEntry::InspectionConflict { txn_id, .. } => *txn_id,
        }
    }

    #[must_use]
    pub fn observation_complete_and_residual_zero(&self) -> bool {
        match self {
            GcEntry::AwaitingInspection { .. } | GcEntry::AbsentUnconfirmed { .. } => false,
            GcEntry::Bound { state, .. } => state.observation_complete_and_residual_zero(),
            GcEntry::Absent { .. } => true,
            // Not clean -- ambiguous, needs administrative review -- but
            // also not auto-retried; see the exclusion in
            // gc::gc_worker_tick's selection filter.
            GcEntry::InspectionConflict { .. } => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TerminalOutcome {
    Activated { generation: NonZeroU64 },
    Revoked { epoch: NonZeroU64 },
    Reactivated { epoch: NonZeroU64 },
}

/// The exact input parameters that produced a `TerminalResult`, not just
/// which transition kind it was. Audit finding (round 5, item D9): the
/// prior idempotent-replay check compared only the *outcome variant*
/// (`Revoked{..}` via a wildcard on fields) — a genuinely different request
/// reusing the same `txn_id` (e.g. a second `RevokeUrgent` with a
/// *different* `reason`) was silently accepted as "the same replay."
/// Comparing the full request closes that: only a byte-for-byte identical
/// request is treated as idempotent; anything else is a reused txn_id,
/// fail-closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TerminalRequestFingerprint {
    Revoke {
        reason: RevocationReason,
    },
    Reactivate {
        #[serde(with = "serde_bytes")]
        next_txn_id: [u8; 16],
        backend: BackendKind,
    },
    Activate {
        generation: NonZeroU64,
        // Boxed -- `Delegation` is ~320 bytes (several Strings/Vecs),
        // dwarfing the other variants (~17 bytes) and tripping clippy's
        // large_enum_variant lint on every `TerminalRequestFingerprint` by
        // value (e.g. inside `TerminalResult`).
        delegation: Box<Delegation>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalResult {
    #[serde(with = "serde_bytes")]
    pub txn_id: [u8; 16],
    pub outcome: TerminalOutcome,
    pub request: TerminalRequestFingerprint,
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
    #[error("txn_id already has a different recorded request")]
    RequestConflict,
    #[error("terminal-result retention is full and no acked entry can be evicted")]
    RetentionExhausted,
}

fn push_bounded_terminal_impl(
    mut v: Vec<TerminalResult>,
    r: TerminalResult,
    force: bool,
) -> Result<Vec<TerminalResult>, TerminalPushError> {
    if let Some(existing) = v.iter().find(|e| e.txn_id == r.txn_id) {
        if existing.request != r.request {
            return Err(TerminalPushError::RequestConflict);
        }
        return Ok(v);
    }
    if v.len() >= MAX_RECENT_TERMINAL_RESULTS {
        match v.iter().position(|e| e.acked) {
            Some(idx) => {
                v.remove(idx);
            }
            None if force => {
                v.remove(0);
            }
            None => return Err(TerminalPushError::RetentionExhausted),
        }
    }
    v.push(r);
    Ok(v)
}

/// Idempotent-by-`(txn_id, request)`, bounded, fail-closed on conflict,
/// ack-aware retention. Re-recording an existing `txn_id` with the *same*
/// request is a no-op (lost-ack recovery re-derives the same terminal
/// result and must not grow the list or disturb its ack state).
/// Re-recording an existing `txn_id` with a *different* request is
/// rejected — two different requests sharing one txn_id is an invariant
/// violation (reuse), never something to silently paper over. When the
/// list is full, only an already-acked entry may be evicted to make room
/// (oldest-acked-first); if every entry is unacked, the push fails rather
/// than dropping one nobody has observed yet.
pub fn push_bounded_terminal(
    v: Vec<TerminalResult>,
    r: TerminalResult,
) -> Result<Vec<TerminalResult>, TerminalPushError> {
    push_bounded_terminal_impl(v, r, false)
}

/// Same idempotent/conflict semantics as `push_bounded_terminal`, but when
/// retention is exhausted with no acked entry to evict, force-evicts the
/// oldest entry regardless of ack state. Used only by `RevokeUrgent` (round
/// 5, item D10): an urgent, security-critical revoke must never be
/// blockable by unrelated terminal-result bookkeeping capacity — this
/// makes that structural, not just documented.
pub fn push_bounded_terminal_urgent(
    v: Vec<TerminalResult>,
    r: TerminalResult,
) -> Result<Vec<TerminalResult>, TerminalPushError> {
    push_bounded_terminal_impl(v, r, true)
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
#[serde(deny_unknown_fields)]
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
