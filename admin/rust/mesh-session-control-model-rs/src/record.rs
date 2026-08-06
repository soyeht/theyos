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

/// Canonical, collision-resistant digest of `ControlIdentity`, with an
/// unambiguous preimage across its two variable-length string fields —
/// length-prefixed so `("ab", "c")` and `("a", "bc")` can never collide on
/// the *input* side. Round 6 terminology correction: this is not literally
/// "injective" (a fixed-width 256-bit digest over an unbounded input
/// domain cannot be, by pigeonhole) — it is collision-resistant (finding a
/// genuine collision is computationally infeasible), which is the property
/// actually being relied on here. This is what `SlotId::identity_digest`
/// must always be derived from (audit finding 4: generation/slot must be
/// *derived*, never caller-supplied).
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
    /// Round 6, item 3: the prior concatenation-based encoding reached 139
    /// bytes for a real input — over the keystore integration's own tested
    /// bound (128 bytes; `admin/rust/keystore-rs/src/opaque_p256.rs`,
    /// commit `91bb74f6`, test `slot_id_is_fixed_width_and_injective`) —
    /// and was not fixed-width.
    ///
    /// Correction mid-fix (kiana): the first draft of this fix copied that
    /// commit's own `"p256.v1."` string prefix literally. That was wrong —
    /// `p256.v1.<...>` is `Slot::account()`'s output, a keystore-*internal*
    /// coordinate that re-hashes `(purpose, label)` on its own side of the
    /// integration boundary. This crate produces the *label* a real
    /// integration hands *to* `Slot::new` — a different value in a
    /// different namespace, which must never collide with or be mistaken
    /// for the keystore's own internal `account()` string. Hence the
    /// distinct `"mesh-slot.v1."` prefix below, not `"p256.v1."` (which
    /// would also be a category error for the `TpmSealedSoftware`/`File`
    /// backend kinds this type covers and P-256/Secure-Enclave does not).
    ///
    /// What *is* adopted from that commit is the structural technique: a
    /// BLAKE3 digest over every field, each preceded by an 8-byte
    /// little-endian length prefix — an unambiguous preimage across
    /// variable-length fields (the same technique `identity_digest`
    /// already uses with SHA-256/big-endian; little-endian and BLAKE3 here
    /// specifically to match this cited integration point). The result is
    /// collision-resistant and has an unambiguous preimage, not literally
    /// injective — a fixed-width 256-bit digest over an unbounded input
    /// domain cannot be, by pigeonhole (round 6 terminology correction:
    /// the prior doc comment here overclaimed "injective").
    #[must_use]
    pub fn canonical_id(&self) -> String {
        let purpose_str = match self.purpose {
            PurposeId::MeshSession => "mesh-session",
            PurposeId::RosterSync => "roster-sync",
        };
        let backend_str = match self.backend_instance {
            BackendKind::SecureEnclave => "se",
            BackendKind::TpmSealedSoftware => "tpm",
            BackendKind::File => "file",
        };
        let mut hasher = blake3::Hasher::new();
        for field in [
            self.identity_digest.as_slice(),
            purpose_str.as_bytes(),
            &self.generation.get().to_le_bytes(),
            &self.txn_id,
            backend_str.as_bytes(),
        ] {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        format!("mesh-slot.v1.{}", hasher.finalize().to_hex())
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

    /// Round 6, item (new) 4: `store::FileBackedStore::load_canonical` used
    /// to only validate CBOR shape plus this store's own identity/purpose
    /// binding — never the record's own SEMANTIC invariants. A
    /// hand-corrupted (but still CBOR-canonical, still identity/purpose
    /// correct) file on disk could satisfy both of those checks and still
    /// describe a state `transition::apply` itself could never produce —
    /// `Active` authority with no `current_generation`, two live
    /// generations sharing a number, a `KeyObserved` pending op with no
    /// binding, a terminal result whose `outcome` doesn't match its own
    /// `request`'s shape. Loading such a record as `LoadOutcome::Exact`
    /// would hand every caller a state the rest of this crate's logic
    /// implicitly assumes can never happen. `load_canonical` treats a
    /// failure here the same as a CBOR-level defect (`LoadOutcome::Corrupt`)
    /// — this crate has no auto-recovery path for either case, so a
    /// distinct "quarantine" outcome is not yet load-bearing.
    #[must_use]
    pub fn invariants_hold(&self) -> bool {
        // Active <=> current_generation is Some, and if Some it must name
        // an actual live generation.
        if matches!(self.authority, Authority::Active) != self.current_generation.is_some() {
            return false;
        }
        if let Some(cur) = self.current_generation {
            if !self.live_generations.iter().any(|g| g.generation == cur) {
                return false;
            }
            if cur > self.generation_high_water {
                return false;
            }
        }
        // No two live_generations share a generation number, and none
        // exceeds the high-water mark. Round 6, wave 4: high_water is now
        // RESERVED at Intent time (see `transition`'s IntentRecorded /
        // ReactivateFromRevoked arms), so a not-yet-activated pending op's
        // own generation (checked further below) is also always
        // `<= generation_high_water`, never `high_water + 1` — the prior
        // version of this check used the old (pre-reservation) assumption
        // and rejected every legitimate in-flight rotation/reactivation.
        let mut seen_generations = std::collections::HashSet::new();
        for g in &self.live_generations {
            if !seen_generations.insert(g.generation) || g.generation > self.generation_high_water {
                return false;
            }
            // Round 6, wave 4: a live generation's own binding must be
            // for the slot it claims -- catches a "foreign" binding
            // swapped onto an unrelated live generation.
            let expected_slot = SlotId {
                identity_digest: identity_digest(&self.identity),
                purpose: self.purpose,
                generation: g.generation,
                txn_id: g.binding.slot.txn_id,
                backend_instance: g.binding.slot.backend_instance,
            };
            if g.binding.slot != expected_slot {
                return false;
            }
        }
        // No two slots (across live_generations, gc_pending, and any
        // pending_op together) coincide — a legitimate history never lets
        // a slot be both live and pending GC at once (see
        // `transition::slot_collides_with_unresolved_gc`).
        let mut seen_slots = std::collections::HashSet::new();
        for g in &self.live_generations {
            if !seen_slots.insert(g.binding.slot.canonical_id()) {
                return false;
            }
        }
        for e in &self.gc_pending {
            if !seen_slots.insert(e.slot().canonical_id()) {
                return false;
            }
            // Round 6, wave 4: a Bound entry's own binding must be for
            // the slot the entry itself claims -- catches a "foreign" GC
            // binding whose .slot disagrees with the key entry.slot()
            // names.
            if let GcEntry::Bound { slot, binding, .. } = e
                && binding.slot != *slot
            {
                return false;
            }
            // Round 6, wave 6: internal consistency (binding.slot ==
            // entry.slot()) is not enough on its own -- it says nothing
            // about whether the slot actually belongs to THIS record at
            // all. Without this, a GC entry naming a completely different
            // identity's slot (but internally self-consistent) still
            // loaded as Exact, and a real gc_worker_tick would then call
            // the backend against a foreign slot with no relationship to
            // this record whatsoever.
            let slot = e.slot();
            if e.txn_id() != slot.txn_id
                || slot.identity_digest != identity_digest(&self.identity)
                || slot.purpose != self.purpose
                || slot.generation > self.generation_high_water
            {
                return false;
            }
        }
        // pending_op must belong to THIS record (purpose), its
        // canonical_slot must be exactly what the derivation formula
        // produces from this record's own identity/purpose/generation/
        // txn_id/backend (never a foreign slot), its binding must be
        // present iff phase is KeyObserved (and for that binding, for
        // the pending op's own slot), its generation must not exceed the
        // high-water mark, its own slot must not collide with a live or
        // gc_pending slot, and its kind must be the one the closed
        // authority matrix (round 4, item 2) actually allows for the
        // record's current authority.
        if let Some(p) = &self.pending_op {
            if p.purpose != self.purpose {
                return false;
            }
            // Round 6, wave 6: this must read `p.txn_id` -- PendingOp's
            // own independent field -- not `p.canonical_slot.txn_id`.
            // Building `expected_slot` from the very field being checked
            // made the comparison tautological on that dimension: it
            // could never catch a canonical_slot whose txn_id disagreed
            // with the pending op's own txn_id.
            let expected_slot = SlotId {
                identity_digest: identity_digest(&self.identity),
                purpose: self.purpose,
                generation: p.generation,
                txn_id: p.txn_id,
                backend_instance: p.backend,
            };
            if p.canonical_slot != expected_slot {
                return false;
            }
            // epoch is set once, at Intent/Reactivate time, to whatever
            // epoch_high_water was at that moment -- and nothing can bump
            // epoch_high_water again without also clearing or replacing
            // pending_op in that SAME transition (RevokeUrgent,
            // ReactivateFromRevoked). So a live pending_op's epoch must
            // always equal the record's current epoch_high_water exactly.
            if p.epoch != self.epoch_high_water {
                return false;
            }
            let binding_matches_phase = match p.phase {
                PendingPhase::Intent => p.binding.is_none(),
                PendingPhase::KeyObserved => p.binding.is_some(),
            };
            if !binding_matches_phase {
                return false;
            }
            if let Some(b) = &p.binding
                && b.slot != p.canonical_slot
            {
                return false;
            }
            if p.generation > self.generation_high_water {
                return false;
            }
            if !seen_slots.insert(p.canonical_slot.canonical_id()) {
                return false;
            }
            let kind_matches_authority = matches!(
                (&self.authority, p.kind),
                (Authority::Empty, PendingOpKind::Create)
                    | (Authority::Active, PendingOpKind::RoutineRotate)
                    | (Authority::Revoked { .. }, PendingOpKind::Reactivate)
            );
            if !kind_matches_authority {
                return false;
            }
        }
        // recent_terminal_results: no two entries share a txn_id, and the
        // list never exceeds its own bounded-retention cap -- both are
        // supposed to be structurally guaranteed by `push_bounded_terminal`/
        // `push_bounded_terminal_urgent`, never independently violable.
        if self.recent_terminal_results.len() > MAX_RECENT_TERMINAL_RESULTS {
            return false;
        }
        let mut seen_terminal_txns = std::collections::HashSet::new();
        for r in &self.recent_terminal_results {
            if !seen_terminal_txns.insert(r.txn_id) {
                return false;
            }
            // Every terminal result's outcome must match its own
            // request's shape — the two are always written together by
            // `apply`, never independently.
            let consistent = match (&r.outcome, &r.request) {
                (
                    TerminalOutcome::Activated { generation: og },
                    TerminalRequestFingerprint::Activate { generation: rg, .. },
                ) => og == rg,
                (TerminalOutcome::Revoked { .. }, TerminalRequestFingerprint::Revoke { .. }) => {
                    true
                }
                (
                    TerminalOutcome::Reactivated { .. },
                    TerminalRequestFingerprint::Reactivate { .. },
                ) => true,
                _ => false,
            };
            if !consistent {
                return false;
            }
        }
        true
    }
}
