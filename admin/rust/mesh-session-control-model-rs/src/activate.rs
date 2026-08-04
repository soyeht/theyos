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
use crate::locks::SignGuard;
use crate::record::{
    GenerationRecord, MeshSignerControlRecordV1, PendingPhase, TerminalRequestFingerprint,
};
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
    //
    // Round 6 fix: this used to match on `existing.outcome`'s *variant*
    // alone (`TerminalOutcome::Activated { .. }`, a wildcard on
    // `generation`) and return `Ok(base)` unconditionally on a match --
    // reopening the exact D9 bug this wrapper's own pre-check was supposed
    // to close, just one layer up: ANY existing `Activated` result for
    // this txn_id short-circuited to "same replay," even for a request
    // with a completely different `delegation`. `apply`'s own
    // `idempotent_replay` never has this gap because it always compares
    // the full `TerminalRequestFingerprint` -- this wrapper must do the
    // same. `expected_generation` isn't available here on a true replay
    // (pending_op is already gone), so the request is reconstructed from
    // what `existing.request` itself records and compared field-for-field
    // against the caller's actual `delegation`.
    if let Some(existing) = base
        .recent_terminal_results
        .iter()
        .find(|r| r.txn_id == expected_txn_id)
    {
        return match &existing.request {
            TerminalRequestFingerprint::Activate {
                delegation: existing_delegation,
                ..
            } if **existing_delegation == delegation => Ok(base),
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
    // Captured immediately before the slow roster query, used only to know
    // what to pass as `expected_revision` to `acquire_currency_lease` once
    // the slow validation below succeeds.
    let roster_revision_before = roster.currency_revision(&delegation.delegator_m_id);
    validate_full_binding::<P>(&generation_record, &ctx, policy, roster, sig, now)?;

    // Round 6 fix (item 3, corrected in wave 6): a bare revision-number
    // re-check (this crate's own first attempt) still left a real gap —
    // the roster could change in the instants between that re-check and
    // the disk write actually going durable, since a NUMBER cannot BLOCK
    // anything. `acquire_currency_lease` is atomic (checks
    // `roster_revision_before` against the CURRENT revision and only
    // grants a lease under the roster implementation's own internal lock)
    // and, unlike a number, is a held object: for as long as `_lease`
    // stays alive here, a real implementation genuinely blocks its own
    // conflicting mutation for this machine — not just fails to notice
    // one. Acquired only now, after all slow I/O (`query_machine_currency`
    // above, `backend.load_exact` earlier) has already completed with no
    // lease held; dropped as soon as this function returns, whether the
    // commit below succeeds or fails.
    let _lease = roster
        .acquire_currency_lease(&delegation.delegator_m_id, roster_revision_before)
        .map_err(|_| ActivateError::Validation(ValidationError::RosterChangedDuringActivation))?;

    // Reacquire only now, and build against a fresh read taken under that
    // same guard (`commit_built_privileged`) — apply()'s own exact-token
    // check catches any divergence against this snapshot (e.g. an urgent
    // revoke that ran while the slow I/O above was in flight).
    let new = cell
        .commit_built_privileged(
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
///
/// Round 6 fix (item 5): this used to validate only the *stored*
/// `GenerationRecord` — the delegation/binding fields frozen at activation
/// time — never re-confirming against the backend that the physical key
/// itself is still actually there and still matches. A key replaced or
/// deleted outside this record's own state machine (e.g. direct keychain
/// tampering, an unrelated process racing the same slot) went completely
/// undetected: the control record still said "live," `sig.verify` still
/// passed against the recorded (not the physical) public key, and nothing
/// here ever called `backend.load_exact`. Every live generation's binding
/// is now reconfirmed the same way `activate_from_key_observed` confirms a
/// pending one, before trusting it.
pub fn revalidate_on_load<P: PurposeMarker>(
    record: &MeshSignerControlRecordV1,
    backend: &dyn SecretBackend,
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
        match backend.load_exact(&g.binding.slot, &g.binding.public_key) {
            LoadExactOutcome::Ready(observed) if observed == g.binding => {}
            _ => return Err(ValidationError::PhysicalKeyNotConfirmed),
        }
        validate_full_binding::<P>(g, &ctx, policy, roster, sig, now)?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum LoadRevalidatedError {
    #[error("store has no record for this identity")]
    NoRecord,
    #[error("record is corrupt")]
    RecordCorrupt,
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

fn load_and_revalidate<P: PurposeMarker>(
    cell: &ControlRecordCell,
    backend: &dyn SecretBackend,
    policy: &DelegationPolicy,
    roster: &dyn RosterLookup,
    sig: &dyn SignatureVerifier,
    now: u64,
) -> Result<MeshSignerControlRecordV1, LoadRevalidatedError> {
    let record = match cell.load_canonical() {
        LoadOutcome::Exact(r) => *r,
        LoadOutcome::Missing => return Err(LoadRevalidatedError::NoRecord),
        LoadOutcome::Corrupt => return Err(LoadRevalidatedError::RecordCorrupt),
    };
    revalidate_on_load::<P>(&record, backend, policy, roster, sig, now)?;
    Ok(record)
}

/// Raw point-in-time snapshot: genuinely revalidated at the instant it
/// returns, and stale from any instant after — no lock is held past this
/// call, so a `RevokeUrgent` may commit immediately afterward.
///
/// Round 6, wave 8 (CFX-1): this is now `pub(crate)`, not `pub`. It was
/// public in wave 7 on the theory that a plain snapshot is fine as long
/// as its doc comment says "reporting only, never authorizes a sign." A
/// doc comment is not a control — this crate has now made that same
/// mistake twice (see `ControlRecordCell::load_canonical`, closed in wave
/// 7 for exactly the same reason), and a caller who wanted a record to
/// act on had no reason to look past a public function that returns one.
///
/// The only door onto it from outside this crate is now this
/// `test-support`-gated one, so a plain `cargo build` exposes no way to
/// obtain a detachable validated record at all. Production callers get
/// `with_authorized_use`, which never hands one back.
///
/// (There is deliberately no `pub(crate)` non-test twin: nothing inside
/// this crate wants a bare revalidated snapshot either — the internal
/// consumer is `load_and_revalidate`, called by `with_authorized_use`
/// under the locks. An unused `pub(crate)` wrapper would just be dead
/// code in the default build.)
#[cfg(feature = "test-support")]
pub fn load_revalidated_report_for_test<P: PurposeMarker>(
    cell: &ControlRecordCell,
    backend: &dyn SecretBackend,
    policy: &DelegationPolicy,
    roster: &dyn RosterLookup,
    sig: &dyn SignatureVerifier,
    now: u64,
) -> Result<MeshSignerControlRecordV1, LoadRevalidatedError> {
    load_and_revalidate::<P>(cell, backend, policy, roster, sig, now)
}

/// # The one global lock order in this crate
///
/// Round 6, wave 8 (CFX-3): the previous wave introduced a genuine
/// ABBA deadlock cycle. `activate_from_key_observed` takes the roster
/// currency lease and *then* the cell's mutation guard; the guarded-load
/// it added took the cell's `SignGuard` and *then* queried the roster
/// (inside `validate_full_binding`). Two callers, one of each, could each
/// hold what the other needed. Nothing about either function read as
/// wrong in isolation — the cycle only exists between them.
///
/// The single order every path in this crate must obey, from here on:
///
/// 1. **All slow I/O with NO lock of any kind held** — `backend.load_exact`,
///    `roster.query_machine_currency`, `sig.verify`. This is also what
///    keeps an urgent `RevokeUrgent` from ever queueing behind unrelated
///    slow work (the round 4/5 property).
/// 2. **Then** the roster currency lease (`acquire_currency_lease`).
/// 3. **Then** the cell's own guard (`acquire_for_sign`/`acquire_for_mutation`).
/// 4. Under both, re-read cheaply and compare the exact revision/binding
///    against what was actually validated in step 1.
/// 5. Run only the short authorized operation.
/// 6. Release in reverse.
///
/// **Never cell → roster.** A cell guard must never be held across any
/// roster call.
///
/// A narrow, non-`Clone`, closure-scoped view of a record that has just
/// been revalidated and re-confirmed unchanged under both locks.
///
/// Round 6, wave 8 (CFX-1/CFX-4): this replaces a `RevalidatedGuard` that
/// handed back `&MeshSignerControlRecordV1` from a `record()` accessor.
/// That design claimed linearized authority it did not have:
/// `MeshSignerControlRecordV1` derives `Clone`, so
/// `let r = guard.record().clone(); drop(guard);` detached a fully
/// "validated" snapshot from the guard that was the only thing making it
/// true — the exact defect the guard was introduced to close, reachable
/// in two lines. Making the *guard* non-`Clone` was worthless while the
/// thing it guarded was `Clone`.
///
/// So this type deliberately exposes **no record and no raw signer** —
/// only the few narrow facts an authorized use site actually needs, all
/// borrowed for strictly less than the closure's own lifetime, so nothing
/// authority-bearing can outlive the locks. Copying a slot id or a public
/// key out is harmless: those are locators, not authority. What can no
/// longer escape is a whole record labelled "revalidated."
///
/// ## What this does and does not enforce
///
/// It *mechanically* prevents detaching authority from the locks. It does
/// **not** mechanically bound how long the caller's closure runs — no
/// type can force that on an arbitrary `FnOnce`. Keeping the closure
/// short is a documented caller obligation, stated here rather than
/// claimed as a control (a prohibition without a mechanism is not a
/// control). The closure form is still strictly better than the RAII
/// handle it replaces: a returned guard could be parked in a struct and
/// held indefinitely; a closure cannot outlive this call.
pub struct AuthorizedUse<'a> {
    identity: &'a crate::record::ControlIdentity,
    purpose: crate::record::PurposeId,
    generation: std::num::NonZeroU64,
    binding: &'a crate::record::ExactBinding,
}

impl AuthorizedUse<'_> {
    #[must_use]
    pub fn identity(&self) -> &crate::record::ControlIdentity {
        self.identity
    }

    #[must_use]
    pub fn purpose(&self) -> crate::record::PurposeId {
        self.purpose
    }

    /// The current generation this use is attributed to.
    #[must_use]
    pub fn generation(&self) -> std::num::NonZeroU64 {
        self.generation
    }

    /// Where the key lives and which public key identifies it — a
    /// locator for the actual sign call a real backend would make, not
    /// the private key and not the record.
    #[must_use]
    pub fn binding(&self) -> &crate::record::ExactBinding {
        self.binding
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizedUseError {
    #[error(transparent)]
    Load(#[from] LoadRevalidatedError),
    #[error("record has no current generation to authorize a use against")]
    NoCurrentGeneration,
    #[error(transparent)]
    RosterChanged(#[from] crate::validator::RosterChanged),
    #[error(
        "record changed between revalidation and acquiring the locks -- the validated snapshot is stale and must not authorize anything"
    )]
    RecordChangedDuringAcquire,
}

/// Runs `use_` against a record that is revalidated **and still provably
/// unchanged** at the moment the closure runs, under both the roster
/// currency lease and the cell's `SignGuard` — acquired in the one global
/// order documented on `AuthorizedUse`, after all slow I/O has already
/// completed with nothing held.
///
/// This is the only sanctioned way to perform an action whose correctness
/// depends on the delegation still being live (a signature, a forward).
/// While the closure runs, a concurrent `RevokeUrgent` genuinely blocks on
/// `acquire_for_mutation` and a conflicting roster-side change genuinely
/// blocks on the lease — so no such change can linearize before the use,
/// and the use cannot act on a snapshot that a change already invalidated.
pub fn with_authorized_use<P: PurposeMarker, R>(
    cell: &ControlRecordCell,
    backend: &dyn SecretBackend,
    policy: &DelegationPolicy,
    roster: &dyn RosterLookup,
    sig: &dyn SignatureVerifier,
    now: u64,
    use_: impl FnOnce(&AuthorizedUse<'_>) -> R,
) -> Result<R, AuthorizedUseError> {
    // ---- step 1: everything slow, with NO lock of any kind held ----
    //
    // A cheap unguarded read first, only to learn which delegator the
    // current generation belongs to -- `currency_revision` needs that id,
    // and it must be sampled BEFORE the slow roster query for the
    // comparison in step 2 to mean anything.
    let peek = match cell.load_canonical() {
        LoadOutcome::Exact(r) => *r,
        LoadOutcome::Missing => return Err(LoadRevalidatedError::NoRecord.into()),
        LoadOutcome::Corrupt => return Err(LoadRevalidatedError::RecordCorrupt.into()),
    };
    let delegator_m_id = current_generation_of(&peek)
        .ok_or(AuthorizedUseError::NoCurrentGeneration)?
        .delegation
        .delegator_m_id
        .clone();
    let roster_revision_before = roster.currency_revision(&delegator_m_id);

    let validated = load_and_revalidate::<P>(cell, backend, policy, roster, sig, now)?;

    // ---- step 2: roster lease, THEN cell guard. Never the reverse. ----
    let _lease = roster.acquire_currency_lease(&delegator_m_id, roster_revision_before)?;
    let _sign: SignGuard<'_> = cell.acquire_for_sign();

    // ---- step 3: cheap re-read under both, compared exactly ----
    //
    // `validated` was produced with nothing held, so anything could have
    // committed between then and the two acquisitions above. Comparing the
    // whole record (not just the revision) is the strongest available
    // check and costs one cheap local read.
    let fresh = match cell.load_canonical() {
        LoadOutcome::Exact(r) => *r,
        LoadOutcome::Missing => return Err(LoadRevalidatedError::NoRecord.into()),
        LoadOutcome::Corrupt => return Err(LoadRevalidatedError::RecordCorrupt.into()),
    };
    if fresh != validated {
        return Err(AuthorizedUseError::RecordChangedDuringAcquire);
    }
    let current = current_generation_of(&fresh).ok_or(AuthorizedUseError::NoCurrentGeneration)?;

    // ---- step 4: only the short authorized operation ----
    Ok(use_(&AuthorizedUse {
        identity: &fresh.identity,
        purpose: fresh.purpose,
        generation: current.generation,
        binding: &current.binding,
    }))
    // ---- step 5: `_sign` then `_lease` drop here, in reverse order ----
}

fn current_generation_of(record: &MeshSignerControlRecordV1) -> Option<&GenerationRecord> {
    let g = record.current_generation?;
    record.live_generations.iter().find(|lg| lg.generation == g)
}
