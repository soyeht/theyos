//! GC worker tick.
//!
//! Successor to the generation audited at commit `d4ecb658` (NO-GO,
//! finding 6). Every change below traces to that audit:
//! - `gc_serial` is now a real, held guard (`GcSerialLock::acquire`) for
//!   the whole tick, not an out-of-band caller responsibility the function
//!   signature didn't even mention.
//! - the prior version read the record under `acquire_for_mutation`, then
//!   *dropped that guard* before calling `store.replace_exact` inside
//!   `commit_transition` — the actual write happened with **no** access
//!   guard held at all, defeating the whole single-mutable-path premise.
//!   Every write here now happens inside its own freshly acquired,
//!   continuously-held `MutateGuard`: read-fresh, build, write, all in one
//!   section (turnstile→access), then release — with the slow `backend`
//!   call always happening strictly *between* two such sections, holding
//!   neither.
//! - `MayHaveTakenEffect` is no longer "closed" by a plain reread that
//!   merely looks plausible: recovery retries the *identical* bytes against
//!   the *identical* `expected_revision`, under the *same* continuously
//!   held guard, until the store returns `Committed` — or, if a retry
//!   itself reports `KnownNoEffect`, that is only trustworthy as proof of
//!   the earlier attempt's own success because nothing else could have
//!   raced in while this guard was held (see `commit_new_bytes`).
//! - one entry reporting `observation_complete: false` (indeterminate) no
//!   longer aborts the whole tick (the old `break` exited the outer loop);
//!   it is set aside for the rest of *this* tick only and every other
//!   unresolved entry is still processed.
//! - a genuine backend mismatch (`GcReport::mismatch`) now routes to
//!   `GcState::Quarantine`, not silently treated as an ordinary retry.
//!
//! Round 5 fix (items A3/D11): `store`/`locks`/`gc_serial` used to be three
//! independent parameters a caller assembled itself — which meant a caller
//! external to this crate needed `ControlRecordCell` to hand back a raw
//! store (defeating A3's closure of that surface) and could construct its
//! own, unrelated `GcSerialLock` not actually tied to the record it was
//! ticking (defeating D11's serialization guarantee). Every entry point
//! here now takes `&ControlRecordCell`, which owns all three together and
//! only ever commits through `apply` (`commit_built`) — never a raw
//! `replace_exact`.

use crate::cell::ControlRecordCell;
use crate::record::{GcEntry, GcState};
use crate::secret_backend::{InspectOutcome, SecretBackend};
use crate::store::LoadOutcome;
use crate::transition::RecordTransition;
use std::collections::HashSet;

pub use crate::cell::CommitTransitionError as GcTickError;

/// One GC tick for one identity. The cell's own `gc_serial` is held for the
/// entire call (erratum1 E1) including every slow `backend` call; each
/// individual record read+write is its own separate, freshly acquired
/// `turnstile`→`access` critical section — the backend is always called
/// with neither held.
pub fn gc_worker_tick(
    cell: &ControlRecordCell,
    backend: &dyn SecretBackend,
    now: u64,
    max_cap: usize,
) -> Result<usize, GcTickError> {
    let _serial = cell.acquire_gc_serial();

    {
        let guard = cell.acquire_for_mutation();
        cell.sweep_orphan_tmp(&guard);
    }

    let mut resolved_count = 0usize;
    // Entries that reported an indeterminate backend outcome this tick —
    // set aside so they do not block other entries, but not treated as
    // resolved; the next tick will retry them fresh.
    let mut indeterminate_this_tick: HashSet<String> = HashSet::new();
    // Entries that already had one `inspect` observation this tick.
    // `AbsentUnconfirmed → Absent` deliberately requires a SECOND,
    // separately scheduled `gc_worker_tick` call — the whole point of the
    // two-observation design is to give a possibly-eventually-consistent
    // backend a real time gap between confirmations. Without this, the
    // outer loop's "reprocess everything unresolved every iteration"
    // policy (correct for other transitions, see `gc_is_plural_*`) would
    // immediately re-select the just-updated `AbsentUnconfirmed` entry and
    // confirm it `Absent` within the same tick, collapsing two observations
    // into one and defeating the protection entirely.
    let mut inspected_this_tick: HashSet<String> = HashSet::new();

    loop {
        let rec = match cell.load_canonical() {
            LoadOutcome::Exact(r) => *r,
            LoadOutcome::Missing => return Err(GcTickError::NoRecord),
            LoadOutcome::Corrupt => return Err(GcTickError::RecordCorrupt),
        };
        let Some(entry) = rec
            .gc_pending
            .iter()
            .find(|e| {
                if e.observation_complete_and_residual_zero() {
                    return false;
                }
                if indeterminate_this_tick.contains(&e.slot().canonical_id()) {
                    return false;
                }
                // Quarantine and InspectionConflict are deliberately not
                // auto-retried -- a backend-reported mismatch or ambiguity
                // needs administrative resolution, not endless automatic
                // re-attempts. Without this exclusion the loop would
                // reselect and re-flag the same entry forever, since
                // neither is `Done`/`Absent` and so neither ever satisfies
                // observation_complete_and_residual_zero().
                if matches!(
                    e,
                    GcEntry::Bound {
                        state: GcState::Quarantine,
                        ..
                    } | GcEntry::InspectionConflict { .. }
                ) {
                    return false;
                }
                // Only AwaitingInspection/AbsentUnconfirmed are limited to
                // one inspection per tick — a freshly created Bound{Pending}
                // (from a GcInspected that just ran THIS tick) must still be
                // free to proceed straight to its destroy attempt below.
                if matches!(
                    e,
                    GcEntry::AwaitingInspection { .. } | GcEntry::AbsentUnconfirmed { .. }
                ) && inspected_this_tick.contains(&e.slot().canonical_id())
                {
                    return false;
                }
                true
            })
            .cloned()
        else {
            break; // nothing left unresolved (or resolvable) this tick
        };
        let slot_id = entry.slot().canonical_id();
        let txn_id = entry.txn_id();

        match &entry {
            GcEntry::AwaitingInspection { slot, .. } | GcEntry::AbsentUnconfirmed { slot, .. } => {
                inspected_this_tick.insert(slot_id.clone());
                // Backend call with no lock held.
                let found = match backend.inspect(slot) {
                    InspectOutcome::Present(b) => Some(b),
                    InspectOutcome::Absent => None,
                    InspectOutcome::Indeterminate => {
                        // Never treated as an absence observation — an
                        // outage must not be able to masquerade as a
                        // confirming inspection. Transient, so nothing is
                        // persisted; the next tick retries fresh.
                        indeterminate_this_tick.insert(slot_id);
                        continue;
                    }
                    InspectOutcome::Conflict => {
                        // An inherent ambiguity, not a transient outage —
                        // persist it durably (GcEntry::InspectionConflict)
                        // rather than silently retrying forever with no
                        // trace it was ever observed.
                        let committed = cell.commit_built(
                            |fresh| {
                                fresh
                                    .gc_pending
                                    .iter()
                                    .any(|e| {
                                        e.slot().canonical_id() == slot_id && e.txn_id() == txn_id
                                    })
                                    .then(|| RecordTransition::GcInspectionConflict {
                                        slot_id: slot_id.clone(),
                                    })
                            },
                            now,
                            max_cap,
                        )?;
                        if committed.is_some() {
                            resolved_count += 1;
                        }
                        continue;
                    }
                };
                let committed = cell.commit_built(
                    |fresh| {
                        fresh
                            .gc_pending
                            .iter()
                            .any(|e| e.slot().canonical_id() == slot_id && e.txn_id() == txn_id)
                            .then(|| RecordTransition::GcInspected {
                                slot_id: slot_id.clone(),
                                found: found.clone(),
                            })
                    },
                    now,
                    max_cap,
                )?;
                if committed.is_some() {
                    resolved_count += 1;
                } else {
                    // Entry moved/vanished between selection and the
                    // result write (e.g. concurrently removed) — loop
                    // again and re-select against fresh state.
                }
            }
            GcEntry::Bound { slot, binding, .. } => {
                let binding = binding.clone();
                // Backend call with no lock held.
                let report = backend.gc_best_effort(slot, &binding);
                if !report.observation_complete {
                    indeterminate_this_tick.insert(slot_id);
                    continue; // this entry only — others still proceed
                }
                let committed = cell.commit_built(
                    |fresh| {
                        fresh
                            .gc_pending
                            .iter()
                            .any(|e| e.slot().canonical_id() == slot_id && e.txn_id() == txn_id)
                            .then(|| RecordTransition::GcResolved {
                                slot_id: slot_id.clone(),
                                residual_zero: !report.residual,
                                quarantine: report.mismatch,
                            })
                    },
                    now,
                    max_cap,
                )?;
                if committed.is_some() {
                    resolved_count += 1;
                }
            }
            GcEntry::Absent { .. } => {
                unreachable!("Absent is already resolved and excluded by the selection filter")
            }
            GcEntry::InspectionConflict { .. } => {
                unreachable!("InspectionConflict is excluded by the selection filter")
            }
        }
    }
    Ok(resolved_count)
}

/// Removes `Done`/`Absent` entries. Separate from resolution itself so a
/// crash between "resolved" and "removed" leaves the entry durably visible
/// as resolved rather than ambiguous.
pub fn gc_removal_pass(
    cell: &ControlRecordCell,
    now: u64,
    max_cap: usize,
) -> Result<usize, GcTickError> {
    let mut removed = 0usize;
    loop {
        let committed = cell.commit_built(
            |fresh| {
                let entry = fresh.gc_pending.iter().find(|e| {
                    matches!(
                        e,
                        GcEntry::Bound {
                            state: GcState::Done,
                            ..
                        }
                    ) || matches!(e, GcEntry::Absent { .. })
                })?;
                Some(RecordTransition::GcRemoval {
                    slot_id: entry.slot().canonical_id(),
                    txn_id: entry.txn_id(),
                })
            },
            now,
            max_cap,
        )?;
        match committed {
            Some(_) => removed += 1,
            None => break,
        }
    }
    Ok(removed)
}
