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

use crate::commit::{CommitError, commit_new_bytes};
use crate::locks::{GcSerialLock, MeshSignerLocks};
use crate::record::{GcEntry, GcState, MeshSignerControlRecordV1};
use crate::secret_backend::{InspectOutcome, SecretBackend};
use crate::store::{AtomicControlRecordStore, LoadOutcome};
use crate::transition::{RecordTransition, TransitionError, apply};
use std::collections::HashSet;

#[derive(Debug, thiserror::Error)]
pub enum GcTickError {
    #[error("store has no record for this identity")]
    NoRecord,
    #[error("record is corrupt")]
    RecordCorrupt,
    #[error(transparent)]
    Transition(#[from] TransitionError),
    #[error(transparent)]
    Commit(#[from] CommitError),
}

/// One claim-or-result write: acquire the mutation guard, read fresh under
/// it, hand the fresh record to `build`, and commit whatever it returns —
/// all in one continuously held critical section. Returns `Ok(None)` if
/// `build` reports there is nothing to do against the fresh state (e.g.
/// the targeted entry was already resolved by a concurrent caller).
fn read_build_commit(
    store: &dyn AtomicControlRecordStore,
    locks: &MeshSignerLocks,
    build: impl FnOnce(&MeshSignerControlRecordV1) -> Option<RecordTransition>,
    now: u64,
    max_cap: usize,
) -> Result<Option<MeshSignerControlRecordV1>, GcTickError> {
    let guard = locks.acquire_for_mutation();
    let base = match store.load_canonical() {
        LoadOutcome::Exact(r) => *r,
        LoadOutcome::Missing => return Err(GcTickError::NoRecord),
        LoadOutcome::Corrupt => return Err(GcTickError::RecordCorrupt),
    };
    let Some(t) = build(&base) else {
        return Ok(None);
    };
    let new = apply(&base, &t, now, max_cap)?;
    commit_new_bytes(store, &guard, base.revision, &new, 8)?;
    Ok(Some(new))
}

/// One GC tick for one identity. `gc_serial` is held for the entire call
/// (erratum1 E1) including every slow `backend` call; each individual
/// record read+write is its own separate, freshly acquired
/// `turnstile`→`access` critical section — the backend is always called
/// with neither held.
pub fn gc_worker_tick(
    store: &dyn AtomicControlRecordStore,
    backend: &dyn SecretBackend,
    locks: &MeshSignerLocks,
    gc_serial: &GcSerialLock,
    now: u64,
    max_cap: usize,
) -> Result<usize, GcTickError> {
    let _serial = gc_serial.acquire();

    {
        let guard = locks.acquire_for_mutation();
        store.sweep_orphan_tmp(&guard);
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
        let rec = match store.load_canonical() {
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
                // Quarantine is deliberately not auto-retried -- a
                // backend-reported mismatch needs administrative
                // resolution, not endless automatic re-attempts. Without
                // this exclusion the loop would reselect and requarantine
                // the same entry forever, since Quarantine is not `Done`
                // and so never satisfies observation_complete_and_residual_zero().
                if matches!(
                    e,
                    GcEntry::Bound {
                        state: GcState::Quarantine,
                        ..
                    }
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
                    InspectOutcome::Indeterminate | InspectOutcome::Conflict => {
                        // Never treated as an absence observation — an
                        // outage or an ambiguous read must not be able to
                        // masquerade as a confirming inspection.
                        indeterminate_this_tick.insert(slot_id);
                        continue;
                    }
                };
                let committed = read_build_commit(
                    store,
                    locks,
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
                let committed = read_build_commit(
                    store,
                    locks,
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
        }
    }
    Ok(resolved_count)
}

/// Removes `Done`/`Absent` entries. Separate from resolution itself so a
/// crash between "resolved" and "removed" leaves the entry durably visible
/// as resolved rather than ambiguous.
pub fn gc_removal_pass(
    store: &dyn AtomicControlRecordStore,
    locks: &MeshSignerLocks,
    now: u64,
    max_cap: usize,
) -> Result<usize, GcTickError> {
    let mut removed = 0usize;
    loop {
        let committed = read_build_commit(
            store,
            locks,
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
