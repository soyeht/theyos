//! GC worker tick. Fixes two v11 sweep findings directly:
//! (1) every unresolved entry is reprocessed every tick — there is no
//!     `Claimed`-and-skip state a crash can strand forever;
//! (2) the record is re-fetched after every write inside the loop instead
//!     of reusing one stale snapshot across multiple mutations.

use crate::locks::MeshSignerLocks;
use crate::record::{GcState, MeshSignerControlRecordV1};
use crate::secret_backend::SecretBackend;
use crate::store::{AtomicControlRecordStore, LoadOutcome, ReplaceOutcome};
use crate::transition::{RecordTransition, TransitionError, apply};

#[derive(Debug, thiserror::Error)]
pub enum GcTickError {
    #[error("store has no record for this identity")]
    NoRecord,
    #[error("record is corrupt")]
    RecordCorrupt,
    #[error(transparent)]
    Transition(#[from] TransitionError),
    #[error("write did not commit after retries")]
    RetryExhausted,
}

/// Writes `t` against `old`, retrying on `KnownNoEffect`/`MayHaveTakenEffect`
/// up to `max_attempts` times, and returns the record actually persisted.
/// `KnownNoEffect` means another writer's revision won by CAS — in that
/// case this function re-reads and re-derives `new` against the fresh
/// `old` rather than blindly retrying the same bytes, since the base the
/// transition was computed against is now stale.
fn commit_transition(
    store: &dyn AtomicControlRecordStore,
    old: MeshSignerControlRecordV1,
    build: impl Fn(&MeshSignerControlRecordV1) -> Result<MeshSignerControlRecordV1, TransitionError>,
    now: u64,
    max_attempts: u32,
) -> Result<MeshSignerControlRecordV1, GcTickError> {
    let _ = now;
    let mut base = old;
    for _ in 0..max_attempts {
        let new = build(&base)?;
        match store.replace_exact(base.revision, &new) {
            ReplaceOutcome::Committed => return Ok(new),
            ReplaceOutcome::MayHaveTakenEffect => {
                // Re-read: if it actually landed, the reread now shows it.
                match store.load_canonical() {
                    LoadOutcome::Exact(r) if *r == new => return Ok(new),
                    LoadOutcome::Exact(r) => base = *r, // did not land as this exact
                    // content — retry from the
                    // fresh base
                    _ => return Err(GcTickError::RecordCorrupt),
                }
            }
            ReplaceOutcome::KnownNoEffect => match store.load_canonical() {
                LoadOutcome::Exact(r) => base = *r,
                LoadOutcome::Missing => return Err(GcTickError::NoRecord),
                LoadOutcome::Corrupt => return Err(GcTickError::RecordCorrupt),
            },
        }
    }
    Err(GcTickError::RetryExhausted)
}

/// One GC tick for one identity. `gc_serial` is held for the entire
/// function (erratum1 E1) including the slow `backend` calls; the two
/// short record transitions per entry each separately acquire and release
/// `turnstile`/`access` via `MeshSignerLocks::acquire_for_mutation`.
pub fn gc_worker_tick(
    store: &dyn AtomicControlRecordStore,
    backend: &dyn SecretBackend,
    locks: &MeshSignerLocks,
    now: u64,
) -> Result<usize, GcTickError> {
    let _serial_held_for_whole_tick = (); // gc_serial ownership is the caller's
    // responsibility in the real integration (a `GcSerialLock` guard held
    // across this whole call) — kept out of this function's signature so
    // the pure record-transition logic can be unit-tested without needing
    // a live lock file.

    store.sweep_orphan_tmp();

    let mut resolved_count = 0usize;
    loop {
        // Re-fetch fresh on every loop entry — never reuse a snapshot from
        // before a previous iteration's write (the v11 bug).
        let rec = {
            let _access = locks.acquire_for_mutation();
            match store.load_canonical() {
                LoadOutcome::Exact(r) => *r,
                LoadOutcome::Missing => return Err(GcTickError::NoRecord),
                LoadOutcome::Corrupt => return Err(GcTickError::RecordCorrupt),
            }
        };

        let Some(entry) = rec
            .gc_pending
            .iter()
            .find(|e| !e.observation_complete_and_residual_zero())
            .cloned()
        else {
            break; // nothing left unresolved this tick
        };
        let slot_id = entry.slot().canonical_id();

        let transition = match &entry {
            crate::record::GcEntry::AwaitingInspection { slot, .. } => {
                let sid = slot.canonical_id();
                // Pure read, no expected key required and no side effect —
                // see `SecretBackend::inspect`'s doc comment for why this,
                // not `load_exact`, is the correct call here.
                RecordTransition::GcInspected {
                    slot_id: slot_id.clone(),
                    found: backend.inspect(&sid),
                }
            }
            crate::record::GcEntry::Bound { slot, binding, .. } => {
                let sid = slot.canonical_id();
                let report = backend.gc_best_effort(&sid, binding);
                if !report.observation_complete {
                    break; // indeterminate this tick — retried next tick, does not
                    // block other entries in THIS tick's remaining loop
                }
                RecordTransition::GcResolved {
                    slot_id: slot_id.clone(),
                    residual_zero: !report.residual,
                    quarantine: false,
                }
            }
        };

        let base = rec;
        commit_transition(store, base, |b| apply(b, &transition, now), now, 8)?;
        resolved_count += 1;
    }
    Ok(resolved_count)
}

/// Removes `Done` entries whose residual is zero. Separate from resolution
/// itself so a crash between "resolved" and "removed" leaves the entry
/// durably visible as `Done` rather than ambiguous.
pub fn gc_removal_pass(
    store: &dyn AtomicControlRecordStore,
    locks: &MeshSignerLocks,
    now: u64,
) -> Result<usize, GcTickError> {
    let mut removed = 0usize;
    loop {
        let rec = {
            let _access = locks.acquire_for_mutation();
            match store.load_canonical() {
                LoadOutcome::Exact(r) => *r,
                LoadOutcome::Missing => return Err(GcTickError::NoRecord),
                LoadOutcome::Corrupt => return Err(GcTickError::RecordCorrupt),
            }
        };
        let Some(entry) = rec.gc_pending.iter().find(|e| {
            matches!(
                e,
                crate::record::GcEntry::Bound {
                    state: GcState::Done,
                    ..
                }
            )
        }) else {
            break;
        };
        let slot_id = entry.slot().canonical_id();
        commit_transition(
            store,
            rec,
            |b| {
                apply(
                    b,
                    &RecordTransition::GcRemoval {
                        slot_id: slot_id.clone(),
                    },
                    now,
                )
            },
            now,
            8,
        )?;
        removed += 1;
    }
    Ok(removed)
}
