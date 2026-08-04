//! Shared "commit these exact bytes" discipline.
//!
//! Second-round fix on top of the generation audited at commit `d4ecb658`
//! (NO-GO, finding 3): the first attempt at this module still closed
//! `MayHaveTakenEffect` by rereading and checking `disk == new` under a
//! continuously held guard. That is real progress over a bare "reread and
//! hope" — it does prove *this exact write*, not some other writer's,
//! produced what is visible — but it is not the same thing `Committed`
//! promises. `rename()` makes the new content visible in the page cache
//! immediately; the parent-directory `fsync` is what makes that rename
//! survive a crash. A `MayHaveTakenEffect` outcome (parent fsync failed)
//! followed by a reread that finds `disk == new` proves *visibility and
//! identity under the in-process guard* — it proves nothing about
//! *durability*, because a crash between that reread and the next moment
//! could still unwind the never-fsynced rename. Concluding `Ok` from the
//! reread alone is the same class of bug as v4–v7's premature closure,
//! just moved one layer down.
//!
//! The only thing that closes an uncertain outcome is another real write
//! that itself reports `Committed` — i.e. one whose own parent `fsync`
//! actually returns `Ok`. So: on anything other than `Committed`, reread
//! only to compute what the *next* attempt's `expected_revision` must be
//! (the original mutation, if it never took; a stabilization rewrite of
//! the identical bytes at the now-current revision, if it did) — then
//! issue that write for real and keep going. `KnownNoEffect` never closes
//! a prior `MayHaveTakenEffect` by itself, and a same-bytes retry that
//! itself reports `Committed` is the only thing that does.
//!
//! Used by both `gc` and `activate`, the two call sites outside tests that
//! invoke `store::AtomicControlRecordStore::replace_exact`.

use crate::locks::MutateGuard;
use crate::record::{INITIAL_REVISION, MeshSignerControlRecordV1};
use crate::store::{AtomicControlRecordStore, LoadOutcome, ReplaceOutcome};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CommitError {
    #[error("write did not commit after retries")]
    RetryExhausted,
    #[error("record is corrupt")]
    RecordCorrupt,
    #[error(
        "disk state after an uncertain outcome matches neither the original base nor the target bytes — impossible under a continuously held exclusive guard unless something else is broken"
    )]
    UnexpectedDivergence,
}

pub fn commit_new_bytes(
    store: &dyn AtomicControlRecordStore,
    guard: &MutateGuard<'_>,
    expected_revision: u64,
    new: &MeshSignerControlRecordV1,
    max_attempts: u32,
) -> Result<(), CommitError> {
    let mut current_expected = expected_revision;
    for _ in 0..max_attempts {
        if store.replace_exact(guard, current_expected, new) == ReplaceOutcome::Committed {
            return Ok(());
        }
        // Not Committed — MayHaveTakenEffect or KnownNoEffect, treated
        // identically: never conclude from this alone. Reread only to
        // pick the correct shape for the NEXT real write attempt.
        current_expected = match store.load_canonical() {
            // The mutation already landed (rename visible) — the next
            // attempt must be a byte-identical stabilization rewrite at
            // the now-current revision, so its own fsync gets a real
            // chance to succeed and report Committed.
            LoadOutcome::Exact(r) if *r == *new => r.revision,
            // Still at the original base — the mutation never took;
            // retry it verbatim.
            LoadOutcome::Exact(r) if r.revision == expected_revision => expected_revision,
            LoadOutcome::Exact(_) => return Err(CommitError::UnexpectedDivergence),
            LoadOutcome::Missing if expected_revision == INITIAL_REVISION => expected_revision,
            LoadOutcome::Missing => return Err(CommitError::UnexpectedDivergence),
            LoadOutcome::Corrupt => return Err(CommitError::RecordCorrupt),
        };
    }
    Err(CommitError::RetryExhausted)
}
