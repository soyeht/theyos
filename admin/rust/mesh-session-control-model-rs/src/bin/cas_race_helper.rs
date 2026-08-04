//! Round 6: a real, separate-process CAS race participant.
//!
//! Exists solely so `tests/model_invariants.rs` can spawn genuinely
//! independent OS processes (not threads within one process, which would
//! all share the SAME process-local `MeshSignerLocks`/cell registry and
//! so could never demonstrate a cross-process race at all) against the
//! SAME record path, each with its own completely independent
//! `FileBackedStore`/`MeshSignerLocks` pair -- exactly the scenario the
//! in-process locking alone cannot protect against.
//!
//! # Round 6, wave 8 (CFX-5): why this grew a `pinned` mode
//!
//! The wave-5/6/7 version had exactly one mode, the one now called
//! `unpinned`: every worker called `cell.commit(...)` with its OWN
//! `txn_id` ([worker_id; 16]) from "whatever revision is currently on
//! disk", with nothing synchronizing the start. Its consuming test then
//! asserted that exactly one of six processes committed.
//!
//! That assertion did not follow from what the workers did. Two workers
//! that do not actually overlap are not racing at all: the first commits
//! revision R -> R+1, the second then legitimately reads R+1 and commits
//! R+1 -> R+2. Two `COMMITTED` lines is *correct* CAS behaviour there,
//! not a violation -- so the test failed intermittently (an independent
//! audit run observed exactly that, 120 passed / 1 failed with two
//! COMMITTED) while passing on faster machines, where the workers usually
//! did overlap and the later revokes usually collapsed into no-ops. It
//! was measuring scheduling luck, not the CAS.
//!
//! `pinned` mode measures the actual property. Every worker is handed the
//! SAME `expected_revision` up front, builds byte-identical new content
//! (one FIXED `txn_id` shared by all workers, not one per worker), waits
//! at a filesystem barrier until every worker is ready, and only then
//! attempts the compare-and-swap. All six then genuinely contend for one
//! revision transition, and exactly one must win.
//!
//! `unpinned` mode is kept ONLY so a negative control can demonstrate the
//! defect above on demand (see
//! `unpinned_sequential_runs_both_commit_which_is_why_the_old_test_was_vacuous`).
//! It must never again be used to assert an exactly-one-commits property.
//!
//! Usage:
//!   `cas_race_helper <record-path> <worker-id> unpinned`
//!   `cas_race_helper <record-path> <worker-id> pinned <expected-revision> <barrier-dir> <total-workers>`
//!
//! Prints exactly one line to stdout: `COMMITTED`, `NO_RECORD`,
//! `NO_EFFECT`, `MAY_HAVE_TAKEN_EFFECT`, `BASE_MOVED`, `BARRIER_TIMEOUT`,
//! or `REJECTED:<debug of the error>`.

use mesh_session_control_model_rs::cell;
use mesh_session_control_model_rs::locks::OrderSpy;
use mesh_session_control_model_rs::record::{
    Channel, ControlIdentity, PurposeId, RevocationReason,
};
use mesh_session_control_model_rs::store::{LoadOutcome, ReplaceOutcome};
use mesh_session_control_model_rs::transition::{RecordTransition, apply};
use std::sync::Arc;

/// Shared by EVERY worker in `pinned` mode, so all of them propose
/// byte-identical content and the only thing that can separate them is
/// the compare-and-swap itself.
const PINNED_TXN_ID: [u8; 16] = [0xC5; 16];
const PINNED_NOW: u64 = 1000;
const MAX_CAP: usize = 100;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = std::path::PathBuf::from(&args[1]);
    let worker_id: u8 = args[2].parse().expect("worker id must be a u8");
    let mode = args[3].as_str();

    let identity = ControlIdentity {
        hh_id: "hh_test".into(),
        machine_id: "m_test".into(),
        channel: Channel::Dev,
    };
    let cell = cell::open(
        path,
        identity,
        PurposeId::MeshSession,
        Arc::new(OrderSpy::new()),
    )
    .expect("open should not conflict -- same identity/purpose every worker");

    // A path that fails the store's fail-closed identity validation (a
    // pre-existing hardlink alias or symlink) loads as `Corrupt`, NOT
    // `Missing` -- the alias tests depend on that staying a rejection
    // rather than collapsing into the same output as an absent record.
    let base = match cell.load_canonical_for_test() {
        LoadOutcome::Exact(base) => base,
        LoadOutcome::Missing => {
            println!("NO_RECORD");
            return;
        }
        // Spelled exactly as `CommitTransitionError::RecordCorrupt` used to
        // arrive here via `cell.commit`, so the alias/symlink tests keep
        // asserting the same precise outcome they always did.
        LoadOutcome::Corrupt => {
            println!("REJECTED:RecordCorrupt");
            return;
        }
    };

    match mode {
        // Legacy, defect-demonstrating mode -- negative control only.
        "unpinned" => {
            let t = RecordTransition::RevokeUrgent {
                reason: RevocationReason::Compromised,
                txn_id: [worker_id; 16],
            };
            match cell.commit(&t, PINNED_NOW, MAX_CAP) {
                Ok(_) => println!("COMMITTED"),
                Err(e) => println!("REJECTED:{e:?}"),
            }
        }
        "pinned" => {
            let expected_revision: u64 = args[4].parse().expect("expected revision must be a u64");
            let barrier_dir = std::path::PathBuf::from(&args[5]);
            let total_workers: usize = args[6].parse().expect("total workers must be a usize");

            // Fail loudly rather than racing from a base nobody pinned --
            // the whole point of this mode is that every worker starts
            // from the SAME revision.
            if base.revision != expected_revision {
                println!("BASE_MOVED");
                return;
            }

            let t = RecordTransition::RevokeUrgent {
                reason: RevocationReason::Compromised,
                txn_id: PINNED_TXN_ID,
            };
            let Ok(target) = apply(&base, &t, PINNED_NOW, MAX_CAP) else {
                println!("REJECTED:apply-failed");
                return;
            };

            if !wait_at_barrier(&barrier_dir, worker_id, total_workers) {
                println!("BARRIER_TIMEOUT");
                return;
            }

            // Every worker reaches this line with byte-identical `target`
            // and the identical `expected_revision`. Exactly one CAS can
            // win.
            let g = cell.acquire_for_mutation();
            match cell.seed_for_test(&g, expected_revision, &target) {
                ReplaceOutcome::Committed => println!("COMMITTED"),
                ReplaceOutcome::KnownNoEffect => println!("NO_EFFECT"),
                ReplaceOutcome::MayHaveTakenEffect => println!("MAY_HAVE_TAKEN_EFFECT"),
            }
        }
        other => panic!("unknown mode {other}"),
    }
}

/// Filesystem barrier: announce this worker, then spin until every worker
/// has announced. Returns false if the others never showed up, so a stuck
/// run reports `BARRIER_TIMEOUT` instead of hanging the test suite.
fn wait_at_barrier(barrier_dir: &std::path::Path, worker_id: u8, total_workers: usize) -> bool {
    std::fs::write(barrier_dir.join(format!("ready-{worker_id}")), b"1")
        .expect("barrier dir must be writable");
    for _ in 0..2000 {
        let ready = std::fs::read_dir(barrier_dir)
            .map(|d| d.filter_map(Result::ok).count())
            .unwrap_or(0);
        if ready >= total_workers {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    false
}
