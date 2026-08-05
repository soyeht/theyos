//! Multi-process CAS REDs, split out of `model_invariants.rs`.
//!
//! These four spawn a REAL helper binary via `env!("CARGO_BIN_EXE_...")`, which
//! cargo injects only for INTEGRATION targets. They therefore cannot compile as
//! a `cfg(test)` module of a library target, which is how the keystore bridge
//! co-locates the rest of this suite. Splitting keeps ONE source per RED -- no
//! duplication -- while letting the other 134 also run co-located.

mod common;
use common::{identity, test_cell};

use mesh_session_control_model_rs::record::*;
use mesh_session_control_model_rs::store::ReplaceOutcome;

/// Legacy unpinned spawn -- every worker commits from whatever revision it
/// happens to read, with its own txn_id and no barrier. Kept ONLY for the
/// fail-closed alias tests (where no worker gets far enough to commit at
/// all) and for the negative control that demonstrates why this shape
/// cannot support an exactly-one-commits assertion. See
/// `src/bin/cas_race_helper.rs`'s module doc.
fn run_cas_race_helper(record_path: &std::path::Path, worker_id: u8) -> std::process::Child {
    std::process::Command::new(env!("CARGO_BIN_EXE_cas_race_helper"))
        .arg(record_path)
        .arg(worker_id.to_string())
        .arg("unpinned")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn cas_race_helper")
}

/// Pinned spawn: every worker is handed the SAME `expected_revision` and
/// builds byte-identical content, then waits at `barrier_dir` until all
/// `total_workers` have arrived before attempting its CAS.
fn run_pinned_cas_race_helper(
    record_path: &std::path::Path,
    worker_id: u8,
    expected_revision: u64,
    barrier_dir: &std::path::Path,
    total_workers: usize,
) -> std::process::Child {
    std::process::Command::new(env!("CARGO_BIN_EXE_cas_race_helper"))
        .arg(record_path)
        .arg(worker_id.to_string())
        .arg("pinned")
        .arg(expected_revision.to_string())
        .arg(barrier_dir)
        .arg(total_workers.to_string())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn cas_race_helper")
}

fn wait_and_read_stdout(child: std::process::Child) -> String {
    let output = child.wait_with_output().unwrap();
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// Round 6, wave 8 (CFX-5). The predecessor of this test spawned six
/// unpinned workers and asserted exactly one committed -- an assertion
/// that did not follow from what the workers actually did, and that an
/// independent audit run caught failing (120 passed / 1 failed, two
/// COMMITTED). See `src/bin/cas_race_helper.rs`'s module doc for the full
/// account. Every worker here starts from the SAME pinned revision with
/// byte-identical content and only begins after all six have arrived at
/// the barrier, so exactly one CAS genuinely can win.
#[test]
fn six_real_processes_racing_one_pinned_revision_exactly_one_cas_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let barrier = dir.path().join("barrier");
    std::fs::create_dir(&barrier).unwrap();

    // Seed the genesis bootstrap for real, through this process's own
    // cell, before any race worker starts.
    let pinned_revision = {
        let cell = test_cell(path.clone());
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation_for_test();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
        bootstrap.revision
    };

    let children: Vec<_> = (0u8..6)
        .map(|i| run_pinned_cas_race_helper(&path, i, pinned_revision, &barrier, 6))
        .collect();
    let outputs: Vec<String> = children.into_iter().map(wait_and_read_stdout).collect();

    assert!(
        !outputs.iter().any(|o| o == "BARRIER_TIMEOUT"),
        "every worker must reach the barrier -- a timeout means this measured startup skew, not the CAS; got {outputs:?}"
    );
    assert!(
        !outputs.iter().any(|o| o == "BASE_MOVED"),
        "every worker must start from the pinned revision -- BASE_MOVED means the race was never on a common base, the exact defect this test replaced; got {outputs:?}"
    );
    let committed = outputs.iter().filter(|o| o.as_str() == "COMMITTED").count();
    assert_eq!(
        committed, 1,
        "exactly one of six independent processes proposing byte-identical content against one pinned revision must win the CAS; got {outputs:?}"
    );
    assert_eq!(
        outputs.iter().filter(|o| o.as_str() == "NO_EFFECT").count(),
        5,
        "the five losers must each be a definitive no-effect rejection, never MAY_HAVE_TAKEN_EFFECT; got {outputs:?}"
    );
}

/// Negative control for the test above, and the standing evidence that
/// the predecessor's assertion was vacuous rather than merely unlucky:
/// run two unpinned workers strictly SEQUENTIALLY (each fully finished
/// before the next starts, so they provably never contend) and watch both
/// commit. Under the old shape that was indistinguishable from a genuine
/// race, which is why "exactly one committed" could flip to two on a
/// machine where the workers happened not to overlap.
#[test]
fn unpinned_sequential_runs_both_commit_which_is_why_the_old_test_was_vacuous() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    {
        let cell = test_cell(path.clone());
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation_for_test();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
    }

    let first = wait_and_read_stdout(run_cas_race_helper(&path, 0));
    let second = wait_and_read_stdout(run_cas_race_helper(&path, 1));

    assert_eq!(
        (first.as_str(), second.as_str()),
        ("COMMITTED", "COMMITTED"),
        "two strictly sequential unpinned workers both commit -- each reads the revision the previous one wrote and legitimately advances it. This is correct CAS behaviour, which is exactly why asserting 'exactly one committed' over unpinned workers measured scheduling luck instead of the CAS."
    );
}

#[test]
fn preexisting_hardlink_alias_makes_every_process_fail_closed_not_double_commit() {
    // Round 6, wave 6 (corrected, retracting an earlier false claim in
    // this same test): `open_non_aliased`'s nlink check does NOT make
    // this store immune to a hardlink alias in general -- see store.rs's
    // top doc comment for the full, honest boundary. A hardlink created
    // DURING a `replace_exact` call (between its nlink check and its
    // rename) is NOT caught by this or any check in this crate: after
    // that rename, the two names permanently and independently show
    // nlink == 1, because they are, from that point on, genuinely two
    // separate files -- there is nothing left to detect.
    //
    // What IS true, and is what this test actually demonstrates: an alias
    // that already exists BEFORE any operation begins is detected and
    // rejected, fail-closed, by every process that tries to use either
    // spelling -- the hardlink here is created before any worker starts,
    // not raced against one.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let alias_path = dir.path().join("alias");
    {
        let cell = test_cell(path.clone());
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation_for_test();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
    }
    std::fs::hard_link(&path, &alias_path).expect("hard_link must succeed on a local filesystem");

    let children: Vec<_> = (0u8..6)
        .map(|i| {
            let target = if i % 2 == 0 { &path } else { &alias_path };
            run_cas_race_helper(target, i)
        })
        .collect();
    let outputs: Vec<String> = children.into_iter().map(wait_and_read_stdout).collect();

    let committed = outputs.iter().filter(|o| o.as_str() == "COMMITTED").count();
    assert_eq!(
        committed, 0,
        "once a hardlink alias exists, every process (via either spelling) must fail closed -- never a silent double-commit through the two spellings; got {outputs:?}"
    );
    assert!(
        outputs.iter().all(|o| o.starts_with("REJECTED")),
        "every worker must observe the alias as a rejection, not silently succeed or crash; got {outputs:?}"
    );
}

#[test]
fn six_processes_via_a_preexisting_symlink_all_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let real_path = dir.path().join("real_record");
    let symlink_path = dir.path().join("record");
    {
        let cell = test_cell(real_path.clone());
        let bootstrap = MeshSignerControlRecordV1::bootstrap(identity(), PurposeId::MeshSession);
        let g = cell.acquire_for_mutation_for_test();
        assert_eq!(
            cell.seed_for_test(&g, INITIAL_REVISION, &bootstrap),
            ReplaceOutcome::Committed
        );
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real_path, &symlink_path).unwrap();
        let children: Vec<_> = (0u8..6)
            .map(|i| run_cas_race_helper(&symlink_path, i))
            .collect();
        let outputs: Vec<String> = children.into_iter().map(wait_and_read_stdout).collect();
        assert!(
            outputs.iter().all(|o| o == "REJECTED:RecordCorrupt"),
            "opening the record through a symlink must fail closed for every worker; got {outputs:?}"
        );
    }
}
