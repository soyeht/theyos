//! Every compile-fail fixture on disk must be run by some runner.
//!
//! An orphan fixture — a `.rs` under `tests/compile-fail/` that no
//! `t.compile_fail(...)` line names — is invisible. It sits in the tree looking
//! like a security proof, it is never compiled, and *nothing fails*. That is
//! indistinguishable from passing, which is the worst property a proof can
//! have.
//!
//! This is not hypothetical. `compile_fail_peer_expectation.rs` is maintained
//! as a hand-written list of fixture paths, and two branches grew that list
//! independently: one added `mesh_intent_nonce_ledger_raw_open`, the other
//! added the two `authenticated_peer_claim_*` cases. Resolving that conflict
//! with "ours" or "theirs" silently deletes whichever proofs the losing side
//! contributed, and the suite stays green — fewer fixtures simply run.
//!
//! Why a source sweep is the right instrument *here*, when it was the wrong one
//! for locking a caller set: "who may call this function" is a property the
//! compiler already enforces if you give it a type to enforce it with, so a
//! text sweep there is a weaker restatement of something free. "Does this file
//! on disk participate in the suite" has no type-system handle at all — the
//! fixture's whole point is that it is *not* compiled into the crate. And the
//! failure mode differs: a reference this sweep cannot recognise is reported as
//! an orphan, so it fails toward noisy, not toward silently permissive.
//!
//! The structural fix is to stop hand-listing: give each runner its own
//! subdirectory and let it glob. Then the list cannot drift from the directory,
//! and this conflict class disappears with it. Until that lands, this test is
//! what makes the drift loud.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Fixture stems present on disk, found by walking the directory rather than
/// from a list — a list is the very thing that drifts.
fn fixtures_on_disk(dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            fixtures_on_disk(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && let Some(stem) = path.file_stem()
        {
            out.insert(stem.to_string_lossy().into_owned());
        }
    }
}

/// Fixture stems named by a `compile_fail("…")` argument in any runner.
///
/// Matching the *argument* rather than the bare filename keeps a fixture that
/// is merely mentioned in prose from counting as covered. A runner that builds
/// its path dynamically would be reported as not covering anything — noisy, and
/// deliberately so.
fn fixtures_referenced(tests: &Path) -> BTreeSet<String> {
    let mut referenced = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(tests) else {
        return referenced;
    };
    // This file must exclude ITSELF. It necessarily contains the literal
    // `compile_fail(` in its own parser and prose, and counting those yields
    // nonsense "references" -- the same self-reference trap as a guard that
    // matches its own source. `file!()` names this file regardless of renames.
    let own = Path::new(file!()).file_name().map(std::ffi::OsString::from);
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() || path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        if own.as_deref() == path.file_name() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let Some(at) = line.find("compile_fail(") else {
                continue;
            };
            let rest = &line[at + "compile_fail(".len()..];
            let Some(open) = rest.find('"') else { continue };
            let Some(close) = rest[open + 1..].find('"') else {
                continue;
            };
            let arg = &rest[open + 1..open + 1 + close];
            if arg.contains('*') {
                // trybuild 1 expands globs itself (`expand_globs` ->
                // `glob::glob`), so a globbed directory covers every fixture
                // in it. Expand the same way here, or this test would report
                // every globbed fixture as an orphan and the runner change
                // that removes the drift would look like the drift.
                let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(Path::new(arg).parent().unwrap_or(Path::new("")));
                let mut covered = BTreeSet::new();
                fixtures_on_disk(&dir, &mut covered);
                referenced.extend(covered);
            } else if let Some(stem) = Path::new(arg).file_stem() {
                referenced.insert(stem.to_string_lossy().into_owned());
            }
        }
    }
    referenced
}

#[test]
fn every_compile_fail_fixture_is_run_by_some_runner() {
    let tests = tests_dir();
    let mut on_disk = BTreeSet::new();
    fixtures_on_disk(&tests.join("compile-fail"), &mut on_disk);

    // Positive control. A broken walk finds nothing, and "no fixtures" would
    // satisfy the subset check below vacuously — the classic way a guard search
    // fails toward "unprotected".
    assert!(
        on_disk.len() >= 5,
        "found only {} compile-fail fixtures; the directory walk is broken, so \
         this test would pass without checking anything",
        on_disk.len()
    );

    let referenced = fixtures_referenced(&tests);
    assert!(
        !referenced.is_empty(),
        "no runner references any fixture; the source sweep is broken"
    );

    let orphans: Vec<&String> = on_disk.difference(&referenced).collect();
    assert!(
        orphans.is_empty(),
        "compile-fail fixtures exist on disk that no runner executes: {orphans:?}. \
         An unreferenced fixture never compiles, so it can never fail — it looks \
         like a proof and is not one. Either add it to a runner or delete it, but \
         do not leave it here."
    );

    // The reverse direction: a referenced fixture that does not exist. trybuild
    // reports this too, but only when the runner is reached; here it is stated
    // as its own failure so a typo'd path is named directly.
    let dangling: Vec<&String> = referenced.difference(&on_disk).collect();
    assert!(
        dangling.is_empty(),
        "runners reference fixtures that do not exist on disk: {dangling:?}"
    );
}

/// Full fixture paths, so the `.stderr` sibling is looked for NEXT TO the
/// fixture. Keying this on the stem and joining it to the root directory was
/// wrong the moment fixtures moved into per-runner subdirectories: every
/// sibling suddenly "went missing" at once. A check that reports all N items
/// failing is usually measuring the checker, not the code.
fn fixture_paths(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            fixture_paths(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_compile_fail_fixture_has_expected_stderr() {
    let dir = tests_dir().join("compile-fail");
    let mut paths = Vec::new();
    fixture_paths(&dir, &mut paths);
    assert!(paths.len() >= 5, "directory walk is broken");

    let missing: Vec<String> = paths
        .iter()
        .filter(|rs| !rs.with_extension("stderr").exists())
        .map(|rs| {
            rs.strip_prefix(&dir)
                .unwrap_or(rs)
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        missing.is_empty(),
        "compile-fail fixtures without a committed .stderr: {missing:?}. Without \
         one, the fixture proves only that the code fails to compile — not that \
         it fails for the stated reason, which is the whole claim."
    );
}
