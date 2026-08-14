#!/usr/bin/env python3
"""Compile the CI surface locally, before pushing. COMPILE ONLY — never runs a test.

Backend CI takes about 43 minutes to answer. Most of what goes red is a lint or a feature
combination that does not build, and both are knowable in seconds on the machine you are
already sitting at.

    python3 scripts/local_check.py            tier 1, then tier 2 if tier 1 is green
    python3 scripts/local_check.py --tier1    lints + workspace build only
    python3 scripts/local_check.py --tier2    the feature-surface matrix only
    python3 scripts/local_check.py --clean    drop the caches this tool created

  tier 1   clippy-workspace, clippy-datapath, build   lints and ordinary compile errors
  tier 2   the feature-surface matrix                 feature COMBINATIONS that fail

Tier 2 is not redundant. `cargo build --workspace` compiles one configuration; the matrix
compiles every one CI promises to cover, and a broken feature combination is invisible to
tier 1 by construction. The persistent cache is where the speed comes from: measured on a
20-core Mac at 2 workers, 499s cold and 85-94s warm across two runs, against 1222s for the
same phase on the runner. The cache reaches about 24 GB; `--clean` drops it.

The ways this tool could claim green without having compiled anything — an empty matrix, a
row that could not be run, a derivation that failed, a changed worker count silently
discarding the cache — are held by `scripts/test_local_check.py`, which stubs the matrix
and needs no toolchain. Each of those guards was mutated and the battery went red.

THIS IS NOT THE GATE, AND GREEN HERE IS NOT GREEN ON CI. CI builds from a fresh target
directory, on a different OS, and then runs the tests this script never runs. Treat a red
here as certain and a green here as encouraging.

WHY IT NEVER RUNS TESTS. Every command it issues is `cargo check` or `cargo test --no-run`:
they compile and stop. Running this repository's tests spawns processes, binds ports and
execs shells — one `core-rs` test hangs on `exec bash -l -i` — so test EXECUTION belongs in
a disposable VM, not on a developer machine. AGENTS.md states both routes.

## Nothing here re-implements a CI command

Tier 1 shells out to `admin/rust/scripts/backend-rust <phase>`, the canonical pipeline whose
equivalence with the workflow is proved by `scripts/ci/check-backend-rust-equivalence.py`.
Tier 2 imports `cargo_test_matrix` and calls ITS `matrix()` and `command()`. A second copy
of either would drift, and the drift would be invisible until CI disagreed with this tool.

## What tier 2 does differ in, with the cost stated rather than hidden

  1. Persistent target dirs, where CI mkdtemps a fresh one per run and deletes it.
     Cost: CI's fresh dir also proves the build works from nothing; this does not, so a
     stale-artefact problem can hide here and still be caught on the runner.
     Benefit: the second run onward is incremental. Nobody runs a cold matrix before a push.

  2. Its OWN target dirs, never `admin/rust/target`. Not a preference, a requirement:
     `debug=0` and the default profile are different profiles, so sharing a directory with
     ordinary `cargo build` would make each tool invalidate the other's artefacts and force
     a full rebuild every time you alternated between them.

  3. Rows run N at a time with `-j ncpu/N` each. Workers and `-j` spend ONE budget and do
     not multiply: N cargos each at `-j ncpu` is how a parallel run ends up slower than a
     serial one. Measured in a clean VM, this saturates at 2 workers (794s -> 597s at 2,
     594s at 4), so 2 is nearly as fast as 4 and costs less disk.

  4. `CARGO_PROFILE_DEV_DEBUG=0`, which is what the CI phase already sets. DWARF has no
     consumer in a compile-only phase. `debug` and `debug-assertions` are separate Cargo
     keys, so this weakens no assertion.

Row i always lands in target dir `i % workers`. Deterministic on purpose: if rows moved
between directories run to run, every directory would keep meeting crates it had not
compiled, and nothing would ever stay warm.

No fail-fast: every row runs even after one goes red, so one pass hands back the whole list
instead of turning one breakage into N edit-push cycles.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND_RUST = ROOT / "admin" / "rust" / "scripts" / "backend-rust"
CACHE = Path(os.path.expanduser("~/.cache/theyos-local-check"))
WORKERS_STAMP = CACHE / "workers"

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = DIM = BOLD = OFF = ""

TIER1_PHASES = ("clippy-workspace", "clippy-datapath", "build")


def load_matrix_module():
    """Import `cargo_test_matrix` lazily, and say something useful when it cannot.

    It needs `tomllib`, which is Python 3.11+. Importing at module scope made
    `--clean` and `--help` fail on an older interpreter for no reason, and turned a
    solvable version problem into a traceback. This is not hypothetical: a macOS guest
    whose `python3` was the system 3.9 failed exactly here.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import cargo_test_matrix as ctm
    except ModuleNotFoundError as exc:
        if exc.name == "tomllib":
            print(f"{RED}tier 2 needs Python 3.11 or newer for tomllib{OFF}; this "
                  f"interpreter is {sys.version.split()[0]}.\n"
                  f"  Tier 1 does not: try `--tier1`, or run this under a newer python3.")
            return None
        raise
    return ctm


def tier1() -> int:
    print(f"{BOLD}tier 1 — lints and the workspace build{OFF}  "
          f"{DIM}(via backend-rust, the same phases CI runs){OFF}")
    failed = []
    for phase in TIER1_PHASES:
        t0 = time.time()
        proc = subprocess.run([str(BACKEND_RUST), phase], cwd=str(ROOT),
                              capture_output=True, text=True)
        secs = time.time() - t0
        if proc.returncode == 0:
            print(f"  {GREEN}OK{OFF}   {phase:<20} {secs:.0f}s")
            continue
        failed.append(phase)
        print(f"  {RED}FAIL{OFF} {phase:<20} {secs:.0f}s")
        body = proc.stdout + proc.stderr
        lines = [l for l in body.splitlines()
                 if l.startswith("error") or l.startswith("warning:") or l.startswith("  -->")]
        for line in (lines or body.splitlines()[-20:])[:25]:
            print(f"       {line}")
    return 1 if failed else 0


def tier2(ctm, workers: int, jobs: int) -> int:
    try:
        rows = list(ctm.matrix())
    except Exception as exc:  # cargo metadata failing is a real, common case
        print(f"{RED}could not derive the matrix{OFF}: {exc}")
        return 2
    if not rows:
        # An empty matrix would let every worker "succeed" instantly. That is not a fast
        # run, it is no run, and it must never be reported as a pass.
        print(f"{RED}the matrix derived zero rows — refusing to call that a pass{OFF}")
        return 2

    # A CHANGED WORKER COUNT SILENTLY THROWS THE CACHE AWAY. Row i lives in dir
    # `i % workers`, so changing workers moves most rows to a directory that has never
    # compiled them. Without this notice the run just looks inexplicably slow, and the
    # docstring's promise that the assignment "keeps things warm" reads as a lie — it
    # holds only for a fixed worker count.
    previous = None
    if WORKERS_STAMP.exists():
        previous = WORKERS_STAMP.read_text().strip() or None
    changed = previous is not None and previous != str(workers)

    warm = (not changed) and all((CACHE / f"t{i}").is_dir() for i in range(workers))
    print(f"{BOLD}tier 2 — feature surface{OFF}  {len(rows)} rows · "
          f"{workers} workers x -j {jobs} · "
          f"{'warm' if warm else 'cold (first run builds everything)'}")
    if changed:
        print(f"{DIM}  worker count changed {previous} -> {workers}: rows move between "
              f"directories, so this run is cold and the old dirs stay on disk "
              f"(--clean drops them){OFF}")
    WORKERS_STAMP.write_text(str(workers))
    print(f"{DIM}  caches in {CACHE}, separate from admin/rust/target on purpose{OFF}")

    results: list[dict | None] = [None] * len(rows)

    def run(i: int) -> None:
        # NOTHING ESCAPES THIS FUNCTION. `pool.map` re-raises the first exception at
        # iteration, so a single row that threw — a missing cargo, an unreadable target
        # dir — used to abort the whole pass and discard the twenty-five results that had
        # already been paid for. A row that could not run is a FAILED row, reported beside
        # the others, not the end of the run.
        row = rows[i]
        t0 = time.time()
        try:
            target = CACHE / f"t{i % workers}"
            target.mkdir(parents=True, exist_ok=True)
            env = dict(os.environ)
            env["CARGO_TARGET_DIR"] = str(target)
            env["CARGO_PROFILE_DEV_DEBUG"] = "0"
            env.setdefault("CLAWS_CATALOG_JSON", str(target / "claws-catalog.json"))
            cmd = [*ctm.command(row), "-j", str(jobs)]
            proc = subprocess.run(cmd, cwd=str(ctm.RUST), env=env,
                                  capture_output=True, text=True)
            rc, out = proc.returncode, proc.stdout + proc.stderr
        except Exception as exc:  # noqa: BLE001 — the row's verdict must survive it
            rc, out = -1, f"error: this row could not be run: {exc!r}"
        results[i] = {"name": row.name, "rc": rc,
                      "secs": time.time() - t0, "out": out}

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(run, range(len(rows))))
    wall = time.time() - t0

    done = [r for r in results if r]
    if len(done) != len(rows):
        print(f"{RED}only {len(done)} of {len(rows)} rows reported — not a pass{OFF}")
        return 2

    bad = [r for r in done if r["rc"] != 0]
    for r in bad:
        print(f"  {RED}FAIL{OFF} {r['name']:<44} {r['secs']:.0f}s")
    if bad:
        first = bad[0]
        print(f"\n{RED}first failing row: {first['name']}{OFF}")
        shown = [l for l in first["out"].splitlines()
                 if l.startswith("error") or l.startswith("  -->")][:20]
        for line in shown or first["out"].splitlines()[-20:]:
            print(f"    {line}")
        if len(bad) > 1:
            print(f"\n  {len(bad) - 1} other row(s) also failed: "
                  f"{', '.join(r['name'] for r in bad[1:])}")
        return 1

    slowest = max(done, key=lambda r: r["secs"])
    print(f"  {GREEN}OK{OFF}   all {len(rows)} feature combinations compile "
          f"({wall:.0f}s, slowest row {slowest['name']} {slowest['secs']:.0f}s)")
    print(f"{DIM}  fresh-target behaviour is NOT covered here; CI still builds from "
          f"nothing, and still runs the tests.{OFF}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compile the CI surface locally. Compile only — never runs a test.")
    parser.add_argument("--tier1", action="store_true", help="lints + workspace build only")
    parser.add_argument("--tier2", action="store_true", help="the feature matrix only")
    parser.add_argument("--workers", type=int, default=2,
                        help="parallel cargo processes for tier 2 (default 2; measured to "
                             "saturate there, and 4 costs more disk for the same wall)")
    parser.add_argument("--jobs", type=int, default=0,
                        help="cargo -j per worker; 0 divides the CPU budget by --workers")
    parser.add_argument("--clean", action="store_true", help="drop this tool's caches")
    args = parser.parse_args()

    if args.clean:
        shutil.rmtree(CACHE, ignore_errors=True)
        print(f"removed {CACHE}")
        return 0

    if not BACKEND_RUST.is_file():
        print(f"{RED}missing {BACKEND_RUST}{OFF} — this must run inside the theyos repo")
        return 2

    workers = max(1, args.workers)
    ncpu = os.cpu_count() or 8
    jobs = args.jobs or max(1, ncpu // workers)
    CACHE.mkdir(parents=True, exist_ok=True)

    if args.tier2:
        ctm = load_matrix_module()
        return 2 if ctm is None else tier2(ctm, workers, jobs)
    rc = tier1()
    if args.tier1 or rc != 0:
        return rc
    print()
    ctm = load_matrix_module()
    return 2 if ctm is None else tier2(ctm, workers, jobs)


if __name__ == "__main__":
    sys.exit(main())
