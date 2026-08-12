#!/usr/bin/env python3
"""The registry, the functions and the workflow must name the same phases.

Unlike `check-backend-rust-equivalence.py`, which compares against the *old*
workflow text and therefore loses its referent the moment the change lands, this
gate's subject survives every merge. It is meant to sit in CI forever.

Three sets, per job, compared for EQUALITY and UNIQUENESS:

    A  PHASES=( ... ) in scripts/ci/backend-rust      the registry
    B  the phase_* functions defined there            what can execute
    C  the phases each workflow job actually invokes  what CI runs

## Why this is not a tidiness check

`scripts/ci/backend-rust all` is a published interface — it is how the pipeline
is run outside GitHub, and it is what a benchmark measures. `all` and `--list`
are driven by PHASES. Before the runtime fix that landed with this file,
`run_phase` resolved `phase_${name//-/_}` directly and never consulted PHASES, so
a function that existed but was omitted from the array was still dispatchable:
its own CI step went green while `--list` omitted it and `all` skipped it in
silence. The published enumeration and the executed set could drift apart with
nothing going red, and the direction that hurts is the quiet one — `all` covering
*less* than CI.

The runtime now refuses to dispatch a non-member. This gate closes the other
half: it refuses to let the three sets differ, in either direction, and names
which direction broke.

## Per job, not merged

Linux and macOS are compared separately. A phase present in one job and missing
from the other is a real coverage hole that a union would hide — and the union is
exactly what a careless implementation computes, because merging the two job
bodies first is the shorter code path.

`Quarantine probe (issue #470)` is deliberately NOT a phase: it stays inline in
the Linux job, pinned there by a contract test that reads this workflow with
`include_str!`. It therefore never appears in set C and must not be expected to.

## Matching only what executes

Phase names are read from the `run:` scalar of each step, never from the raw job
text. A grep over the whole file would be satisfied by the command name appearing
in a comment, in documentation prose, or in a step a later edit disabled — text
that never runs. The parser walks steps and reads their `run:` value, so a match
means an invocation. `--self-test` proves that distinction rather than asserting
it: one of its mutations moves a real invocation into a comment and requires this
gate to go red.

## This gate checks that it is itself wired

`assert_wired` requires an active step in the workflow to invoke this script.
A gate nothing runs is not a gate, and the cheapest way to neuter one is to
replace its step with an `echo` while leaving the file in the tree.

The residual limit, stated rather than papered over: if the whole job is deleted,
nothing here runs and nothing complains. That is true of every gate — a gate
cannot outlive its own removal — so the protection against *that* is review of
the workflow diff, not this file.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COMMAND = REPO_ROOT / "scripts/ci/backend-rust"
WORKFLOW = REPO_ROOT / ".github/workflows/backend-ci.yml"

JOBS = ("build-and-test-linux", "build-and-test-macos")
EXPECTED_COMMON = 11
SELF = "scripts/ci/check-backend-rust-phase-wiring.py"

INVOCATION = re.compile(r"(?:^|\s)scripts/ci/backend-rust\s+([a-z0-9][a-z0-9-]*)\s*$")


def registry(text: str) -> list[str]:
    block = re.search(r"^PHASES=\(\n(.*?)^\)$", text, re.M | re.S)
    if not block:
        raise SystemExit("PHASES=( ... ) not found — this gate's subject moved")
    return [ln.strip() for ln in block.group(1).splitlines() if ln.strip()]


def functions(text: str) -> list[str]:
    return [m.replace("_", "-") for m in re.findall(r"^phase_(\w+)\(\)", text, re.M)]


def job_block(workflow: str, job: str) -> str:
    start = re.search(rf"^  {re.escape(job)}:$", workflow, re.M)
    if not start:
        raise SystemExit(f"job {job} not found — this gate's subject moved")
    rest = workflow[start.end() :]
    nxt = re.search(r"^  [A-Za-z0-9_-]+:$", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def run_scalars(block: str) -> list[str]:
    """Every executable line of every `run:` in a job. Comments excluded."""
    out: list[str] = []
    lines = block.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("#"):
            i += 1
            continue
        inline = re.match(r"^\s+run: (?![|>])(.+)$", line)
        if inline:
            out.append(inline.group(1).strip())
            i += 1
            continue
        opened = re.match(r"^(\s+)run: [|>]", line)
        if not opened:
            i += 1
            continue
        indent = len(opened.group(1))
        i += 1
        while i < len(lines):
            body = lines[i]
            if body.strip() and (len(body) - len(body.lstrip())) <= indent:
                break
            stripped = body.strip()
            if stripped and not stripped.startswith("#"):
                out.append(stripped)
            i += 1
    return out


def invoked(block: str) -> list[str]:
    out = []
    for cmd in run_scalars(block):
        hit = INVOCATION.search(cmd)
        if hit:
            out.append(hit.group(1))
    return out


def duplicates(names: list[str]) -> list[str]:
    return sorted({n for n in names if names.count(n) > 1})


def assert_wired(workflow: str) -> list[str]:
    """Some active step must invoke this script."""
    for job in re.findall(r"^  ([A-Za-z0-9_-]+):$", workflow, re.M):
        if any(SELF in cmd for cmd in run_scalars(job_block(workflow, job))):
            return []
    return [
        f"no active workflow step invokes {SELF} — an orphaned gate never fires, "
        "and replacing its step with an echo is the cheapest way to neuter it"
    ]


def evaluate(cmd: str, wf: str) -> tuple[list[str], dict[str, int]]:
    reg, fns = registry(cmd), functions(cmd)
    per_job = {j: invoked(job_block(wf, j)) for j in JOBS}
    errs: list[str] = []

    for label, names in (("PHASES", reg), ("phase_* functions", fns), *per_job.items()):
        dup = duplicates(names)
        if dup:
            errs.append(f"{label} contains duplicates: {dup}")

    rset, fset = set(reg), set(fns)
    if rset - fset:
        errs.append(f"in PHASES but not defined: {sorted(rset - fset)} — `all` aborts")
    if fset - rset:
        errs.append(
            f"defined but not in PHASES: {sorted(fset - rset)} — unreachable at "
            "runtime, absent from `--list`/`all`"
        )
    for job, names in per_job.items():
        jset = set(names)
        if jset - rset:
            errs.append(f"{job} invokes non-members: {sorted(jset - rset)} — exits 2")
        if rset - jset:
            errs.append(f"{job} never invokes: {sorted(rset - jset)} — registered, unrun")

    common = set.intersection(*(set(v) for v in per_job.values()))
    if len(common) != EXPECTED_COMMON:
        errs.append(
            f"the jobs share {len(common)} phases, expected {EXPECTED_COMMON}: "
            f"{sorted(common)}"
        )

    errs += assert_wired(wf)
    counts = {"PHASES": len(reg), "functions": len(fns)}
    counts.update({j: len(v) for j, v in per_job.items()})
    return errs, counts


def harness(cmd: str, phases: list[str], extra: str = "") -> str:
    """The real header and the real dispatcher, with toy phases spliced in.

    Faithfulness is the entire point and it rests on this splice: everything
    outside `PHASES=( ... )` and the `phase_*` bodies is copied verbatim, so
    `validate_registry`, `run_phase` and `main` under test are the ones that
    ship. Weaken the membership check in the real file and these runtime cases
    inherit the weakening and fail — which is asserted below rather than
    assumed, because a harness that quietly reimplemented the dispatcher would
    keep passing while the shipped code rotted.

    Toy phases rather than the real ones because the real bodies invoke cargo.
    """
    head = cmd[: cmd.index("PHASES=(")]
    tail = cmd[cmd.index("usage() {") :]
    body = "PHASES=(\n" + "".join(f"  {p}\n" for p in phases) + ")\n\n"
    for p in dict.fromkeys(phases):
        body += f'phase_{p.replace("-", "_")}() {{ echo "RAN-{p}"; }}\n'
    return head + body + extra + "\n" + tail


def run_harness(text: str, arg: str) -> tuple[int, str]:
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
        fh.write(text)
        path = fh.name
    try:
        p = subprocess.run(
            ("bash", path, arg), capture_output=True, text=True, timeout=60
        )
        return p.returncode, p.stdout + p.stderr
    finally:
        os.unlink(path)


def runtime_self_test(cmd: str) -> None:
    """Prove the dispatcher refuses everything outside the registry.

    The structural gate above cannot see this layer at all. Measured: delete the
    membership test from `run_phase` and the three sets are untouched, so the
    structural gate stays green while a `phase_*` function outside PHASES
    becomes directly callable again — rc=0, body executed. Without the cases
    below, this file would certify a dispatcher whose registry had stopped
    governing it.
    """
    ok = harness(cmd, ["one", "two", "three"], 'phase_orphan() { echo "RAN-orphan"; }')
    dup = harness(cmd, ["one", "one", "two"])

    rc, _ = run_harness(ok, "no-such-phase")
    if rc == 0:
        raise SystemExit("RUNTIME SELF-TEST FAILED: unknown phase name exited 0")
    print("  self-test  runtime: unknown name refused")

    rc, out = run_harness(ok, "orphan")
    if rc == 0 or "RAN-orphan" in out:
        raise SystemExit(
            "RUNTIME SELF-TEST FAILED: a phase_* function outside PHASES was "
            f"dispatchable (rc={rc}, body ran={'RAN-orphan' in out}). The "
            "registry has stopped governing execution."
        )
    print("  self-test  runtime: unregistered function refused, body did not run")

    rc, out = run_harness(dup, "one")
    if rc == 0 or "RAN-one" in out:
        raise SystemExit(
            f"RUNTIME SELF-TEST FAILED: duplicate PHASES entry ran anyway (rc={rc})"
        )
    print("  self-test  runtime: duplicate registry entry refused before dispatch")

    rc, out = run_harness(ok, "two")
    if rc != 0 or out.count("RAN-two") != 1:
        raise SystemExit(
            f"RUNTIME SELF-TEST FAILED: a valid phase ran {out.count('RAN-two')} "
            f"time(s) with rc={rc}, expected exactly 1 and rc=0"
        )
    print("  self-test  runtime: a valid phase runs exactly once")

    rc, out = run_harness(ok, "all")
    ran = [ln[4:] for ln in out.splitlines() if ln.startswith("RAN-")]
    if rc != 0 or ran != ["one", "two", "three"]:
        raise SystemExit(
            f"RUNTIME SELF-TEST FAILED: `all` ran {ran}, expected each phase once "
            "in registry order"
        )
    print("  self-test  runtime: `all` runs each phase once, in registry order")

    # NEGATIVE CONTROL on the runtime cases themselves. Strip the membership
    # test out of the copy under test; the orphan case MUST start passing. If it
    # does not, these cases are not bound to the shipped dispatcher — they would
    # be testing the harness's own text and would survive the defect they exist
    # to catch.
    start = cmd.find("  # MEMBERSHIP FIRST")
    end = cmd.find('  local fn="phase_${phase//-/_}"')
    if start == -1 or end == -1 or end <= start:
        raise SystemExit(
            "RUNTIME SELF-TEST INVALID: cannot locate the membership check in "
            "run_phase, so its removal cannot be simulated"
        )
    crippled = harness(cmd[:start] + cmd[end:], ["one", "two"], 'phase_orphan() { echo "RAN-orphan"; }')
    rc, out = run_harness(crippled, "orphan")
    if rc != 0 or "RAN-orphan" not in out:
        raise SystemExit(
            "RUNTIME SELF-TEST INVALID: with the membership check removed the "
            f"orphan case still refused (rc={rc}). These cases are not measuring "
            "the shipped dispatcher."
        )
    print("  self-test  runtime: negative control — removing the check reopens it")


def self_test(cmd: str, wf: str) -> None:
    """Every mutation below must be caught. If one is not, refuse to report.

    A three-set comparison that has never been observed to fail is
    indistinguishable from one that returns success unconditionally, and this
    gate is what authorises trusting `backend-rust all` as the pipeline.
    """
    victim = registry(cmd)[-1]
    fn = f"phase_{victim.replace('-', '_')}"
    step = f"run: scripts/ci/backend-rust {victim}"
    macos_at = wf.index("  build-and-test-macos:")

    cases: list[tuple[str, str, str]] = [
        ("function defined but absent from PHASES", cmd.replace(f"  {victim}\n)", ")"), wf),
        ("PHASES entry with no function", re.sub(rf"{fn}\(\) \{{.*?\n\}}\n", "", cmd, flags=re.S), wf),
        ("workflow invokes a non-member", cmd, wf.replace(step, "run: scripts/ci/backend-rust ghost-phase", 1)),
        ("phase missing from one job only", cmd, wf[:macos_at] + wf[macos_at:].replace(f"        {step}\n", "", 1)),
        ("duplicate entry in PHASES", cmd.replace(f"  {victim}\n)", f"  {victim}\n  {victim}\n)"), wf),
        ("invocation present only in a comment", cmd, wf.replace(f"        {step}", f"        run: /bin/true\n        # {step}", 1)),
        ("the gate's own step replaced by an echo", cmd, wf.replace(SELF, "echo neutered")),
    ]

    for label, mc, mw in cases:
        if mc == cmd and mw == wf:
            raise SystemExit(f"SELF-TEST INVALID: mutation '{label}' changed nothing")
        errs, _ = evaluate(mc, mw)
        if not errs:
            raise SystemExit(
                f"SELF-TEST FAILED: '{label}' was not detected. The gate does not "
                "discriminate; its green verdict would mean nothing."
            )
        print(f"  self-test  caught: {label}")

    errs, _ = evaluate(cmd, wf)
    if errs:
        raise SystemExit(f"SELF-TEST FAILED: the unmutated tree is red: {errs}")
    print("  self-test  clean tree stays green")

    runtime_self_test(cmd)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    cmd, wf = COMMAND.read_text(), WORKFLOW.read_text()

    if args.self_test:
        self_test(cmd, wf)
        return 0

    errs, counts = evaluate(cmd, wf)
    for k, v in counts.items():
        print(f"  {k:26} {v}")
    for e in errs:
        print(f"ERROR: {e}")
    if errs:
        return 1
    print(f"  OK: registry, functions and both jobs agree on {counts['PHASES']} phases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
